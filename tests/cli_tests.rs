//! Интеграционные тесты для интерфейса командной строки (CLI) NovaRay Core.
//!
//! Проверяют:
//! - Корректность вызова встроенных команд (`--help`, `--version`, `status`, `pinned-releases`).
//! - Валидацию конфигурации (`validate`) на валидных и поврежденных файлах с точными exit codes.
//! - Запуск прокси-сервиса (`start`) с mock-движком, работу в non-interactive и timeout режимах,
//!   а также отказы (бинарник не найден, несовпадение чексуммы, занятый порт) с соответствующими кодами возврата.

use novaray_core::cli::ExitCode;
use novaray_core::config::{
    AppConfig, ClientSettings, FlowType, ProtocolType, SecurityType, ServerProfile,
    SplitTunnelMode, SplitTunnelingSettings, TlsConfig, TransportType, UserSettings,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

static TEST_CLI_PORT_OFFSET: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
static TEST_CLI_BASE_OFFSET: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

fn allocate_test_ports() -> (u16, u16) {
    let base = *TEST_CLI_BASE_OFFSET.get_or_init(|| {
        let pid_part = ((std::process::id() as u16) % 30) * 150;
        let time_part = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u16)
            % 30
            * 50;
        pid_part.wrapping_add(time_part)
    });
    let step = TEST_CLI_PORT_OFFSET.fetch_add(50, std::sync::atomic::Ordering::SeqCst);
    let p1 = 36000 + ((base.wrapping_add(step)) % 8000);
    let p2 = p1 + 1;
    (p1, p2)
}

fn get_novaray_core_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_novaray-core"))
}

#[cfg(unix)]
fn sha256_file(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).unwrap();
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug)]
struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

impl std::ops::Deref for TempDirGuard {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for TempDirGuard {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

static TEMP_DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn create_temp_dir() -> TempDirGuard {
    let count = TEMP_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "novaray_cli_test_{}_{}_{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    TempDirGuard::new(dir)
}

#[cfg(unix)]
struct ChildGuard(Option<std::process::Child>);

#[cfg(unix)]
impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.0.as_mut().and_then(|c| c.stdout.take())
    }

    fn wait_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> std::io::Result<std::process::ExitStatus> {
        let start = std::time::Instant::now();
        loop {
            if let Some(child) = self.0.as_mut() {
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
            }
            if start.elapsed() >= timeout {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Child process wait timed out",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn create_mock_engine(dir: &Path) -> PathBuf {
    let py_path = dir.join("mock_engine.py");
    let script = r#"import sys, socket, time, json, threading, os

if len(sys.argv) >= 3 and ((sys.argv[1] == "run" and sys.argv[2] == "-test") or (sys.argv[1] == "check" and sys.argv[2] == "-c")):
    sys.stdout.write("Configuration OK\n")
    sys.stdout.flush()
    sys.exit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-c":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        cfg = json.load(f)
    inbound = cfg["inbounds"][0]
    socks_port = inbound.get("port", inbound.get("listen_port"))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    s.bind(('127.0.0.1', socks_port))
    s.listen(128)
    print(f"Xray started on port {socks_port}")
    sys.stdout.flush()

    parent_pid = os.getppid()
    for _ in range(120):
        time.sleep(0.5)
        try:
            os.kill(parent_pid, 0)
        except Exception:
            break
"#;
    let unix_script = format!("#!/usr/bin/env python3\n{}", script);
    std::fs::write(&py_path, unix_script).unwrap();
    let mut perms = std::fs::metadata(&py_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&py_path, perms).unwrap();
    py_path
}

#[cfg(unix)]
fn create_crashing_mock_engine(dir: &Path) -> PathBuf {
    let py_path = dir.join("crashing_mock_engine.py");
    let script = r#"import sys, socket, time, json, os

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    sys.stdout.write("Configuration OK\n")
    sys.stdout.flush()
    sys.exit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-c":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        cfg = json.load(f)
    socks_port = cfg["inbounds"][0]["port"]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', socks_port))
    s.listen(128)
    print(f"Xray started on port {socks_port}")
    sys.stdout.flush()

    # Быстро падаем через 800мс
    time.sleep(0.8)
    sys.exit(137)
"#;
    let unix_script = format!("#!/usr/bin/env python3\n{}", script);
    std::fs::write(&py_path, unix_script).unwrap();
    let mut perms = std::fs::metadata(&py_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&py_path, perms).unwrap();
    py_path
}

#[cfg(unix)]
fn create_slow_mock_engine(dir: &Path) -> PathBuf {
    let py_path = dir.join("slow_mock_engine.py");
    let script = r#"import sys, socket, time, json, os

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    sys.stdout.write("Configuration OK\n")
    sys.stdout.flush()
    sys.exit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-c":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        cfg = json.load(f)
    socks_port = cfg["inbounds"][0]["port"]

    time.sleep(2.0)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', socks_port))
    s.listen(128)
    print(f"Xray started on port {socks_port}")
    sys.stdout.flush()

    for _ in range(120):
        time.sleep(0.5)
"#;
    let unix_script = format!("#!/usr/bin/env python3\n{}", script);
    std::fs::write(&py_path, unix_script).unwrap();
    let mut perms = std::fs::metadata(&py_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&py_path, perms).unwrap();
    py_path
}

fn create_valid_test_configs(dir: &Path, socks_port: u16, http_port: u16) -> (PathBuf, PathBuf) {
    let profile = ServerProfile {
        id: "profile-cli-1".to_string(),
        name: "CLI Test Profile".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8443,
        uuid: "00000000-0000-4000-8000-000000000001".to_string(),
        transport: TransportType::Tcp,
        host: None,
        path: None,
        flow: Some(FlowType::XtlsRprxVision),
        tls: Some(TlsConfig {
            enabled: true,
            security: SecurityType::Reality,
            server_name: "example.com".to_string(),
            public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
            short_id: Some("abcd".to_string()),
            fingerprint: Some("chrome".to_string()),
        }),
        protocol: ProtocolType::Vless,
    };

    let app_config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: "profile-cli-1".to_string(),
        profiles: vec![profile],
    };

    let user_settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let config_path = dir.join("config.json");
    let settings_path = dir.join("settings.json");

    std::fs::write(
        &config_path,
        serde_json::to_string_pretty(&app_config).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &settings_path,
        serde_json::to_string_pretty(&user_settings).unwrap(),
    )
    .unwrap();

    (config_path, settings_path)
}

#[test]
fn test_cli_help_and_version_flags() {
    let bin = get_novaray_core_bin();

    // --help
    let output = Command::new(&bin).arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NovaRay Core CLI"));
    assert!(stdout.contains("start"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("--engine-config <NAME>"));
    assert!(stdout.contains("--engine-version <VER>"));
    assert!(stdout.contains("--engine-bin задаёт путь, но не меняет формат конфигурации"));

    // -h
    let output = Command::new(&bin).arg("-h").output().unwrap();
    assert!(output.status.success());

    // --version
    let output = Command::new(&bin).arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("novaray-core 0.1.0"));

    // -V
    let output = Command::new(&bin).arg("-V").output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_cli_status_and_pinned_releases_commands() {
    let bin = get_novaray_core_bin();

    // status
    let output = Command::new(&bin).arg("status").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NovaRay Core Status Summary"));
    assert!(stdout.contains("VLESS"));
    assert!(stdout.contains("SOCKS5"));
    assert!(stdout.contains("Engine Routing:"));
    assert!(stdout.contains("Core Matcher:"));

    // pinned-releases
    let output = Command::new(&bin).arg("pinned-releases").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Pinned Engine Releases Catalog"));
    assert!(stdout.to_lowercase().contains("xray-core"));
    assert!(stdout.contains("v26.3.27"));
    assert!(stdout
        .contains("Binary SHA:  5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404"));
}

#[test]
fn test_cli_validate_success_with_example_files() {
    let bin = get_novaray_core_bin();

    let output = Command::new(&bin)
        .args([
            "validate",
            "-c",
            "config.example.json",
            "-s",
            "settings.example.json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Конфигурация успешно прошла валидацию"));
    assert!(stdout.contains("Локальный SOCKS5 порт:  10808"));
}

#[test]
fn test_cli_validate_nonexistent_files_returns_general_error_exit_1() {
    let bin = get_novaray_core_bin();

    let output = Command::new(&bin)
        .args([
            "validate",
            "-c",
            "nonexistent_conf.json",
            "-s",
            "settings.example.json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(ExitCode::GeneralError.as_i32()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("не найден"));
}

#[test]
fn test_cli_validate_corrupted_json_returns_validation_error_exit_3() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let corrupted_config = temp_dir.join("corrupted.json");
    std::fs::write(&corrupted_config, "{ invalid json").unwrap();

    let output = Command::new(&bin)
        .args([
            "validate",
            "-c",
            corrupted_config.to_str().unwrap(),
            "-s",
            "settings.example.json",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(ExitCode::ValidationError.as_i32())
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Синтаксическая ошибка JSON"));
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_validate_semantic_failure_returns_validation_error_exit_3() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, 10808, 10809);

    // Ломаем порт в конфигурации (порт 0 недопустим)
    let mut config: AppConfig =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    config.profiles[0].port = 0;
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let output = Command::new(&bin)
        .args([
            "validate",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(ExitCode::ValidationError.as_i32())
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Ошибка семантической валидации"));
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_unknown_arguments_return_usage_error_exit_2() {
    let bin = get_novaray_core_bin();

    let output = Command::new(&bin).arg("unknown_command").output().unwrap();
    assert_eq!(output.status.code(), Some(ExitCode::UsageError.as_i32()));

    let output2 = Command::new(&bin)
        .args(["start", "--invalid-flag"])
        .output()
        .unwrap();
    assert_eq!(output2.status.code(), Some(ExitCode::UsageError.as_i32()));

    let output3 = Command::new(&bin)
        .args(["start", "--engine-config", "unknown-engine"])
        .output()
        .unwrap();
    assert_eq!(output3.status.code(), Some(ExitCode::UsageError.as_i32()));
    assert!(String::from_utf8_lossy(&output3.stderr).contains("--engine-config"));
}

#[test]
#[cfg(unix)]
fn test_cli_start_sigterm_graceful_shutdown_and_runtime_config_cleanup() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);
    let mock_bin = create_mock_engine(&temp_dir);
    let mock_sha256 = sha256_file(&mock_bin);

    // Запускаем novaray-core start как дочерний процесс
    let child = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            mock_bin.to_str().unwrap(),
            "--expected-sha256",
            &mock_sha256,
            "--timeout-secs",
            "30",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI процесс должен успешно запуститься");

    let mut guard = ChildGuard::new(child);
    let cli_pid = guard.id();
    let stdout = guard.take_stdout().expect("stdout pipe");
    let mut reader = BufReader::new(stdout);

    let mut engine_pid: Option<u32> = None;
    let mut line = String::new();
    let mut collected_stdout = Vec::new();
    let start_wait = std::time::Instant::now();
    while start_wait.elapsed() < std::time::Duration::from_secs(5) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                collected_stdout.push(line.clone());
                if line.contains("PID процесса:") {
                    if let Some(pid_str) = line.split(':').next_back() {
                        if let Ok(p) = pid_str.trim().parse::<u32>() {
                            engine_pid = Some(p);
                            break;
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    let engine_pid = match engine_pid {
        Some(p) => p,
        None => {
            let mut stderr_str = String::new();
            if let Some(mut stderr) = guard.0.as_mut().and_then(|c| c.stderr.take()) {
                use std::io::Read;
                let _ = stderr.read_to_string(&mut stderr_str);
            }
            panic!(
                "PID дочернего движка не найден в stdout.\nStdout: {}\nStderr: {}",
                collected_stdout.join(""),
                stderr_str
            );
        }
    };

    // 1. Проверяем наблюдаемый эффект во время работы:
    // - Процесс движка жив
    let is_engine_alive = unsafe { libc::kill(engine_pid as libc::pid_t, 0) == 0 };
    assert!(
        is_engine_alive,
        "Процесс движка (PID {}) должен быть жив во время работы CLI",
        engine_pid
    );

    // - SOCKS5 порт слушает и принимает TCP-соединения (с retry до 2 сек на старт Python mock)
    let mut socket_ready = false;
    let socket_start = std::time::Instant::now();
    while socket_start.elapsed() < std::time::Duration::from_secs(2) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", socks_port)).is_ok() {
            socket_ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        socket_ready,
        "SOCKS5 порт {} должен принимать соединения во время работы CLI",
        socks_port
    );

    // - Временный runtime-конфиг существует на диске (с retry до 2 сек)
    let mut temp_runtime_configs = Vec::new();
    let find_start = std::time::Instant::now();
    while find_start.elapsed() < std::time::Duration::from_secs(2) {
        temp_runtime_configs = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(&format!("novaray_runtime_config_{}_", cli_pid))
                    && name.ends_with(".json")
            })
            .collect();
        if !temp_runtime_configs.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        !temp_runtime_configs.is_empty(),
        "Файл runtime-конфигурации для CLI PID {} должен существовать на диске во время работы",
        cli_pid
    );

    // 2. Отправляем SIGTERM в процесс CLI
    unsafe {
        libc::kill(cli_pid as libc::pid_t, libc::SIGTERM);
    }

    // Ждем завершения CLI процесса с таймаутом
    let status = guard
        .wait_timeout(std::time::Duration::from_secs(5))
        .expect("CLI процесс должен завершиться в течение 5 секунд");
    assert!(
        status.success(),
        "CLI процесс должен завершиться с кодом 0 после SIGTERM, получен: {:?}",
        status
    );

    // 3. Проверяем наблюдаемый эффект после завершения:
    // - Процесс движка завершен (убит)
    let mut engine_stopped = false;
    let stop_wait = std::time::Instant::now();
    while stop_wait.elapsed() < std::time::Duration::from_secs(2) {
        if unsafe { libc::kill(engine_pid as libc::pid_t, 0) != 0 } {
            engine_stopped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        engine_stopped,
        "Процесс движка (PID {}) должен быть завершен после остановки CLI",
        engine_pid
    );

    // - SOCKS5 порт закрыт (с retry до 2 сек на освобождение сокета ОС)
    let mut socket_closed = false;
    let close_start = std::time::Instant::now();
    while close_start.elapsed() < std::time::Duration::from_secs(2) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", socks_port)).is_err() {
            socket_closed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        socket_closed,
        "SOCKS5 порт {} должен быть закрыт после остановки CLI",
        socks_port
    );

    // - Файлы runtime-конфигурации удалены
    for entry in temp_runtime_configs {
        assert!(
            !entry.path().exists(),
            "Файл runtime-конфигурации {:?} должен быть удален после остановки CLI",
            entry.path()
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(unix)]
fn test_cli_start_abrupt_engine_crash_exits_with_engine_error() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);
    let mock_bin = create_crashing_mock_engine(&temp_dir);
    let mock_sha256 = sha256_file(&mock_bin);

    let start_time = std::time::Instant::now();
    let output = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            mock_bin.to_str().unwrap(),
            "--expected-sha256",
            &mock_sha256,
            "--timeout-secs",
            "10",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(ExitCode::EngineError.as_i32()),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let elapsed = start_time.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(5));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("завершился") || stderr.contains("137"),
        "stderr должен сообщать о падении процесса: {}",
        stderr
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(unix)]
fn test_cli_start_with_sing_box_strategy_stops_cleanly() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);
    let mock_bin = create_mock_engine(&temp_dir);
    let mock_sha256 = sha256_file(&mock_bin);

    let start_time = std::time::Instant::now();
    let output = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            mock_bin.to_str().unwrap(),
            "--engine-config",
            "sing-box",
            "--engine-version",
            "v1.13.18",
            "--expected-sha256",
            &mock_sha256,
            "--timeout-secs",
            "1",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "CLI start failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let elapsed = start_time.elapsed();
    assert!(elapsed >= std::time::Duration::from_millis(900));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Остановка прокси-сервиса (причина: timeout)"));
    assert!(stdout.contains("корректно остановлен"));

    // Проверяем, что после таймаута порт освобожден (с retry до 2 сек)
    let mut socket_closed = false;
    let close_start = std::time::Instant::now();
    while close_start.elapsed() < std::time::Duration::from_secs(2) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", socks_port)).is_err() {
            socket_closed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        socket_closed,
        "SOCKS5 порт должен быть закрыт после таймаута"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_start_with_nonexistent_binary_returns_engine_error_exit_4() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);

    let output = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            "/tmp/nonexistent_xray_binary_12345",
            "--timeout-secs",
            "2",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(ExitCode::EngineError.as_i32()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("не найден"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_start_unknown_engine_version_fails_before_binary_lookup() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);

    let output = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            "/tmp/nonexistent_xray_binary_12345",
            "--engine-version",
            "v99.0.0",
            "--timeout-secs",
            "2",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(ExitCode::EngineError.as_i32()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Версия движка xray-core v99.0.0 не найдена в pinned catalog"),
        "stderr={}",
        stderr
    );
    assert!(
        !stderr.contains("не найден: \"/tmp/nonexistent_xray_binary_12345\""),
        "engine version error must happen before binary lookup: {}",
        stderr
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(unix)]
fn test_cli_start_port_in_use_fails_fast_with_engine_error_exit_4() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();
    let listener = std::net::TcpListener::bind(("127.0.0.1", socks_port)).unwrap();
    let _conn = std::net::TcpStream::connect(format!("127.0.0.1:{}", socks_port));

    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);
    let mock_bin = create_mock_engine(&temp_dir);
    let mock_sha256 = sha256_file(&mock_bin);

    let output = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            mock_bin.to_str().unwrap(),
            "--expected-sha256",
            &mock_sha256,
            "--timeout-secs",
            "2",
        ])
        .output()
        .unwrap();

    drop(_conn);
    drop(listener);

    assert_eq!(
        output.status.code(),
        Some(ExitCode::EngineError.as_i32()),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("уже занят"),
        "stderr должен содержать 'уже занят', получено: {}",
        stderr
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(unix)]
fn test_cli_start_sigterm_early_before_ready_stops_cleanly_and_cleans_up() {
    let bin = get_novaray_core_bin();
    let temp_dir = create_temp_dir();
    let (socks_port, http_port) = allocate_test_ports();

    let (config_path, settings_path) = create_valid_test_configs(&temp_dir, socks_port, http_port);
    let mock_bin = create_slow_mock_engine(&temp_dir);
    let mock_sha256 = sha256_file(&mock_bin);

    // Запускаем CLI сервис с медленным стартом движка (2 сек до бинда)
    let child = Command::new(&bin)
        .args([
            "start",
            "-c",
            config_path.to_str().unwrap(),
            "-s",
            settings_path.to_str().unwrap(),
            "-e",
            mock_bin.to_str().unwrap(),
            "--expected-sha256",
            &mock_sha256,
            "--timeout-secs",
            "30",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("CLI процесс должен успешно запуститься");

    let mut guard = ChildGuard::new(child);
    let cli_pid = guard.id();

    // Даем CLI войти в start_with_options и создать runtime-конфиг, но до готовности движка
    let mut temp_runtime_configs_before = Vec::new();
    let find_start = std::time::Instant::now();
    while find_start.elapsed() < std::time::Duration::from_secs(2) {
        temp_runtime_configs_before = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(&format!("novaray_runtime_config_{}_", cli_pid))
                    && name.ends_with(".json")
            })
            .collect();
        if !temp_runtime_configs_before.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        !temp_runtime_configs_before.is_empty(),
        "Файл runtime-конфигурации для CLI PID {} должен появиться на диске до готовности",
        cli_pid
    );

    // Отправляем SIGTERM ДО появления строки готовности
    unsafe {
        libc::kill(cli_pid as libc::pid_t, libc::SIGTERM);
    }

    let status = guard
        .wait_timeout(std::time::Duration::from_secs(5))
        .expect("CLI процесс должен завершиться в течение 5 секунд");

    assert!(
        status.success(),
        "CLI процесс должен завершиться с кодом 0 после раннего SIGTERM, получен: {:?}",
        status
    );

    // Проверяем, что runtime-конфиги удалены после раннего прерывания
    std::thread::sleep(std::time::Duration::from_millis(50));
    for entry in temp_runtime_configs_before {
        assert!(
            !entry.path().exists(),
            "Файл runtime-конфигурации {:?} должен быть удален после ранней остановки",
            entry.path()
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
