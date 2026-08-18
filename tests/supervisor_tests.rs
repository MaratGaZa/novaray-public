use novaray_core::core::{
    is_process_alive, ProcessSupervisor, ReadinessProbe, SupervisorOptions, SupervisorState,
};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static TEST_PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

static TEST_BASE_OFFSET: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

const REDACTION_CHILD_TEST: &str = "supervisor_test_child_emits_sensitive_logs";
const READINESS_CHILD_TEST: &str = "supervisor_test_child_emits_readiness_pattern";

fn current_test_binary() -> String {
    std::env::current_exe()
        .expect("Путь к текущему test binary должен быть доступен")
        .into_os_string()
        .into_string()
        .expect("Путь к test binary должен быть валидным UTF-8")
}

#[test]
#[ignore = "test-only child process; запускается ProcessSupervisor"]
fn supervisor_test_child_emits_sensitive_logs() {
    println!(
        "User 00000000-0000-4000-8000-000000000001 connected to \
         192.0.2.10:443 via [2001:db8::1234]:8443"
    );
    eprintln!("Proxy error at 198.51.100.20");
    io::stdout().flush().expect("stdout flush должен пройти");
    io::stderr().flush().expect("stderr flush должен пройти");
    std::thread::sleep(Duration::from_secs(3));
}

#[test]
#[ignore = "test-only child process; запускается ProcessSupervisor"]
fn supervisor_test_child_emits_readiness_pattern() {
    std::thread::sleep(Duration::from_millis(100));
    println!("Xray 26.3.27 started");
    io::stdout().flush().expect("stdout flush должен пройти");
    std::thread::sleep(Duration::from_secs(5));
}

fn get_base_port_offset() -> u16 {
    *TEST_BASE_OFFSET.get_or_init(|| {
        let pid_part = ((std::process::id() as u16) % 30) * 150;
        let time_part = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u16)
            % 30
            * 50;
        pid_part.wrapping_add(time_part)
    })
}

async fn allocate_isolated_test_port() -> u16 {
    let base = get_base_port_offset();
    let step = TEST_PORT_OFFSET.fetch_add(50, Ordering::SeqCst);
    27000 + ((base.wrapping_add(step)) % 8000)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_normal_lifecycle_state_transitions() {
    let mut supervisor = ProcessSupervisor::new();
    assert_eq!(supervisor.state(), SupervisorState::Stopped);

    // Кроссплатформенный запуск долгоживущего процесса через python3
    let res = supervisor
        .start_with_args("python3", &["-c", "import time; time.sleep(10)"])
        .await;
    assert!(res.is_ok(), "Запуск процесса должен пройти успешно");
    assert_eq!(supervisor.state(), SupervisorState::Ready);
    assert!(supervisor.is_running());

    let pid = supervisor.pid().expect("PID должен быть доступен");
    assert!(
        is_process_alive(pid),
        "Процесс PID {} должен быть активен в ОС",
        pid
    );

    // Пауза 300 мс в multi_thread рантайме (проверка отсутствия race condition в мониторе)
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Останавливаем процесс
    let stop_res = supervisor.stop().await;
    assert!(stop_res.is_ok(), "Остановка должна пройти успешно");
    assert_eq!(supervisor.state(), SupervisorState::Stopped);
    assert!(!supervisor.is_running());

    // Даем ОС закрыть дескрипторы процесса
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !is_process_alive(pid),
        "Процесс PID {} должен быть гарантированно завершён после stop()",
        pid
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_stop_after_delay_actually_kills_process() {
    let mut supervisor = ProcessSupervisor::new();
    let res = supervisor
        .start_with_args("python3", &["-c", "import time; time.sleep(30)"])
        .await;
    assert!(res.is_ok());

    let pid = supervisor.pid().unwrap();
    assert!(is_process_alive(pid));

    // Имитируем реальную работу в течение 500 мс
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Вызываем stop()
    let stop_res = supervisor.stop().await;
    assert!(stop_res.is_ok());
    assert_eq!(supervisor.state(), SupervisorState::Stopped);

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !is_process_alive(pid),
        "Процесс PID {} должен быть гарантированно уничтожен после stop()",
        pid
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_drop_kills_child_process() {
    let pid = {
        let mut supervisor = ProcessSupervisor::new();
        let res = supervisor
            .start_with_args("python3", &["-c", "import time; time.sleep(30)"])
            .await;
        assert!(res.is_ok());
        let p = supervisor.pid().unwrap();
        assert!(is_process_alive(p));
        tokio::time::sleep(Duration::from_millis(200)).await;
        p
        // supervisor сбрасывается по Drop
    };

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !is_process_alive(pid),
        "Процесс PID {} должен быть уничтожен при Drop супервизора",
        pid
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_immediate_probe_fails_on_early_exit_0() {
    // Выполняем 10 итераций для доказательства отсутствия гонки в проверке раннего завершения
    for _ in 0..10 {
        let mut supervisor = ProcessSupervisor::new();

        #[cfg(unix)]
        let res = supervisor.start_with_args("sh", &["-c", "exit 0"]).await;
        #[cfg(windows)]
        let res = supervisor.start_with_args("cmd", &["/c", "exit 0"]).await;
        #[cfg(not(any(unix, windows)))]
        let res = supervisor.start_with_args("true", &[]).await;

        assert!(
            res.is_err(),
            "Раннее завершение с exit 0 должно отклоняться readiness probe"
        );
        assert!(
            matches!(supervisor.state(), SupervisorState::Failed(_)),
            "Состояние супервизора должно быть Failed при раннем завершении, текущее: {}",
            supervisor.state()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_log_drain_and_redaction() {
    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::Immediate,
        readiness_timeout: Duration::from_secs(5),
        graceful_shutdown_timeout: Duration::from_secs(2),
        max_log_lines: 500,
        runtime_config_cleanup: None,
        redact_logs: true,
    };
    let mut supervisor = ProcessSupervisor::with_options(options);

    // Запускаем текущий Rust test binary как контролируемый child process. Это исключает
    // platform-specific различия python launcher и pipe buffering на Windows runner.
    let test_binary = current_test_binary();
    let res = supervisor
        .start_with_args(
            &test_binary,
            &["--ignored", "--exact", REDACTION_CHILD_TEST, "--nocapture"],
        )
        .await;
    assert!(res.is_ok());

    let start = tokio::time::Instant::now();
    let mut all_logs = String::new();
    while start.elapsed() < Duration::from_secs(5) {
        let logs = supervisor.get_logs().await;
        all_logs = logs.join("\n");
        if all_logs.contains("[REDACTED-UUID]")
            && all_logs.contains("[REDACTED-IP]")
            && all_logs.contains("[[REDACTED-IPV6]]:8443")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !all_logs.is_empty(),
        "Логи должны быть вычитаны из stdout/stderr"
    );
    assert!(
        !all_logs.contains("00000000-0000-4000-8000-000000000001"),
        "UUID не должен присутствовать в сырых логах"
    );
    assert!(
        !all_logs.contains("192.0.2.10"),
        "IPv4 адрес не должен присутствовать в сырых логах"
    );
    assert!(
        !all_logs.contains("2001:db8::1234"),
        "IPv6 адрес не должен присутствовать в сырых логах"
    );
    assert!(
        all_logs.contains("[REDACTED-UUID]"),
        "UUID должен быть замаскирован"
    );
    assert!(
        all_logs.contains("[REDACTED-IP]"),
        "IPv4 должен быть замаскирован"
    );
    assert!(
        all_logs.contains("[REDACTED-IPV6]"),
        "IPv6 должен быть замаскирован"
    );

    let _ = supervisor.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_log_drain_prevents_pipe_buffer_deadlock() {
    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::Immediate,
        readiness_timeout: Duration::from_secs(10),
        graceful_shutdown_timeout: Duration::from_secs(2),
        max_log_lines: 1000,
        runtime_config_cleanup: None,
        redact_logs: false,
    };
    let mut supervisor = ProcessSupervisor::with_options(options);

    // Интенсивно выводим 5000 строк в stdout и 5000 строк в stderr (переполнение 64KB pipe buffer)
    let py_script = "import sys, time; [print(f'out {i}') for i in range(5000)]; [print(f'err {i}', file=sys.stderr) for i in range(5000)]; sys.stdout.flush(); sys.stderr.flush(); time.sleep(1)";
    let res = supervisor
        .start_with_args("python3", &["-u", "-c", py_script])
        .await;
    assert!(
        res.is_ok(),
        "Запуск интенсивного генератора логов должен пройти успешно"
    );

    // Ждем завершения генерации и вычитки
    let start = tokio::time::Instant::now();
    let mut has_drained_5000 = false;
    while start.elapsed() < Duration::from_secs(8) {
        let logs = supervisor.get_logs().await;
        let combined = logs.join("\n");
        if combined.contains("out 4999") || combined.contains("err 4999") {
            has_drained_5000 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    assert!(
        has_drained_5000,
        "Все 5000 строк логов должны быть успешно вычитаны без deadlock pipe buffer"
    );

    let final_logs = supervisor.get_logs().await;
    assert!(
        final_logs.len() <= 1000,
        "Кольцевой буфер должен быть ограничен max_log_lines (1000)"
    );

    let _ = supervisor.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_spontaneous_child_crash_transitions_to_failed() {
    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::Immediate,
        readiness_timeout: Duration::from_secs(5),
        graceful_shutdown_timeout: Duration::from_secs(1),
        max_log_lines: 100,
        runtime_config_cleanup: None,
        redact_logs: true,
    };
    let mut supervisor = ProcessSupervisor::with_options(options);

    // Запускаем процесс, который успешно становится Ready (спит 200мс), а затем падает с кодом 42
    let py_script = "import sys, time; time.sleep(0.2); sys.exit(42)";
    let res = supervisor
        .start_with_args("python3", &["-u", "-c", py_script])
        .await;
    assert!(res.is_ok());
    assert_eq!(supervisor.state(), SupervisorState::Ready);

    let pid = supervisor.pid().expect("PID должен быть доступен");

    // Ожидаем самопроизвольного падения процесса
    let start = tokio::time::Instant::now();
    let mut detected_crash = false;
    while start.elapsed() < Duration::from_secs(5) {
        if let SupervisorState::Failed(msg) = supervisor.state() {
            assert!(
                msg.contains("42") || msg.contains("exit"),
                "Сообщение об ошибке должно отражать код падения процесса: {}",
                msg
            );
            detected_crash = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        detected_crash,
        "Супервизор должен обнаружить самопроизвольное падение и перейти в Failed"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !is_process_alive(pid),
        "Упавший процесс должен отсутствовать в ОС"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_tcp_readiness_probe_success() {
    let port = allocate_isolated_test_port().await;

    let py_server = format!(
        "import socket, time; s = socket.socket(); s.bind(('127.0.0.1', {})); s.listen(1); time.sleep(5)",
        port
    );

    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::TcpPort(port),
        readiness_timeout: Duration::from_secs(5),
        graceful_shutdown_timeout: Duration::from_secs(2),
        max_log_lines: 100,
        runtime_config_cleanup: None,
        redact_logs: true,
    };

    let mut supervisor = ProcessSupervisor::with_options(options);
    let res = supervisor
        .start_with_args("python3", &["-c", &py_server])
        .await;
    assert!(
        res.is_ok(),
        "Readiness probe по TCP порту должен успешно завершиться"
    );
    assert_eq!(supervisor.state(), SupervisorState::Ready);

    let pid = supervisor.pid().unwrap();
    assert!(is_process_alive(pid));

    let _ = supervisor.stop().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!is_process_alive(pid));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_readiness_timeout_fails_safely() {
    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::TcpPort(59999),
        readiness_timeout: Duration::from_millis(150),
        graceful_shutdown_timeout: Duration::from_millis(100),
        max_log_lines: 100,
        runtime_config_cleanup: None,
        redact_logs: true,
    };

    let mut supervisor = ProcessSupervisor::with_options(options);
    let res = supervisor
        .start_with_args("python3", &["-c", "import time; time.sleep(10)"])
        .await;

    assert!(
        res.is_err(),
        "Таймаут readiness probe должен вернуть ошибку"
    );
    assert!(matches!(supervisor.state(), SupervisorState::Failed(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_log_pattern_readiness_probe() {
    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::LogPattern("Xray 26.3.27 started".to_string()),
        readiness_timeout: Duration::from_secs(3),
        graceful_shutdown_timeout: Duration::from_secs(1),
        max_log_lines: 100,
        runtime_config_cleanup: None,
        redact_logs: true,
    };

    let mut supervisor = ProcessSupervisor::with_options(options);
    let test_binary = current_test_binary();
    let res = supervisor
        .start_with_args(
            &test_binary,
            &["--ignored", "--exact", READINESS_CHILD_TEST, "--nocapture"],
        )
        .await;
    assert!(
        res.is_ok(),
        "Log pattern probe должен найти строку и перевести в Ready"
    );
    assert_eq!(supervisor.state(), SupervisorState::Ready);

    let _ = supervisor.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_supervisor_runtime_config_cleanup() {
    let temp_path = std::env::temp_dir().join(format!(
        "novaray_test_runtime_config_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&temp_path, "{}").unwrap();
    assert!(temp_path.exists());

    let options = SupervisorOptions {
        readiness_probe: ReadinessProbe::Immediate,
        readiness_timeout: Duration::from_secs(2),
        graceful_shutdown_timeout: Duration::from_secs(1),
        max_log_lines: 100,
        runtime_config_cleanup: Some(temp_path.clone()),
        redact_logs: true,
    };

    let mut supervisor = ProcessSupervisor::with_options(options);
    let res = supervisor
        .start_with_args("python3", &["-c", "import time; time.sleep(5)"])
        .await;
    assert!(res.is_ok());

    let stop_res = supervisor.stop().await;
    assert!(stop_res.is_ok());

    assert!(
        !temp_path.exists(),
        "Временный runtime-конфиг должен быть автоматически удален при остановке"
    );
}
