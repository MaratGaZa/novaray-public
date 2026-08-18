//! Управление сетевым движком (Xray-core / sing-box), артефактами и безопасной runtime-конфигурацией.
//!
//! Обеспечивает:
//! - Верификацию бинарных артефактов движка (проверка наличия, прав на исполнение, сверка SHA-256 чексуммы).
//! - Безопасную запись runtime-конфигураций с ограниченными правами доступа (0600 на Unix, чтение/запись только владельцем).
//! - Гарантированное удаление runtime-конфигураций, содержащих секреты, при остановке или сбросе.
//! - Оркестрацию жизненного цикла `ProxyService`: связывание `AppConfig`, генератора Xray JSON и `ProcessSupervisor`.

use crate::config::{AppConfig, UserSettings};
use crate::core::{ProcessSupervisor, ReadinessProbe, SupervisorOptions, SupervisorState};
use crate::xray_generator::XrayConfigGenerator;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, watch};
use tracing::{debug, info};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Ошибки управления сетевым движком и runtime-конфигурацией
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Прокси-сервис уже запущен (PID {0}). Сначала вызовите stop()")]
    AlreadyRunning(u32),

    #[error("Локальный порт {0} уже занят другим процессом")]
    PortInUse(u16),

    #[error("Бинарный файл движка не найден: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Файл движка не имеет прав на исполнение: {0}")]
    PermissionDenied(PathBuf),

    #[error("Несоответствие контрольной суммы SHA-256 бинарного файла: ожидалось {expected}, получено {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Pre-flight проверка конфигурации движком не пройдена: {0}")]
    ConfigPreflightFailed(String),

    #[error("Ошибка I/O при работе с движком или конфигурацией: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Ошибка сериализации конфигурации: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Ошибка валидации конфигурации приложения: {0}")]
    ConfigValidationError(String),

    #[error("Ошибка супервизора процессов: {0}")]
    SupervisorError(String),
}

/// Метаданные верифицированного бинарного артефакта движка
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Зафиксированный релиз сетевого движка (архив дистрибутива и контрольные суммы)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEngineRelease {
    pub engine_name: &'static str,
    pub version: &'static str,
    pub revision: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub archive_name: &'static str,
    /// SHA-256 контрольная сумма загружаемого ZIP-архива дистрибутива
    pub archive_sha256: &'static str,
    /// SHA-256 контрольная сумма распакованного бинарника (None, если ещё не верифицирован для целевой платформы)
    pub binary_sha256: Option<&'static str>,
}

/// Возвращает зафиксированные релизы сетевых движков (Xray-core v26.3.27)
pub fn get_pinned_engine_releases() -> &'static [PinnedEngineRelease] {
    &[
        PinnedEngineRelease {
            engine_name: "xray-core",
            version: "v26.3.27",
            revision: "d2758a023cd7f4174a5a5fa4ff66e487d4342ba0",
            target_os: "macos",
            target_arch: "arm64",
            archive_name: "Xray-macos-arm64-v8a.zip",
            archive_sha256: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
            binary_sha256: None,
        },
        PinnedEngineRelease {
            engine_name: "xray-core",
            version: "v26.3.27",
            revision: "d2758a023cd7f4174a5a5fa4ff66e487d4342ba0",
            target_os: "linux",
            target_arch: "arm64",
            archive_name: "Xray-linux-arm64-v8a.zip",
            archive_sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
            binary_sha256: None,
        },
        PinnedEngineRelease {
            engine_name: "xray-core",
            version: "v26.3.27",
            revision: "d2758a023cd7f4174a5a5fa4ff66e487d4342ba0",
            target_os: "linux",
            target_arch: "x86_64",
            archive_name: "Xray-linux-64.zip",
            archive_sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
            binary_sha256: None,
        },
    ]
}

fn normalize_os(os: &str) -> &str {
    match os.to_ascii_lowercase().as_str() {
        "macos" | "darwin" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        _ => os,
    }
}

fn normalize_arch(arch: &str) -> &str {
    match arch.to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => "arm64",
        "x86_64" | "amd64" | "x64" => "x86_64",
        _ => arch,
    }
}

/// Находит ожидаемый SHA-256 ZIP-архива для текущей платформы из зафиксированных релизов
pub fn find_pinned_archive_checksum(engine_name: &str, version: &str) -> Option<&'static str> {
    let current_os = normalize_os(std::env::consts::OS);
    let current_arch = normalize_arch(std::env::consts::ARCH);
    get_pinned_engine_releases()
        .iter()
        .find(|r| {
            r.engine_name.eq_ignore_ascii_case(engine_name)
                && r.version.eq_ignore_ascii_case(version)
                && normalize_os(r.target_os).eq_ignore_ascii_case(current_os)
                && normalize_arch(r.target_arch).eq_ignore_ascii_case(current_arch)
        })
        .map(|r| r.archive_sha256)
}

/// Находит ожидаемый SHA-256 распакованного бинарника для текущей платформы из зафиксированных релизов
pub fn find_pinned_binary_checksum(engine_name: &str, version: &str) -> Option<&'static str> {
    let current_os = normalize_os(std::env::consts::OS);
    let current_arch = normalize_arch(std::env::consts::ARCH);
    get_pinned_engine_releases()
        .iter()
        .find(|r| {
            r.engine_name.eq_ignore_ascii_case(engine_name)
                && r.version.eq_ignore_ascii_case(version)
                && normalize_os(r.target_os).eq_ignore_ascii_case(current_os)
                && normalize_arch(r.target_arch).eq_ignore_ascii_case(current_arch)
        })
        .and_then(|r| r.binary_sha256)
}

/// Находит ожидаемый SHA-256 ZIP-архива для текущей платформы из зафиксированных релизов (обратная совместимость)
pub fn find_pinned_checksum(engine_name: &str, version: &str) -> Option<&'static str> {
    find_pinned_archive_checksum(engine_name, version)
}

/// Проверяет бинарный файл движка на существование, права на исполнение и соответствие SHA-256 (если задана)
pub fn verify_engine_artifact(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<EngineArtifact, EngineError> {
    if !path.exists() || !path.is_file() {
        return Err(EngineError::BinaryNotFound(path.to_path_buf()));
    }

    let metadata = std::fs::metadata(path)?;

    #[cfg(unix)]
    {
        let permissions = metadata.permissions();
        let mode = permissions.mode();
        if mode & 0o111 == 0 {
            return Err(EngineError::PermissionDenied(path.to_path_buf()));
        }
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let actual_sha256 = hex::encode(hasher.finalize());

    if let Some(expected) = expected_sha256 {
        let expected_clean = expected.trim().to_lowercase();
        if actual_sha256 != expected_clean {
            return Err(EngineError::ChecksumMismatch {
                expected: expected_clean,
                actual: actual_sha256,
            });
        }
    }

    Ok(EngineArtifact {
        path: path.to_path_buf(),
        sha256: actual_sha256,
        size_bytes: metadata.len(),
    })
}

/// Выполняет pre-flight проверку сгенерированной конфигурации движком (`xray run -test -c <config_path>`) с таймаутом
pub async fn preflight_check_config(
    engine_binary: &Path,
    config_path: &Path,
    timeout: Duration,
) -> Result<(), EngineError> {
    let mut cmd = tokio::process::Command::new(engine_binary);
    cmd.kill_on_drop(true)
        .args(["run", "-test", "-c"])
        .arg(config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let child = cmd.spawn().map_err(EngineError::IoError)?;
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(res) => res.map_err(EngineError::IoError)?,
        Err(_) => {
            return Err(EngineError::ConfigPreflightFailed(format!(
                "Pre-flight проверка конфигурации превысила таймаут {:?}",
                timeout
            )));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let err_msg = format!("stdout: {}, stderr: {}", stdout.trim(), stderr.trim());
        return Err(EngineError::ConfigPreflightFailed(err_msg));
    }

    Ok(())
}

static RUNTIME_CONFIG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Безопасно записывает runtime-конфигурацию во временный файл с правами 0600 (Unix)
pub fn write_secure_runtime_config(
    dir: Option<&Path>,
    content: &str,
) -> Result<PathBuf, EngineError> {
    let base_dir = dir
        .map(|d| d.to_path_buf())
        .unwrap_or_else(std::env::temp_dir);

    if !base_dir.exists() {
        std::fs::create_dir_all(&base_dir)?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        options.mode(0o600); // Чтение и запись строго для владельца
    }

    for _ in 0..100 {
        let count = RUNTIME_CONFIG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let file_name = format!(
            "novaray_runtime_config_{}_{}_{}.json",
            std::process::id(),
            count,
            now_nanos
        );
        let target_path = base_dir.join(file_name);

        match options.open(&target_path) {
            Ok(mut file) => {
                file.write_all(content.as_bytes())?;
                file.flush()?;
                debug!("Runtime-конфигурация успешно записана в {:?}", target_path);
                return Ok(target_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(e) => return Err(EngineError::IoError(e)),
        }
    }

    Err(EngineError::IoError(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "Не удалось создать уникальный файл runtime-конфигурации",
    )))
}

/// Удаляет файл runtime-конфигурации с диска
pub fn cleanup_runtime_config(path: &Path) -> Result<(), EngineError> {
    if path.exists() {
        std::fs::remove_file(path)?;
        debug!("Runtime-конфигурация удалена: {:?}", path);
    }
    Ok(())
}

/// Опции запуска ProxyService
#[derive(Debug, Clone)]
pub struct ProxyServiceOptions {
    /// Ожидаемая контрольная сумма SHA-256 (None для пропуска)
    pub expected_sha256: Option<String>,
    /// Выполнять ли pre-flight валидацию конфигурации через CLI движка (`xray run -test -c <path>`)
    pub enable_preflight_check: bool,
    /// Таймаут для pre-flight валидации конфигурации движком
    pub preflight_timeout: Duration,
    /// Таймаут ожидания готовности сетевого порта
    pub readiness_timeout: Duration,
    /// Таймаут graceful stop перед forced kill
    pub graceful_shutdown_timeout: Duration,
    /// Максимальное число сохраняемых строк логов
    pub max_log_lines: usize,
    /// Маскировать ли чувствительные данные в логах
    pub redact_logs: bool,
}

impl Default for ProxyServiceOptions {
    fn default() -> Self {
        Self {
            expected_sha256: None,
            enable_preflight_check: true,
            preflight_timeout: Duration::from_secs(5),
            readiness_timeout: Duration::from_secs(5),
            graceful_shutdown_timeout: Duration::from_secs(3),
            max_log_lines: 1000,
            redact_logs: true,
        }
    }
}

/// Высокоуровневый сервис оркестрации проксирования (ProxyService)
pub struct ProxyService {
    supervisor: ProcessSupervisor,
    runtime_config_path: Option<PathBuf>,
}

impl Default for ProxyService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyService {
    /// Создает экземпляр ProxyService
    pub fn new() -> Self {
        Self {
            supervisor: ProcessSupervisor::new(),
            runtime_config_path: None,
        }
    }

    /// Запускает прокси-сервис с настройками по умолчанию
    pub async fn start(
        &mut self,
        engine_binary: &Path,
        expected_sha256: Option<&str>,
        config: &AppConfig,
        settings: &UserSettings,
    ) -> Result<(), EngineError> {
        let options = ProxyServiceOptions {
            expected_sha256: expected_sha256.map(String::from),
            ..Default::default()
        };
        self.start_with_options(engine_binary, config, settings, &options)
            .await
    }

    /// Запускает прокси-сервис с расширенными опциями (включая pre-flight проверку)
    pub async fn start_with_options(
        &mut self,
        engine_binary: &Path,
        config: &AppConfig,
        settings: &UserSettings,
        options: &ProxyServiceOptions,
    ) -> Result<(), EngineError> {
        // 0. Защита от повторного запуска работающего сервиса
        if self.is_running() {
            let pid = self.pid().unwrap_or(0);
            return Err(EngineError::AlreadyRunning(pid));
        }

        // 1. Валидация конфигурации в Core
        config
            .validate()
            .map_err(EngineError::ConfigValidationError)?;
        settings
            .validate()
            .map_err(EngineError::ConfigValidationError)?;

        let active_profile = config.find_active_profile().ok_or_else(|| {
            EngineError::ConfigValidationError("Активный профиль не найден".to_string())
        })?;

        // 2. Проверка доступности локальных портов до старта (защита от ложного readiness при занятом порте)
        let socks_port = settings.client.local_socks_port;
        let http_port = settings.client.local_http_port;
        if std::net::TcpListener::bind(("127.0.0.1", socks_port)).is_err() {
            return Err(EngineError::PortInUse(socks_port));
        }
        if std::net::TcpListener::bind(("127.0.0.1", http_port)).is_err() {
            return Err(EngineError::PortInUse(http_port));
        }

        // 3. Верификация бинарного артефакта
        let _artifact = verify_engine_artifact(engine_binary, options.expected_sha256.as_deref())?;

        // 4. Генерация Xray JSON
        let xray_value = XrayConfigGenerator::generate(active_profile, settings);
        let xray_json = serde_json::to_string_pretty(&xray_value)?;

        // 5. Безопасная запись временного конфига (0600)
        let config_path = write_secure_runtime_config(None, &xray_json)?;
        self.runtime_config_path = Some(config_path.clone());

        // 6. Pre-flight проверка CLI движка (`xray run -test -c`)
        if options.enable_preflight_check {
            if let Err(e) =
                preflight_check_config(engine_binary, &config_path, options.preflight_timeout).await
            {
                let _ = cleanup_runtime_config(&config_path);
                self.runtime_config_path = None;
                return Err(e);
            }
        }

        // 7. Конфигурация супервизора
        let supervisor_options = SupervisorOptions {
            readiness_probe: ReadinessProbe::TcpPort(settings.client.local_socks_port),
            readiness_timeout: options.readiness_timeout,
            graceful_shutdown_timeout: options.graceful_shutdown_timeout,
            max_log_lines: options.max_log_lines,
            runtime_config_cleanup: Some(config_path.clone()),
            redact_logs: options.redact_logs,
        };

        self.supervisor = ProcessSupervisor::with_options(supervisor_options);

        // 8. Запуск процесса движка
        let config_path_str = config_path.to_string_lossy().to_string();
        let args = ["run", "-c", &config_path_str];

        info!(
            "Запуск движка {:?} с runtime-конфигурацией {:?}",
            engine_binary, config_path
        );
        if let Err(e) = self
            .supervisor
            .start_with_args(engine_binary.to_string_lossy().as_ref(), &args)
            .await
        {
            let _ = cleanup_runtime_config(&config_path);
            self.runtime_config_path = None;
            return Err(EngineError::SupervisorError(e.to_string()));
        }

        Ok(())
    }

    /// Останавливает прокси-сервис и гарантирует удаление runtime-файлов
    pub async fn stop(&mut self) -> Result<(), EngineError> {
        let stop_res = self
            .supervisor
            .stop()
            .await
            .map_err(|e| EngineError::SupervisorError(e.to_string()));

        if let Some(ref path) = self.runtime_config_path.take() {
            let _ = cleanup_runtime_config(path);
        }

        stop_res
    }

    /// Текущее состояние супервизора
    pub fn state(&self) -> SupervisorState {
        self.supervisor.state()
    }

    /// Активен ли сервис
    pub fn is_running(&self) -> bool {
        self.supervisor.is_running()
    }

    /// PID активного процесса движка
    pub fn pid(&self) -> Option<u32> {
        self.supervisor.pid()
    }

    /// Получить буферизованные логи
    pub async fn get_logs(&self) -> Vec<String> {
        self.supervisor.get_logs().await
    }

    /// Подписка на обновление состояния
    pub fn subscribe_state(&self) -> watch::Receiver<SupervisorState> {
        self.supervisor.subscribe_state()
    }

    /// Подписка на поток логов
    pub fn subscribe_logs(&self) -> broadcast::Receiver<String> {
        self.supervisor.subscribe_logs()
    }
}

impl Drop for ProxyService {
    fn drop(&mut self) {
        if let Some(ref path) = self.runtime_config_path.take() {
            let _ = cleanup_runtime_config(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_releases_catalog_and_lookup() {
        let releases = get_pinned_engine_releases();
        assert!(!releases.is_empty());
        assert_eq!(releases[0].engine_name, "xray-core");
        assert_eq!(releases[0].version, "v26.3.27");

        let checksum = find_pinned_checksum("xray-core", "v26.3.27");
        if std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64" {
            assert_eq!(
                checksum,
                Some("2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf")
            );
        }
    }

    #[test]
    fn test_verify_nonexistent_binary_fails() {
        let res = verify_engine_artifact(Path::new("/nonexistent_engine_bin_12345"), None);
        assert!(matches!(res, Err(EngineError::BinaryNotFound(_))));
    }

    #[test]
    fn test_verify_valid_file_and_checksum() {
        let temp_dir = std::env::temp_dir();
        let test_bin = temp_dir.join(format!("test_bin_{}.sh", std::process::id()));
        std::fs::write(&test_bin, b"#!/bin/sh\necho test\n").unwrap();

        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&test_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&test_bin, perms).unwrap();
        }

        let verified = verify_engine_artifact(&test_bin, None).expect("Должно пройти проверку");
        assert_eq!(verified.path, test_bin);

        // Проверка корректной контрольной суммы
        let res_correct = verify_engine_artifact(&test_bin, Some(&verified.sha256));
        assert!(res_correct.is_ok());

        // Проверка неверной контрольной суммы
        let res_wrong = verify_engine_artifact(
            &test_bin,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        assert!(matches!(
            res_wrong,
            Err(EngineError::ChecksumMismatch { .. })
        ));

        let _ = std::fs::remove_file(&test_bin);
    }

    #[test]
    fn test_write_secure_runtime_config_creates_file_and_cleans_up() {
        let content = "{\"test\": \"secret_value_123\"}";
        let path = write_secure_runtime_config(None, content).expect("Запись должна быть успешной");
        assert!(path.exists());

        #[cfg(unix)]
        {
            let perms = std::fs::metadata(&path).unwrap().permissions();
            let mode = perms.mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Права на runtime-конфигурацию должны быть строго 0600 (rw-------)"
            );
        }

        let read_content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_content, content);

        cleanup_runtime_config(&path).unwrap();
        assert!(!path.exists(), "Файл должен быть удален после cleanup");
    }
}
