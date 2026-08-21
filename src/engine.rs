//! Управление сетевым движком (Xray-core / sing-box), артефактами и безопасной runtime-конфигурацией.
//!
//! Обеспечивает:
//! - Верификацию бинарных артефактов движка (проверка наличия, прав на исполнение, сверка SHA-256 чексуммы).
//! - Безопасную запись runtime-конфигураций с ограниченными правами доступа (0600 на Unix, чтение/запись только владельцем).
//! - Гарантированное удаление runtime-конфигураций, содержащих секреты, при остановке или сбросе.
//! - Оркестрацию жизненного цикла `ProxyService`: связывание `AppConfig`, engine config strategy и `ProcessSupervisor`.

use crate::config::{AppConfig, UserSettings};
use crate::config_generator::{EngineConfigDialect, EngineConfigStrategy};
use crate::core::{ProcessSupervisor, ReadinessProbe, SupervisorOptions, SupervisorState};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
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

    #[error(transparent)]
    PinnedBinaryChecksumMismatch(Box<PinnedBinaryChecksumMismatch>),

    #[error(transparent)]
    MissingPinnedBinaryChecksum(Box<MissingPinnedBinaryChecksum>),

    #[error("Ожидаемая SHA-256 контрольная сумма бинарника движка не задана; запуск без проверки запрещён")]
    MissingExpectedChecksum,

    #[error("Конфигурационный диалект {dialect:?} несовместим с {engine_name} {version}; запуск запрещён")]
    IncompatibleEngineRelease {
        engine_name: String,
        version: String,
        dialect: EngineConfigDialect,
    },

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

/// Контекст mismatch автоматической pinned checksum.
#[derive(Debug, Error)]
#[error(
    "Бинарник не совпадает с pinned артефактом {engine_name} {version} для {target_os}/{target_arch}: ожидалось {expected}, получено {actual}. Это может означать другую/неподдерживаемую версию или изменённый артефакт; запуск запрещён"
)]
pub struct PinnedBinaryChecksumMismatch {
    pub engine_name: String,
    pub version: String,
    pub target_os: String,
    pub target_arch: String,
    pub expected: String,
    pub actual: String,
}

/// Контекст отсутствующего pinned binary checksum для выбранной платформы.
#[derive(Debug, Error)]
#[error(
    "Для {engine_name} {version} нет pinned SHA-256 бинарника на {target_os}/{target_arch}; запуск без explicit --expected-sha256 запрещён"
)]
pub struct MissingPinnedBinaryChecksum {
    pub engine_name: String,
    pub version: String,
    pub target_os: String,
    pub target_arch: String,
}

/// Метаданные верифицированного бинарного артефакта движка
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Зафиксированный релиз сетевого движка (архив дистрибутива и контрольные суммы)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PinnedEngineRelease {
    pub engine_name: String,
    pub version: String,
    pub revision: String,
    pub status: EngineReleaseStatus,
    pub config_dialect: EngineConfigDialect,
    pub target_os: String,
    pub target_arch: String,
    pub archive_name: String,
    /// SHA-256 контрольная сумма загружаемого ZIP-архива дистрибутива
    pub archive_sha256: String,
    /// SHA-256 контрольная сумма распакованного бинарника.
    pub binary_sha256: String,
}

/// Lifecycle policy for a catalogued engine release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineReleaseStatus {
    Recommended,
    Supported,
    Deprecated,
    Yanked,
}

#[derive(Debug, Deserialize)]
struct EngineCatalog {
    schema_version: u32,
    declared_targets: Vec<EngineTarget>,
    releases: Vec<PinnedEngineRelease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EngineTarget {
    target_os: String,
    target_arch: String,
}

fn parse_engine_catalog(input: &str) -> Result<EngineCatalog, String> {
    let catalog: EngineCatalog = serde_json::from_str(input)
        .map_err(|error| format!("engine catalog JSON is invalid: {error}"))?;
    validate_engine_catalog(&catalog)?;
    Ok(catalog)
}

// `engine_catalog.json` is the sole checked-in source of engine release metadata.
fn engine_catalog() -> &'static EngineCatalog {
    static CATALOG: OnceLock<EngineCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        parse_engine_catalog(include_str!("../engine_catalog.json"))
            .expect("checked-in engine catalog must satisfy fail-closed invariants")
    })
}

/// Returns catalogued releases from the checked-in, offline manifest.
pub fn get_pinned_engine_releases() -> &'static [PinnedEngineRelease] {
    &engine_catalog().releases
}

/// Returns the only default release version allowed for an engine family.
pub fn recommended_engine_version(engine_name: &str) -> Option<&'static str> {
    recommended_engine_version_in_releases(get_pinned_engine_releases(), engine_name)
}

fn recommended_engine_version_in_releases<'a>(
    releases: &'a [PinnedEngineRelease],
    engine_name: &str,
) -> Option<&'a str> {
    let versions = releases
        .iter()
        .filter(|release| {
            release.engine_name.eq_ignore_ascii_case(engine_name)
                && release.status == EngineReleaseStatus::Recommended
        })
        .map(|release| release.version.as_str())
        .collect::<BTreeSet<_>>();
    (versions.len() == 1).then(|| *versions.first().expect("checked length"))
}

fn catalog_release_dialect_in_releases(
    releases: &[PinnedEngineRelease],
    engine_name: &str,
    version: &str,
) -> Option<EngineConfigDialect> {
    releases
        .iter()
        .find(|release| {
            release.engine_name.eq_ignore_ascii_case(engine_name)
                && release.version.eq_ignore_ascii_case(version)
                && release.status != EngineReleaseStatus::Yanked
        })
        .map(|release| release.config_dialect)
}

#[cfg(test)]
fn validate_release_compatibility(
    strategy: EngineConfigStrategy,
    version: &str,
) -> Result<(), EngineError> {
    validate_release_compatibility_in_releases(strategy, version, get_pinned_engine_releases())
}

fn validate_release_compatibility_in_releases(
    strategy: EngineConfigStrategy,
    version: &str,
    releases: &[PinnedEngineRelease],
) -> Result<(), EngineError> {
    let engine_name = strategy.engine_name();
    catalog_release_dialect_in_releases(releases, engine_name, version)
        .is_some_and(|dialect| dialect == strategy.config_dialect())
        .then_some(())
        .ok_or_else(|| EngineError::IncompatibleEngineRelease {
            engine_name: engine_name.to_string(),
            version: version.to_string(),
            dialect: strategy.config_dialect(),
        })
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn validate_engine_catalog(catalog: &EngineCatalog) -> Result<(), String> {
    if catalog.schema_version != 1 {
        return Err(format!(
            "unsupported catalog schema version {}",
            catalog.schema_version
        ));
    }
    if catalog.declared_targets.is_empty() || catalog.releases.is_empty() {
        return Err("catalog must declare targets and releases".to_string());
    }

    let targets = catalog
        .declared_targets
        .iter()
        .map(|target| {
            (
                normalize_os(&target.target_os).to_string(),
                normalize_arch(&target.target_arch).to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    if targets.len() != catalog.declared_targets.len() {
        return Err("declared targets must be unique".to_string());
    }

    let mut keys = HashSet::new();
    let mut engine_versions = BTreeSet::new();
    for release in &catalog.releases {
        if !is_lower_sha256(&release.archive_sha256) || !is_lower_sha256(&release.binary_sha256) {
            return Err(format!(
                "{} {} has a malformed checksum",
                release.engine_name, release.version
            ));
        }
        let key = (
            release.engine_name.to_ascii_lowercase(),
            release.version.to_ascii_lowercase(),
            normalize_os(&release.target_os).to_string(),
            normalize_arch(&release.target_arch).to_string(),
        );
        if !keys.insert(key.clone()) {
            return Err(format!(
                "duplicate engine catalog key: {} {} {}/{}",
                key.0, key.1, key.2, key.3
            ));
        }
        if !targets.contains(&(key.2.clone(), key.3.clone())) {
            return Err(format!("undeclared target in catalog: {}/{}", key.2, key.3));
        }
        engine_versions.insert((key.0, key.1));
    }

    for (engine_name, version) in &engine_versions {
        let entries = catalog.releases.iter().filter(|release| {
            release.engine_name.eq_ignore_ascii_case(engine_name)
                && release.version.eq_ignore_ascii_case(version)
        });
        let statuses = entries
            .clone()
            .map(|release| release.status)
            .collect::<HashSet<_>>();
        if statuses.len() != 1 {
            return Err(format!(
                "{engine_name} {version} must use one lifecycle status"
            ));
        }
        let dialects = entries
            .clone()
            .map(|release| release.config_dialect)
            .collect::<HashSet<_>>();
        if dialects.len() != 1 {
            return Err(format!(
                "{engine_name} {version} must use one configuration dialect"
            ));
        }
        let coverage = entries
            .map(|release| {
                (
                    normalize_os(&release.target_os).to_string(),
                    normalize_arch(&release.target_arch).to_string(),
                )
            })
            .collect::<BTreeSet<_>>();
        if coverage != targets {
            return Err(format!(
                "{engine_name} {version} does not cover every declared target"
            ));
        }
    }

    let engines = catalog
        .releases
        .iter()
        .map(|release| release.engine_name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    for engine_name in engines {
        let recommended = catalog
            .releases
            .iter()
            .filter(|release| {
                release.engine_name.eq_ignore_ascii_case(&engine_name)
                    && release.status == EngineReleaseStatus::Recommended
            })
            .map(|release| release.version.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if recommended.len() != 1 {
            return Err(format!(
                "{engine_name} must have exactly one recommended version"
            ));
        }
    }
    Ok(())
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
                && normalize_os(&r.target_os).eq_ignore_ascii_case(current_os)
                && normalize_arch(&r.target_arch).eq_ignore_ascii_case(current_arch)
        })
        .map(|r| r.archive_sha256.as_str())
}

/// Находит ожидаемый SHA-256 распакованного бинарника для текущей платформы из зафиксированных релизов
pub fn find_pinned_binary_checksum(engine_name: &str, version: &str) -> Option<&'static str> {
    find_pinned_binary_checksum_for_target(
        engine_name,
        version,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn find_pinned_binary_checksum_for_target(
    engine_name: &str,
    version: &str,
    target_os: &str,
    target_arch: &str,
) -> Option<&'static str> {
    find_pinned_binary_checksum_in_releases(
        get_pinned_engine_releases(),
        engine_name,
        version,
        target_os,
        target_arch,
    )
}

fn find_pinned_binary_checksum_in_releases<'a>(
    releases: &'a [PinnedEngineRelease],
    engine_name: &str,
    version: &str,
    target_os: &str,
    target_arch: &str,
) -> Option<&'a str> {
    let target_os = normalize_os(target_os);
    let target_arch = normalize_arch(target_arch);
    releases
        .iter()
        .find(|r| {
            r.engine_name.eq_ignore_ascii_case(engine_name)
                && r.version.eq_ignore_ascii_case(version)
                && r.status != EngineReleaseStatus::Yanked
                && normalize_os(&r.target_os).eq_ignore_ascii_case(target_os)
                && normalize_arch(&r.target_arch).eq_ignore_ascii_case(target_arch)
        })
        .map(|r| r.binary_sha256.as_str())
}

/// Находит ожидаемый SHA-256 ZIP-архива для текущей платформы из зафиксированных релизов (обратная совместимость)
pub fn find_pinned_checksum(engine_name: &str, version: &str) -> Option<&'static str> {
    find_pinned_archive_checksum(engine_name, version)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedBinaryChecksumSource {
    Explicit,
    Pinned {
        engine_name: String,
        version: String,
        target_os: String,
        target_arch: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedBinaryChecksum<'a> {
    value: Cow<'a, str>,
    source: ExpectedBinaryChecksumSource,
}

fn resolve_expected_binary_checksum_for_target<'a>(
    strategy: EngineConfigStrategy,
    explicit_sha256: Option<&'a str>,
    target_os: &str,
    target_arch: &str,
) -> Result<ExpectedBinaryChecksum<'a>, EngineError> {
    resolve_expected_binary_checksum_in_releases(
        get_pinned_engine_releases(),
        strategy,
        explicit_sha256,
        target_os,
        target_arch,
    )
}

fn resolve_expected_binary_checksum_in_releases<'a>(
    releases: &'a [PinnedEngineRelease],
    strategy: EngineConfigStrategy,
    explicit_sha256: Option<&'a str>,
    target_os: &str,
    target_arch: &str,
) -> Result<ExpectedBinaryChecksum<'a>, EngineError> {
    let target_os = normalize_os(target_os).to_string();
    let target_arch = normalize_arch(target_arch).to_string();
    let engine_name = strategy.engine_name().to_string();
    let version = recommended_engine_version_in_releases(releases, &engine_name)
        .ok_or(EngineError::MissingExpectedChecksum)?
        .to_string();
    validate_release_compatibility_in_releases(strategy, &version, releases)?;

    if let Some(explicit) = explicit_sha256 {
        return Ok(ExpectedBinaryChecksum {
            value: Cow::Borrowed(explicit),
            source: ExpectedBinaryChecksumSource::Explicit,
        });
    }

    let value = find_pinned_binary_checksum_in_releases(
        releases,
        &engine_name,
        &version,
        &target_os,
        &target_arch,
    )
    .ok_or_else(|| {
        EngineError::MissingPinnedBinaryChecksum(Box::new(MissingPinnedBinaryChecksum {
            engine_name: engine_name.clone(),
            version: version.clone(),
            target_os: target_os.clone(),
            target_arch: target_arch.clone(),
        }))
    })?;

    Ok(ExpectedBinaryChecksum {
        value: Cow::Borrowed(value),
        source: ExpectedBinaryChecksumSource::Pinned {
            engine_name,
            version,
            target_os,
            target_arch,
        },
    })
}

fn verify_selected_engine_artifact(
    path: &Path,
    strategy: EngineConfigStrategy,
    explicit_sha256: Option<&str>,
) -> Result<EngineArtifact, EngineError> {
    verify_selected_engine_artifact_for_target(
        path,
        strategy,
        explicit_sha256,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn verify_selected_engine_artifact_for_target(
    path: &Path,
    strategy: EngineConfigStrategy,
    explicit_sha256: Option<&str>,
    target_os: &str,
    target_arch: &str,
) -> Result<EngineArtifact, EngineError> {
    // Проверяем сам бинарник до поиска platform pin: неверный путь не должен маскироваться
    // отсутствием checksum для выбранных OS/arch.
    validate_engine_binary_path(path)?;
    let expected = resolve_expected_binary_checksum_for_target(
        strategy,
        explicit_sha256,
        target_os,
        target_arch,
    )?;
    match verify_engine_artifact(path, Some(expected.value.as_ref())) {
        Err(EngineError::ChecksumMismatch {
            expected: expected_hash,
            actual,
        }) => match expected.source {
            ExpectedBinaryChecksumSource::Explicit => Err(EngineError::ChecksumMismatch {
                expected: expected_hash,
                actual,
            }),
            ExpectedBinaryChecksumSource::Pinned {
                engine_name,
                version,
                target_os,
                target_arch,
            } => Err(EngineError::PinnedBinaryChecksumMismatch(Box::new(
                PinnedBinaryChecksumMismatch {
                    engine_name,
                    version,
                    target_os,
                    target_arch,
                    expected: expected_hash,
                    actual,
                },
            ))),
        },
        result => result,
    }
}

fn validate_engine_binary_path(path: &Path) -> Result<(), EngineError> {
    if !path.exists() || !path.is_file() {
        return Err(EngineError::BinaryNotFound(path.to_path_buf()));
    }

    #[cfg(unix)]
    {
        let permissions = std::fs::metadata(path)?.permissions();
        if permissions.mode() & 0o111 == 0 {
            return Err(EngineError::PermissionDenied(path.to_path_buf()));
        }
    }

    Ok(())
}

/// Проверяет бинарный файл движка на существование, права на исполнение и соответствие SHA-256.
pub fn verify_engine_artifact(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<EngineArtifact, EngineError> {
    validate_engine_binary_path(path)?;
    let metadata = std::fs::metadata(path)?;

    let expected_clean = expected_sha256
        .map(str::trim)
        .filter(|expected| !expected.is_empty())
        .map(str::to_lowercase)
        .ok_or(EngineError::MissingExpectedChecksum)?;

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

    if actual_sha256 != expected_clean {
        return Err(EngineError::ChecksumMismatch {
            expected: expected_clean,
            actual: actual_sha256,
        });
    }

    Ok(EngineArtifact {
        path: path.to_path_buf(),
        sha256: actual_sha256,
        size_bytes: metadata.len(),
    })
}

/// Выполняет pre-flight проверку сгенерированной конфигурации Xray (`xray run -test -c <config_path>`) с таймаутом.
pub async fn preflight_check_config(
    engine_binary: &Path,
    config_path: &Path,
    timeout: Duration,
) -> Result<(), EngineError> {
    preflight_check_config_with_strategy(
        engine_binary,
        config_path,
        timeout,
        EngineConfigStrategy::Xray,
    )
    .await
}

/// Выполняет pre-flight проверку сгенерированной конфигурации выбранным движком.
pub async fn preflight_check_config_with_strategy(
    engine_binary: &Path,
    config_path: &Path,
    timeout: Duration,
    strategy: EngineConfigStrategy,
) -> Result<(), EngineError> {
    let args = strategy.preflight_args(config_path);
    let mut cmd = tokio::process::Command::new(engine_binary);
    cmd.kill_on_drop(true)
        .args(args)
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
    /// Стратегия генерации конфигурации внешнего движка.
    pub config_strategy: EngineConfigStrategy,
    /// Ожидаемая контрольная сумма SHA-256. Если `None`, используется pinned binary checksum
    /// для выбранной стратегии и текущей платформы; отсутствие такого pin запрещает запуск fail-closed.
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
            config_strategy: EngineConfigStrategy::Xray,
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
        let _artifact = verify_selected_engine_artifact(
            engine_binary,
            options.config_strategy,
            options.expected_sha256.as_deref(),
        )?;

        // 4. Генерация JSON для выбранного движка
        let engine_value = options.config_strategy.generate(active_profile, settings);
        let engine_json = serde_json::to_string_pretty(&engine_value)?;

        // 5. Безопасная запись временного конфига (0600)
        let config_path = write_secure_runtime_config(None, &engine_json)?;
        self.runtime_config_path = Some(config_path.clone());

        // 6. Pre-flight проверка CLI движка
        if options.enable_preflight_check {
            if let Err(e) = preflight_check_config_with_strategy(
                engine_binary,
                &config_path,
                options.preflight_timeout,
                options.config_strategy,
            )
            .await
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
        let args = options.config_strategy.run_args(&config_path);

        info!(
            "Запуск движка {} {:?} с runtime-конфигурацией {:?}",
            options.config_strategy.engine_name(),
            engine_binary,
            config_path
        );
        if let Err(e) = self
            .supervisor
            .start_with_os_args(engine_binary.as_os_str(), &args)
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

        let binary_checksum = find_pinned_binary_checksum("xray-core", "v26.3.27");
        if std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64" {
            assert_eq!(
                binary_checksum,
                Some("5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404")
            );
        }
    }

    #[test]
    fn test_engine_catalog_rejects_duplicate_keys_and_malformed_hashes() {
        let source = include_str!("../engine_catalog.json");
        let mut duplicate: serde_json::Value = serde_json::from_str(source).unwrap();
        let row = duplicate["releases"][0].clone();
        duplicate["releases"].as_array_mut().unwrap().push(row);
        let duplicate = serde_json::to_string(&duplicate).unwrap();
        assert!(parse_engine_catalog(&duplicate).is_err());

        let malformed = source.replacen(
            "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
            "UPPERCASE",
            1,
        );
        assert!(parse_engine_catalog(&malformed).is_err());
    }

    #[test]
    fn test_engine_catalog_accepts_nondefault_lifecycle_versions() {
        let mut catalog = parse_engine_catalog(include_str!("../engine_catalog.json")).unwrap();
        let mut deprecated = catalog.releases.clone();
        for release in &mut deprecated {
            if release.engine_name == "sing-box" {
                release.version = "v1.12.0".to_string();
                release.status = EngineReleaseStatus::Deprecated;
            }
        }
        catalog.releases.extend(
            deprecated
                .into_iter()
                .filter(|release| release.engine_name == "sing-box"),
        );
        assert!(validate_engine_catalog(&catalog).is_ok());
    }

    #[test]
    fn test_config_dialect_rejects_incompatible_catalog_release_before_start() {
        assert!(validate_release_compatibility(EngineConfigStrategy::Xray, "v26.3.27").is_ok());
        assert!(validate_release_compatibility(EngineConfigStrategy::SingBox, "v1.13.18").is_ok());
        assert_eq!(
            validate_release_compatibility(EngineConfigStrategy::SingBox, "v1.12.0")
                .unwrap_err()
                .to_string(),
            "Конфигурационный диалект SingBoxV1_13 несовместим с sing-box v1.12.0; запуск запрещён"
        );

        let mut catalog = parse_engine_catalog(include_str!("../engine_catalog.json")).unwrap();
        for release in &mut catalog.releases {
            if release.engine_name == "sing-box" && release.version == "v1.13.18" {
                release.config_dialect = EngineConfigDialect::XrayV26;
            }
        }
        assert!(validate_engine_catalog(&catalog).is_ok());
        assert_eq!(
            validate_release_compatibility_in_releases(
                EngineConfigStrategy::SingBox,
                "v1.13.18",
                &catalog.releases,
            )
            .unwrap_err()
            .to_string(),
            "Конфигурационный диалект SingBoxV1_13 несовместим с sing-box v1.13.18; запуск запрещён"
        );
    }

    #[test]
    fn test_engine_catalog_rejects_invalid_lifecycle_and_multiple_defaults() {
        let source = include_str!("../engine_catalog.json");
        let invalid_status = source.replacen("\"recommended\"", "\"unknown\"", 1);
        assert!(parse_engine_catalog(&invalid_status).is_err());
        assert_eq!(
            serde_json::from_value::<EngineConfigDialect>(serde_json::json!("unknown"))
                .unwrap_err()
                .to_string(),
            "unknown variant `unknown`, expected `xray_v26` or `sing_box_v1_13`"
        );

        let mut catalog = parse_engine_catalog(source).unwrap();
        let mut second_default = catalog.releases.clone();
        for release in &mut second_default {
            if release.engine_name == "sing-box" {
                release.version = "v1.12.0".to_string();
            }
        }
        catalog.releases.extend(
            second_default
                .into_iter()
                .filter(|release| release.engine_name == "sing-box"),
        );
        assert_eq!(
            validate_engine_catalog(&catalog),
            Err("sing-box must have exactly one recommended version".to_string())
        );
    }

    #[test]
    fn test_engine_catalog_rejects_multiple_config_dialects_for_one_version() {
        let mut catalog = parse_engine_catalog(include_str!("../engine_catalog.json")).unwrap();
        let release = catalog
            .releases
            .iter_mut()
            .find(|release| {
                release.engine_name == "sing-box"
                    && release.version == "v1.13.18"
                    && release.target_os == "linux"
                    && release.target_arch == "x86_64"
            })
            .unwrap();
        release.config_dialect = EngineConfigDialect::XrayV26;

        assert_eq!(
            validate_engine_catalog(&catalog),
            Err("sing-box v1.13.18 must use one configuration dialect".to_string())
        );
    }

    #[test]
    fn test_yanked_release_is_excluded_from_checksum_lookup() {
        let mut catalog = parse_engine_catalog(include_str!("../engine_catalog.json")).unwrap();
        let mut yanked = catalog.releases.clone();
        for release in &mut yanked {
            if release.engine_name == "sing-box" {
                release.version = "v1.12.0".to_string();
                release.status = EngineReleaseStatus::Yanked;
            }
        }
        catalog.releases.extend(
            yanked
                .into_iter()
                .filter(|release| release.engine_name == "sing-box"),
        );
        assert!(validate_engine_catalog(&catalog).is_ok());
        assert_eq!(
            find_pinned_binary_checksum_in_releases(
                &catalog.releases,
                "sing-box",
                "v1.12.0",
                "linux",
                "x86_64",
            ),
            None
        );
    }

    #[test]
    fn test_declared_engine_support_matrix_has_binary_checksums() {
        let declared_targets = [
            ("macos", "arm64"),
            ("macos", "x86_64"),
            ("linux", "arm64"),
            ("linux", "x86_64"),
            ("windows", "x86_64"),
        ];

        for strategy in [EngineConfigStrategy::Xray, EngineConfigStrategy::SingBox] {
            let version = recommended_engine_version(strategy.engine_name())
                .expect("every supported engine has one recommended catalog version");
            for (target_os, target_arch) in declared_targets {
                let release = get_pinned_engine_releases().iter().find(|release| {
                    release.engine_name == strategy.engine_name()
                        && release.version == version
                        && release.target_os == target_os
                        && release.target_arch == target_arch
                });
                assert!(
                    release.is_some_and(|release| !release.binary_sha256.is_empty()),
                    "{} {} must have a binary SHA-256 for {target_os}/{target_arch}",
                    strategy.engine_name(),
                    version
                );
            }
        }
    }

    #[test]
    fn test_resolve_expected_binary_checksum_distinguishes_explicit_pinned_and_missing_pin() {
        let explicit = resolve_expected_binary_checksum_for_target(
            EngineConfigStrategy::Xray,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "linux",
            "x86_64",
        )
        .unwrap();
        assert_eq!(
            explicit.value,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(explicit.source, ExpectedBinaryChecksumSource::Explicit);

        let explicit_unsupported_target = resolve_expected_binary_checksum_for_target(
            EngineConfigStrategy::SingBox,
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            "windows",
            "arm64",
        )
        .unwrap();
        assert_eq!(
            explicit_unsupported_target.value,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            explicit_unsupported_target.source,
            ExpectedBinaryChecksumSource::Explicit
        );

        let mut catalog = parse_engine_catalog(include_str!("../engine_catalog.json")).unwrap();
        for release in &mut catalog.releases {
            if release.engine_name == "sing-box" && release.version == "v1.13.18" {
                release.config_dialect = EngineConfigDialect::XrayV26;
            }
        }
        let explicit_incompatible = resolve_expected_binary_checksum_in_releases(
            &catalog.releases,
            EngineConfigStrategy::SingBox,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "windows",
            "arm64",
        );
        assert_eq!(
            explicit_incompatible.unwrap_err().to_string(),
            "Конфигурационный диалект SingBoxV1_13 несовместим с sing-box v1.13.18; запуск запрещён"
        );

        let pinned = resolve_expected_binary_checksum_for_target(
            EngineConfigStrategy::Xray,
            None,
            "linux",
            "x86_64",
        )
        .unwrap();
        assert_eq!(
            pinned.value,
            "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
        );
        assert!(matches!(
            pinned.source,
            ExpectedBinaryChecksumSource::Pinned {
                ref engine_name,
                ref version,
                ref target_os,
                ref target_arch,
            } if engine_name == "xray-core"
                && version == "v26.3.27"
                && target_os == "linux"
                && target_arch == "x86_64"
        ));

        let missing = resolve_expected_binary_checksum_for_target(
            EngineConfigStrategy::SingBox,
            None,
            "windows",
            "arm64",
        );
        assert!(matches!(
            missing,
            Err(EngineError::MissingPinnedBinaryChecksum(ref details))
                if details.engine_name == "sing-box"
                    && details.version == "v1.13.18"
                    && details.target_os == "windows"
                    && details.target_arch == "arm64"
        ));
    }

    #[test]
    fn test_selected_artifact_verification_distinguishes_pinned_and_explicit_mismatch() {
        let test_bin = std::env::temp_dir().join(format!(
            "test_checksum_diagnostics_{}.sh",
            std::process::id()
        ));
        std::fs::write(&test_bin, b"#!/bin/sh\necho test\n").unwrap();

        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&test_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&test_bin, perms).unwrap();
        }

        let pinned = verify_selected_engine_artifact_for_target(
            &test_bin,
            EngineConfigStrategy::Xray,
            None,
            "linux",
            "x86_64",
        );
        assert!(matches!(
            pinned,
            Err(EngineError::PinnedBinaryChecksumMismatch(ref details))
                if details.engine_name == "xray-core"
                    && details.version == "v26.3.27"
                    && details.target_os == "linux"
                    && details.target_arch == "x86_64"
        ));

        let explicit = verify_selected_engine_artifact_for_target(
            &test_bin,
            EngineConfigStrategy::Xray,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "linux",
            "x86_64",
        );
        assert!(matches!(
            explicit,
            Err(EngineError::ChecksumMismatch { .. })
        ));

        let _ = std::fs::remove_file(&test_bin);
    }

    #[test]
    fn test_missing_binary_takes_priority_over_missing_platform_pin() {
        let missing_path =
            std::env::temp_dir().join(format!("missing_engine_before_pin_{}", std::process::id()));
        let result = verify_selected_engine_artifact_for_target(
            &missing_path,
            EngineConfigStrategy::SingBox,
            None,
            "windows",
            "arm64",
        );

        assert!(matches!(result, Err(EngineError::BinaryNotFound(path)) if path == missing_path));
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
        let test_payload = b"#!/bin/sh\necho test\n";
        std::fs::write(&test_bin, test_payload).unwrap();

        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&test_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&test_bin, perms).unwrap();
        }

        let expected_sha256 = hex::encode(Sha256::digest(test_payload));
        let verified = verify_engine_artifact(&test_bin, Some(&expected_sha256))
            .expect("Должно пройти проверку");
        assert_eq!(verified.path, test_bin);
        assert_eq!(verified.sha256, expected_sha256);

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
    fn test_verify_existing_binary_without_checksum_fails_closed() {
        let temp_dir = std::env::temp_dir();
        let test_bin = temp_dir.join(format!(
            "test_bin_without_checksum_{}.sh",
            std::process::id()
        ));
        std::fs::write(&test_bin, b"#!/bin/sh\necho test\n").unwrap();

        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&test_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&test_bin, perms).unwrap();
        }

        let res = verify_engine_artifact(&test_bin, None);
        assert!(matches!(res, Err(EngineError::MissingExpectedChecksum)));

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
