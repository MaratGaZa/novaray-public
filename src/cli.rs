//! Интерфейс командной строки (CLI) NovaRay Core.
//!
//! Тонкий адаптер над `ProxyService`, `AppConfig` и `UserSettings`.
//! Обеспечивает:
//! - Проверяемые коды возврата (exit codes) для скриптов и системной интеграции.
//! - Защиту секретов (параметры считываются из защищенных конфигурационных файлов, а не через CLI argv).
//! - Обработку сигналов (Ctrl+C / SIGTERM) с гарантированной очисткой временных файлов при остановке.

use crate::config::{AppConfig, UserSettings};
use crate::config_generator::EngineConfigStrategy;
use crate::core::SupervisorState;
use crate::engine::{get_pinned_engine_releases, EngineError, ProxyService, ProxyServiceOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

/// Коды возврата CLI NovaRay Core
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Успешное выполнение
    Success = 0,
    /// Общая ошибка или ошибка ввода-вывода (файл не найден, ошибка прав доступа)
    GeneralError = 1,
    /// Ошибка аргументов командной строки (неизвестный флаг, отсутствует значение)
    UsageError = 2,
    /// Ошибка валидации конфигурации (невалидный JSON, некорректные семантические правила)
    ValidationError = 3,
    /// Ошибка сетевого движка (бинарник не найден, занят порт, pre-flight failed)
    EngineError = 4,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Распарсенная команда CLI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Запуск прокси-сервиса
    Start(StartOptions),
    /// Проверка и валидация конфигурационных файлов
    Validate(ValidateOptions),
    /// Информация о поддерживаемых возможностях и версиях
    Status,
    /// Список зафиксированных релизов движка и чексумм
    PinnedReleases,
    /// Вывод справки
    Help,
    /// Вывод версии
    Version,
}

/// Опции для команды `start` / `connect`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOptions {
    pub config_path: PathBuf,
    pub settings_path: PathBuf,
    pub engine_binary: PathBuf,
    pub config_strategy: EngineConfigStrategy,
    pub expected_sha256: Option<String>,
    pub enable_preflight: bool,
    pub preflight_timeout_secs: u64,
    pub timeout_secs: Option<u64>,
}

impl Default for StartOptions {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("config.example.json"),
            settings_path: PathBuf::from("settings.example.json"),
            engine_binary: default_engine_binary(),
            config_strategy: EngineConfigStrategy::Xray,
            expected_sha256: None,
            enable_preflight: true,
            preflight_timeout_secs: 5,
            timeout_secs: None,
        }
    }
}

/// Опции для команды `validate` / `check`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateOptions {
    pub config_path: PathBuf,
    pub settings_path: PathBuf,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("config.example.json"),
            settings_path: PathBuf::from("settings.example.json"),
        }
    }
}

fn default_engine_binary() -> PathBuf {
    if let Ok(bin) = std::env::var("NOVAPROXY_ENGINE_BIN") {
        return PathBuf::from(bin);
    }
    if let Ok(bin) = std::env::var("XRAY_BIN") {
        return PathBuf::from(bin);
    }
    PathBuf::from("xray")
}

/// Разбор строковых аргументов в команду CLI
pub fn parse_args<I, T>(args: I) -> Result<CliCommand, (String, ExitCode)>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if args.is_empty() {
        return Ok(CliCommand::Help);
    }

    let first = &args[0];
    if first == "--help" || first == "-h" || first == "help" {
        return Ok(CliCommand::Help);
    }
    if first == "--version" || first == "-V" || first == "version" {
        return Ok(CliCommand::Version);
    }
    if first == "status" {
        return Ok(CliCommand::Status);
    }
    if first == "pinned-releases" || first == "engines" {
        return Ok(CliCommand::PinnedReleases);
    }

    match first.as_str() {
        "start" | "connect" | "run" => {
            let mut opts = StartOptions::default();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" | "-c" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --config требует указания пути к файлу".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.config_path = PathBuf::from(&args[i]);
                    }
                    "--settings" | "-s" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --settings требует указания пути к файлу".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.settings_path = PathBuf::from(&args[i]);
                    }
                    "--engine-bin" | "-e" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --engine-bin требует указания пути к бинарнику".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.engine_binary = PathBuf::from(&args[i]);
                    }
                    "--engine-config" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --engine-config требует значения xray или sing-box"
                                    .to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.config_strategy = parse_engine_config_strategy(&args[i])?;
                    }
                    "--expected-sha256" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --expected-sha256 требует значения хеша".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.expected_sha256 = Some(args[i].clone());
                    }
                    "--no-preflight" => {
                        opts.enable_preflight = false;
                    }
                    "--preflight-timeout" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --preflight-timeout требует числа секунд".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.preflight_timeout_secs = args[i].parse::<u64>().map_err(|_| {
                            (
                                "Некорректное значение таймаута pre-flight".to_string(),
                                ExitCode::UsageError,
                            )
                        })?;
                    }
                    "--timeout-secs" | "-t" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --timeout-secs требует числа секунд".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        let secs = args[i].parse::<u64>().map_err(|_| {
                            (
                                "Некорректное значение таймаута работы".to_string(),
                                ExitCode::UsageError,
                            )
                        })?;
                        opts.timeout_secs = Some(secs);
                    }
                    unknown => {
                        return Err((
                            format!("Неизвестный флаг команды start: {}", unknown),
                            ExitCode::UsageError,
                        ));
                    }
                }
                i += 1;
            }
            Ok(CliCommand::Start(opts))
        }
        "validate" | "check" => {
            let mut opts = ValidateOptions::default();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" | "-c" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --config требует указания пути к файлу".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.config_path = PathBuf::from(&args[i]);
                    }
                    "--settings" | "-s" => {
                        i += 1;
                        if i >= args.len() {
                            return Err((
                                "Флаг --settings требует указания пути к файлу".to_string(),
                                ExitCode::UsageError,
                            ));
                        }
                        opts.settings_path = PathBuf::from(&args[i]);
                    }
                    unknown => {
                        return Err((
                            format!("Неизвестный флаг команды validate: {}", unknown),
                            ExitCode::UsageError,
                        ));
                    }
                }
                i += 1;
            }
            Ok(CliCommand::Validate(opts))
        }
        unknown => Err((
            format!(
                "Неизвестная команда '{}'. Запустите 'novaray-core --help' для справки.",
                unknown
            ),
            ExitCode::UsageError,
        )),
    }
}

fn parse_engine_config_strategy(value: &str) -> Result<EngineConfigStrategy, (String, ExitCode)> {
    match value {
        "xray" => Ok(EngineConfigStrategy::Xray),
        "sing-box" => Ok(EngineConfigStrategy::SingBox),
        _ => Err((
            format!(
                "Некорректное значение --engine-config: '{}'. Ожидается xray или sing-box",
                value
            ),
            ExitCode::UsageError,
        )),
    }
}

/// Выполняет CLI команду и возвращает ExitCode
pub async fn execute_command(cmd: CliCommand) -> ExitCode {
    match cmd {
        CliCommand::Help => {
            print_help();
            ExitCode::Success
        }
        CliCommand::Version => {
            println!("novaray-core {}", env!("CARGO_PKG_VERSION"));
            ExitCode::Success
        }
        CliCommand::Status => {
            print_status();
            ExitCode::Success
        }
        CliCommand::PinnedReleases => {
            print_pinned_releases();
            ExitCode::Success
        }
        CliCommand::Validate(opts) => execute_validate(&opts),
        CliCommand::Start(opts) => execute_start(&opts).await,
    }
}

fn print_help() {
    println!(
        "NovaRay Core CLI — Управление сетевым движком и прокси-сервисом (v{})\n",
        env!("CARGO_PKG_VERSION")
    );
    println!("ИСПОЛЬЗОВАНИЕ:");
    println!("    novaray-core <КОМАНДА> [ОПЦИИ]\n");
    println!("КОМАНДЫ:");
    println!("    start, connect     Запустить прокси-сервис и сетевой движок");
    println!("    validate, check    Проверить синтаксис и семантику конфигурационных файлов");
    println!("    status             Показать поддерживаемые протоколы и режимы");
    println!("    pinned-releases    Показать зафиксированные версии и чексуммы движков");
    println!("    help, --help, -h   Показать данную справку");
    println!("    version, -V        Показать версию программы\n");
    println!("ОПЦИИ КОМАНДЫ 'start':");
    println!("    -c, --config <PATH>           Путь к файлу конфигурации (по умолчанию: config.example.json)");
    println!("    -s, --settings <PATH>         Путь к файлу настроек (по умолчанию: settings.example.json)");
    println!(
        "    -e, --engine-bin <PATH>       Путь к бинарнику выбранного движка (по умолчанию: xray)"
    );
    println!(
        "        --engine-config <NAME>    Формат конфигурации: xray или sing-box (по умолчанию: xray)"
    );
    println!(
        "                                   --engine-bin задаёт путь, но не меняет формат конфигурации"
    );
    println!(
        "        --expected-sha256 <HASH>  SHA-256 override; по умолчанию используется pinned checksum"
    );
    println!(
        "                                   Иные OS/arch без catalog pin требуют явный trusted override"
    );
    println!("        --no-preflight            Отключить pre-flight проверку конфигурации");
    println!("        --preflight-timeout <S>   Таймаут pre-flight проверки в секундах (по умолчанию: 5)");
    println!("    -t, --timeout-secs <S>        Ограничить время работы сервиса N секундами (для тестов/демо)\n");
    println!("ОПЦИИ КОМАНДЫ 'validate':");
    println!("    -c, --config <PATH>           Путь к файлу конфигурации");
    println!("    -s, --settings <PATH>         Путь к файлу настроек\n");
    println!("КОДЫ ВОЗВРАТА (EXIT CODES):");
    println!("    0    Успешное завершение (Success)");
    println!("    1    Ошибка ввода-вывода или общая ошибка (General / I/O Error)");
    println!("    2    Ошибка аргументов командной строки (Usage Error)");
    println!("    3    Ошибка валидации конфигурации (Validation Error)");
    println!("    4    Ошибка сетевого движка или портов (Engine Error)");
}

fn print_status() {
    println!("NovaRay Core Status Summary:");
    println!("  Version:            {}", env!("CARGO_PKG_VERSION"));
    println!("  Protocols:          VLESS (Reality/Standard TLS; TCP, WebSocket, gRPC)");
    println!("  Inbounds:           SOCKS5 (RFC 1928), HTTP Forward Proxy");
    println!("  Engine Routing:     Global Proxy (M2 local proxy; per-app engine routing planned for sing-box Task 14)");
    println!("  Core Matcher:       Domain, IP CIDR, App Process Name matching rules");
    println!("  Supported Engines:  Xray-core (default, pinned v26.3.27), sing-box (select with --engine-config sing-box)");
    println!("  Pinned Targets:     macOS arm64/x86_64, Linux arm64/x86_64, Windows x86_64; другие targets требуют --expected-sha256");
    println!("  Topology:           Direct Local-Proxy (M2) / Privileged Helper utun (M3 target)");
}

fn print_pinned_releases() {
    println!("Pinned Engine Releases Catalog:");
    for release in get_pinned_engine_releases() {
        println!("  - Engine:      {}", release.engine_name);
        println!("    Version:     {}", release.version);
        println!(
            "    OS/Arch:     {}/{}",
            release.target_os, release.target_arch
        );
        println!("    Archive:     {}", release.archive_name);
        println!("    Archive SHA: {}", release.archive_sha256);
        println!("    Binary SHA:  {}", release.binary_sha256);
        println!("    Lifecycle:   {:?}", release.status);
        println!();
    }
    println!("Automatic binary pins: macOS arm64/x86_64, Linux arm64/x86_64, Windows x86_64.");
    println!("Other OS/arch targets are unsupported by the catalog and require --expected-sha256.");
}

/// Загрузка и валидация конфигурации из файлов
pub fn load_and_validate_configs(
    config_path: &Path,
    settings_path: &Path,
) -> Result<(AppConfig, UserSettings), (String, ExitCode)> {
    if !config_path.exists() {
        return Err((
            format!("Файл конфигурации не найден: {:?}", config_path),
            ExitCode::GeneralError,
        ));
    }
    if !settings_path.exists() {
        return Err((
            format!("Файл настроек не найден: {:?}", settings_path),
            ExitCode::GeneralError,
        ));
    }

    let config_content = std::fs::read_to_string(config_path).map_err(|e| {
        (
            format!("Ошибка чтения файла конфигурации {:?}: {}", config_path, e),
            ExitCode::GeneralError,
        )
    })?;

    let settings_content = std::fs::read_to_string(settings_path).map_err(|e| {
        (
            format!("Ошибка чтения файла настроек {:?}: {}", settings_path, e),
            ExitCode::GeneralError,
        )
    })?;

    let config: AppConfig = serde_json::from_str(&config_content).map_err(|e| {
        (
            format!(
                "Синтаксическая ошибка JSON в файле конфигурации {:?}: {}",
                config_path, e
            ),
            ExitCode::ValidationError,
        )
    })?;

    let settings: UserSettings = serde_json::from_str(&settings_content).map_err(|e| {
        (
            format!(
                "Синтаксическая ошибка JSON в файле настроек {:?}: {}",
                settings_path, e
            ),
            ExitCode::ValidationError,
        )
    })?;

    config.validate().map_err(|e| {
        (
            format!("Ошибка семантической валидации конфигурации: {}", e),
            ExitCode::ValidationError,
        )
    })?;

    settings.validate().map_err(|e| {
        (
            format!("Ошибка семантической валидации настроек: {}", e),
            ExitCode::ValidationError,
        )
    })?;

    Ok((config, settings))
}

fn execute_validate(opts: &ValidateOptions) -> ExitCode {
    match load_and_validate_configs(&opts.config_path, &opts.settings_path) {
        Ok((config, settings)) => {
            let active_profile = config
                .find_active_profile()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "none".to_string());

            println!("Конфигурация успешно прошла валидацию:");
            println!("  - Файл конфигурации:      {:?}", opts.config_path);
            println!("  - Файл настроек:          {:?}", opts.settings_path);
            println!("  - Активный профиль:       \"{}\"", active_profile);
            println!(
                "  - Локальный SOCKS5 порт:  {}",
                settings.client.local_socks_port
            );
            println!(
                "  - Локальный HTTP порт:    {}",
                settings.client.local_http_port
            );
            println!(
                "  - Режим Split-Tunneling:  {}",
                settings.split_tunneling.mode
            );
            ExitCode::Success
        }
        Err((err_msg, code)) => {
            eprintln!("Ошибка валидации: {}", err_msg);
            code
        }
    }
}

async fn execute_start(opts: &StartOptions) -> ExitCode {
    let (config, settings) = match load_and_validate_configs(&opts.config_path, &opts.settings_path)
    {
        Ok(pair) => pair,
        Err((err_msg, code)) => {
            eprintln!("{}", err_msg);
            return code;
        }
    };

    let active_profile = match config.find_active_profile() {
        Some(p) => p.clone(),
        None => {
            eprintln!("Ошибка: в конфигурации отсутствует активный профиль");
            return ExitCode::ValidationError;
        }
    };

    let service_opts = proxy_service_options(opts);

    let mut service = ProxyService::new();

    // Регистрируем обработчики сигналов до старта сервиса для предотвращения race condition
    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    #[cfg(unix)]
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();

    info!(
        "Запуск NovaRay ProxyService с бинарником {:?}",
        opts.engine_binary
    );

    #[cfg(unix)]
    let start_res = {
        let recv_sigterm = async {
            if let Some(s) = sigterm.as_mut() {
                s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let recv_sigint = async {
            if let Some(s) = sigint.as_mut() {
                s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            res = service.start_with_options(&opts.engine_binary, &config, &settings, &service_opts) => {
                Some(res)
            }
            _ = recv_sigint => {
                println!("\nОстановка прокси-сервиса (причина: SIGINT во время инициализации)...");
                let _ = service.stop().await;
                None
            }
            _ = recv_sigterm => {
                println!("\nОстановка прокси-сервиса (причина: SIGTERM во время инициализации)...");
                let _ = service.stop().await;
                None
            }
        }
    };

    #[cfg(not(unix))]
    let start_res = Some(
        service
            .start_with_options(&opts.engine_binary, &config, &settings, &service_opts)
            .await,
    );

    let start_res = match start_res {
        Some(res) => res,
        None => return ExitCode::Success,
    };

    if let Err(e) = start_res {
        eprintln!("Ошибка запуска прокси-сервиса: {}", e);
        return map_engine_error_to_exit_code(&e);
    }

    let pid = service.pid().unwrap_or(0);
    println!("NovaRay Proxy Service v0.1.0 успешно запущен");
    println!("  - PID процесса:          {}", pid);
    println!(
        "  - Активный профиль:      \"{}\" ({:?})",
        active_profile.name, active_profile.protocol
    );
    println!(
        "  - SOCKS5 Proxy inbound:  127.0.0.1:{}",
        settings.client.local_socks_port
    );
    println!(
        "  - HTTP Proxy inbound:    127.0.0.1:{}",
        settings.client.local_http_port
    );

    let state_rx = service.subscribe_state();
    #[cfg(unix)]
    let stop_reason = wait_for_shutdown(sigterm, sigint, state_rx, opts.timeout_secs).await;
    #[cfg(not(unix))]
    let stop_reason = wait_for_shutdown(state_rx, opts.timeout_secs).await;

    match stop_reason {
        ShutdownReason::SupervisorState(SupervisorState::Failed(err)) => {
            eprintln!("\nПроцесс движка неожиданно завершился со сбоем: {}", err);
            let _ = service.stop().await;
            ExitCode::EngineError
        }
        ShutdownReason::SupervisorState(SupervisorState::Stopped) => {
            eprintln!("\nПроцесс движка остановлен (состояние: Stopped).");
            let _ = service.stop().await;
            ExitCode::EngineError
        }
        ShutdownReason::SupervisorState(state) => {
            eprintln!("\nПроцесс движка перешел в состояние: {:?}.", state);
            let _ = service.stop().await;
            ExitCode::EngineError
        }
        ShutdownReason::Timeout => {
            println!("\nОстановка прокси-сервиса (причина: timeout)...");
            if let Err(e) = service.stop().await {
                eprintln!("Предупреждение при остановке сервиса: {}", e);
            } else {
                println!("NovaRay Proxy Service корректно остановлен.");
            }
            ExitCode::Success
        }
        ShutdownReason::Signal(sig) => {
            println!("\nОстановка прокси-сервиса (причина: {})...", sig);
            if let Err(e) = service.stop().await {
                eprintln!("Предупреждение при остановке сервиса: {}", e);
            } else {
                println!("NovaRay Proxy Service корректно остановлен.");
            }
            ExitCode::Success
        }
    }
}

fn proxy_service_options(opts: &StartOptions) -> ProxyServiceOptions {
    ProxyServiceOptions {
        config_strategy: opts.config_strategy,
        expected_sha256: opts.expected_sha256.clone(),
        enable_preflight_check: opts.enable_preflight,
        preflight_timeout: Duration::from_secs(opts.preflight_timeout_secs),
        ..Default::default()
    }
}

/// Причина остановки цикла ожидания CLI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownReason {
    Signal(&'static str),
    Timeout,
    SupervisorState(SupervisorState),
}

async fn wait_for_state_termination(
    mut state_rx: tokio::sync::watch::Receiver<SupervisorState>,
) -> SupervisorState {
    while state_rx.changed().await.is_ok() {
        let state = state_rx.borrow().clone();
        if matches!(state, SupervisorState::Failed(_) | SupervisorState::Stopped) {
            return state;
        }
    }
    SupervisorState::Stopped
}

#[cfg(unix)]
async fn wait_for_shutdown(
    mut sigterm: Option<tokio::signal::unix::Signal>,
    mut sigint: Option<tokio::signal::unix::Signal>,
    state_rx: tokio::sync::watch::Receiver<SupervisorState>,
    timeout_secs: Option<u64>,
) -> ShutdownReason {
    let recv_sigterm = async {
        if let Some(s) = sigterm.as_mut() {
            s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    let recv_sigint = async {
        if let Some(s) = sigint.as_mut() {
            s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    if let Some(secs) = timeout_secs {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(secs)) => ShutdownReason::Timeout,
            _ = recv_sigint => ShutdownReason::Signal("SIGINT"),
            _ = recv_sigterm => ShutdownReason::Signal("SIGTERM"),
            state = wait_for_state_termination(state_rx) => ShutdownReason::SupervisorState(state),
        }
    } else {
        tokio::select! {
            _ = recv_sigint => ShutdownReason::Signal("SIGINT"),
            _ = recv_sigterm => ShutdownReason::Signal("SIGTERM"),
            state = wait_for_state_termination(state_rx) => ShutdownReason::SupervisorState(state),
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(
    state_rx: tokio::sync::watch::Receiver<SupervisorState>,
    timeout_secs: Option<u64>,
) -> ShutdownReason {
    if let Some(secs) = timeout_secs {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(secs)) => ShutdownReason::Timeout,
            _ = tokio::signal::ctrl_c() => ShutdownReason::Signal("Ctrl+C"),
            state = wait_for_state_termination(state_rx) => ShutdownReason::SupervisorState(state),
        }
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => ShutdownReason::Signal("Ctrl+C"),
            state = wait_for_state_termination(state_rx) => ShutdownReason::SupervisorState(state),
        }
    }
}

fn map_engine_error_to_exit_code(err: &EngineError) -> ExitCode {
    match err {
        EngineError::ConfigValidationError(_) => ExitCode::ValidationError,
        EngineError::BinaryNotFound(_) => ExitCode::EngineError,
        EngineError::PermissionDenied(_) => ExitCode::EngineError,
        EngineError::ChecksumMismatch { .. } => ExitCode::EngineError,
        EngineError::PinnedBinaryChecksumMismatch(_) => ExitCode::EngineError,
        EngineError::MissingPinnedBinaryChecksum(_) => ExitCode::EngineError,
        EngineError::MissingExpectedChecksum => ExitCode::EngineError,
        EngineError::IncompatibleEngineRelease { .. } => ExitCode::EngineError,
        EngineError::PortInUse(_) => ExitCode::EngineError,
        EngineError::ConfigPreflightFailed(_) => ExitCode::EngineError,
        EngineError::AlreadyRunning(_) => ExitCode::EngineError,
        EngineError::SupervisorError(_) => ExitCode::EngineError,
        EngineError::IoError(_) => ExitCode::GeneralError,
        EngineError::SerializationError(_) => ExitCode::ValidationError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_help_and_version() {
        assert_eq!(parse_args(["--help"]).unwrap(), CliCommand::Help);
        assert_eq!(parse_args(["-h"]).unwrap(), CliCommand::Help);
        assert_eq!(parse_args(["help"]).unwrap(), CliCommand::Help);
        assert_eq!(parse_args(["--version"]).unwrap(), CliCommand::Version);
        assert_eq!(parse_args(["-V"]).unwrap(), CliCommand::Version);
        assert_eq!(parse_args(["status"]).unwrap(), CliCommand::Status);
        assert_eq!(
            parse_args(["pinned-releases"]).unwrap(),
            CliCommand::PinnedReleases
        );
    }

    #[test]
    fn test_cli_parse_validate_command() {
        let args = [
            "validate",
            "-c",
            "custom_config.json",
            "-s",
            "custom_settings.json",
        ];
        let cmd = parse_args(args).unwrap();
        match cmd {
            CliCommand::Validate(opts) => {
                assert_eq!(opts.config_path, PathBuf::from("custom_config.json"));
                assert_eq!(opts.settings_path, PathBuf::from("custom_settings.json"));
            }
            _ => panic!("Ожидалась команда Validate"),
        }
    }

    #[test]
    fn test_cli_parse_start_command_options() {
        let args = [
            "start",
            "--config",
            "my_conf.json",
            "--settings",
            "my_set.json",
            "--engine-bin",
            "/usr/local/bin/xray",
            "--engine-config",
            "sing-box",
            "--expected-sha256",
            "abc12345",
            "--no-preflight",
            "--preflight-timeout",
            "10",
            "--timeout-secs",
            "10",
        ];
        let cmd = parse_args(args).unwrap();
        match cmd {
            CliCommand::Start(opts) => {
                assert_eq!(opts.config_path, PathBuf::from("my_conf.json"));
                assert_eq!(opts.settings_path, PathBuf::from("my_set.json"));
                assert_eq!(opts.engine_binary, PathBuf::from("/usr/local/bin/xray"));
                assert_eq!(opts.config_strategy, EngineConfigStrategy::SingBox);
                assert_eq!(opts.expected_sha256.as_deref(), Some("abc12345"));
                assert!(!opts.enable_preflight);
                assert_eq!(opts.preflight_timeout_secs, 10);
                assert_eq!(opts.timeout_secs, Some(10));
            }
            _ => panic!("Ожидалась команда Start"),
        }
    }

    #[test]
    fn test_cli_start_defaults_to_xray_and_maps_strategy_to_service_options() {
        let CliCommand::Start(opts) = parse_args(["start"]).unwrap() else {
            panic!("Ожидалась команда Start");
        };

        assert_eq!(opts.config_strategy, EngineConfigStrategy::Xray);
        assert_eq!(
            proxy_service_options(&opts).config_strategy,
            EngineConfigStrategy::Xray
        );
    }

    #[test]
    fn test_cli_parse_invalid_engine_config_returns_usage_error() {
        let error = parse_args(["start", "--engine-config", "unknown-engine"]).unwrap_err();
        assert_eq!(error.1, ExitCode::UsageError);
        assert!(error.0.contains("--engine-config"));
    }

    #[test]
    fn test_cli_parse_unknown_command_or_flag_returns_usage_error() {
        let err = parse_args(["unknown_cmd"]).unwrap_err();
        assert_eq!(err.1, ExitCode::UsageError);

        let err2 = parse_args(["start", "--unknown-flag"]).unwrap_err();
        assert_eq!(err2.1, ExitCode::UsageError);
    }
}
