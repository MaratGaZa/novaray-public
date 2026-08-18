//! Модуль управления дочерним процессом сетевого ядра (Xray-core / sing-box).
//!
//! Обеспечивает:
//! - State Machine жизненного цикла: `Stopped` -> `Starting` -> `Ready` -> `Stopping` -> `Failed`.
//! - Устойчивую модель владения процессом через Actor/Command worker (без race conditions в `stop` и `Drop`).
//! - Асинхронный log drain (stdout/stderr) с защитой от переполнения pipe buffer и кольцевым буфером логов.
//! - Санитизацию (redaction) конфиденциальных данных (UUID, IP-адреса) в логах перед сохранением и трансляцией.
//! - Readiness probe (проверка TCP-порта, log pattern или immediate) с настраиваемым таймаутом.
//! - Fail-closed поведение: любой преждевременный выход дочернего процесса (даже с кодом 0) переводит супервизор в `Failed`.
//! - Graceful stop (SIGTERM/SIGINT) с гарантированным переходом на SIGKILL по таймауту.
//! - Автоматическую очистку runtime-файлов конфигурации.
//! - Мониторинг самопроизвольного падения/завершения дочернего процесса.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Состояние процесса сетевого ядра
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisorState {
    Stopped,
    Starting,
    Ready,
    Stopping,
    Failed(String),
}

impl std::fmt::Display for SupervisorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorState::Stopped => write!(f, "Stopped"),
            SupervisorState::Starting => write!(f, "Starting"),
            SupervisorState::Ready => write!(f, "Ready"),
            SupervisorState::Stopping => write!(f, "Stopping"),
            SupervisorState::Failed(err) => write!(f, "Failed: {}", err),
        }
    }
}

/// Стратегия проверки готовности дочернего процесса
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessProbe {
    /// Считать готовым сразу после успешного запуска процесса и подтверждения активности
    Immediate,
    /// Ожидать открытия локального TCP-порта (например, SOCKS 10808 или HTTP 10809)
    TcpPort(u16),
    /// Ожидать появления подстроки в логах stdout/stderr
    LogPattern(String),
}

/// Параметры конфигурации супервизора процессов
#[derive(Debug, Clone)]
pub struct SupervisorOptions {
    /// Стратегия проверки готовности
    pub readiness_probe: ReadinessProbe,
    /// Максимальное время ожидания перехода в состояние Ready
    pub readiness_timeout: Duration,
    /// Таймаут ожидания корректного завершения процесса (graceful) до посылки SIGKILL
    pub graceful_shutdown_timeout: Duration,
    /// Максимальное количество строк логов в кольцевом буфере
    pub max_log_lines: usize,
    /// Путь к файлу конфигурации, который необходимо удалить при остановке
    pub runtime_config_cleanup: Option<PathBuf>,
    /// Включить санитизацию UUID и IP в логах
    pub redact_logs: bool,
}

impl Default for SupervisorOptions {
    fn default() -> Self {
        Self {
            readiness_probe: ReadinessProbe::Immediate,
            readiness_timeout: Duration::from_secs(5),
            graceful_shutdown_timeout: Duration::from_secs(3),
            max_log_lines: 1000,
            runtime_config_cleanup: None,
            redact_logs: true,
        }
    }
}

enum SupervisorCommand {
    Stop { respond_to: oneshot::Sender<()> },
}

/// Супервизор жизненного цикла дочернего процесса Xray/sing-box
pub struct ProcessSupervisor {
    options: SupervisorOptions,
    state_tx: Arc<watch::Sender<SupervisorState>>,
    state_rx: watch::Receiver<SupervisorState>,
    log_tx: broadcast::Sender<String>,
    log_buffer: Arc<RwLock<VecDeque<String>>>,
    is_pattern_matched: Arc<AtomicBool>,
    active_pid: Arc<AtomicU32>,
    cmd_tx: Arc<Mutex<Option<mpsc::Sender<SupervisorCommand>>>>,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSupervisor {
    /// Создает супервизор с настройками по умолчанию
    pub fn new() -> Self {
        Self::with_options(SupervisorOptions::default())
    }

    /// Создает супервизор с пользовательскими настройками
    pub fn with_options(options: SupervisorOptions) -> Self {
        let (state_tx, state_rx) = watch::channel(SupervisorState::Stopped);
        let (log_tx, _) = broadcast::channel(1024);

        Self {
            options,
            state_tx: Arc::new(state_tx),
            state_rx,
            log_tx,
            log_buffer: Arc::new(RwLock::new(VecDeque::new())),
            is_pattern_matched: Arc::new(AtomicBool::new(false)),
            active_pid: Arc::new(AtomicU32::new(0)),
            cmd_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Текущее состояние процесса
    pub fn state(&self) -> SupervisorState {
        self.state_rx.borrow().clone()
    }

    /// Подписка на изменения состояния
    pub fn subscribe_state(&self) -> watch::Receiver<SupervisorState> {
        self.state_rx.clone()
    }

    /// Подписка на поток строк логов в реальном времени
    pub fn subscribe_logs(&self) -> broadcast::Receiver<String> {
        self.log_tx.subscribe()
    }

    /// Получить снимок последних строк логов из кольцевого буфера
    pub async fn get_logs(&self) -> Vec<String> {
        let buffer = self.log_buffer.read().await;
        buffer.iter().cloned().collect()
    }

    /// Получить PID активного дочернего процесса (если запущен)
    pub fn pid(&self) -> Option<u32> {
        let p = self.active_pid.load(Ordering::SeqCst);
        if p != 0 {
            Some(p)
        } else {
            None
        }
    }

    /// Проверка, запущен ли процесс
    pub fn is_running(&self) -> bool {
        matches!(
            self.state(),
            SupervisorState::Starting | SupervisorState::Ready
        )
    }

    /// Запуск сетевого ядра Xray-core / sing-box с указанным конфигурационным файлом
    pub async fn start(&mut self, binary_path: &str, config_path: &str) -> Result<()> {
        self.start_with_args(binary_path, &["run", "-c", config_path])
            .await
    }

    /// Запуск произвольной программы с аргументами под управлением супервизора
    pub async fn start_with_args(&mut self, program: &str, args: &[&str]) -> Result<()> {
        let current_state = self.state();
        if matches!(
            current_state,
            SupervisorState::Starting | SupervisorState::Ready
        ) {
            return Err(anyhow!(
                "Супервизор уже запущен в состоянии '{}'",
                current_state
            ));
        }

        info!("Запуск дочернего процесса: {} {:?}", program, args);
        self.set_state(SupervisorState::Starting);
        self.is_pattern_matched.store(false, Ordering::SeqCst);

        // Очищаем буфер логов для новой сессии
        {
            let mut buf = self.log_buffer.write().await;
            buf.clear();
        }

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let err_msg = format!("Не удалось запустить '{}': {}", program, e);
                error!("{}", err_msg);
                self.set_state(SupervisorState::Failed(err_msg.clone()));
                return Err(anyhow!(err_msg));
            }
        };

        let pid = child.id().unwrap_or(0);
        self.active_pid.store(pid, Ordering::SeqCst);
        info!("Процесс запущен с PID: {}", pid);

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let mut drain_tasks = Vec::new();

        // Запуск log drain для stdout
        if let Some(out) = stdout {
            let log_tx = self.log_tx.clone();
            let log_buffer = self.log_buffer.clone();
            let max_lines = self.options.max_log_lines;
            let pattern_flag = self.is_pattern_matched.clone();
            let target_pattern = match &self.options.readiness_probe {
                ReadinessProbe::LogPattern(p) => Some(p.clone()),
                _ => None,
            };
            let should_redact = self.options.redact_logs;

            let task = tokio::spawn(async move {
                let mut reader = BufReader::new(out).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let sanitized = if should_redact {
                        redact_log_line(&line)
                    } else {
                        line
                    };
                    debug!("[stdout] {}", sanitized);
                    let formatted = format!("[stdout] {}", sanitized);
                    if let Some(ref pat) = target_pattern {
                        if formatted.contains(pat) || sanitized.contains(pat) {
                            pattern_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    let _ = log_tx.send(formatted.clone());
                    let mut buf = log_buffer.write().await;
                    if buf.len() >= max_lines {
                        buf.pop_front();
                    }
                    buf.push_back(formatted);
                }
            });
            drain_tasks.push(task);
        }

        // Запуск log drain для stderr
        if let Some(err) = stderr {
            let log_tx = self.log_tx.clone();
            let log_buffer = self.log_buffer.clone();
            let max_lines = self.options.max_log_lines;
            let pattern_flag = self.is_pattern_matched.clone();
            let target_pattern = match &self.options.readiness_probe {
                ReadinessProbe::LogPattern(p) => Some(p.clone()),
                _ => None,
            };
            let should_redact = self.options.redact_logs;

            let task = tokio::spawn(async move {
                let mut reader = BufReader::new(err).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let sanitized = if should_redact {
                        redact_log_line(&line)
                    } else {
                        line
                    };
                    debug!("[stderr] {}", sanitized);
                    let formatted = format!("[stderr] {}", sanitized);
                    if let Some(ref pat) = target_pattern {
                        if formatted.contains(pat) || sanitized.contains(pat) {
                            pattern_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    let _ = log_tx.send(formatted.clone());
                    let mut buf = log_buffer.write().await;
                    if buf.len() >= max_lines {
                        buf.pop_front();
                    }
                    buf.push_back(formatted);
                }
            });
            drain_tasks.push(task);
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = oneshot::channel();

        {
            let mut guard = self.cmd_tx.lock().await;
            *guard = Some(cmd_tx);
        }

        let options_clone = self.options.clone();
        let state_tx_clone = self.state_tx.clone();
        let active_pid_clone = self.active_pid.clone();
        let pattern_flag_clone = self.is_pattern_matched.clone();

        // Запуск фонового воркера супервизора, владеющего Child
        let ctx = WorkerContext {
            child,
            pid,
            cmd_rx,
            readiness_tx,
            options: options_clone,
            state_tx: state_tx_clone,
            active_pid: active_pid_clone,
            pattern_flag: pattern_flag_clone,
            drain_tasks,
        };
        tokio::spawn(async move {
            run_supervisor_worker(ctx).await;
        });

        // Ожидание результата readiness проверки от воркера
        match readiness_rx.await {
            Ok(Ok(())) => {
                info!("Процесс успешно переведён в состояние Ready (PID {})", pid);
                Ok(())
            }
            Ok(Err(e)) => {
                let err_msg = format!("Readiness probe failed: {}", e);
                error!("{}", err_msg);
                {
                    let mut guard = self.cmd_tx.lock().await;
                    guard.take();
                }
                self.active_pid.store(0, Ordering::SeqCst);
                self.set_state(SupervisorState::Failed(err_msg.clone()));
                Err(anyhow!(err_msg))
            }
            Err(_) => {
                let err_msg = "Readiness probe channel dropped unexpectedly".to_string();
                error!("{}", err_msg);
                {
                    let mut guard = self.cmd_tx.lock().await;
                    guard.take();
                }
                self.active_pid.store(0, Ordering::SeqCst);
                self.set_state(SupervisorState::Failed(err_msg.clone()));
                Err(anyhow!(err_msg))
            }
        }
    }

    /// Корректная остановка процесса с graceful shutdown и forced-kill fallback
    pub async fn stop(&mut self) -> Result<()> {
        let current_state = self.state();
        if current_state == SupervisorState::Stopped {
            return Ok(());
        }

        info!("Остановка дочернего процесса (graceful stop)...");
        self.set_state(SupervisorState::Stopping);

        let cmd_tx = {
            let mut guard = self.cmd_tx.lock().await;
            guard.take()
        };

        if let Some(tx) = cmd_tx {
            let (resp_tx, resp_rx) = oneshot::channel();
            if tx
                .send(SupervisorCommand::Stop {
                    respond_to: resp_tx,
                })
                .await
                .is_ok()
            {
                let total_timeout = self.options.graceful_shutdown_timeout + Duration::from_secs(2);
                let _ = tokio::time::timeout(total_timeout, resp_rx).await;
            }
        }

        // Для абсолютной надёжности проверяем PID: если процесс ещё жив (worker завис), принудительно завершаем
        let pid = self.active_pid.swap(0, Ordering::SeqCst);
        if pid != 0 {
            kill_process_by_pid(pid);
        }

        // Очищаем cleanup файл если остался
        if let Some(ref path) = self.options.runtime_config_cleanup {
            if path.exists() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }

        self.set_state(SupervisorState::Stopped);
        info!("Дочерний процесс успешно остановлен.");
        Ok(())
    }

    fn set_state(&self, new_state: SupervisorState) {
        let _ = self.state_tx.send(new_state);
    }
}

struct WorkerContext {
    child: Child,
    pid: u32,
    cmd_rx: mpsc::Receiver<SupervisorCommand>,
    readiness_tx: oneshot::Sender<Result<()>>,
    options: SupervisorOptions,
    state_tx: Arc<watch::Sender<SupervisorState>>,
    active_pid: Arc<AtomicU32>,
    pattern_flag: Arc<AtomicBool>,
    drain_tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn run_supervisor_worker(ctx: WorkerContext) {
    let mut child = ctx.child;
    let pid = ctx.pid;
    let mut cmd_rx = ctx.cmd_rx;
    let readiness_tx = ctx.readiness_tx;
    let options = ctx.options;
    let state_tx = ctx.state_tx;
    let active_pid = ctx.active_pid;
    let pattern_flag = ctx.pattern_flag;
    let drain_tasks = ctx.drain_tasks;

    let probe = options.readiness_probe.clone();
    let timeout = options.readiness_timeout;
    let mut readiness_tx_opt = Some(readiness_tx);

    let start_time = tokio::time::Instant::now();
    let poll_interval = Duration::from_millis(10);

    // Фаза 1: Readiness probe loop
    loop {
        // Проверяем, не поступила ли команда Stop во время readiness
        if let Ok(SupervisorCommand::Stop { respond_to }) = cmd_rx.try_recv() {
            info!("Остановка во время readiness probe PID {}", pid);
            let _ = child.kill().await;
            active_pid.store(0, Ordering::SeqCst);
            if let Some(ref path) = options.runtime_config_cleanup {
                if path.exists() {
                    let _ = tokio::fs::remove_file(path).await;
                }
            }
            for h in drain_tasks {
                h.abort();
            }
            let _ = state_tx.send(SupervisorState::Stopped);
            let _ = respond_to.send(());
            if let Some(tx) = readiness_tx_opt.take() {
                let _ = tx.send(Err(anyhow!("Остановлено во время readiness probe")));
            }
            return;
        }

        // Проверяем, не завершился ли дочерний процесс преждевременно
        // Fail-closed: любое завершение до подтверждения готовности является ошибкой!
        match child.try_wait() {
            Ok(Some(status)) => {
                let err_msg = format!("Дочерний процесс преждевременно завершился: {}", status);
                warn!("{}", err_msg);
                active_pid.store(0, Ordering::SeqCst);
                if let Some(ref path) = options.runtime_config_cleanup {
                    if path.exists() {
                        let _ = tokio::fs::remove_file(path).await;
                    }
                }
                for h in drain_tasks {
                    h.abort();
                }
                let _ = state_tx.send(SupervisorState::Failed(err_msg.clone()));
                if let Some(tx) = readiness_tx_opt.take() {
                    let _ = tx.send(Err(anyhow!(err_msg)));
                }
                return;
            }
            Ok(None) => {}
            Err(e) => {
                let err_msg = format!("Ошибка проверки статуса процесса: {}", e);
                error!("{}", err_msg);
                active_pid.store(0, Ordering::SeqCst);
                if let Some(ref path) = options.runtime_config_cleanup {
                    if path.exists() {
                        let _ = tokio::fs::remove_file(path).await;
                    }
                }
                for h in drain_tasks {
                    h.abort();
                }
                let _ = state_tx.send(SupervisorState::Failed(err_msg.clone()));
                if let Some(tx) = readiness_tx_opt.take() {
                    let _ = tx.send(Err(anyhow!(err_msg)));
                }
                return;
            }
        }

        // Проверка условия readiness
        let is_ready = match &probe {
            ReadinessProbe::Immediate => {
                // Даем 150мс убедиться, что процесс не падает мгновенно
                start_time.elapsed() >= Duration::from_millis(150)
            }
            ReadinessProbe::TcpPort(port) => {
                let addr = format!("127.0.0.1:{}", port);
                TcpStream::connect(&addr).await.is_ok()
            }
            ReadinessProbe::LogPattern(_) => pattern_flag.load(Ordering::SeqCst),
        };

        if is_ready {
            // Атомарная перепроверка активности процесса: исключаем окно гонки перед отправкой Ready
            match child.try_wait() {
                Ok(Some(status)) => {
                    let err_msg = format!(
                        "Дочерний процесс преждевременно завершился до подтверждения готовности: {}",
                        status
                    );
                    warn!("{}", err_msg);
                    active_pid.store(0, Ordering::SeqCst);
                    if let Some(ref path) = options.runtime_config_cleanup {
                        if path.exists() {
                            let _ = tokio::fs::remove_file(path).await;
                        }
                    }
                    for h in drain_tasks {
                        h.abort();
                    }
                    let _ = state_tx.send(SupervisorState::Failed(err_msg.clone()));
                    if let Some(tx) = readiness_tx_opt.take() {
                        let _ = tx.send(Err(anyhow!(err_msg)));
                    }
                    return;
                }
                Ok(None) => {
                    let _ = state_tx.send(SupervisorState::Ready);
                    if let Some(tx) = readiness_tx_opt.take() {
                        let _ = tx.send(Ok(()));
                    }
                    break;
                }
                Err(e) => {
                    let err_msg = format!("Ошибка проверки статуса процесса: {}", e);
                    error!("{}", err_msg);
                    active_pid.store(0, Ordering::SeqCst);
                    if let Some(ref path) = options.runtime_config_cleanup {
                        if path.exists() {
                            let _ = tokio::fs::remove_file(path).await;
                        }
                    }
                    for h in drain_tasks {
                        h.abort();
                    }
                    let _ = state_tx.send(SupervisorState::Failed(err_msg.clone()));
                    if let Some(tx) = readiness_tx_opt.take() {
                        let _ = tx.send(Err(anyhow!(err_msg)));
                    }
                    return;
                }
            }
        }

        if start_time.elapsed() >= timeout {
            let err_msg = format!(
                "Таймаут ожидания готовности процесса ({}ms)",
                timeout.as_millis()
            );
            error!("{}", err_msg);
            let _ = child.kill().await;
            active_pid.store(0, Ordering::SeqCst);
            if let Some(ref path) = options.runtime_config_cleanup {
                if path.exists() {
                    let _ = tokio::fs::remove_file(path).await;
                }
            }
            for h in drain_tasks {
                h.abort();
            }
            let _ = state_tx.send(SupervisorState::Failed(err_msg.clone()));
            if let Some(tx) = readiness_tx_opt.take() {
                let _ = tx.send(Err(anyhow!(err_msg)));
            }
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Фаза 2: Основной цикл работы в состоянии Ready
    tokio::select! {
        cmd = cmd_rx.recv() => {
            match cmd {
                Some(SupervisorCommand::Stop { respond_to }) => {
                    info!("Получена команда остановки дочернего процесса PID {}", pid);
                    let _ = state_tx.send(SupervisorState::Stopping);

                    // 1. Попытка graceful завершения (SIGTERM на Unix)
                    #[cfg(unix)]
                    if pid != 0 {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGTERM);
                        }
                    }

                    // 2. Ожидание завершения в течение graceful_shutdown_timeout
                    let wait_res = tokio::time::timeout(options.graceful_shutdown_timeout, child.wait()).await;
                    match wait_res {
                        Ok(Ok(status)) => {
                            debug!("Процесс PID {} штатно завершился: {}", pid, status);
                        }
                        _ => {
                            warn!("Таймаут graceful остановки PID {}, принудительное завершение...", pid);
                            let _ = child.kill().await;
                        }
                    }

                    active_pid.store(0, Ordering::SeqCst);

                    // 3. Очистка runtime config
                    if let Some(ref path) = options.runtime_config_cleanup {
                        if path.exists() {
                            let _ = tokio::fs::remove_file(path).await;
                        }
                    }

                    // 4. Остановка drain задач
                    for h in drain_tasks {
                        h.abort();
                    }

                    let _ = state_tx.send(SupervisorState::Stopped);
                    let _ = respond_to.send(());
                }
                None => {
                    // Канал команд супервизора закрыт (Drop) — немедленно завершаем дочерний процесс
                    debug!("Канал команд супервизора закрыт (Drop), завершение дочернего процесса PID {}", pid);
                    let _ = child.kill().await;
                    active_pid.store(0, Ordering::SeqCst);

                    if let Some(ref path) = options.runtime_config_cleanup {
                        if path.exists() {
                            let _ = tokio::fs::remove_file(path).await;
                        }
                    }

                    for h in drain_tasks {
                        h.abort();
                    }

                    let _ = state_tx.send(SupervisorState::Stopped);
                }
            }
        }
        status = child.wait() => {
            // Самопроизвольное завершение дочернего процесса
            active_pid.store(0, Ordering::SeqCst);
            let current_state = state_tx.borrow().clone();

            if let Some(ref path) = options.runtime_config_cleanup {
                if path.exists() {
                    let _ = tokio::fs::remove_file(path).await;
                }
            }

            for h in drain_tasks {
                h.abort();
            }

            match status {
                Ok(exit_status) => {
                    if current_state == SupervisorState::Stopping {
                        let _ = state_tx.send(SupervisorState::Stopped);
                    } else if exit_status.success() {
                        info!("Дочерний процесс PID {} завершился успешно (код 0).", pid);
                        let _ = state_tx.send(SupervisorState::Stopped);
                    } else {
                        warn!("Дочерний процесс PID {} неожиданно упал: {}", pid, exit_status);
                        let _ = state_tx.send(SupervisorState::Failed(format!(
                            "Процесс неожиданно завершился: {}",
                            exit_status
                        )));
                    }
                }
                Err(e) => {
                    error!("Ошибка ожидания дочернего процесса PID {}: {}", pid, e);
                    if current_state != SupervisorState::Stopping {
                        let _ = state_tx.send(SupervisorState::Failed(e.to_string()));
                    }
                }
            }
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        let pid = self.active_pid.swap(0, Ordering::SeqCst);
        if pid != 0 {
            kill_process_by_pid(pid);
        }
        if let Some(ref path) = self.options.runtime_config_cleanup {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Маскирование конфиденциальных данных в строке лога (UUID, IPv4, IPv6)
pub fn redact_log_line(line: &str) -> String {
    let mut result = line.to_string();
    result = mask_uuids(&result);
    result = mask_ipv4(&result);
    result = mask_ipv6(&result);
    result
}

fn mask_uuids(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 36 <= chars.len() && is_uuid_slice(&chars[i..i + 36]) {
            output.push_str("[REDACTED-UUID]");
            i += 36;
        } else {
            output.push(chars[i]);
            i += 1;
        }
    }
    output
}

fn is_uuid_slice(slice: &[char]) -> bool {
    if slice.len() != 36 {
        return false;
    }
    for (idx, &c) in slice.iter().enumerate() {
        if idx == 8 || idx == 13 || idx == 18 || idx == 23 {
            if c != '-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn mask_ipv4(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let words: Vec<&str> = input
        .split_inclusive(|c: char| !c.is_ascii_digit() && c != '.')
        .collect();

    for segment in words {
        let (digits_and_dots, trailing) = split_trailing_delimiter(segment);
        if is_valid_ipv4_literal(digits_and_dots) {
            output.push_str("[REDACTED-IP]");
            output.push_str(trailing);
        } else {
            output.push_str(segment);
        }
    }
    output
}

fn split_trailing_delimiter(s: &str) -> (&str, &str) {
    if let Some(pos) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..pos], &s[pos..])
    } else {
        (s, "")
    }
}

fn is_valid_ipv4_literal(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        if let Ok(val) = p.parse::<u8>() {
            if val.to_string() != p {
                return false; // Защита от ведущих нулей (01.02...)
            }
        } else {
            return false;
        }
    }
    true
}

fn mask_ipv6(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let words: Vec<&str> = input
        .split_inclusive(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'')
        .collect();

    for segment in words {
        let (body, trailing) = split_trailing_delimiter_v6(segment);
        if let Some(masked) = try_mask_single_ipv6_token(body) {
            output.push_str(&masked);
            output.push_str(trailing);
        } else {
            output.push_str(segment);
        }
    }
    output
}

fn split_trailing_delimiter_v6(s: &str) -> (&str, &str) {
    if let Some(pos) = s.find(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'') {
        (&s[..pos], &s[pos..])
    } else {
        (s, "")
    }
}

fn try_mask_single_ipv6_token(token: &str) -> Option<String> {
    // 1. Bracketed format: [2001:db8::1234] or [2001:db8::1234]:443
    if token.starts_with('[') {
        if let Some(close_bracket) = token.find(']') {
            let inside = &token[1..close_bracket];
            if inside.contains(':') && inside.parse::<std::net::Ipv6Addr>().is_ok() {
                let rest = &token[close_bracket + 1..];
                return Some(format!("[[REDACTED-IPV6]]{}", rest));
            }
        }
    }

    // 2. Unbracketed IPv6: 2001:db8::1234
    if token.contains(':') && token.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some("[REDACTED-IPV6]".to_string());
    }

    None
}

/// Проверка, жив ли процесс по PID
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
        fn GetExitCodeProcess(hProcess: isize, lpExitCode: *mut u32) -> i32;
        fn CloseHandle(hObject: isize) -> i32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle == 0 {
            return false;
        }
        let mut exit_code: u32 = 0;
        let success = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        success != 0 && exit_code == STILL_ACTIVE
    }
}

#[cfg(not(any(unix, windows)))]
pub fn is_process_alive(_pid: u32) -> bool {
    false
}

/// Принудительное уничтожение процесса по PID
#[cfg(unix)]
pub fn kill_process_by_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
pub fn kill_process_by_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
        fn TerminateProcess(hProcess: isize, uExitCode: u32) -> i32;
        fn CloseHandle(hObject: isize) -> i32;
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle != 0 {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn kill_process_by_pid(_pid: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_state_display_and_equality() {
        assert_eq!(SupervisorState::Stopped.to_string(), "Stopped");
        assert_eq!(SupervisorState::Starting.to_string(), "Starting");
        assert_eq!(SupervisorState::Ready.to_string(), "Ready");
        assert_eq!(SupervisorState::Stopping.to_string(), "Stopping");
        assert_eq!(
            SupervisorState::Failed("timeout".to_string()).to_string(),
            "Failed: timeout"
        );
    }

    #[tokio::test]
    async fn test_supervisor_initial_state_is_stopped() {
        let supervisor = ProcessSupervisor::new();
        assert_eq!(supervisor.state(), SupervisorState::Stopped);
        assert!(!supervisor.is_running());
        assert_eq!(supervisor.pid(), None);
    }

    #[tokio::test]
    async fn test_supervisor_spawn_nonexistent_binary_fails() {
        let mut supervisor = ProcessSupervisor::new();
        let res = supervisor
            .start_with_args("/nonexistent_binary_path_12345", &[])
            .await;
        assert!(res.is_err());
        assert!(matches!(supervisor.state(), SupervisorState::Failed(_)));
    }

    #[test]
    fn test_redact_log_line_masks_sensitive_data() {
        let raw = "Connected user 00000000-0000-4000-8000-000000000001 to remote server 192.0.2.10:443 via [2001:db8::1234]:8443";
        let redacted = redact_log_line(raw);
        assert_eq!(
            redacted,
            "Connected user [REDACTED-UUID] to remote server [REDACTED-IP]:443 via [[REDACTED-IPV6]]:8443"
        );
    }
}
