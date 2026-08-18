//! NovaRay Core CLI Entrypoint
use novaray_core::cli::{execute_command, parse_args, ExitCode};
use tracing::Level;

#[tokio::main]
async fn main() {
    // 1. Инициализация логирования (env-filter или INFO по умолчанию)
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_max_level(Level::INFO)
        .try_init();

    // 2. Сбор аргументов командной строки (пропуская нулевой аргумент - имя бинарника)
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // 3. Парсинг команды
    let cmd = match parse_args(&raw_args) {
        Ok(cmd) => cmd,
        Err((err_msg, code)) => {
            eprintln!("Ошибка: {}", err_msg);
            std::process::exit(code.as_i32());
        }
    };

    // 4. Выполнение команды
    let exit_code = execute_command(cmd).await;
    if exit_code != ExitCode::Success {
        std::process::exit(exit_code.as_i32());
    }
}
