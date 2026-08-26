//! Side-effect-free platform helper skeleton entrypoint.

use std::io::{self, Read, Write};

use novaray_core::platform_helper::{run_helper_once, PlatformHelperExitCode};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "novaray-platform-helper\n\nReads one PlatformHelperCommand JSON document from stdin and writes one PlatformHelperEvent JSON document to stdout.\nThis skeleton does not run as root, install launchd jobs, open sockets, create utun, or mutate routes/DNS/firewall."
        );
        return;
    }

    if !args.is_empty() {
        eprintln!("unexpected argument");
        std::process::exit(PlatformHelperExitCode::Usage.as_i32());
    }

    let mut input = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut input) {
        eprintln!("failed to read command: {error}");
        std::process::exit(PlatformHelperExitCode::IoError.as_i32());
    }

    let result = run_helper_once(&input);
    match serde_json::to_vec(&result.event) {
        Ok(payload) => {
            let mut stdout = io::stdout().lock();
            if stdout
                .write_all(&payload)
                .and_then(|_| stdout.write_all(b"\n"))
                .is_err()
            {
                std::process::exit(PlatformHelperExitCode::IoError.as_i32());
            }
        }
        Err(error) => {
            eprintln!("failed to serialize helper event: {error}");
            std::process::exit(PlatformHelperExitCode::InternalError.as_i32());
        }
    }

    std::process::exit(result.exit_code.as_i32());
}
