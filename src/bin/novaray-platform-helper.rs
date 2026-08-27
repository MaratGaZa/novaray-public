//! Side-effect-free platform helper skeleton entrypoint.

use std::io::{self, Read, Write};

use novaray_core::platform_contract::{PlatformHelperEvent, MAX_PLATFORM_MESSAGE_BYTES};
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

    let mut input = Vec::with_capacity(MAX_PLATFORM_MESSAGE_BYTES.min(8192));
    let read_limit = MAX_PLATFORM_MESSAGE_BYTES as u64 + 1;
    if let Err(error) = io::stdin().take(read_limit).read_to_end(&mut input) {
        eprintln!("failed to read command: {error}");
        std::process::exit(PlatformHelperExitCode::IoError.as_i32());
    }

    if input.len() > MAX_PLATFORM_MESSAGE_BYTES {
        let event = PlatformHelperEvent::CommandRejected(format!(
            "payload_too_large: limit={MAX_PLATFORM_MESSAGE_BYTES}"
        ));
        if write_event(&event).is_err() {
            std::process::exit(PlatformHelperExitCode::IoError.as_i32());
        }
        std::process::exit(PlatformHelperExitCode::Rejected.as_i32());
    }

    let result = run_helper_once(&input);
    match write_event(&result.event) {
        Ok(()) => {}
        Err(exit_code) => {
            eprintln!("failed to write helper event");
            std::process::exit(exit_code.as_i32());
        }
    }

    std::process::exit(result.exit_code.as_i32());
}

fn write_event(event: &PlatformHelperEvent) -> Result<(), PlatformHelperExitCode> {
    let payload = serde_json::to_vec(event).map_err(|_| PlatformHelperExitCode::InternalError)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&payload)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| PlatformHelperExitCode::IoError)
}
