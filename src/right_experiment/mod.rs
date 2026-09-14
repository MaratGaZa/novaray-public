//! Opt-in experiment controller, never used by the product CLI or helper.
//! A successful base case is not production ownership, restoration or Gate H/I evidence.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native;
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
mod protocol;

use std::process::ExitCode;

/// Only `--help` is safe without per-run authorization. There is no unattended mode.
pub fn entry(args: Vec<String>) -> ExitCode {
    if args == ["--help"] {
        println!("Experimental target only. --run requires a private terminal, dedicated disposable\n\
            Apple Silicon macOS, verified whole-environment restore, controlled writers, reviewed\n\
            binary SHA-256 and explicit per-run approval. Run from an empty private 0700 directory.\n\
            Native calls may prompt. Deadline: 120 seconds including operator input.\n\
            Exit: 0 verified base case; 2 refused; 3 quarantine/unknown effects.\n\
            See docs/AUTHORIZATION_RIGHT_NATIVE_VALIDATION.md. No resume or cleanup command.");
        return ExitCode::SUCCESS;
    }
    if args != ["--run"] {
        eprintln!("expected --help or --run; no experiment started");
        return ExitCode::from(2);
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return native::run();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        eprintln!("experiment requires macOS Apple Silicon; no experiment started");
        ExitCode::from(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_help_and_invalid_arguments_never_enter_native_runner() {
        assert_eq!(entry(vec!["--help".into()]), ExitCode::SUCCESS);
        for args in [
            vec![],
            vec!["--cleanup".into()],
            vec!["--run".into(), "x".into()],
        ] {
            assert_eq!(entry(args), ExitCode::from(2));
        }
    }
}
