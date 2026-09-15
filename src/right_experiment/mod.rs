//! Opt-in experiment controller, never used by the product CLI or helper.
//! A successful base case is not production ownership, restoration or Gate H/I evidence.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native;
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
mod protocol;

use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::ExitCode;

const MANIFEST_NAME: &str = "native-right-roundtrip.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightStatus {
    Pass,
    Manual,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreflightCheck {
    name: &'static str,
    status: PreflightStatus,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryPreflight {
    private_directory: bool,
    manifest_absent: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreflightInputs {
    target_supported: bool,
    private_terminal: bool,
    ci_present: bool,
    directory: DirectoryPreflight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreflightReport {
    checks: Vec<PreflightCheck>,
}

impl PreflightReport {
    fn automation_allows_operator_review(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status != PreflightStatus::Fail)
    }
}

fn preflight_report(input: PreflightInputs) -> PreflightReport {
    let mut checks = vec![
        PreflightCheck {
            name: "target",
            status: if input.target_supported {
                PreflightStatus::Pass
            } else {
                PreflightStatus::Fail
            },
            detail: if input.target_supported {
                "macOS Apple Silicon target".into()
            } else {
                "experiment target must be macOS Apple Silicon".into()
            },
        },
        PreflightCheck {
            name: "terminal",
            status: if input.private_terminal {
                PreflightStatus::Pass
            } else {
                PreflightStatus::Fail
            },
            detail: if input.private_terminal {
                "stdin/stdout/stderr are terminals".into()
            } else {
                "stdin/stdout/stderr must all be private terminals".into()
            },
        },
        PreflightCheck {
            name: "ci",
            status: if input.ci_present {
                PreflightStatus::Fail
            } else {
                PreflightStatus::Pass
            },
            detail: if input.ci_present {
                "CI environment is present".into()
            } else {
                "CI environment is absent".into()
            },
        },
        PreflightCheck {
            name: "directory",
            status: if input.directory.private_directory {
                PreflightStatus::Pass
            } else {
                PreflightStatus::Fail
            },
            detail: input.directory.detail,
        },
        PreflightCheck {
            name: "manifest",
            status: if input.directory.manifest_absent {
                PreflightStatus::Pass
            } else {
                PreflightStatus::Fail
            },
            detail: if input.directory.manifest_absent {
                format!("{MANIFEST_NAME} is absent")
            } else {
                format!("{MANIFEST_NAME} already exists or is not inspectable")
            },
        },
    ];
    checks.extend([
        PreflightCheck {
            name: "disposable-environment",
            status: PreflightStatus::Manual,
            detail: "owner must separately verify dedicated disposable macOS environment".into(),
        },
        PreflightCheck {
            name: "restore-drill",
            status: PreflightStatus::Manual,
            detail: "whole-environment restore drill remains manual evidence".into(),
        },
        PreflightCheck {
            name: "exclusive-writers",
            status: PreflightStatus::Manual,
            detail: "operator must establish there are no other authorization database writers"
                .into(),
        },
        PreflightCheck {
            name: "reviewed-binary",
            status: PreflightStatus::Manual,
            detail: "reviewed commit and binary digest are checked only by per-run approval".into(),
        },
        PreflightCheck {
            name: "owner-approval",
            status: PreflightStatus::Manual,
            detail: "`--preflight` is not approval to execute `--run`".into(),
        },
    ]);
    PreflightReport { checks }
}

fn collect_preflight_inputs() -> PreflightInputs {
    PreflightInputs {
        target_supported: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        private_terminal: std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        ci_present: std::env::var_os("CI").is_some(),
        directory: inspect_current_directory(),
    }
}

#[cfg(unix)]
fn inspect_current_directory() -> DirectoryPreflight {
    let metadata = match std::fs::metadata(".") {
        Ok(metadata) => metadata,
        Err(_) => {
            return DirectoryPreflight {
                private_directory: false,
                manifest_absent: false,
                detail: "current directory cannot be inspected".into(),
            }
        }
    };
    // SAFETY: getuid/geteuid have no preconditions and do not mutate process or system state.
    let (uid, effective_uid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let private_directory = uid != 0
        && effective_uid == uid
        && metadata.is_dir()
        && metadata.uid() == uid
        && metadata.permissions().mode() & 0o777 == 0o700;
    let manifest_absent = std::fs::symlink_metadata(MANIFEST_NAME).is_err();
    let detail = if private_directory {
        "current directory is owned by current UID with mode 0700".into()
    } else {
        "current directory must be a non-root owned directory with mode 0700".into()
    };
    DirectoryPreflight {
        private_directory,
        manifest_absent,
        detail,
    }
}

#[cfg(not(unix))]
fn inspect_current_directory() -> DirectoryPreflight {
    DirectoryPreflight {
        private_directory: false,
        manifest_absent: false,
        detail: "native right experiment requires Unix directory ownership and mode checks".into(),
    }
}

fn print_preflight(report: &PreflightReport) {
    println!(
        "Native right experiment preflight (no Authorization Services calls, no manifest write):"
    );
    for check in &report.checks {
        let status = match check.status {
            PreflightStatus::Pass => "pass",
            PreflightStatus::Manual => "manual",
            PreflightStatus::Fail => "fail",
        };
        println!("- {status}: {} — {}", check.name, check.detail);
    }
    if report.automation_allows_operator_review() {
        println!(
            "Automated preflight passed; this still does not prove disposable restore, writer control, owner approval, native evidence or Gate I/H."
        );
    } else {
        println!("Automated preflight failed; no experiment may be started.");
    }
}

/// `--help` and `--preflight` are safe without per-run authorization. There is no unattended mode.
pub fn entry(args: Vec<String>) -> ExitCode {
    if args == ["--help"] {
        println!("Experimental target only. --preflight performs no Authorization Services calls\n\
            and no manifest write. --run requires a private terminal, dedicated disposable\n\
            Apple Silicon macOS, verified whole-environment restore, controlled writers, reviewed\n\
            binary SHA-256 and explicit per-run approval. Run from an empty private 0700 directory.\n\
            Native calls may prompt. Deadline: 120 seconds including operator input.\n\
            Exit: 0 verified base case; 2 refused; 3 quarantine/unknown effects.\n\
            See docs/AUTHORIZATION_RIGHT_NATIVE_VALIDATION.md. No resume or cleanup command.");
        return ExitCode::SUCCESS;
    }
    if args == ["--preflight"] {
        let report = preflight_report(collect_preflight_inputs());
        let passed = report.automation_allows_operator_review();
        print_preflight(&report);
        return if passed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    if args != ["--run"] {
        eprintln!("expected --help, --preflight or --run; no experiment started");
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

    #[test]
    fn preflight_accepts_only_automated_checks_and_keeps_manual_gates_open() {
        let report = preflight_report(PreflightInputs {
            target_supported: true,
            private_terminal: true,
            ci_present: false,
            directory: DirectoryPreflight {
                private_directory: true,
                manifest_absent: true,
                detail: "ok".into(),
            },
        });
        assert!(report.automation_allows_operator_review());
        assert_eq!(
            report
                .checks
                .iter()
                .filter(|check| check.status == PreflightStatus::Manual)
                .count(),
            5
        );
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "owner-approval"
                && check.detail.contains("not approval to execute")));
    }

    #[test]
    fn preflight_fails_closed_for_ci_nonterminal_platform_directory_or_manifest() {
        let cases = [
            PreflightInputs {
                target_supported: false,
                private_terminal: true,
                ci_present: false,
                directory: DirectoryPreflight {
                    private_directory: true,
                    manifest_absent: true,
                    detail: "ok".into(),
                },
            },
            PreflightInputs {
                target_supported: true,
                private_terminal: false,
                ci_present: false,
                directory: DirectoryPreflight {
                    private_directory: true,
                    manifest_absent: true,
                    detail: "ok".into(),
                },
            },
            PreflightInputs {
                target_supported: true,
                private_terminal: true,
                ci_present: true,
                directory: DirectoryPreflight {
                    private_directory: true,
                    manifest_absent: true,
                    detail: "ok".into(),
                },
            },
            PreflightInputs {
                target_supported: true,
                private_terminal: true,
                ci_present: false,
                directory: DirectoryPreflight {
                    private_directory: false,
                    manifest_absent: true,
                    detail: "bad".into(),
                },
            },
            PreflightInputs {
                target_supported: true,
                private_terminal: true,
                ci_present: false,
                directory: DirectoryPreflight {
                    private_directory: true,
                    manifest_absent: false,
                    detail: "bad".into(),
                },
            },
        ];
        for input in cases {
            let report = preflight_report(input);
            assert!(!report.automation_allows_operator_review());
        }
    }
}
