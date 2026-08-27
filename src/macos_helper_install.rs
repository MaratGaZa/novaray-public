//! Side-effect-free install/uninstall plan contract for the macOS privileged helper.
//!
//! The contract models the future administrative step as typed operations. It does not prompt for
//! authorization, write to `/Library`, call `launchctl`, run as root, open IPC sockets, create
//! `utun`, or mutate routes, DNS, firewall, system proxy or packet-flow state.

use std::fmt;

use thiserror::Error;

use crate::macos_launchd::{LaunchdDaemonSpec, DEFAULT_HELPER_PROGRAM_PATH, DEFAULT_LAUNCHD_LABEL};

pub const DEFAULT_LAUNCHD_PLIST_PATH: &str =
    "/Library/LaunchDaemons/org.novaray.platform-helper.plist";
pub const ROOT_USER: &str = "root";
pub const WHEEL_GROUP: &str = "wheel";
pub const HELPER_MODE: u16 = 0o755;
pub const PLIST_MODE: u16 = 0o644;
pub const MAX_INSTALL_PATH_BYTES: usize = 4096;
pub const SHA256_HEX_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthorizationMethod {
    ManualSudo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuthorizationRequirement {
    pub method: AdminAuthorizationMethod,
    pub reason: String,
}

impl Default for AdminAuthorizationRequirement {
    fn default() -> Self {
        Self {
            method: AdminAuthorizationMethod::ManualSudo,
            reason: "Install or remove NovaRay privileged helper under /Library".to_string(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HelperInstallPlan {
    pub authorization: AdminAuthorizationRequirement,
    pub operations: Vec<HelperInstallOperation>,
}

impl fmt::Debug for HelperInstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperInstallPlan")
            .field("authorization", &self.authorization)
            .field("operations", &self.operations)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperInstallOperation {
    CopyHelper {
        source_path: String,
        expected_sha256: String,
        destination_path: String,
        owner: String,
        group: String,
        mode: u16,
    },
    WriteLaunchDaemonPlist {
        path: String,
        label: String,
        plist_xml: String,
        owner: String,
        group: String,
        mode: u16,
    },
    LoadLaunchDaemon {
        path: String,
        label: String,
    },
    UnloadLaunchDaemon {
        label: String,
    },
    RemoveFile {
        path: String,
    },
}

impl HelperInstallPlan {
    pub fn install(
        source_helper_path: impl Into<String>,
        expected_sha256: impl Into<String>,
    ) -> Result<Self, HelperInstallError> {
        let source_helper_path = source_helper_path.into();
        let expected_sha256 = expected_sha256.into();
        validate_install_path(&source_helper_path)?;
        validate_expected_sha256(&expected_sha256)?;

        let launchd = LaunchdDaemonSpec {
            disabled: false,
            run_at_load: false,
            keep_alive: true,
            ..LaunchdDaemonSpec::disabled_default()
        };
        let plist_xml = launchd
            .to_plist_xml()
            .map_err(HelperInstallError::Launchd)?;

        let plan = Self {
            authorization: AdminAuthorizationRequirement::default(),
            operations: vec![
                HelperInstallOperation::CopyHelper {
                    source_path: source_helper_path,
                    expected_sha256,
                    destination_path: DEFAULT_HELPER_PROGRAM_PATH.to_string(),
                    owner: ROOT_USER.to_string(),
                    group: WHEEL_GROUP.to_string(),
                    mode: HELPER_MODE,
                },
                HelperInstallOperation::WriteLaunchDaemonPlist {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                    plist_xml,
                    owner: ROOT_USER.to_string(),
                    group: WHEEL_GROUP.to_string(),
                    mode: PLIST_MODE,
                },
                HelperInstallOperation::LoadLaunchDaemon {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                },
            ],
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn uninstall() -> Result<Self, HelperInstallError> {
        let plan = Self {
            authorization: AdminAuthorizationRequirement::default(),
            operations: vec![
                HelperInstallOperation::UnloadLaunchDaemon {
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                },
                HelperInstallOperation::RemoveFile {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                },
                HelperInstallOperation::RemoveFile {
                    path: DEFAULT_HELPER_PROGRAM_PATH.to_string(),
                },
            ],
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), HelperInstallError> {
        validate_authorization(&self.authorization)?;
        if self.operations.is_empty() {
            return Err(HelperInstallError::MissingOperation);
        }

        let mut has_helper_copy = false;
        let mut has_plist_write = false;
        let mut has_load = false;
        let mut has_unload = false;
        let mut removes_plist = false;
        let mut removes_helper = false;

        for operation in &self.operations {
            match operation {
                HelperInstallOperation::CopyHelper {
                    source_path,
                    expected_sha256,
                    destination_path,
                    owner,
                    group,
                    mode,
                } => {
                    validate_install_path(source_path)?;
                    validate_expected_sha256(expected_sha256)?;
                    validate_fixed_path(destination_path, DEFAULT_HELPER_PROGRAM_PATH)?;
                    validate_root_wheel(owner, group)?;
                    validate_mode(*mode, HELPER_MODE)?;
                    has_helper_copy = true;
                }
                HelperInstallOperation::WriteLaunchDaemonPlist {
                    path,
                    label,
                    plist_xml,
                    owner,
                    group,
                    mode,
                } => {
                    validate_fixed_path(path, DEFAULT_LAUNCHD_PLIST_PATH)?;
                    validate_label(label)?;
                    validate_plist(plist_xml)?;
                    validate_root_wheel(owner, group)?;
                    validate_mode(*mode, PLIST_MODE)?;
                    has_plist_write = true;
                }
                HelperInstallOperation::LoadLaunchDaemon { path, label } => {
                    validate_fixed_path(path, DEFAULT_LAUNCHD_PLIST_PATH)?;
                    validate_label(label)?;
                    has_load = true;
                }
                HelperInstallOperation::UnloadLaunchDaemon { label } => {
                    validate_label(label)?;
                    has_unload = true;
                }
                HelperInstallOperation::RemoveFile { path } => {
                    validate_install_path(path)?;
                    if path == DEFAULT_LAUNCHD_PLIST_PATH {
                        removes_plist = true;
                    } else if path == DEFAULT_HELPER_PROGRAM_PATH {
                        removes_helper = true;
                    } else {
                        return Err(HelperInstallError::UnexpectedRemovalPath);
                    }
                }
            }
        }

        let is_install = has_helper_copy || has_plist_write || has_load;
        let is_uninstall = has_unload || removes_plist || removes_helper;
        match (is_install, is_uninstall) {
            (true, true) => Err(HelperInstallError::MixedInstallAndUninstall),
            (true, false) if has_helper_copy && has_plist_write && has_load => Ok(()),
            (true, false) => Err(HelperInstallError::IncompleteInstallPlan),
            (false, true) if has_unload && removes_plist && removes_helper => Ok(()),
            (false, true) => Err(HelperInstallError::IncompleteUninstallPlan),
            (false, false) => Err(HelperInstallError::MissingOperation),
        }
    }
}

pub trait HelperInstallSourceInspector {
    fn helper_sha256(&mut self, source_path: &str) -> Result<String, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperInstallPreflightExecutor<I> {
    inspector: I,
    records: Vec<HelperInstallPreflightRecord>,
}

impl<I> HelperInstallPreflightExecutor<I>
where
    I: HelperInstallSourceInspector,
{
    pub fn new(inspector: I) -> Self {
        Self {
            inspector,
            records: Vec::new(),
        }
    }

    pub fn execute(&mut self, plan: &HelperInstallPlan) -> Result<(), HelperInstallError> {
        plan.validate()?;
        self.records.clear();

        for operation in &plan.operations {
            match operation {
                HelperInstallOperation::CopyHelper {
                    source_path,
                    expected_sha256,
                    destination_path,
                    ..
                } => {
                    let actual_sha256 = self
                        .inspector
                        .helper_sha256(source_path)
                        .map_err(|reason| HelperInstallError::SourceInspectorFailed { reason })?;
                    validate_expected_sha256(&actual_sha256)?;
                    if actual_sha256 != *expected_sha256 {
                        return Err(HelperInstallError::HelperSourceSha256Mismatch {
                            expected: expected_sha256.clone(),
                            actual: actual_sha256,
                        });
                    }
                    self.records
                        .push(HelperInstallPreflightRecord::CopyHelperVerified {
                            source_path: source_path.clone(),
                            expected_sha256: expected_sha256.clone(),
                            actual_sha256,
                            destination_path: destination_path.clone(),
                        });
                }
                HelperInstallOperation::WriteLaunchDaemonPlist { path, label, .. } => {
                    self.records.push(
                        HelperInstallPreflightRecord::WriteLaunchDaemonPlistValidated {
                            path: path.clone(),
                            label: label.clone(),
                        },
                    );
                }
                HelperInstallOperation::LoadLaunchDaemon { path, label } => {
                    self.records
                        .push(HelperInstallPreflightRecord::LoadLaunchDaemonValidated {
                            path: path.clone(),
                            label: label.clone(),
                        });
                }
                HelperInstallOperation::UnloadLaunchDaemon { label } => {
                    self.records
                        .push(HelperInstallPreflightRecord::UnloadLaunchDaemonValidated {
                            label: label.clone(),
                        });
                }
                HelperInstallOperation::RemoveFile { path } => {
                    self.records
                        .push(HelperInstallPreflightRecord::RemoveFileValidated {
                            path: path.clone(),
                        });
                }
            }
        }

        Ok(())
    }

    pub fn records(&self) -> &[HelperInstallPreflightRecord] {
        &self.records
    }

    pub fn into_inner(self) -> I {
        self.inspector
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperInstallPreflightRecord {
    CopyHelperVerified {
        source_path: String,
        expected_sha256: String,
        actual_sha256: String,
        destination_path: String,
    },
    WriteLaunchDaemonPlistValidated {
        path: String,
        label: String,
    },
    LoadLaunchDaemonValidated {
        path: String,
        label: String,
    },
    UnloadLaunchDaemonValidated {
        label: String,
    },
    RemoveFileValidated {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HelperInstallError {
    #[error("helper install plan requires an administrative authorization reason")]
    MissingAuthorizationReason,

    #[error("helper install path must be an absolute POSIX path")]
    RelativePath,

    #[error("helper install path exceeds {limit} bytes: {actual}")]
    OversizedPath { limit: usize, actual: usize },

    #[error("helper install path contains a control character")]
    ControlCharacter,

    #[error("helper install path must not contain traversal components")]
    TraversalPath,

    #[error("helper install path must not point at a shell or command dispatcher")]
    ShellProgramPath,

    #[error("helper install plan requires expected helper SHA-256")]
    MissingExpectedSha256,

    #[error("helper install plan expected helper SHA-256 must be 64 lowercase hex characters")]
    InvalidExpectedSha256,

    #[error("helper install source inspector failed: {reason}")]
    SourceInspectorFailed { reason: String },

    #[error("helper install source SHA-256 mismatch")]
    HelperSourceSha256Mismatch { expected: String, actual: String },

    #[error("helper install plan used an unexpected fixed path")]
    UnexpectedFixedPath,

    #[error("helper install plan used an unexpected removal path")]
    UnexpectedRemovalPath,

    #[error("helper install plan requires root:wheel ownership")]
    InvalidOwner,

    #[error("helper install plan used invalid file mode")]
    InvalidMode,

    #[error("helper install plan used an unexpected launchd label")]
    InvalidLabel,

    #[error("helper install plan plist does not match the expected helper descriptor")]
    InvalidPlist,

    #[error("helper install plan requires at least one operation")]
    MissingOperation,

    #[error("helper install plan is missing copy, plist write or load")]
    IncompleteInstallPlan,

    #[error("helper uninstall plan is missing unload, plist removal or helper removal")]
    IncompleteUninstallPlan,

    #[error("helper install plan must not mix install and uninstall operations")]
    MixedInstallAndUninstall,

    #[error("invalid launchd daemon descriptor: {0}")]
    Launchd(crate::macos_launchd::LaunchdDaemonError),
}

fn validate_authorization(
    authorization: &AdminAuthorizationRequirement,
) -> Result<(), HelperInstallError> {
    if authorization.reason.trim().is_empty() {
        Err(HelperInstallError::MissingAuthorizationReason)
    } else {
        Ok(())
    }
}

fn validate_fixed_path(actual: &str, expected: &str) -> Result<(), HelperInstallError> {
    validate_install_path(actual)?;
    if actual == expected {
        Ok(())
    } else {
        Err(HelperInstallError::UnexpectedFixedPath)
    }
}

fn validate_install_path(path: &str) -> Result<(), HelperInstallError> {
    if !path.starts_with('/') {
        return Err(HelperInstallError::RelativePath);
    }
    let actual = path.len();
    if actual > MAX_INSTALL_PATH_BYTES {
        return Err(HelperInstallError::OversizedPath {
            limit: MAX_INSTALL_PATH_BYTES,
            actual,
        });
    }
    if path.chars().any(char::is_control) {
        return Err(HelperInstallError::ControlCharacter);
    }
    if path.split('/').any(|component| component == "..") {
        return Err(HelperInstallError::TraversalPath);
    }
    let file_name = path.rsplit('/').next().unwrap_or_default();
    if matches!(
        file_name,
        "sh" | "bash" | "zsh" | "fish" | "env" | "osascript"
    ) {
        return Err(HelperInstallError::ShellProgramPath);
    }
    Ok(())
}

fn validate_expected_sha256(expected_sha256: &str) -> Result<(), HelperInstallError> {
    if expected_sha256.is_empty() {
        return Err(HelperInstallError::MissingExpectedSha256);
    }
    if expected_sha256.len() != SHA256_HEX_BYTES
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HelperInstallError::InvalidExpectedSha256);
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), HelperInstallError> {
    if label == DEFAULT_LAUNCHD_LABEL {
        Ok(())
    } else {
        Err(HelperInstallError::InvalidLabel)
    }
}

fn validate_plist(plist_xml: &str) -> Result<(), HelperInstallError> {
    let expected = LaunchdDaemonSpec {
        disabled: false,
        run_at_load: false,
        keep_alive: true,
        ..LaunchdDaemonSpec::disabled_default()
    }
    .to_plist_xml()
    .map_err(HelperInstallError::Launchd)?;

    if plist_xml == expected {
        Ok(())
    } else {
        Err(HelperInstallError::InvalidPlist)
    }
}

fn validate_root_wheel(owner: &str, group: &str) -> Result<(), HelperInstallError> {
    if owner == ROOT_USER && group == WHEEL_GROUP {
        Ok(())
    } else {
        Err(HelperInstallError::InvalidOwner)
    }
}

fn validate_mode(actual: u16, expected: u16) -> Result<(), HelperInstallError> {
    if actual == expected {
        Ok(())
    } else {
        Err(HelperInstallError::InvalidMode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HELPER_SHA256: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_HELPER_SHA256: &str =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const HELPER_SOURCE_PATH: &str = "/Users/build/target/release/novaray-platform-helper";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestInspector {
        expected_path: String,
        sha256: Result<String, String>,
        requested_paths: Vec<String>,
    }

    impl TestInspector {
        fn new(expected_path: &str, sha256: Result<&str, &str>) -> Self {
            Self {
                expected_path: expected_path.to_string(),
                sha256: sha256.map(String::from).map_err(String::from),
                requested_paths: Vec::new(),
            }
        }
    }

    impl HelperInstallSourceInspector for TestInspector {
        fn helper_sha256(&mut self, source_path: &str) -> Result<String, String> {
            assert_eq!(source_path, self.expected_path);
            self.requested_paths.push(source_path.to_string());
            self.sha256.clone()
        }
    }

    #[test]
    fn install_plan_is_allowlisted_and_requires_admin_authorization() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");

        assert_eq!(
            plan.authorization.method,
            AdminAuthorizationMethod::ManualSudo
        );
        assert_eq!(plan.operations.len(), 3);
        assert!(matches!(
            &plan.operations[0],
            HelperInstallOperation::CopyHelper {
                source_path,
                expected_sha256,
                destination_path,
                owner,
                group,
                mode,
            } if source_path == HELPER_SOURCE_PATH
                && expected_sha256 == VALID_HELPER_SHA256
                && destination_path == DEFAULT_HELPER_PROGRAM_PATH
                && owner == ROOT_USER
                && group == WHEEL_GROUP
                && *mode == HELPER_MODE
        ));
        assert!(matches!(
            &plan.operations[1],
            HelperInstallOperation::WriteLaunchDaemonPlist {
                path,
                label,
                plist_xml,
                owner,
                group,
                mode,
            } if path == DEFAULT_LAUNCHD_PLIST_PATH
                && label == DEFAULT_LAUNCHD_LABEL
                && plist_xml.contains("<key>Disabled</key>\n  <false/>")
                && plist_xml.contains("<key>KeepAlive</key>\n  <true/>")
                && owner == ROOT_USER
                && group == WHEEL_GROUP
                && *mode == PLIST_MODE
        ));
        assert!(matches!(
            &plan.operations[2],
            HelperInstallOperation::LoadLaunchDaemon { path, label }
                if path == DEFAULT_LAUNCHD_PLIST_PATH && label == DEFAULT_LAUNCHD_LABEL
        ));
        assert_eq!(plan.validate(), Ok(()));
        let debug = format!("{plan:?}");
        assert!(!debug.contains("sudo "));
        assert!(!debug.contains("launchctl "));
    }

    #[test]
    fn install_preflight_verifies_exact_copy_source_before_later_install_steps() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Ok(VALID_HELPER_SHA256));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(executor.execute(&plan), Ok(()));
        assert_eq!(
            executor.records(),
            [
                HelperInstallPreflightRecord::CopyHelperVerified {
                    source_path: HELPER_SOURCE_PATH.to_string(),
                    expected_sha256: VALID_HELPER_SHA256.to_string(),
                    actual_sha256: VALID_HELPER_SHA256.to_string(),
                    destination_path: DEFAULT_HELPER_PROGRAM_PATH.to_string(),
                },
                HelperInstallPreflightRecord::WriteLaunchDaemonPlistValidated {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                },
                HelperInstallPreflightRecord::LoadLaunchDaemonValidated {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                },
            ]
        );
        assert_eq!(
            executor.into_inner().requested_paths,
            [HELPER_SOURCE_PATH.to_string()]
        );
    }

    #[test]
    fn install_preflight_hash_mismatch_stops_before_plist_or_load_records() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Ok(OTHER_HELPER_SHA256));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::HelperSourceSha256Mismatch {
                expected: VALID_HELPER_SHA256.to_string(),
                actual: OTHER_HELPER_SHA256.to_string(),
            })
        );
        assert!(executor.records().is_empty());
        assert_eq!(
            executor.into_inner().requested_paths,
            [HELPER_SOURCE_PATH.to_string()]
        );
    }

    #[test]
    fn install_preflight_propagates_source_inspector_failure() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Err("source disappeared"));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::SourceInspectorFailed {
                reason: "source disappeared".to_string(),
            })
        );
        assert!(executor.records().is_empty());
    }

    #[test]
    fn uninstall_preflight_does_not_inspect_helper_artifact_bytes() {
        let plan = HelperInstallPlan::uninstall().expect("uninstall plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Err("should not inspect"));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(executor.execute(&plan), Ok(()));
        assert_eq!(
            executor.records(),
            [
                HelperInstallPreflightRecord::UnloadLaunchDaemonValidated {
                    label: DEFAULT_LAUNCHD_LABEL.to_string(),
                },
                HelperInstallPreflightRecord::RemoveFileValidated {
                    path: DEFAULT_LAUNCHD_PLIST_PATH.to_string(),
                },
                HelperInstallPreflightRecord::RemoveFileValidated {
                    path: DEFAULT_HELPER_PROGRAM_PATH.to_string(),
                },
            ]
        );
        assert!(executor.into_inner().requested_paths.is_empty());
    }

    #[test]
    fn install_plan_rejects_missing_or_invalid_helper_integrity() {
        assert_eq!(
            HelperInstallPlan::install(HELPER_SOURCE_PATH, "",).unwrap_err(),
            HelperInstallError::MissingExpectedSha256
        );
        assert_eq!(
            HelperInstallPlan::install(HELPER_SOURCE_PATH, "0123456789abcdef",).unwrap_err(),
            HelperInstallError::InvalidExpectedSha256
        );
        assert_eq!(
            HelperInstallPlan::install(
                HELPER_SOURCE_PATH,
                "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap_err(),
            HelperInstallError::InvalidExpectedSha256
        );

        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let HelperInstallOperation::CopyHelper {
            expected_sha256, ..
        } = &mut plan.operations[0]
        else {
            panic!("expected copy helper");
        };
        *expected_sha256 =
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffz".to_string();
        assert_eq!(
            plan.validate(),
            Err(HelperInstallError::InvalidExpectedSha256)
        );
    }

    #[test]
    fn uninstall_plan_is_reversible_and_removes_only_owned_paths() {
        let plan = HelperInstallPlan::uninstall().expect("uninstall plan");

        assert_eq!(plan.operations.len(), 3);
        assert!(matches!(
            &plan.operations[0],
            HelperInstallOperation::UnloadLaunchDaemon { label }
                if label == DEFAULT_LAUNCHD_LABEL
        ));
        assert_eq!(plan.validate(), Ok(()));

        let mut unsafe_plan = plan.clone();
        unsafe_plan
            .operations
            .push(HelperInstallOperation::RemoveFile {
                path: "/Library/LaunchDaemons/com.apple.other.plist".to_string(),
            });
        assert_eq!(
            unsafe_plan.validate(),
            Err(HelperInstallError::UnexpectedRemovalPath)
        );
    }

    #[test]
    fn path_validation_rejects_relative_traversal_shell_and_control_paths() {
        assert_eq!(
            HelperInstallPlan::install(
                "target/release/novaray-platform-helper",
                VALID_HELPER_SHA256
            )
            .unwrap_err(),
            HelperInstallError::RelativePath
        );
        assert_eq!(
            HelperInstallPlan::install("/opt/../usr/local/bin/helper", VALID_HELPER_SHA256)
                .unwrap_err(),
            HelperInstallError::TraversalPath
        );
        assert_eq!(
            HelperInstallPlan::install("/bin/sh", VALID_HELPER_SHA256).unwrap_err(),
            HelperInstallError::ShellProgramPath
        );
        assert_eq!(
            HelperInstallPlan::install("/tmp/helper\nx", VALID_HELPER_SHA256).unwrap_err(),
            HelperInstallError::ControlCharacter
        );
    }

    #[test]
    fn install_plan_rejects_tampered_plist_label_owner_mode_and_missing_steps() {
        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");

        let HelperInstallOperation::WriteLaunchDaemonPlist { label, .. } = &mut plan.operations[1]
        else {
            panic!("expected plist write");
        };
        *label = "org.novaray.other".to_string();
        assert_eq!(plan.validate(), Err(HelperInstallError::InvalidLabel));

        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let HelperInstallOperation::CopyHelper { owner, .. } = &mut plan.operations[0] else {
            panic!("expected copy helper");
        };
        *owner = "user".to_string();
        assert_eq!(plan.validate(), Err(HelperInstallError::InvalidOwner));

        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let HelperInstallOperation::CopyHelper { mode, .. } = &mut plan.operations[0] else {
            panic!("expected copy helper");
        };
        *mode = 0o777;
        assert_eq!(plan.validate(), Err(HelperInstallError::InvalidMode));

        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        plan.operations.pop();
        assert_eq!(
            plan.validate(),
            Err(HelperInstallError::IncompleteInstallPlan)
        );
    }

    #[test]
    fn install_and_uninstall_operations_cannot_be_mixed() {
        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        plan.operations
            .push(HelperInstallOperation::UnloadLaunchDaemon {
                label: DEFAULT_LAUNCHD_LABEL.to_string(),
            });

        assert_eq!(
            plan.validate(),
            Err(HelperInstallError::MixedInstallAndUninstall)
        );
    }
}
