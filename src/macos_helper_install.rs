//! Side-effect-free install/uninstall plan contract for the macOS privileged helper.
//!
//! The contract models the future administrative step as typed operations. It does not prompt for
//! authorization, write to `/Library`, call `launchctl`, run as root, open IPC sockets, create
//! `utun`, or mutate routes, DNS, firewall, system proxy or packet-flow state.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};
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
            (true, false) if has_helper_copy && has_plist_write && has_load => {
                validate_install_operation_order(&self.operations)
            }
            (true, false) => Err(HelperInstallError::IncompleteInstallPlan),
            (false, true) if has_unload && removes_plist && removes_helper => {
                validate_uninstall_operation_order(&self.operations)
            }
            (false, true) => Err(HelperInstallError::IncompleteUninstallPlan),
            (false, false) => Err(HelperInstallError::MissingOperation),
        }
    }
}

pub trait HelperInstallSourceInspector {
    type Source;

    fn open_helper_source(
        &mut self,
        source_path: &str,
    ) -> Result<Self::Source, HelperInstallSourceError>;
    fn helper_sha256(
        &mut self,
        source: &mut Self::Source,
    ) -> Result<String, HelperInstallSourceError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HelperInstallFileSourceInspector;

pub struct HelperInstallFileSource {
    file: File,
}

impl fmt::Debug for HelperInstallFileSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperInstallFileSource")
            .field("file", &self.file)
            .finish()
    }
}

impl HelperInstallFileSource {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

impl HelperInstallSourceInspector for HelperInstallFileSourceInspector {
    type Source = HelperInstallFileSource;

    fn open_helper_source(
        &mut self,
        source_path: &str,
    ) -> Result<Self::Source, HelperInstallSourceError> {
        let mut options = OpenOptions::new();
        options.read(true);
        set_no_follow_final_component(&mut options);

        #[cfg(not(unix))]
        reject_symlink_before_open(source_path)?;

        let file = options
            .open(source_path)
            .map_err(HelperInstallSourceError::from_open_error)?;
        let metadata = file
            .metadata()
            .map_err(HelperInstallSourceError::from_open_metadata_error)?;
        if !metadata.file_type().is_file() {
            return Err(HelperInstallSourceError::NotRegularFile);
        }

        Ok(HelperInstallFileSource { file })
    }

    fn helper_sha256(
        &mut self,
        source: &mut Self::Source,
    ) -> Result<String, HelperInstallSourceError> {
        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(HelperInstallSourceError::from_hash_seek_error)?;

        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = source
                .file
                .read(&mut buffer)
                .map_err(HelperInstallSourceError::from_hash_read_error)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }

        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(HelperInstallSourceError::from_hash_seek_error)?;

        Ok(hex::encode(hasher.finalize()))
    }
}

pub struct HelperInstallPreflightExecutor<I: HelperInstallSourceInspector> {
    inspector: I,
    records: Vec<HelperInstallPreflightRecord>,
    verified_helper_source: Option<VerifiedHelperInstallSource<I::Source>>,
}

impl<I> HelperInstallPreflightExecutor<I>
where
    I: HelperInstallSourceInspector,
{
    pub fn new(inspector: I) -> Self {
        Self {
            inspector,
            records: Vec::new(),
            verified_helper_source: None,
        }
    }

    pub fn execute(&mut self, plan: &HelperInstallPlan) -> Result<(), HelperInstallError> {
        plan.validate()?;
        self.records.clear();
        self.verified_helper_source = None;

        for operation in &plan.operations {
            match operation {
                HelperInstallOperation::CopyHelper {
                    source_path,
                    expected_sha256,
                    destination_path,
                    ..
                } => {
                    let mut source = self
                        .inspector
                        .open_helper_source(source_path)
                        .map_err(HelperInstallError::SourceInspector)?;
                    let actual_sha256 = self
                        .inspector
                        .helper_sha256(&mut source)
                        .map_err(HelperInstallError::SourceInspector)?;
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
                            actual_sha256: actual_sha256.clone(),
                            destination_path: destination_path.clone(),
                        });
                    self.verified_helper_source = Some(VerifiedHelperInstallSource {
                        source_path: source_path.clone(),
                        expected_sha256: expected_sha256.clone(),
                        actual_sha256,
                        destination_path: destination_path.clone(),
                        source,
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

    pub fn verified_helper_source(&self) -> Option<&VerifiedHelperInstallSource<I::Source>> {
        self.verified_helper_source.as_ref()
    }

    pub fn take_verified_helper_source(
        &mut self,
    ) -> Option<VerifiedHelperInstallSource<I::Source>> {
        self.verified_helper_source.take()
    }

    pub fn into_inner(self) -> I {
        self.inspector
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHelperInstallSource<S> {
    pub source_path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub destination_path: String,
    pub source: S,
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

    #[error(transparent)]
    SourceInspector(HelperInstallSourceError),

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

    #[error("helper install plan must verify helper integrity before plist write or launchd load")]
    InvalidInstallOperationOrder,

    #[error("helper uninstall plan is missing unload, plist removal or helper removal")]
    IncompleteUninstallPlan,

    #[error("helper uninstall plan must unload launchd before removing plist or helper binary")]
    InvalidUninstallOperationOrder,

    #[error("helper install plan must not mix install and uninstall operations")]
    MixedInstallAndUninstall,

    #[error("invalid launchd daemon descriptor: {0}")]
    Launchd(crate::macos_launchd::LaunchdDaemonError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HelperInstallSourceError {
    #[error("helper source open failed: {kind:?}")]
    OpenFailed { kind: io::ErrorKind },

    #[error("helper source metadata inspection failed: {kind:?}")]
    OpenMetadataFailed { kind: io::ErrorKind },

    #[error("helper source must not be a symbolic link")]
    Symlink,

    #[error("helper source must be a regular file")]
    NotRegularFile,

    #[error("helper source hash read failed: {kind:?}")]
    HashReadFailed { kind: io::ErrorKind },

    #[error("helper source hash seek failed: {kind:?}")]
    HashSeekFailed { kind: io::ErrorKind },

    #[error("helper source inspector rejected the source")]
    InspectorRejected,
}

impl HelperInstallSourceError {
    fn from_open_error(error: io::Error) -> Self {
        if is_symlink_open_error(&error) {
            Self::Symlink
        } else {
            Self::OpenFailed { kind: error.kind() }
        }
    }

    fn from_open_metadata_error(error: io::Error) -> Self {
        Self::OpenMetadataFailed { kind: error.kind() }
    }

    fn from_hash_read_error(error: io::Error) -> Self {
        Self::HashReadFailed { kind: error.kind() }
    }

    fn from_hash_seek_error(error: io::Error) -> Self {
        Self::HashSeekFailed { kind: error.kind() }
    }
}

#[cfg(unix)]
fn set_no_follow_final_component(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow_final_component(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn is_symlink_open_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_error: &io::Error) -> bool {
    false
}

#[cfg(not(unix))]
fn reject_symlink_before_open(source_path: &str) -> Result<(), HelperInstallSourceError> {
    let metadata = std::fs::symlink_metadata(source_path)
        .map_err(HelperInstallSourceError::from_open_metadata_error)?;
    if metadata.file_type().is_symlink() {
        Err(HelperInstallSourceError::Symlink)
    } else {
        Ok(())
    }
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

fn validate_install_operation_order(
    operations: &[HelperInstallOperation],
) -> Result<(), HelperInstallError> {
    match operations {
        [HelperInstallOperation::CopyHelper { .. }, HelperInstallOperation::WriteLaunchDaemonPlist { .. }, HelperInstallOperation::LoadLaunchDaemon { .. }] => {
            Ok(())
        }
        _ => Err(HelperInstallError::InvalidInstallOperationOrder),
    }
}

fn validate_uninstall_operation_order(
    operations: &[HelperInstallOperation],
) -> Result<(), HelperInstallError> {
    match operations {
        [HelperInstallOperation::UnloadLaunchDaemon { .. }, HelperInstallOperation::RemoveFile { path: plist_path }, HelperInstallOperation::RemoveFile { path: helper_path }]
            if plist_path == DEFAULT_LAUNCHD_PLIST_PATH
                && helper_path == DEFAULT_HELPER_PROGRAM_PATH =>
        {
            Ok(())
        }
        _ => Err(HelperInstallError::InvalidUninstallOperationOrder),
    }
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
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::{Read, Seek};
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_HELPER_SHA256: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_HELPER_SHA256: &str =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const HELPER_SOURCE_PATH: &str = "/Users/build/target/release/novaray-platform-helper";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestHelperSource {
        path: String,
        descriptor_id: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestInspector {
        expected_path: String,
        sha256: Result<String, String>,
        opened_paths: Vec<String>,
        hashed_descriptor_ids: Vec<u64>,
        next_descriptor_id: u64,
    }

    impl TestInspector {
        fn new(expected_path: &str, sha256: Result<&str, &str>) -> Self {
            Self {
                expected_path: expected_path.to_string(),
                sha256: sha256.map(String::from).map_err(String::from),
                opened_paths: Vec::new(),
                hashed_descriptor_ids: Vec::new(),
                next_descriptor_id: 1,
            }
        }
    }

    impl HelperInstallSourceInspector for TestInspector {
        type Source = TestHelperSource;

        fn open_helper_source(
            &mut self,
            source_path: &str,
        ) -> Result<Self::Source, HelperInstallSourceError> {
            assert_eq!(source_path, self.expected_path);
            self.opened_paths.push(source_path.to_string());
            let descriptor_id = self.next_descriptor_id;
            self.next_descriptor_id += 1;
            Ok(TestHelperSource {
                path: source_path.to_string(),
                descriptor_id,
            })
        }

        fn helper_sha256(
            &mut self,
            source: &mut Self::Source,
        ) -> Result<String, HelperInstallSourceError> {
            assert_eq!(source.path, self.expected_path);
            self.hashed_descriptor_ids.push(source.descriptor_id);
            self.sha256
                .clone()
                .map_err(|_| HelperInstallSourceError::InspectorRejected)
        }
    }

    #[cfg(unix)]
    fn helper_sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(bytes))
    }

    #[cfg(unix)]
    fn unique_temp_dir(slug: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "novaray-helper-install-{slug}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temp dir");
        path
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
            executor.verified_helper_source(),
            Some(&VerifiedHelperInstallSource {
                source_path: HELPER_SOURCE_PATH.to_string(),
                expected_sha256: VALID_HELPER_SHA256.to_string(),
                actual_sha256: VALID_HELPER_SHA256.to_string(),
                destination_path: DEFAULT_HELPER_PROGRAM_PATH.to_string(),
                source: TestHelperSource {
                    path: HELPER_SOURCE_PATH.to_string(),
                    descriptor_id: 1,
                },
            })
        );
        assert_eq!(
            executor.into_inner().opened_paths,
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
        assert!(executor.verified_helper_source().is_none());
        assert_eq!(executor.into_inner().hashed_descriptor_ids, [1]);
    }

    #[test]
    fn install_preflight_hashes_the_opened_source_handle_once() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Ok(VALID_HELPER_SHA256));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(executor.execute(&plan), Ok(()));
        let verified_source = executor
            .take_verified_helper_source()
            .expect("verified helper source");
        assert_eq!(verified_source.source_path, HELPER_SOURCE_PATH);
        assert_eq!(verified_source.source.descriptor_id, 1);
        assert!(executor.verified_helper_source().is_none());
        assert_eq!(
            executor.into_inner().hashed_descriptor_ids,
            [verified_source.source.descriptor_id]
        );
    }

    #[test]
    fn install_preflight_source_open_failure_stops_before_records() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct FailingOpenInspector;

        impl HelperInstallSourceInspector for FailingOpenInspector {
            type Source = TestHelperSource;

            fn open_helper_source(
                &mut self,
                _source_path: &str,
            ) -> Result<Self::Source, HelperInstallSourceError> {
                Err(HelperInstallSourceError::InspectorRejected)
            }

            fn helper_sha256(
                &mut self,
                _source: &mut Self::Source,
            ) -> Result<String, HelperInstallSourceError> {
                panic!("hash should not run after open failure");
            }
        }

        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let mut executor = HelperInstallPreflightExecutor::new(FailingOpenInspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::SourceInspector(
                HelperInstallSourceError::InspectorRejected,
            ))
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());
    }

    #[test]
    fn install_preflight_hash_mismatch_still_opens_only_copy_source() {
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
        assert!(executor.verified_helper_source().is_none());
        assert_eq!(
            executor.into_inner().opened_paths,
            [HELPER_SOURCE_PATH.to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_source_inspector_opens_regular_file_hashes_handle_and_rewinds() {
        let temp_dir = unique_temp_dir("regular-file");
        let helper_path = temp_dir.join("novaray-platform-helper");
        let helper_bytes = b"test helper artifact bytes";
        fs::write(&helper_path, helper_bytes).expect("write helper source");
        let expected_sha256 = helper_sha256_hex(helper_bytes);
        let plan = HelperInstallPlan::install(
            helper_path.to_str().expect("utf-8 helper path"),
            &expected_sha256,
        )
        .expect("install plan");
        let mut executor = HelperInstallPreflightExecutor::new(HelperInstallFileSourceInspector);

        assert_eq!(executor.execute(&plan), Ok(()));
        let verified = executor
            .take_verified_helper_source()
            .expect("verified helper source");
        assert_eq!(verified.expected_sha256, expected_sha256);
        assert_eq!(verified.actual_sha256, expected_sha256);

        let mut file = verified.source.into_file();
        assert_eq!(file.stream_position().expect("stream position"), 0);
        let mut copied_from_verified_handle = Vec::new();
        file.read_to_end(&mut copied_from_verified_handle)
            .expect("read verified handle");
        assert_eq!(copied_from_verified_handle, helper_bytes);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[cfg(unix)]
    #[test]
    fn file_source_inspector_hash_mismatch_leaves_no_verified_source() {
        let temp_dir = unique_temp_dir("hash-mismatch");
        let helper_path = temp_dir.join("novaray-platform-helper");
        fs::write(&helper_path, b"actual helper bytes").expect("write helper source");
        let plan = HelperInstallPlan::install(
            helper_path.to_str().expect("utf-8 helper path"),
            VALID_HELPER_SHA256,
        )
        .expect("install plan");
        let mut executor = HelperInstallPreflightExecutor::new(HelperInstallFileSourceInspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::HelperSourceSha256Mismatch {
                expected: VALID_HELPER_SHA256.to_string(),
                actual: helper_sha256_hex(b"actual helper bytes"),
            })
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[cfg(unix)]
    #[test]
    fn file_source_inspector_rejects_final_symlink_component() {
        let temp_dir = unique_temp_dir("symlink");
        let target_path = temp_dir.join("target-helper");
        let symlink_path = temp_dir.join("novaray-platform-helper-link");
        fs::write(&target_path, b"target helper bytes").expect("write helper source");
        std::os::unix::fs::symlink(&target_path, &symlink_path).expect("create helper symlink");
        let plan = HelperInstallPlan::install(
            symlink_path.to_str().expect("utf-8 helper path"),
            helper_sha256_hex(b"target helper bytes"),
        )
        .expect("install plan");
        let mut executor = HelperInstallPreflightExecutor::new(HelperInstallFileSourceInspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::SourceInspector(
                HelperInstallSourceError::Symlink,
            ))
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[cfg(unix)]
    #[test]
    fn file_source_inspector_rejects_non_regular_file() {
        let temp_dir = unique_temp_dir("directory");
        let helper_path = temp_dir.join("novaray-platform-helper-dir");
        fs::create_dir(&helper_path).expect("create source directory");
        let plan = HelperInstallPlan::install(
            helper_path.to_str().expect("utf-8 helper path"),
            VALID_HELPER_SHA256,
        )
        .expect("install plan");
        let mut executor = HelperInstallPreflightExecutor::new(HelperInstallFileSourceInspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::SourceInspector(
                HelperInstallSourceError::NotRegularFile,
            ))
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn install_plan_rejects_reordered_steps_before_preflight_records() {
        let mut plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        plan.operations.rotate_left(1);

        assert_eq!(
            plan.validate(),
            Err(HelperInstallError::InvalidInstallOperationOrder)
        );

        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Ok(VALID_HELPER_SHA256));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);
        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::InvalidInstallOperationOrder)
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());
    }

    #[test]
    fn install_preflight_propagates_source_inspector_failure() {
        let plan = HelperInstallPlan::install(HELPER_SOURCE_PATH, VALID_HELPER_SHA256)
            .expect("install plan");
        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Err("source disappeared"));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);

        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::SourceInspector(
                HelperInstallSourceError::InspectorRejected,
            ))
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());
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
        assert!(executor.verified_helper_source().is_none());
        assert!(executor.into_inner().opened_paths.is_empty());
    }

    #[test]
    fn uninstall_plan_rejects_reordered_steps_before_preflight_records() {
        let mut plan = HelperInstallPlan::uninstall().expect("uninstall plan");
        plan.operations.reverse();

        assert_eq!(
            plan.validate(),
            Err(HelperInstallError::InvalidUninstallOperationOrder)
        );

        let inspector = TestInspector::new(HELPER_SOURCE_PATH, Err("should not inspect"));
        let mut executor = HelperInstallPreflightExecutor::new(inspector);
        assert_eq!(
            executor.execute(&plan),
            Err(HelperInstallError::InvalidUninstallOperationOrder)
        );
        assert!(executor.records().is_empty());
        assert!(executor.verified_helper_source().is_none());
        assert!(executor.into_inner().opened_paths.is_empty());
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
