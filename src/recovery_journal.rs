//! Durable recovery journal contract for network transactions.
//!
//! This module persists typed network transaction state so a later process launch can detect
//! unfinished work. It does not execute rollback steps and does not mutate routes, DNS, firewall,
//! system proxy state, or any platform network interface.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::network_state::{
    AppliedNetworkState, NetworkSnapshot, NetworkStateError, NetworkStateOwner,
    NetworkTransactionPhase, MAX_NETWORK_STATE_ID_BYTES,
};

pub const NETWORK_RECOVERY_JOURNAL_VERSION: u32 = 1;
pub const NETWORK_APPLIED_STATE_RECORD_VERSION: u32 = 1;

static JOURNAL_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRecoveryJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub snapshot: NetworkSnapshot,
    pub applied_state: AppliedNetworkState,
}

impl fmt::Debug for NetworkRecoveryJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkRecoveryJournal")
            .field("schema_version", &self.schema_version)
            .field("journal_id", &self.journal_id)
            .field("snapshot_id", &self.snapshot.snapshot_id)
            .field("transaction_id", &self.applied_state.transaction_id)
            .field("platform", &self.applied_state.platform)
            .field("phase", &self.applied_state.phase)
            .field("operations_len", &self.applied_state.operations.len())
            .finish()
    }
}

impl NetworkRecoveryJournal {
    pub fn new(snapshot: NetworkSnapshot, applied_state: AppliedNetworkState) -> Self {
        Self {
            schema_version: NETWORK_RECOVERY_JOURNAL_VERSION,
            journal_id: applied_state.transaction_id.clone(),
            snapshot,
            applied_state,
        }
    }

    pub fn validate(&self) -> Result<(), NetworkRecoveryJournalError> {
        if self.schema_version != NETWORK_RECOVERY_JOURNAL_VERSION {
            return Err(NetworkRecoveryJournalError::UnsupportedVersion {
                expected: NETWORK_RECOVERY_JOURNAL_VERSION,
                actual: self.schema_version,
            });
        }

        validate_journal_file_component("journal_id", &self.journal_id)?;
        validate_journal_file_component("transaction_id", &self.applied_state.transaction_id)?;
        self.snapshot.validate()?;
        self.applied_state.validate()?;

        if self.journal_id != self.applied_state.transaction_id {
            return Err(NetworkRecoveryJournalError::MismatchedTransactionId {
                journal_id: self.journal_id.clone(),
                transaction_id: self.applied_state.transaction_id.clone(),
            });
        }

        if self.snapshot.snapshot_id != self.applied_state.snapshot_id {
            return Err(NetworkRecoveryJournalError::MismatchedSnapshotId {
                snapshot_id: self.snapshot.snapshot_id.clone(),
                applied_snapshot_id: self.applied_state.snapshot_id.clone(),
            });
        }

        if self.snapshot.platform != self.applied_state.platform {
            return Err(NetworkRecoveryJournalError::MismatchedPlatform);
        }

        if self.snapshot.owner != self.applied_state.owner {
            return Err(NetworkRecoveryJournalError::MismatchedOwner {
                snapshot_owner: self.snapshot.owner.clone(),
                applied_owner: self.applied_state.owner.clone(),
            });
        }

        if matches!(self.applied_state.phase, NetworkTransactionPhase::Planned) {
            return Err(NetworkRecoveryJournalError::NotRecoverablePhase {
                phase: self.applied_state.phase,
            });
        }

        self.applied_state.rollback_steps_reverse_order()?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAppliedStateRecord {
    pub schema_version: u32,
    pub record_id: String,
    pub snapshot: NetworkSnapshot,
    pub applied_state: AppliedNetworkState,
}

impl fmt::Debug for NetworkAppliedStateRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkAppliedStateRecord")
            .field("schema_version", &self.schema_version)
            .field("record_id", &self.record_id)
            .field("snapshot_id", &self.snapshot.snapshot_id)
            .field("transaction_id", &self.applied_state.transaction_id)
            .field("platform", &self.applied_state.platform)
            .field("phase", &self.applied_state.phase)
            .field("operations_len", &self.applied_state.operations.len())
            .finish()
    }
}

impl NetworkAppliedStateRecord {
    pub fn new(snapshot: NetworkSnapshot, applied_state: AppliedNetworkState) -> Self {
        Self {
            schema_version: NETWORK_APPLIED_STATE_RECORD_VERSION,
            record_id: applied_state.transaction_id.clone(),
            snapshot,
            applied_state,
        }
    }

    pub fn validate(&self) -> Result<(), NetworkRecoveryJournalError> {
        if self.schema_version != NETWORK_APPLIED_STATE_RECORD_VERSION {
            return Err(
                NetworkRecoveryJournalError::UnsupportedAppliedStateVersion {
                    expected: NETWORK_APPLIED_STATE_RECORD_VERSION,
                    actual: self.schema_version,
                },
            );
        }

        validate_journal_file_component("record_id", &self.record_id)?;
        validate_journal_file_component("transaction_id", &self.applied_state.transaction_id)?;
        self.snapshot.validate()?;
        self.applied_state.validate()?;

        if self.record_id != self.applied_state.transaction_id {
            return Err(
                NetworkRecoveryJournalError::MismatchedAppliedStateTransactionId {
                    record_id: self.record_id.clone(),
                    transaction_id: self.applied_state.transaction_id.clone(),
                },
            );
        }

        if self.snapshot.snapshot_id != self.applied_state.snapshot_id {
            return Err(NetworkRecoveryJournalError::MismatchedSnapshotId {
                snapshot_id: self.snapshot.snapshot_id.clone(),
                applied_snapshot_id: self.applied_state.snapshot_id.clone(),
            });
        }

        if self.snapshot.platform != self.applied_state.platform {
            return Err(NetworkRecoveryJournalError::MismatchedPlatform);
        }

        if self.snapshot.owner != self.applied_state.owner {
            return Err(NetworkRecoveryJournalError::MismatchedOwner {
                snapshot_owner: self.snapshot.owner.clone(),
                applied_owner: self.applied_state.owner.clone(),
            });
        }

        if !matches!(self.applied_state.phase, NetworkTransactionPhase::Applied) {
            return Err(NetworkRecoveryJournalError::NotAppliedStatePhase {
                phase: self.applied_state.phase,
            });
        }

        self.applied_state.rollback_steps_reverse_order()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NetworkRecoveryJournalStore {
    dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRecoveryJournalLoadReport {
    pub journals: Vec<NetworkRecoveryJournal>,
    pub quarantined: Vec<QuarantinedRecoveryJournal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAppliedStateLoadReport {
    pub records: Vec<NetworkAppliedStateRecord>,
    pub quarantined: Vec<QuarantinedRecoveryJournal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedRecoveryJournal {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub reason: String,
}

impl NetworkRecoveryJournalStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    pub fn write_pending(
        &self,
        journal: &NetworkRecoveryJournal,
    ) -> Result<PathBuf, NetworkRecoveryJournalError> {
        journal.validate()?;
        ensure_private_journal_dir(&self.dir)?;

        let target_path = self.journal_path_for(&journal.journal_id)?;
        let temp_path = self.temp_path_for(&journal.journal_id)?;
        let payload = serde_json::to_vec_pretty(journal)?;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_owner_only_permissions(&mut options);

        let mut file = options.open(&temp_path)?;
        let write_result = (|| -> Result<(), NetworkRecoveryJournalError> {
            file.write_all(&payload)?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        replace_file(&temp_path, &target_path)?;
        sync_parent_dir(&self.dir)?;
        Ok(target_path)
    }

    pub fn write_applied_state(
        &self,
        record: &NetworkAppliedStateRecord,
    ) -> Result<PathBuf, NetworkRecoveryJournalError> {
        record.validate()?;
        let dir = self.applied_state_dir();
        ensure_private_journal_dir(&dir)?;

        let target_path = self.applied_state_path_for(&record.record_id)?;
        let temp_path = temp_path_for(&dir, &record.record_id)?;
        let payload = serde_json::to_vec_pretty(record)?;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_owner_only_permissions(&mut options);

        let mut file = options.open(&temp_path)?;
        let write_result = (|| -> Result<(), NetworkRecoveryJournalError> {
            file.write_all(&payload)?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        replace_file(&temp_path, &target_path)?;
        sync_parent_dir(&dir)?;
        self.clear_other_applied_states(&record.record_id)?;
        Ok(target_path)
    }

    pub fn load_pending(&self) -> Result<Vec<NetworkRecoveryJournal>, NetworkRecoveryJournalError> {
        Ok(self.load_pending_report()?.journals)
    }

    pub fn load_pending_report(
        &self,
    ) -> Result<NetworkRecoveryJournalLoadReport, NetworkRecoveryJournalError> {
        if !self.dir.exists() {
            return Ok(NetworkRecoveryJournalLoadReport {
                journals: Vec::new(),
                quarantined: Vec::new(),
            });
        }

        let removed_temp_files = cleanup_temp_candidates(&self.dir)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths.sort();

        let mut journals = Vec::new();
        let mut quarantined = Vec::new();
        for path in paths {
            match load_one_journal(&path) {
                Ok(journal) => journals.push(journal),
                Err(reason) => quarantined.push(quarantine_journal_file(&path, reason)?),
            }
        }

        if removed_temp_files || !quarantined.is_empty() {
            sync_parent_dir(&self.dir)?;
        }

        Ok(NetworkRecoveryJournalLoadReport {
            journals,
            quarantined,
        })
    }

    pub fn load_applied_state(
        &self,
    ) -> Result<Vec<NetworkAppliedStateRecord>, NetworkRecoveryJournalError> {
        Ok(self.load_applied_state_report()?.records)
    }

    pub fn load_applied_state_report(
        &self,
    ) -> Result<NetworkAppliedStateLoadReport, NetworkRecoveryJournalError> {
        let dir = self.applied_state_dir();
        if !dir.exists() {
            return Ok(NetworkAppliedStateLoadReport {
                records: Vec::new(),
                quarantined: Vec::new(),
            });
        }

        let removed_temp_files = cleanup_temp_candidates(&dir)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths.sort();

        let mut records = Vec::new();
        let mut quarantined = Vec::new();
        for path in paths {
            match load_one_applied_state_record(&path) {
                Ok(record) => records.push(record),
                Err(reason) => quarantined.push(quarantine_journal_file(&path, reason)?),
            }
        }

        if removed_temp_files || !quarantined.is_empty() {
            sync_parent_dir(&dir)?;
        }

        Ok(NetworkAppliedStateLoadReport {
            records,
            quarantined,
        })
    }

    pub fn clear_pending(&self, transaction_id: &str) -> Result<bool, NetworkRecoveryJournalError> {
        let path = self.journal_path_for(transaction_id)?;
        match fs::remove_file(path) {
            Ok(()) => {
                sync_parent_dir(&self.dir)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn clear_applied_state(
        &self,
        transaction_id: &str,
    ) -> Result<bool, NetworkRecoveryJournalError> {
        let path = self.applied_state_path_for(transaction_id)?;
        match fs::remove_file(path) {
            Ok(()) => {
                sync_parent_dir(&self.applied_state_dir())?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn journal_path_for(
        &self,
        transaction_id: &str,
    ) -> Result<PathBuf, NetworkRecoveryJournalError> {
        let file_name = journal_file_name(transaction_id)?;
        Ok(self.dir.join(file_name))
    }

    pub fn applied_state_path_for(
        &self,
        transaction_id: &str,
    ) -> Result<PathBuf, NetworkRecoveryJournalError> {
        let file_name = journal_file_name(transaction_id)?;
        Ok(self.applied_state_dir().join(file_name))
    }

    pub fn applied_state_dir(&self) -> PathBuf {
        self.dir.join("applied")
    }

    fn clear_other_applied_states(
        &self,
        active_record_id: &str,
    ) -> Result<(), NetworkRecoveryJournalError> {
        validate_journal_file_component("record_id", active_record_id)?;
        let dir = self.applied_state_dir();
        if !dir.exists() {
            return Ok(());
        }

        let active_file_name = journal_file_name(active_record_id)?;
        let mut removed = false;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            if path.file_name().and_then(|value| value.to_str()) == Some(active_file_name.as_str())
            {
                continue;
            }

            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        if removed {
            sync_parent_dir(&dir)?;
        }
        Ok(())
    }

    fn temp_path_for(&self, transaction_id: &str) -> Result<PathBuf, NetworkRecoveryJournalError> {
        temp_path_for(&self.dir, transaction_id)
    }
}

#[derive(Debug, Error)]
pub enum NetworkRecoveryJournalError {
    #[error("invalid recovery journal id in {field}")]
    InvalidJournalId { field: &'static str },

    #[error("unsupported recovery journal version {actual}; expected {expected}")]
    UnsupportedVersion { expected: u32, actual: u32 },

    #[error("unsupported applied network state version {actual}; expected {expected}")]
    UnsupportedAppliedStateVersion { expected: u32, actual: u32 },

    #[error("recovery journal id {journal_id} does not match transaction id {transaction_id}")]
    MismatchedTransactionId {
        journal_id: String,
        transaction_id: String,
    },

    #[error("applied network state id {record_id} does not match transaction id {transaction_id}")]
    MismatchedAppliedStateTransactionId {
        record_id: String,
        transaction_id: String,
    },

    #[error("recovery journal snapshot id mismatch")]
    MismatchedSnapshotId {
        snapshot_id: String,
        applied_snapshot_id: String,
    },

    #[error("recovery journal platform mismatch")]
    MismatchedPlatform,

    #[error("recovery journal owner mismatch")]
    MismatchedOwner {
        snapshot_owner: NetworkStateOwner,
        applied_owner: NetworkStateOwner,
    },

    #[error("recovery journal phase {phase:?} is not recoverable")]
    NotRecoverablePhase { phase: NetworkTransactionPhase },

    #[error("applied network state phase {phase:?} is not applied")]
    NotAppliedStatePhase { phase: NetworkTransactionPhase },

    #[error("invalid recovery journal file {path:?}: {reason}")]
    InvalidJournalFile { path: PathBuf, reason: String },

    #[error("invalid persisted recovery journal state in {path:?}: {source}")]
    InvalidPersistedState {
        path: PathBuf,
        source: Box<NetworkRecoveryJournalError>,
    },

    #[error("no available quarantine path for invalid recovery journal {path:?}")]
    NoQuarantinePath { path: PathBuf },

    #[error(transparent)]
    NetworkState(#[from] NetworkStateError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn journal_file_name(transaction_id: &str) -> Result<String, NetworkRecoveryJournalError> {
    validate_journal_file_component("transaction_id", transaction_id)?;
    Ok(format!("{transaction_id}.json"))
}

fn validate_journal_file_component(
    field: &'static str,
    value: &str,
) -> Result<(), NetworkRecoveryJournalError> {
    if value.is_empty() || value.len() > MAX_NETWORK_STATE_ID_BYTES {
        return Err(NetworkRecoveryJournalError::InvalidJournalId { field });
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(NetworkRecoveryJournalError::InvalidJournalId { field });
    }

    Ok(())
}

fn ensure_private_journal_dir(dir: &Path) -> Result<(), NetworkRecoveryJournalError> {
    fs::create_dir_all(dir)?;
    set_private_dir_permissions(dir)?;
    Ok(())
}

fn load_one_journal(path: &Path) -> Result<NetworkRecoveryJournal, String> {
    let payload = fs::read(path).map_err(|source| source.to_string())?;
    let journal: NetworkRecoveryJournal =
        serde_json::from_slice(&payload).map_err(|source| source.to_string())?;
    journal.validate().map_err(|source| source.to_string())?;
    Ok(journal)
}

fn load_one_applied_state_record(path: &Path) -> Result<NetworkAppliedStateRecord, String> {
    let payload = fs::read(path).map_err(|source| source.to_string())?;
    let record: NetworkAppliedStateRecord =
        serde_json::from_slice(&payload).map_err(|source| source.to_string())?;
    record.validate().map_err(|source| source.to_string())?;
    Ok(record)
}

fn temp_path_for(dir: &Path, transaction_id: &str) -> Result<PathBuf, NetworkRecoveryJournalError> {
    validate_journal_file_component("transaction_id", transaction_id)?;
    let sequence = JOURNAL_TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    Ok(dir.join(format!(
        ".{transaction_id}.{}.{}.tmp",
        std::process::id(),
        sequence
    )))
}

fn cleanup_temp_candidates(dir: &Path) -> Result<bool, NetworkRecoveryJournalError> {
    let mut removed = false;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with('.') && name.ends_with(".tmp"))
        {
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(removed)
}

fn quarantine_journal_file(
    path: &Path,
    reason: String,
) -> Result<QuarantinedRecoveryJournal, NetworkRecoveryJournalError> {
    let quarantine_path = next_quarantine_path(path)?;
    fs::rename(path, &quarantine_path)?;
    Ok(QuarantinedRecoveryJournal {
        original_path: path.to_path_buf(),
        quarantine_path,
        reason,
    })
}

fn next_quarantine_path(path: &Path) -> Result<PathBuf, NetworkRecoveryJournalError> {
    for suffix in 1..=1000 {
        let candidate = path.with_extension(format!("json.invalid.{suffix}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(NetworkRecoveryJournalError::NoQuarantinePath {
        path: path.to_path_buf(),
    })
}

fn replace_file(source: &Path, target: &Path) -> Result<(), NetworkRecoveryJournalError> {
    #[cfg(windows)]
    {
        if target.exists() {
            fs::remove_file(target)?;
        }
    }

    fs::rename(source, target)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_private_dir_permissions(dir: &Path) -> Result<(), NetworkRecoveryJournalError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(dir)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_dir: &Path) -> Result<(), NetworkRecoveryJournalError> {
    Ok(())
}

fn sync_parent_dir(dir: &Path) -> Result<(), NetworkRecoveryJournalError> {
    #[cfg(unix)]
    {
        use std::fs::File;
        File::open(dir)?.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let _ = dir;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::network_state::{
        AppliedNetworkOperation, DnsSnapshot, FirewallSnapshot, IpNetwork,
        NetworkInterfaceSnapshot, NetworkOperationKind, NetworkOperationStatus,
        NetworkRollbackPlan, RouteSnapshot,
    };
    use crate::network_transaction::{ConnectNetworkIntent, ConnectNetworkTransactionPlanner};
    use crate::platform_contract::PlatformKind;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "novaray_recovery_journal_{label}_{}_{}",
                std::process::id(),
                JOURNAL_TMP_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&dir).expect("create temp journal dir");
            Self(dir)
        }
    }

    impl AsRef<Path> for TempDirGuard {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn owner() -> NetworkStateOwner {
        NetworkStateOwner {
            component: "core".to_string(),
            correlation_id: "req-1".to_string(),
        }
    }

    fn snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            snapshot_id: "snap-1".to_string(),
            platform: PlatformKind::MacOs,
            owner: owner(),
            interfaces: vec![NetworkInterfaceSnapshot {
                name: "en0".to_string(),
                addresses: vec![IpNetwork::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 7, 10)),
                    24,
                )],
                mtu: Some(1500),
            }],
            routes: vec![RouteSnapshot {
                destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
                interface: Some("en0".to_string()),
            }],
            dns: DnsSnapshot {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))],
                search_domains: vec!["corp.internal".to_string()],
                match_domains: vec!["corp.example".to_string()],
            },
            firewall: FirewallSnapshot {
                policy_id: Some("pf-baseline".to_string()),
                kill_switch_enabled: true,
            },
        }
    }

    fn applied_state() -> AppliedNetworkState {
        AppliedNetworkState {
            transaction_id: "txn-1".to_string(),
            snapshot_id: "snap-1".to_string(),
            platform: PlatformKind::MacOs,
            owner: owner(),
            phase: NetworkTransactionPhase::Applied,
            operations: vec![AppliedNetworkOperation {
                key: "dns".to_string(),
                apply_order: Some(1),
                kind: NetworkOperationKind::SetDns {
                    servers: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53))],
                    search_domains: vec!["proxy.internal".to_string()],
                    match_domains: vec!["proxy.example".to_string()],
                },
                status: NetworkOperationStatus::Applied,
                rollback: NetworkRollbackPlan {
                    required: true,
                    inverse: Some(NetworkOperationKind::SetDns {
                        servers: vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))],
                        search_domains: vec!["corp.internal".to_string()],
                        match_domains: vec!["corp.example".to_string()],
                    }),
                },
            }],
            last_error: None,
        }
    }

    fn journal() -> NetworkRecoveryJournal {
        NetworkRecoveryJournal::new(snapshot(), applied_state())
    }

    fn applied_record() -> NetworkAppliedStateRecord {
        NetworkAppliedStateRecord::new(snapshot(), applied_state())
    }

    fn applied_record_with_id(transaction_id: &str) -> NetworkAppliedStateRecord {
        let mut state = applied_state();
        state.transaction_id = transaction_id.to_string();
        NetworkAppliedStateRecord::new(snapshot(), state)
    }

    fn connect_snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            snapshot_id: "connect-snap-1".to_string(),
            platform: PlatformKind::MacOs,
            owner: owner(),
            interfaces: vec![NetworkInterfaceSnapshot {
                name: "utun4".to_string(),
                addresses: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24)],
                mtu: Some(1500),
            }],
            routes: vec![
                RouteSnapshot {
                    destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 32),
                    gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
                    interface: Some("en0".to_string()),
                },
                RouteSnapshot {
                    destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
                    interface: Some("en0".to_string()),
                },
            ],
            dns: DnsSnapshot {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))],
                search_domains: vec!["corp.internal".to_string()],
                match_domains: vec!["corp.example".to_string()],
            },
            firewall: FirewallSnapshot {
                policy_id: Some("pf-baseline".to_string()),
                kill_switch_enabled: false,
            },
        }
    }

    fn connect_intent() -> ConnectNetworkIntent {
        ConnectNetworkIntent {
            transaction_id: "txn-route-crash".to_string(),
            owner: owner(),
            endpoint: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            endpoint_gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
            endpoint_interface: Some("en0".to_string()),
            tunnel_interface: "utun4".to_string(),
            tunnel_address: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 30),
            tunnel_mtu: 1280,
            dns: DnsSnapshot {
                servers: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53))],
                search_domains: vec!["vpn.internal".to_string()],
                match_domains: vec!["vpn.example".to_string()],
            },
            firewall_policy_id: "novaray-full-tunnel".to_string(),
            kill_switch_enabled: true,
        }
    }

    fn crash_after_full_tunnel_route_journal(
        snapshot: NetworkSnapshot,
        intent: ConnectNetworkIntent,
    ) -> NetworkRecoveryJournal {
        let mut state =
            ConnectNetworkTransactionPlanner::plan(&snapshot, intent).expect("valid connect plan");
        state.phase = NetworkTransactionPhase::RollingBack;
        for operation in &mut state.operations {
            operation.status = match operation.apply_order {
                Some(1..=4) => NetworkOperationStatus::Applied,
                Some(5..) => NetworkOperationStatus::Planned,
                _ => unreachable!("planner always assigns apply_order"),
            };
        }

        NetworkRecoveryJournal::new(snapshot, state)
    }

    fn assert_route_crash_recovery_order(journal: &NetworkRecoveryJournal) {
        let steps = journal
            .applied_state
            .rollback_steps_reverse_order()
            .expect("recoverable route-crash rollback work");

        assert_eq!(
            steps
                .iter()
                .map(|step| (step.apply_order, step.operation_key.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (4, "004_route_full_tunnel"),
                (3, "003_set_tunnel_mtu"),
                (2, "002_set_tunnel_address"),
                (1, "001_preserve_endpoint_route"),
            ]
        );
    }

    #[test]
    fn journal_roundtrips_and_clears_pending_state() {
        let temp_dir = TempDirGuard::new("roundtrip");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let journal = journal();

        let path = store.write_pending(&journal).expect("write journal");
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("txn-1.json")
        );

        let loaded = store.load_pending().expect("load journals");
        assert_eq!(loaded, vec![journal]);

        assert!(store.clear_pending("txn-1").expect("clear journal"));
        assert!(!store.clear_pending("txn-1").expect("clear is idempotent"));
        assert!(store.load_pending().expect("empty after clear").is_empty());
    }

    #[test]
    fn applied_state_record_roundtrips_without_becoming_pending_work() {
        let temp_dir = TempDirGuard::new("applied_roundtrip");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let record = applied_record();

        let path = store
            .write_applied_state(&record)
            .expect("write applied state");
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("txn-1.json")
        );
        assert_eq!(
            path.parent(),
            Some(store.applied_state_dir().as_path()),
            "applied records live outside the pending journal directory"
        );

        assert!(store
            .load_pending()
            .expect("applied state is not pending recovery work")
            .is_empty());
        assert_eq!(
            store
                .load_applied_state()
                .expect("load applied state records"),
            vec![record]
        );

        assert!(store
            .clear_applied_state("txn-1")
            .expect("clear applied state"));
        assert!(!store
            .clear_applied_state("txn-1")
            .expect("clear applied state is idempotent"));
        assert!(store
            .load_applied_state()
            .expect("empty applied state after clear")
            .is_empty());
    }

    #[test]
    fn writing_applied_state_replaces_previous_active_record() {
        let temp_dir = TempDirGuard::new("applied_replace");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        store
            .write_applied_state(&applied_record_with_id("txn-1"))
            .expect("write first applied state");
        store
            .write_applied_state(&applied_record_with_id("txn-2"))
            .expect("write replacement applied state");
        store
            .write_applied_state(&applied_record_with_id("txn-3"))
            .expect("write latest applied state");

        let records = store
            .load_applied_state()
            .expect("load active applied state");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, "txn-3");
        assert!(!store
            .applied_state_path_for("txn-1")
            .expect("txn-1 applied path")
            .exists());
        assert!(!store
            .applied_state_path_for("txn-2")
            .expect("txn-2 applied path")
            .exists());
    }

    #[test]
    #[cfg(unix)]
    fn journal_directory_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDirGuard::new("permissions");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        store.write_pending(&journal()).expect("write journal");

        let mode = fs::metadata(temp_dir.as_ref())
            .expect("journal dir metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o700);
    }

    #[test]
    #[cfg(unix)]
    fn applied_state_directory_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDirGuard::new("applied_permissions");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        store
            .write_applied_state(&applied_record())
            .expect("write applied state");

        let mode = fs::metadata(store.applied_state_dir())
            .expect("applied state dir metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o700);
    }

    #[test]
    fn corrupt_journal_is_quarantined_without_blocking_valid_recovery_work() {
        let temp_dir = TempDirGuard::new("quarantine");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let valid = journal();
        store.write_pending(&valid).expect("write valid journal");

        let path = temp_dir.as_ref().join("txn-2.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"journal_id":"txn-2","unexpected":true}"#,
        )
        .expect("write corrupt journal");

        let report = store
            .load_pending_report()
            .expect("load valid and quarantine invalid");

        assert_eq!(report.journals, vec![valid]);
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(report.quarantined[0].original_path, path);
        assert!(!report.quarantined[0].original_path.exists());
        assert!(report.quarantined[0].quarantine_path.exists());
        assert!(report.quarantined[0]
            .quarantine_path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("txn-2.json.invalid.")));
        assert!(!format!("{report:?}").contains("10.13.37.53"));
    }

    #[test]
    fn corrupt_applied_state_is_quarantined_without_hiding_valid_records() {
        let temp_dir = TempDirGuard::new("applied_quarantine");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let valid = applied_record();
        store
            .write_applied_state(&valid)
            .expect("write valid applied state");

        fs::write(
            store.applied_state_dir().join("txn-2.json"),
            r#"{"schema_version":1,"record_id":"txn-2","unexpected":true}"#,
        )
        .expect("write corrupt applied state");

        let report = store
            .load_applied_state_report()
            .expect("load valid and quarantine invalid applied state");

        assert_eq!(report.records, vec![valid]);
        assert_eq!(report.quarantined.len(), 1);
        assert!(report.quarantined[0]
            .quarantine_path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("txn-2.json.invalid.")));
        assert!(!format!("{report:?}").contains("10.13.37.53"));
    }

    #[test]
    fn temp_candidate_files_are_cleaned_and_not_treated_as_pending_journals() {
        let temp_dir = TempDirGuard::new("temp");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let temp_path = temp_dir.as_ref().join(".txn-1.123.tmp");
        fs::write(&temp_path, b"partial").expect("write temp candidate");

        assert!(store.load_pending().expect("ignore temp").is_empty());
        assert!(!temp_path.exists());
    }

    #[test]
    fn transaction_id_cannot_escape_journal_directory() {
        let temp_dir = TempDirGuard::new("path");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());

        assert!(matches!(
            store.journal_path_for("../txn-1"),
            Err(NetworkRecoveryJournalError::InvalidJournalId {
                field: "transaction_id"
            })
        ));

        assert!(matches!(
            store.clear_pending("txn/1"),
            Err(NetworkRecoveryJournalError::InvalidJournalId {
                field: "transaction_id"
            })
        ));

        assert!(matches!(
            store.applied_state_path_for("a b"),
            Err(NetworkRecoveryJournalError::InvalidJournalId {
                field: "transaction_id"
            })
        ));

        assert!(matches!(
            store.clear_applied_state("a\\b"),
            Err(NetworkRecoveryJournalError::InvalidJournalId {
                field: "transaction_id"
            })
        ));
    }

    #[test]
    fn invalid_persisted_state_cannot_produce_recovery_work() {
        let temp_dir = TempDirGuard::new("invalid_state");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let mut journal = journal();
        journal.applied_state.operations[0].rollback = NetworkRollbackPlan {
            required: true,
            inverse: None,
        };
        let payload = serde_json::to_vec_pretty(&journal).expect("serialize invalid journal");
        fs::write(temp_dir.as_ref().join("txn-1.json"), payload).expect("write invalid journal");

        let report = store
            .load_pending_report()
            .expect("invalid persisted state is quarantined");
        assert!(report.journals.is_empty());
        assert_eq!(report.quarantined.len(), 1);
        assert!(report.quarantined[0]
            .reason
            .contains("requires rollback metadata"));
    }

    #[test]
    fn planned_transactions_are_not_recoverable_journals() {
        let mut journal = journal();
        journal.applied_state.phase = NetworkTransactionPhase::Planned;
        journal.applied_state.operations.clear();

        assert!(matches!(
            journal.validate(),
            Err(NetworkRecoveryJournalError::NotRecoverablePhase {
                phase: NetworkTransactionPhase::Planned
            })
        ));
    }

    #[test]
    fn non_applied_phase_is_not_an_applied_state_record() {
        let mut record = applied_record();
        record.applied_state.phase = NetworkTransactionPhase::RollingBack;

        assert!(matches!(
            record.validate(),
            Err(NetworkRecoveryJournalError::NotAppliedStatePhase {
                phase: NetworkTransactionPhase::RollingBack
            })
        ));
    }

    #[test]
    fn debug_output_redacts_network_identity_values() {
        let journal = journal();
        let record = applied_record();
        let debug = format!("{journal:?}");
        let applied_debug = format!("{record:?}");
        let error_debug = format!(
            "{:?}",
            NetworkRecoveryJournalError::MismatchedOwner {
                snapshot_owner: journal.snapshot.owner.clone(),
                applied_owner: journal.applied_state.owner.clone(),
            }
        );

        for output in [&debug, &applied_debug, &error_debug] {
            assert!(!output.contains("192.168.7.1"));
            assert!(!output.contains("10.13.37.53"));
            assert!(!output.contains("corp.internal"));
            assert!(!output.contains("proxy.internal"));
            assert!(!output.contains("en0"));
        }

        assert!(debug.contains("transaction_id: \"txn-1\""));
        assert!(debug.contains("operations_len: 1"));
    }

    #[test]
    fn crash_after_full_tunnel_route_recovers_existing_default_route_before_endpoint_route() {
        let temp_dir = TempDirGuard::new("route_crash_existing_default");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let journal = crash_after_full_tunnel_route_journal(connect_snapshot(), connect_intent());

        store
            .write_pending(&journal)
            .expect("write route-crash journal");
        let loaded = store.load_pending().expect("load route-crash journal");

        assert_eq!(loaded.len(), 1);
        assert_route_crash_recovery_order(&loaded[0]);

        let steps = loaded[0]
            .applied_state
            .rollback_steps_reverse_order()
            .expect("rollback steps");
        assert!(matches!(
            steps[0].inverse,
            NetworkOperationKind::AddRoute {
                destination: IpNetwork {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix: 0,
                },
                gateway: Some(IpAddr::V4(_)),
                interface: Some(ref interface),
            } if interface == "en0"
        ));
        assert!(matches!(
            steps.last().map(|step| &step.inverse),
            Some(NetworkOperationKind::PreserveEndpointRoute { .. })
        ));

        let debug = format!("{:?} {:?}", loaded[0], steps);
        for leaked in [
            "192.168.7.1",
            "10.13.37.53",
            "198.51.100.53",
            "corp.internal",
            "vpn.internal",
        ] {
            assert!(!debug.contains(leaked), "debug leaked {leaked}");
        }
    }

    #[test]
    fn crash_after_full_tunnel_route_removes_added_route_when_no_default_existed() {
        let temp_dir = TempDirGuard::new("route_crash_missing_default");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let mut snapshot = connect_snapshot();
        snapshot
            .routes
            .retain(|route| route.destination.prefix != 0);
        let journal = crash_after_full_tunnel_route_journal(snapshot, connect_intent());

        store
            .write_pending(&journal)
            .expect("write route-crash journal");
        let loaded = store.load_pending().expect("load route-crash journal");

        assert_eq!(loaded.len(), 1);
        assert_route_crash_recovery_order(&loaded[0]);

        let steps = loaded[0]
            .applied_state
            .rollback_steps_reverse_order()
            .expect("rollback steps");
        assert!(matches!(
            steps[0].inverse,
            NetworkOperationKind::RemoveRoute {
                destination: IpNetwork {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix: 0,
                },
                gateway: None,
                interface: Some(ref interface),
            } if interface == "utun4"
        ));
    }

    #[test]
    fn crash_after_full_tunnel_route_does_not_mix_ipv4_and_ipv6_defaults() {
        let temp_dir = TempDirGuard::new("route_crash_ipv6");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let mut snapshot = connect_snapshot();
        snapshot.interfaces[0].name = "utun6".to_string();
        let mut intent = connect_intent();
        intent.transaction_id = "txn-route-crash-ipv6".to_string();
        intent.tunnel_interface = "utun6".to_string();
        intent.tunnel_address =
            IpNetwork::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 64);
        let journal = crash_after_full_tunnel_route_journal(snapshot, intent);

        store
            .write_pending(&journal)
            .expect("write IPv6 route-crash journal");
        let loaded = store.load_pending().expect("load IPv6 route-crash journal");

        assert_eq!(loaded.len(), 1);
        assert_route_crash_recovery_order(&loaded[0]);

        let steps = loaded[0]
            .applied_state
            .rollback_steps_reverse_order()
            .expect("rollback steps");
        assert!(matches!(
            steps[0].inverse,
            NetworkOperationKind::RemoveRoute {
                destination: IpNetwork {
                    address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix: 0,
                },
                gateway: None,
                interface: Some(ref interface),
            } if interface == "utun6"
        ));
    }
}
