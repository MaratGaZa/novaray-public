//! Durable recovery journal contract for network transactions.
//!
//! This module persists typed network transaction state so a later process launch can detect
//! unfinished work. It does not execute rollback steps and does not mutate routes, DNS, firewall,
//! system proxy state, or any platform network interface.

use std::fmt;
use std::fs::{self, File, OpenOptions};
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

#[derive(Clone, Debug)]
pub struct NetworkRecoveryJournalStore {
    dir: PathBuf,
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
        fs::create_dir_all(&self.dir)?;

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

    pub fn load_pending(&self) -> Result<Vec<NetworkRecoveryJournal>, NetworkRecoveryJournalError> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }

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
        for path in paths {
            let payload = fs::read(&path)?;
            let journal: NetworkRecoveryJournal =
                serde_json::from_slice(&payload).map_err(|source| {
                    NetworkRecoveryJournalError::InvalidJournalFile {
                        path: path.clone(),
                        reason: source.to_string(),
                    }
                })?;
            journal.validate().map_err(|source| {
                NetworkRecoveryJournalError::InvalidPersistedState {
                    path: path.clone(),
                    source: Box::new(source),
                }
            })?;
            journals.push(journal);
        }

        Ok(journals)
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

    pub fn journal_path_for(
        &self,
        transaction_id: &str,
    ) -> Result<PathBuf, NetworkRecoveryJournalError> {
        let file_name = journal_file_name(transaction_id)?;
        Ok(self.dir.join(file_name))
    }

    fn temp_path_for(&self, transaction_id: &str) -> Result<PathBuf, NetworkRecoveryJournalError> {
        validate_journal_file_component("transaction_id", transaction_id)?;
        let sequence = JOURNAL_TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        Ok(self.dir.join(format!(
            ".{transaction_id}.{}.{}.tmp",
            std::process::id(),
            sequence
        )))
    }
}

#[derive(Debug, Error)]
pub enum NetworkRecoveryJournalError {
    #[error("invalid recovery journal id in {field}")]
    InvalidJournalId { field: &'static str },

    #[error("unsupported recovery journal version {actual}; expected {expected}")]
    UnsupportedVersion { expected: u32, actual: u32 },

    #[error("recovery journal id {journal_id} does not match transaction id {transaction_id}")]
    MismatchedTransactionId {
        journal_id: String,
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

    #[error("invalid recovery journal file {path:?}: {reason}")]
    InvalidJournalFile { path: PathBuf, reason: String },

    #[error("invalid persisted recovery journal state in {path:?}: {source}")]
    InvalidPersistedState {
        path: PathBuf,
        source: Box<NetworkRecoveryJournalError>,
    },

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

fn set_owner_only_permissions(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

fn sync_parent_dir(dir: &Path) -> Result<(), NetworkRecoveryJournalError> {
    #[cfg(unix)]
    {
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
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::network_state::{
        AppliedNetworkOperation, DnsSnapshot, FirewallSnapshot, IpNetwork,
        NetworkInterfaceSnapshot, NetworkOperationKind, NetworkOperationStatus,
        NetworkRollbackPlan, RouteSnapshot,
    };
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
    fn corrupt_or_unknown_field_journal_is_rejected_fail_closed() {
        let temp_dir = TempDirGuard::new("corrupt");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let path = temp_dir.as_ref().join("txn-1.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"journal_id":"txn-1","unexpected":true}"#,
        )
        .expect("write corrupt journal");

        let err = store.load_pending().expect_err("unknown field is invalid");
        assert!(matches!(
            err,
            NetworkRecoveryJournalError::InvalidJournalFile { .. }
        ));
        assert!(!format!("{err:?}").contains("10.13.37.53"));
    }

    #[test]
    fn temp_candidate_files_are_not_treated_as_pending_journals() {
        let temp_dir = TempDirGuard::new("temp");
        let store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        fs::write(temp_dir.as_ref().join(".txn-1.123.tmp"), b"partial")
            .expect("write temp candidate");

        assert!(store.load_pending().expect("ignore temp").is_empty());
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

        let err = store
            .load_pending()
            .expect_err("invalid persisted state rejected");
        assert!(matches!(
            err,
            NetworkRecoveryJournalError::InvalidPersistedState { .. }
        ));
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
    fn debug_output_redacts_network_identity_values() {
        let journal = journal();
        let debug = format!("{journal:?}");
        let error_debug = format!(
            "{:?}",
            NetworkRecoveryJournalError::MismatchedOwner {
                snapshot_owner: journal.snapshot.owner.clone(),
                applied_owner: journal.applied_state.owner.clone(),
            }
        );

        for output in [&debug, &error_debug] {
            assert!(!output.contains("192.168.7.1"));
            assert!(!output.contains("10.13.37.53"));
            assert!(!output.contains("corp.internal"));
            assert!(!output.contains("proxy.internal"));
        }

        assert!(debug.contains("transaction_id: \"txn-1\""));
        assert!(debug.contains("operations_len: 1"));
    }
}
