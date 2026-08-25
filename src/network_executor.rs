//! Pure network operation executor contract.
//!
//! This module connects planned network transactions to a typed operation executor without
//! invoking platform APIs. It does not create `utun`, run as root, execute shell commands, or mutate
//! routes, DNS, firewall, system proxy, or packet-flow state.

use std::fmt;

use thiserror::Error;

use crate::network_state::{
    AppliedNetworkState, NetworkOperationKind, NetworkOperationStatus, NetworkStateError,
    NetworkTransactionPhase,
};
use crate::recovery_journal::{
    NetworkRecoveryJournal, NetworkRecoveryJournalError, NetworkRecoveryJournalStore,
};

use crate::network_state::NetworkSnapshot;

pub trait NetworkOperationExecutor {
    fn execute(&mut self, operation: &NetworkOperationKind) -> Result<(), NetworkOperationError>;

    fn interruption_after_execute_before_postwrite(&self, _apply_order: u32) -> Option<String> {
        None
    }

    fn interruption_after(&self, _apply_order: u32) -> Option<String> {
        None
    }
}

pub trait NetworkRecoveryJournalWriter {
    fn write_recovery_journal(
        &mut self,
        journal: &NetworkRecoveryJournal,
    ) -> Result<(), NetworkRecoveryJournalError>;
}

impl NetworkRecoveryJournalWriter for NetworkRecoveryJournalStore {
    fn write_recovery_journal(
        &mut self,
        journal: &NetworkRecoveryJournal,
    ) -> Result<(), NetworkRecoveryJournalError> {
        self.write_pending(journal)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkExecutionOutcome {
    Applied,
    Failed {
        operation_key: String,
        reason: String,
    },
    Interrupted {
        after_apply_order: u32,
        reason: String,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct NetworkExecutionReport {
    pub state: AppliedNetworkState,
    pub outcome: NetworkExecutionOutcome,
}

impl fmt::Debug for NetworkExecutionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkExecutionReport")
            .field("state", &self.state)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum NetworkExecutionError {
    #[error(transparent)]
    State(#[from] NetworkStateError),

    #[error(transparent)]
    Journal(#[from] NetworkRecoveryJournalError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetworkOperationError {
    #[error("dry-run operation failed: {reason}")]
    DryRunFailure { reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct NetworkTransactionExecutor;

impl NetworkTransactionExecutor {
    pub fn execute(
        &self,
        snapshot: &NetworkSnapshot,
        plan: AppliedNetworkState,
        operation_executor: &mut impl NetworkOperationExecutor,
        journal_writer: &mut impl NetworkRecoveryJournalWriter,
    ) -> Result<NetworkExecutionReport, NetworkExecutionError> {
        plan.validate()?;
        let mut state = plan;
        state.phase = NetworkTransactionPhase::RollingBack;

        let mut order = state
            .operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                operation
                    .apply_order
                    .map(|apply_order| (apply_order, index))
                    .ok_or_else(|| NetworkStateError::MissingApplyOrder {
                        operation_key: operation.key.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        order.sort_by_key(|(apply_order, _)| *apply_order);

        for (apply_order, index) in order {
            state.operations[index].status = NetworkOperationStatus::Applying;
            write_recovery_journal(snapshot, &state, journal_writer)?;

            let operation_key = state.operations[index].key.clone();
            let operation_kind = state.operations[index].kind.clone();
            match operation_executor.execute(&operation_kind) {
                Ok(()) => {
                    if let Some(reason) =
                        operation_executor.interruption_after_execute_before_postwrite(apply_order)
                    {
                        return Ok(NetworkExecutionReport {
                            state,
                            outcome: NetworkExecutionOutcome::Interrupted {
                                after_apply_order: apply_order,
                                reason,
                            },
                        });
                    }

                    state.operations[index].status = NetworkOperationStatus::Applied;
                    write_recovery_journal(snapshot, &state, journal_writer)?;
                }
                Err(error) => {
                    state.operations[index].status = NetworkOperationStatus::Failed;
                    state.phase = NetworkTransactionPhase::Failed;
                    state.last_error = Some("operation_failed".to_string());
                    write_recovery_journal(snapshot, &state, journal_writer)?;
                    return Ok(NetworkExecutionReport {
                        state,
                        outcome: NetworkExecutionOutcome::Failed {
                            operation_key,
                            reason: error.to_string(),
                        },
                    });
                }
            }

            if let Some(reason) = operation_executor.interruption_after(apply_order) {
                write_recovery_journal(snapshot, &state, journal_writer)?;
                return Ok(NetworkExecutionReport {
                    state,
                    outcome: NetworkExecutionOutcome::Interrupted {
                        after_apply_order: apply_order,
                        reason,
                    },
                });
            }
        }

        state.phase = NetworkTransactionPhase::Applied;
        state.validate()?;
        Ok(NetworkExecutionReport {
            state,
            outcome: NetworkExecutionOutcome::Applied,
        })
    }
}

fn write_recovery_journal(
    snapshot: &NetworkSnapshot,
    state: &AppliedNetworkState,
    journal_writer: &mut impl NetworkRecoveryJournalWriter,
) -> Result<(), NetworkRecoveryJournalError> {
    journal_writer.write_recovery_journal(&NetworkRecoveryJournal::new(
        snapshot.clone(),
        state.clone(),
    ))
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct DryRunNetworkOperationExecutor {
    executed: Vec<NetworkOperationKind>,
    fail_on_apply_order: Option<u32>,
    interrupt_after_execute_before_postwrite_order: Option<u32>,
    interrupt_after_apply_order: Option<u32>,
}

impl fmt::Debug for DryRunNetworkOperationExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DryRunNetworkOperationExecutor")
            .field("executed_len", &self.executed.len())
            .field("fail_on_apply_order", &self.fail_on_apply_order)
            .field(
                "interrupt_after_execute_before_postwrite_order",
                &self.interrupt_after_execute_before_postwrite_order,
            )
            .field(
                "interrupt_after_apply_order",
                &self.interrupt_after_apply_order,
            )
            .finish()
    }
}

impl DryRunNetworkOperationExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_on_apply_order(mut self, apply_order: u32) -> Self {
        self.fail_on_apply_order = Some(apply_order);
        self
    }

    pub fn interrupt_after_execute_before_postwrite(mut self, apply_order: u32) -> Self {
        self.interrupt_after_execute_before_postwrite_order = Some(apply_order);
        self
    }

    pub fn interrupt_after_apply_order(mut self, apply_order: u32) -> Self {
        self.interrupt_after_apply_order = Some(apply_order);
        self
    }

    pub fn executed(&self) -> &[NetworkOperationKind] {
        &self.executed
    }
}

impl NetworkOperationExecutor for DryRunNetworkOperationExecutor {
    fn execute(&mut self, operation: &NetworkOperationKind) -> Result<(), NetworkOperationError> {
        let next_order = self.executed.len() as u32 + 1;
        if self.fail_on_apply_order == Some(next_order) {
            return Err(NetworkOperationError::DryRunFailure {
                reason: "configured_failure".to_string(),
            });
        }

        self.executed.push(operation.clone());
        Ok(())
    }

    fn interruption_after_execute_before_postwrite(&self, apply_order: u32) -> Option<String> {
        (self.interrupt_after_execute_before_postwrite_order == Some(apply_order))
            .then(|| "configured_pre_postwrite_interruption".to_string())
    }

    fn interruption_after(&self, apply_order: u32) -> Option<String> {
        (self.interrupt_after_apply_order == Some(apply_order))
            .then(|| "configured_interruption".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};

    use crate::network_state::{
        DnsSnapshot, FirewallSnapshot, IpNetwork, NetworkInterfaceSnapshot, NetworkStateOwner,
        NetworkTransactionPhase, RouteSnapshot,
    };
    use crate::network_transaction::{ConnectNetworkIntent, ConnectNetworkTransactionPlanner};
    use crate::platform_contract::PlatformKind;
    use crate::recovery_journal::NetworkRecoveryJournalStore;

    use super::*;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "novaray_network_executor_{label}_{}_{}",
                std::process::id(),
                crate::recovery_journal::NETWORK_RECOVERY_JOURNAL_VERSION
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create temp executor dir");
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
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug, Default)]
    struct RecordingJournalWriter {
        writes: Vec<AppliedNetworkState>,
    }

    impl NetworkRecoveryJournalWriter for RecordingJournalWriter {
        fn write_recovery_journal(
            &mut self,
            journal: &NetworkRecoveryJournal,
        ) -> Result<(), NetworkRecoveryJournalError> {
            self.writes.push(journal.applied_state.clone());
            Ok(())
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

    fn intent() -> ConnectNetworkIntent {
        ConnectNetworkIntent {
            transaction_id: "txn-1".to_string(),
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

    fn plan() -> AppliedNetworkState {
        ConnectNetworkTransactionPlanner::plan(&snapshot(), intent()).expect("valid plan")
    }

    #[test]
    fn dry_run_executor_records_successful_execution_order() {
        let snapshot = snapshot();
        let mut executor = DryRunNetworkOperationExecutor::new();
        let mut journal = RecordingJournalWriter::default();

        let report = NetworkTransactionExecutor
            .execute(&snapshot, plan(), &mut executor, &mut journal)
            .expect("execute plan");

        assert_eq!(report.outcome, NetworkExecutionOutcome::Applied);
        assert_eq!(report.state.phase, NetworkTransactionPhase::Applied);
        assert_eq!(executor.executed().len(), 6);
        assert!(matches!(
            executor.executed()[3],
            NetworkOperationKind::AddRoute { .. }
        ));
        assert_eq!(journal.writes.len(), 12);
        for (index, state_before_execute) in journal.writes.iter().step_by(2).enumerate() {
            assert_eq!(
                state_before_execute
                    .operations
                    .iter()
                    .filter(|operation| operation.status == NetworkOperationStatus::Applied)
                    .count(),
                index
            );
            assert_eq!(
                state_before_execute
                    .operations
                    .iter()
                    .filter(|operation| operation.status == NetworkOperationStatus::Applying)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn interruption_before_postwrite_persists_applying_operation_for_rollback() {
        let snapshot = snapshot();
        let temp_dir = TempDirGuard::new("route_crash_before_postwrite");
        let mut store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let mut executor =
            DryRunNetworkOperationExecutor::new().interrupt_after_execute_before_postwrite(4);

        let report = NetworkTransactionExecutor
            .execute(&snapshot, plan(), &mut executor, &mut store)
            .expect("execute until simulated interruption");

        assert_eq!(
            report.outcome,
            NetworkExecutionOutcome::Interrupted {
                after_apply_order: 4,
                reason: "configured_pre_postwrite_interruption".to_string(),
            }
        );
        assert_eq!(report.state.phase, NetworkTransactionPhase::RollingBack);
        assert_eq!(
            report
                .state
                .operations
                .iter()
                .map(|operation| operation.status)
                .collect::<Vec<_>>(),
            vec![
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applying,
                NetworkOperationStatus::Planned,
                NetworkOperationStatus::Planned,
            ]
        );

        let loaded = store
            .load_pending()
            .expect("load persisted route-crash state");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].applied_state, report.state);

        let steps = loaded[0]
            .applied_state
            .rollback_steps_reverse_order()
            .expect("rollback applied prefix");
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
    fn interruption_after_postwrite_persists_recoverable_applied_prefix() {
        let snapshot = snapshot();
        let temp_dir = TempDirGuard::new("route_crash_after_postwrite");
        let mut store = NetworkRecoveryJournalStore::new(temp_dir.as_ref());
        let mut executor = DryRunNetworkOperationExecutor::new().interrupt_after_apply_order(4);

        let report = NetworkTransactionExecutor
            .execute(&snapshot, plan(), &mut executor, &mut store)
            .expect("execute until simulated interruption");

        assert_eq!(
            report
                .state
                .operations
                .iter()
                .map(|operation| operation.status)
                .collect::<Vec<_>>(),
            vec![
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Planned,
                NetworkOperationStatus::Planned,
            ]
        );

        let loaded = store
            .load_pending()
            .expect("load persisted route-crash state");
        assert_eq!(loaded[0].applied_state, report.state);
    }

    #[test]
    fn executor_error_stops_later_operations_and_marks_failed_operation() {
        let snapshot = snapshot();
        let mut executor = DryRunNetworkOperationExecutor::new().fail_on_apply_order(4);
        let mut journal = RecordingJournalWriter::default();

        let report = NetworkTransactionExecutor
            .execute(&snapshot, plan(), &mut executor, &mut journal)
            .expect("operation failure is a typed report");

        assert_eq!(executor.executed().len(), 3);
        assert!(matches!(
            report.outcome,
            NetworkExecutionOutcome::Failed {
                ref operation_key,
                ..
            } if operation_key == "004_route_full_tunnel"
        ));
        assert_eq!(report.state.phase, NetworkTransactionPhase::Failed);
        assert_eq!(report.state.last_error.as_deref(), Some("operation_failed"));
        assert_eq!(
            report
                .state
                .operations
                .iter()
                .map(|operation| operation.status)
                .collect::<Vec<_>>(),
            vec![
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Applied,
                NetworkOperationStatus::Failed,
                NetworkOperationStatus::Planned,
                NetworkOperationStatus::Planned,
            ]
        );
    }

    #[test]
    fn debug_output_redacts_network_identity_values() {
        let snapshot = snapshot();
        let mut executor = DryRunNetworkOperationExecutor::new().interrupt_after_apply_order(4);
        let mut journal = RecordingJournalWriter::default();

        let report = NetworkTransactionExecutor
            .execute(&snapshot, plan(), &mut executor, &mut journal)
            .expect("execute until interruption");
        let debug = format!("{report:?} {executor:?} {:?}", journal.writes);

        for leaked in [
            "192.168.7.1",
            "10.13.37.53",
            "198.51.100.53",
            "corp.internal",
            "vpn.internal",
        ] {
            assert!(!debug.contains(leaked), "debug leaked {leaked}");
        }
        assert!(debug.contains("operations_len"));
    }
}
