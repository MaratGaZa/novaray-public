//! Pure network transaction state contract for the future privileged helper.
//!
//! This module models snapshots, planned/applied operations and rollback metadata only. It does
//! not open sockets, run as root, create `utun`, or mutate routes/DNS/firewall/system proxy state.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::platform_contract::PlatformKind;

pub const MAX_NETWORK_STATE_ID_BYTES: usize = 128;
pub const MAX_NETWORK_COLLECTION_ITEMS: usize = 256;
pub const MAX_DNS_SERVERS: usize = 16;
pub const MAX_DOMAIN_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSnapshot {
    pub snapshot_id: String,
    pub platform: PlatformKind,
    pub owner: NetworkStateOwner,
    pub interfaces: Vec<NetworkInterfaceSnapshot>,
    pub routes: Vec<RouteSnapshot>,
    pub dns: DnsSnapshot,
    pub firewall: FirewallSnapshot,
}

impl NetworkSnapshot {
    pub fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("snapshot_id", &self.snapshot_id)?;
        self.owner.validate()?;
        validate_collection_len("interfaces", self.interfaces.len())?;
        validate_collection_len("routes", self.routes.len())?;

        let mut interface_names = HashSet::new();
        for interface in &self.interfaces {
            interface.validate()?;
            if !interface_names.insert(interface.name.as_str()) {
                return Err(NetworkStateError::DuplicateKey {
                    field: "interfaces",
                    key: interface.name.clone(),
                });
            }
        }

        let mut route_keys = HashSet::new();
        for route in &self.routes {
            route.validate()?;
            let key = route.key();
            if !route_keys.insert(key.clone()) {
                return Err(NetworkStateError::DuplicateKey {
                    field: "routes",
                    key,
                });
            }
        }

        self.dns.validate()?;
        self.firewall.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedNetworkState {
    pub transaction_id: String,
    pub snapshot_id: String,
    pub platform: PlatformKind,
    pub owner: NetworkStateOwner,
    pub phase: NetworkTransactionPhase,
    pub operations: Vec<AppliedNetworkOperation>,
    pub last_error: Option<String>,
}

impl AppliedNetworkState {
    pub fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("transaction_id", &self.transaction_id)?;
        validate_id("snapshot_id", &self.snapshot_id)?;
        self.owner.validate()?;
        validate_collection_len("operations", self.operations.len())?;

        let mut operation_keys = HashSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !operation_keys.insert(operation.key.as_str()) {
                return Err(NetworkStateError::DuplicateKey {
                    field: "operations",
                    key: operation.key.clone(),
                });
            }
        }

        match self.phase {
            NetworkTransactionPhase::Planned => {
                if self
                    .operations
                    .iter()
                    .any(|operation| operation.status != NetworkOperationStatus::Planned)
                {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "planned transactions may only contain planned operations",
                    });
                }
                if self.last_error.is_some() {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "planned transactions must not carry last_error",
                    });
                }
            }
            NetworkTransactionPhase::Applied => {
                if self.operations.is_empty() {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "applied transactions require at least one operation",
                    });
                }
                if self
                    .operations
                    .iter()
                    .any(|operation| operation.status != NetworkOperationStatus::Applied)
                {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "applied transactions may only contain applied operations",
                    });
                }
                if self.last_error.is_some() {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "applied transactions must not carry last_error",
                    });
                }
            }
            NetworkTransactionPhase::Failed => {
                validate_optional_id("last_error", self.last_error.as_deref())?;
                if self.last_error.is_none() {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "failed transactions require last_error",
                    });
                }
                if !self.operations.iter().any(|operation| {
                    matches!(
                        operation.status,
                        NetworkOperationStatus::Failed | NetworkOperationStatus::RolledBack
                    )
                }) {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "failed transactions require a failed or rolled-back operation",
                    });
                }
            }
            NetworkTransactionPhase::RollingBack => {
                if !self
                    .operations
                    .iter()
                    .any(|operation| operation.rollback.required)
                {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "rolling_back transactions require rollback metadata",
                    });
                }
            }
            NetworkTransactionPhase::RolledBack => {
                if self
                    .operations
                    .iter()
                    .any(|operation| operation.status != NetworkOperationStatus::RolledBack)
                {
                    return Err(NetworkStateError::InvalidPhase {
                        phase: self.phase,
                        reason: "rolled_back transactions may only contain rolled_back operations",
                    });
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkStateOwner {
    pub component: String,
    pub correlation_id: String,
}

impl NetworkStateOwner {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("owner.component", &self.component)?;
        validate_id("owner.correlation_id", &self.correlation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceSnapshot {
    pub name: String,
    pub addresses: Vec<IpNetwork>,
    pub mtu: Option<u32>,
}

impl NetworkInterfaceSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("interface.name", &self.name)?;
        validate_collection_len("interface.addresses", self.addresses.len())?;
        for address in &self.addresses {
            address.validate()?;
        }

        if matches!(self.mtu, Some(0)) {
            return Err(NetworkStateError::InvalidMtu { mtu: 0 });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSnapshot {
    pub destination: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
}

impl RouteSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        self.destination.validate()?;
        validate_optional_id("route.interface", self.interface.as_deref())
    }

    fn key(&self) -> String {
        format!(
            "{:?}|{:?}|{:?}",
            self.destination, self.gateway, self.interface
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSnapshot {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
}

impl DnsSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_max_len("dns.servers", self.servers.len(), MAX_DNS_SERVERS)?;
        validate_max_len(
            "dns.search_domains",
            self.search_domains.len(),
            MAX_DOMAIN_ITEMS,
        )?;
        validate_max_len(
            "dns.match_domains",
            self.match_domains.len(),
            MAX_DOMAIN_ITEMS,
        )?;

        for domain in self.search_domains.iter().chain(&self.match_domains) {
            validate_domain_label_list(domain)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSnapshot {
    pub policy_id: Option<String>,
    pub kill_switch_enabled: bool,
}

impl FirewallSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_optional_id("firewall.policy_id", self.policy_id.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedNetworkOperation {
    pub key: String,
    pub kind: NetworkOperationKind,
    pub status: NetworkOperationStatus,
    pub rollback: NetworkRollbackPlan,
}

impl AppliedNetworkOperation {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("operation.key", &self.key)?;
        self.kind.validate()?;
        self.rollback.validate(&self.key, self.status)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTransactionPhase {
    Planned,
    Applied,
    Failed,
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkOperationStatus {
    Planned,
    Applied,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NetworkOperationKind {
    PreserveEndpointRoute {
        endpoint: IpAddr,
        gateway: Option<IpAddr>,
        interface: Option<String>,
    },
    AddRoute {
        destination: IpNetwork,
        gateway: Option<IpAddr>,
        interface: Option<String>,
    },
    SetInterfaceAddress {
        interface: String,
        address: IpNetwork,
    },
    SetMtu {
        interface: String,
        mtu: u32,
    },
    SetDns {
        servers: Vec<IpAddr>,
        search_domains: Vec<String>,
        match_domains: Vec<String>,
    },
    ApplyFirewallPolicy {
        policy_id: String,
        kill_switch_enabled: bool,
    },
}

impl NetworkOperationKind {
    fn validate(&self) -> Result<(), NetworkStateError> {
        match self {
            Self::PreserveEndpointRoute {
                interface,
                endpoint: _,
                gateway: _,
            } => validate_optional_id("operation.interface", interface.as_deref()),
            Self::AddRoute {
                destination,
                interface,
                gateway: _,
            } => {
                destination.validate()?;
                validate_optional_id("operation.interface", interface.as_deref())
            }
            Self::SetInterfaceAddress { interface, address } => {
                validate_id("operation.interface", interface)?;
                address.validate()
            }
            Self::SetMtu { interface, mtu } => {
                validate_id("operation.interface", interface)?;
                if *mtu == 0 {
                    return Err(NetworkStateError::InvalidMtu { mtu: *mtu });
                }
                Ok(())
            }
            Self::SetDns {
                servers,
                search_domains,
                match_domains,
            } => DnsSnapshot {
                servers: servers.clone(),
                search_domains: search_domains.clone(),
                match_domains: match_domains.clone(),
            }
            .validate(),
            Self::ApplyFirewallPolicy {
                policy_id,
                kill_switch_enabled: _,
            } => validate_id("operation.policy_id", policy_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRollbackPlan {
    pub required: bool,
    pub inverse: Option<NetworkOperationKind>,
}

impl NetworkRollbackPlan {
    fn validate(
        &self,
        operation_key: &str,
        status: NetworkOperationStatus,
    ) -> Result<(), NetworkStateError> {
        if self.required && self.inverse.is_none() {
            return Err(NetworkStateError::MissingRollback {
                operation_key: operation_key.to_string(),
            });
        }

        if !self.required && self.inverse.is_some() {
            return Err(NetworkStateError::InvalidRollback {
                operation_key: operation_key.to_string(),
                reason: "non-required rollback must not carry inverse operation",
            });
        }

        if matches!(
            status,
            NetworkOperationStatus::Applied | NetworkOperationStatus::Failed
        ) && !self.required
        {
            return Err(NetworkStateError::MissingRollback {
                operation_key: operation_key.to_string(),
            });
        }

        if let Some(inverse) = &self.inverse {
            inverse.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpNetwork {
    pub address: IpAddr,
    pub prefix: u8,
}

impl IpNetwork {
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        Self { address, prefix }
    }

    fn validate(&self) -> Result<(), NetworkStateError> {
        let max_prefix = match self.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if self.prefix > max_prefix {
            return Err(NetworkStateError::InvalidPrefix {
                address: self.address,
                prefix: self.prefix,
                max_prefix,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetworkStateError {
    #[error("{field} must be non-empty")]
    EmptyId { field: &'static str },

    #[error("{field} exceeds {limit} bytes: {actual}")]
    OversizedId {
        field: &'static str,
        limit: usize,
        actual: usize,
    },

    #[error("{field} contains an invalid character")]
    InvalidId { field: &'static str },

    #[error("{field} exceeds {limit} items: {actual}")]
    TooManyItems {
        field: &'static str,
        limit: usize,
        actual: usize,
    },

    #[error("duplicate {field} key: {key}")]
    DuplicateKey { field: &'static str, key: String },

    #[error("invalid network prefix {prefix} for {address}; max is {max_prefix}")]
    InvalidPrefix {
        address: IpAddr,
        prefix: u8,
        max_prefix: u8,
    },

    #[error("invalid MTU value: {mtu}")]
    InvalidMtu { mtu: u32 },

    #[error("invalid DNS domain value: {domain}")]
    InvalidDomain { domain: String },

    #[error("operation {operation_key} requires rollback metadata")]
    MissingRollback { operation_key: String },

    #[error("invalid rollback for operation {operation_key}: {reason}")]
    InvalidRollback {
        operation_key: String,
        reason: &'static str,
    },

    #[error("invalid transaction phase {phase:?}: {reason}")]
    InvalidPhase {
        phase: NetworkTransactionPhase,
        reason: &'static str,
    },
}

fn validate_collection_len(field: &'static str, actual: usize) -> Result<(), NetworkStateError> {
    validate_max_len(field, actual, MAX_NETWORK_COLLECTION_ITEMS)
}

fn validate_max_len(
    field: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), NetworkStateError> {
    if actual > limit {
        Err(NetworkStateError::TooManyItems {
            field,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn validate_optional_id(field: &'static str, value: Option<&str>) -> Result<(), NetworkStateError> {
    if let Some(value) = value {
        validate_id(field, value)?;
    }
    Ok(())
}

fn validate_id(field: &'static str, value: &str) -> Result<(), NetworkStateError> {
    if value.is_empty() {
        return Err(NetworkStateError::EmptyId { field });
    }

    let actual = value.len();
    if actual > MAX_NETWORK_STATE_ID_BYTES {
        return Err(NetworkStateError::OversizedId {
            field,
            limit: MAX_NETWORK_STATE_ID_BYTES,
            actual,
        });
    }

    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(NetworkStateError::InvalidId { field });
    }

    Ok(())
}

fn validate_domain_label_list(value: &str) -> Result<(), NetworkStateError> {
    if value.is_empty()
        || value.len() > MAX_NETWORK_STATE_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(NetworkStateError::InvalidDomain {
            domain: value.to_string(),
        });
    }

    Ok(())
}

pub fn group_operations_by_status(
    state: &AppliedNetworkState,
) -> HashMap<NetworkOperationStatus, usize> {
    let mut counts = HashMap::new();
    for operation in &state.operations {
        *counts.entry(operation.status).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn owner() -> NetworkStateOwner {
        NetworkStateOwner {
            component: "core".to_string(),
            correlation_id: "req-1".to_string(),
        }
    }

    fn route(destination: IpAddr, prefix: u8) -> RouteSnapshot {
        RouteSnapshot {
            destination: IpNetwork::new(destination, prefix),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            interface: Some("en0".to_string()),
        }
    }

    fn snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            snapshot_id: "snap-1".to_string(),
            platform: PlatformKind::MacOs,
            owner: owner(),
            interfaces: vec![NetworkInterfaceSnapshot {
                name: "en0".to_string(),
                addresses: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24)],
                mtu: Some(1500),
            }],
            routes: vec![route(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)],
            dns: DnsSnapshot {
                servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                search_domains: vec!["example.test".to_string()],
                match_domains: vec!["corp.example".to_string()],
            },
            firewall: FirewallSnapshot {
                policy_id: Some("pf-baseline".to_string()),
                kill_switch_enabled: false,
            },
        }
    }

    fn set_mtu_operation(key: &str, status: NetworkOperationStatus) -> AppliedNetworkOperation {
        AppliedNetworkOperation {
            key: key.to_string(),
            kind: NetworkOperationKind::SetMtu {
                interface: "utun9".to_string(),
                mtu: 1280,
            },
            status,
            rollback: NetworkRollbackPlan {
                required: true,
                inverse: Some(NetworkOperationKind::SetMtu {
                    interface: "utun9".to_string(),
                    mtu: 1500,
                }),
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
            operations: vec![set_mtu_operation("mtu", NetworkOperationStatus::Applied)],
            last_error: None,
        }
    }

    #[test]
    fn valid_snapshot_and_applied_state_validate() {
        snapshot().validate().expect("valid snapshot");
        applied_state().validate().expect("valid applied state");
    }

    #[test]
    fn duplicate_route_snapshot_is_rejected() {
        let mut snapshot = snapshot();
        snapshot
            .routes
            .push(route(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));

        assert_eq!(
            snapshot.validate(),
            Err(NetworkStateError::DuplicateKey {
                field: "routes",
                key: "IpNetwork { address: 0.0.0.0, prefix: 0 }|Some(192.0.2.1)|Some(\"en0\")"
                    .to_string(),
            })
        );
    }

    #[test]
    fn duplicate_operation_key_is_rejected() {
        let mut state = applied_state();
        state
            .operations
            .push(set_mtu_operation("mtu", NetworkOperationStatus::Applied));

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::DuplicateKey {
                field: "operations",
                key: "mtu".to_string(),
            })
        );
    }

    #[test]
    fn applied_operation_requires_rollback_metadata() {
        let mut state = applied_state();
        state.operations[0].rollback = NetworkRollbackPlan {
            required: true,
            inverse: None,
        };

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::MissingRollback {
                operation_key: "mtu".to_string(),
            })
        );
    }

    #[test]
    fn applied_status_cannot_disable_rollback() {
        let mut state = applied_state();
        state.operations[0].rollback = NetworkRollbackPlan {
            required: false,
            inverse: None,
        };

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::MissingRollback {
                operation_key: "mtu".to_string(),
            })
        );
    }

    #[test]
    fn bounded_identifier_checks_reject_log_injection() {
        let mut state = applied_state();
        state.transaction_id = "txn\nspoofed".to_string();

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::InvalidId {
                field: "transaction_id",
            })
        );
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        let mut snapshot = snapshot();
        snapshot.interfaces[0].addresses[0] =
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 33);

        assert_eq!(
            snapshot.validate(),
            Err(NetworkStateError::InvalidPrefix {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix: 33,
                max_prefix: 32,
            })
        );
    }

    #[test]
    fn failed_transaction_requires_error_and_failed_operation() {
        let mut state = applied_state();
        state.phase = NetworkTransactionPhase::Failed;

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::InvalidPhase {
                phase: NetworkTransactionPhase::Failed,
                reason: "failed transactions require last_error",
            })
        );

        state.last_error = Some("route-step-failed".to_string());
        assert_eq!(
            state.validate(),
            Err(NetworkStateError::InvalidPhase {
                phase: NetworkTransactionPhase::Failed,
                reason: "failed transactions require a failed or rolled-back operation",
            })
        );

        state.operations[0].status = NetworkOperationStatus::Failed;
        state.validate().expect("failed transaction is explicit");
    }

    #[test]
    fn rolled_back_transaction_requires_all_operations_rolled_back() {
        let mut state = applied_state();
        state.phase = NetworkTransactionPhase::RolledBack;

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::InvalidPhase {
                phase: NetworkTransactionPhase::RolledBack,
                reason: "rolled_back transactions may only contain rolled_back operations",
            })
        );

        state.operations[0].status = NetworkOperationStatus::RolledBack;
        state.validate().expect("all operations rolled back");
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        let raw = r#"{
            "transaction_id":"txn-1",
            "snapshot_id":"snap-1",
            "platform":"mac_os",
            "owner":{"component":"core","correlation_id":"req-1"},
            "phase":"planned",
            "operations":[],
            "last_error":null,
            "shell":"route delete default"
        }"#;

        assert!(serde_json::from_str::<AppliedNetworkState>(raw).is_err());
    }

    #[test]
    fn operation_status_counts_are_diagnostic_only() {
        let mut state = applied_state();
        state
            .operations
            .push(set_mtu_operation("mtu2", NetworkOperationStatus::Applied));

        let counts = group_operations_by_status(&state);
        assert_eq!(counts.get(&NetworkOperationStatus::Applied), Some(&2));
    }
}
