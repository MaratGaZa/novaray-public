//! Pure network transaction state contract for the future privileged helper.
//!
//! This module models snapshots, planned/applied operations and rollback metadata only. It does
//! not open sockets, run as root, create `utun`, or mutate routes/DNS/firewall/system proxy state.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::platform_contract::PlatformKind;

pub const MAX_NETWORK_STATE_ID_BYTES: usize = 128;
pub const MAX_NETWORK_COLLECTION_ITEMS: usize = 256;
pub const MAX_DNS_SERVERS: usize = 16;
pub const MAX_DOMAIN_ITEMS: usize = 64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for NetworkSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSnapshot")
            .field("snapshot_id", &self.snapshot_id)
            .field("platform", &self.platform)
            .field("owner", &self.owner)
            .field("interfaces_len", &self.interfaces.len())
            .field("routes_len", &self.routes.len())
            .field("dns", &self.dns)
            .field("firewall", &self.firewall)
            .finish()
    }
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
            let key = route.dedupe_key();
            if !route_keys.insert(key.clone()) {
                return Err(NetworkStateError::DuplicateKey {
                    field: "routes",
                    key: route.redacted_key(),
                });
            }
        }

        self.dns.validate()?;
        self.firewall.validate()?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for AppliedNetworkState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppliedNetworkState")
            .field("transaction_id", &self.transaction_id)
            .field("snapshot_id", &self.snapshot_id)
            .field("platform", &self.platform)
            .field("owner", &self.owner)
            .field("phase", &self.phase)
            .field("operations_len", &self.operations.len())
            .field("last_error_present", &self.last_error.is_some())
            .finish()
    }
}

impl AppliedNetworkState {
    pub fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("transaction_id", &self.transaction_id)?;
        validate_id("snapshot_id", &self.snapshot_id)?;
        self.owner.validate()?;
        validate_collection_len("operations", self.operations.len())?;

        let mut operation_keys = HashSet::new();
        let mut apply_orders = HashSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !operation_keys.insert(operation.key.as_str()) {
                return Err(NetworkStateError::DuplicateKey {
                    field: "operations",
                    key: operation.key.clone(),
                });
            }
            if let Some(apply_order) = operation.apply_order {
                if !apply_orders.insert(apply_order) {
                    return Err(NetworkStateError::DuplicateApplyOrder { apply_order });
                }
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

    pub fn rollback_steps_reverse_order(&self) -> Result<Vec<RollbackStep>, NetworkStateError> {
        self.validate()?;

        let mut steps = Vec::new();
        for operation in &self.operations {
            if !matches!(
                operation.status,
                NetworkOperationStatus::Applying
                    | NetworkOperationStatus::Applied
                    | NetworkOperationStatus::Failed
            ) {
                continue;
            }

            if operation.rollback.required {
                steps.push(RollbackStep {
                    apply_order: operation.apply_order.ok_or_else(|| {
                        NetworkStateError::MissingApplyOrder {
                            operation_key: operation.key.clone(),
                        }
                    })?,
                    operation_key: operation.key.clone(),
                    inverse: operation.rollback.inverse.clone().ok_or_else(|| {
                        NetworkStateError::MissingRollback {
                            operation_key: operation.key.clone(),
                        }
                    })?,
                });
            }
        }

        steps.sort_by_key(|step| Reverse(step.apply_order));
        Ok(steps)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkStateOwner {
    pub component: String,
    pub correlation_id: String,
}

impl fmt::Debug for NetworkStateOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkStateOwner")
            .field("component", &self.component)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl NetworkStateOwner {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("owner.component", &self.component)?;
        validate_id("owner.correlation_id", &self.correlation_id)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceSnapshot {
    pub name: String,
    pub addresses: Vec<IpNetwork>,
    pub mtu: Option<u32>,
}

impl fmt::Debug for NetworkInterfaceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkInterfaceSnapshot")
            .field("name_len", &self.name.len())
            .field("addresses_len", &self.addresses.len())
            .field("mtu", &self.mtu)
            .finish()
    }
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSnapshot {
    pub destination: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
}

impl fmt::Debug for RouteSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSnapshot")
            .field("destination", &self.destination)
            .field("gateway_present", &self.gateway.is_some())
            .field("interface_present", &self.interface.is_some())
            .finish()
    }
}

impl RouteSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        self.destination.validate()?;
        validate_optional_id("route.interface", self.interface.as_deref())
    }

    fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{:?}|{:?}",
            self.destination.address, self.destination.prefix, self.gateway, self.interface
        )
    }

    fn redacted_key(&self) -> String {
        format!(
            "{:?}|gateway_present={}|interface={:?}",
            self.destination,
            self.gateway.is_some(),
            self.interface.as_ref().map(|value| value.len())
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSnapshot {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
}

impl fmt::Debug for DnsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsSnapshot")
            .field("servers_len", &self.servers.len())
            .field("search_domains_len", &self.search_domains.len())
            .field("match_domains_len", &self.match_domains.len())
            .finish()
    }
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSnapshot {
    pub policy_id: Option<String>,
    pub kill_switch_enabled: bool,
}

impl fmt::Debug for FirewallSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirewallSnapshot")
            .field("policy_id_present", &self.policy_id.is_some())
            .field("kill_switch_enabled", &self.kill_switch_enabled)
            .finish()
    }
}

impl FirewallSnapshot {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_optional_id("firewall.policy_id", self.policy_id.as_deref())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedNetworkOperation {
    pub key: String,
    pub apply_order: Option<u32>,
    pub kind: NetworkOperationKind,
    pub status: NetworkOperationStatus,
    pub rollback: NetworkRollbackPlan,
}

impl fmt::Debug for AppliedNetworkOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppliedNetworkOperation")
            .field("key", &self.key)
            .field("apply_order", &self.apply_order)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("rollback", &self.rollback)
            .finish()
    }
}

impl AppliedNetworkOperation {
    fn validate(&self) -> Result<(), NetworkStateError> {
        validate_id("operation.key", &self.key)?;
        self.kind.validate()?;
        if self.rollback.required || self.status != NetworkOperationStatus::Planned {
            self.apply_order
                .ok_or_else(|| NetworkStateError::MissingApplyOrder {
                    operation_key: self.key.clone(),
                })?;
        }
        self.rollback.validate(&self.key, self.status)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackStep {
    pub apply_order: u32,
    pub operation_key: String,
    pub inverse: NetworkOperationKind,
}

impl fmt::Debug for RollbackStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackStep")
            .field("apply_order", &self.apply_order)
            .field("operation_key", &self.operation_key)
            .field("inverse", &self.inverse)
            .finish()
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
    Applying,
    Applied,
    Failed,
    RolledBack,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    RemoveEndpointRoute {
        endpoint: IpAddr,
    },
    AddRoute {
        destination: IpNetwork,
        gateway: Option<IpAddr>,
        interface: Option<String>,
    },
    RemoveRoute {
        destination: IpNetwork,
        gateway: Option<IpAddr>,
        interface: Option<String>,
    },
    SetInterfaceAddress {
        interface: String,
        address: IpNetwork,
    },
    RemoveInterfaceAddress {
        interface: String,
        address: IpNetwork,
    },
    SetMtu {
        interface: String,
        mtu: u32,
    },
    ResetMtu {
        interface: String,
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
    RestoreFirewallSnapshot {
        policy_id: Option<String>,
        kill_switch_enabled: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOperationRetryEffect {
    IdempotentRepeat,
    ConflictingMutation,
    IndependentMutation,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum NetworkOperationIdempotencyScope {
    EndpointRoute { endpoint: IpAddr },
    Route { destination: IpNetwork },
    InterfaceAddress { interface: String },
    InterfaceMtu { interface: String },
    Dns,
    Firewall,
}

impl fmt::Debug for NetworkOperationIdempotencyScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointRoute { endpoint } => formatter
                .debug_struct("EndpointRoute")
                .field("endpoint_family", &ip_family(*endpoint))
                .finish(),
            Self::Route { destination } => formatter
                .debug_struct("Route")
                .field("destination", destination)
                .finish(),
            Self::InterfaceAddress { interface } => formatter
                .debug_struct("InterfaceAddress")
                .field("interface_len", &interface.len())
                .finish(),
            Self::InterfaceMtu { interface } => formatter
                .debug_struct("InterfaceMtu")
                .field("interface_len", &interface.len())
                .finish(),
            Self::Dns => formatter.write_str("Dns"),
            Self::Firewall => formatter.write_str("Firewall"),
        }
    }
}

impl fmt::Debug for NetworkOperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreserveEndpointRoute {
                endpoint,
                gateway,
                interface,
            } => formatter
                .debug_struct("PreserveEndpointRoute")
                .field("endpoint_family", &ip_family(*endpoint))
                .field("gateway_present", &gateway.is_some())
                .field("interface_present", &interface.is_some())
                .finish(),
            Self::RemoveEndpointRoute { endpoint } => formatter
                .debug_struct("RemoveEndpointRoute")
                .field("endpoint_family", &ip_family(*endpoint))
                .finish(),
            Self::AddRoute {
                destination,
                gateway,
                interface,
            } => formatter
                .debug_struct("AddRoute")
                .field("destination", destination)
                .field("gateway_present", &gateway.is_some())
                .field("interface_present", &interface.is_some())
                .finish(),
            Self::RemoveRoute {
                destination,
                gateway,
                interface,
            } => formatter
                .debug_struct("RemoveRoute")
                .field("destination", destination)
                .field("gateway_present", &gateway.is_some())
                .field("interface_present", &interface.is_some())
                .finish(),
            Self::SetInterfaceAddress { interface, address } => formatter
                .debug_struct("SetInterfaceAddress")
                .field("interface_len", &interface.len())
                .field("address", address)
                .finish(),
            Self::RemoveInterfaceAddress { interface, address } => formatter
                .debug_struct("RemoveInterfaceAddress")
                .field("interface_len", &interface.len())
                .field("address", address)
                .finish(),
            Self::SetMtu { interface, mtu } => formatter
                .debug_struct("SetMtu")
                .field("interface_len", &interface.len())
                .field("mtu", mtu)
                .finish(),
            Self::ResetMtu { interface } => formatter
                .debug_struct("ResetMtu")
                .field("interface_len", &interface.len())
                .finish(),
            Self::SetDns {
                servers,
                search_domains,
                match_domains,
            } => formatter
                .debug_struct("SetDns")
                .field("servers_len", &servers.len())
                .field("search_domains_len", &search_domains.len())
                .field("match_domains_len", &match_domains.len())
                .finish(),
            Self::ApplyFirewallPolicy {
                policy_id,
                kill_switch_enabled,
            } => formatter
                .debug_struct("ApplyFirewallPolicy")
                .field("policy_id_len", &policy_id.len())
                .field("kill_switch_enabled", kill_switch_enabled)
                .finish(),
            Self::RestoreFirewallSnapshot {
                policy_id,
                kill_switch_enabled,
            } => formatter
                .debug_struct("RestoreFirewallSnapshot")
                .field("policy_id_present", &policy_id.is_some())
                .field("kill_switch_enabled", kill_switch_enabled)
                .finish(),
        }
    }
}

impl NetworkOperationKind {
    pub fn idempotency_scope(&self) -> NetworkOperationIdempotencyScope {
        match self {
            Self::PreserveEndpointRoute { endpoint, .. }
            | Self::RemoveEndpointRoute { endpoint } => {
                NetworkOperationIdempotencyScope::EndpointRoute {
                    endpoint: *endpoint,
                }
            }
            Self::AddRoute { destination, .. } | Self::RemoveRoute { destination, .. } => {
                NetworkOperationIdempotencyScope::Route {
                    destination: destination.clone(),
                }
            }
            Self::SetInterfaceAddress { interface, .. }
            | Self::RemoveInterfaceAddress { interface, .. } => {
                NetworkOperationIdempotencyScope::InterfaceAddress {
                    interface: interface.clone(),
                }
            }
            Self::SetMtu { interface, .. } | Self::ResetMtu { interface } => {
                NetworkOperationIdempotencyScope::InterfaceMtu {
                    interface: interface.clone(),
                }
            }
            Self::SetDns { .. } => NetworkOperationIdempotencyScope::Dns,
            Self::ApplyFirewallPolicy { .. } | Self::RestoreFirewallSnapshot { .. } => {
                NetworkOperationIdempotencyScope::Firewall
            }
        }
    }

    pub fn retry_effect_against(&self, previous: &Self) -> NetworkOperationRetryEffect {
        if self == previous {
            return NetworkOperationRetryEffect::IdempotentRepeat;
        }

        if self.idempotency_scope() == previous.idempotency_scope() {
            NetworkOperationRetryEffect::ConflictingMutation
        } else {
            NetworkOperationRetryEffect::IndependentMutation
        }
    }

    fn validate(&self) -> Result<(), NetworkStateError> {
        match self {
            Self::PreserveEndpointRoute {
                interface,
                endpoint: _,
                gateway: _,
            } => validate_optional_id("operation.interface", interface.as_deref()),
            Self::RemoveEndpointRoute { endpoint: _ } => Ok(()),
            Self::AddRoute {
                destination,
                interface,
                gateway: _,
            }
            | Self::RemoveRoute {
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
            Self::RemoveInterfaceAddress { interface, address } => {
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
            Self::ResetMtu { interface } => validate_id("operation.interface", interface),
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
            Self::RestoreFirewallSnapshot {
                policy_id,
                kill_switch_enabled: _,
            } => validate_optional_id("operation.policy_id", policy_id.as_deref()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRollbackPlan {
    pub required: bool,
    pub inverse: Option<NetworkOperationKind>,
}

impl fmt::Debug for NetworkRollbackPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkRollbackPlan")
            .field("required", &self.required)
            .field("inverse_present", &self.inverse.is_some())
            .finish()
    }
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
            NetworkOperationStatus::Applying
                | NetworkOperationStatus::Applied
                | NetworkOperationStatus::Failed
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

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpNetwork {
    pub address: IpAddr,
    pub prefix: u8,
}

impl fmt::Debug for IpNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpNetwork")
            .field("family", &ip_family(self.address))
            .field("prefix", &self.prefix)
            .finish()
    }
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

fn ip_family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
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

    #[error("duplicate operation apply_order: {apply_order}")]
    DuplicateApplyOrder { apply_order: u32 },

    #[error("operation {operation_key} requires apply_order for deterministic rollback")]
    MissingApplyOrder { operation_key: String },

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

    fn set_mtu_operation(
        key: &str,
        apply_order: u32,
        status: NetworkOperationStatus,
    ) -> AppliedNetworkOperation {
        AppliedNetworkOperation {
            key: key.to_string(),
            apply_order: Some(apply_order),
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

    fn add_route_operation(gateway: IpAddr) -> NetworkOperationKind {
        NetworkOperationKind::AddRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            gateway: Some(gateway),
            interface: Some("utun4".to_string()),
        }
    }

    fn set_dns_operation(server: IpAddr, domain: &str) -> NetworkOperationKind {
        NetworkOperationKind::SetDns {
            servers: vec![server],
            search_domains: vec![domain.to_string()],
            match_domains: vec![],
        }
    }

    fn applied_state() -> AppliedNetworkState {
        AppliedNetworkState {
            transaction_id: "txn-1".to_string(),
            snapshot_id: "snap-1".to_string(),
            platform: PlatformKind::MacOs,
            owner: owner(),
            phase: NetworkTransactionPhase::Applied,
            operations: vec![set_mtu_operation("mtu", 1, NetworkOperationStatus::Applied)],
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
                key: "IpNetwork { family: \"ipv4\", prefix: 0 }|gateway_present=true|interface=Some(3)".to_string(),
            })
        );
    }

    #[test]
    fn debug_redacts_network_identity_values() {
        let mut snapshot = snapshot();
        snapshot.routes[0].gateway = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1)));
        snapshot.dns.servers = vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))];
        snapshot.dns.search_domains = vec!["corp.internal".to_string()];
        snapshot.dns.match_domains = vec!["secret.example".to_string()];

        let mut applied = applied_state();
        applied.operations.push(AppliedNetworkOperation {
            key: "dns".to_string(),
            apply_order: Some(2),
            kind: NetworkOperationKind::SetDns {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))],
                search_domains: vec!["corp.internal".to_string()],
                match_domains: vec!["secret.example".to_string()],
            },
            status: NetworkOperationStatus::Applied,
            rollback: NetworkRollbackPlan {
                required: true,
                inverse: Some(NetworkOperationKind::SetDns {
                    servers: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 7, 53))],
                    search_domains: vec!["home.internal".to_string()],
                    match_domains: vec![],
                }),
            },
        });

        let snapshot_debug = format!("{snapshot:?}");
        let applied_debug = format!("{applied:?}");
        let operation_debug = format!("{:?}", applied.operations[1]);

        for debug_output in [&snapshot_debug, &applied_debug, &operation_debug] {
            assert!(!debug_output.contains("192.168.7.1"));
            assert!(!debug_output.contains("192.168.7.53"));
            assert!(!debug_output.contains("10.13.37.53"));
            assert!(!debug_output.contains("corp.internal"));
            assert!(!debug_output.contains("secret.example"));
            assert!(!debug_output.contains("home.internal"));
        }

        assert!(snapshot_debug.contains("correlation_id: \"req-1\""));
        assert!(applied_debug.contains("correlation_id: \"req-1\""));

        let serialized = serde_json::to_string(&snapshot).expect("snapshot serializes fully");
        assert!(serialized.contains("192.168.7.1"));
        assert!(serialized.contains("10.13.37.53"));
        assert!(serialized.contains("corp.internal"));
    }

    #[test]
    fn duplicate_operation_key_is_rejected() {
        let mut state = applied_state();
        state
            .operations
            .push(set_mtu_operation("mtu", 2, NetworkOperationStatus::Applied));

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::DuplicateKey {
                field: "operations",
                key: "mtu".to_string(),
            })
        );
    }

    #[test]
    fn duplicate_apply_order_is_rejected() {
        let mut state = applied_state();
        state
            .operations
            .push(set_mtu_operation("dns", 1, NetworkOperationStatus::Applied));

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::DuplicateApplyOrder { apply_order: 1 })
        );
    }

    #[test]
    fn applied_operation_requires_apply_order_for_deterministic_rollback() {
        let mut state = applied_state();
        state.operations[0].apply_order = None;

        assert_eq!(
            state.validate(),
            Err(NetworkStateError::MissingApplyOrder {
                operation_key: "mtu".to_string(),
            })
        );
    }

    #[test]
    fn rollback_steps_are_returned_in_reverse_apply_order() {
        let mut state = applied_state();
        state.operations.push(AppliedNetworkOperation {
            key: "dns".to_string(),
            apply_order: Some(2),
            kind: NetworkOperationKind::SetDns {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53))],
                search_domains: vec!["corp.internal".to_string()],
                match_domains: vec![],
            },
            status: NetworkOperationStatus::Applied,
            rollback: NetworkRollbackPlan {
                required: true,
                inverse: Some(NetworkOperationKind::SetDns {
                    servers: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 7, 53))],
                    search_domains: vec!["home.internal".to_string()],
                    match_domains: vec![],
                }),
            },
        });

        let steps = state
            .rollback_steps_reverse_order()
            .expect("valid rollback plan");

        assert_eq!(
            steps
                .iter()
                .map(|step| (step.apply_order, step.operation_key.as_str()))
                .collect::<Vec<_>>(),
            vec![(2, "dns"), (1, "mtu")]
        );

        let debug = format!("{:?}", steps[0]);
        assert!(!debug.contains("10.13.37.53"));
        assert!(!debug.contains("192.168.7.53"));
        assert!(!debug.contains("corp.internal"));
        assert!(!debug.contains("home.internal"));
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
    fn identical_route_commands_are_idempotent_retries() {
        let operation = add_route_operation(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1)));

        assert_eq!(
            operation.retry_effect_against(&operation),
            NetworkOperationRetryEffect::IdempotentRepeat
        );

        let debug = format!("{:?} {:?}", operation, operation.idempotency_scope());
        assert!(!debug.contains("192.168.7.1"));
        assert!(debug.contains("gateway_present: true"));
    }

    #[test]
    fn same_route_scope_with_different_payload_is_conflicting_mutation() {
        let first = add_route_operation(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1)));
        let second = add_route_operation(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 254)));
        let unrelated = NetworkOperationKind::AddRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 32),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
            interface: Some("en0".to_string()),
        };

        assert_eq!(
            second.retry_effect_against(&first),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            unrelated.retry_effect_against(&first),
            NetworkOperationRetryEffect::IndependentMutation
        );
    }

    #[test]
    fn default_route_restore_conflicts_even_when_interface_changes() {
        let tunnel_default = NetworkOperationKind::AddRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            gateway: None,
            interface: Some("utun4".to_string()),
        };
        let restore_physical_default = NetworkOperationKind::AddRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))),
            interface: Some("en0".to_string()),
        };
        let remove_tunnel_default = NetworkOperationKind::RemoveRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            gateway: None,
            interface: Some("utun4".to_string()),
        };
        let unrelated_route = NetworkOperationKind::AddRoute {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            gateway: None,
            interface: Some("utun4".to_string()),
        };

        assert_eq!(
            restore_physical_default.retry_effect_against(&tunnel_default),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            remove_tunnel_default.retry_effect_against(&tunnel_default),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            unrelated_route.retry_effect_against(&tunnel_default),
            NetworkOperationRetryEffect::IndependentMutation
        );

        let debug = format!(
            "{:?} {:?}",
            tunnel_default.idempotency_scope(),
            restore_physical_default.idempotency_scope()
        );
        assert!(!debug.contains("192.168.7.1"));
        assert!(!debug.contains("utun4"));
        assert!(!debug.contains("en0"));
    }

    #[test]
    fn dns_retry_contract_distinguishes_repeats_from_conflicts() {
        let first = set_dns_operation(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 53)), "corp.internal");
        let second = set_dns_operation(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 54)), "corp.internal");

        assert_eq!(
            first.retry_effect_against(&first),
            NetworkOperationRetryEffect::IdempotentRepeat
        );
        assert_eq!(
            second.retry_effect_against(&first),
            NetworkOperationRetryEffect::ConflictingMutation
        );

        let debug = format!("{:?} {:?}", first, first.idempotency_scope());
        assert!(!debug.contains("10.13.37.53"));
        assert!(!debug.contains("corp.internal"));
    }

    #[test]
    fn tunnel_address_and_mtu_retry_contracts_are_interface_scoped() {
        let address = NetworkOperationKind::SetInterfaceAddress {
            interface: "utun4".to_string(),
            address: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 30),
        };
        let other_address = NetworkOperationKind::SetInterfaceAddress {
            interface: "utun4".to_string(),
            address: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 6)), 30),
        };
        let remove_address = NetworkOperationKind::RemoveInterfaceAddress {
            interface: "utun4".to_string(),
            address: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 30),
        };
        let mtu = NetworkOperationKind::SetMtu {
            interface: "utun4".to_string(),
            mtu: 1280,
        };
        let other_mtu = NetworkOperationKind::SetMtu {
            interface: "utun4".to_string(),
            mtu: 1400,
        };
        let reset_mtu = NetworkOperationKind::ResetMtu {
            interface: "utun4".to_string(),
        };

        assert_eq!(
            address.retry_effect_against(&address),
            NetworkOperationRetryEffect::IdempotentRepeat
        );
        assert_eq!(
            other_address.retry_effect_against(&address),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            remove_address.retry_effect_against(&address),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            mtu.retry_effect_against(&mtu),
            NetworkOperationRetryEffect::IdempotentRepeat
        );
        assert_eq!(
            other_mtu.retry_effect_against(&mtu),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            reset_mtu.retry_effect_against(&mtu),
            NetworkOperationRetryEffect::ConflictingMutation
        );
    }

    #[test]
    fn firewall_retry_contract_distinguishes_repeats_from_conflicts() {
        let policy = NetworkOperationKind::ApplyFirewallPolicy {
            policy_id: "novaray-full-tunnel".to_string(),
            kill_switch_enabled: true,
        };
        let changed_policy = NetworkOperationKind::ApplyFirewallPolicy {
            policy_id: "novaray-full-tunnel".to_string(),
            kill_switch_enabled: false,
        };
        let restore = NetworkOperationKind::RestoreFirewallSnapshot {
            policy_id: Some("pf-baseline".to_string()),
            kill_switch_enabled: false,
        };

        assert_eq!(
            policy.retry_effect_against(&policy),
            NetworkOperationRetryEffect::IdempotentRepeat
        );
        assert_eq!(
            changed_policy.retry_effect_against(&policy),
            NetworkOperationRetryEffect::ConflictingMutation
        );
        assert_eq!(
            restore.retry_effect_against(&policy),
            NetworkOperationRetryEffect::ConflictingMutation
        );
    }

    #[test]
    fn rollback_inverse_commands_are_idempotent_retries() {
        let operations = [
            NetworkOperationKind::RemoveEndpointRoute {
                endpoint: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            },
            NetworkOperationKind::RemoveRoute {
                destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                gateway: None,
                interface: Some("utun4".to_string()),
            },
            NetworkOperationKind::RemoveInterfaceAddress {
                interface: "utun4".to_string(),
                address: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 30),
            },
            NetworkOperationKind::ResetMtu {
                interface: "utun4".to_string(),
            },
            NetworkOperationKind::SetDns {
                servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
                search_domains: vec!["example.test".to_string()],
                match_domains: vec![],
            },
            NetworkOperationKind::RestoreFirewallSnapshot {
                policy_id: None,
                kill_switch_enabled: false,
            },
        ];

        for operation in operations {
            assert_eq!(
                operation.retry_effect_against(&operation),
                NetworkOperationRetryEffect::IdempotentRepeat,
                "{operation:?}"
            );
        }
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
        state.operations.push(set_mtu_operation(
            "mtu2",
            2,
            NetworkOperationStatus::Applied,
        ));

        let counts = group_operations_by_status(&state);
        assert_eq!(counts.get(&NetworkOperationStatus::Applied), Some(&2));
    }
}
