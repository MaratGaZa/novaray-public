//! Pure connect transaction planner.
//!
//! This module turns a typed full-tunnel connect intent into an ordered network transaction plan.
//! It does not create interfaces, open sockets, call helpers, run as root, or mutate routes, DNS,
//! firewall, system proxy, or packet-flow state.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::network_state::{
    AppliedNetworkOperation, AppliedNetworkState, DnsSnapshot, IpNetwork, NetworkOperationKind,
    NetworkOperationStatus, NetworkRollbackPlan, NetworkSnapshot, NetworkStateError,
    NetworkStateOwner, NetworkTransactionPhase, RouteSnapshot,
};

const KEY_PRESERVE_ENDPOINT_ROUTE: &str = "001_preserve_endpoint_route";
const KEY_SET_TUNNEL_ADDRESS: &str = "002_set_tunnel_address";
const KEY_SET_TUNNEL_MTU: &str = "003_set_tunnel_mtu";
const KEY_ROUTE_FULL_TUNNEL: &str = "004_route_full_tunnel";
const KEY_SET_DNS: &str = "005_set_dns";
const KEY_APPLY_FIREWALL: &str = "006_apply_firewall";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectNetworkIntent {
    pub transaction_id: String,
    pub owner: NetworkStateOwner,
    pub endpoint: IpAddr,
    pub endpoint_gateway: Option<IpAddr>,
    pub endpoint_interface: Option<String>,
    pub tunnel_interface: String,
    pub tunnel_address: IpNetwork,
    pub tunnel_mtu: u32,
    pub dns: DnsSnapshot,
    pub firewall_policy_id: String,
    pub kill_switch_enabled: bool,
}

impl fmt::Debug for ConnectNetworkIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectNetworkIntent")
            .field("transaction_id", &self.transaction_id)
            .field("owner", &self.owner)
            .field("endpoint_family", &ip_family(self.endpoint))
            .field("endpoint_gateway_present", &self.endpoint_gateway.is_some())
            .field("endpoint_interface", &self.endpoint_interface)
            .field("tunnel_interface", &self.tunnel_interface)
            .field("tunnel_address", &self.tunnel_address)
            .field("tunnel_mtu", &self.tunnel_mtu)
            .field("dns", &self.dns)
            .field("firewall_policy_id_len", &self.firewall_policy_id.len())
            .field("kill_switch_enabled", &self.kill_switch_enabled)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConnectNetworkTransactionPlanner;

impl ConnectNetworkTransactionPlanner {
    pub fn plan(
        snapshot: &NetworkSnapshot,
        intent: ConnectNetworkIntent,
    ) -> Result<AppliedNetworkState, NetworkStateError> {
        let operations = vec![
            operation(
                KEY_PRESERVE_ENDPOINT_ROUTE,
                1,
                NetworkOperationKind::PreserveEndpointRoute {
                    endpoint: intent.endpoint,
                    gateway: intent.endpoint_gateway,
                    interface: intent.endpoint_interface.clone(),
                },
                endpoint_route_inverse(snapshot, intent.endpoint),
            ),
            operation(
                KEY_SET_TUNNEL_ADDRESS,
                2,
                NetworkOperationKind::SetInterfaceAddress {
                    interface: intent.tunnel_interface.clone(),
                    address: intent.tunnel_address.clone(),
                },
                NetworkOperationKind::RemoveInterfaceAddress {
                    interface: intent.tunnel_interface.clone(),
                    address: intent.tunnel_address.clone(),
                },
            ),
            operation(
                KEY_SET_TUNNEL_MTU,
                3,
                NetworkOperationKind::SetMtu {
                    interface: intent.tunnel_interface.clone(),
                    mtu: intent.tunnel_mtu,
                },
                mtu_inverse(snapshot, &intent.tunnel_interface),
            ),
            operation(
                KEY_ROUTE_FULL_TUNNEL,
                4,
                NetworkOperationKind::AddRoute {
                    destination: default_route_for(intent.tunnel_address.address),
                    gateway: None,
                    interface: Some(intent.tunnel_interface.clone()),
                },
                default_route_inverse(
                    snapshot,
                    intent.tunnel_address.address,
                    &intent.tunnel_interface,
                ),
            ),
            operation(
                KEY_SET_DNS,
                5,
                NetworkOperationKind::SetDns {
                    servers: intent.dns.servers.clone(),
                    search_domains: intent.dns.search_domains.clone(),
                    match_domains: intent.dns.match_domains.clone(),
                },
                NetworkOperationKind::SetDns {
                    servers: snapshot.dns.servers.clone(),
                    search_domains: snapshot.dns.search_domains.clone(),
                    match_domains: snapshot.dns.match_domains.clone(),
                },
            ),
            operation(
                KEY_APPLY_FIREWALL,
                6,
                NetworkOperationKind::ApplyFirewallPolicy {
                    policy_id: intent.firewall_policy_id,
                    kill_switch_enabled: intent.kill_switch_enabled,
                },
                NetworkOperationKind::RestoreFirewallSnapshot {
                    policy_id: snapshot.firewall.policy_id.clone(),
                    kill_switch_enabled: snapshot.firewall.kill_switch_enabled,
                },
            ),
        ];

        let state = AppliedNetworkState {
            transaction_id: intent.transaction_id,
            snapshot_id: snapshot.snapshot_id.clone(),
            platform: snapshot.platform,
            owner: intent.owner,
            phase: NetworkTransactionPhase::Planned,
            operations,
            last_error: None,
        };
        state.validate()?;
        Ok(state)
    }
}

fn operation(
    key: &'static str,
    apply_order: u32,
    kind: NetworkOperationKind,
    inverse: NetworkOperationKind,
) -> AppliedNetworkOperation {
    AppliedNetworkOperation {
        key: key.to_string(),
        apply_order: Some(apply_order),
        kind,
        status: NetworkOperationStatus::Planned,
        rollback: NetworkRollbackPlan {
            required: true,
            inverse: Some(inverse),
        },
    }
}

fn endpoint_route_inverse(snapshot: &NetworkSnapshot, endpoint: IpAddr) -> NetworkOperationKind {
    match find_exact_endpoint_route(snapshot, endpoint) {
        Some(route) => NetworkOperationKind::PreserveEndpointRoute {
            endpoint,
            gateway: route.gateway,
            interface: route.interface.clone(),
        },
        None => NetworkOperationKind::RemoveEndpointRoute { endpoint },
    }
}

fn default_route_inverse(
    snapshot: &NetworkSnapshot,
    tunnel_address: IpAddr,
    tunnel_interface: &str,
) -> NetworkOperationKind {
    let destination = default_route_for(tunnel_address);
    match find_default_route(snapshot, tunnel_address) {
        Some(route) => NetworkOperationKind::AddRoute {
            destination,
            gateway: route.gateway,
            interface: route.interface.clone(),
        },
        None => NetworkOperationKind::RemoveRoute {
            destination,
            gateway: None,
            interface: Some(tunnel_interface.to_string()),
        },
    }
}

fn default_route_for(address: IpAddr) -> IpNetwork {
    match address {
        IpAddr::V4(_) => IpNetwork::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => IpNetwork::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn find_default_route(snapshot: &NetworkSnapshot, address: IpAddr) -> Option<&RouteSnapshot> {
    let expected_address = default_route_for(address).address;
    snapshot.routes.iter().find(|route| {
        route.destination.address == expected_address && route.destination.prefix == 0
    })
}

fn find_exact_endpoint_route(
    snapshot: &NetworkSnapshot,
    endpoint: IpAddr,
) -> Option<&RouteSnapshot> {
    let expected_prefix = match endpoint {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    snapshot.routes.iter().find(|route| {
        route.destination.address == endpoint && route.destination.prefix == expected_prefix
    })
}

fn mtu_inverse(snapshot: &NetworkSnapshot, interface: &str) -> NetworkOperationKind {
    snapshot
        .interfaces
        .iter()
        .find(|candidate| candidate.name == interface)
        .and_then(|candidate| candidate.mtu)
        .map_or_else(
            || NetworkOperationKind::ResetMtu {
                interface: interface.to_string(),
            },
            |mtu| NetworkOperationKind::SetMtu {
                interface: interface.to_string(),
                mtu,
            },
        )
}

fn ip_family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::network_state::{
        FirewallSnapshot, NetworkInterfaceSnapshot, NetworkRollbackPlan, RouteSnapshot,
    };
    use crate::platform_contract::PlatformKind;

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
                name: "utun9".to_string(),
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
                policy_id: Some("baseline-pf".to_string()),
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
            tunnel_interface: "utun9".to_string(),
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

    #[test]
    fn full_tunnel_connect_intent_produces_deterministic_ordered_plan() {
        let plan =
            ConnectNetworkTransactionPlanner::plan(&snapshot(), intent()).expect("valid plan");

        assert_eq!(plan.phase, NetworkTransactionPhase::Planned);
        assert_eq!(plan.snapshot_id, "snap-1");
        assert_eq!(
            plan.operations
                .iter()
                .map(|operation| (operation.apply_order, operation.key.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (Some(1), KEY_PRESERVE_ENDPOINT_ROUTE),
                (Some(2), KEY_SET_TUNNEL_ADDRESS),
                (Some(3), KEY_SET_TUNNEL_MTU),
                (Some(4), KEY_ROUTE_FULL_TUNNEL),
                (Some(5), KEY_SET_DNS),
                (Some(6), KEY_APPLY_FIREWALL),
            ]
        );

        assert!(matches!(
            plan.operations[3].kind,
            NetworkOperationKind::AddRoute {
                destination: IpNetwork {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix: 0,
                },
                gateway: None,
                interface: Some(_),
            }
        ));

        for operation in &plan.operations {
            assert_eq!(operation.status, NetworkOperationStatus::Planned);
            assert!(operation.rollback.required);
            assert!(operation.rollback.inverse.is_some());
        }
    }

    #[test]
    fn plan_can_feed_reverse_rollback_order_after_operations_are_applied() {
        let mut plan =
            ConnectNetworkTransactionPlanner::plan(&snapshot(), intent()).expect("valid plan");
        plan.phase = NetworkTransactionPhase::Applied;
        for operation in &mut plan.operations {
            operation.status = NetworkOperationStatus::Applied;
        }

        let steps = plan
            .rollback_steps_reverse_order()
            .expect("rollback steps from planned metadata");

        assert_eq!(
            steps
                .iter()
                .map(|step| (step.apply_order, step.operation_key.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (6, KEY_APPLY_FIREWALL),
                (5, KEY_SET_DNS),
                (4, KEY_ROUTE_FULL_TUNNEL),
                (3, KEY_SET_TUNNEL_MTU),
                (2, KEY_SET_TUNNEL_ADDRESS),
                (1, KEY_PRESERVE_ENDPOINT_ROUTE),
            ]
        );
    }

    #[test]
    fn endpoint_route_without_existing_snapshot_route_rolls_back_by_removal() {
        let mut snapshot = snapshot();
        snapshot.routes.clear();

        let plan = ConnectNetworkTransactionPlanner::plan(&snapshot, intent()).expect("valid plan");

        assert!(matches!(
            plan.operations[0].rollback,
            NetworkRollbackPlan {
                inverse: Some(NetworkOperationKind::RemoveEndpointRoute { .. }),
                ..
            }
        ));
    }

    #[test]
    fn missing_default_route_rolls_back_by_removal() {
        let mut snapshot = snapshot();
        snapshot
            .routes
            .retain(|route| route.destination.prefix != 0);

        let plan = ConnectNetworkTransactionPlanner::plan(&snapshot, intent()).expect("valid plan");

        assert!(matches!(
            plan.operations[3].rollback,
            NetworkRollbackPlan {
                inverse: Some(NetworkOperationKind::RemoveRoute {
                    destination: IpNetwork {
                        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        prefix: 0,
                    },
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn invalid_identifiers_fail_closed_via_state_validation() {
        let mut intent = intent();
        intent.transaction_id = "txn\nspoof".to_string();

        assert_eq!(
            ConnectNetworkTransactionPlanner::plan(&snapshot(), intent),
            Err(NetworkStateError::InvalidId {
                field: "transaction_id"
            })
        );
    }

    #[test]
    fn debug_output_redacts_network_identity_values() {
        let snapshot = snapshot();
        let intent = intent();
        let intent_debug = format!("{intent:?}");
        let plan = ConnectNetworkTransactionPlanner::plan(&snapshot, intent).expect("valid plan");
        let plan_debug = format!("{plan:?}");
        let operation_debug = format!("{:?}", plan.operations);

        for output in [&intent_debug, &plan_debug, &operation_debug] {
            assert!(!output.contains("192.168.7.1"));
            assert!(!output.contains("10.13.37.53"));
            assert!(!output.contains("198.51.100.53"));
            assert!(!output.contains("corp.internal"));
            assert!(!output.contains("vpn.internal"));
        }

        assert!(intent_debug.contains("endpoint_family: \"ipv4\""));
        assert!(plan_debug.contains("operations_len: 6"));
    }
}
