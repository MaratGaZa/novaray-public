//! Preparatory outbound IP allowlist, without packet capture, routing or firewall enforcement.
//!
//! Interface names must eventually be resolved and verified by a platform adapter. This matcher
//! cannot authenticate an interface supplied by a caller. Bootstrap and inbound rules are absent.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

const MAX_INTERFACE_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelIpFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for TunnelIpFamily {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// The destination port is meaningful only for TCP/UDP. Other IP protocols may use the tunnel,
/// but never receive an implicit uplink exception.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EgressTransport {
    Tcp { destination_port: u16 },
    Udp { destination_port: u16 },
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    AllowEndpoint,
    AllowTunnel,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KillSwitchPolicyError {
    #[error("kill-switch allowlist requires an enabled kill switch")]
    Disabled,
    #[error("kill-switch allowlist requires an explicit endpoint interface")]
    MissingEndpointInterface,
    #[error("kill-switch allowlist requires an exact bounded ASCII interface name")]
    InvalidInterface,
    #[error("kill-switch uplink and tunnel interfaces must be distinct")]
    SameInterface,
    #[error("kill-switch endpoint address is unsupported")]
    InvalidEndpoint,
    #[error("kill-switch endpoint port must be non-zero")]
    InvalidPort,
}

/// Validated and immutable. No deserializer or public fields can bypass construction checks.
#[derive(Clone, PartialEq, Eq)]
pub struct KillSwitchAllowlist {
    endpoint: SocketAddr,
    endpoint_transport: EndpointTransport,
    uplink_interface: String,
    tunnel_interface: String,
    tunnel_family: TunnelIpFamily,
}

impl fmt::Debug for KillSwitchAllowlist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KillSwitchAllowlist")
            .field("endpoint", &"<redacted>")
            .field("endpoint_transport", &self.endpoint_transport)
            .field("uplink_interface", &"<redacted>")
            .field("tunnel_interface", &"<redacted>")
            .field("tunnel_family", &self.tunnel_family)
            .finish()
    }
}

impl KillSwitchAllowlist {
    pub fn new(
        endpoint: SocketAddr,
        endpoint_transport: EndpointTransport,
        uplink_interface: String,
        tunnel_interface: String,
        tunnel_family: TunnelIpFamily,
    ) -> Result<Self, KillSwitchPolicyError> {
        for interface in [&uplink_interface, &tunnel_interface] {
            if interface.is_empty()
                || interface.len() > MAX_INTERFACE_NAME_BYTES
                || !interface
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(KillSwitchPolicyError::InvalidInterface);
            }
        }
        if uplink_interface == tunnel_interface {
            return Err(KillSwitchPolicyError::SameInterface);
        }
        if !supported_unicast(endpoint.ip())
            || matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0)
        {
            return Err(KillSwitchPolicyError::InvalidEndpoint);
        }
        if endpoint.port() == 0 {
            return Err(KillSwitchPolicyError::InvalidPort);
        }
        Ok(Self {
            endpoint,
            endpoint_transport,
            uplink_interface,
            tunnel_interface,
            tunnel_family,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn endpoint_transport(&self) -> EndpointTransport {
        self.endpoint_transport
    }

    pub fn uplink_interface(&self) -> &str {
        &self.uplink_interface
    }

    pub fn tunnel_interface(&self) -> &str {
        &self.tunnel_interface
    }

    pub fn tunnel_family(&self) -> TunnelIpFamily {
        self.tunnel_family
    }

    pub fn classify_egress(
        &self,
        interface: &str,
        destination: IpAddr,
        transport: EgressTransport,
    ) -> EgressDecision {
        if !supported_unicast(destination)
            || matches!(
                transport,
                EgressTransport::Tcp {
                    destination_port: 0
                } | EgressTransport::Udp {
                    destination_port: 0
                }
            )
        {
            return EgressDecision::Deny;
        }
        if interface == self.tunnel_interface
            && TunnelIpFamily::from(destination) == self.tunnel_family
        {
            return EgressDecision::AllowTunnel;
        }
        if interface == self.uplink_interface && destination == self.endpoint.ip() {
            let port = match (self.endpoint_transport, transport) {
                (EndpointTransport::Tcp, EgressTransport::Tcp { destination_port })
                | (EndpointTransport::Udp, EgressTransport::Udp { destination_port }) => {
                    Some(destination_port)
                }
                _ => None,
            };
            if port == Some(self.endpoint.port()) {
                return EgressDecision::AllowEndpoint;
            }
        }
        EgressDecision::Deny
    }
}

fn supported_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
                && address.to_ipv4_mapped().is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn policy(
        endpoint: &str,
        transport: EndpointTransport,
        family: TunnelIpFamily,
    ) -> KillSwitchAllowlist {
        KillSwitchAllowlist::new(
            SocketAddr::new(ip(endpoint), 443),
            transport,
            "en0".into(),
            "utun4".into(),
            family,
        )
        .unwrap()
    }

    #[test]
    fn uplink_requires_exact_endpoint_port_transport_and_interface() {
        for endpoint in ["192.0.2.10", "2001:db8::10"] {
            for expected_transport in [EndpointTransport::Tcp, EndpointTransport::Udp] {
                let policy = policy(endpoint, expected_transport, TunnelIpFamily::Ipv4);
                for interface in ["en0", "en1", "en00", "EN0", "*", ""] {
                    for destination in [ip(endpoint), ip("198.51.100.20"), ip("2001:db8::20")] {
                        for port in [0, 53, 443, 8443] {
                            for (actual_transport, flow) in [
                                (
                                    EndpointTransport::Tcp,
                                    EgressTransport::Tcp {
                                        destination_port: port,
                                    },
                                ),
                                (
                                    EndpointTransport::Udp,
                                    EgressTransport::Udp {
                                        destination_port: port,
                                    },
                                ),
                            ] {
                                let expected = if interface == "en0"
                                    && destination == ip(endpoint)
                                    && port == 443
                                    && actual_transport == expected_transport
                                {
                                    EgressDecision::AllowEndpoint
                                } else {
                                    EgressDecision::Deny
                                };
                                assert_eq!(
                                    policy.classify_egress(interface, destination, flow),
                                    expected
                                );
                            }
                        }
                    }
                }
                assert_eq!(
                    policy.classify_egress("en0", ip(endpoint), EgressTransport::Other),
                    EgressDecision::Deny
                );
            }
        }
    }

    #[test]
    fn tunnel_permission_is_bound_to_interface_and_single_ip_family() {
        for family in [TunnelIpFamily::Ipv4, TunnelIpFamily::Ipv6] {
            let policy = policy("192.0.2.10", EndpointTransport::Tcp, family);
            for interface in ["utun4", "utun5", "en0"] {
                for destination in [ip("198.51.100.20"), ip("2001:db8::20")] {
                    for flow in [
                        EgressTransport::Tcp {
                            destination_port: 80,
                        },
                        EgressTransport::Udp {
                            destination_port: 53,
                        },
                        EgressTransport::Other,
                    ] {
                        let expected = if interface == "utun4"
                            && TunnelIpFamily::from(destination) == family
                        {
                            EgressDecision::AllowTunnel
                        } else {
                            EgressDecision::Deny
                        };
                        assert_eq!(
                            policy.classify_egress(interface, destination, flow),
                            expected
                        );
                    }
                }
            }
            assert_eq!(
                policy.classify_egress(
                    "utun4",
                    ip("198.51.100.20"),
                    EgressTransport::Tcp {
                        destination_port: 0
                    }
                ),
                EgressDecision::Deny
            );
        }
    }

    #[test]
    fn no_implicit_direct_dns_dhcp_ndp_lan_or_update_exceptions() {
        let policy = policy("192.0.2.10", EndpointTransport::Tcp, TunnelIpFamily::Ipv4);
        for destination in [
            "192.0.2.53",
            "10.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "fe80::1",
            "198.51.100.20",
        ] {
            for port in [53, 67, 68, 80, 443, 546, 547] {
                for flow in [
                    EgressTransport::Tcp {
                        destination_port: port,
                    },
                    EgressTransport::Udp {
                        destination_port: port,
                    },
                ] {
                    assert_eq!(
                        policy.classify_egress("en0", ip(destination), flow),
                        EgressDecision::Deny
                    );
                }
            }
        }
        assert_eq!(
            policy.classify_egress(
                "utun4",
                ip("192.0.2.53"),
                EgressTransport::Udp {
                    destination_port: 53
                }
            ),
            EgressDecision::AllowTunnel
        );
    }

    #[test]
    fn invalid_destinations_fail_construction_and_classification() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "::",
            "::1",
            "ff02::1",
            "fe80::1",
            "::ffff:192.0.2.10",
        ] {
            let destination = ip(address);
            assert_eq!(
                KillSwitchAllowlist::new(
                    SocketAddr::new(destination, 443),
                    EndpointTransport::Tcp,
                    "en0".into(),
                    "utun4".into(),
                    TunnelIpFamily::from(destination)
                ),
                Err(KillSwitchPolicyError::InvalidEndpoint)
            );
            let policy = policy(
                "192.0.2.10",
                EndpointTransport::Tcp,
                TunnelIpFamily::from(destination),
            );
            for interface in ["en0", "utun4"] {
                assert_eq!(
                    policy.classify_egress(interface, destination, EgressTransport::Other),
                    EgressDecision::Deny
                );
            }
        }
        for (flowinfo, scope_id) in [(1, 0), (0, 1)] {
            let endpoint = SocketAddr::V6(std::net::SocketAddrV6::new(
                "2001:db8::10".parse().unwrap(),
                443,
                flowinfo,
                scope_id,
            ));
            assert_eq!(
                KillSwitchAllowlist::new(
                    endpoint,
                    EndpointTransport::Tcp,
                    "en0".into(),
                    "utun4".into(),
                    TunnelIpFamily::Ipv6
                ),
                Err(KillSwitchPolicyError::InvalidEndpoint)
            );
        }
    }

    #[test]
    fn invalid_interfaces_and_zero_port_are_rejected() {
        let endpoint = SocketAddr::new(ip("192.0.2.10"), 443);
        for invalid in [
            "",
            "*",
            "en*",
            "en 0",
            "en0\n",
            "en0/utun4",
            "\u{00e9}",
            &"x".repeat(65),
        ] {
            for (uplink, tunnel) in [(invalid, "utun4"), ("en0", invalid)] {
                assert_eq!(
                    KillSwitchAllowlist::new(
                        endpoint,
                        EndpointTransport::Tcp,
                        uplink.into(),
                        tunnel.into(),
                        TunnelIpFamily::Ipv4
                    ),
                    Err(KillSwitchPolicyError::InvalidInterface)
                );
            }
        }
        assert!(KillSwitchAllowlist::new(
            endpoint,
            EndpointTransport::Tcp,
            "x".repeat(64),
            "utun4".into(),
            TunnelIpFamily::Ipv4
        )
        .is_ok());
        assert_eq!(
            KillSwitchAllowlist::new(
                endpoint,
                EndpointTransport::Tcp,
                "en0".into(),
                "en0".into(),
                TunnelIpFamily::Ipv4
            ),
            Err(KillSwitchPolicyError::SameInterface)
        );
        assert_eq!(
            KillSwitchAllowlist::new(
                SocketAddr::new(endpoint.ip(), 0),
                EndpointTransport::Tcp,
                "en0".into(),
                "utun4".into(),
                TunnelIpFamily::Ipv4
            ),
            Err(KillSwitchPolicyError::InvalidPort)
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_endpoint_or_interface_values() {
        let policy = policy("192.0.2.10", EndpointTransport::Tcp, TunnelIpFamily::Ipv4);
        let debug = format!("{policy:?}");
        for secret in ["192.0.2.10", "443", "en0", "utun4"] {
            assert!(!debug.contains(secret));
        }
        let error = KillSwitchAllowlist::new(
            policy.endpoint(),
            EndpointTransport::Tcp,
            "private-interface\n".into(),
            "utun4".into(),
            TunnelIpFamily::Ipv4,
        )
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-interface"));
    }
}
