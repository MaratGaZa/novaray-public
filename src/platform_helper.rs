//! Side-effect-free macOS platform helper skeleton.
//!
//! This module wires the existing typed platform contract into a helper-style runtime harness. It
//! does not install launchd jobs, open IPC sockets, run as root, create `utun`, execute shell
//! commands, or mutate routes, DNS, firewall, system proxy or packet-flow state.

use std::fmt;

use crate::platform_contract::{
    validate_helper_command, HelperHello, PlatformCapability, PlatformContractError,
    PlatformHelperCommand, PlatformHelperEvent, PlatformHelperStatus, PlatformKind,
    PlatformObservedState, CURRENT_PLATFORM_CONTRACT_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformHelperExitCode {
    Success = 0,
    Usage = 2,
    Rejected = 3,
    IoError = 4,
    InternalError = 5,
}

impl PlatformHelperExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PlatformHelperRunResult {
    pub exit_code: PlatformHelperExitCode,
    pub event: PlatformHelperEvent,
}

impl fmt::Debug for PlatformHelperRunResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformHelperRunResult")
            .field("exit_code", &self.exit_code)
            .field("event", &self.event)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsPlatformHelperSkeleton {
    hello: HelperHello,
}

impl Default for MacOsPlatformHelperSkeleton {
    fn default() -> Self {
        Self {
            hello: default_helper_hello(),
        }
    }
}

impl MacOsPlatformHelperSkeleton {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hello(&self) -> &HelperHello {
        &self.hello
    }

    pub fn handle_command(
        &self,
        command: PlatformHelperCommand,
    ) -> Result<PlatformHelperEvent, PlatformContractError> {
        validate_helper_command(&command, &self.hello)?;
        Ok(match command {
            PlatformHelperCommand::Handshake(_) => {
                PlatformHelperEvent::HandshakeAccepted(self.hello.clone())
            }
            PlatformHelperCommand::Status => {
                PlatformHelperEvent::Status(self.status(PlatformObservedState::Idle))
            }
            PlatformHelperCommand::PrepareTunnel(_) => {
                PlatformHelperEvent::Status(self.status(PlatformObservedState::Preparing))
            }
            PlatformHelperCommand::Disconnect { .. } => {
                PlatformHelperEvent::Status(self.status(PlatformObservedState::Idle))
            }
            PlatformHelperCommand::Recover { .. } => {
                PlatformHelperEvent::Status(self.status(PlatformObservedState::Recovering))
            }
        })
    }

    fn status(&self, observed_state: PlatformObservedState) -> PlatformHelperStatus {
        PlatformHelperStatus {
            protocol_version: self.hello.protocol_version,
            platform: self.hello.platform,
            capabilities: self.hello.capabilities.clone(),
            observed_state,
        }
    }
}

pub fn default_helper_hello() -> HelperHello {
    HelperHello {
        protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
        platform: PlatformKind::MacOs,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            PlatformCapability::Tun,
            PlatformCapability::Ipv4,
            PlatformCapability::Ipv6,
            PlatformCapability::Dns,
            PlatformCapability::Firewall,
            PlatformCapability::KillSwitch,
            PlatformCapability::RecoveryJournal,
        ],
    }
}

pub fn run_helper_once(input: &[u8]) -> PlatformHelperRunResult {
    let helper = MacOsPlatformHelperSkeleton::new();
    let command = match serde_json::from_slice::<PlatformHelperCommand>(input) {
        Ok(command) => command,
        Err(error) => {
            return rejected(format!("invalid helper command JSON: {error}"));
        }
    };

    match helper.handle_command(command) {
        Ok(event) => PlatformHelperRunResult {
            exit_code: PlatformHelperExitCode::Success,
            event,
        },
        Err(error) => rejected(error.to_string()),
    }
}

fn rejected(reason: String) -> PlatformHelperRunResult {
    PlatformHelperRunResult {
        exit_code: PlatformHelperExitCode::Rejected,
        event: PlatformHelperEvent::CommandRejected(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform_contract::{CoreHello, TunnelCommandPayload, MAX_PLATFORM_MESSAGE_BYTES};

    #[test]
    fn valid_handshake_roundtrip_succeeds() {
        let command = PlatformHelperCommand::Handshake(CoreHello {
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Dns],
            ..Default::default()
        });
        let input = serde_json::to_vec(&command).expect("serialize command");

        let result = run_helper_once(&input);

        assert_eq!(result.exit_code, PlatformHelperExitCode::Success);
        assert!(matches!(
            result.event,
            PlatformHelperEvent::HandshakeAccepted(HelperHello {
                platform: PlatformKind::MacOs,
                ..
            })
        ));
    }

    #[test]
    fn valid_prepare_command_is_dry_run_only_status_transition() {
        let command = PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
            correlation_id: "connect-1".to_string(),
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Dns],
            engine_config_json:
                br#"{"uuid":"00000000-0000-4000-8000-000000000001","server":"example.com"}"#
                    .to_vec(),
        });
        let input = serde_json::to_vec(&command).expect("serialize command");

        let result = run_helper_once(&input);

        assert_eq!(result.exit_code, PlatformHelperExitCode::Success);
        assert_eq!(
            result.event,
            PlatformHelperEvent::Status(PlatformHelperStatus {
                protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
                platform: PlatformKind::MacOs,
                capabilities: default_helper_hello().capabilities,
                observed_state: PlatformObservedState::Preparing,
            })
        );
        let debug = format!("{result:?}");
        assert!(!debug.contains("00000000-0000-4000-8000-000000000001"));
        assert!(!debug.contains("example.com"));
    }

    #[test]
    fn invalid_json_unknown_fields_and_unsupported_versions_fail_closed() {
        let invalid_json = run_helper_once(br#"{"type":"status","payload":null,"extra":true}"#);
        assert_eq!(invalid_json.exit_code, PlatformHelperExitCode::Rejected);
        assert!(matches!(
            invalid_json.event,
            PlatformHelperEvent::CommandRejected(ref reason)
                if reason.contains("invalid helper command JSON")
        ));

        let incompatible = PlatformHelperCommand::Handshake(CoreHello {
            protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
            min_supported_protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION + 1,
            required_capabilities: vec![],
        });
        let result = run_helper_once(&serde_json::to_vec(&incompatible).expect("serialize"));
        assert_eq!(result.exit_code, PlatformHelperExitCode::Rejected);
        assert!(matches!(
            result.event,
            PlatformHelperEvent::CommandRejected(ref reason)
                if reason.contains("Несовместимая версия platform helper contract")
        ));
    }

    #[test]
    fn oversized_prepare_command_fails_before_execution() {
        let command = PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
            correlation_id: "connect-1".to_string(),
            required_capabilities: vec![PlatformCapability::Tun],
            engine_config_json: vec![b'x'; MAX_PLATFORM_MESSAGE_BYTES + 1],
        });

        let result = run_helper_once(&serde_json::to_vec(&command).expect("serialize"));

        assert_eq!(result.exit_code, PlatformHelperExitCode::Rejected);
        assert!(matches!(
            result.event,
            PlatformHelperEvent::CommandRejected(ref reason)
                if reason.contains("payload превышает лимит")
        ));
    }
}
