//! Typed platform helper contract shared by core and future privileged boundaries.
//!
//! This module models protocol handshake, capabilities and command validation only.
//! It does not open sockets, install helpers, run as root or mutate routes/DNS/firewall state.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CURRENT_PLATFORM_CONTRACT_VERSION: u16 = 1;
pub const MIN_PLATFORM_CONTRACT_VERSION: u16 = 1;
pub const MAX_PLATFORM_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_PLATFORM_CAPABILITIES: usize = 32;
pub const MAX_CORRELATION_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    MacOs,
    Windows,
    Android,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformCapability {
    Tun,
    Ipv4,
    Ipv6,
    Dns,
    Firewall,
    KillSwitch,
    PerAppRouting,
    RecoveryJournal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperHello {
    pub protocol_version: u16,
    pub platform: PlatformKind,
    pub app_version: String,
    pub capabilities: Vec<PlatformCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreHello {
    pub protocol_version: u16,
    pub min_supported_protocol_version: u16,
    pub required_capabilities: Vec<PlatformCapability>,
}

impl Default for CoreHello {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
            min_supported_protocol_version: MIN_PLATFORM_CONTRACT_VERSION,
            required_capabilities: vec![],
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelCommandPayload {
    pub correlation_id: String,
    pub required_capabilities: Vec<PlatformCapability>,
    pub engine_config_json: Vec<u8>,
}

impl fmt::Debug for TunnelCommandPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelCommandPayload")
            .field("correlation_id", &self.correlation_id)
            .field("required_capabilities", &self.required_capabilities)
            .field("engine_config_json_len", &self.engine_config_json.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PlatformHelperCommand {
    Handshake(CoreHello),
    Status,
    PrepareTunnel(TunnelCommandPayload),
    Disconnect { correlation_id: String },
    Recover { correlation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PlatformHelperEvent {
    HandshakeAccepted(HelperHello),
    Status(PlatformHelperStatus),
    CommandRejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformHelperStatus {
    pub protocol_version: u16,
    pub platform: PlatformKind,
    pub capabilities: Vec<PlatformCapability>,
    pub observed_state: PlatformObservedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformObservedState {
    Idle,
    Preparing,
    Connected,
    Disconnecting,
    Recovering,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlatformContractError {
    #[error("Несовместимая версия platform helper contract: core поддерживает {min_supported}-{current}, helper сообщил {actual}")]
    IncompatibleProtocolVersion {
        min_supported: u16,
        current: u16,
        actual: u16,
    },

    #[error("Platform helper не объявил обязательную capability: {0:?}")]
    MissingCapability(PlatformCapability),

    #[error("Platform helper command payload превышает лимит {limit} байт: {actual}")]
    OversizedPayload { limit: usize, actual: usize },

    #[error("Platform helper capability list превышает лимит {limit}: {actual}")]
    TooManyCapabilities { limit: usize, actual: usize },

    #[error("Platform helper command требует непустой correlation_id")]
    EmptyCorrelationId,

    #[error("Platform helper command correlation_id превышает лимит {limit} байт: {actual}")]
    OversizedCorrelationId { limit: usize, actual: usize },

    #[error("Platform helper command correlation_id содержит недопустимый символ")]
    InvalidCorrelationId,

    #[error("Platform helper command не удалось сериализовать для проверки размера")]
    InvalidCommand,
}

pub fn validate_helper_handshake(
    core: &CoreHello,
    helper: &HelperHello,
) -> Result<(), PlatformContractError> {
    validate_capability_count(&core.required_capabilities)?;
    validate_capability_count(&helper.capabilities)?;

    if helper.protocol_version < core.min_supported_protocol_version
        || helper.protocol_version > core.protocol_version
    {
        return Err(PlatformContractError::IncompatibleProtocolVersion {
            min_supported: core.min_supported_protocol_version,
            current: core.protocol_version,
            actual: helper.protocol_version,
        });
    }

    for capability in &core.required_capabilities {
        if !helper.capabilities.contains(capability) {
            return Err(PlatformContractError::MissingCapability(*capability));
        }
    }

    Ok(())
}

pub fn validate_helper_command(
    command: &PlatformHelperCommand,
    helper: &HelperHello,
) -> Result<(), PlatformContractError> {
    validate_payload_size(command)?;

    match command {
        PlatformHelperCommand::Handshake(core) => validate_helper_handshake(core, helper),
        PlatformHelperCommand::Status => Ok(()),
        PlatformHelperCommand::PrepareTunnel(payload) => {
            validate_correlation_id(&payload.correlation_id)?;
            validate_capability_count(&payload.required_capabilities)?;
            validate_required_capabilities(&payload.required_capabilities, helper)
        }
        PlatformHelperCommand::Disconnect { correlation_id }
        | PlatformHelperCommand::Recover { correlation_id } => {
            validate_correlation_id(correlation_id)
        }
    }
}

fn validate_required_capabilities(
    required: &[PlatformCapability],
    helper: &HelperHello,
) -> Result<(), PlatformContractError> {
    validate_capability_count(required)?;
    validate_capability_count(&helper.capabilities)?;

    for capability in required {
        if !helper.capabilities.contains(capability) {
            return Err(PlatformContractError::MissingCapability(*capability));
        }
    }
    Ok(())
}

fn validate_correlation_id(correlation_id: &str) -> Result<(), PlatformContractError> {
    if correlation_id.trim().is_empty() {
        return Err(PlatformContractError::EmptyCorrelationId);
    }

    let actual = correlation_id.len();
    if actual > MAX_CORRELATION_ID_BYTES {
        return Err(PlatformContractError::OversizedCorrelationId {
            limit: MAX_CORRELATION_ID_BYTES,
            actual,
        });
    }

    if !correlation_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(PlatformContractError::InvalidCorrelationId)
    } else {
        Ok(())
    }
}

fn validate_payload_size(command: &PlatformHelperCommand) -> Result<(), PlatformContractError> {
    let actual = serde_json::to_vec(command)
        .map_err(|_| PlatformContractError::InvalidCommand)?
        .len();

    if actual > MAX_PLATFORM_MESSAGE_BYTES {
        Err(PlatformContractError::OversizedPayload {
            limit: MAX_PLATFORM_MESSAGE_BYTES,
            actual,
        })
    } else {
        Ok(())
    }
}

fn validate_capability_count(
    capabilities: &[PlatformCapability],
) -> Result<(), PlatformContractError> {
    let actual = capabilities.len();
    if actual > MAX_PLATFORM_CAPABILITIES {
        Err(PlatformContractError::TooManyCapabilities {
            limit: MAX_PLATFORM_CAPABILITIES,
            actual,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper(capabilities: Vec<PlatformCapability>) -> HelperHello {
        HelperHello {
            protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
            platform: PlatformKind::MacOs,
            app_version: "0.1.0".to_string(),
            capabilities,
        }
    }

    #[test]
    fn compatible_handshake_accepts_declared_capabilities() {
        let core = CoreHello {
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Dns],
            ..Default::default()
        };
        let helper = helper(vec![
            PlatformCapability::Tun,
            PlatformCapability::Dns,
            PlatformCapability::RecoveryJournal,
        ]);

        assert_eq!(validate_helper_handshake(&core, &helper), Ok(()));
    }

    #[test]
    fn incompatible_protocol_version_fails_closed() {
        let core = CoreHello::default();
        let helper = HelperHello {
            protocol_version: 0,
            platform: PlatformKind::MacOs,
            app_version: "0.1.0".to_string(),
            capabilities: vec![],
        };

        assert_eq!(
            validate_helper_handshake(&core, &helper).unwrap_err().to_string(),
            "Несовместимая версия platform helper contract: core поддерживает 1-1, helper сообщил 0"
        );
    }

    #[test]
    fn missing_capability_fails_closed() {
        let core = CoreHello {
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Firewall],
            ..Default::default()
        };
        let helper = helper(vec![PlatformCapability::Tun]);

        assert_eq!(
            validate_helper_handshake(&core, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper не объявил обязательную capability: Firewall"
        );
    }

    #[test]
    fn unknown_command_or_capability_string_is_rejected_by_schema() {
        let unknown_command = r#"{"type":"raw_shell","payload":"route delete default"}"#;
        assert!(serde_json::from_str::<PlatformHelperCommand>(unknown_command).is_err());

        let unknown_command_field = r#"{"type":"status","payload":null,"extra":"ignored"}"#;
        assert!(serde_json::from_str::<PlatformHelperCommand>(unknown_command_field).is_err());

        let unknown_hello_field = r#"{
            "protocol_version":1,
            "platform":"mac_os",
            "app_version":"0.1.0",
            "capabilities":[],
            "EVIL_EXTRA":"ignored"
        }"#;
        assert!(serde_json::from_str::<HelperHello>(unknown_hello_field).is_err());

        let unknown_capability = r#"{
            "protocol_version":1,
            "platform":"mac_os",
            "app_version":"0.1.0",
            "capabilities":["raw_shell"]
        }"#;
        assert!(serde_json::from_str::<HelperHello>(unknown_capability).is_err());
    }

    #[test]
    fn oversized_payload_and_empty_correlation_id_are_rejected() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let oversized = PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
            correlation_id: "connect-1".to_string(),
            required_capabilities: vec![PlatformCapability::Tun],
            engine_config_json: vec![b'x'; MAX_PLATFORM_MESSAGE_BYTES + 1],
        });
        assert_eq!(
            validate_helper_command(&oversized, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper command payload превышает лимит 65536 байт: 262269"
        );

        let empty = PlatformHelperCommand::Disconnect {
            correlation_id: "   ".to_string(),
        };
        assert_eq!(
            validate_helper_command(&empty, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper command требует непустой correlation_id"
        );

        let oversized_correlation_id = PlatformHelperCommand::Disconnect {
            correlation_id: "a".repeat(MAX_CORRELATION_ID_BYTES + 1),
        };
        assert_eq!(
            validate_helper_command(&oversized_correlation_id, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper command correlation_id превышает лимит 128 байт: 129"
        );

        let log_injection_correlation_id = PlatformHelperCommand::Recover {
            correlation_id: "recover-1\nforged".to_string(),
        };
        assert_eq!(
            validate_helper_command(&log_injection_correlation_id, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper command correlation_id содержит недопустимый символ"
        );
    }

    #[test]
    fn oversized_serialized_command_and_capability_lists_are_rejected() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let core = CoreHello {
            required_capabilities: vec![PlatformCapability::Tun; MAX_PLATFORM_CAPABILITIES + 1],
            ..Default::default()
        };
        assert_eq!(
            validate_helper_handshake(&core, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper capability list превышает лимит 32: 33"
        );
    }

    #[test]
    fn debug_redacts_engine_config_json_contents() {
        let command = PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
            correlation_id: "connect-1".to_string(),
            required_capabilities: vec![PlatformCapability::Tun],
            engine_config_json:
                br#"{"uuid":"00000000-0000-4000-8000-000000000001","server":"example.com"}"#
                    .to_vec(),
        });

        let debug = format!("{command:?}");
        assert!(debug.contains("engine_config_json_len"));
        assert!(!debug.contains("engine_config_json: ["));
        assert!(!debug.contains("uuid"));
        assert!(!debug.contains("example.com"));
    }

    #[test]
    fn allowlisted_commands_validate_without_network_side_effects() {
        let helper = helper(vec![
            PlatformCapability::Tun,
            PlatformCapability::Dns,
            PlatformCapability::RecoveryJournal,
        ]);
        let status = PlatformHelperCommand::Status;
        assert_eq!(validate_helper_command(&status, &helper), Ok(()));

        let prepare = PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
            correlation_id: "connect-1".to_string(),
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Dns],
            engine_config_json: br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
        });
        assert_eq!(validate_helper_command(&prepare, &helper), Ok(()));
    }
}
