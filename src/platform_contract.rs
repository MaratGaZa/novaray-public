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
pub const MAX_HELPER_RUNTIME_SESSION_ID_BYTES: usize = 128;

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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRuntimeCommandEnvelope {
    pub session_id: String,
    pub sequence: u64,
    pub correlation_id: String,
    pub command: PlatformHelperCommand,
}

impl fmt::Debug for HelperRuntimeCommandEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperRuntimeCommandEnvelope")
            .field("session_id", &"<redacted>")
            .field("sequence", &self.sequence)
            .field("correlation_id", &"<redacted>")
            .field("command_type", &helper_command_type(&self.command))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HelperRuntimeReplayGuard {
    session: Option<HelperRuntimeSession>,
}

impl fmt::Debug for HelperRuntimeReplayGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperRuntimeReplayGuard")
            .field("has_session", &self.session.is_some())
            .field(
                "last_sequence",
                &self.session.as_ref().map(|session| session.last_sequence),
            )
            .finish()
    }
}

impl Default for HelperRuntimeReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperRuntimeReplayGuard {
    pub fn new() -> Self {
        Self { session: None }
    }

    pub fn begin_session(
        &mut self,
        session_id: impl Into<String>,
    ) -> Result<(), PlatformContractError> {
        self.session = Some(HelperRuntimeSession::new(session_id.into())?);
        Ok(())
    }

    pub fn current_session_last_sequence(&self) -> Option<u64> {
        self.session.as_ref().map(|session| session.last_sequence)
    }

    pub fn accept_command(
        &mut self,
        envelope: &HelperRuntimeCommandEnvelope,
        helper: &HelperHello,
    ) -> Result<(), PlatformContractError> {
        validate_helper_runtime_envelope(envelope, helper)?;

        let session = self
            .session
            .as_mut()
            .ok_or(PlatformContractError::MissingRuntimeSession)?;

        if envelope.session_id != session.session_id {
            return Err(PlatformContractError::RuntimeSessionMismatch);
        }

        if envelope.sequence <= session.last_sequence {
            return Err(PlatformContractError::StaleRuntimeSequence {
                last_seen: session.last_sequence,
                received: envelope.sequence,
            });
        }

        session.last_sequence = envelope.sequence;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct HelperRuntimeSession {
    session_id: String,
    last_sequence: u64,
}

impl HelperRuntimeSession {
    fn new(session_id: String) -> Result<Self, PlatformContractError> {
        validate_helper_runtime_session_id(&session_id)?;
        Ok(Self {
            session_id,
            last_sequence: 0,
        })
    }
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

    #[error("Platform helper runtime требует активную handshake session")]
    MissingRuntimeSession,

    #[error("Platform helper runtime session_id должен быть непустым")]
    EmptyRuntimeSessionId,

    #[error("Platform helper runtime session_id превышает лимит {limit} байт: {actual}")]
    OversizedRuntimeSessionId { limit: usize, actual: usize },

    #[error("Platform helper runtime session_id содержит недопустимый символ")]
    InvalidRuntimeSessionId,

    #[error("Platform helper runtime command относится не к текущей handshake session")]
    RuntimeSessionMismatch,

    #[error("Platform helper runtime sequence должен быть больше 0")]
    InvalidRuntimeSequence,

    #[error("Platform helper runtime sequence повторён или устарел: last_seen={last_seen}, received={received}")]
    StaleRuntimeSequence { last_seen: u64, received: u64 },

    #[error("Platform helper runtime command не должен повторять handshake")]
    RuntimeHandshakeCommand,

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

pub fn validate_helper_runtime_envelope(
    envelope: &HelperRuntimeCommandEnvelope,
    helper: &HelperHello,
) -> Result<(), PlatformContractError> {
    validate_helper_runtime_session_id(&envelope.session_id)?;
    validate_correlation_id(&envelope.correlation_id)?;

    if envelope.sequence == 0 {
        return Err(PlatformContractError::InvalidRuntimeSequence);
    }

    if matches!(envelope.command, PlatformHelperCommand::Handshake(_)) {
        return Err(PlatformContractError::RuntimeHandshakeCommand);
    }

    validate_helper_command(&envelope.command, helper)
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

fn validate_helper_runtime_session_id(session_id: &str) -> Result<(), PlatformContractError> {
    if session_id.trim().is_empty() {
        return Err(PlatformContractError::EmptyRuntimeSessionId);
    }

    let actual = session_id.len();
    if actual > MAX_HELPER_RUNTIME_SESSION_ID_BYTES {
        return Err(PlatformContractError::OversizedRuntimeSessionId {
            limit: MAX_HELPER_RUNTIME_SESSION_ID_BYTES,
            actual,
        });
    }

    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(PlatformContractError::InvalidRuntimeSessionId)
    } else {
        Ok(())
    }
}

fn helper_command_type(command: &PlatformHelperCommand) -> &'static str {
    match command {
        PlatformHelperCommand::Handshake(_) => "handshake",
        PlatformHelperCommand::Status => "status",
        PlatformHelperCommand::PrepareTunnel(_) => "prepare_tunnel",
        PlatformHelperCommand::Disconnect { .. } => "disconnect",
        PlatformHelperCommand::Recover { .. } => "recover",
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

    fn runtime_envelope(
        session_id: &str,
        sequence: u64,
        correlation_id: &str,
    ) -> HelperRuntimeCommandEnvelope {
        HelperRuntimeCommandEnvelope {
            session_id: session_id.to_string(),
            sequence,
            correlation_id: correlation_id.to_string(),
            command: PlatformHelperCommand::Disconnect {
                correlation_id: "disconnect-1".to_string(),
            },
        }
    }

    #[test]
    fn helper_runtime_replay_guard_accepts_monotonic_commands_in_current_session() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();

        guard.begin_session("session-1").unwrap();

        assert_eq!(
            guard.accept_command(&runtime_envelope("session-1", 1, "cmd-1"), &helper),
            Ok(())
        );
        assert_eq!(
            guard.accept_command(&runtime_envelope("session-1", 2, "cmd-2"), &helper),
            Ok(())
        );
        assert_eq!(guard.current_session_last_sequence(), Some(2));
    }

    #[test]
    fn helper_runtime_replay_guard_rejects_commands_before_session() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();

        assert_eq!(
            guard
                .accept_command(&runtime_envelope("session-1", 1, "cmd-1"), &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime требует активную handshake session"
        );
        assert_eq!(guard.current_session_last_sequence(), None);
    }

    #[test]
    fn helper_runtime_replay_guard_rejects_wrong_session_before_consuming_sequence() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();
        guard.begin_session("session-1").unwrap();

        assert_eq!(
            guard
                .accept_command(&runtime_envelope("session-2", 1, "cmd-1"), &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime command относится не к текущей handshake session"
        );
        assert_eq!(guard.current_session_last_sequence(), Some(0));
    }

    #[test]
    fn helper_runtime_replay_guard_rejects_repeated_or_stale_sequence() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();
        guard.begin_session("session-1").unwrap();

        guard
            .accept_command(&runtime_envelope("session-1", 7, "cmd-1"), &helper)
            .unwrap();

        assert_eq!(
            guard
                .accept_command(&runtime_envelope("session-1", 7, "cmd-1-replay"), &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime sequence повторён или устарел: last_seen=7, received=7"
        );
        assert_eq!(
            guard
                .accept_command(&runtime_envelope("session-1", 6, "cmd-older"), &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime sequence повторён или устарел: last_seen=7, received=6"
        );
        assert_eq!(guard.current_session_last_sequence(), Some(7));
    }

    #[test]
    fn helper_runtime_replay_guard_resets_sequence_only_for_new_session() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();
        guard.begin_session("session-1").unwrap();
        guard
            .accept_command(&runtime_envelope("session-1", 3, "cmd-3"), &helper)
            .unwrap();

        guard.begin_session("session-2").unwrap();

        assert_eq!(
            guard.accept_command(&runtime_envelope("session-2", 1, "cmd-1"), &helper),
            Ok(())
        );
        assert_eq!(
            guard
                .accept_command(
                    &runtime_envelope("session-1", 4, "cmd-old-session"),
                    &helper
                )
                .unwrap_err()
                .to_string(),
            "Platform helper runtime command относится не к текущей handshake session"
        );
        assert_eq!(guard.current_session_last_sequence(), Some(1));
    }

    #[test]
    fn helper_runtime_replay_guard_validates_bounded_session_and_sequence() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();

        assert_eq!(
            guard.begin_session("   ").unwrap_err().to_string(),
            "Platform helper runtime session_id должен быть непустым"
        );
        assert_eq!(
            guard.begin_session("bad\nsession").unwrap_err().to_string(),
            "Platform helper runtime session_id содержит недопустимый символ"
        );
        assert_eq!(
            guard
                .begin_session("s".repeat(MAX_HELPER_RUNTIME_SESSION_ID_BYTES + 1))
                .unwrap_err()
                .to_string(),
            "Platform helper runtime session_id превышает лимит 128 байт: 129"
        );

        guard.begin_session("session-1").unwrap();

        assert_eq!(
            guard
                .accept_command(&runtime_envelope("session-1", 0, "cmd-0"), &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime sequence должен быть больше 0"
        );
        assert_eq!(guard.current_session_last_sequence(), Some(0));
    }

    #[test]
    fn helper_runtime_correlation_id_is_not_freshness_proof() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let mut guard = HelperRuntimeReplayGuard::new();
        guard.begin_session("session-1").unwrap();

        assert_eq!(
            guard.accept_command(
                &runtime_envelope("session-1", 1, "same-correlation"),
                &helper
            ),
            Ok(())
        );
        assert_eq!(
            guard.accept_command(
                &runtime_envelope("session-1", 2, "same-correlation"),
                &helper
            ),
            Ok(())
        );
        assert_eq!(
            guard
                .accept_command(
                    &runtime_envelope("session-1", 2, "different-correlation"),
                    &helper
                )
                .unwrap_err()
                .to_string(),
            "Platform helper runtime sequence повторён или устарел: last_seen=2, received=2"
        );
    }

    #[test]
    fn helper_runtime_envelope_rejects_handshake_as_runtime_command() {
        let helper = helper(vec![PlatformCapability::Tun]);
        let envelope = HelperRuntimeCommandEnvelope {
            session_id: "session-1".to_string(),
            sequence: 1,
            correlation_id: "cmd-1".to_string(),
            command: PlatformHelperCommand::Handshake(CoreHello::default()),
        };

        assert_eq!(
            validate_helper_runtime_envelope(&envelope, &helper)
                .unwrap_err()
                .to_string(),
            "Platform helper runtime command не должен повторять handshake"
        );
    }

    #[test]
    fn helper_runtime_debug_redacts_session_and_correlation_ids() {
        let envelope = runtime_envelope("session-secret", 1, "uuid-like-correlation");
        let debug = format!("{envelope:?}");

        assert!(debug.contains("sequence: 1"));
        assert!(debug.contains("command_type"));
        assert!(!debug.contains("session-secret"));
        assert!(!debug.contains("uuid-like-correlation"));

        let mut guard = HelperRuntimeReplayGuard::new();
        guard.begin_session("session-secret").unwrap();
        let debug = format!("{guard:?}");
        assert!(debug.contains("has_session: true"));
        assert!(!debug.contains("session-secret"));
    }
}
