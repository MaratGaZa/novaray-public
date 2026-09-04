//! Side-effect-free helper runtime admission orchestration.
//!
//! The platform adapter supplies peer credentials, Authorization Services right checks and
//! session-ID generation. This module only enforces ordering and connection-local ownership; it
//! does not open sockets, call platform APIs, run as root or mutate network state.

use std::fmt;

use thiserror::Error;

use crate::platform_contract::{
    validate_helper_handshake, CoreHello, HelperHello, HelperRuntimeCommandEnvelope,
    HelperRuntimeConnectionSession, PlatformContractError, PlatformHelperCommand,
};

pub const AUTHORIZATION_EXTERNAL_FORM_BYTES: usize = 32;

pub struct HelperRuntimeAuthorizationExternalForm {
    bytes: [u8; AUTHORIZATION_EXTERNAL_FORM_BYTES],
}

impl HelperRuntimeAuthorizationExternalForm {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HelperRuntimeAdmissionError> {
        let actual = bytes.len();
        let bytes = bytes.try_into().map_err(|_| {
            HelperRuntimeAdmissionError::InvalidAuthorizationExternalFormLength {
                expected: AUTHORIZATION_EXTERNAL_FORM_BYTES,
                actual,
            }
        })?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; AUTHORIZATION_EXTERNAL_FORM_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for HelperRuntimeAuthorizationExternalForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperRuntimeAuthorizationExternalForm")
            .field("bytes", &"<redacted>")
            .field("len", &AUTHORIZATION_EXTERNAL_FORM_BYTES)
            .finish()
    }
}

pub struct HelperRuntimeAdmissionRequest {
    pub core_hello: CoreHello,
    pub authorization: HelperRuntimeAuthorizationExternalForm,
}

impl fmt::Debug for HelperRuntimeAdmissionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperRuntimeAdmissionRequest")
            .field("core_hello", &self.core_hello)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimePeerCredentials {
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimeAdmissionPolicy {
    expected_client_uid: u32,
}

impl HelperRuntimeAdmissionPolicy {
    pub fn new(expected_client_uid: u32) -> Result<Self, HelperRuntimeAdmissionError> {
        if expected_client_uid == 0 {
            return Err(HelperRuntimeAdmissionError::PrivilegedClientUidRejected);
        }
        Ok(Self {
            expected_client_uid,
        })
    }

    pub fn expected_client_uid(&self) -> u32 {
        self.expected_client_uid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimeAdmissionAdapterError;

pub trait HelperRuntimeAdmissionAdapter {
    type Connection;

    fn peer_credentials(
        &mut self,
        connection: &Self::Connection,
    ) -> Result<HelperRuntimePeerCredentials, HelperRuntimeAdmissionAdapterError>;

    fn validate_runtime_right(
        &mut self,
        connection: &mut Self::Connection,
        authorization: &HelperRuntimeAuthorizationExternalForm,
    ) -> Result<(), HelperRuntimeAdmissionAdapterError>;

    fn generate_session_id(&mut self) -> Result<String, HelperRuntimeAdmissionAdapterError>;
}

pub struct HelperRuntimeAdmissionExecutor<A> {
    adapter: A,
    helper: HelperHello,
    policy: HelperRuntimeAdmissionPolicy,
}

impl<A> HelperRuntimeAdmissionExecutor<A>
where
    A: HelperRuntimeAdmissionAdapter,
{
    pub fn new(adapter: A, helper: HelperHello, policy: HelperRuntimeAdmissionPolicy) -> Self {
        Self {
            adapter,
            helper,
            policy,
        }
    }

    pub fn admit(
        mut self,
        mut connection: A::Connection,
        request: HelperRuntimeAdmissionRequest,
    ) -> Result<AuthenticatedHelperRuntimeSession<A>, HelperRuntimeAdmissionError> {
        let peer = self
            .adapter
            .peer_credentials(&connection)
            .map_err(|_| HelperRuntimeAdmissionError::PeerCredentialInspectionFailed)?;

        if peer.effective_uid != self.policy.expected_client_uid {
            return Err(HelperRuntimeAdmissionError::UnexpectedPeerUid);
        }

        self.adapter
            .validate_runtime_right(&mut connection, &request.authorization)
            .map_err(|_| HelperRuntimeAdmissionError::RuntimeAuthorizationRejected)?;

        validate_helper_handshake(&request.core_hello, &self.helper)?;

        let session_id = self
            .adapter
            .generate_session_id()
            .map_err(|_| HelperRuntimeAdmissionError::SessionIdGenerationFailed)?;
        let session = HelperRuntimeConnectionSession::new(self.helper, session_id)?;

        Ok(AuthenticatedHelperRuntimeSession {
            adapter: self.adapter,
            connection,
            authorization: request.authorization,
            session,
        })
    }
}

pub struct AuthenticatedHelperRuntimeSession<A>
where
    A: HelperRuntimeAdmissionAdapter,
{
    adapter: A,
    connection: A::Connection,
    authorization: HelperRuntimeAuthorizationExternalForm,
    session: HelperRuntimeConnectionSession,
}

impl<A> AuthenticatedHelperRuntimeSession<A>
where
    A: HelperRuntimeAdmissionAdapter,
{
    pub fn session_id(&self) -> &str {
        self.session.session_id()
    }

    pub fn last_sequence(&self) -> u64 {
        self.session.last_sequence()
    }

    pub fn accept_command(
        &mut self,
        envelope: &HelperRuntimeCommandEnvelope,
    ) -> Result<(), HelperRuntimeAdmissionError> {
        if requires_runtime_right(&envelope.command) {
            self.adapter
                .validate_runtime_right(&mut self.connection, &self.authorization)
                .map_err(|_| HelperRuntimeAdmissionError::RuntimeAuthorizationRejected)?;
        }

        self.session.accept_command(envelope)?;
        Ok(())
    }
}

impl<A> fmt::Debug for AuthenticatedHelperRuntimeSession<A>
where
    A: HelperRuntimeAdmissionAdapter,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedHelperRuntimeSession")
            .field("connection", &"<redacted>")
            .field("authorization", &"<redacted>")
            .field("session", &self.session)
            .finish()
    }
}

fn requires_runtime_right(command: &PlatformHelperCommand) -> bool {
    matches!(
        command,
        PlatformHelperCommand::PrepareTunnel(_)
            | PlatformHelperCommand::Disconnect { .. }
            | PlatformHelperCommand::Recover { .. }
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HelperRuntimeAdmissionError {
    #[error(
        "helper runtime authorization external form must be exactly {expected} bytes, got {actual}"
    )]
    InvalidAuthorizationExternalFormLength { expected: usize, actual: usize },

    #[error("helper runtime client UID must be unprivileged")]
    PrivilegedClientUidRejected,

    #[error("helper runtime peer credential inspection failed")]
    PeerCredentialInspectionFailed,

    #[error("helper runtime peer UID does not match the configured client")]
    UnexpectedPeerUid,

    #[error("helper runtime authorization was rejected")]
    RuntimeAuthorizationRejected,

    #[error("helper runtime session ID generation failed")]
    SessionIdGenerationFailed,

    #[error(transparent)]
    PlatformContract(#[from] PlatformContractError),
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::platform_contract::{
        PlatformCapability, PlatformKind, TunnelCommandPayload, CURRENT_PLATFORM_CONTRACT_VERSION,
        MIN_PLATFORM_CONTRACT_VERSION,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecordedStep {
        PeerCredentials,
        RuntimeRight,
        SessionId,
    }

    #[derive(Debug)]
    struct RecordingAdapter {
        steps: Rc<RefCell<Vec<RecordedStep>>>,
        peer: Result<HelperRuntimePeerCredentials, HelperRuntimeAdmissionAdapterError>,
        authorization_results: Vec<Result<(), HelperRuntimeAdmissionAdapterError>>,
        session_id: Result<String, HelperRuntimeAdmissionAdapterError>,
    }

    impl RecordingAdapter {
        fn allowed(expected_uid: u32) -> (Self, Rc<RefCell<Vec<RecordedStep>>>) {
            let steps = Rc::new(RefCell::new(Vec::new()));
            let adapter = Self {
                steps: Rc::clone(&steps),
                peer: Ok(HelperRuntimePeerCredentials {
                    effective_uid: expected_uid,
                    effective_gid: 20,
                }),
                authorization_results: vec![Ok(()), Ok(())],
                session_id: Ok("helper-session-1".to_string()),
            };
            (adapter, steps)
        }
    }

    impl HelperRuntimeAdmissionAdapter for RecordingAdapter {
        type Connection = String;

        fn peer_credentials(
            &mut self,
            _connection: &Self::Connection,
        ) -> Result<HelperRuntimePeerCredentials, HelperRuntimeAdmissionAdapterError> {
            self.steps.borrow_mut().push(RecordedStep::PeerCredentials);
            self.peer
        }

        fn validate_runtime_right(
            &mut self,
            _connection: &mut Self::Connection,
            _authorization: &HelperRuntimeAuthorizationExternalForm,
        ) -> Result<(), HelperRuntimeAdmissionAdapterError> {
            self.steps.borrow_mut().push(RecordedStep::RuntimeRight);
            if self.authorization_results.is_empty() {
                return Ok(());
            }
            self.authorization_results.remove(0)
        }

        fn generate_session_id(&mut self) -> Result<String, HelperRuntimeAdmissionAdapterError> {
            self.steps.borrow_mut().push(RecordedStep::SessionId);
            self.session_id.clone()
        }
    }

    fn helper() -> HelperHello {
        HelperHello {
            protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
            platform: PlatformKind::MacOs,
            app_version: "0.1.0".to_string(),
            capabilities: vec![PlatformCapability::Tun],
        }
    }

    fn request() -> HelperRuntimeAdmissionRequest {
        HelperRuntimeAdmissionRequest {
            core_hello: CoreHello {
                protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
                min_supported_protocol_version: MIN_PLATFORM_CONTRACT_VERSION,
                required_capabilities: vec![PlatformCapability::Tun],
            },
            authorization: HelperRuntimeAuthorizationExternalForm::from_slice(&[0x5a; 32]).unwrap(),
        }
    }

    fn envelope(sequence: u64) -> HelperRuntimeCommandEnvelope {
        HelperRuntimeCommandEnvelope {
            session_id: "helper-session-1".to_string(),
            sequence,
            correlation_id: format!("command-{sequence}"),
            command: PlatformHelperCommand::Disconnect {
                correlation_id: format!("disconnect-{sequence}"),
            },
        }
    }

    fn policy() -> HelperRuntimeAdmissionPolicy {
        HelperRuntimeAdmissionPolicy::new(501).unwrap()
    }

    #[test]
    fn admission_uses_peer_authorization_handshake_and_helper_session_order() {
        let (adapter, steps) = RecordingAdapter::allowed(501);
        let session = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection-secret".to_string(), request())
            .unwrap();

        assert_eq!(session.session_id(), "helper-session-1");
        assert_eq!(
            *steps.borrow(),
            vec![
                RecordedStep::PeerCredentials,
                RecordedStep::RuntimeRight,
                RecordedStep::SessionId,
            ]
        );
    }

    #[test]
    fn peer_mismatch_stops_before_authorization_and_session_creation() {
        let (adapter, steps) = RecordingAdapter::allowed(502);
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap_err();

        assert_eq!(error, HelperRuntimeAdmissionError::UnexpectedPeerUid);
        assert_eq!(*steps.borrow(), vec![RecordedStep::PeerCredentials]);
    }

    #[test]
    fn peer_inspection_failure_stops_admission_immediately() {
        let (mut adapter, steps) = RecordingAdapter::allowed(501);
        adapter.peer = Err(HelperRuntimeAdmissionAdapterError);
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap_err();

        assert_eq!(
            error,
            HelperRuntimeAdmissionError::PeerCredentialInspectionFailed
        );
        assert_eq!(*steps.borrow(), vec![RecordedStep::PeerCredentials]);
    }

    #[test]
    fn authorization_denial_stops_before_handshake_and_session_creation() {
        let (mut adapter, steps) = RecordingAdapter::allowed(501);
        adapter.authorization_results = vec![Err(HelperRuntimeAdmissionAdapterError)];
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap_err();

        assert_eq!(
            error,
            HelperRuntimeAdmissionError::RuntimeAuthorizationRejected
        );
        assert_eq!(
            *steps.borrow(),
            vec![RecordedStep::PeerCredentials, RecordedStep::RuntimeRight]
        );
    }

    #[test]
    fn handshake_failure_stops_before_helper_session_id_generation() {
        let mut incompatible = request();
        incompatible.core_hello.required_capabilities = vec![PlatformCapability::Firewall];
        let (adapter, steps) = RecordingAdapter::allowed(501);
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), incompatible)
            .unwrap_err();

        assert!(matches!(
            error,
            HelperRuntimeAdmissionError::PlatformContract(
                PlatformContractError::MissingCapability(PlatformCapability::Firewall)
            )
        ));
        assert_eq!(
            *steps.borrow(),
            vec![RecordedStep::PeerCredentials, RecordedStep::RuntimeRight]
        );
    }

    #[test]
    fn invalid_helper_generated_session_id_is_rejected() {
        let (mut adapter, steps) = RecordingAdapter::allowed(501);
        adapter.session_id = Ok("bad\nsession".to_string());
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap_err();

        assert!(matches!(
            error,
            HelperRuntimeAdmissionError::PlatformContract(
                PlatformContractError::InvalidRuntimeSessionId
            )
        ));
        assert_eq!(
            *steps.borrow(),
            vec![
                RecordedStep::PeerCredentials,
                RecordedStep::RuntimeRight,
                RecordedStep::SessionId,
            ]
        );
    }

    #[test]
    fn session_id_generation_failure_has_stable_error_category() {
        let (mut adapter, steps) = RecordingAdapter::allowed(501);
        adapter.session_id = Err(HelperRuntimeAdmissionAdapterError);
        let error = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap_err();

        assert_eq!(
            error,
            HelperRuntimeAdmissionError::SessionIdGenerationFailed
        );
        assert_eq!(
            *steps.borrow(),
            vec![
                RecordedStep::PeerCredentials,
                RecordedStep::RuntimeRight,
                RecordedStep::SessionId,
            ]
        );
    }

    #[test]
    fn mutating_command_rechecks_authorization_before_consuming_sequence() {
        let (mut adapter, _steps) = RecordingAdapter::allowed(501);
        adapter.authorization_results =
            vec![Ok(()), Err(HelperRuntimeAdmissionAdapterError), Ok(())];
        let mut session = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap();

        assert_eq!(
            session.accept_command(&envelope(1)).unwrap_err(),
            HelperRuntimeAdmissionError::RuntimeAuthorizationRejected
        );
        assert_eq!(session.last_sequence(), 0);
        assert_eq!(session.accept_command(&envelope(1)), Ok(()));
        assert_eq!(session.last_sequence(), 1);
    }

    #[test]
    fn invalid_mutating_command_does_not_consume_sequence_after_right_check() {
        let (adapter, _steps) = RecordingAdapter::allowed(501);
        let mut session = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection".to_string(), request())
            .unwrap();
        let invalid = HelperRuntimeCommandEnvelope {
            session_id: "helper-session-1".to_string(),
            sequence: 1,
            correlation_id: "command-1".to_string(),
            command: PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload {
                correlation_id: "prepare-1".to_string(),
                required_capabilities: vec![PlatformCapability::Firewall],
                engine_config_json: br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
            }),
        };

        assert!(matches!(
            session.accept_command(&invalid),
            Err(HelperRuntimeAdmissionError::PlatformContract(
                PlatformContractError::MissingCapability(PlatformCapability::Firewall)
            ))
        ));
        assert_eq!(session.last_sequence(), 0);
    }

    #[test]
    fn external_form_requires_exact_length_and_redacts_debug_output() {
        assert!(matches!(
            HelperRuntimeAuthorizationExternalForm::from_slice(&[0; 31]),
            Err(
                HelperRuntimeAdmissionError::InvalidAuthorizationExternalFormLength {
                    expected: 32,
                    actual: 31
                }
            )
        ));
        assert!(matches!(
            HelperRuntimeAuthorizationExternalForm::from_slice(&[0; 33]),
            Err(
                HelperRuntimeAdmissionError::InvalidAuthorizationExternalFormLength {
                    expected: 32,
                    actual: 33
                }
            )
        ));

        let form = HelperRuntimeAuthorizationExternalForm::from_slice(&[0x5a; 32]).unwrap();
        let debug = format!("{form:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("90"));
    }

    #[test]
    fn authenticated_session_debug_redacts_connection_and_session_secrets() {
        let (adapter, _steps) = RecordingAdapter::allowed(501);
        let session = HelperRuntimeAdmissionExecutor::new(adapter, helper(), policy())
            .admit("connection-secret".to_string(), request())
            .unwrap();
        let debug = format!("{session:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("connection-secret"));
        assert!(!debug.contains("helper-session-1"));
        assert!(!debug.contains("90"));
    }

    #[test]
    fn admission_policy_rejects_root_client_uid() {
        assert_eq!(
            HelperRuntimeAdmissionPolicy::new(0),
            Err(HelperRuntimeAdmissionError::PrivilegedClientUidRejected)
        );
    }
}
