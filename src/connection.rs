//! UI-independent connection lifecycle state machine and helper command executor.
//!
//! This module serializes high-level connection intents into validated platform helper commands.
//! It does not open IPC transports, start helpers, run as root, spawn engines, or mutate network
//! state.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::platform_contract::{
    validate_helper_command, HelperHello, PlatformContractError, PlatformHelperCommand,
    PlatformObservedState, TunnelCommandPayload,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting {
        correlation_id: String,
    },
    Connected {
        correlation_id: String,
    },
    Disconnecting {
        correlation_id: String,
    },
    Recovering {
        correlation_id: String,
    },
    Failed {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionIntent {
    Connect(TunnelCommandPayload),
    Status,
    Disconnect { correlation_id: String },
    Recover { correlation_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionIntentKind {
    Connect,
    Status,
    Disconnect,
    Recover,
}

impl ConnectionIntent {
    fn kind(&self) -> ConnectionIntentKind {
        match self {
            Self::Connect(_) => ConnectionIntentKind::Connect,
            Self::Status => ConnectionIntentKind::Status,
            Self::Disconnect { .. } => ConnectionIntentKind::Disconnect,
            Self::Recover { .. } => ConnectionIntentKind::Recover,
        }
    }

    fn into_command(self) -> PlatformHelperCommand {
        match self {
            Self::Connect(payload) => PlatformHelperCommand::PrepareTunnel(payload),
            Self::Status => PlatformHelperCommand::Status,
            Self::Disconnect { correlation_id } => {
                PlatformHelperCommand::Disconnect { correlation_id }
            }
            Self::Recover { correlation_id } => PlatformHelperCommand::Recover { correlation_id },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCommandResult {
    pub previous_state: ConnectionState,
    pub next_state: ConnectionState,
    pub command: PlatformHelperCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectionError {
    #[error("Недопустимая команда {intent:?} для состояния {state:?}")]
    InvalidTransition {
        state: ConnectionState,
        intent: ConnectionIntentKind,
    },

    #[error("Наблюдаемое состояние {observed:?} недопустимо для текущего состояния {state:?}")]
    InvalidObservedState {
        state: ConnectionState,
        observed: PlatformObservedState,
    },

    #[error("Correlation id mismatch: expected {expected}, actual {actual}")]
    CorrelationMismatch { expected: String, actual: String },

    #[error(transparent)]
    PlatformContract(#[from] PlatformContractError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCommandExecutor {
    state: ConnectionState,
    helper: HelperHello,
}

impl ConnectionCommandExecutor {
    pub fn new(helper: HelperHello) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            helper,
        }
    }

    pub fn with_state(helper: HelperHello, state: ConnectionState) -> Self {
        Self { state, helper }
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn execute(
        &mut self,
        intent: ConnectionIntent,
    ) -> Result<ConnectionCommandResult, ConnectionError> {
        let previous_state = self.state.clone();
        let next_state = next_state_for_intent(&previous_state, &intent)?;
        let command = intent.into_command();

        validate_helper_command(&command, &self.helper)?;

        self.state = next_state.clone();
        Ok(ConnectionCommandResult {
            previous_state,
            next_state,
            command,
        })
    }

    pub fn observe_helper_state(
        &mut self,
        observed: PlatformObservedState,
        correlation_id: Option<&str>,
    ) -> Result<ConnectionState, ConnectionError> {
        let next = next_state_for_observed(&self.state, observed, correlation_id)?;
        self.state = next.clone();
        Ok(next)
    }
}

fn next_state_for_intent(
    state: &ConnectionState,
    intent: &ConnectionIntent,
) -> Result<ConnectionState, ConnectionError> {
    match intent {
        ConnectionIntent::Status => Ok(state.clone()),
        ConnectionIntent::Connect(payload) => match state {
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => {
                Ok(ConnectionState::Connecting {
                    correlation_id: payload.correlation_id.clone(),
                })
            }
            _ => Err(invalid_transition(state, intent.kind())),
        },
        ConnectionIntent::Disconnect { correlation_id } => match state {
            ConnectionState::Connecting { .. } | ConnectionState::Connected { .. } => {
                Ok(ConnectionState::Disconnecting {
                    correlation_id: correlation_id.clone(),
                })
            }
            _ => Err(invalid_transition(state, intent.kind())),
        },
        ConnectionIntent::Recover { correlation_id } => match state {
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => {
                Ok(ConnectionState::Recovering {
                    correlation_id: correlation_id.clone(),
                })
            }
            _ => Err(invalid_transition(state, intent.kind())),
        },
    }
}

fn next_state_for_observed(
    state: &ConnectionState,
    observed: PlatformObservedState,
    correlation_id: Option<&str>,
) -> Result<ConnectionState, ConnectionError> {
    match (state, observed) {
        (_, PlatformObservedState::Failed) => Ok(ConnectionState::Failed {
            message: "platform helper reported failed state".to_string(),
        }),
        (ConnectionState::Disconnected, PlatformObservedState::Idle) => {
            Ok(ConnectionState::Disconnected)
        }
        (
            ConnectionState::Connecting {
                correlation_id: expected,
            },
            PlatformObservedState::Preparing,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(state.clone())
        }
        (
            ConnectionState::Connecting {
                correlation_id: expected,
            },
            PlatformObservedState::Connected,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(ConnectionState::Connected {
                correlation_id: expected.to_string(),
            })
        }
        (
            ConnectionState::Connected {
                correlation_id: expected,
            },
            PlatformObservedState::Connected,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(state.clone())
        }
        (
            ConnectionState::Disconnecting {
                correlation_id: expected,
            },
            PlatformObservedState::Disconnecting,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(state.clone())
        }
        (
            ConnectionState::Disconnecting {
                correlation_id: expected,
            },
            PlatformObservedState::Idle,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(ConnectionState::Disconnected)
        }
        (
            ConnectionState::Recovering {
                correlation_id: expected,
            },
            PlatformObservedState::Recovering,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(state.clone())
        }
        (
            ConnectionState::Recovering {
                correlation_id: expected,
            },
            PlatformObservedState::Idle,
        ) => {
            ensure_correlation(expected, correlation_id)?;
            Ok(ConnectionState::Disconnected)
        }
        _ => Err(ConnectionError::InvalidObservedState {
            state: state.clone(),
            observed,
        }),
    }
}

fn ensure_correlation(expected: &str, actual: Option<&str>) -> Result<(), ConnectionError> {
    let actual = actual.unwrap_or(expected);
    if actual == expected {
        Ok(())
    } else {
        Err(ConnectionError::CorrelationMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn invalid_transition(state: &ConnectionState, intent: ConnectionIntentKind) -> ConnectionError {
    ConnectionError::InvalidTransition {
        state: state.clone(),
        intent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform_contract::{PlatformCapability, PlatformKind};

    fn helper(capabilities: Vec<PlatformCapability>) -> HelperHello {
        HelperHello {
            protocol_version: crate::platform_contract::CURRENT_PLATFORM_CONTRACT_VERSION,
            platform: PlatformKind::MacOs,
            app_version: "0.1.0".to_string(),
            capabilities,
        }
    }

    fn connect_payload(correlation_id: &str) -> TunnelCommandPayload {
        TunnelCommandPayload {
            correlation_id: correlation_id.to_string(),
            required_capabilities: vec![PlatformCapability::Tun, PlatformCapability::Dns],
            engine_config_json: br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
        }
    }

    #[test]
    fn connect_emits_prepare_tunnel_and_moves_to_connecting() {
        let mut executor = ConnectionCommandExecutor::new(helper(vec![
            PlatformCapability::Tun,
            PlatformCapability::Dns,
        ]));

        let result = executor
            .execute(ConnectionIntent::Connect(connect_payload("connect-1")))
            .unwrap();

        assert_eq!(result.previous_state, ConnectionState::Disconnected);
        assert_eq!(
            result.next_state,
            ConnectionState::Connecting {
                correlation_id: "connect-1".to_string()
            }
        );
        assert!(matches!(
            result.command,
            PlatformHelperCommand::PrepareTunnel(TunnelCommandPayload { .. })
        ));
        assert_eq!(executor.state(), &result.next_state);
    }

    #[test]
    fn status_is_allowlisted_and_does_not_change_state() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::Tun]),
            ConnectionState::Connected {
                correlation_id: "connect-1".to_string(),
            },
        );

        let result = executor.execute(ConnectionIntent::Status).unwrap();

        assert_eq!(result.previous_state, result.next_state);
        assert_eq!(result.command, PlatformHelperCommand::Status);
        assert_eq!(executor.state(), &result.next_state);
    }

    #[test]
    fn connected_session_can_disconnect() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::Tun]),
            ConnectionState::Connected {
                correlation_id: "connect-1".to_string(),
            },
        );

        let result = executor
            .execute(ConnectionIntent::Disconnect {
                correlation_id: "disconnect-1".to_string(),
            })
            .unwrap();

        assert_eq!(
            result.next_state,
            ConnectionState::Disconnecting {
                correlation_id: "disconnect-1".to_string()
            }
        );
        assert_eq!(
            result.command,
            PlatformHelperCommand::Disconnect {
                correlation_id: "disconnect-1".to_string()
            }
        );
    }

    #[test]
    fn failed_or_disconnected_session_can_recover() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::RecoveryJournal]),
            ConnectionState::Failed {
                message: "previous crash".to_string(),
            },
        );

        let result = executor
            .execute(ConnectionIntent::Recover {
                correlation_id: "recover-1".to_string(),
            })
            .unwrap();

        assert_eq!(
            result.next_state,
            ConnectionState::Recovering {
                correlation_id: "recover-1".to_string()
            }
        );
        assert_eq!(
            result.command,
            PlatformHelperCommand::Recover {
                correlation_id: "recover-1".to_string()
            }
        );
    }

    #[test]
    fn duplicate_or_concurrent_connect_fails_before_command_emission() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::Tun, PlatformCapability::Dns]),
            ConnectionState::Connecting {
                correlation_id: "connect-1".to_string(),
            },
        );

        let error = executor
            .execute(ConnectionIntent::Connect(connect_payload("connect-2")))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Недопустимая команда Connect для состояния Connecting { correlation_id: \"connect-1\" }"
        );
        assert_eq!(
            executor.state(),
            &ConnectionState::Connecting {
                correlation_id: "connect-1".to_string()
            }
        );
    }

    #[test]
    fn invalid_disconnect_from_disconnected_fails() {
        let mut executor = ConnectionCommandExecutor::new(helper(vec![PlatformCapability::Tun]));

        let error = executor
            .execute(ConnectionIntent::Disconnect {
                correlation_id: "disconnect-1".to_string(),
            })
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Недопустимая команда Disconnect для состояния Disconnected"
        );
        assert_eq!(executor.state(), &ConnectionState::Disconnected);
    }

    #[test]
    fn platform_contract_errors_are_propagated_without_state_change() {
        let mut executor = ConnectionCommandExecutor::new(helper(vec![PlatformCapability::Tun]));

        let error = executor
            .execute(ConnectionIntent::Connect(connect_payload("connect-1")))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Platform helper не объявил обязательную capability: Dns"
        );
        assert_eq!(executor.state(), &ConnectionState::Disconnected);
    }

    #[test]
    fn observed_helper_state_advances_and_completes_lifecycle() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::Tun]),
            ConnectionState::Connecting {
                correlation_id: "connect-1".to_string(),
            },
        );

        assert_eq!(
            executor
                .observe_helper_state(PlatformObservedState::Connected, Some("connect-1"))
                .unwrap(),
            ConnectionState::Connected {
                correlation_id: "connect-1".to_string()
            }
        );

        executor
            .execute(ConnectionIntent::Disconnect {
                correlation_id: "disconnect-1".to_string(),
            })
            .unwrap();
        assert_eq!(
            executor
                .observe_helper_state(PlatformObservedState::Idle, Some("disconnect-1"))
                .unwrap(),
            ConnectionState::Disconnected
        );
    }

    #[test]
    fn observed_correlation_mismatch_fails_without_state_change() {
        let mut executor = ConnectionCommandExecutor::with_state(
            helper(vec![PlatformCapability::Tun]),
            ConnectionState::Connecting {
                correlation_id: "connect-1".to_string(),
            },
        );

        let error = executor
            .observe_helper_state(PlatformObservedState::Connected, Some("other"))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Correlation id mismatch: expected connect-1, actual other"
        );
        assert_eq!(
            executor.state(),
            &ConnectionState::Connecting {
                correlation_id: "connect-1".to_string()
            }
        );
    }
}
