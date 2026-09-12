//! Side-effect-free ownership contract for the macOS helper runtime Authorization right.
//!
//! A future platform adapter is responsible for reading and writing the authorization database.
//! This module only classifies a bounded observed definition and plans fail-closed reconciliation.

use thiserror::Error;

pub const HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME: &str = "org.novaray.platform-helper.runtime";
pub const HELPER_RUNTIME_AUTHORIZATION_RULE: &str = "authenticate-admin";

pub(crate) const MAX_OBSERVED_RULE_BYTES: usize = 128;
const MAX_OBSERVED_ADDITIONAL_FIELDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimeAuthorizationRightDefinition;

impl HelperRuntimeAuthorizationRightDefinition {
    pub fn delegated_rule(self) -> &'static str {
        HELPER_RUNTIME_AUTHORIZATION_RULE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimeAuthorizationRightObservation {
    kind: HelperRuntimeAuthorizationRightObservationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperRuntimeAuthorizationRightObservationKind {
    Absent,
    ExactOwned,
    Conflicting,
    Unrecognized,
}

impl HelperRuntimeAuthorizationRightObservation {
    pub fn absent() -> Self {
        Self {
            kind: HelperRuntimeAuthorizationRightObservationKind::Absent,
        }
    }

    pub fn unrecognized() -> Self {
        Self {
            kind: HelperRuntimeAuthorizationRightObservationKind::Unrecognized,
        }
    }

    pub fn classify_present(
        delegated_rule: &str,
        additional_field_count: usize,
    ) -> Result<Self, HelperRuntimeAuthorizationRightContractError> {
        validate_observed_shape(delegated_rule, additional_field_count)?;

        if delegated_rule == HELPER_RUNTIME_AUTHORIZATION_RULE && additional_field_count == 0 {
            Ok(Self {
                kind: HelperRuntimeAuthorizationRightObservationKind::ExactOwned,
            })
        } else {
            Ok(Self {
                kind: HelperRuntimeAuthorizationRightObservationKind::Conflicting,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRuntimeAuthorizationRightInstallPlan {
    CreateOwned {
        right_name: &'static str,
        definition: HelperRuntimeAuthorizationRightDefinition,
    },
    AlreadyOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRuntimeAuthorizationRightUninstallPlan {
    RemoveOwned { right_name: &'static str },
    AlreadyAbsent,
    PreserveConflictingDefinition { right_name: &'static str },
}

pub fn plan_helper_runtime_right_install(
    observed: HelperRuntimeAuthorizationRightObservation,
) -> Result<HelperRuntimeAuthorizationRightInstallPlan, HelperRuntimeAuthorizationRightContractError>
{
    match observed.kind {
        HelperRuntimeAuthorizationRightObservationKind::Absent => {
            Ok(HelperRuntimeAuthorizationRightInstallPlan::CreateOwned {
                right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
                definition: HelperRuntimeAuthorizationRightDefinition,
            })
        }
        HelperRuntimeAuthorizationRightObservationKind::ExactOwned => {
            Ok(HelperRuntimeAuthorizationRightInstallPlan::AlreadyOwned)
        }
        HelperRuntimeAuthorizationRightObservationKind::Conflicting
        | HelperRuntimeAuthorizationRightObservationKind::Unrecognized => {
            Err(HelperRuntimeAuthorizationRightContractError::ExistingDefinitionConflict)
        }
    }
}

pub fn plan_helper_runtime_right_uninstall(
    observed: HelperRuntimeAuthorizationRightObservation,
) -> HelperRuntimeAuthorizationRightUninstallPlan {
    match observed.kind {
        HelperRuntimeAuthorizationRightObservationKind::Absent => {
            HelperRuntimeAuthorizationRightUninstallPlan::AlreadyAbsent
        }
        HelperRuntimeAuthorizationRightObservationKind::ExactOwned => {
            HelperRuntimeAuthorizationRightUninstallPlan::RemoveOwned {
                right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
            }
        }
        HelperRuntimeAuthorizationRightObservationKind::Conflicting
        | HelperRuntimeAuthorizationRightObservationKind::Unrecognized => {
            HelperRuntimeAuthorizationRightUninstallPlan::PreserveConflictingDefinition {
                right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HelperRuntimeAuthorizationRightContractError {
    #[error("helper runtime authorization right definition has an invalid shape")]
    InvalidObservedDefinitionShape,

    #[error("helper runtime authorization right is already defined by another policy")]
    ExistingDefinitionConflict,
}

fn validate_observed_shape(
    delegated_rule: &str,
    additional_field_count: usize,
) -> Result<(), HelperRuntimeAuthorizationRightContractError> {
    if delegated_rule.is_empty()
        || delegated_rule.len() > MAX_OBSERVED_RULE_BYTES
        || !delegated_rule.is_ascii()
        || delegated_rule.bytes().any(|byte| byte.is_ascii_control())
        || additional_field_count > MAX_OBSERVED_ADDITIONAL_FIELDS
    {
        return Err(HelperRuntimeAuthorizationRightContractError::InvalidObservedDefinitionShape);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_right_name_and_owned_rule_are_narrow() {
        assert_eq!(
            HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
            "org.novaray.platform-helper.runtime"
        );
        assert!(!HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME.contains('*'));
        assert_eq!(
            HelperRuntimeAuthorizationRightDefinition.delegated_rule(),
            "authenticate-admin"
        );
    }

    #[test]
    fn absent_install_plans_exact_owned_definition() {
        assert_eq!(
            plan_helper_runtime_right_install(HelperRuntimeAuthorizationRightObservation::absent()),
            Ok(HelperRuntimeAuthorizationRightInstallPlan::CreateOwned {
                right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
                definition: HelperRuntimeAuthorizationRightDefinition,
            })
        );
    }

    #[test]
    fn exact_owned_install_is_idempotent() {
        let observed = HelperRuntimeAuthorizationRightObservation::classify_present(
            HELPER_RUNTIME_AUTHORIZATION_RULE,
            0,
        )
        .unwrap();

        assert_eq!(
            plan_helper_runtime_right_install(observed),
            Ok(HelperRuntimeAuthorizationRightInstallPlan::AlreadyOwned)
        );
    }

    #[test]
    fn foreign_and_superset_definitions_stop_install() {
        let foreign =
            HelperRuntimeAuthorizationRightObservation::classify_present("foreign-policy", 0)
                .unwrap();
        assert!(!format!("{foreign:?}").contains("foreign-policy"));

        for observed in [
            foreign,
            HelperRuntimeAuthorizationRightObservation::classify_present(
                HELPER_RUNTIME_AUTHORIZATION_RULE,
                1,
            )
            .unwrap(),
            HelperRuntimeAuthorizationRightObservation::unrecognized(),
        ] {
            assert_eq!(
                plan_helper_runtime_right_install(observed),
                Err(HelperRuntimeAuthorizationRightContractError::ExistingDefinitionConflict)
            );
        }
    }

    #[test]
    fn uninstall_removes_only_exact_owned_definition() {
        assert_eq!(
            plan_helper_runtime_right_uninstall(
                HelperRuntimeAuthorizationRightObservation::classify_present(
                    HELPER_RUNTIME_AUTHORIZATION_RULE,
                    0,
                )
                .unwrap()
            ),
            HelperRuntimeAuthorizationRightUninstallPlan::RemoveOwned {
                right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
            }
        );
        assert_eq!(
            plan_helper_runtime_right_uninstall(
                HelperRuntimeAuthorizationRightObservation::absent()
            ),
            HelperRuntimeAuthorizationRightUninstallPlan::AlreadyAbsent
        );
    }

    #[test]
    fn uninstall_preserves_changed_or_unrecognized_definition() {
        for observed in [
            HelperRuntimeAuthorizationRightObservation::classify_present("allow", 0).unwrap(),
            HelperRuntimeAuthorizationRightObservation::unrecognized(),
        ] {
            assert_eq!(
                plan_helper_runtime_right_uninstall(observed),
                HelperRuntimeAuthorizationRightUninstallPlan::PreserveConflictingDefinition {
                    right_name: HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
                }
            );
        }
    }

    #[test]
    fn invalid_observed_input_is_rejected_without_echoing_it() {
        let secret = "foreign-policy\nsecret";
        let error =
            HelperRuntimeAuthorizationRightObservation::classify_present(secret, 0).unwrap_err();

        assert_eq!(
            error,
            HelperRuntimeAuthorizationRightContractError::InvalidObservedDefinitionShape
        );
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        assert!(
            HelperRuntimeAuthorizationRightObservation::classify_present(
                HELPER_RUNTIME_AUTHORIZATION_RULE,
                MAX_OBSERVED_ADDITIONAL_FIELDS + 1,
            )
            .is_err()
        );
    }
}
