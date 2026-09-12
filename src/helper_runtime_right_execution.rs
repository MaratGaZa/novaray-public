//! Runtime-right lifecycle orchestration, currently exercised only through recording adapters.
//!
//! Observations are snapshots, not atomic ownership tokens. A native mutation adapter requires
//! separately reviewed authorization, cross-process race exclusion and crash recovery. This module
//! supplies no such adapter and must not be treated as evidence that those system gates passed.

use thiserror::Error;

use crate::helper_runtime_right::{
    plan_helper_runtime_right_install, plan_helper_runtime_right_uninstall,
    HelperRuntimeAuthorizationRightInstallPlan as InstallPlan,
    HelperRuntimeAuthorizationRightObservation as Observation,
    HelperRuntimeAuthorizationRightUninstallPlan as UninstallPlan,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRuntimeRightAdapterError;

/// All operations address only HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME and its fixed definition.
/// Errors may occur after effects. Implementations must never map a denied write to absence.
/// Exclusive &mut access serializes this caller only, not other processes or database writers.
pub trait HelperRuntimeRightLifecycleAdapter {
    fn inspect(&mut self) -> Result<Observation, HelperRuntimeRightAdapterError>;
    fn create_owned(&mut self) -> Result<(), HelperRuntimeRightAdapterError>;
    fn remove_owned(&mut self) -> Result<(), HelperRuntimeRightAdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRuntimeRightLifecycleOutcome {
    Installed,
    AlreadyOwned,
    Uninstalled,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRuntimeRightFailure {
    InspectionFailed,
    ConflictingDefinition,
    CreateFailed,
    CreateVerificationFailed,
    RemoveFailed,
    RemoveVerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRuntimeRightCleanup {
    NotAttempted,
    CreateEffectsUnknown,
    AlreadyAbsent,
    Removed,
    PreservedConflict,
    InspectionFailed,
    RemovalFailed,
    VerificationFailed,
    StillPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("helper runtime right lifecycle failed: {primary:?}; cleanup: {cleanup:?}")]
pub struct HelperRuntimeRightLifecycleError {
    pub primary: HelperRuntimeRightFailure,
    pub cleanup: HelperRuntimeRightCleanup,
}

use HelperRuntimeRightCleanup as Cleanup;
use HelperRuntimeRightFailure as Failure;
use HelperRuntimeRightLifecycleError as Error;
use HelperRuntimeRightLifecycleOutcome as Outcome;

fn failure(primary: Failure) -> Error {
    Error {
        primary,
        cleanup: Cleanup::NotAttempted,
    }
}

/// Reads state itself instead of accepting an externally built (possibly stale) install plan.
pub fn install_helper_runtime_right(
    adapter: &mut impl HelperRuntimeRightLifecycleAdapter,
) -> Result<Outcome, Error> {
    let observed = adapter
        .inspect()
        .map_err(|_| failure(Failure::InspectionFailed))?;
    match plan_helper_runtime_right_install(observed)
        .map_err(|_| failure(Failure::ConflictingDefinition))?
    {
        InstallPlan::AlreadyOwned => return Ok(Outcome::AlreadyOwned),
        InstallPlan::CreateOwned { .. } => {}
    }

    // A failed create provides no provenance for any definition subsequently observed.
    // Do not turn uncertain effects into permission to delete a possibly unrelated right.
    adapter.create_owned().map_err(|_| Error {
        primary: Failure::CreateFailed,
        cleanup: Cleanup::CreateEffectsUnknown,
    })?;

    if matches!(
        adapter.inspect().map(plan_helper_runtime_right_install),
        Ok(Ok(InstallPlan::AlreadyOwned))
    ) {
        return Ok(Outcome::Installed);
    }

    Err(Error {
        primary: Failure::CreateVerificationFailed,
        cleanup: compensate_created_right(adapter),
    })
}

/// Preserves changed/unrecognized definitions rather than attempting destructive recovery.
pub fn uninstall_helper_runtime_right(
    adapter: &mut impl HelperRuntimeRightLifecycleAdapter,
) -> Result<Outcome, Error> {
    let observed = adapter
        .inspect()
        .map_err(|_| failure(Failure::InspectionFailed))?;
    match plan_helper_runtime_right_uninstall(observed) {
        UninstallPlan::AlreadyAbsent => return Ok(Outcome::AlreadyAbsent),
        UninstallPlan::PreserveConflictingDefinition { .. } => {
            return Err(failure(Failure::ConflictingDefinition));
        }
        UninstallPlan::RemoveOwned { .. } => {}
    }
    adapter
        .remove_owned()
        .map_err(|_| failure(Failure::RemoveFailed))?;
    if matches!(
        adapter.inspect().map(plan_helper_runtime_right_uninstall),
        Ok(UninstallPlan::AlreadyAbsent)
    ) {
        Ok(Outcome::Uninstalled)
    } else {
        Err(failure(Failure::RemoveVerificationFailed))
    }
}

fn compensate_created_right(adapter: &mut impl HelperRuntimeRightLifecycleAdapter) -> Cleanup {
    // Never reuse the failed readback as authority for cleanup; inspect again, then attempt once.
    let observed = match adapter.inspect() {
        Ok(observed) => observed,
        Err(_) => return Cleanup::InspectionFailed,
    };
    match plan_helper_runtime_right_uninstall(observed) {
        UninstallPlan::AlreadyAbsent => return Cleanup::AlreadyAbsent,
        UninstallPlan::PreserveConflictingDefinition { .. } => return Cleanup::PreservedConflict,
        UninstallPlan::RemoveOwned { .. } => {}
    }
    if adapter.remove_owned().is_err() {
        return Cleanup::RemovalFailed;
    }
    match adapter.inspect().map(plan_helper_runtime_right_uninstall) {
        Ok(UninstallPlan::AlreadyAbsent) => Cleanup::Removed,
        Ok(_) => Cleanup::StillPresent,
        Err(_) => Cleanup::VerificationFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::helper_runtime_right::HELPER_RUNTIME_AUTHORIZATION_RULE;

    #[derive(Debug)]
    enum Step {
        Inspect(Result<Observation, HelperRuntimeRightAdapterError>),
        Create(Result<(), HelperRuntimeRightAdapterError>),
        Remove(Result<(), HelperRuntimeRightAdapterError>),
    }

    struct RecordingAdapter(VecDeque<Step>);

    impl HelperRuntimeRightLifecycleAdapter for RecordingAdapter {
        fn inspect(&mut self) -> Result<Observation, HelperRuntimeRightAdapterError> {
            match self.0.pop_front().expect("unexpected inspection") {
                Step::Inspect(result) => result,
                other => panic!("expected inspection, got {other:?}"),
            }
        }

        fn create_owned(&mut self) -> Result<(), HelperRuntimeRightAdapterError> {
            match self.0.pop_front().expect("unexpected creation") {
                Step::Create(result) => result,
                other => panic!("expected creation, got {other:?}"),
            }
        }

        fn remove_owned(&mut self) -> Result<(), HelperRuntimeRightAdapterError> {
            match self.0.pop_front().expect("unexpected removal") {
                Step::Remove(result) => result,
                other => panic!("expected removal, got {other:?}"),
            }
        }
    }

    fn owned() -> Observation {
        Observation::classify_present(HELPER_RUNTIME_AUTHORIZATION_RULE, 0).unwrap()
    }

    fn read(observation: Observation) -> Step {
        Step::Inspect(Ok(observation))
    }

    fn run(install: bool, steps: Vec<Step>, expected: Result<Outcome, Error>) {
        let mut adapter = RecordingAdapter(steps.into());
        let result = if install {
            install_helper_runtime_right(&mut adapter)
        } else {
            uninstall_helper_runtime_right(&mut adapter)
        };
        assert_eq!(result, expected);
        assert!(adapter.0.is_empty(), "not all expected calls occurred");
    }

    #[test]
    fn lifecycle_install_and_uninstall_verify_readback() {
        run(
            true,
            vec![
                read(Observation::absent()),
                Step::Create(Ok(())),
                read(owned()),
            ],
            Ok(Outcome::Installed),
        );
        run(
            false,
            vec![
                read(owned()),
                Step::Remove(Ok(())),
                read(Observation::absent()),
            ],
            Ok(Outcome::Uninstalled),
        );
    }

    #[test]
    fn lifecycle_retries_read_current_state_without_repeating_mutations() {
        let mut adapter = RecordingAdapter(
            vec![
                read(Observation::absent()),
                Step::Create(Ok(())),
                read(owned()),
                read(owned()),
                read(owned()),
                Step::Remove(Ok(())),
                read(Observation::absent()),
                read(Observation::absent()),
            ]
            .into(),
        );
        assert_eq!(
            install_helper_runtime_right(&mut adapter),
            Ok(Outcome::Installed)
        );
        assert_eq!(
            install_helper_runtime_right(&mut adapter),
            Ok(Outcome::AlreadyOwned)
        );
        assert_eq!(
            uninstall_helper_runtime_right(&mut adapter),
            Ok(Outcome::Uninstalled)
        );
        assert_eq!(
            uninstall_helper_runtime_right(&mut adapter),
            Ok(Outcome::AlreadyAbsent)
        );
        assert!(adapter.0.is_empty());
    }

    #[test]
    fn lifecycle_entry_inspection_failure_and_conflict_stop_before_writes() {
        for install in [true, false] {
            run(
                install,
                vec![Step::Inspect(Err(HelperRuntimeRightAdapterError))],
                Err(failure(Failure::InspectionFailed)),
            );
            for observation in [
                Observation::unrecognized(),
                Observation::classify_present("foreign-policy", 0).unwrap(),
                Observation::classify_present(HELPER_RUNTIME_AUTHORIZATION_RULE, 1).unwrap(),
            ] {
                run(
                    install,
                    vec![read(observation)],
                    Err(failure(Failure::ConflictingDefinition)),
                );
            }
        }
    }

    #[test]
    fn lifecycle_failed_create_never_authorizes_blind_cleanup() {
        run(
            true,
            vec![
                read(Observation::absent()),
                Step::Create(Err(HelperRuntimeRightAdapterError)),
            ],
            Err(Error {
                primary: Failure::CreateFailed,
                cleanup: Cleanup::CreateEffectsUnknown,
            }),
        );
    }

    #[test]
    fn lifecycle_failed_readback_reinspects_before_compensation() {
        run(
            true,
            vec![
                read(Observation::absent()),
                Step::Create(Ok(())),
                Step::Inspect(Err(HelperRuntimeRightAdapterError)),
                read(owned()),
                Step::Remove(Ok(())),
                read(Observation::absent()),
            ],
            Err(Error {
                primary: Failure::CreateVerificationFailed,
                cleanup: Cleanup::Removed,
            }),
        );
    }

    #[test]
    fn lifecycle_cleanup_preserves_changed_policy_and_does_not_remove_absence() {
        for (observed, cleanup) in [
            (Observation::absent(), Cleanup::AlreadyAbsent),
            (Observation::unrecognized(), Cleanup::PreservedConflict),
            (
                Observation::classify_present("foreign-policy", 0).unwrap(),
                Cleanup::PreservedConflict,
            ),
            (
                Observation::classify_present(HELPER_RUNTIME_AUTHORIZATION_RULE, 1).unwrap(),
                Cleanup::PreservedConflict,
            ),
        ] {
            run(
                true,
                vec![
                    read(Observation::absent()),
                    Step::Create(Ok(())),
                    read(Observation::unrecognized()),
                    read(observed),
                ],
                Err(Error {
                    primary: Failure::CreateVerificationFailed,
                    cleanup,
                }),
            );
        }
    }

    #[test]
    fn lifecycle_cleanup_failures_retain_the_primary_failure() {
        for (cleanup_steps, cleanup) in [
            (
                vec![Step::Inspect(Err(HelperRuntimeRightAdapterError))],
                Cleanup::InspectionFailed,
            ),
            (
                vec![
                    read(owned()),
                    Step::Remove(Err(HelperRuntimeRightAdapterError)),
                ],
                Cleanup::RemovalFailed,
            ),
            (
                vec![
                    read(owned()),
                    Step::Remove(Ok(())),
                    Step::Inspect(Err(HelperRuntimeRightAdapterError)),
                ],
                Cleanup::VerificationFailed,
            ),
            (
                vec![read(owned()), Step::Remove(Ok(())), read(owned())],
                Cleanup::StillPresent,
            ),
            (
                vec![
                    read(owned()),
                    Step::Remove(Ok(())),
                    read(Observation::unrecognized()),
                ],
                Cleanup::StillPresent,
            ),
        ] {
            let mut steps = vec![
                read(Observation::absent()),
                Step::Create(Ok(())),
                read(Observation::absent()),
            ];
            steps.extend(cleanup_steps);
            run(
                true,
                steps,
                Err(Error {
                    primary: Failure::CreateVerificationFailed,
                    cleanup,
                }),
            );
        }
    }

    #[test]
    fn lifecycle_uninstall_failure_is_not_retried_or_recreated() {
        run(
            false,
            vec![
                read(owned()),
                Step::Remove(Err(HelperRuntimeRightAdapterError)),
            ],
            Err(failure(Failure::RemoveFailed)),
        );
        for readback in [
            read(owned()),
            read(Observation::unrecognized()),
            Step::Inspect(Err(HelperRuntimeRightAdapterError)),
        ] {
            run(
                false,
                vec![read(owned()), Step::Remove(Ok(())), readback],
                Err(failure(Failure::RemoveVerificationFailed)),
            );
        }
    }

    #[test]
    fn lifecycle_errors_do_not_retain_observed_policy_contents() {
        let policy = "private-foreign-policy";
        let mut adapter =
            RecordingAdapter(vec![read(Observation::classify_present(policy, 0).unwrap())].into());
        let error = install_helper_runtime_right(&mut adapter).unwrap_err();
        assert!(!format!("{error:?}").contains(policy));
        assert!(!error.to_string().contains(policy));
        assert_eq!(error, failure(Failure::ConflictingDefinition));
    }
}
