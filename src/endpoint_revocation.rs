//! Recording-adapter revocation ordering, not native enforcement or authority to grant a new tuple.
//!
//! Exclusive mutable access serializes this caller only. A future native adapter needs separately
//! reviewed lifecycle locking, authentic observations, durable snapshot/recovery and checks at each
//! mutation boundary. There is no native adapter, timer, retry or automatic compensation here.

use thiserror::Error;

use crate::endpoint_bootstrap::BootstrapBinding;
use crate::kill_switch::KillSwitchAllowlist;

#[derive(Debug)]
pub struct RevocationScope {
    policy: KillSwitchAllowlist,
    binding: BootstrapBinding,
}

impl RevocationScope {
    pub fn policy(&self) -> &KillSwitchAllowlist {
        &self.policy
    }

    pub fn binding(&self) -> BootstrapBinding {
        self.binding
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedPresence {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedDeny {
    Active,
    Inactive,
    Unknown,
}

/// A trusted adapter's snapshot for the supplied exact scope, not a kernel attestation.
#[derive(Debug, Clone, Copy)]
pub struct RevocationObservation {
    pub binding: BootstrapBinding,
    pub deny: ObservedDeny,
    pub transport: ObservedPresence,
    /// Both the old firewall exception and its endpoint exclusion route.
    pub exception: ObservedPresence,
    pub established: ObservedPresence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationAdapterError;

/// Every operation is scoped to the old tuple; none may remove deny or grant another endpoint.
/// Hold the future system lifecycle guard for the whole run; &mut alone does not supply it.
/// Inspections must address this scope, not merely return cached plan state. Mutations must check
/// binding/deny at their own boundary. Failures may follow effects. There is deliberately no default
/// implementation: recording success is not a working native adapter or a durable journal.
pub trait EndpointRevocationAdapter {
    fn inspect(
        &mut self,
        scope: &RevocationScope,
    ) -> Result<RevocationObservation, RevocationAdapterError>;
    /// A native implementation must durably retain the complete recovery snapshot before returning.
    fn record_intent(
        &mut self,
        scope: &RevocationScope,
        initial: &RevocationObservation,
    ) -> Result<(), RevocationAdapterError>;
    fn stop_transport(&mut self, scope: &RevocationScope) -> Result<(), RevocationAdapterError>;
    /// Withdraw only the old firewall allowance and endpoint exclusion route, never shared deny.
    fn remove_exception(&mut self, scope: &RevocationScope) -> Result<(), RevocationAdapterError>;
    fn clear_established(&mut self, scope: &RevocationScope) -> Result<(), RevocationAdapterError>;
    /// Records a snapshot, not permission to resume after crash or install a new tuple.
    fn record_observed_revocation(
        &mut self,
        scope: &RevocationScope,
        observed: &RevocationObservation,
    ) -> Result<(), RevocationAdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    Ready,
    Executing,
    Observed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStage {
    Admission,
    InitialInspection,
    RecordIntent,
    PreStopInspection,
    StopTransport,
    TransportInspection,
    RemoveException,
    ExceptionInspection,
    ClearEstablished,
    FinalInspection,
    RecordObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationFailure {
    AlreadyAttempted,
    AdapterFailed,
    ContextChanged,
    DenyUnproven,
    UnknownState,
    RevocationUnproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("endpoint revocation stopped at {stage:?}: {cause:?}")]
pub struct EndpointRevocationError {
    pub stage: RevocationStage,
    pub cause: RevocationFailure,
    pub journal_may_exist: bool,
    pub mutation_attempted: bool,
}

/// Adapter-reported categories only: synchronous core cannot preempt a blocked callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentAdapterError {
    Failed,
    TimedOut,
}

/// Whole-connection snapshot, not merely the old tuple or a kernel attestation.
#[derive(Debug, Clone, Copy)]
pub struct ContainmentObservation {
    /// Identity of the original owning connection, not the current network generation.
    pub owner: BootstrapBinding,
    pub deny: ObservedDeny,
    pub engine: ObservedPresence,
    pub transport: ObservedPresence,
    pub resources: ObservedPresence,
    /// ALL exceptions and exclusion routes owned by this connection.
    pub exceptions: ObservedPresence,
    pub established: ObservedPresence,
}

/// Separate recovery path: preserve deny and pending intent, never retry revocation or reconnect.
/// A native implementation must bound/cancel its work, authenticate observations and verify original
/// ownership under the lifecycle lock even when the current network context has changed. It must not
/// touch another connection's resources. These obligations are not implemented by the core caller.
pub trait EndpointContainmentAdapter: EndpointRevocationAdapter {
    fn teardown_connection(
        &mut self,
        scope: &RevocationScope,
        primary: &EndpointRevocationError,
    ) -> Result<(), ContainmentAdapterError>;
    fn inspect_connection_after_teardown(
        &mut self,
        scope: &RevocationScope,
    ) -> Result<ContainmentObservation, ContainmentAdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentFailure {
    Teardown(ContainmentAdapterError),
    Inspection(ContainmentAdapterError),
    WrongOwner,
    DenyUnproven,
    UnknownState,
    ResidualState,
}

/// No variant is a protected status, new grant, or authority to clear pending recovery intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentOutcome {
    NotRequired,
    TeardownObserved,
    RecoveryUnknown(ContainmentFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{primary}; containment: {containment:?}")]
pub struct RevocationContainmentError {
    #[source]
    pub primary: EndpointRevocationError,
    pub containment: ContainmentOutcome,
}

/// Single-use orchestration. Observed is not a grant, a durable recovery token or packet evidence.
#[derive(Debug)]
pub struct EndpointRevocation {
    scope: RevocationScope,
    state: RevocationState,
    journal_may_exist: bool,
    mutation_attempted: bool,
}

impl EndpointRevocation {
    pub fn new(policy: KillSwitchAllowlist, binding: BootstrapBinding) -> Self {
        Self {
            scope: RevocationScope { policy, binding },
            state: RevocationState::Ready,
            journal_may_exist: false,
            mutation_attempted: false,
        }
    }

    pub fn state(&self) -> RevocationState {
        self.state
    }

    fn failure(&self, stage: RevocationStage, cause: RevocationFailure) -> EndpointRevocationError {
        EndpointRevocationError {
            stage,
            cause,
            journal_may_exist: self.journal_may_exist,
            mutation_attempted: self.mutation_attempted,
        }
    }

    fn checked_call(
        &self,
        stage: RevocationStage,
        result: Result<(), RevocationAdapterError>,
    ) -> Result<(), EndpointRevocationError> {
        result.map_err(|_| self.failure(stage, RevocationFailure::AdapterFailed))
    }

    fn inspect(
        &self,
        adapter: &mut impl EndpointRevocationAdapter,
        stage: RevocationStage,
    ) -> Result<RevocationObservation, EndpointRevocationError> {
        use ObservedPresence::{Absent, Unknown};
        use RevocationStage::{ExceptionInspection, FinalInspection, TransportInspection};
        let observed = adapter
            .inspect(&self.scope)
            .map_err(|_| self.failure(stage, RevocationFailure::AdapterFailed))?;
        let cause = if observed.binding != self.scope.binding {
            Some(RevocationFailure::ContextChanged)
        } else if observed.deny != ObservedDeny::Active {
            Some(RevocationFailure::DenyUnproven)
        } else if [observed.transport, observed.exception, observed.established].contains(&Unknown)
        {
            Some(RevocationFailure::UnknownState)
        } else if (matches!(
            stage,
            TransportInspection | ExceptionInspection | FinalInspection
        ) && observed.transport != Absent)
            || (matches!(stage, ExceptionInspection | FinalInspection)
                && observed.exception != Absent)
            || (stage == FinalInspection && observed.established != Absent)
        {
            Some(RevocationFailure::RevocationUnproven)
        } else {
            None
        };
        match cause {
            Some(cause) => Err(self.failure(stage, cause)),
            None => Ok(observed),
        }
    }

    /// Runs revocation once, with mandatory containment on returned post-mutation errors.
    /// A successful cleanup never turns the primary failure into success. Pending intent remains.
    /// Panics/crashes require external supervision; there is no Drop cleanup or callback preemption.
    ///
    /// The raw path cannot be called by external consumers:
    /// ```compile_fail,E0624
    /// use novaray_core::endpoint_revocation::{EndpointRevocation, EndpointRevocationAdapter};
    /// fn bypass(mut operation: EndpointRevocation, adapter: &mut impl EndpointRevocationAdapter) {
    ///     let _ = operation.execute_revocation(adapter);
    /// }
    /// ```
    pub fn execute(
        mut self,
        adapter: &mut impl EndpointContainmentAdapter,
    ) -> Result<(), RevocationContainmentError> {
        self.execute_revocation(adapter).map_err(|primary| {
            let containment = if primary.mutation_attempted {
                match self.contain(adapter, &primary) {
                    Ok(()) => ContainmentOutcome::TeardownObserved,
                    Err(cause) => ContainmentOutcome::RecoveryUnknown(cause),
                }
            } else {
                ContainmentOutcome::NotRequired
            };
            RevocationContainmentError {
                primary,
                containment,
            }
        })
    }

    fn contain(
        &self,
        adapter: &mut impl EndpointContainmentAdapter,
        primary: &EndpointRevocationError,
    ) -> Result<(), ContainmentFailure> {
        adapter
            .teardown_connection(&self.scope, primary)
            .map_err(ContainmentFailure::Teardown)?;
        let observed = adapter
            .inspect_connection_after_teardown(&self.scope)
            .map_err(ContainmentFailure::Inspection)?;
        let presence = [
            observed.engine,
            observed.transport,
            observed.resources,
            observed.exceptions,
            observed.established,
        ];
        if observed.owner != self.scope.binding {
            Err(ContainmentFailure::WrongOwner)
        } else if observed.deny != ObservedDeny::Active {
            Err(ContainmentFailure::DenyUnproven)
        } else if presence.contains(&ObservedPresence::Unknown) {
            Err(ContainmentFailure::UnknownState)
        } else if presence.contains(&ObservedPresence::Present) {
            Err(ContainmentFailure::ResidualState)
        } else {
            Ok(())
        }
    }

    fn execute_revocation(
        &mut self,
        adapter: &mut impl EndpointRevocationAdapter,
    ) -> Result<(), EndpointRevocationError> {
        if self.state != RevocationState::Ready {
            return Err(self.failure(
                RevocationStage::Admission,
                RevocationFailure::AlreadyAttempted,
            ));
        }
        // A panic also leaves the object non-reusable; no Drop handler performs system cleanup.
        self.state = RevocationState::Executing;
        let result = self.run(adapter);
        self.state = if result.is_ok() {
            RevocationState::Observed
        } else {
            RevocationState::Blocked
        };
        result
    }

    fn run(
        &mut self,
        adapter: &mut impl EndpointRevocationAdapter,
    ) -> Result<(), EndpointRevocationError> {
        use RevocationStage::*;
        let initial = self.inspect(adapter, InitialInspection)?;
        // Persist failure may mean a partial journal. It never authorizes a mutation or cleanup.
        self.journal_may_exist = true;
        self.checked_call(RecordIntent, adapter.record_intent(&self.scope, &initial))?;
        self.inspect(adapter, PreStopInspection)?;

        self.mutation_attempted = true;
        self.checked_call(StopTransport, adapter.stop_transport(&self.scope))?;
        self.inspect(adapter, TransportInspection)?;
        self.checked_call(RemoveException, adapter.remove_exception(&self.scope))?;
        self.inspect(adapter, ExceptionInspection)?;
        self.checked_call(ClearEstablished, adapter.clear_established(&self.scope))?;
        let observed = self.inspect(adapter, FinalInspection)?;
        self.checked_call(
            RecordObservation,
            adapter.record_observed_revocation(&self.scope, &observed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kill_switch::{EndpointTransport, TunnelIpFamily};
    use std::num::NonZeroU64;

    const ORDER: [RevocationStage; 10] = [
        RevocationStage::InitialInspection,
        RevocationStage::RecordIntent,
        RevocationStage::PreStopInspection,
        RevocationStage::StopTransport,
        RevocationStage::TransportInspection,
        RevocationStage::RemoveException,
        RevocationStage::ExceptionInspection,
        RevocationStage::ClearEstablished,
        RevocationStage::FinalInspection,
        RevocationStage::RecordObservation,
    ];

    fn binding(values: [u64; 4]) -> BootstrapBinding {
        let [session, request, profile, network] = values.map(|v| NonZeroU64::new(v).unwrap());
        BootstrapBinding::new(session, request, profile, network)
    }

    fn policy() -> KillSwitchAllowlist {
        KillSwitchAllowlist::new(
            "203.0.113.42:8443".parse().unwrap(),
            EndpointTransport::Tcp,
            "en7".into(),
            "utun19".into(),
            TunnelIpFamily::Ipv4,
        )
        .unwrap()
    }

    struct RecordingAdapter {
        seen: Vec<RevocationStage>,
        fault: Option<usize>,
        panic_at: Option<usize>,
        observations: [RevocationObservation; 5],
        expected_policy: KillSwitchAllowlist,
        expected_binding: BootstrapBinding,
        mutation_attempts: usize,
        containment_calls: Vec<&'static str>,
        primary: Option<EndpointRevocationError>,
        teardown_result: Result<(), ContainmentAdapterError>,
        cleanup_snapshot: Result<ContainmentObservation, ContainmentAdapterError>,
    }

    impl RecordingAdapter {
        fn new() -> Self {
            use ObservedPresence::{Absent, Present};
            let binding = binding([17001, 17002, 17003, 17004]);
            let mut observations = [RevocationObservation {
                binding,
                deny: ObservedDeny::Active,
                transport: Present,
                exception: Present,
                established: Present,
            }; 5];
            observations[2].transport = Absent;
            observations[3].transport = Absent;
            observations[3].exception = Absent;
            observations[4].transport = Absent;
            observations[4].exception = Absent;
            observations[4].established = Absent;
            Self {
                seen: Vec::new(),
                fault: None,
                panic_at: None,
                observations,
                expected_policy: policy(),
                expected_binding: binding,
                mutation_attempts: 0,
                containment_calls: Vec::new(),
                primary: None,
                teardown_result: Ok(()),
                cleanup_snapshot: Ok(ContainmentObservation {
                    owner: binding,
                    deny: ObservedDeny::Active,
                    engine: Absent,
                    transport: Absent,
                    resources: Absent,
                    exceptions: Absent,
                    established: Absent,
                }),
            }
        }

        fn executor(&self) -> EndpointRevocation {
            EndpointRevocation::new(self.expected_policy.clone(), self.expected_binding)
        }

        fn call(
            &mut self,
            scope: &RevocationScope,
            stage: RevocationStage,
        ) -> Result<(), RevocationAdapterError> {
            assert_eq!(scope.policy(), &self.expected_policy);
            assert_eq!(scope.binding(), self.expected_binding);
            let index = self.seen.len();
            assert_eq!(ORDER.get(index), Some(&stage));
            self.seen.push(stage);
            if matches!(
                stage,
                RevocationStage::StopTransport
                    | RevocationStage::RemoveException
                    | RevocationStage::ClearEstablished
            ) {
                self.mutation_attempts += 1;
            }
            assert_ne!(self.panic_at, Some(index), "injected adapter panic");
            if self.fault == Some(index) {
                Err(RevocationAdapterError)
            } else {
                Ok(())
            }
        }
    }

    impl EndpointContainmentAdapter for RecordingAdapter {
        fn teardown_connection(
            &mut self,
            scope: &RevocationScope,
            primary: &EndpointRevocationError,
        ) -> Result<(), ContainmentAdapterError> {
            assert!(self.containment_calls.is_empty());
            assert_eq!(scope.policy(), &self.expected_policy);
            assert_eq!(scope.binding(), self.expected_binding);
            assert!(primary.mutation_attempted);
            assert!(primary.journal_may_exist);
            assert!(self.mutation_attempts > 0);
            self.primary = Some(*primary);
            self.containment_calls.push("teardown");
            self.teardown_result
        }

        fn inspect_connection_after_teardown(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<ContainmentObservation, ContainmentAdapterError> {
            assert_eq!(self.containment_calls, ["teardown"]);
            assert_eq!(scope.policy(), &self.expected_policy);
            assert_eq!(scope.binding(), self.expected_binding);
            self.containment_calls.push("inspect");
            self.cleanup_snapshot
        }
    }

    impl EndpointRevocationAdapter for RecordingAdapter {
        fn inspect(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<RevocationObservation, RevocationAdapterError> {
            let index = self.seen.len();
            let stage = match index {
                0 => RevocationStage::InitialInspection,
                2 => RevocationStage::PreStopInspection,
                4 => RevocationStage::TransportInspection,
                6 => RevocationStage::ExceptionInspection,
                8 => RevocationStage::FinalInspection,
                _ => panic!("unexpected inspection"),
            };
            self.call(scope, stage)?;
            Ok(self.observations[index / 2])
        }

        fn record_intent(
            &mut self,
            scope: &RevocationScope,
            initial: &RevocationObservation,
        ) -> Result<(), RevocationAdapterError> {
            assert_eq!(initial.binding, self.observations[0].binding);
            assert_eq!(initial.deny, self.observations[0].deny);
            assert_eq!(initial.transport, self.observations[0].transport);
            assert_eq!(initial.exception, self.observations[0].exception);
            assert_eq!(initial.established, self.observations[0].established);
            self.call(scope, RevocationStage::RecordIntent)
        }

        fn stop_transport(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<(), RevocationAdapterError> {
            self.call(scope, RevocationStage::StopTransport)
        }

        fn remove_exception(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<(), RevocationAdapterError> {
            self.call(scope, RevocationStage::RemoveException)
        }

        fn clear_established(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<(), RevocationAdapterError> {
            self.call(scope, RevocationStage::ClearEstablished)
        }

        fn record_observed_revocation(
            &mut self,
            scope: &RevocationScope,
            observed: &RevocationObservation,
        ) -> Result<(), RevocationAdapterError> {
            assert_eq!(observed.binding, self.expected_binding);
            assert_eq!(observed.deny, ObservedDeny::Active);
            assert_eq!(observed.transport, ObservedPresence::Absent);
            assert_eq!(observed.exception, ObservedPresence::Absent);
            assert_eq!(observed.established, ObservedPresence::Absent);
            self.call(scope, RevocationStage::RecordObservation)
        }
    }

    #[test]
    fn revocation_orders_scoped_callbacks_and_is_single_use() {
        let mut adapter = RecordingAdapter::new();
        let mut executor = adapter.executor();
        assert_eq!(executor.state(), RevocationState::Ready);
        executor.execute_revocation(&mut adapter).unwrap();
        assert_eq!(adapter.seen, ORDER);
        assert_eq!(adapter.mutation_attempts, 3);
        assert_eq!(executor.state(), RevocationState::Observed);
        let error = executor.execute_revocation(&mut adapter).unwrap_err();
        assert_eq!(error.cause, RevocationFailure::AlreadyAttempted);
        assert_eq!(error.stage, RevocationStage::Admission);
        assert_eq!(adapter.seen, ORDER);
        assert_eq!(executor.state(), RevocationState::Observed);
    }

    #[test]
    fn every_callback_failure_stops_without_compensation_or_retry() {
        for (index, stage) in ORDER.iter().enumerate() {
            let mut adapter = RecordingAdapter::new();
            adapter.fault = Some(index);
            let mut executor = adapter.executor();
            let error = executor.execute_revocation(&mut adapter).unwrap_err();
            assert_eq!(error.stage, *stage);
            assert_eq!(error.cause, RevocationFailure::AdapterFailed);
            assert_eq!(error.journal_may_exist, index >= 1);
            assert_eq!(error.mutation_attempted, index >= 3);
            assert_eq!(adapter.seen, ORDER[..=index]);
            assert_eq!(executor.state(), RevocationState::Blocked);
            adapter.fault = None;
            assert_eq!(
                executor.execute_revocation(&mut adapter).unwrap_err().cause,
                RevocationFailure::AlreadyAttempted
            );
            assert_eq!(adapter.seen, ORDER[..=index]);
        }
    }

    #[test]
    fn every_inspection_rechecks_all_binding_generations() {
        for observation_index in 0..5 {
            for dimension in 0..4 {
                let mut adapter = RecordingAdapter::new();
                let mut values = [17001, 17002, 17003, 17004];
                values[dimension] += 1;
                adapter.observations[observation_index].binding = binding(values);
                let mut executor = adapter.executor();
                let error = executor.execute_revocation(&mut adapter).unwrap_err();
                assert_eq!(error.cause, RevocationFailure::ContextChanged);
                assert_eq!(error.stage, ORDER[observation_index * 2]);
                assert_eq!(adapter.seen, ORDER[..=observation_index * 2]);
                assert_eq!(executor.state(), RevocationState::Blocked);
                if observation_index <= 1 {
                    assert!(!error.mutation_attempted);
                    assert_eq!(adapter.mutation_attempts, 0);
                }
            }
        }
    }

    #[test]
    fn inactive_or_unknown_deny_stops_at_every_inspection() {
        for index in 0..5 {
            for deny in [ObservedDeny::Inactive, ObservedDeny::Unknown] {
                let mut adapter = RecordingAdapter::new();
                adapter.observations[index].deny = deny;
                let mut executor = adapter.executor();
                let error = executor.execute_revocation(&mut adapter).unwrap_err();
                assert_eq!(error.cause, RevocationFailure::DenyUnproven);
                assert_eq!(adapter.seen, ORDER[..=index * 2]);
                assert_eq!(executor.state(), RevocationState::Blocked);
            }
        }
    }

    #[test]
    fn unknown_transport_exception_or_flows_never_passes() {
        for index in 0..5 {
            for field in 0..3 {
                let mut adapter = RecordingAdapter::new();
                let observed = &mut adapter.observations[index];
                match field {
                    0 => observed.transport = ObservedPresence::Unknown,
                    1 => observed.exception = ObservedPresence::Unknown,
                    _ => observed.established = ObservedPresence::Unknown,
                }
                let mut executor = adapter.executor();
                assert_eq!(
                    executor.execute_revocation(&mut adapter).unwrap_err().cause,
                    RevocationFailure::UnknownState
                );
                assert_eq!(adapter.seen, ORDER[..=index * 2]);
                assert_eq!(executor.state(), RevocationState::Blocked);
            }
        }
    }

    #[test]
    fn incomplete_or_regressed_revocation_prevents_completion() {
        for index in 2..5 {
            for field in 0..(index - 1) {
                let mut adapter = RecordingAdapter::new();
                let observed = &mut adapter.observations[index];
                match field {
                    0 => observed.transport = ObservedPresence::Present,
                    1 => observed.exception = ObservedPresence::Present,
                    _ => observed.established = ObservedPresence::Present,
                }
                let mut executor = adapter.executor();
                assert_eq!(
                    executor.execute_revocation(&mut adapter).unwrap_err().cause,
                    RevocationFailure::RevocationUnproven
                );
                assert_eq!(adapter.seen, ORDER[..=index * 2]);
                assert_eq!(executor.state(), RevocationState::Blocked);
            }
        }
    }

    #[test]
    fn absent_rule_does_not_substitute_for_established_state_revocation() {
        let mut adapter = RecordingAdapter::new();
        adapter.observations[4].established = ObservedPresence::Present;
        let mut executor = adapter.executor();
        let error = executor.execute_revocation(&mut adapter).unwrap_err();
        assert_eq!(error.stage, RevocationStage::FinalInspection);
        assert_eq!(error.cause, RevocationFailure::RevocationUnproven);
        assert!(error.journal_may_exist && error.mutation_attempted);
        assert!(!adapter.seen.contains(&RevocationStage::RecordObservation));
    }

    #[test]
    fn adapter_panic_cannot_make_object_reusable_or_trigger_cleanup() {
        let mut adapter = RecordingAdapter::new();
        adapter.panic_at = Some(3);
        let mut executor = adapter.executor();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute_revocation(&mut adapter)
        }));
        assert!(panic.is_err());
        assert_eq!(executor.state(), RevocationState::Executing);
        assert_eq!(
            executor.execute_revocation(&mut adapter).unwrap_err().cause,
            RevocationFailure::AlreadyAttempted
        );
        drop(executor);
        assert_eq!(adapter.seen, ORDER[..=3]);
    }

    #[test]
    fn revocation_diagnostics_redact_scope_and_expose_only_categories() {
        let mut adapter = RecordingAdapter::new();
        let mut executor = adapter.executor();
        adapter.fault = Some(5);
        let error = executor.execute_revocation(&mut adapter).unwrap_err();
        let diagnostics = format!(
            "{executor:?} {:?} {error:?} {error}",
            adapter.observations[0]
        );
        for secret in [
            "203.0.113.42",
            "8443",
            "en7",
            "utun19",
            "17001",
            "17002",
            "17003",
            "17004",
        ] {
            assert!(!diagnostics.contains(secret));
        }
        assert!(diagnostics.contains("<redacted>"));
        assert!(diagnostics.contains("RemoveException"));
        assert!(diagnostics.contains("AdapterFailed"));
    }

    #[test]
    fn containment_dispatches_once_for_every_post_mutation_callback_error() {
        for (index, stage) in ORDER.iter().enumerate() {
            let mut adapter = RecordingAdapter::new();
            adapter.fault = Some(index);
            let error = adapter.executor().execute(&mut adapter).unwrap_err();
            assert_eq!(
                error.primary,
                EndpointRevocationError {
                    stage: *stage,
                    cause: RevocationFailure::AdapterFailed,
                    journal_may_exist: index >= 1,
                    mutation_attempted: index >= 3,
                }
            );
            assert_eq!(adapter.seen, ORDER[..=index]);
            if index >= 3 {
                assert_eq!(adapter.containment_calls, ["teardown", "inspect"]);
                assert_eq!(adapter.primary, Some(error.primary));
                assert_eq!(error.containment, ContainmentOutcome::TeardownObserved);
            } else {
                assert!(adapter.containment_calls.is_empty());
                assert_eq!(error.containment, ContainmentOutcome::NotRequired);
            }
        }
        let mut adapter = RecordingAdapter::new();
        adapter.executor().execute(&mut adapter).unwrap();
        assert_eq!(adapter.seen, ORDER);
        assert!(adapter.containment_calls.is_empty());
    }

    #[test]
    fn containment_handles_observation_failures_and_context_changes() {
        for index in 0..5 {
            for kind in 0..4 {
                let mut adapter = RecordingAdapter::new();
                let observation = &mut adapter.observations[index];
                match kind {
                    0 => observation.binding = binding([18001, 18002, 18003, 18004]),
                    1 => observation.deny = ObservedDeny::Unknown,
                    2 => observation.transport = ObservedPresence::Unknown,
                    _ => observation.established = ObservedPresence::Unknown,
                }
                let error = adapter.executor().execute(&mut adapter).unwrap_err();
                assert_eq!(error.primary.stage, ORDER[index * 2]);
                assert_eq!(
                    error.primary.cause,
                    match kind {
                        0 => RevocationFailure::ContextChanged,
                        1 => RevocationFailure::DenyUnproven,
                        _ => RevocationFailure::UnknownState,
                    }
                );
                assert_eq!(adapter.seen, ORDER[..=index * 2]);
                assert_eq!(
                    error.containment,
                    if index >= 2 {
                        assert_eq!(adapter.primary, Some(error.primary));
                        assert_eq!(adapter.containment_calls, ["teardown", "inspect"]);
                        ContainmentOutcome::TeardownObserved
                    } else {
                        assert!(adapter.containment_calls.is_empty());
                        ContainmentOutcome::NotRequired
                    }
                );
            }
        }
        let mut adapter = RecordingAdapter::new();
        adapter.observations[4].established = ObservedPresence::Present;
        let error = adapter.executor().execute(&mut adapter).unwrap_err();
        assert_eq!(error.primary.cause, RevocationFailure::RevocationUnproven);
        assert_eq!(adapter.containment_calls, ["teardown", "inspect"]);
    }

    #[test]
    fn containment_failure_and_reported_timeout_preserve_primary_error() {
        for fault in [
            ContainmentAdapterError::Failed,
            ContainmentAdapterError::TimedOut,
        ] {
            for during_inspection in [false, true] {
                let mut adapter = RecordingAdapter::new();
                adapter.fault = Some(3);
                if during_inspection {
                    adapter.cleanup_snapshot = Err(fault);
                } else {
                    adapter.teardown_result = Err(fault);
                }
                let error = adapter.executor().execute(&mut adapter).unwrap_err();
                assert_eq!(error.primary.stage, RevocationStage::StopTransport);
                assert_eq!(error.primary.cause, RevocationFailure::AdapterFailed);
                assert_eq!(adapter.primary, Some(error.primary));
                assert_eq!(
                    error.containment,
                    ContainmentOutcome::RecoveryUnknown(if during_inspection {
                        ContainmentFailure::Inspection(fault)
                    } else {
                        ContainmentFailure::Teardown(fault)
                    })
                );
                assert_eq!(
                    adapter.containment_calls,
                    if during_inspection {
                        vec!["teardown", "inspect"]
                    } else {
                        vec!["teardown"]
                    }
                );
                assert_eq!(adapter.seen, ORDER[..=3]);
                assert!(error.primary.journal_may_exist);
            }
        }
    }

    #[test]
    fn containment_requires_every_owned_resource_absent() {
        for presence in [ObservedPresence::Present, ObservedPresence::Unknown] {
            for field in 0..5 {
                let mut adapter = RecordingAdapter::new();
                adapter.fault = Some(5);
                let snapshot = adapter.cleanup_snapshot.as_mut().unwrap();
                match field {
                    0 => snapshot.engine = presence,
                    1 => snapshot.transport = presence,
                    2 => snapshot.resources = presence,
                    3 => snapshot.exceptions = presence,
                    _ => snapshot.established = presence,
                }
                let error = adapter.executor().execute(&mut adapter).unwrap_err();
                assert_eq!(
                    error.containment,
                    ContainmentOutcome::RecoveryUnknown(if presence == ObservedPresence::Unknown {
                        ContainmentFailure::UnknownState
                    } else {
                        ContainmentFailure::ResidualState
                    })
                );
                assert_eq!(adapter.primary, Some(error.primary));
                assert_eq!(adapter.containment_calls, ["teardown", "inspect"]);
            }
        }
    }

    #[test]
    fn containment_rejects_each_wrong_owner_generation_and_unproven_deny() {
        for field in 0..4 {
            let mut adapter = RecordingAdapter::new();
            adapter.fault = Some(7);
            let mut values = [17001, 17002, 17003, 17004];
            values[field] += 1;
            adapter.cleanup_snapshot.as_mut().unwrap().owner = binding(values);
            let error = adapter.executor().execute(&mut adapter).unwrap_err();
            assert_eq!(
                error.containment,
                ContainmentOutcome::RecoveryUnknown(ContainmentFailure::WrongOwner)
            );
        }
        for deny in [ObservedDeny::Inactive, ObservedDeny::Unknown] {
            let mut adapter = RecordingAdapter::new();
            adapter.fault = Some(7);
            adapter.cleanup_snapshot.as_mut().unwrap().deny = deny;
            let error = adapter.executor().execute(&mut adapter).unwrap_err();
            assert_eq!(
                error.containment,
                ContainmentOutcome::RecoveryUnknown(ContainmentFailure::DenyUnproven)
            );
        }
    }

    #[test]
    fn containment_diagnostics_redact_owner_and_preserve_error_source() {
        let mut adapter = RecordingAdapter::new();
        adapter.fault = Some(3);
        let snapshot = adapter.cleanup_snapshot.unwrap();
        let error = adapter.executor().execute(&mut adapter).unwrap_err();
        let diagnostics = format!("{snapshot:?} {error:?} {error}");
        for secret in [
            "17001",
            "17002",
            "17003",
            "17004",
            "203.0.113.42",
            "8443",
            "en7",
            "utun19",
        ] {
            assert!(!diagnostics.contains(secret));
        }
        assert!(diagnostics.contains("<redacted>"));
        let source = std::error::Error::source(&error).unwrap();
        assert_eq!(
            source.downcast_ref::<EndpointRevocationError>(),
            Some(&error.primary)
        );
    }
}
