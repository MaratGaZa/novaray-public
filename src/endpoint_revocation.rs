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

    pub fn execute(
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
        executor.execute(&mut adapter).unwrap();
        assert_eq!(adapter.seen, ORDER);
        assert_eq!(adapter.mutation_attempts, 3);
        assert_eq!(executor.state(), RevocationState::Observed);
        let error = executor.execute(&mut adapter).unwrap_err();
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
            let error = executor.execute(&mut adapter).unwrap_err();
            assert_eq!(error.stage, *stage);
            assert_eq!(error.cause, RevocationFailure::AdapterFailed);
            assert_eq!(error.journal_may_exist, index >= 1);
            assert_eq!(error.mutation_attempted, index >= 3);
            assert_eq!(adapter.seen, ORDER[..=index]);
            assert_eq!(executor.state(), RevocationState::Blocked);
            adapter.fault = None;
            assert_eq!(
                executor.execute(&mut adapter).unwrap_err().cause,
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
                let error = executor.execute(&mut adapter).unwrap_err();
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
                let error = executor.execute(&mut adapter).unwrap_err();
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
                    executor.execute(&mut adapter).unwrap_err().cause,
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
                    executor.execute(&mut adapter).unwrap_err().cause,
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
        let error = executor.execute(&mut adapter).unwrap_err();
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
            executor.execute(&mut adapter)
        }));
        assert!(panic.is_err());
        assert_eq!(executor.state(), RevocationState::Executing);
        assert_eq!(
            executor.execute(&mut adapter).unwrap_err().cause,
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
        let error = executor.execute(&mut adapter).unwrap_err();
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
}
