use novaray_core::endpoint_bootstrap::BootstrapBinding;
use novaray_core::endpoint_revocation::*;
use novaray_core::kill_switch::{EndpointTransport, KillSwitchAllowlist, TunnelIpFamily};
use std::num::NonZeroU64;

struct ExternalAdapter {
    calls: Vec<&'static str>,
    owner: BootstrapBinding,
    policy: KillSwitchAllowlist,
}

impl ExternalAdapter {
    fn check_scope(&self, scope: &RevocationScope) {
        assert_eq!(scope.binding(), self.owner);
        assert_eq!(scope.policy(), &self.policy);
    }
}

impl EndpointRevocationAdapter for ExternalAdapter {
    fn inspect(
        &mut self,
        scope: &RevocationScope,
    ) -> Result<RevocationObservation, RevocationAdapterError> {
        self.check_scope(scope);
        self.calls.push("inspect");
        Ok(RevocationObservation {
            binding: self.owner,
            deny: ObservedDeny::Active,
            transport: ObservedPresence::Present,
            exception: ObservedPresence::Present,
            established: ObservedPresence::Present,
        })
    }

    fn record_intent(
        &mut self,
        scope: &RevocationScope,
        _: &RevocationObservation,
    ) -> Result<(), RevocationAdapterError> {
        self.check_scope(scope);
        self.calls.push("intent");
        Ok(())
    }

    fn stop_transport(&mut self, scope: &RevocationScope) -> Result<(), RevocationAdapterError> {
        self.check_scope(scope);
        self.calls.push("stop");
        Err(RevocationAdapterError)
    }

    fn remove_exception(&mut self, _: &RevocationScope) -> Result<(), RevocationAdapterError> {
        panic!("revocation must stop after the first failure")
    }

    fn clear_established(&mut self, _: &RevocationScope) -> Result<(), RevocationAdapterError> {
        panic!("revocation must stop after the first failure")
    }

    fn record_observed_revocation(
        &mut self,
        _: &RevocationScope,
        _: &RevocationObservation,
    ) -> Result<(), RevocationAdapterError> {
        panic!("failed revocation must not be recorded as observed")
    }
}

impl EndpointContainmentAdapter for ExternalAdapter {
    fn teardown_connection(
        &mut self,
        scope: &RevocationScope,
        primary: &EndpointRevocationError,
    ) -> Result<(), ContainmentAdapterError> {
        self.check_scope(scope);
        assert_eq!(primary.stage, RevocationStage::StopTransport);
        assert!(primary.mutation_attempted);
        self.calls.push("teardown");
        Ok(())
    }

    fn inspect_connection_after_teardown(
        &mut self,
        scope: &RevocationScope,
    ) -> Result<ContainmentObservation, ContainmentAdapterError> {
        self.check_scope(scope);
        self.calls.push("inspect_cleanup");
        Ok(ContainmentObservation {
            owner: self.owner,
            deny: ObservedDeny::Active,
            engine: ObservedPresence::Absent,
            transport: ObservedPresence::Absent,
            resources: ObservedPresence::Absent,
            exceptions: ObservedPresence::Absent,
            established: ObservedPresence::Absent,
        })
    }
}

#[test]
fn public_revocation_entry_dispatches_containment_and_keeps_primary_failure() {
    let [session, request, profile, network] = [1, 2, 3, 4].map(|v| NonZeroU64::new(v).unwrap());
    let owner = BootstrapBinding::new(session, request, profile, network);
    let policy = KillSwitchAllowlist::new(
        "203.0.113.42:8443".parse().unwrap(),
        EndpointTransport::Tcp,
        "en7".into(),
        "utun19".into(),
        TunnelIpFamily::Ipv4,
    )
    .unwrap();
    let operation = EndpointRevocation::new(policy.clone(), owner);
    let mut adapter = ExternalAdapter {
        calls: Vec::new(),
        owner,
        policy,
    };
    let error = operation.execute(&mut adapter).unwrap_err();
    assert_eq!(
        adapter.calls,
        [
            "inspect",
            "intent",
            "inspect",
            "stop",
            "teardown",
            "inspect_cleanup"
        ]
    );
    assert_eq!(
        error.primary,
        EndpointRevocationError {
            stage: RevocationStage::StopTransport,
            cause: RevocationFailure::AdapterFailed,
            journal_may_exist: true,
            mutation_attempted: true,
        }
    );
    assert_eq!(error.containment, ContainmentOutcome::TeardownObserved);
}
