use novaray_core::endpoint_bootstrap::BootstrapBinding;
use novaray_core::endpoint_revocation::*;
use novaray_core::kill_switch::{EndpointTransport, KillSwitchAllowlist, TunnelIpFamily};
use std::num::NonZeroU64;

struct ExternalAdapter {
    calls: Vec<&'static str>,
    owner: BootstrapBinding,
    policy: KillSwitchAllowlist,
    deny: ObservedDeny,
}

impl ExternalAdapter {
    fn new(deny: ObservedDeny) -> Self {
        let [session, request, profile, network] =
            [1, 2, 3, 4].map(|v| NonZeroU64::new(v).unwrap());
        let owner = BootstrapBinding::new(session, request, profile, network);
        let policy = KillSwitchAllowlist::new(
            "203.0.113.42:8443".parse().unwrap(),
            EndpointTransport::Tcp,
            "en7".into(),
            "utun19".into(),
            TunnelIpFamily::Ipv4,
        )
        .unwrap();
        Self {
            calls: Vec::new(),
            owner,
            policy,
            deny,
        }
    }

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
            deny: self.deny,
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
    let mut adapter = ExternalAdapter::new(ObservedDeny::Active);
    let operation = EndpointRevocation::new(adapter.policy.clone(), adapter.owner);
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

#[test]
fn public_initial_unproven_deny_requires_recovery_not_blind_cleanup() {
    for deny in [ObservedDeny::Inactive, ObservedDeny::Unknown] {
        let mut adapter = ExternalAdapter::new(deny);
        let operation = EndpointRevocation::new(adapter.policy.clone(), adapter.owner);
        let error = operation.execute(&mut adapter).unwrap_err();
        assert_eq!(adapter.calls, ["inspect"]);
        assert_eq!(
            error.primary,
            EndpointRevocationError {
                stage: RevocationStage::InitialInspection,
                cause: RevocationFailure::DenyUnproven,
                journal_may_exist: false,
                mutation_attempted: false,
            }
        );
        assert_eq!(
            error.containment,
            ContainmentOutcome::RecoveryRequiredBeforeMutation(PreMutationRecovery::DenyUnproven,)
        );
    }
}

#[test]
fn public_diagnostic_records_preserve_categories_without_owner_or_policy() {
    for deny in [ObservedDeny::Inactive, ObservedDeny::Active] {
        let mut outputs = Vec::new();
        for alternate_scope in [false, true] {
            let mut adapter = ExternalAdapter::new(deny);
            if alternate_scope {
                let [session, request, profile, network] =
                    [9001, 9002, 9003, 9004].map(|v| NonZeroU64::new(v).unwrap());
                adapter.owner = BootstrapBinding::new(session, request, profile, network);
                adapter.policy = KillSwitchAllowlist::new(
                    "198.51.100.18:9443".parse().unwrap(),
                    EndpointTransport::Udp,
                    "en9".into(),
                    "utun21".into(),
                    TunnelIpFamily::Ipv4,
                )
                .unwrap();
            }
            let operation = EndpointRevocation::new(adapter.policy.clone(), adapter.owner);
            let error = operation.execute(&mut adapter).unwrap_err();
            let diagnostic = error.diagnostic();
            let output = serde_json::to_string(&diagnostic).unwrap();
            let value: serde_json::Value = serde_json::from_str(&output).unwrap();
            let attempted = deny == ObservedDeny::Active;
            assert_eq!(
                value["primary"]["stage"],
                if attempted {
                    "stop_transport"
                } else {
                    "initial_inspection"
                }
            );
            assert_eq!(
                value["primary"]["cause"],
                if attempted {
                    "adapter_failed"
                } else {
                    "deny_unproven"
                }
            );
            assert_eq!(value["primary"]["mutation_attempted"], attempted);
            assert_eq!(value["primary"]["journal_may_exist"], attempted);
            assert_eq!(
                value["containment"]["outcome"],
                if attempted {
                    "teardown_observed"
                } else {
                    "recovery_required_before_mutation"
                }
            );
            let debug = format!("{diagnostic:?}");
            for secret in [
                "203.0.113.42",
                "198.51.100.18",
                "8443",
                "9443",
                "en7",
                "en9",
                "utun19",
                "utun21",
                "9001",
                "9002",
                "9003",
                "9004",
            ] {
                assert!(!output.contains(secret));
                assert!(!debug.contains(secret));
            }
            outputs.push(output);
        }
        assert_eq!(outputs[0], outputs[1]);
    }
}
