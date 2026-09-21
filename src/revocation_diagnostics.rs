//! Bounded, opt-in in-memory retention of allowlisted revocation diagnostics.
//! Opt-in execution composition; no global runtime instrumentation, persistent logging or authority.

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::endpoint_revocation::{
    EndpointContainmentAdapter, EndpointRevocation, RevocationContainmentError,
    RevocationDiagnostic,
};

pub const MAX_REVOCATION_DIAGNOSTIC_RECORDS: usize = 64;
pub const MAX_REVOCATION_SNAPSHOT_JSON_BYTES: usize = 33 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RevocationDiagnosticBufferError {
    #[error("revocation diagnostic capacity must be between 1 and 64")]
    InvalidCapacity,
    #[error("revocation diagnostic loss counter is exhausted; record was not retained")]
    CounterExhausted,
}

/// The original failure remains authoritative even if diagnostic retention fails.
/// Raw domain errors are deliberately not a serialization surface:
/// ```compile_fail,E0277
/// use novaray_core::revocation_diagnostics::RecordedRevocationError;
/// fn serializable<T: serde::Serialize>() {}
/// serializable::<RecordedRevocationError>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("endpoint revocation failed; diagnostic recording error: {recording_error:?}")]
pub struct RecordedRevocationError {
    #[source]
    pub revocation: RevocationContainmentError,
    /// None means the diagnostic was retained, never that revocation succeeded.
    pub recording_error: Option<RevocationDiagnosticBufferError>,
}

/// Consume once, finish mandatory containment, then attempt to retain a returned failure once.
/// Success does not touch diagnostics. No retry, buffer reset, panic interception or native work.
/// ```compile_fail,E0382
/// use novaray_core::endpoint_revocation::{EndpointRevocation, EndpointContainmentAdapter};
/// use novaray_core::revocation_diagnostics::{execute_revocation_with_diagnostics, RevocationDiagnosticBuffer};
/// fn retry(operation: EndpointRevocation, adapter: &mut impl EndpointContainmentAdapter,
///          buffer: &mut RevocationDiagnosticBuffer) {
///     let _ = execute_revocation_with_diagnostics(operation, adapter, buffer);
///     let _ = execute_revocation_with_diagnostics(operation, adapter, buffer);
/// }
/// ```
pub fn execute_revocation_with_diagnostics(
    operation: EndpointRevocation,
    adapter: &mut impl EndpointContainmentAdapter,
    buffer: &mut RevocationDiagnosticBuffer,
) -> Result<(), RecordedRevocationError> {
    operation.execute(adapter).map_err(|revocation| {
        let recording_error = buffer.record(&revocation).err();
        RecordedRevocationError {
            revocation,
            recording_error,
        }
    })
}

pub struct RevocationDiagnosticBuffer {
    capacity: usize,
    dropped_records: u64,
    records: VecDeque<RevocationDiagnostic>,
}

impl fmt::Debug for RevocationDiagnosticBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationDiagnosticBuffer")
            .field("capacity", &self.capacity)
            .field("retained_records", &self.records.len())
            .field("dropped_records", &self.dropped_records)
            .finish()
    }
}

/// Immutable borrowed view, not an authenticated log or a complete diagnostic bundle.
/// Compact serde_json is bounded to 33 KiB: <=64 records of <=512 bytes, plus envelope/separators.
/// Pretty/custom serialization is not covered. Mutation is forbidden while the view is used:
/// ```compile_fail,E0502
/// use novaray_core::revocation_diagnostics::RevocationDiagnosticBuffer;
/// let mut buffer = RevocationDiagnosticBuffer::new(1).unwrap();
/// let snapshot = buffer.snapshot();
/// buffer.clear();
/// serde_json::to_string(&snapshot).unwrap();
/// ```
/// There is no input/deserialization path:
/// ```compile_fail,E0277
/// use novaray_core::revocation_diagnostics::RevocationDiagnosticSnapshot;
/// let _: RevocationDiagnosticSnapshot<'_> = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Serialize)]
pub struct RevocationDiagnosticSnapshot<'a> {
    schema_version: u8,
    capacity: usize,
    dropped_records: u64,
    records: &'a VecDeque<RevocationDiagnostic>,
}

impl RevocationDiagnosticBuffer {
    pub fn new(capacity: usize) -> Result<Self, RevocationDiagnosticBufferError> {
        if !(1..=MAX_REVOCATION_DIAGNOSTIC_RECORDS).contains(&capacity) {
            return Err(RevocationDiagnosticBufferError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            dropped_records: 0,
            records: VecDeque::with_capacity(capacity),
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped_records(&self) -> u64 {
        self.dropped_records
    }

    /// Capture only the safe projection. A retention failure must not replace the original error.
    pub fn record(
        &mut self,
        error: &RevocationContainmentError,
    ) -> Result<(), RevocationDiagnosticBufferError> {
        let full = self.records.len() == self.capacity;
        // Check accounting before eviction so overflow cannot silently lose either record.
        let dropped_records = if full {
            self.dropped_records
                .checked_add(1)
                .ok_or(RevocationDiagnosticBufferError::CounterExhausted)?
        } else {
            self.dropped_records
        };
        let record = error.diagnostic();
        if full {
            self.records.pop_front();
        }
        self.records.push_back(record);
        self.dropped_records = dropped_records;
        Ok(())
    }

    pub fn snapshot(&self) -> RevocationDiagnosticSnapshot<'_> {
        RevocationDiagnosticSnapshot {
            schema_version: 1,
            capacity: self.capacity,
            dropped_records: self.dropped_records,
            records: &self.records,
        }
    }

    /// Logical clearing only: does not wipe allocation contents or invalidate already copied JSON.
    pub fn clear(&mut self) {
        self.records.clear();
        self.dropped_records = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_revocation::{
        ContainmentAdapterError, ContainmentFailure, ContainmentOutcome, EndpointRevocationError,
        PreMutationRecovery, RevocationFailure, RevocationStage,
    };
    use serde_json::json;

    fn error(index: usize) -> RevocationContainmentError {
        RevocationContainmentError {
            primary: EndpointRevocationError {
                stage: [
                    RevocationStage::InitialInspection,
                    RevocationStage::StopTransport,
                    RevocationStage::ExceptionInspection,
                ][index % 3],
                cause: [
                    RevocationFailure::DenyUnproven,
                    RevocationFailure::AdapterFailed,
                ][index % 2],
                journal_may_exist: index.is_multiple_of(5),
                mutation_attempted: index.is_multiple_of(7),
            },
            containment: if index.is_multiple_of(2) {
                ContainmentOutcome::RecoveryRequiredBeforeMutation(
                    PreMutationRecovery::DenyUnproven,
                )
            } else {
                ContainmentOutcome::RecoveryUnknown(ContainmentFailure::Inspection(
                    ContainmentAdapterError::TimedOut,
                ))
            },
        }
    }

    #[test]
    fn capacity_is_validated_and_empty_snapshot_has_exact_fields() {
        for capacity in [0, 65, usize::MAX] {
            assert_eq!(
                RevocationDiagnosticBuffer::new(capacity).unwrap_err(),
                RevocationDiagnosticBufferError::InvalidCapacity
            );
        }
        for capacity in 1..=64 {
            let buffer = RevocationDiagnosticBuffer::new(capacity).unwrap();
            assert!(buffer.is_empty());
            assert_eq!(buffer.len(), 0);
            assert_eq!(buffer.capacity(), capacity);
            assert_eq!(buffer.dropped_records(), 0);
            assert_eq!(
                serde_json::to_value(buffer.snapshot()).unwrap(),
                json!({"schema_version":1,"capacity":capacity,"dropped_records":0,"records":[]})
            );
        }
    }

    #[test]
    fn every_capacity_retains_fifo_and_counts_every_eviction() {
        for capacity in 1..=64 {
            let mut buffer = RevocationDiagnosticBuffer::new(capacity).unwrap();
            let mut history = Vec::new();
            for index in 0..(capacity * 3 + 2) {
                let error = error(index);
                history.push(serde_json::to_value(error.diagnostic()).unwrap());
                buffer.record(&error).unwrap();
                let lost = history.len().saturating_sub(capacity);
                assert_eq!(buffer.len(), history.len().min(capacity));
                assert!(!buffer.is_empty());
                assert_eq!(buffer.dropped_records(), lost as u64);
                assert_eq!(
                    serde_json::to_value(buffer.snapshot()).unwrap(),
                    json!({"schema_version":1,"capacity":capacity,
                        "dropped_records":lost,"records":history[lost..]})
                );
            }
        }
    }

    #[test]
    fn repeated_events_are_not_coalesced_or_silently_lost() {
        let mut buffer = RevocationDiagnosticBuffer::new(2).unwrap();
        for _ in 0..5 {
            buffer.record(&error(0)).unwrap();
        }
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.dropped_records(), 3);
        assert_eq!(buffer.records[0], buffer.records[1]);
    }

    #[test]
    fn counter_overflow_rejects_append_without_any_state_change() {
        let mut buffer = RevocationDiagnosticBuffer::new(2).unwrap();
        buffer.record(&error(0)).unwrap();
        buffer.record(&error(1)).unwrap();
        buffer.dropped_records = u64::MAX - 1;
        buffer.record(&error(2)).unwrap();
        assert_eq!(buffer.dropped_records(), u64::MAX);
        let before = serde_json::to_string(&buffer.snapshot()).unwrap();
        assert_eq!(
            buffer.record(&error(3)),
            Err(RevocationDiagnosticBufferError::CounterExhausted)
        );
        assert_eq!(serde_json::to_string(&buffer.snapshot()).unwrap(), before);
    }

    #[test]
    fn clear_resets_records_and_loss_count_but_preserves_capacity() {
        let mut buffer = RevocationDiagnosticBuffer::new(2).unwrap();
        for index in 0..4 {
            buffer.record(&error(index)).unwrap();
        }
        buffer.dropped_records = u64::MAX;
        buffer.clear();
        buffer.clear();
        assert_eq!(buffer.capacity(), 2);
        assert!(buffer.is_empty());
        assert_eq!(buffer.dropped_records(), 0);
        buffer.record(&error(5)).unwrap();
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.records[0], error(5).diagnostic());
        assert_eq!(buffer.dropped_records(), 0);
    }

    #[test]
    fn compact_snapshot_stays_bounded_at_max_capacity_and_counter() {
        let mut buffer = RevocationDiagnosticBuffer::new(64).unwrap();
        for index in 0..64 {
            buffer.record(&error(index)).unwrap();
        }
        buffer.dropped_records = u64::MAX;
        let compact = serde_json::to_string(&buffer.snapshot()).unwrap();
        assert!(compact.len() <= MAX_REVOCATION_SNAPSHOT_JSON_BYTES);
        // Task 75 bounds every record variant, including those not selected by this fixture.
        let envelope = serde_json::to_string(&json!({
            "schema_version":1,"capacity":64,"dropped_records":u64::MAX,"records":[]
        }))
        .unwrap();
        assert!(envelope.len() + 64 * 512 + 63 <= MAX_REVOCATION_SNAPSHOT_JSON_BYTES);
    }

    use crate::endpoint_bootstrap::BootstrapBinding;
    use crate::endpoint_revocation::{
        ContainmentObservation, EndpointContainmentAdapter, EndpointRevocationAdapter,
        ObservedDeny, ObservedPresence, RevocationAdapterError, RevocationObservation,
        RevocationScope,
    };
    use crate::kill_switch::{EndpointTransport, KillSwitchAllowlist, TunnelIpFamily};
    use std::num::NonZeroU64;

    struct RecordingAdapter {
        calls: Vec<&'static str>,
        fail_at: Option<usize>,
        panic_at: Option<usize>,
        containment_mode: u8,
        stopped: bool,
        removed: bool,
        cleared: bool,
    }

    impl RecordingAdapter {
        fn new(fail_at: Option<usize>, containment_mode: u8) -> Self {
            Self {
                calls: Vec::new(),
                fail_at,
                panic_at: None,
                containment_mode,
                stopped: false,
                removed: false,
                cleared: false,
            }
        }

        fn call(&mut self, name: &'static str) -> Result<(), RevocationAdapterError> {
            let index = self.calls.len();
            self.calls.push(name);
            assert_ne!(self.panic_at, Some(index), "injected adapter panic");
            if self.fail_at == Some(index) {
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
            self.call("inspect")?;
            let presence = |absent| {
                if absent {
                    ObservedPresence::Absent
                } else {
                    ObservedPresence::Present
                }
            };
            Ok(RevocationObservation {
                binding: scope.binding(),
                deny: ObservedDeny::Active,
                transport: presence(self.stopped),
                exception: presence(self.removed),
                established: presence(self.cleared),
            })
        }
        fn record_intent(
            &mut self,
            _: &RevocationScope,
            _: &RevocationObservation,
        ) -> Result<(), RevocationAdapterError> {
            self.call("intent")
        }
        fn stop_transport(&mut self, _: &RevocationScope) -> Result<(), RevocationAdapterError> {
            self.stopped = true;
            self.call("stop")
        }
        fn remove_exception(&mut self, _: &RevocationScope) -> Result<(), RevocationAdapterError> {
            self.removed = true;
            self.call("remove")
        }
        fn clear_established(&mut self, _: &RevocationScope) -> Result<(), RevocationAdapterError> {
            self.cleared = true;
            self.call("clear")
        }
        fn record_observed_revocation(
            &mut self,
            _: &RevocationScope,
            _: &RevocationObservation,
        ) -> Result<(), RevocationAdapterError> {
            self.call("observed")
        }
    }

    impl EndpointContainmentAdapter for RecordingAdapter {
        fn teardown_connection(
            &mut self,
            _: &RevocationScope,
            _: &EndpointRevocationError,
        ) -> Result<(), ContainmentAdapterError> {
            self.call("teardown").unwrap();
            if self.containment_mode == 1 {
                Err(ContainmentAdapterError::TimedOut)
            } else {
                Ok(())
            }
        }
        fn inspect_connection_after_teardown(
            &mut self,
            scope: &RevocationScope,
        ) -> Result<ContainmentObservation, ContainmentAdapterError> {
            self.call("inspect_cleanup").unwrap();
            if self.containment_mode == 2 {
                return Err(ContainmentAdapterError::Failed);
            }
            Ok(ContainmentObservation {
                owner: scope.binding(),
                deny: ObservedDeny::Active,
                engine: ObservedPresence::Absent,
                transport: ObservedPresence::Absent,
                resources: ObservedPresence::Absent,
                exceptions: ObservedPresence::Absent,
                established: ObservedPresence::Absent,
            })
        }
    }

    fn operation() -> EndpointRevocation {
        let [session, request, profile, network] =
            [1, 2, 3, 4].map(|v| NonZeroU64::new(v).unwrap());
        EndpointRevocation::new(
            KillSwitchAllowlist::new(
                "203.0.113.42:8443".parse().unwrap(),
                EndpointTransport::Tcp,
                "en7".into(),
                "utun19".into(),
                TunnelIpFamily::Ipv4,
            )
            .unwrap(),
            BootstrapBinding::new(session, request, profile, network),
        )
    }

    #[test]
    fn recorded_success_leaves_even_exhausted_buffer_unchanged() {
        for counter in [0, u64::MAX] {
            let mut buffer = RevocationDiagnosticBuffer::new(1).unwrap();
            buffer.record(&error(0)).unwrap();
            buffer.dropped_records = counter;
            let before = serde_json::to_string(&buffer.snapshot()).unwrap();
            let mut adapter = RecordingAdapter::new(None, 0);
            assert_eq!(
                execute_revocation_with_diagnostics(operation(), &mut adapter, &mut buffer),
                Ok(())
            );
            assert_eq!(
                adapter.calls,
                [
                    "inspect", "intent", "inspect", "stop", "inspect", "remove", "inspect",
                    "clear", "inspect", "observed"
                ]
            );
            assert_eq!(serde_json::to_string(&buffer.snapshot()).unwrap(), before);
        }
    }

    #[test]
    fn recorded_failures_preserve_execute_result_and_final_containment_once() {
        for fail_at in 0..10 {
            for mode in 0..3 {
                let mut baseline = RecordingAdapter::new(Some(fail_at), mode);
                let expected = operation().execute(&mut baseline).unwrap_err();
                let mut adapter = RecordingAdapter::new(Some(fail_at), mode);
                let mut buffer = RevocationDiagnosticBuffer::new(1).unwrap();
                buffer.record(&error(0)).unwrap();
                buffer.dropped_records = 17;
                let actual =
                    execute_revocation_with_diagnostics(operation(), &mut adapter, &mut buffer)
                        .unwrap_err();
                assert_eq!(actual.revocation, expected);
                assert_eq!(actual.recording_error, None);
                assert_eq!(adapter.calls, baseline.calls);
                assert_eq!(buffer.dropped_records(), 18);
                assert_eq!(buffer.records, VecDeque::from([expected.diagnostic()]));
                let source = std::error::Error::source(&actual).unwrap();
                assert_eq!(
                    source.downcast_ref::<RevocationContainmentError>(),
                    Some(&expected)
                );
                let primary = source.source().unwrap();
                assert_eq!(
                    primary.downcast_ref::<EndpointRevocationError>(),
                    Some(&expected.primary)
                );
                assert!(!actual.to_string().contains(&expected.primary.to_string()));
            }
        }
    }

    #[test]
    fn exhausted_recording_never_preempts_containment_or_replaces_failure() {
        for fail_at in 0..10 {
            for mode in 0..3 {
                let mut baseline = RecordingAdapter::new(Some(fail_at), mode);
                let expected = operation().execute(&mut baseline).unwrap_err();
                let mut adapter = RecordingAdapter::new(Some(fail_at), mode);
                let mut buffer = RevocationDiagnosticBuffer::new(1).unwrap();
                buffer.record(&error(0)).unwrap();
                buffer.dropped_records = u64::MAX;
                let before = serde_json::to_string(&buffer.snapshot()).unwrap();
                let actual =
                    execute_revocation_with_diagnostics(operation(), &mut adapter, &mut buffer)
                        .unwrap_err();
                assert_eq!(actual.revocation, expected);
                assert_eq!(
                    actual.recording_error,
                    Some(RevocationDiagnosticBufferError::CounterExhausted)
                );
                assert_eq!(adapter.calls, baseline.calls);
                assert_eq!(serde_json::to_string(&buffer.snapshot()).unwrap(), before);
                assert_eq!(
                    std::error::Error::source(&actual)
                        .unwrap()
                        .downcast_ref::<RevocationContainmentError>(),
                    Some(&expected)
                );
            }
        }
    }

    #[test]
    fn adapter_panic_is_not_converted_to_a_recorded_result() {
        let mut buffer = RevocationDiagnosticBuffer::new(1).unwrap();
        buffer.record(&error(0)).unwrap();
        let before = serde_json::to_string(&buffer.snapshot()).unwrap();
        let mut adapter = RecordingAdapter::new(Some(3), 0);
        adapter.panic_at = Some(4);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = execute_revocation_with_diagnostics(operation(), &mut adapter, &mut buffer);
        }));
        assert!(panic.is_err());
        assert_eq!(
            adapter.calls,
            ["inspect", "intent", "inspect", "stop", "teardown"]
        );
        assert_eq!(serde_json::to_string(&buffer.snapshot()).unwrap(), before);
    }
}
