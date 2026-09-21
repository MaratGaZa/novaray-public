//! Bounded, opt-in in-memory retention of allowlisted revocation diagnostics.
//! No runtime instrumentation, persistent logging, event authentication or recovery authority.

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::endpoint_revocation::{RevocationContainmentError, RevocationDiagnostic};

pub const MAX_REVOCATION_DIAGNOSTIC_RECORDS: usize = 64;
pub const MAX_REVOCATION_SNAPSHOT_JSON_BYTES: usize = 33 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RevocationDiagnosticBufferError {
    #[error("revocation diagnostic capacity must be between 1 and 64")]
    InvalidCapacity,
    #[error("revocation diagnostic loss counter is exhausted; record was not retained")]
    CounterExhausted,
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
}
