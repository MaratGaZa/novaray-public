use serde::{Deserialize, Serialize};

pub(super) const DEADLINE_SECONDS: u64 = 120;
pub(super) const PREFIX: &str = "org.novaray.validation.runtime-right.";

// No Deserialize/Clone: a run name is generated inside this process, not loaded from a manifest.
pub(super) struct TestName(String);

impl TestName {
    pub(super) fn from_entropy(bytes: [u8; 16]) -> Self {
        Self(format!("{PREFIX}{}", hex::encode(bytes)))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    pub environment: String,
    pub os_build: String,
    pub sdk: String,
    pub reviewed_commit: String,
    pub reviewed_sha256: String,
    pub restore_evidence: String,
    pub disposable: bool,
    pub restore_tested: bool,
    pub exclusive_writers: bool,
    pub allow_authorization_interaction: bool,
    pub confirmation: String,
}

impl Approval {
    pub(super) fn validate(&self, name: &TestName, digest: &str, os_build: &str) -> bool {
        let bounded = [
            &self.environment,
            &self.os_build,
            &self.sdk,
            &self.restore_evidence,
        ]
        .iter()
        .all(|s| {
            !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        });
        bounded
            && self.disposable
            && self.restore_tested
            && self.exclusive_writers
            && self.allow_authorization_interaction
            && self.os_build == os_build
            && is_hex(&self.reviewed_commit, 40)
            && is_hex(&self.reviewed_sha256, 64)
            && self.reviewed_sha256 == digest
            && self.confirmation
                == format!("CREATE READ REMOVE {} {DEADLINE_SECONDS}", name.as_str())
    }
}

fn is_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum Observation {
    Absent,
    Exact,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum Failure {
    Denied,
    Canceled,
    InteractionNotAllowed,
    Api,
    Inspection,
    Journal,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum Record {
    Baseline(Observation),
    AuthorizationResult(Result<(), Failure>),
    BeforeCreate(Observation),
    CreateIntent,
    CreateResult(Result<(), Failure>),
    Created(Observation),
    BeforeRemove(Observation),
    RemoveIntent,
    RemoveResult(Result<(), Failure>),
    Removed(Observation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum Stop {
    Refused,
    Quarantine {
        primary: Failure,
        journal_failed: bool,
    },
}

/// Not the production fixed-right adapter. Owns one fresh name and one uninterrupted run.
/// `inspect` must durably record bounded complete shape information, without arbitrary values.
pub(super) trait Adapter {
    fn checkpoint(&mut self) -> Result<(), Failure>;
    fn record(&mut self, record: Record) -> Result<(), Failure>;
    fn inspect(&mut self) -> Result<Observation, Failure>;
    fn authorize(&mut self) -> Result<(), Failure>;
    fn create(&mut self) -> Result<(), Failure>;
    fn remove(&mut self) -> Result<(), Failure>;
}

/// No retry/resume or compensating delete. On ambiguity the approved whole environment is
/// quarantined instead. Exact equality does not establish provenance against an external writer.
pub(super) fn execute(adapter: &mut impl Adapter) -> Result<(), Stop> {
    let result = execute_inner(adapter);
    result.map_err(|(primary, journal_failed, started)| {
        if started {
            Stop::Quarantine {
                primary,
                journal_failed,
            }
        } else {
            Stop::Refused
        }
    })
}

fn execute_inner(a: &mut impl Adapter) -> Result<(), (Failure, bool, bool)> {
    // 'started' is conservative: once the baseline was inspected, a conflicting pre-existing
    // test name also quarantines the environment; never adopt it as a resumable experiment.
    a.checkpoint().map_err(|e| (e, false, false))?;
    let baseline = a.inspect().map_err(|e| (e, e == Failure::Journal, true))?;
    a.record(Record::Baseline(baseline))
        .map_err(|e| (e, true, true))?;
    if baseline != Observation::Absent {
        return Err((Failure::Inspection, false, true));
    }
    a.checkpoint().map_err(|e| (e, false, false))?;
    let authorization = a.authorize();
    a.record(Record::AuthorizationResult(authorization))
        .map_err(|e| (e, true, true))?;
    authorization.map_err(|e| (e, false, false))?;
    checked_read(a, Record::BeforeCreate, Observation::Absent)?;
    mutation(a, Record::CreateIntent, true)?;
    checked_read(a, Record::Created, Observation::Exact)?;
    checked_read(a, Record::BeforeRemove, Observation::Exact)?;
    mutation(a, Record::RemoveIntent, false)?;
    checked_read(a, Record::Removed, Observation::Absent)
}

fn checked_read(
    a: &mut impl Adapter,
    record: fn(Observation) -> Record,
    expected: Observation,
) -> Result<(), (Failure, bool, bool)> {
    a.checkpoint().map_err(|e| (e, false, true))?;
    let observed = a.inspect().map_err(|e| (e, e == Failure::Journal, true))?;
    a.record(record(observed)).map_err(|e| (e, true, true))?;
    if observed != expected {
        return Err((Failure::Inspection, false, true));
    }
    Ok(())
}

fn mutation(
    a: &mut impl Adapter,
    intent: Record,
    create: bool,
) -> Result<(), (Failure, bool, bool)> {
    a.record(intent).map_err(|e| (e, true, true))?;
    a.checkpoint().map_err(|e| (e, false, true))?;
    let result = if create { a.create() } else { a.remove() };
    // Retain the primary API failure even if writing its result also fails.
    let recorded = a.record(if create {
        Record::CreateResult(result)
    } else {
        Record::RemoveResult(result)
    });
    if let Err(primary) = result {
        return Err((primary, recorded.is_err(), true));
    }
    recorded.map_err(|e| (e, true, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Check,
        Record(Record),
        Read,
        Auth,
        Create,
        Remove,
    }
    struct Fake {
        reads: VecDeque<Result<Observation, Failure>>,
        calls: Vec<Call>,
        fail_call: Option<usize>,
        create_error: Option<Failure>,
        remove_error: Option<Failure>,
    }
    impl Fake {
        fn normal() -> Self {
            Self {
                reads: [
                    Observation::Absent,
                    Observation::Absent,
                    Observation::Exact,
                    Observation::Exact,
                    Observation::Absent,
                ]
                .map(Ok)
                .into(),
                calls: vec![],
                fail_call: None,
                create_error: None,
                remove_error: None,
            }
        }
        fn call(&mut self, call: Call) -> Result<(), Failure> {
            let error = match call {
                Call::Record(_) => Failure::Journal,
                Call::Check => Failure::Deadline,
                _ => Failure::Api,
            };
            self.calls.push(call);
            if self.fail_call == Some(self.calls.len() - 1) {
                Err(error)
            } else {
                Ok(())
            }
        }
        fn mutations(&self) -> Vec<&'static str> {
            self.calls
                .iter()
                .filter_map(|call| match call {
                    Call::Create => Some("create"),
                    Call::Remove => Some("remove"),
                    _ => None,
                })
                .collect()
        }
    }
    impl Adapter for Fake {
        fn checkpoint(&mut self) -> Result<(), Failure> {
            self.call(Call::Check)
        }
        fn record(&mut self, r: Record) -> Result<(), Failure> {
            self.call(Call::Record(r))
        }
        fn inspect(&mut self) -> Result<Observation, Failure> {
            self.call(Call::Read)?;
            self.reads.pop_front().expect("unexpected read")
        }
        fn authorize(&mut self) -> Result<(), Failure> {
            self.call(Call::Auth)
        }
        fn create(&mut self) -> Result<(), Failure> {
            self.call(Call::Create)?;
            self.create_error.map_or(Ok(()), Err)
        }
        fn remove(&mut self) -> Result<(), Failure> {
            self.call(Call::Remove)?;
            self.remove_error.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn base_case_requires_fresh_reads_and_durable_intents() {
        let mut a = Fake::normal();
        assert_eq!(execute(&mut a), Ok(()));
        assert_eq!(a.mutations(), ["create", "remove"]);
        assert!(a.reads.is_empty());
        assert_eq!(
            a.calls,
            vec![
                Call::Check,
                Call::Read,
                Call::Record(Record::Baseline(Observation::Absent)),
                Call::Check,
                Call::Auth,
                Call::Record(Record::AuthorizationResult(Ok(()))),
                Call::Check,
                Call::Read,
                Call::Record(Record::BeforeCreate(Observation::Absent)),
                Call::Record(Record::CreateIntent),
                Call::Check,
                Call::Create,
                Call::Record(Record::CreateResult(Ok(()))),
                Call::Check,
                Call::Read,
                Call::Record(Record::Created(Observation::Exact)),
                Call::Check,
                Call::Read,
                Call::Record(Record::BeforeRemove(Observation::Exact)),
                Call::Record(Record::RemoveIntent),
                Call::Check,
                Call::Remove,
                Call::Record(Record::RemoveResult(Ok(()))),
                Call::Check,
                Call::Read,
                Call::Record(Record::Removed(Observation::Absent)),
            ]
        );
        let records: Vec<_> = a
            .calls
            .iter()
            .filter_map(|c| {
                if let Call::Record(r) = c {
                    Some(*r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            records,
            [
                Record::Baseline(Observation::Absent),
                Record::AuthorizationResult(Ok(())),
                Record::BeforeCreate(Observation::Absent),
                Record::CreateIntent,
                Record::CreateResult(Ok(())),
                Record::Created(Observation::Exact),
                Record::BeforeRemove(Observation::Exact),
                Record::RemoveIntent,
                Record::RemoveResult(Ok(())),
                Record::Removed(Observation::Absent)
            ]
        );
    }

    #[test]
    fn every_callback_failure_stops_without_retry_or_blind_cleanup() {
        let mut normal = Fake::normal();
        execute(&mut normal).unwrap();
        for index in 0..normal.calls.len() {
            let mut a = Fake::normal();
            a.fail_call = Some(index);
            assert!(execute(&mut a).is_err(), "failure index {index}");
            let may_record_result = matches!(
                normal.calls[index],
                Call::Auth | Call::Create | Call::Remove
            );
            assert_eq!(a.calls.len(), index + 1 + usize::from(may_record_result));
            assert!(a.mutations().len() <= 2);
        }
    }

    #[test]
    fn any_nonmatching_or_unreadable_snapshot_stops_writes() {
        for read_index in 0..5 {
            for replacement in [
                Ok(Observation::Absent),
                Ok(Observation::Exact),
                Ok(Observation::Incompatible),
                Err(Failure::Inspection),
            ] {
                let mut a = Fake::normal();
                if a.reads[read_index] == replacement {
                    continue;
                }
                a.reads[read_index] = replacement;
                assert!(execute(&mut a).is_err());
                let expected = match read_index {
                    0 | 1 => vec![],
                    2 | 3 => vec!["create"],
                    _ => vec!["create", "remove"],
                };
                assert_eq!(a.mutations(), expected);
                if read_index == 0 {
                    assert!(!a.calls.iter().any(|c| matches!(c, Call::Auth)));
                }
            }
        }
    }

    #[test]
    fn failed_create_is_unknown_even_for_denial_and_cancellation() {
        for error in [
            Failure::Denied,
            Failure::Canceled,
            Failure::InteractionNotAllowed,
            Failure::Api,
        ] {
            let mut a = Fake::normal();
            a.create_error = Some(error);
            assert_eq!(
                execute(&mut a),
                Err(Stop::Quarantine {
                    primary: error,
                    journal_failed: false
                })
            );
            assert_eq!(a.mutations(), ["create"]);
            assert_eq!(a.reads.len(), 3);
        }
    }

    #[test]
    fn result_journal_failure_retains_primary_mutation_failure() {
        let mut normal = Fake::normal();
        execute(&mut normal).unwrap();
        for create in [true, false] {
            let mut a = Fake::normal();
            if create {
                a.create_error = Some(Failure::Denied);
            } else {
                a.remove_error = Some(Failure::Denied);
            }
            a.fail_call = normal.calls.iter().position(|c| {
                matches!(
                    (create, c),
                    (true, Call::Record(Record::CreateResult(_)))
                        | (false, Call::Record(Record::RemoveResult(_)))
                )
            });
            assert_eq!(
                execute(&mut a),
                Err(Stop::Quarantine {
                    primary: Failure::Denied,
                    journal_failed: true
                })
            );
        }
    }

    fn approved(name: &TestName) -> Approval {
        Approval {
            environment: "disposable-fixture".into(),
            os_build: "fixture-build".into(),
            sdk: "fixture-sdk".into(),
            reviewed_commit: "a".repeat(40),
            reviewed_sha256: "b".repeat(64),
            restore_evidence: "fixture-restore".into(),
            disposable: true,
            restore_tested: true,
            exclusive_writers: true,
            allow_authorization_interaction: true,
            confirmation: format!("CREATE READ REMOVE {} {DEADLINE_SECONDS}", name.as_str()),
        }
    }

    #[test]
    fn approval_binds_generated_name_build_digest_and_all_prerequisites() {
        let name = TestName::from_entropy([1; 16]);
        let valid = approved(&name);
        let digest = "b".repeat(64);
        assert!(valid.validate(&name, &digest, "fixture-build"));
        assert!(!valid.validate(&TestName::from_entropy([2; 16]), &digest, "fixture-build"));
        assert!(!valid.validate(&name, &"c".repeat(64), "fixture-build"));
        assert!(!valid.validate(&name, &digest, "another-build"));
        for field in [
            "disposable",
            "restore_tested",
            "exclusive_writers",
            "allow_authorization_interaction",
        ] {
            let mut json = serde_json::to_value(approved(&name)).unwrap();
            json[field] = false.into();
            let invalid: Approval = serde_json::from_value(json).unwrap();
            assert!(!invalid.validate(&name, &digest, "fixture-build"));
        }
        for field in [
            "environment",
            "os_build",
            "sdk",
            "reviewed_commit",
            "reviewed_sha256",
            "restore_evidence",
            "confirmation",
        ] {
            for value in ["", "\nsecret", &"x".repeat(1024)] {
                let mut json = serde_json::to_value(approved(&name)).unwrap();
                json[field] = value.into();
                let invalid: Approval = serde_json::from_value(json).unwrap();
                assert!(!invalid.validate(&name, &digest, "fixture-build"));
            }
        }
    }

    #[test]
    fn names_cannot_target_runtime_or_built_in_rights() {
        for bytes in [[0; 16], [255; 16], [17; 16]] {
            let name = TestName::from_entropy(bytes);
            assert!(name.as_str().starts_with(PREFIX));
            assert!(is_hex(&name.as_str()[PREFIX.len()..], 32));
            assert_ne!(
                name.as_str(),
                crate::helper_runtime_right::HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME
            );
        }
    }
}
