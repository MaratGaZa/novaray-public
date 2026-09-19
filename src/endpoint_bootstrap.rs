//! Pure initial endpoint selection, not a resolver, timer, session runtime or firewall authority.
//!
//! The future owner must supply truthful observations, non-reused binding generations and one
//! monotonic clock domain. Returned data still needs validation at the eventual side-effect boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU64};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::kill_switch::{supported_unicast, EndpointTransport};

pub const MAX_BOOTSTRAP_RECORDS: usize = 64;
pub const MAX_BOOTSTRAP_CANDIDATES: usize = 16;
pub const MAX_BOOTSTRAP_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BootstrapBinding {
    session: NonZeroU64,
    request: NonZeroU64,
    profile: NonZeroU64,
    network: NonZeroU64,
}

impl BootstrapBinding {
    pub fn new(
        session: NonZeroU64,
        request: NonZeroU64,
        profile: NonZeroU64,
        network: NonZeroU64,
    ) -> Self {
        Self {
            session,
            request,
            profile,
            network,
        }
    }
}

impl fmt::Debug for BootstrapBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapBinding(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionObservation {
    Unprotected,
    Active,
    Inherited,
    Unknown,
}

/// Caller observations are inputs to policy, never evidence of authentication or kernel state.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapObservation {
    pub binding: BootstrapBinding,
    pub protection: ProtectionObservation,
    pub pending_recovery: bool,
    pub explicit_connect: bool,
    pub disclosure_acknowledged: bool,
    pub always_on_required: bool,
    pub now: Instant,
}

impl BootstrapObservation {
    fn admits_bootstrap(self) -> bool {
        self.protection == ProtectionObservation::Unprotected
            && !self.pending_recovery
            && self.explicit_connect
            && self.disclosure_acknowledged
            && !self.always_on_required
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UplinkFamilies {
    Ipv4,
    Ipv6,
    DualStack,
}

impl UplinkFamilies {
    fn supports(self, address: IpAddr) -> bool {
        matches!(self, Self::DualStack)
            || matches!(
                (self, address),
                (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
            )
    }
}

#[derive(Clone, Copy)]
pub struct ResolutionCandidate {
    pub address: IpAddr,
    pub valid_until: Instant,
}

impl fmt::Debug for ResolutionCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolutionCandidate(<redacted>)")
    }
}

/// Owned selection data, not a revocable permission or proof that any packets may be sent.
pub struct SelectedEndpoint {
    endpoint: SocketAddr,
    transport: EndpointTransport,
    binding: BootstrapBinding,
    valid_until: Instant,
}

impl SelectedEndpoint {
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn transport(&self) -> EndpointTransport {
        self.transport
    }

    pub fn binding(&self) -> BootstrapBinding {
        self.binding
    }

    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }
}

impl fmt::Debug for SelectedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedEndpoint(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapState {
    Resolving,
    Prepared,
    Consumed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BootstrapError {
    #[error("initial endpoint bootstrap is not admitted")]
    AdmissionDenied,
    #[error("bootstrap lifetime must be positive and bounded")]
    InvalidLifetime,
    #[error("bootstrap transition is not allowed")]
    InvalidState,
    #[error("bootstrap current context changed")]
    ContextChanged,
    #[error("bootstrap response belongs to another request context")]
    StaleResponse,
    #[error("bootstrap clock moved backwards")]
    ClockRegressed,
    #[error("bootstrap lifetime expired")]
    TimedOut,
    #[error("bootstrap resolution failed")]
    ResolutionFailed,
    #[error("bootstrap response exceeds record or candidate bounds")]
    ResponseTooLarge,
    #[error("bootstrap candidate deadline is invalid")]
    InvalidCandidateDeadline,
    #[error("bootstrap has no fresh supported candidate")]
    NoFreshCandidate,
}

/// Single-use pre-protection state machine. There is deliberately no retry, reset or rotation API.
pub struct EndpointBootstrap {
    state: BootstrapState,
    binding: BootstrapBinding,
    started_at: Instant,
    last_observed_at: Instant,
    deadline: Instant,
    port: NonZeroU16,
    transport: EndpointTransport,
    families: UplinkFamilies,
    selected: Option<ResolutionCandidate>,
}

impl fmt::Debug for EndpointBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointBootstrap")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl EndpointBootstrap {
    pub fn begin(
        observation: BootstrapObservation,
        port: NonZeroU16,
        transport: EndpointTransport,
        families: UplinkFamilies,
        deadline: Instant,
    ) -> Result<Self, BootstrapError> {
        if !observation.admits_bootstrap() {
            return Err(BootstrapError::AdmissionDenied);
        }
        let lifetime = deadline.checked_duration_since(observation.now);
        if !matches!(lifetime, Some(value) if !value.is_zero() && value <= MAX_BOOTSTRAP_LIFETIME) {
            return Err(BootstrapError::InvalidLifetime);
        }
        Ok(Self {
            state: BootstrapState::Resolving,
            binding: observation.binding,
            started_at: observation.now,
            last_observed_at: observation.now,
            deadline,
            port,
            transport,
            families,
            selected: None,
        })
    }

    pub fn state(&self) -> BootstrapState {
        self.state
    }

    fn block<T>(&mut self, reason: BootstrapError) -> Result<T, BootstrapError> {
        self.selected = None;
        self.state = BootstrapState::Blocked;
        Err(reason)
    }

    /// The caller drives observation and timeout checks; this method never starts a timer.
    pub fn revalidate(&mut self, observation: BootstrapObservation) -> Result<(), BootstrapError> {
        if !matches!(
            self.state,
            BootstrapState::Resolving | BootstrapState::Prepared
        ) {
            return Err(BootstrapError::InvalidState);
        }
        if observation.binding != self.binding {
            return self.block(BootstrapError::ContextChanged);
        }
        if !observation.admits_bootstrap() {
            return self.block(BootstrapError::AdmissionDenied);
        }
        if observation.now < self.last_observed_at {
            return self.block(BootstrapError::ClockRegressed);
        }
        if observation.now >= self.deadline {
            return self.block(BootstrapError::TimedOut);
        }
        self.last_observed_at = observation.now;
        if self
            .selected
            .is_some_and(|selected| selected.valid_until <= observation.now)
        {
            return self.block(BootstrapError::NoFreshCandidate);
        }
        Ok(())
    }

    fn check_response(
        &mut self,
        observation: BootstrapObservation,
        response_binding: BootstrapBinding,
    ) -> Result<(), BootstrapError> {
        if self.state != BootstrapState::Resolving {
            return Err(BootstrapError::InvalidState);
        }
        self.revalidate(observation)?;
        // A late reply is not evidence that the *current* observed context changed.
        if response_binding != self.binding {
            return Err(BootstrapError::StaleResponse);
        }
        Ok(())
    }

    pub fn resolution_failed(
        &mut self,
        observation: BootstrapObservation,
        response_binding: BootstrapBinding,
    ) -> Result<(), BootstrapError> {
        self.check_response(observation, response_binding)?;
        self.block(BootstrapError::ResolutionFailed)
    }

    pub fn accept_response(
        &mut self,
        observation: BootstrapObservation,
        response_binding: BootstrapBinding,
        records: &[ResolutionCandidate],
    ) -> Result<(), BootstrapError> {
        self.check_response(observation, response_binding)?;
        if records.len() > MAX_BOOTSTRAP_RECORDS {
            return self.block(BootstrapError::ResponseTooLarge);
        }
        let mut candidates = BTreeMap::<IpAddr, Instant>::new();
        for record in records {
            if record.valid_until <= self.started_at {
                return self.block(BootstrapError::InvalidCandidateDeadline);
            }
            candidates
                .entry(record.address)
                .and_modify(|deadline| *deadline = (*deadline).min(record.valid_until))
                .or_insert(record.valid_until);
            // Count before filtering, so unsupported/expired entries cannot hide oversized input.
            if candidates.len() > MAX_BOOTSTRAP_CANDIDATES {
                return self.block(BootstrapError::ResponseTooLarge);
            }
        }
        let selected = candidates
            .into_iter()
            .filter(|(address, deadline)| {
                supported_unicast(*address)
                    && self.families.supports(*address)
                    && *deadline > observation.now
            })
            .min_by_key(|(address, _)| (address.is_ipv6(), *address));
        let Some((address, valid_until)) = selected else {
            return self.block(BootstrapError::NoFreshCandidate);
        };
        self.selected = Some(ResolutionCandidate {
            address,
            valid_until,
        });
        self.state = BootstrapState::Prepared;
        Ok(())
    }

    pub fn take_endpoint(
        &mut self,
        observation: BootstrapObservation,
    ) -> Result<SelectedEndpoint, BootstrapError> {
        if self.state != BootstrapState::Prepared {
            return Err(BootstrapError::InvalidState);
        }
        self.revalidate(observation)?;
        let Some(selected) = self.selected.take() else {
            return self.block(BootstrapError::InvalidState);
        };
        self.state = BootstrapState::Consumed;
        Ok(SelectedEndpoint {
            endpoint: SocketAddr::new(selected.address, self.port.get()),
            transport: self.transport,
            binding: self.binding,
            valid_until: selected.valid_until,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(values: [u64; 4]) -> BootstrapBinding {
        let [session, request, profile, network] =
            values.map(|value| NonZeroU64::new(value).unwrap());
        BootstrapBinding::new(session, request, profile, network)
    }

    fn observation(now: Instant) -> BootstrapObservation {
        BootstrapObservation {
            binding: binding([1, 2, 3, 4]),
            protection: ProtectionObservation::Unprotected,
            pending_recovery: false,
            explicit_connect: true,
            disclosure_acknowledged: true,
            always_on_required: false,
            now,
        }
    }

    fn candidate(address: &str, valid_until: Instant) -> ResolutionCandidate {
        ResolutionCandidate {
            address: address.parse().unwrap(),
            valid_until,
        }
    }

    fn begin(obs: BootstrapObservation) -> EndpointBootstrap {
        EndpointBootstrap::begin(
            obs,
            NonZeroU16::new(8443).unwrap(),
            EndpointTransport::Udp,
            UplinkFamilies::DualStack,
            obs.now + MAX_BOOTSTRAP_LIFETIME,
        )
        .unwrap()
    }

    fn prepared(obs: BootstrapObservation) -> EndpointBootstrap {
        let mut model = begin(obs);
        model
            .accept_response(
                obs,
                obs.binding,
                &[candidate("192.0.2.20", obs.now + Duration::from_secs(10))],
            )
            .unwrap();
        model
    }

    fn denied_observations(obs: BootstrapObservation) -> Vec<BootstrapObservation> {
        let mut observations: Vec<_> = [
            ProtectionObservation::Active,
            ProtectionObservation::Inherited,
            ProtectionObservation::Unknown,
        ]
        .map(|protection| BootstrapObservation { protection, ..obs })
        .into();
        observations.extend([
            BootstrapObservation {
                pending_recovery: true,
                ..obs
            },
            BootstrapObservation {
                explicit_connect: false,
                ..obs
            },
            BootstrapObservation {
                disclosure_acknowledged: false,
                ..obs
            },
            BootstrapObservation {
                always_on_required: true,
                ..obs
            },
        ]);
        observations
    }

    #[test]
    fn admission_is_checked_at_start_response_and_handoff() {
        let obs = observation(Instant::now());
        for denied in denied_observations(obs) {
            assert_eq!(
                EndpointBootstrap::begin(
                    denied,
                    NonZeroU16::new(443).unwrap(),
                    EndpointTransport::Tcp,
                    UplinkFamilies::Ipv4,
                    obs.now + Duration::from_secs(1)
                )
                .unwrap_err(),
                BootstrapError::AdmissionDenied
            );
            let mut resolving = begin(obs);
            assert_eq!(
                resolving.accept_response(denied, obs.binding, &[]),
                Err(BootstrapError::AdmissionDenied)
            );
            assert_eq!(resolving.state(), BootstrapState::Blocked);
            let mut ready = prepared(obs);
            assert_eq!(
                ready.take_endpoint(denied).unwrap_err(),
                BootstrapError::AdmissionDenied
            );
            assert_eq!(ready.state(), BootstrapState::Blocked);
            assert!(ready.selected.is_none());
            assert_eq!(
                ready.take_endpoint(obs).unwrap_err(),
                BootstrapError::InvalidState
            );
        }
    }

    #[test]
    fn lifetime_is_positive_bounded_and_expires_at_exact_deadline() {
        let obs = observation(Instant::now());
        for deadline in [
            obs.now - Duration::from_secs(1),
            obs.now,
            obs.now + Duration::from_secs(31),
        ] {
            assert_eq!(
                EndpointBootstrap::begin(
                    obs,
                    NonZeroU16::new(443).unwrap(),
                    EndpointTransport::Tcp,
                    UplinkFamilies::Ipv4,
                    deadline
                )
                .unwrap_err(),
                BootstrapError::InvalidLifetime
            );
        }
        let mut model = begin(obs);
        assert_eq!(
            model.revalidate(BootstrapObservation {
                now: obs.now + Duration::from_secs(29),
                ..obs
            }),
            Ok(())
        );
        assert_eq!(
            model.revalidate(BootstrapObservation {
                now: obs.now + MAX_BOOTSTRAP_LIFETIME,
                ..obs
            }),
            Err(BootstrapError::TimedOut)
        );
        assert_eq!(model.state(), BootstrapState::Blocked);
        let expired = BootstrapObservation {
            now: obs.now + MAX_BOOTSTRAP_LIFETIME,
            ..obs
        };
        let records = [candidate("192.0.2.1", obs.now + Duration::from_secs(60))];
        assert_eq!(
            begin(obs).accept_response(expired, obs.binding, &records),
            Err(BootstrapError::TimedOut)
        );
        let mut model = begin(obs);
        model.accept_response(obs, obs.binding, &records).unwrap();
        assert_eq!(
            model.take_endpoint(expired).unwrap_err(),
            BootstrapError::TimedOut
        );
        assert!(model.selected.is_none());
    }

    #[test]
    fn deterministic_single_handoff_owns_profile_tuple_and_binding() {
        let obs = observation(Instant::now());
        let deadline = obs.now + Duration::from_secs(10);
        let mut records = [
            candidate("2001:db8::1", deadline),
            candidate("192.0.2.20", deadline),
            candidate("192.0.2.10", deadline),
        ];
        for _ in 0..records.len() {
            let mut model = begin(obs);
            assert_eq!(model.state(), BootstrapState::Resolving);
            assert_eq!(
                model.take_endpoint(obs).unwrap_err(),
                BootstrapError::InvalidState
            );
            model.accept_response(obs, obs.binding, &records).unwrap();
            assert_eq!(model.state(), BootstrapState::Prepared);
            assert_eq!(
                model.accept_response(obs, obs.binding, &records),
                Err(BootstrapError::InvalidState)
            );
            let selected = model.take_endpoint(obs).unwrap();
            assert_eq!(selected.endpoint(), "192.0.2.10:8443".parse().unwrap());
            assert_eq!(selected.transport(), EndpointTransport::Udp);
            assert_eq!(selected.binding(), obs.binding);
            assert_eq!(selected.valid_until(), deadline);
            assert_eq!(model.state(), BootstrapState::Consumed);
            assert!(model.selected.is_none());
            assert_eq!(
                model.take_endpoint(obs).unwrap_err(),
                BootstrapError::InvalidState
            );
            assert_eq!(
                model.accept_response(obs, obs.binding, &records),
                Err(BootstrapError::InvalidState)
            );
            assert_eq!(
                model.resolution_failed(obs, obs.binding),
                Err(BootstrapError::InvalidState)
            );
            assert_eq!(model.revalidate(obs), Err(BootstrapError::InvalidState));
            records.rotate_left(1);
            assert_eq!(selected.endpoint(), "192.0.2.10:8443".parse().unwrap());
        }
        let mut records = [candidate("192.0.2.10", deadline)];
        let mut model = begin(obs);
        model.accept_response(obs, obs.binding, &records).unwrap();
        records[0].address = "198.51.100.1".parse().unwrap();
        records[0].valid_until = obs.now;
        let selected = model.take_endpoint(obs).unwrap();
        assert_ne!(selected.endpoint().ip(), records[0].address);
        assert_eq!(selected.valid_until(), deadline);
    }

    #[test]
    fn raw_and_unique_bounds_are_checked_without_truncation() {
        let obs = observation(Instant::now());
        let record = candidate("192.0.2.1", obs.now + Duration::from_secs(10));
        for count in [64, 65] {
            let mut model = begin(obs);
            let result = model.accept_response(obs, obs.binding, &vec![record; count]);
            assert_eq!(
                result,
                if count == 64 {
                    Ok(())
                } else {
                    Err(BootstrapError::ResponseTooLarge)
                }
            );
        }
        for count in [16, 17] {
            let records: Vec<_> = (1..=count)
                .map(|i| candidate(&format!("192.0.2.{i}"), record.valid_until))
                .collect();
            let mut model = begin(obs);
            assert_eq!(
                model.accept_response(obs, obs.binding, &records),
                if count == 16 {
                    Ok(())
                } else {
                    Err(BootstrapError::ResponseTooLarge)
                }
            );
        }
        let unsupported: Vec<_> = (1..=17)
            .map(|i| candidate(&format!("224.0.0.{i}"), record.valid_until))
            .collect();
        assert_eq!(
            begin(obs).accept_response(obs, obs.binding, &unsupported),
            Err(BootstrapError::ResponseTooLarge)
        );
        assert_eq!(
            begin(obs).accept_response(obs, obs.binding, &[]),
            Err(BootstrapError::NoFreshCandidate)
        );
    }

    #[test]
    fn address_family_and_freshness_filter_before_selection() {
        let start = observation(Instant::now());
        let later = BootstrapObservation {
            now: start.now + Duration::from_secs(2),
            ..start
        };
        let valid = start.now + Duration::from_secs(10);
        let mut records: Vec<_> = [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "::",
            "::1",
            "ff02::1",
            "fe80::1",
            "::ffff:192.0.2.1",
        ]
        .map(|ip| candidate(ip, valid))
        .into();
        records.push(candidate("192.0.2.1", later.now));
        assert_eq!(
            begin(start).accept_response(later, start.binding, &records),
            Err(BootstrapError::NoFreshCandidate)
        );
        records.extend([
            candidate("2001:db8::2", valid),
            candidate("2001:db8::1", valid),
            candidate("192.0.2.20", valid),
        ]);
        for (family, expected) in [
            (UplinkFamilies::Ipv4, "192.0.2.20:443"),
            (UplinkFamilies::Ipv6, "[2001:db8::1]:443"),
            (UplinkFamilies::DualStack, "192.0.2.20:443"),
        ] {
            let mut model = EndpointBootstrap::begin(
                start,
                NonZeroU16::new(443).unwrap(),
                EndpointTransport::Tcp,
                family,
                start.now + MAX_BOOTSTRAP_LIFETIME,
            )
            .unwrap();
            model
                .accept_response(later, start.binding, &records)
                .unwrap();
            let selected = model.take_endpoint(later).unwrap();
            assert_eq!(selected.endpoint(), expected.parse().unwrap());
            assert_eq!(selected.transport(), EndpointTransport::Tcp);
        }
        let mut v4 = EndpointBootstrap::begin(
            start,
            NonZeroU16::new(443).unwrap(),
            EndpointTransport::Tcp,
            UplinkFamilies::Ipv4,
            valid,
        )
        .unwrap();
        assert_eq!(
            v4.accept_response(later, start.binding, &[candidate("2001:db8::1", valid)]),
            Err(BootstrapError::NoFreshCandidate)
        );
    }

    #[test]
    fn duplicates_use_minimum_deadline_and_expiry_does_not_rotate() {
        let start = observation(Instant::now());
        let short = start.now + Duration::from_secs(2);
        let long = start.now + Duration::from_secs(20);
        let mut records = [
            candidate("192.0.2.10", long),
            candidate("192.0.2.10", short),
            candidate("192.0.2.20", long),
        ];
        for _ in 0..2 {
            let mut model = begin(start);
            model
                .accept_response(start, start.binding, &records)
                .unwrap();
            assert_eq!(model.selected.unwrap().valid_until, short);
            let later = BootstrapObservation {
                now: short,
                ..start
            };
            assert_eq!(
                model.take_endpoint(later).unwrap_err(),
                BootstrapError::NoFreshCandidate
            );
            assert!(model.selected.is_none());
            assert_eq!(model.state(), BootstrapState::Blocked);
            assert_eq!(
                model.accept_response(later, start.binding, &records),
                Err(BootstrapError::InvalidState)
            );
            // Expired duplicates do not resurrect from the longer lifetime during initial filtering.
            let mut fresh = begin(start);
            fresh
                .accept_response(later, start.binding, &records)
                .unwrap();
            assert_eq!(
                fresh.take_endpoint(later).unwrap().endpoint().ip(),
                "192.0.2.20".parse::<IpAddr>().unwrap()
            );
            records.swap(0, 1);
        }
    }

    #[test]
    fn stale_responses_do_not_replace_current_request_or_consume_it() {
        let obs = observation(Instant::now());
        for values in [[9, 2, 3, 4], [1, 9, 3, 4], [1, 2, 9, 4], [1, 2, 3, 9]] {
            let mut model = begin(obs);
            assert_eq!(
                model.accept_response(obs, binding(values), &[]),
                Err(BootstrapError::StaleResponse)
            );
            assert_eq!(
                model.resolution_failed(obs, binding(values)),
                Err(BootstrapError::StaleResponse)
            );
            assert_eq!(model.state(), BootstrapState::Resolving);
            assert!(model.selected.is_none());
            model
                .accept_response(
                    obs,
                    obs.binding,
                    &[candidate("192.0.2.1", obs.now + Duration::from_secs(1))],
                )
                .unwrap();
            assert!(model.take_endpoint(obs).is_ok());
        }
    }

    #[test]
    fn current_context_change_invalidates_before_response_or_handoff() {
        let obs = observation(Instant::now());
        for values in [[9, 2, 3, 4], [1, 9, 3, 4], [1, 2, 9, 4], [1, 2, 3, 9]] {
            let changed = BootstrapObservation {
                binding: binding(values),
                ..obs
            };
            let mut model = begin(obs);
            assert_eq!(
                model.accept_response(changed, obs.binding, &[]),
                Err(BootstrapError::ContextChanged)
            );
            assert_eq!(model.state(), BootstrapState::Blocked);
            let mut model = prepared(obs);
            assert_eq!(
                model.take_endpoint(changed).unwrap_err(),
                BootstrapError::ContextChanged
            );
            assert!(model.selected.is_none());
            assert_eq!(
                model.take_endpoint(obs).unwrap_err(),
                BootstrapError::InvalidState
            );
        }
    }

    #[test]
    fn resolver_failure_bad_deadline_and_clock_regression_are_terminal() {
        let obs = observation(Instant::now());
        let mut model = begin(obs);
        assert_eq!(
            model.resolution_failed(obs, obs.binding),
            Err(BootstrapError::ResolutionFailed)
        );
        assert_eq!(model.state(), BootstrapState::Blocked);
        assert_eq!(
            model.accept_response(obs, obs.binding, &[]),
            Err(BootstrapError::InvalidState)
        );
        for deadline in [obs.now - Duration::from_secs(1), obs.now] {
            let mut model = begin(obs);
            assert_eq!(
                model.accept_response(obs, obs.binding, &[candidate("192.0.2.1", deadline)]),
                Err(BootstrapError::InvalidCandidateDeadline)
            );
            assert_eq!(model.state(), BootstrapState::Blocked);
        }
        let mut model = prepared(obs);
        model
            .revalidate(BootstrapObservation {
                now: obs.now + Duration::from_secs(2),
                ..obs
            })
            .unwrap();
        assert_eq!(
            model
                .take_endpoint(BootstrapObservation {
                    now: obs.now + Duration::from_secs(1),
                    ..obs
                })
                .unwrap_err(),
            BootstrapError::ClockRegressed
        );
        assert_eq!(model.state(), BootstrapState::Blocked);
        assert!(model.selected.is_none());
        assert_eq!(model.revalidate(obs), Err(BootstrapError::InvalidState));
    }

    #[test]
    fn diagnostics_redact_addresses_ports_and_binding_generations() {
        let obs = BootstrapObservation {
            binding: binding([123456789123, 2, 3, 4]),
            ..observation(Instant::now())
        };
        let mut model = prepared(obs);
        let record = model.selected.unwrap();
        let selected = model.take_endpoint(obs).unwrap();
        let diagnostics = format!("{obs:?} {model:?} {record:?} {selected:?}");
        for secret in ["192.0.2.20", ":8443", "123456789123"] {
            assert!(!diagnostics.contains(secret));
        }
        for error in [
            BootstrapError::AdmissionDenied,
            BootstrapError::InvalidLifetime,
            BootstrapError::InvalidState,
            BootstrapError::ContextChanged,
            BootstrapError::StaleResponse,
            BootstrapError::ClockRegressed,
            BootstrapError::TimedOut,
            BootstrapError::ResolutionFailed,
            BootstrapError::ResponseTooLarge,
            BootstrapError::InvalidCandidateDeadline,
            BootstrapError::NoFreshCandidate,
        ] {
            let message = format!("{error:?} {error}");
            assert!(!message.contains("192.0.2.20"));
            assert!(!message.contains("123456789123"));
        }
    }
}
