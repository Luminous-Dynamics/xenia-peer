// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Local acceptance policy for signed machine-authority history.
//!
//! The authority provider owns signed history and its declared freshness horizon. A consuming
//! deployment may be stricter. This module keeps the raw verified-history state crate-internal and
//! exposes the only public verification path through a non-serialized local policy that caps how
//! long any signed snapshot may be treated as fresh for current/offline authority decisions.
//!
//! Historical qualification remains independent of current freshness. A correctly signed stale
//! head can still prove an observation that lies inside its completeness horizon, while the same
//! head cannot mint a fresh current-use qualification after either provider or local freshness
//! policy expires.

use ed25519_dalek::VerifyingKey;

use crate::authority_history::{
    HistoricalMachineAuthorityQualificationV1, MachineAuthorityHistoryError,
    MachineAuthorityHistoryEventV1, SignedMachineAuthorityHistoryHeadV1,
    VerifiedMachineAuthorityHistoryV1, verify_machine_authority_history,
};

/// Consumer-owned bound on the offline/current usefulness of a signed authority-history head.
///
/// This policy deliberately has no serde surface. A remote provider may assert a shorter
/// `fresh_until_ms`, but it cannot expand the deployment's locally configured maximum window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineAuthorityHistoryAcceptancePolicyV1 {
    max_snapshot_freshness_ms: u64,
}

impl MachineAuthorityHistoryAcceptancePolicyV1 {
    /// Construct a local acceptance policy. Zero would deny every snapshot and is rejected as a
    /// configuration error rather than silently giving it special meaning.
    pub fn new(
        max_snapshot_freshness_ms: u64,
    ) -> Result<Self, MachineAuthorityHistoryAcceptanceError> {
        if max_snapshot_freshness_ms == 0 {
            return Err(MachineAuthorityHistoryAcceptanceError::InvalidMaximumSnapshotFreshness);
        }
        Ok(Self {
            max_snapshot_freshness_ms,
        })
    }

    /// Maximum provider-declared `fresh_until_ms - observed_through_ms` accepted locally.
    pub const fn max_snapshot_freshness_ms(&self) -> u64 {
        self.max_snapshot_freshness_ms
    }
}

/// History whose signature, chain semantics, rollback continuity and local freshness policy have
/// all been verified.
///
/// This wrapper is non-serializable. Portable events and signed heads remain evidence; callers
/// must reconstruct this value through [`verify_machine_authority_history_with_policy`] after
/// loading an independently trusted authority public key and any rollback-resistant retained head.
#[derive(Debug, Clone)]
pub struct AcceptedMachineAuthorityHistoryV1 {
    inner: VerifiedMachineAuthorityHistoryV1,
    policy: MachineAuthorityHistoryAcceptancePolicyV1,
}

impl AcceptedMachineAuthorityHistoryV1 {
    /// Machine identity whose provider history was verified.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.inner.peer_identity_fingerprint()
    }

    /// Trusted completeness horizon asserted by the signed provider head.
    pub const fn observed_through_ms(&self) -> u64 {
        self.inner.observed_through_ms()
    }

    /// Provider-declared exclusive freshness horizon, already checked against local policy.
    pub const fn fresh_until_ms(&self) -> u64 {
        self.inner.fresh_until_ms()
    }

    /// Exact sequence number of the verified signed history head.
    pub const fn head_sequence(&self) -> u64 {
        self.inner.head_sequence()
    }

    /// Exact digest of the verified signed history head event.
    pub const fn head_digest(&self) -> [u8; 32] {
        self.inner.head_digest()
    }

    /// Local maximum freshness window that admitted this signed history.
    pub const fn max_snapshot_freshness_ms(&self) -> u64 {
        self.policy.max_snapshot_freshness_ms()
    }

    /// Qualify one exact authority epoch from session admission through an observation time.
    ///
    /// Historical eligibility intentionally does not require the signed head to remain fresh at
    /// the time of audit. It does require the head to have covered the observation, and the epoch
    /// must not have expired, been revoked, or been superseded before that observation.
    pub fn qualify_session_observation(
        &self,
        authority_epoch: u64,
        session_authenticated_at_ms: u64,
        observation_at_ms: u64,
    ) -> Result<HistoricalMachineAuthorityQualificationV1, MachineAuthorityHistoryError> {
        self.inner.qualify_session_observation(
            authority_epoch,
            session_authenticated_at_ms,
            observation_at_ms,
        )
    }

    /// Produce a non-serializable current/offline-use qualification only while both the provider
    /// freshness horizon and the deployment's already-applied maximum freshness policy hold.
    pub fn qualify_current_snapshot(
        &self,
        now_ms: u64,
        trusted_time_available: bool,
    ) -> Result<
        LocallyAcceptedFreshMachineAuthorityHistoryV1,
        MachineAuthorityHistoryAcceptanceError,
    > {
        let fresh = self
            .inner
            .qualify_current_snapshot(now_ms, trusted_time_available)
            .map_err(MachineAuthorityHistoryAcceptanceError::History)?;
        Ok(LocallyAcceptedFreshMachineAuthorityHistoryV1 {
            peer_identity_fingerprint: fresh.peer_identity_fingerprint(),
            now_ms: fresh.now_ms(),
            fresh_until_ms: fresh.fresh_until_ms(),
            head_sequence: fresh.head_sequence(),
            head_digest: fresh.head_digest(),
            max_snapshot_freshness_ms: self.policy.max_snapshot_freshness_ms(),
        })
    }
}

/// Non-serializable proof that a signed authority-history snapshot passed both provider and local
/// freshness bounds at a trusted-time instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocallyAcceptedFreshMachineAuthorityHistoryV1 {
    peer_identity_fingerprint: [u8; 32],
    now_ms: u64,
    fresh_until_ms: u64,
    head_sequence: u64,
    head_digest: [u8; 32],
    max_snapshot_freshness_ms: u64,
}

impl LocallyAcceptedFreshMachineAuthorityHistoryV1 {
    /// Machine identity covered by this current-use qualification.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Trusted-time instant at which current-use freshness was evaluated.
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Provider-declared exclusive freshness horizon.
    pub const fn fresh_until_ms(&self) -> u64 {
        self.fresh_until_ms
    }

    /// Sequence number of the exact signed head admitted by local policy.
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    /// Digest of the exact signed head admitted by local policy.
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    /// Deployment-owned maximum freshness window that constrained this qualification.
    pub const fn max_snapshot_freshness_ms(&self) -> u64 {
        self.max_snapshot_freshness_ms
    }
}

/// Failure in the local acceptance layer above provider-owned authority history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineAuthorityHistoryAcceptanceError {
    /// A zero local freshness budget is invalid configuration.
    #[error("machine-authority history maximum snapshot freshness must be positive")]
    InvalidMaximumSnapshotFreshness,
    /// Provider-declared freshness exceeds the deployment's local maximum.
    #[error("signed machine-authority history freshness exceeds local policy")]
    FreshnessWindowTooLong,
    /// Provider history failed signature, continuity, semantic, rollback, or point-of-use checks.
    #[error(transparent)]
    History(#[from] MachineAuthorityHistoryError),
}

/// Verify provider-owned authority history and apply the deployment's local freshness ceiling.
///
/// This is the public entry point for authority-history verification. The provider's signed head
/// may choose a freshness window shorter than local policy, but never longer. Historical queries
/// remain usable after freshness expiry because their authority derives from the signed
/// completeness horizon, not from a claim of current authorization.
pub fn verify_machine_authority_history_with_policy(
    events: &[MachineAuthorityHistoryEventV1],
    signed_head: &SignedMachineAuthorityHistoryHeadV1,
    verifying_key: &VerifyingKey,
    retained_head: Option<&SignedMachineAuthorityHistoryHeadV1>,
    policy: MachineAuthorityHistoryAcceptancePolicyV1,
) -> Result<AcceptedMachineAuthorityHistoryV1, MachineAuthorityHistoryAcceptanceError> {
    signed_head
        .head
        .validate_shape()
        .map_err(MachineAuthorityHistoryAcceptanceError::History)?;
    let declared_freshness = signed_head
        .head
        .fresh_until_ms
        .checked_sub(signed_head.head.observed_through_ms)
        .ok_or(MachineAuthorityHistoryAcceptanceError::FreshnessWindowTooLong)?;
    if declared_freshness > policy.max_snapshot_freshness_ms() {
        return Err(MachineAuthorityHistoryAcceptanceError::FreshnessWindowTooLong);
    }

    let inner = verify_machine_authority_history(events, signed_head, verifying_key, retained_head)
        .map_err(MachineAuthorityHistoryAcceptanceError::History)?;
    Ok(AcceptedMachineAuthorityHistoryV1 { inner, policy })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_history::{
        MachineAuthorityGrantV1, MachineAuthorityHistoryHeadV1,
        MachineAuthorityHistoryTransitionV1,
    };
    use ed25519_dalek::SigningKey;

    const PEER: [u8; 32] = [0x55; 32];

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn event() -> MachineAuthorityHistoryEventV1 {
        MachineAuthorityHistoryEventV1 {
            schema_version: 1,
            sequence: 0,
            previous_event_digest: None,
            peer_identity_fingerprint: PEER,
            recorded_at_ms: 100,
            transition: MachineAuthorityHistoryTransitionV1::Grant(MachineAuthorityGrantV1 {
                authority_epoch: 9,
                valid_from_ms: 100,
                valid_until_ms: 1_000,
            }),
        }
    }

    fn head(
        event: &MachineAuthorityHistoryEventV1,
        observed_through_ms: u64,
        fresh_until_ms: u64,
    ) -> SignedMachineAuthorityHistoryHeadV1 {
        MachineAuthorityHistoryHeadV1 {
            schema_version: 1,
            peer_identity_fingerprint: PEER,
            head_sequence: event.sequence,
            head_digest: event.content_digest().unwrap(),
            observed_through_ms,
            fresh_until_ms,
        }
        .sign(&key())
        .unwrap()
    }

    #[test]
    fn local_policy_accepts_equal_or_shorter_provider_freshness() {
        let event = event();
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(100).unwrap();

        let equal = head(&event, 200, 300);
        assert!(verify_machine_authority_history_with_policy(
            std::slice::from_ref(&event),
            &equal,
            &key().verifying_key(),
            None,
            policy,
        )
        .is_ok());

        let shorter = head(&event, 200, 250);
        assert!(verify_machine_authority_history_with_policy(
            std::slice::from_ref(&event),
            &shorter,
            &key().verifying_key(),
            None,
            policy,
        )
        .is_ok());
    }

    #[test]
    fn provider_cannot_expand_local_offline_freshness_budget() {
        let event = event();
        let head = head(&event, 200, 301);
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(100).unwrap();

        assert!(matches!(
            verify_machine_authority_history_with_policy(
                std::slice::from_ref(&event),
                &head,
                &key().verifying_key(),
                None,
                policy,
            ),
            Err(MachineAuthorityHistoryAcceptanceError::FreshnessWindowTooLong)
        ));
    }

    #[test]
    fn historical_audit_survives_current_freshness_expiry() {
        let event = event();
        let head = head(&event, 500, 600);
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(100).unwrap();
        let accepted = verify_machine_authority_history_with_policy(
            std::slice::from_ref(&event),
            &head,
            &key().verifying_key(),
            None,
            policy,
        )
        .unwrap();

        assert!(accepted.qualify_session_observation(9, 200, 400).is_ok());
        assert!(accepted.qualify_current_snapshot(599, true).is_ok());
        assert_eq!(
            accepted.qualify_current_snapshot(600, true),
            Err(MachineAuthorityHistoryAcceptanceError::History(
                MachineAuthorityHistoryError::StaleHistoryHead
            ))
        );
        assert!(accepted.qualify_session_observation(9, 200, 400).is_ok());
    }

    #[test]
    fn local_freshness_policy_is_not_deserializable_remote_authority() {
        assert!(MachineAuthorityHistoryAcceptancePolicyV1::new(0).is_err());
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(60_000).unwrap();
        assert_eq!(policy.max_snapshot_freshness_ms(), 60_000);
    }
}
