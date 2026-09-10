// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Local acceptance policy for signed machine-authority history.
//!
//! The authority provider owns signed history and its declared freshness horizon. A consuming
//! deployment may be stricter. This module keeps raw reconstructed history crate-internal and
//! exposes public qualification only through an actual [`VerifiedMachineSessionEvidenceV1`].
//! Historical evidence therefore cannot be paired with caller-invented session timestamps, epochs,
//! identities, or transcript bindings.
//!
//! Historical qualification remains independent of current freshness. A correctly signed stale
//! head can still prove an observation that lies inside its completeness horizon and the exact
//! admitted session interval, while the same head cannot mint a fresh current-use qualification
//! after either provider or local freshness policy expires.

use ed25519_dalek::VerifyingKey;

use crate::authority_history::{
    HistoricalMachineAuthorityQualificationV1, MachineAuthorityHistoryError,
    MachineAuthorityHistoryEventV1, SignedMachineAuthorityHistoryHeadV1,
    VerifiedMachineAuthorityHistoryV1, verify_machine_authority_history,
};
use crate::verified_session_evidence::VerifiedMachineSessionEvidenceV1;

/// Stable prefix for an opaque binding to the exact signed history head used for qualification.
pub const MACHINE_AUTHORITY_HISTORY_BINDING_PREFIX_V1: &str =
    "xenia-machine-authority-history-head-v1:blake3-256:";
const XENIA_SIGNING_IDENTITY_BINDING_PREFIX_V1: &str =
    "xenia-signing-identity-v1:blake3-256:";

// The raw verified type is crate-internal. Equality means "same verified evidence head and signed
// horizons" rather than comparing reconstructed implementation details. The head digest commits
// to the complete transition chain, so this is the stable identity of a verified history state.
impl PartialEq for VerifiedMachineAuthorityHistoryV1 {
    fn eq(&self, other: &Self) -> bool {
        self.peer_identity_fingerprint() == other.peer_identity_fingerprint()
            && self.observed_through_ms() == other.observed_through_ms()
            && self.fresh_until_ms() == other.fresh_until_ms()
            && self.head_sequence() == other.head_sequence()
            && self.head_digest() == other.head_digest()
    }
}

impl Eq for VerifiedMachineAuthorityHistoryV1 {}

/// Consumer-owned bound on the offline/current usefulness of a signed authority-history head.
///
/// This policy deliberately has no serde surface. A remote provider may assert a shorter
/// `fresh_until_ms`, but it cannot expand the deployment's locally configured maximum window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineAuthorityHistoryAcceptancePolicyV1 {
    max_snapshot_freshness_ms: u64,
}

impl MachineAuthorityHistoryAcceptancePolicyV1 {
    /// Construct a local acceptance policy. Zero is rejected instead of receiving special meaning.
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

    /// Qualify one actual Xenia verified session through an exact observation instant.
    ///
    /// This is the public historical-session API. The session's immutable provider evidence owns
    /// the principal, session id, transcript binding, authority epoch and admitted interval. The
    /// caller supplies only the observation instant. A long-lived authority epoch therefore cannot
    /// be paired with invented or extended session bounds.
    pub fn qualify_verified_session_observation(
        &self,
        session: &VerifiedMachineSessionEvidenceV1,
        observation_at_ms: u64,
    ) -> Result<HistoricallyQualifiedVerifiedMachineSessionV1, MachineAuthorityHistoryAcceptanceError>
    {
        session
            .validate_shape()
            .map_err(|_| MachineAuthorityHistoryAcceptanceError::InvalidVerifiedSessionEvidence)?;

        let expected_identity = format!(
            "{XENIA_SIGNING_IDENTITY_BINDING_PREFIX_V1}{}",
            hex_lower(&self.peer_identity_fingerprint())
        );
        if session.peer_identity_binding() != expected_identity {
            return Err(MachineAuthorityHistoryAcceptanceError::SessionIdentityMismatch);
        }

        let _historical = self.qualify_session_interval(
            session.authority_epoch(),
            session.authenticated_at_ms(),
            session.expires_at_ms(),
            observation_at_ms,
        )?;

        Ok(HistoricallyQualifiedVerifiedMachineSessionV1 {
            provider_schema: session.schema().to_owned(),
            session_id: session.session_id().to_owned(),
            peer_identity_binding: session.peer_identity_binding().to_owned(),
            session_evidence_binding: session.evidence_binding().to_owned(),
            authority_epoch: session.authority_epoch(),
            session_authenticated_at_ms: session.authenticated_at_ms(),
            session_expires_at_ms: session.expires_at_ms(),
            observation_at_ms,
            provider_history_binding: format!(
                "{MACHINE_AUTHORITY_HISTORY_BINDING_PREFIX_V1}{}",
                hex_lower(&self.head_digest())
            ),
            history_head_sequence: self.head_sequence(),
            history_observed_through_ms: self.observed_through_ms(),
        })
    }

    fn qualify_session_interval(
        &self,
        authority_epoch: u64,
        session_authenticated_at_ms: u64,
        session_expires_at_ms: u64,
        observation_at_ms: u64,
    ) -> Result<HistoricalMachineAuthorityQualificationV1, MachineAuthorityHistoryAcceptanceError> {
        if session_expires_at_ms <= session_authenticated_at_ms {
            return Err(MachineAuthorityHistoryAcceptanceError::InvalidSessionInterval);
        }
        if observation_at_ms >= session_expires_at_ms {
            return Err(MachineAuthorityHistoryAcceptanceError::ObservationOutsideSession);
        }
        self.inner
            .qualify_session_observation(
                authority_epoch,
                session_authenticated_at_ms,
                observation_at_ms,
            )
            .map_err(MachineAuthorityHistoryAcceptanceError::History)
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

/// Non-serializable provider result binding historical authority to one exact verified session.
///
/// This is the intended adapter input for consumers such as Symthaea. It carries the same provider
/// session identity/evidence fields that were historically qualified plus the exact signed history
/// head binding that supported the result. It does not claim current authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricallyQualifiedVerifiedMachineSessionV1 {
    provider_schema: String,
    session_id: String,
    peer_identity_binding: String,
    session_evidence_binding: String,
    authority_epoch: u64,
    session_authenticated_at_ms: u64,
    session_expires_at_ms: u64,
    observation_at_ms: u64,
    provider_history_binding: String,
    history_head_sequence: u64,
    history_observed_through_ms: u64,
}

impl HistoricallyQualifiedVerifiedMachineSessionV1 {
    /// Exact verified-session schema carried by the qualified session.
    pub fn provider_schema(&self) -> &str {
        &self.provider_schema
    }

    /// Exact non-secret session id carried by the qualified session.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Exact hybrid machine-principal binding carried by the qualified session.
    pub fn peer_identity_binding(&self) -> &str {
        &self.peer_identity_binding
    }

    /// Exact handshake/transcript evidence binding carried by the qualified session.
    pub fn session_evidence_binding(&self) -> &str {
        &self.session_evidence_binding
    }

    /// Authority generation carried by the exact qualified session.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Trusted admission time carried by the exact qualified session.
    pub const fn session_authenticated_at_ms(&self) -> u64 {
        self.session_authenticated_at_ms
    }

    /// Exclusive expiry carried by the exact qualified session.
    pub const fn session_expires_at_ms(&self) -> u64 {
        self.session_expires_at_ms
    }

    /// Observation instant qualified by history.
    pub const fn observation_at_ms(&self) -> u64 {
        self.observation_at_ms
    }

    /// Opaque binding to the exact signed history head supporting this qualification.
    pub fn provider_history_binding(&self) -> &str {
        &self.provider_history_binding
    }

    /// Sequence number of the exact signed history head supporting this qualification.
    pub const fn history_head_sequence(&self) -> u64 {
        self.history_head_sequence
    }

    /// Completeness horizon of the signed history supporting this qualification.
    pub const fn history_observed_through_ms(&self) -> u64 {
        self.history_observed_through_ms
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
    /// Supplied Xenia verified-session evidence failed its own canonical shape validation.
    #[error("verified machine-session evidence is malformed")]
    InvalidVerifiedSessionEvidence,
    /// Verified session names a machine principal different from this signed authority history.
    #[error("verified machine-session principal does not match signed authority history")]
    SessionIdentityMismatch,
    /// The admitted session has an empty or reversed validity interval.
    #[error("historical qualification requires a positive admitted-session interval")]
    InvalidSessionInterval,
    /// The observation is at or beyond the exact admitted session's exclusive expiry.
    #[error("observation lies outside the admitted session validity interval")]
    ObservationOutsideSession,
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

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_history::{
        MachineAuthorityGrantV1, MachineAuthorityHistoryHeadV1,
        MachineAuthorityHistoryTransitionV1,
    };
    use crate::handshake::{HandshakeOutcome, VerifiedPeerIdentity};
    use crate::machine_authority::{MachineAuthorityPolicyV1, MachineAuthorityRecordV1};
    use crate::verified_session_evidence::VerifiedMachineSessionEvidenceV1;
    use ed25519_dalek::SigningKey;
    use xenia_handshake::derive_session_key_schedule;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn event_for(peer_identity_fingerprint: [u8; 32]) -> MachineAuthorityHistoryEventV1 {
        MachineAuthorityHistoryEventV1 {
            schema_version: 1,
            sequence: 0,
            previous_event_digest: None,
            peer_identity_fingerprint,
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
            peer_identity_fingerprint: event.peer_identity_fingerprint,
            head_sequence: event.sequence,
            head_digest: event.content_digest().unwrap(),
            observed_through_ms,
            fresh_until_ms,
        }
        .sign(&key())
        .unwrap()
    }

    fn peer(byte: u8) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [byte; 32],
            ml_dsa_pk: vec![byte.wrapping_add(1); xenia_handshake::ML_DSA_65_PK_LEN],
        }
    }

    fn outcome() -> HandshakeOutcome {
        let transcript_hash = [0x22; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([0x33; 32]),
            host_identity_fingerprint: [0x44; 32],
        }
    }

    fn verified_session(peer: &VerifiedPeerIdentity) -> VerifiedMachineSessionEvidenceV1 {
        let outcome = outcome();
        let policy = MachineAuthorityPolicyV1::new(
            [MachineAuthorityRecordV1 {
                peer_identity_fingerprint: peer.signing_identity_fingerprint(),
                authority_epoch: 9,
                valid_from_ms: 100,
                valid_until_ms: 1_000,
                revoked: false,
            }],
            100,
        )
        .unwrap();
        let admission = policy
            .admit_verified_session(peer, &outcome, 200, true)
            .unwrap();
        VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome,
            peer,
            "session-history-test",
            &admission,
        )
        .unwrap()
    }

    fn accepted_for(
        fingerprint: [u8; 32],
        observed_through_ms: u64,
        fresh_until_ms: u64,
    ) -> AcceptedMachineAuthorityHistoryV1 {
        let event = event_for(fingerprint);
        let signed = head(&event, observed_through_ms, fresh_until_ms);
        verify_machine_authority_history_with_policy(
            &[event],
            &signed,
            &key().verifying_key(),
            None,
            MachineAuthorityHistoryAcceptancePolicyV1::new(
                fresh_until_ms - observed_through_ms,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn local_policy_accepts_equal_or_shorter_provider_freshness() {
        let peer = peer(0x55);
        let event = event_for(peer.signing_identity_fingerprint());
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
        let peer = peer(0x55);
        let event = event_for(peer.signing_identity_fingerprint());
        let signed = head(&event, 200, 301);
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(100).unwrap();

        assert!(matches!(
            verify_machine_authority_history_with_policy(
                std::slice::from_ref(&event),
                &signed,
                &key().verifying_key(),
                None,
                policy,
            ),
            Err(MachineAuthorityHistoryAcceptanceError::FreshnessWindowTooLong)
        ));
    }

    #[test]
    fn historical_qualification_is_bound_to_actual_verified_session() {
        let peer = peer(0x55);
        let session = verified_session(&peer);
        let accepted = accepted_for(peer.signing_identity_fingerprint(), 250, 300);
        let qualified = accepted
            .qualify_verified_session_observation(&session, 249)
            .unwrap();

        assert_eq!(qualified.provider_schema(), session.schema());
        assert_eq!(qualified.session_id(), session.session_id());
        assert_eq!(qualified.peer_identity_binding(), session.peer_identity_binding());
        assert_eq!(qualified.session_evidence_binding(), session.evidence_binding());
        assert_eq!(qualified.authority_epoch(), session.authority_epoch());
        assert_eq!(qualified.session_authenticated_at_ms(), session.authenticated_at_ms());
        assert_eq!(qualified.session_expires_at_ms(), session.expires_at_ms());
        assert_eq!(qualified.observation_at_ms(), 249);
        assert_eq!(qualified.history_observed_through_ms(), 250);
        assert!(qualified
            .provider_history_binding()
            .starts_with(MACHINE_AUTHORITY_HISTORY_BINDING_PREFIX_V1));
    }

    #[test]
    fn history_for_another_machine_cannot_qualify_verified_session() {
        let session_peer = peer(0x55);
        let history_peer = peer(0x77);
        let session = verified_session(&session_peer);
        let accepted = accepted_for(history_peer.signing_identity_fingerprint(), 250, 300);

        assert_eq!(
            accepted.qualify_verified_session_observation(&session, 249),
            Err(MachineAuthorityHistoryAcceptanceError::SessionIdentityMismatch)
        );
    }

    #[test]
    fn verified_session_expiry_is_not_extendable_by_long_authority_epoch() {
        let peer = peer(0x55);
        let session = verified_session(&peer);
        let accepted = accepted_for(peer.signing_identity_fingerprint(), 400, 450);
        assert_eq!(session.expires_at_ms(), 300);

        assert_eq!(
            accepted.qualify_verified_session_observation(&session, 300),
            Err(MachineAuthorityHistoryAcceptanceError::ObservationOutsideSession)
        );
        assert!(accepted
            .qualify_verified_session_observation(&session, 299)
            .is_ok());
    }

    #[test]
    fn historical_audit_survives_current_freshness_expiry() {
        let peer = peer(0x55);
        let session = verified_session(&peer);
        let accepted = accepted_for(peer.signing_identity_fingerprint(), 299, 300);

        assert!(accepted
            .qualify_verified_session_observation(&session, 250)
            .is_ok());
        assert_eq!(
            accepted.qualify_current_snapshot(300, true),
            Err(MachineAuthorityHistoryAcceptanceError::History(
                MachineAuthorityHistoryError::StaleHistoryHead
            ))
        );
        assert!(accepted
            .qualify_verified_session_observation(&session, 250)
            .is_ok());
    }

    #[test]
    fn local_freshness_policy_is_not_deserializable_remote_authority() {
        assert!(MachineAuthorityHistoryAcceptancePolicyV1::new(0).is_err());
        let policy = MachineAuthorityHistoryAcceptancePolicyV1::new(60_000).unwrap();
        assert_eq!(policy.max_snapshot_freshness_ms(), 60_000);
    }
}
