// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Local machine/peer authority admission, deliberately separate from human operator RBAC.
//!
//! A successful Xenia handshake proves control of a hybrid signing identity; it does not grant
//! application authority. This module binds that already-verified identity and exact handshake to
//! an explicit local machine policy and mints a short-lived, non-serializable admission object.
//! Portable session evidence can then require that admission instead of accepting caller-supplied
//! authority epochs, time bounds, revocation assertions, or a reusable identity-only approval.

use std::collections::BTreeMap;

use crate::handshake::{HandshakeOutcome, VerifiedPeerIdentity};
use crate::verified_session_evidence::MachineSessionAuthorityContextV1;

/// One machine identity's current local authority record.
///
/// This is policy input, not portable session evidence. Persistence/authentication of a policy
/// file belongs to the embedding application; this type defines only the validated in-memory
/// semantics used by `xenia-peer-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthorityRecordV1 {
    /// Exact domain-separated fingerprint of the verified Ed25519 + ML-DSA signing identity.
    pub peer_identity_fingerprint: [u8; 32],
    /// Monotonic generation of this machine authority record.
    pub authority_epoch: u64,
    /// Inclusive trusted-time start of the authority record.
    pub valid_from_ms: u64,
    /// Exclusive trusted-time end of the authority record.
    pub valid_until_ms: u64,
    /// Current local revocation state.
    pub revoked: bool,
}

impl MachineAuthorityRecordV1 {
    /// Validate the time bounds of this policy record.
    pub fn validate(&self) -> Result<(), MachineAuthorityError> {
        if self.valid_until_ms <= self.valid_from_ms {
            return Err(MachineAuthorityError::InvalidRecordValidity);
        }
        Ok(())
    }
}

/// Validated local authority policy keyed by the exact hybrid peer identity fingerprint.
#[derive(Debug, Clone)]
pub struct MachineAuthorityPolicyV1 {
    records: BTreeMap<[u8; 32], MachineAuthorityRecordV1>,
    max_session_lifetime_ms: u64,
}

/// Non-serializable proof that current policy admitted one exact verified handshake.
///
/// Fields are private and there is no public constructor. External code cannot manufacture an
/// admission by supplying an epoch/time horizon directly; it must ask
/// [`MachineAuthorityPolicyV1`] to admit the exact [`VerifiedPeerIdentity`] and
/// [`HandshakeOutcome`] produced by the handshake verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthorityAdmissionV1 {
    peer_identity_fingerprint: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
    authority_epoch: u64,
    admitted_at_ms: u64,
    expires_at_ms: u64,
}

impl MachineAuthorityAdmissionV1 {
    /// Exact hybrid signing identity admitted by policy.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Authority generation that admitted this peer.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Trusted-time instant at which admission was evaluated.
    pub const fn admitted_at_ms(&self) -> u64 {
        self.admitted_at_ms
    }

    /// Exclusive hard expiry of this admission.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Whether this admission belongs to the exact completed handshake outcome.
    pub(crate) fn matches_handshake(&self, outcome: &HandshakeOutcome) -> bool {
        self.handshake_transcript_hash == outcome.transcript_hash
            && self.negotiated_context_hash == outcome.negotiated_context_hash
    }
}

/// Machine-authority admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineAuthorityError {
    /// More than one policy record names the same hybrid identity.
    #[error("duplicate machine identity in authority policy")]
    DuplicateIdentity,
    /// A policy record has an empty or reversed validity interval.
    #[error("machine authority record must have a positive validity interval")]
    InvalidRecordValidity,
    /// Policy configured a zero maximum session lifetime.
    #[error("machine authority policy must have a positive maximum session lifetime")]
    InvalidMaximumSessionLifetime,
    /// No current machine-policy record exists for the verified peer identity.
    #[error("verified peer identity is not enrolled in machine authority policy")]
    UnknownIdentity,
    /// The enrolled machine identity is currently revoked.
    #[error("machine identity is revoked")]
    Revoked,
    /// Current trusted time is outside the machine authority record's validity window.
    #[error("machine authority record is not currently valid")]
    OutsideValidity,
    /// Admission was attempted without an authority-approved trusted time source.
    #[error("trusted time is required for machine authority admission")]
    UntrustedTime,
    /// Computing the policy-owned validity horizon overflowed.
    #[error("machine-session validity horizon overflowed")]
    LifetimeOverflow,
}

impl MachineAuthorityPolicyV1 {
    /// Build a policy while rejecting duplicate identities, malformed validity windows and a
    /// zero session-lifetime bound.
    pub fn new(
        records: impl IntoIterator<Item = MachineAuthorityRecordV1>,
        max_session_lifetime_ms: u64,
    ) -> Result<Self, MachineAuthorityError> {
        if max_session_lifetime_ms == 0 {
            return Err(MachineAuthorityError::InvalidMaximumSessionLifetime);
        }
        let mut by_identity = BTreeMap::new();
        for record in records {
            record.validate()?;
            let fingerprint = record.peer_identity_fingerprint;
            if by_identity.insert(fingerprint, record).is_some() {
                return Err(MachineAuthorityError::DuplicateIdentity);
            }
        }
        Ok(Self {
            records: by_identity,
            max_session_lifetime_ms,
        })
    }

    /// Admit one already-authenticated handshake using only policy-owned authority/lifetime bounds.
    ///
    /// The caller supplies current time plus whether that time is actually trusted; it does not
    /// supply an authority generation or requested lifetime. Expiry is the earlier of the
    /// deployment's maximum session lifetime and the enrolled identity's own validity horizon.
    /// The returned admission is bound to this exact transcript and negotiated context.
    pub fn admit_verified_session(
        &self,
        peer: &VerifiedPeerIdentity,
        outcome: &HandshakeOutcome,
        now_ms: u64,
        trusted_time_available: bool,
    ) -> Result<MachineAuthorityAdmissionV1, MachineAuthorityError> {
        if !trusted_time_available {
            return Err(MachineAuthorityError::UntrustedTime);
        }
        let fingerprint = peer.signing_identity_fingerprint();
        let record = self
            .records
            .get(&fingerprint)
            .ok_or(MachineAuthorityError::UnknownIdentity)?;
        if record.revoked {
            return Err(MachineAuthorityError::Revoked);
        }
        if now_ms < record.valid_from_ms || now_ms >= record.valid_until_ms {
            return Err(MachineAuthorityError::OutsideValidity);
        }
        let policy_until = now_ms
            .checked_add(self.max_session_lifetime_ms)
            .ok_or(MachineAuthorityError::LifetimeOverflow)?;
        let expires_at_ms = policy_until.min(record.valid_until_ms);
        Ok(MachineAuthorityAdmissionV1 {
            peer_identity_fingerprint: fingerprint,
            handshake_transcript_hash: outcome.transcript_hash,
            negotiated_context_hash: outcome.negotiated_context_hash,
            authority_epoch: record.authority_epoch,
            admitted_at_ms: now_ms,
            expires_at_ms,
        })
    }

    /// Re-evaluate live authority facts for a previously minted admission.
    ///
    /// Missing enrollment fails closed as revoked. Epoch rotation is exposed independently so a
    /// consumer can distinguish revocation from replacement of the authority generation.
    pub fn context_for(
        &self,
        admission: &MachineAuthorityAdmissionV1,
        now_ms: u64,
        trusted_time_available: bool,
    ) -> MachineSessionAuthorityContextV1 {
        match self.records.get(&admission.peer_identity_fingerprint) {
            Some(record) => MachineSessionAuthorityContextV1::from_policy(
                now_ms,
                record.authority_epoch,
                trusted_time_available,
                record.revoked || now_ms < record.valid_from_ms || now_ms >= record.valid_until_ms,
            ),
            None => MachineSessionAuthorityContextV1::from_policy(
                now_ms,
                admission.authority_epoch,
                trusted_time_available,
                true,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake::derive_session_key_schedule;

    fn peer(byte: u8) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [byte; 32],
            ml_dsa_pk: vec![byte.wrapping_add(1); xenia_handshake::ML_DSA_65_PK_LEN],
        }
    }

    fn outcome(byte: u8) -> HandshakeOutcome {
        let transcript_hash = [byte; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([byte.wrapping_add(1); 32]),
            host_identity_fingerprint: [0x44; 32],
        }
    }

    fn record_for(peer: &VerifiedPeerIdentity) -> MachineAuthorityRecordV1 {
        MachineAuthorityRecordV1 {
            peer_identity_fingerprint: peer.signing_identity_fingerprint(),
            authority_epoch: 9,
            valid_from_ms: 100,
            valid_until_ms: 1_000,
            revoked: false,
        }
    }

    fn policy_for(peer: &VerifiedPeerIdentity) -> MachineAuthorityPolicyV1 {
        MachineAuthorityPolicyV1::new([record_for(peer)], 100).unwrap()
    }

    #[test]
    fn exact_verified_identity_is_required_for_admission() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let policy = policy_for(&enrolled);
        assert!(policy
            .admit_verified_session(&enrolled, &handshake, 200, true)
            .is_ok());
        assert_eq!(
            policy.admit_verified_session(&peer(8), &handshake, 200, true),
            Err(MachineAuthorityError::UnknownIdentity)
        );
    }

    #[test]
    fn admission_is_bound_to_exact_handshake() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let other_handshake = outcome(0x33);
        let policy = policy_for(&enrolled);
        let admission = policy
            .admit_verified_session(&enrolled, &handshake, 200, true)
            .unwrap();
        assert!(admission.matches_handshake(&handshake));
        assert!(!admission.matches_handshake(&other_handshake));
    }

    #[test]
    fn admission_lifetime_is_owned_by_policy_and_clamped_to_record_horizon() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let policy = policy_for(&enrolled);
        let admission = policy
            .admit_verified_session(&enrolled, &handshake, 200, true)
            .unwrap();
        assert_eq!(admission.admitted_at_ms(), 200);
        assert_eq!(admission.expires_at_ms(), 300);

        let admission = policy
            .admit_verified_session(&enrolled, &handshake, 950, true)
            .unwrap();
        assert_eq!(admission.expires_at_ms(), 1_000);
        assert_eq!(admission.authority_epoch(), 9);
    }

    #[test]
    fn untrusted_clock_cannot_mint_admission() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let policy = policy_for(&enrolled);
        assert_eq!(
            policy.admit_verified_session(&enrolled, &handshake, 200, false),
            Err(MachineAuthorityError::UntrustedTime)
        );
    }

    #[test]
    fn revoked_or_out_of_window_identity_fails_closed() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let mut record = record_for(&enrolled);
        record.revoked = true;
        let policy = MachineAuthorityPolicyV1::new([record], 100).unwrap();
        assert_eq!(
            policy.admit_verified_session(&enrolled, &handshake, 200, true),
            Err(MachineAuthorityError::Revoked)
        );

        let policy = policy_for(&enrolled);
        assert_eq!(
            policy.admit_verified_session(&enrolled, &handshake, 1_000, true),
            Err(MachineAuthorityError::OutsideValidity)
        );
    }

    #[test]
    fn live_context_exposes_revocation_and_epoch_rotation() {
        let enrolled = peer(7);
        let handshake = outcome(0x22);
        let policy = policy_for(&enrolled);
        let admission = policy
            .admit_verified_session(&enrolled, &handshake, 200, true)
            .unwrap();
        let context = policy.context_for(&admission, 250, true);
        assert!(!context.revoked());
        assert_eq!(context.authority_epoch(), 9);
        assert_eq!(context.now_ms(), 250);
        assert!(context.trusted_time_available());

        let mut rotated = record_for(&enrolled);
        rotated.authority_epoch = 10;
        let policy = MachineAuthorityPolicyV1::new([rotated], 100).unwrap();
        let context = policy.context_for(&admission, 250, true);
        assert!(!context.revoked());
        assert_eq!(context.authority_epoch(), 10);

        let context = policy.context_for(&admission, 1_000, true);
        assert!(context.revoked());
    }

    #[test]
    fn malformed_duplicate_or_unbounded_policy_records_are_rejected() {
        let enrolled = peer(7);
        let mut invalid = record_for(&enrolled);
        invalid.valid_until_ms = invalid.valid_from_ms;
        assert!(matches!(
            MachineAuthorityPolicyV1::new([invalid], 100),
            Err(MachineAuthorityError::InvalidRecordValidity)
        ));

        let record = record_for(&enrolled);
        assert!(matches!(
            MachineAuthorityPolicyV1::new([record.clone(), record], 100),
            Err(MachineAuthorityError::DuplicateIdentity)
        ));
        assert!(matches!(
            MachineAuthorityPolicyV1::new([record_for(&enrolled)], 0),
            Err(MachineAuthorityError::InvalidMaximumSessionLifetime)
        ));
    }
}
