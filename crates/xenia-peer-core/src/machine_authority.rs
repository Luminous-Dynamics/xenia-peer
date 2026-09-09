// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Local machine/peer authority admission, deliberately separate from human operator RBAC.
//!
//! A successful Xenia handshake proves control of a hybrid signing identity; it does not grant
//! application authority. This module binds that already-verified identity to an explicit local
//! machine policy and mints a short-lived, non-serializable admission object. Portable session
//! evidence can then require that admission instead of accepting caller-supplied authority epochs
//! or validity horizons.

use std::collections::BTreeMap;

use crate::handshake::VerifiedPeerIdentity;
use crate::verified_session_evidence::MachineSessionAuthorityContextV1;

/// One machine identity's current local authority record.
///
/// This is policy input, not portable session evidence. Persistence/authentication of a policy
/// file belongs to the embedding application; this type only defines the validated in-memory
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
#[derive(Debug, Clone, Default)]
pub struct MachineAuthorityPolicyV1 {
    records: BTreeMap<[u8; 32], MachineAuthorityRecordV1>,
}

/// Non-serializable proof that the current policy admitted one already-verified peer.
///
/// Fields are private and there is no public constructor. External code cannot manufacture an
/// admission by supplying an epoch directly; it must ask [`MachineAuthorityPolicyV1`] to admit
/// the exact [`VerifiedPeerIdentity`] produced by the handshake verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthorityAdmissionV1 {
    peer_identity_fingerprint: [u8; 32],
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
    /// No current machine-policy record exists for the verified peer identity.
    #[error("verified peer identity is not enrolled in machine authority policy")]
    UnknownIdentity,
    /// The enrolled machine identity is currently revoked.
    #[error("machine identity is revoked")]
    Revoked,
    /// Current trusted time is outside the machine authority record's validity window.
    #[error("machine authority record is not currently valid")]
    OutsideValidity,
    /// Requested admission lifetime was zero.
    #[error("requested machine-session lifetime must be positive")]
    InvalidRequestedLifetime,
    /// Computing the requested validity horizon overflowed.
    #[error("requested machine-session lifetime overflowed")]
    LifetimeOverflow,
}

impl MachineAuthorityPolicyV1 {
    /// Build a policy while rejecting duplicate identities and malformed validity windows.
    pub fn new(
        records: impl IntoIterator<Item = MachineAuthorityRecordV1>,
    ) -> Result<Self, MachineAuthorityError> {
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
        })
    }

    /// Admit an already-authenticated peer for a bounded lifetime.
    ///
    /// `requested_lifetime_ms` is clamped to the authority record's own end time; a caller cannot
    /// extend session evidence beyond the policy that admitted the identity.
    pub fn admit_verified_peer(
        &self,
        peer: &VerifiedPeerIdentity,
        now_ms: u64,
        requested_lifetime_ms: u64,
    ) -> Result<MachineAuthorityAdmissionV1, MachineAuthorityError> {
        if requested_lifetime_ms == 0 {
            return Err(MachineAuthorityError::InvalidRequestedLifetime);
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
        let requested_until = now_ms
            .checked_add(requested_lifetime_ms)
            .ok_or(MachineAuthorityError::LifetimeOverflow)?;
        let expires_at_ms = requested_until.min(record.valid_until_ms);
        Ok(MachineAuthorityAdmissionV1 {
            peer_identity_fingerprint: fingerprint,
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
            Some(record) => MachineSessionAuthorityContextV1 {
                now_ms,
                authority_epoch: record.authority_epoch,
                trusted_time_available,
                revoked: record.revoked
                    || now_ms < record.valid_from_ms
                    || now_ms >= record.valid_until_ms,
            },
            None => MachineSessionAuthorityContextV1 {
                now_ms,
                authority_epoch: admission.authority_epoch,
                trusted_time_available,
                revoked: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [byte; 32],
            ml_dsa_pk: vec![byte.wrapping_add(1); xenia_handshake::ML_DSA_65_PK_LEN],
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

    #[test]
    fn exact_verified_identity_is_required_for_admission() {
        let enrolled = peer(7);
        let policy = MachineAuthorityPolicyV1::new([record_for(&enrolled)]).unwrap();
        assert!(policy.admit_verified_peer(&enrolled, 200, 100).is_ok());
        assert_eq!(
            policy.admit_verified_peer(&peer(8), 200, 100),
            Err(MachineAuthorityError::UnknownIdentity)
        );
    }

    #[test]
    fn admission_is_clamped_to_policy_horizon() {
        let enrolled = peer(7);
        let policy = MachineAuthorityPolicyV1::new([record_for(&enrolled)]).unwrap();
        let admission = policy.admit_verified_peer(&enrolled, 900, 500).unwrap();
        assert_eq!(admission.admitted_at_ms(), 900);
        assert_eq!(admission.expires_at_ms(), 1_000);
        assert_eq!(admission.authority_epoch(), 9);
    }

    #[test]
    fn revoked_or_out_of_window_identity_fails_closed() {
        let enrolled = peer(7);
        let mut record = record_for(&enrolled);
        record.revoked = true;
        let policy = MachineAuthorityPolicyV1::new([record]).unwrap();
        assert_eq!(
            policy.admit_verified_peer(&enrolled, 200, 100),
            Err(MachineAuthorityError::Revoked)
        );

        let policy = MachineAuthorityPolicyV1::new([record_for(&enrolled)]).unwrap();
        assert_eq!(
            policy.admit_verified_peer(&enrolled, 1_000, 100),
            Err(MachineAuthorityError::OutsideValidity)
        );
    }

    #[test]
    fn live_context_exposes_revocation_and_epoch_rotation() {
        let enrolled = peer(7);
        let policy = MachineAuthorityPolicyV1::new([record_for(&enrolled)]).unwrap();
        let admission = policy.admit_verified_peer(&enrolled, 200, 100).unwrap();
        let context = policy.context_for(&admission, 250, true);
        assert!(!context.revoked);
        assert_eq!(context.authority_epoch, 9);

        let mut rotated = record_for(&enrolled);
        rotated.authority_epoch = 10;
        let policy = MachineAuthorityPolicyV1::new([rotated]).unwrap();
        let context = policy.context_for(&admission, 250, true);
        assert!(!context.revoked);
        assert_eq!(context.authority_epoch, 10);

        let context = policy.context_for(&admission, 1_000, true);
        assert!(context.revoked);
    }

    #[test]
    fn malformed_or_duplicate_policy_records_are_rejected() {
        let enrolled = peer(7);
        let mut invalid = record_for(&enrolled);
        invalid.valid_until_ms = invalid.valid_from_ms;
        assert!(matches!(
            MachineAuthorityPolicyV1::new([invalid]),
            Err(MachineAuthorityError::InvalidRecordValidity)
        ));

        let record = record_for(&enrolled);
        assert!(matches!(
            MachineAuthorityPolicyV1::new([record.clone(), record]),
            Err(MachineAuthorityError::DuplicateIdentity)
        ));
    }
}
