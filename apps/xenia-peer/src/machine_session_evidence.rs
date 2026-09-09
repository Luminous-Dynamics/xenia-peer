// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bind a cryptographically verified Xenia peer to the daemon's current operator authority.
//!
//! The handshake proves control of an Ed25519 + ML-DSA-65 key pair. This module
//! then requires that exact pair to be enrolled and not currently revoked before
//! minting portable machine-session evidence. Point-of-use context is recomputed
//! from the live policy so key replacement, de-enrollment, or revocation invalidates
//! an already-issued session without rewriting its immutable handshake evidence.

use crate::operator::{EnrolledOperator, OperatorPolicy};
use crate::operator_revocations::OperatorRevocations;
use xenia_peer_core::handshake::{HandshakeOutcome, VerifiedPeerIdentity};
use xenia_peer_core::{
    MachineSessionAuthorityContextV1, VerifiedMachineSessionEvidenceV1,
    VerifiedSessionEvidenceError,
};

/// Error while binding a verified cryptographic peer to operator authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MachineSessionAdmissionError {
    /// The verified hybrid key pair is not an exact current enrollment.
    #[error("verified peer identity is not currently enrolled")]
    NotEnrolled,
    /// The matching enrolled operator is currently revoked.
    #[error("verified operator is currently revoked")]
    Revoked,
    /// The portable evidence shape was invalid.
    #[error(transparent)]
    Evidence(#[from] VerifiedSessionEvidenceError),
}

/// Immutable portable evidence plus the local operator id needed to refresh
/// current authorization state later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedMachineSession {
    pub(crate) operator_id: String,
    pub(crate) evidence: VerifiedMachineSessionEvidenceV1,
}

/// Admit the exact hybrid identity authenticated by the host-side handshake.
///
/// This function is the intended construction path for machine-session evidence
/// in the daemon: the caller cannot substitute an operator id or role independent
/// of the verified signing keys.
pub(crate) fn admit_verified_machine_session(
    outcome: &HandshakeOutcome,
    peer: &VerifiedPeerIdentity,
    policy: &OperatorPolicy,
    revocations: &OperatorRevocations,
    session_id: impl Into<String>,
    authenticated_at_ms: u64,
    expires_at_ms: u64,
) -> Result<AuthorizedMachineSession, MachineSessionAdmissionError> {
    let enrolled = policy
        .lookup_verified(&peer.ed25519_pk, &peer.ml_dsa_pk)
        .ok_or(MachineSessionAdmissionError::NotEnrolled)?;
    if revocations.is_revoked(&enrolled.operator_id) {
        return Err(MachineSessionAdmissionError::Revoked);
    }

    let epoch = authority_epoch(&enrolled);
    let evidence = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
        outcome,
        peer,
        session_id,
        authenticated_at_ms,
        expires_at_ms,
        epoch,
    )?;

    Ok(AuthorizedMachineSession {
        operator_id: enrolled.operator_id,
        evidence,
    })
}

/// Refresh the live trust facts for an already-issued session.
///
/// Missing enrollment is treated exactly like revocation. A live key replacement
/// changes the deterministic authority epoch, so a consumer comparing this context
/// to the session's issuance epoch fails closed even if the operator id itself did
/// not change.
pub(crate) fn current_machine_session_context(
    policy: &OperatorPolicy,
    revocations: &OperatorRevocations,
    operator_id: &str,
    now_ms: u64,
    trusted_time_available: bool,
) -> MachineSessionAuthorityContextV1 {
    let Some(enrolled) = policy.lookup_by_id(operator_id) else {
        return MachineSessionAuthorityContextV1 {
            now_ms,
            authority_epoch: 0,
            trusted_time_available,
            revoked: true,
        };
    };

    MachineSessionAuthorityContextV1 {
        now_ms,
        authority_epoch: authority_epoch(&enrolled),
        trusted_time_available,
        revoked: revocations.is_revoked(operator_id),
    }
}

/// Deterministic generation identifier for the authority state relevant to one
/// enrolled operator.
///
/// The epoch intentionally binds only facts that can change this operator's
/// authority: id, exact hybrid signing keys, optional high-security key, and role.
/// Changes to unrelated operators do not invalidate an otherwise unchanged live
/// session. The full BLAKE3 digest is truncated to u64 because the current
/// cross-repo consumer contract uses a compact epoch equality check; this is a
/// generation discriminator, not a cryptographic authenticator.
fn authority_epoch(operator: &EnrolledOperator) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia-operator-authority-epoch-v1\0");
    hash_bytes(&mut hasher, operator.operator_id.as_bytes());
    hash_bytes(&mut hasher, &operator.ed25519_pubkey);
    hash_bytes(&mut hasher, &operator.ml_dsa_pubkey);
    match &operator.ml_dsa_87_pubkey {
        Some(key) => {
            hasher.update(&[1]);
            hash_bytes(&mut hasher, key);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hash_bytes(&mut hasher, operator.role.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(epoch)
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::OperatorRole;
    use xenia_handshake::{ML_DSA_65_PK_LEN, derive_session_key_schedule};

    fn enrolled(id: &str, ed: u8, pq: u8) -> EnrolledOperator {
        EnrolledOperator {
            operator_id: id.into(),
            ed25519_pubkey: [ed; 32],
            ml_dsa_pubkey: vec![pq; ML_DSA_65_PK_LEN],
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }
    }

    fn peer(ed: u8, pq: u8) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [ed; 32],
            ml_dsa_pk: vec![pq; ML_DSA_65_PK_LEN],
        }
    }

    fn outcome() -> HandshakeOutcome {
        let transcript_hash = [0x44; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([0x55; 32]),
            host_identity_fingerprint: [0x66; 32],
        }
    }

    #[test]
    fn exact_verified_hybrid_identity_is_admitted() {
        let policy = OperatorPolicy::from_operators(vec![enrolled("alice", 1, 2)]).unwrap();
        let revocations = OperatorRevocations::empty();
        let authorized = admit_verified_machine_session(
            &outcome(),
            &peer(1, 2),
            &policy,
            &revocations,
            "session-a",
            100,
            200,
        )
        .unwrap();

        assert_eq!(authorized.operator_id, "alice");
        assert_eq!(authorized.evidence.authenticated_at_ms, 100);
        assert!(!authorized.evidence.peer_identity_binding.is_empty());
        assert!(!authorized.evidence.evidence_binding.is_empty());
    }

    #[test]
    fn ed25519_match_with_wrong_pq_key_is_not_enrolled() {
        let policy = OperatorPolicy::from_operators(vec![enrolled("alice", 1, 2)]).unwrap();
        let revocations = OperatorRevocations::empty();
        assert_eq!(
            admit_verified_machine_session(
                &outcome(),
                &peer(1, 9),
                &policy,
                &revocations,
                "session-a",
                100,
                200,
            ),
            Err(MachineSessionAdmissionError::NotEnrolled)
        );
    }

    #[test]
    fn live_revocation_invalidates_context_without_rewriting_session() {
        let policy = OperatorPolicy::from_operators(vec![enrolled("alice", 1, 2)]).unwrap();
        let revocations = OperatorRevocations::empty();
        let authorized = admit_verified_machine_session(
            &outcome(),
            &peer(1, 2),
            &policy,
            &revocations,
            "session-a",
            100,
            200,
        )
        .unwrap();

        let before = current_machine_session_context(&policy, &revocations, "alice", 150, true);
        assert!(!before.revoked);
        assert_eq!(before.authority_epoch, authorized.evidence.authority_epoch);

        revocations.revoke("alice");
        let after = current_machine_session_context(&policy, &revocations, "alice", 151, true);
        assert!(after.revoked);
        assert_eq!(after.authority_epoch, authorized.evidence.authority_epoch);
    }

    #[test]
    fn live_key_replacement_changes_authority_epoch() {
        let policy = OperatorPolicy::from_operators(vec![enrolled("alice", 1, 2)]).unwrap();
        let revocations = OperatorRevocations::empty();
        let authorized = admit_verified_machine_session(
            &outcome(),
            &peer(1, 2),
            &policy,
            &revocations,
            "session-a",
            100,
            200,
        )
        .unwrap();

        policy
            .replace_operator_key(
                "alice",
                [3; 32],
                vec![4; ML_DSA_65_PK_LEN],
                None,
            )
            .unwrap();

        let current = current_machine_session_context(&policy, &revocations, "alice", 150, true);
        assert!(!current.revoked);
        assert_ne!(current.authority_epoch, authorized.evidence.authority_epoch);
    }

    #[test]
    fn missing_current_enrollment_fails_closed_as_revoked_context() {
        let empty = OperatorPolicy::from_operators(vec![]).unwrap();
        let current = current_machine_session_context(
            &empty,
            &OperatorRevocations::empty(),
            "alice",
            150,
            true,
        );
        assert!(current.revoked);
        assert_eq!(current.authority_epoch, 0);
    }
}
