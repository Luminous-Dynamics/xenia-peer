// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reusable Forge-bound Xenia hybrid-authentication verifier.
//!
//! The verifier owns cryptographic verification and receipt issuance, while
//! challenge storage and enrollment authority are injected through small
//! traits. This keeps the proof reusable without importing the xenia-peer
//! daemon's HTTP/session/RBAC machinery.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_forge_auth_receipt::{
    ForgeAuthenticationReceiptV1, ForgeDigest, ForgeReceiptError, XeniaHybridSuite,
    challenge_commitment, challenge_consumption_evidence, cryptographic_evidence_commitment,
    forge_authentication_transcript, key_lineage_commitment, operator_id_commitment,
    verifier_state_commitment, RECEIPT_VERSION,
};
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

/// One signed Forge-bound Xenia authentication response.
#[derive(Clone)]
pub struct ForgeAuthenticationResponse {
    /// Exact SHA-256 of the Forge authentication request.
    pub forge_request_commitment: [u8; 32],
    /// One-time verifier challenge.
    pub challenge: [u8; 32],
    /// Presented Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Presented ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Ed25519 signature over the Forge-bound transcript.
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 signature over the same transcript.
    pub ml_dsa_65_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Authoritative enrollment returned only when the exact presented hybrid key
/// pair belongs to one current logical Xenia operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnrollment {
    /// Stable logical Xenia operator id.
    pub operator_id: String,
    /// Current role string from authoritative enrollment state.
    pub role: String,
    /// Authoritative Ed25519 key.
    pub ed25519_pubkey: [u8; 32],
    /// Authoritative ML-DSA-65 key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Optional authoritative ML-DSA-87 key.
    pub ml_dsa_87_pubkey: Option<Vec<u8>>,
}

/// Single-use challenge authority.
pub trait ChallengeConsumer {
    /// Consume `challenge` if it is currently outstanding and unexpired.
    /// Returning true must make a second consume of the same challenge fail.
    fn consume(&mut self, challenge: &[u8; 32], now_unix_secs: u64) -> bool;
}

/// Enrollment authority for exact hybrid key-pair resolution.
pub trait EnrollmentResolver {
    /// Resolve only if both public keys identify the same currently enrolled
    /// operator. Classical-only or mixed-pair lookup must return `None`.
    fn resolve_verified(
        &self,
        ed25519_pubkey: &[u8; 32],
        ml_dsa_65_pubkey: &[u8],
    ) -> Option<VerifiedEnrollment>;
}

/// Successful verified Forge authentication plus the portable receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedForgeAuthentication {
    /// Stable logical operator id authenticated by this run.
    pub operator_id: String,
    /// Current Xenia role observed from authoritative enrollment state.
    pub role: String,
    /// Portable receipt for Mycelix Forge FORGE-005B1.
    pub receipt: ForgeAuthenticationReceiptV1,
}

/// Verify the Forge-bound response and issue a receipt.
///
/// Ordering is fail-closed and mirrors Xenia's existing challenge ceremony:
/// the challenge is consumed before signature verification, then both
/// signatures must verify over the exact Forge-bound transcript, then the
/// exact hybrid key pair must resolve to one current enrollment record.
pub fn verify_and_issue_receipt<C, E>(
    challenges: &mut C,
    enrollments: &E,
    now_unix_secs: u64,
    response: &ForgeAuthenticationResponse,
) -> Result<VerifiedForgeAuthentication, ForgeVerifierError>
where
    C: ChallengeConsumer,
    E: EnrollmentResolver,
{
    if !challenges.consume(&response.challenge, now_unix_secs) {
        return Err(ForgeVerifierError::UnknownOrExpiredChallenge);
    }

    if response.ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(ForgeVerifierError::MalformedKey);
    }

    let transcript = forge_authentication_transcript(
        &response.forge_request_commitment,
        &response.challenge,
        &response.ed25519_pubkey,
        &response.ml_dsa_65_pubkey,
    )?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&response.ed25519_pubkey)
        .map_err(|_| ForgeVerifierError::MalformedKey)?;
    let ed_sig = Signature::from_bytes(&response.ed25519_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_sig)
        .map_err(|_| ForgeVerifierError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = response
        .ml_dsa_65_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ForgeVerifierError::MalformedKey)?;
    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &response.ml_dsa_65_signature)
        .map_err(|_| ForgeVerifierError::MlDsaVerifyFailed)?;

    let enrollment = enrollments
        .resolve_verified(&response.ed25519_pubkey, &response.ml_dsa_65_pubkey)
        .ok_or(ForgeVerifierError::NotEnrolled)?;

    // Fail closed if an adapter returned inconsistent authoritative state.
    if enrollment.ed25519_pubkey != response.ed25519_pubkey
        || enrollment.ml_dsa_65_pubkey != response.ml_dsa_65_pubkey
    {
        return Err(ForgeVerifierError::EnrollmentInconsistent);
    }

    let lineage = key_lineage_commitment(
        &enrollment.ed25519_pubkey,
        &enrollment.ml_dsa_65_pubkey,
        enrollment.ml_dsa_87_pubkey.as_deref(),
    )?;
    let operator = operator_id_commitment(&enrollment.operator_id)?;
    let challenge = challenge_commitment(&response.challenge);
    let crypto = cryptographic_evidence_commitment(
        &transcript,
        &response.ed25519_signature,
        &response.ml_dsa_65_signature,
    )?;
    let consumed = challenge_consumption_evidence(
        &response.challenge,
        &enrollment.operator_id,
        now_unix_secs,
    )?;
    let verifier_state = verifier_state_commitment(
        &enrollment.operator_id,
        &enrollment.role,
        &lineage,
    )?;

    let receipt = ForgeAuthenticationReceiptV1 {
        version: RECEIPT_VERSION,
        request_commitment: ForgeDigest::sha256(response.forge_request_commitment),
        operator_id_commitment: ForgeDigest::sha256(operator),
        key_lineage_commitment: ForgeDigest::sha256(lineage),
        challenge_commitment: ForgeDigest::sha256(challenge),
        suite: XeniaHybridSuite::Ed25519MlDsa65V1,
        cryptographic_evidence: ForgeDigest::sha256(crypto),
        challenge_consumption_evidence: ForgeDigest::sha256(consumed),
        verifier_state_commitment: ForgeDigest::sha256(verifier_state),
        verified_at_unix_secs: now_unix_secs,
    };

    Ok(VerifiedForgeAuthentication {
        operator_id: enrollment.operator_id,
        role: enrollment.role,
        receipt,
    })
}

/// Forge-bound Xenia verifier failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ForgeVerifierError {
    /// Challenge is absent, expired, or already consumed.
    #[error("unknown, expired, or already-consumed Forge authentication challenge")]
    UnknownOrExpiredChallenge,
    /// Presented public key has an invalid encoding/length.
    #[error("malformed Forge authentication public key")]
    MalformedKey,
    /// Ed25519 verification failed.
    #[error("Forge authentication Ed25519 verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 verification failed.
    #[error("Forge authentication ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
    /// Both signatures verified but the exact key pair is not enrolled.
    #[error("Forge authentication key pair is not currently enrolled")]
    NotEnrolled,
    /// Enrollment adapter returned state inconsistent with the resolved pair.
    #[error("Forge authentication enrollment resolver returned inconsistent state")]
    EnrollmentInconsistent,
    /// Receipt canonicalization failed.
    #[error(transparent)]
    Receipt(#[from] ForgeReceiptError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    struct Challenges {
        live: HashSet<[u8; 32]>,
    }

    impl ChallengeConsumer for Challenges {
        fn consume(&mut self, challenge: &[u8; 32], _now_unix_secs: u64) -> bool {
            self.live.remove(challenge)
        }
    }

    struct Enrollments {
        by_ed: HashMap<[u8; 32], VerifiedEnrollment>,
    }

    impl EnrollmentResolver for Enrollments {
        fn resolve_verified(
            &self,
            ed25519_pubkey: &[u8; 32],
            ml_dsa_65_pubkey: &[u8],
        ) -> Option<VerifiedEnrollment> {
            self.by_ed
                .get(ed25519_pubkey)
                .filter(|e| e.ml_dsa_65_pubkey.as_slice() == ml_dsa_65_pubkey)
                .cloned()
        }
    }

    fn fixture() -> (HandshakeManager, Challenges, Enrollments) {
        let op = HandshakeManager::new();
        let ed = op.identity_public_key_bytes();
        let ml = op.ml_dsa_public_key_bytes().to_vec();
        let mut by_ed = HashMap::new();
        by_ed.insert(
            ed,
            VerifiedEnrollment {
                operator_id: "op".into(),
                role: "Approver".into(),
                ed25519_pubkey: ed,
                ml_dsa_65_pubkey: ml,
                ml_dsa_87_pubkey: None,
            },
        );
        (
            op,
            Challenges {
                live: HashSet::from([[7u8; 32]]),
            },
            Enrollments { by_ed },
        )
    }

    fn response(op: &HandshakeManager, request: [u8; 32], challenge: [u8; 32]) -> ForgeAuthenticationResponse {
        let ed = op.identity_public_key_bytes();
        let ml = op.ml_dsa_public_key_bytes().to_vec();
        let transcript = forge_authentication_transcript(&request, &challenge, &ed, &ml).unwrap();
        ForgeAuthenticationResponse {
            forge_request_commitment: request,
            challenge,
            ed25519_pubkey: ed,
            ml_dsa_65_pubkey: ml,
            ed25519_signature: op.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: op.sign_ml_dsa(&transcript),
        }
    }

    #[test]
    fn exact_request_verifies_and_receipt_is_single_use() {
        let (op, mut challenges, enrollments) = fixture();
        let req = response(&op, [1; 32], [7; 32]);
        let verified = verify_and_issue_receipt(&mut challenges, &enrollments, 1000, &req).unwrap();
        assert_eq!(verified.operator_id, "op");
        assert_eq!(verified.receipt.request_commitment.as_sha256().unwrap(), [1; 32]);
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 1000, &req).unwrap_err(),
            ForgeVerifierError::UnknownOrExpiredChallenge
        );
    }

    #[test]
    fn request_substitution_breaks_signature() {
        let (op, mut challenges, enrollments) = fixture();
        let mut req = response(&op, [1; 32], [7; 32]);
        req.forge_request_commitment = [2; 32];
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 1000, &req).unwrap_err(),
            ForgeVerifierError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn foreign_ml_dsa_pair_is_rejected_even_when_both_signatures_verify() {
        let (op, mut challenges, enrollments) = fixture();
        let attacker = HandshakeManager::new();
        let ed = op.identity_public_key_bytes();
        let ml = attacker.ml_dsa_public_key_bytes().to_vec();
        let transcript = forge_authentication_transcript(&[1; 32], &[7; 32], &ed, &ml).unwrap();
        let req = ForgeAuthenticationResponse {
            forge_request_commitment: [1; 32],
            challenge: [7; 32],
            ed25519_pubkey: ed,
            ml_dsa_65_pubkey: ml,
            ed25519_signature: op.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: attacker.sign_ml_dsa(&transcript),
        };
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 1000, &req).unwrap_err(),
            ForgeVerifierError::NotEnrolled
        );
    }
}
