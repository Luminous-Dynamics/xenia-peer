// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-cryptography verification for context-bound Xenia evidence authentication.
//!
//! This crate proves only hybrid signature validity and exact current-enrollment
//! binding for one content-addressed evidence subject. It does **not** own a
//! challenge store, authenticate the semantic truth of the evidence, or grant
//! application/runtime authority. A daemon integration tranche must consume the
//! real Xenia challenge before minting any freshness-bearing portable receipt.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use thiserror::Error;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

const EVIDENCE_AUTH_TRANSCRIPT_DOMAIN_V1: &[u8] = b"xenia-evidence-auth-v1\0";
const IDENTITY_COMMITMENT_DOMAIN_V1: &[u8] = b"xenia-evidence-auth/identity/v1\0";
const KEY_LINEAGE_COMMITMENT_DOMAIN_V1: &[u8] = b"xenia-evidence-auth/key-lineage/v1\0";
const CHALLENGE_COMMITMENT_DOMAIN_V1: &[u8] = b"xenia-evidence-auth/challenge/v1\0";
const CRYPTO_EVIDENCE_DOMAIN_V1: &[u8] = b"xenia-evidence-auth/crypto-evidence/v1\0";

/// Hybrid signatures over one exact evidence-authentication transcript.
#[derive(Debug, Clone)]
pub struct SignedEvidenceAuthV1 {
    /// Application-defined context digest separating this evidence use from others.
    pub context_sha256: [u8; 32],
    /// SHA-256 digest of the exact canonical evidence subject being authenticated.
    pub evidence_subject_sha256: [u8; 32],
    /// Xenia verifier-issued challenge participating in the transcript.
    pub challenge: [u8; 32],
    /// Presented Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Presented ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Ed25519 signature over the exact evidence-auth transcript.
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 signature over the same transcript.
    pub ml_dsa_65_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// One authoritative current enrollment supplied by Xenia policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledEvidenceIdentityV1 {
    identity_id: String,
    ed25519_pubkey: [u8; 32],
    ml_dsa_65_pubkey: Vec<u8>,
}

impl EnrolledEvidenceIdentityV1 {
    /// Construct from one already-validated current enrollment record.
    pub fn new(
        identity_id: String,
        ed25519_pubkey: [u8; 32],
        ml_dsa_65_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            identity_id,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
        }
    }

    /// Stable logical identity identifier used only for enrollment correlation.
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }
}

/// Positive result proving both signatures verified over one exact transcript.
///
/// This type deliberately carries no enrollment, freshness, truth, or authority claim.
#[derive(Debug, Clone)]
pub struct VerifiedEvidenceAuthSignaturesV1 {
    signed: SignedEvidenceAuthV1,
    transcript: Vec<u8>,
}

impl VerifiedEvidenceAuthSignaturesV1 {
    /// Signed input whose two signatures have verified.
    pub fn signed(&self) -> &SignedEvidenceAuthV1 {
        &self.signed
    }

    /// Exact canonical transcript covered by both signatures.
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

/// Positive cryptographic/enrollment evidence ready for later freshness binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidenceAuthCryptographyV1 {
    identity_id: String,
    context_sha256: [u8; 32],
    evidence_subject_sha256: [u8; 32],
    identity_id_commitment: [u8; 32],
    key_lineage_commitment: [u8; 32],
    challenge_commitment: [u8; 32],
    cryptographic_evidence: [u8; 32],
}

impl VerifiedEvidenceAuthCryptographyV1 {
    /// Stable logical identity retained for daemon-local correlation.
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    /// Exact application context digest covered by both signatures.
    pub fn context_sha256(&self) -> &[u8; 32] {
        &self.context_sha256
    }

    /// Exact evidence-subject digest covered by both signatures.
    pub fn evidence_subject_sha256(&self) -> &[u8; 32] {
        &self.evidence_subject_sha256
    }

    /// Commitment to the stable logical identity id.
    pub fn identity_id_commitment(&self) -> &[u8; 32] {
        &self.identity_id_commitment
    }

    /// Commitment to the exact currently enrolled hybrid key pair.
    pub fn key_lineage_commitment(&self) -> &[u8; 32] {
        &self.key_lineage_commitment
    }

    /// Commitment to the exact presented Xenia challenge.
    pub fn challenge_commitment(&self) -> &[u8; 32] {
        &self.challenge_commitment
    }

    /// Commitment to the transcript and both verified signatures.
    pub fn cryptographic_evidence(&self) -> &[u8; 32] {
        &self.cryptographic_evidence
    }
}

/// Construct the exact transcript both signature systems must cover.
pub fn evidence_auth_signing_transcript_v1(
    context_sha256: &[u8; 32],
    evidence_subject_sha256: &[u8; 32],
    challenge: &[u8; 32],
    ed25519_pubkey: &[u8; 32],
    ml_dsa_65_pubkey: &[u8],
) -> Result<Vec<u8>, EvidenceAuthVerifierError> {
    if ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(EvidenceAuthVerifierError::MalformedKey);
    }
    let mut out = Vec::new();
    out.extend_from_slice(EVIDENCE_AUTH_TRANSCRIPT_DOMAIN_V1);
    push_bytes(&mut out, b"context-sha256", context_sha256)?;
    push_bytes(
        &mut out,
        b"evidence-subject-sha256",
        evidence_subject_sha256,
    )?;
    push_bytes(&mut out, b"challenge", challenge)?;
    push_bytes(&mut out, b"ed25519-pubkey", ed25519_pubkey)?;
    push_bytes(&mut out, b"ml-dsa-65-pubkey", ml_dsa_65_pubkey)?;
    Ok(out)
}

/// Verify both signatures over the exact context/evidence-bound transcript.
///
/// No enrollment lookup or challenge consumption occurs here.
pub fn verify_evidence_auth_signatures_v1(
    signed: SignedEvidenceAuthV1,
) -> Result<VerifiedEvidenceAuthSignaturesV1, EvidenceAuthVerifierError> {
    let transcript = evidence_auth_signing_transcript_v1(
        &signed.context_sha256,
        &signed.evidence_subject_sha256,
        &signed.challenge,
        &signed.ed25519_pubkey,
        &signed.ml_dsa_65_pubkey,
    )?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&signed.ed25519_pubkey)
        .map_err(|_| EvidenceAuthVerifierError::MalformedKey)?;
    let ed_signature = Signature::from_bytes(&signed.ed25519_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_signature)
        .map_err(|_| EvidenceAuthVerifierError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = signed
        .ml_dsa_65_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| EvidenceAuthVerifierError::MalformedKey)?;
    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &signed.ml_dsa_65_signature)
        .map_err(|_| EvidenceAuthVerifierError::MlDsaVerifyFailed)?;

    Ok(VerifiedEvidenceAuthSignaturesV1 { signed, transcript })
}

/// Bind already-verified signatures to one exact current enrollment record.
pub fn bind_verified_evidence_auth_to_enrollment_v1(
    verified: VerifiedEvidenceAuthSignaturesV1,
    enrollment: &EnrolledEvidenceIdentityV1,
) -> Result<VerifiedEvidenceAuthCryptographyV1, EvidenceAuthVerifierError> {
    if enrollment.identity_id.is_empty() {
        return Err(EvidenceAuthVerifierError::EmptyIdentityId);
    }
    let signed = verified.signed();
    if signed.ed25519_pubkey != enrollment.ed25519_pubkey
        || signed.ml_dsa_65_pubkey.as_slice() != enrollment.ml_dsa_65_pubkey.as_slice()
    {
        return Err(EvidenceAuthVerifierError::EnrollmentMismatch);
    }

    Ok(VerifiedEvidenceAuthCryptographyV1 {
        identity_id: enrollment.identity_id.clone(),
        context_sha256: signed.context_sha256,
        evidence_subject_sha256: signed.evidence_subject_sha256,
        identity_id_commitment: domain_hash(
            IDENTITY_COMMITMENT_DOMAIN_V1,
            &[enrollment.identity_id.as_bytes()],
        )?,
        key_lineage_commitment: domain_hash(
            KEY_LINEAGE_COMMITMENT_DOMAIN_V1,
            &[&enrollment.ed25519_pubkey, &enrollment.ml_dsa_65_pubkey],
        )?,
        challenge_commitment: domain_hash(CHALLENGE_COMMITMENT_DOMAIN_V1, &[&signed.challenge])?,
        cryptographic_evidence: cryptographic_evidence(&verified)?,
    })
}

fn cryptographic_evidence(
    verified: &VerifiedEvidenceAuthSignaturesV1,
) -> Result<[u8; 32], EvidenceAuthVerifierError> {
    domain_hash(
        CRYPTO_EVIDENCE_DOMAIN_V1,
        &[
            verified.transcript(),
            &verified.signed().ed25519_signature,
            &verified.signed().ml_dsa_65_signature,
        ],
    )
}

fn domain_hash(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], EvidenceAuthVerifierError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| EvidenceAuthVerifierError::FieldTooLarge)?;
        hasher.update(len.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

fn push_bytes(
    out: &mut Vec<u8>,
    label: &[u8],
    bytes: &[u8],
) -> Result<(), EvidenceAuthVerifierError> {
    let label_len = u16::try_from(label.len()).map_err(|_| EvidenceAuthVerifierError::FieldTooLarge)?;
    let bytes_len = u32::try_from(bytes.len()).map_err(|_| EvidenceAuthVerifierError::FieldTooLarge)?;
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&bytes_len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Real-crypto evidence-auth verifier failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum EvidenceAuthVerifierError {
    /// Presented public-key material is malformed.
    #[error("malformed evidence-auth public key")]
    MalformedKey,
    /// Stable logical identity id is empty.
    #[error("evidence-auth enrollment identity id is empty")]
    EmptyIdentityId,
    /// Ed25519 verification failed.
    #[error("evidence-auth Ed25519 verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 verification failed.
    #[error("evidence-auth ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
    /// Verified keys do not equal one current enrolled hybrid pair.
    #[error("verified evidence-auth key pair does not match enrollment")]
    EnrollmentMismatch,
    /// A canonical transcript/commitment field cannot fit its length prefix.
    #[error("evidence-auth canonical field too large")]
    FieldTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(mgr: &HandshakeManager, identity_id: &str) -> EnrolledEvidenceIdentityV1 {
        EnrolledEvidenceIdentityV1::new(
            identity_id.to_string(),
            mgr.identity_public_key_bytes(),
            mgr.ml_dsa_public_key_bytes().to_vec(),
        )
    }

    fn signed(
        mgr: &HandshakeManager,
        context: [u8; 32],
        subject: [u8; 32],
        challenge: [u8; 32],
    ) -> SignedEvidenceAuthV1 {
        let ed25519_pubkey = mgr.identity_public_key_bytes();
        let ml_dsa_65_pubkey = mgr.ml_dsa_public_key_bytes().to_vec();
        let transcript = evidence_auth_signing_transcript_v1(
            &context,
            &subject,
            &challenge,
            &ed25519_pubkey,
            &ml_dsa_65_pubkey,
        )
        .unwrap();
        SignedEvidenceAuthV1 {
            context_sha256: context,
            evidence_subject_sha256: subject,
            challenge,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ed25519_signature: mgr.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: mgr.sign_ml_dsa(&transcript),
        }
    }

    #[test]
    fn exact_hybrid_signatures_bind_context_subject_and_current_enrollment() {
        let operator = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let proof = signed(&operator, [0x31; 32], [0x41; 32], [0x51; 32]);
        let verified = verify_evidence_auth_signatures_v1(proof).unwrap();
        let bound = bind_verified_evidence_auth_to_enrollment_v1(
            verified,
            &enrollment(&operator, "evidence:issuer:alice"),
        )
        .unwrap();
        assert_eq!(bound.identity_id(), "evidence:issuer:alice");
        assert_eq!(bound.context_sha256(), &[0x31; 32]);
        assert_eq!(bound.evidence_subject_sha256(), &[0x41; 32]);
        assert_ne!(bound.challenge_commitment(), &[0u8; 32]);
        assert_ne!(bound.cryptographic_evidence(), &[0u8; 32]);
    }

    #[test]
    fn evidence_subject_substitution_breaks_signature_verification() {
        let operator = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let mut proof = signed(&operator, [0x32; 32], [0x42; 32], [0x52; 32]);
        proof.evidence_subject_sha256 = [0x43; 32];
        assert_eq!(
            verify_evidence_auth_signatures_v1(proof).unwrap_err(),
            EvidenceAuthVerifierError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn evidence_context_substitution_breaks_signature_verification() {
        let operator = HandshakeManager::from_identity_seeds([0x23; 32], [0x24; 32]);
        let mut proof = signed(&operator, [0x33; 32], [0x44; 32], [0x53; 32]);
        proof.context_sha256 = [0x34; 32];
        assert_eq!(
            verify_evidence_auth_signatures_v1(proof).unwrap_err(),
            EvidenceAuthVerifierError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn individually_valid_signatures_from_mixed_pair_fail_enrollment_binding() {
        let classical = HandshakeManager::from_identity_seeds([0x31; 32], [0x32; 32]);
        let pq = HandshakeManager::from_identity_seeds([0x33; 32], [0x34; 32]);
        let context = [0x35; 32];
        let subject = [0x45; 32];
        let challenge = [0x55; 32];
        let ed25519_pubkey = classical.identity_public_key_bytes();
        let ml_dsa_65_pubkey = pq.ml_dsa_public_key_bytes().to_vec();
        let transcript = evidence_auth_signing_transcript_v1(
            &context,
            &subject,
            &challenge,
            &ed25519_pubkey,
            &ml_dsa_65_pubkey,
        )
        .unwrap();
        let proof = SignedEvidenceAuthV1 {
            context_sha256: context,
            evidence_subject_sha256: subject,
            challenge,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ed25519_signature: classical.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: pq.sign_ml_dsa(&transcript),
        };
        let verified = verify_evidence_auth_signatures_v1(proof).unwrap();
        assert_eq!(
            bind_verified_evidence_auth_to_enrollment_v1(
                verified,
                &enrollment(&classical, "evidence:issuer:alice"),
            )
            .unwrap_err(),
            EvidenceAuthVerifierError::EnrollmentMismatch
        );
    }

    #[test]
    fn rotation_invalidates_old_pair_against_current_enrollment() {
        let old = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let replacement = HandshakeManager::from_identity_seeds([0x43; 32], [0x44; 32]);
        let verified = verify_evidence_auth_signatures_v1(signed(
            &old,
            [0x36; 32],
            [0x46; 32],
            [0x56; 32],
        ))
        .unwrap();
        assert_eq!(
            bind_verified_evidence_auth_to_enrollment_v1(
                verified,
                &enrollment(&replacement, "evidence:issuer:alice"),
            )
            .unwrap_err(),
            EvidenceAuthVerifierError::EnrollmentMismatch
        );
    }

    #[test]
    fn verifier_intentionally_does_not_claim_challenge_single_use() {
        let operator = HandshakeManager::from_identity_seeds([0x61; 32], [0x62; 32]);
        let proof = signed(&operator, [0x37; 32], [0x47; 32], [0x57; 32]);
        assert!(verify_evidence_auth_signatures_v1(proof.clone()).is_ok());
        assert!(verify_evidence_auth_signatures_v1(proof).is_ok());
    }

    #[test]
    fn evidence_bytes_are_authenticated_as_digest_not_interpreted_as_truth() {
        let operator = HandshakeManager::from_identity_seeds([0x71; 32], [0x72; 32]);
        let arbitrary_subject_digest = [0xA5; 32];
        let verified = verify_evidence_auth_signatures_v1(signed(
            &operator,
            [0x38; 32],
            arbitrary_subject_digest,
            [0x58; 32],
        ))
        .unwrap();
        let bound = bind_verified_evidence_auth_to_enrollment_v1(
            verified,
            &enrollment(&operator, "evidence:issuer:alice"),
        )
        .unwrap();
        assert_eq!(bound.evidence_subject_sha256(), &arbitrary_subject_digest);
    }
}
