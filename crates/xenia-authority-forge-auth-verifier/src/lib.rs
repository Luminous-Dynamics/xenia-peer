// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-cryptography verification for Forge-bound Xenia operator authentication.
//!
//! This crate deliberately proves only the cryptographic/enrollment half of
//! the producer theorem. It does **not** own a challenge store and therefore
//! does not claim freshness or single-use. The daemon integration tranche must
//! consume the real Xenia challenge before calling this verifier and only then
//! mint the portable receipt.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_forge_auth_receipt::{
    Digest, ReceiptError, challenge_commitment, forge_auth_signing_transcript,
    key_lineage_commitment, operator_id_commitment,
};
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

const CRYPTO_EVIDENCE_DOMAIN_V1: &[u8] = b"xenia-forge-auth/crypto-evidence/v1\0";

/// Signed proof over one exact Forge authentication request and Xenia challenge.
#[derive(Debug, Clone)]
pub struct SignedForgeAuthV1 {
    /// SHA-256 digest of the exact Forge `PrincipalAuthenticationRequest`.
    pub forge_request_sha256: [u8; 32],
    /// Xenia verifier-issued challenge that participates in the transcript.
    pub challenge: [u8; 32],
    /// Presented Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Presented ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Ed25519 signature over the exact Forge-bound transcript.
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 signature over the same transcript.
    pub ml_dsa_65_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Authoritative enrolled logical identity supplied by the daemon's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledForgeIdentityV1 {
    operator_id: String,
    ed25519_pubkey: [u8; 32],
    ml_dsa_65_pubkey: Vec<u8>,
    ml_dsa_87_pubkey: Option<Vec<u8>>,
}

impl EnrolledForgeIdentityV1 {
    /// Construct from one already-validated Xenia enrollment record.
    pub fn new(
        operator_id: String,
        ed25519_pubkey: [u8; 32],
        ml_dsa_65_pubkey: Vec<u8>,
        ml_dsa_87_pubkey: Option<Vec<u8>>,
    ) -> Self {
        Self {
            operator_id,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ml_dsa_87_pubkey,
        }
    }

    /// Stable logical Xenia operator identifier.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }
}

/// Positive result proving both signatures verified over one exact transcript.
///
/// This type intentionally carries no enrollment claim and no freshness claim.
#[derive(Debug, Clone)]
pub struct VerifiedForgeAuthSignaturesV1 {
    signed: SignedForgeAuthV1,
    transcript: Vec<u8>,
}

impl VerifiedForgeAuthSignaturesV1 {
    /// Signed input whose two signatures have both verified.
    pub fn signed(&self) -> &SignedForgeAuthV1 {
        &self.signed
    }

    /// Exact transcript that both signatures covered.
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

/// Positive cryptographic/enrollment evidence ready for daemon freshness binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedForgeAuthCryptographyV1 {
    operator_id: String,
    request_commitment: Digest,
    operator_id_commitment: Digest,
    key_lineage_commitment: Digest,
    challenge_commitment: Digest,
    cryptographic_evidence: Digest,
}

impl VerifiedForgeAuthCryptographyV1 {
    /// Stable logical operator id retained for daemon-local audit correlation.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Exact Forge request commitment.
    pub fn request_commitment(&self) -> &Digest {
        &self.request_commitment
    }

    /// Stable logical operator-id commitment.
    pub fn operator_id_commitment(&self) -> &Digest {
        &self.operator_id_commitment
    }

    /// Current exact hybrid key-lineage commitment.
    pub fn key_lineage_commitment(&self) -> &Digest {
        &self.key_lineage_commitment
    }

    /// Exact Xenia challenge commitment.
    pub fn challenge_commitment(&self) -> &Digest {
        &self.challenge_commitment
    }

    /// Commitment to the transcript and both verified signatures.
    pub fn cryptographic_evidence(&self) -> &Digest {
        &self.cryptographic_evidence
    }
}

/// Verify both signatures over the exact Forge-bound Xenia transcript.
///
/// No enrollment lookup occurs here. This permits the daemon to preserve the
/// existing fail-closed ordering: consume challenge, verify both signatures,
/// then resolve the pair against current enrollment state.
pub fn verify_forge_auth_signatures_v1(
    signed: SignedForgeAuthV1,
) -> Result<VerifiedForgeAuthSignaturesV1, ForgeAuthVerifierError> {
    if signed.ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(ForgeAuthVerifierError::MalformedKey);
    }

    let transcript = forge_auth_signing_transcript(
        &signed.forge_request_sha256,
        &signed.challenge,
        &signed.ed25519_pubkey,
        &signed.ml_dsa_65_pubkey,
    )?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&signed.ed25519_pubkey)
        .map_err(|_| ForgeAuthVerifierError::MalformedKey)?;
    let ed_signature = Signature::from_bytes(&signed.ed25519_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_signature)
        .map_err(|_| ForgeAuthVerifierError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = signed
        .ml_dsa_65_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ForgeAuthVerifierError::MalformedKey)?;
    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &signed.ml_dsa_65_signature)
        .map_err(|_| ForgeAuthVerifierError::MlDsaVerifyFailed)?;

    Ok(VerifiedForgeAuthSignaturesV1 { signed, transcript })
}

/// Bind already-verified signatures to one exact current enrollment record.
pub fn bind_verified_forge_auth_to_enrollment_v1(
    verified: VerifiedForgeAuthSignaturesV1,
    enrollment: &EnrolledForgeIdentityV1,
) -> Result<VerifiedForgeAuthCryptographyV1, ForgeAuthVerifierError> {
    let signed = verified.signed();
    if signed.ed25519_pubkey != enrollment.ed25519_pubkey
        || signed.ml_dsa_65_pubkey.as_slice() != enrollment.ml_dsa_65_pubkey.as_slice()
    {
        return Err(ForgeAuthVerifierError::EnrollmentMismatch);
    }

    let operator_id_commitment = operator_id_commitment(&enrollment.operator_id)?;
    let key_lineage_commitment = key_lineage_commitment(
        &enrollment.ed25519_pubkey,
        &enrollment.ml_dsa_65_pubkey,
        enrollment.ml_dsa_87_pubkey.as_deref(),
    )?;
    let cryptographic_evidence = cryptographic_evidence(&verified)?;

    Ok(VerifiedForgeAuthCryptographyV1 {
        operator_id: enrollment.operator_id.clone(),
        request_commitment: Digest::sha256(signed.forge_request_sha256),
        operator_id_commitment,
        key_lineage_commitment,
        challenge_commitment: challenge_commitment(&signed.challenge),
        cryptographic_evidence,
    })
}

fn cryptographic_evidence(
    verified: &VerifiedForgeAuthSignaturesV1,
) -> Result<Digest, ForgeAuthVerifierError> {
    let mut out = Vec::new();
    out.extend_from_slice(CRYPTO_EVIDENCE_DOMAIN_V1);
    push_bytes(&mut out, verified.transcript())?;
    push_bytes(&mut out, &verified.signed().ed25519_signature)?;
    push_bytes(&mut out, &verified.signed().ml_dsa_65_signature)?;
    Ok(Digest::of_bytes(&out))
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ForgeAuthVerifierError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ReceiptError::CanonicalFieldTooLarge {
        field: "forge_auth_evidence",
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Real-crypto verifier failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ForgeAuthVerifierError {
    /// Presented key material is malformed.
    #[error("malformed Forge authentication public key")]
    MalformedKey,
    /// Ed25519 verification failed.
    #[error("Forge authentication Ed25519 verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 verification failed.
    #[error("Forge authentication ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
    /// The verified pair does not equal the current authoritative enrollment.
    #[error("verified Forge authentication key pair does not match enrollment")]
    EnrollmentMismatch,
    /// Portable receipt/transcript canonicalization failed.
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(mgr: &HandshakeManager, operator_id: &str) -> EnrolledForgeIdentityV1 {
        EnrolledForgeIdentityV1::new(
            operator_id.to_string(),
            mgr.identity_public_key_bytes(),
            mgr.ml_dsa_public_key_bytes().to_vec(),
            None,
        )
    }

    fn signed(
        mgr: &HandshakeManager,
        request: [u8; 32],
        challenge: [u8; 32],
    ) -> SignedForgeAuthV1 {
        let ed25519_pubkey = mgr.identity_public_key_bytes();
        let ml_dsa_65_pubkey = mgr.ml_dsa_public_key_bytes().to_vec();
        let transcript = forge_auth_signing_transcript(
            &request,
            &challenge,
            &ed25519_pubkey,
            &ml_dsa_65_pubkey,
        )
        .unwrap();
        SignedForgeAuthV1 {
            forge_request_sha256: request,
            challenge,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ed25519_signature: mgr.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: mgr.sign_ml_dsa(&transcript),
        }
    }

    #[test]
    fn exact_hybrid_signatures_bind_to_current_enrollment() {
        let operator = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let signed = signed(&operator, [0x55; 32], [0x44; 32]);
        let verified = verify_forge_auth_signatures_v1(signed).unwrap();
        let bound = bind_verified_forge_auth_to_enrollment_v1(
            verified,
            &enrollment(&operator, "operator:alice"),
        )
        .unwrap();

        assert_eq!(bound.operator_id(), "operator:alice");
        assert_eq!(bound.request_commitment(), &Digest::sha256([0x55; 32]));
        assert_eq!(
            bound.operator_id_commitment(),
            &operator_id_commitment("operator:alice").unwrap()
        );
        assert_eq!(
            bound.key_lineage_commitment(),
            &key_lineage_commitment(
                &operator.identity_public_key_bytes(),
                &operator.ml_dsa_public_key_bytes(),
                None,
            )
            .unwrap()
        );
        assert_eq!(bound.challenge_commitment(), &challenge_commitment(&[0x44; 32]));
    }

    #[test]
    fn request_substitution_breaks_signature_verification() {
        let operator = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let mut proof = signed(&operator, [0x51; 32], [0x45; 32]);
        proof.forge_request_sha256 = [0x52; 32];
        assert_eq!(
            verify_forge_auth_signatures_v1(proof).unwrap_err(),
            ForgeAuthVerifierError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn both_signatures_can_be_valid_while_pair_is_not_enrolled_together() {
        let classical = HandshakeManager::from_identity_seeds([0x31; 32], [0x32; 32]);
        let pq = HandshakeManager::from_identity_seeds([0x33; 32], [0x34; 32]);
        let request = [0x53; 32];
        let challenge = [0x46; 32];
        let ed25519_pubkey = classical.identity_public_key_bytes();
        let ml_dsa_65_pubkey = pq.ml_dsa_public_key_bytes().to_vec();
        let transcript = forge_auth_signing_transcript(
            &request,
            &challenge,
            &ed25519_pubkey,
            &ml_dsa_65_pubkey,
        )
        .unwrap();
        let proof = SignedForgeAuthV1 {
            forge_request_sha256: request,
            challenge,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ed25519_signature: classical.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: pq.sign_ml_dsa(&transcript),
        };

        let verified = verify_forge_auth_signatures_v1(proof).unwrap();
        assert_eq!(
            bind_verified_forge_auth_to_enrollment_v1(
                verified,
                &enrollment(&classical, "operator:alice"),
            )
            .unwrap_err(),
            ForgeAuthVerifierError::EnrollmentMismatch
        );
    }

    #[test]
    fn key_rotation_changes_enrollment_binding() {
        let old = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let replacement = HandshakeManager::from_identity_seeds([0x43; 32], [0x44; 32]);
        let verified = verify_forge_auth_signatures_v1(signed(&old, [0x54; 32], [0x47; 32]))
            .unwrap();

        assert_eq!(
            bind_verified_forge_auth_to_enrollment_v1(
                verified,
                &enrollment(&replacement, "operator:alice"),
            )
            .unwrap_err(),
            ForgeAuthVerifierError::EnrollmentMismatch
        );
    }

    #[test]
    fn verifier_intentionally_does_not_claim_challenge_single_use() {
        let operator = HandshakeManager::from_identity_seeds([0x61; 32], [0x62; 32]);
        let proof = signed(&operator, [0x57; 32], [0x48; 32]);
        assert!(verify_forge_auth_signatures_v1(proof.clone()).is_ok());
        assert!(verify_forge_auth_signatures_v1(proof).is_ok());
    }
}
