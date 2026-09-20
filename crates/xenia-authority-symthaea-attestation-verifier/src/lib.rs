// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-cryptography verification for Symthaea verification-receipt attestations.
//!
//! This tranche proves only that both Ed25519 and ML-DSA-65 signatures verify
//! over the exact XENIA-SYM-001A / Symthaea SEC-002F canonical transcript and
//! that the transcript payload is bound to the supplied canonical receipt bytes.
//! It deliberately does not claim current enrollment, revocation state,
//! authorization scope, Symthaea evidence admission, or assurance qualification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};
use xenia_symthaea_attestation_contract::{
    ML_DSA_65_SIGNATURE_LEN, SymthaeaReceiptAttestationV1,
};

/// Presented public keys plus a Symthaea receipt-attestation envelope.
#[derive(Debug, Clone)]
pub struct SignedSymthaeaReceiptAttestationV1 {
    /// Portable SEC-002F-compatible attestation envelope.
    pub attestation: SymthaeaReceiptAttestationV1,
    /// Presented Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Presented ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
}

/// Positive result proving both hybrid signatures verified over one exact
/// receipt-bound transcript.
///
/// This type intentionally carries no enrollment or authorization claim.
#[derive(Debug, Clone)]
pub struct VerifiedSymthaeaAttestationSignaturesV1 {
    signed: SignedSymthaeaReceiptAttestationV1,
    transcript: Vec<u8>,
}

impl VerifiedSymthaeaAttestationSignaturesV1 {
    /// Original signed input whose two signatures verified.
    pub fn signed(&self) -> &SignedSymthaeaReceiptAttestationV1 {
        &self.signed
    }

    /// Exact transcript authenticated by both signatures.
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

/// Verify both signatures over the exact receipt-bound Symthaea transcript.
///
/// `canonical_receipt_bytes` must be the exact bytes whose SHA-256 is carried by
/// the attestation. The function checks that binding before any positive crypto
/// result is returned.
pub fn verify_symthaea_attestation_signatures_v1(
    canonical_receipt_bytes: &[u8],
    signed: SignedSymthaeaReceiptAttestationV1,
) -> Result<VerifiedSymthaeaAttestationSignaturesV1, SymthaeaAttestationVerifierError> {
    if ML_DSA_65_SIGNATURE_LEN != ML_DSA_65_SIG_LEN {
        return Err(SymthaeaAttestationVerifierError::ContractConstantMismatch);
    }

    if !signed.attestation.signatures.validate_structure() {
        return Err(SymthaeaAttestationVerifierError::MalformedSignatureBundle);
    }
    if signed.ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(SymthaeaAttestationVerifierError::MalformedKey);
    }

    let transcript = signed
        .attestation
        .canonical_signing_transcript_for(canonical_receipt_bytes)
        .ok_or(SymthaeaAttestationVerifierError::ReceiptBindingMismatch)?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&signed.ed25519_pubkey)
        .map_err(|_| SymthaeaAttestationVerifierError::MalformedKey)?;
    let ed_signature = Signature::from_bytes(&signed.attestation.signatures.ed25519);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_signature)
        .map_err(|_| SymthaeaAttestationVerifierError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = signed
        .ml_dsa_65_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| SymthaeaAttestationVerifierError::MalformedKey)?;
    let ml_signature: [u8; ML_DSA_65_SIG_LEN] = signed
        .attestation
        .signatures
        .ml_dsa_65
        .as_slice()
        .try_into()
        .map_err(|_| SymthaeaAttestationVerifierError::MalformedSignatureBundle)?;

    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &ml_signature)
        .map_err(|_| SymthaeaAttestationVerifierError::MlDsaVerifyFailed)?;

    Ok(VerifiedSymthaeaAttestationSignaturesV1 { signed, transcript })
}

/// Real-crypto verifier failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SymthaeaAttestationVerifierError {
    /// Xenia and the portable contract disagree about fixed ML-DSA-65 sizes.
    #[error("portable Symthaea contract and Xenia ML-DSA-65 constants disagree")]
    ContractConstantMismatch,
    /// The supplied canonical receipt bytes do not match the attestation payload.
    #[error("Symthaea attestation payload does not match canonical receipt bytes")]
    ReceiptBindingMismatch,
    /// Presented public key material is malformed.
    #[error("malformed Symthaea attestation public key")]
    MalformedKey,
    /// Hybrid signature bundle has an invalid shape.
    #[error("malformed Symthaea hybrid signature bundle")]
    MalformedSignatureBundle,
    /// Ed25519 verification failed.
    #[error("Symthaea attestation Ed25519 verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 verification failed.
    #[error("Symthaea attestation ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_symthaea_attestation_contract::{
        ED25519_SIGNATURE_LEN, HybridSignatureBundleV1, XeniaHybridSuiteV1,
    };

    const RECEIPT_BYTES: &[u8] = b"canonical-symthaea-receipt-fixture-v1";

    fn unsigned_attestation() -> SymthaeaReceiptAttestationV1 {
        SymthaeaReceiptAttestationV1::new(
            RECEIPT_BYTES,
            1,
            [0x11; 16],
            "luminous-dynamics/xenia",
            "operator:alice",
            "sha256:lineage",
            XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            HybridSignatureBundleV1 {
                ed25519: [0; ED25519_SIGNATURE_LEN],
                ml_dsa_65: vec![0; ML_DSA_65_SIGNATURE_LEN],
            },
        )
        .unwrap()
    }

    fn signed_with(
        ed_signer: &HandshakeManager,
        pq_signer: &HandshakeManager,
    ) -> SignedSymthaeaReceiptAttestationV1 {
        let mut attestation = unsigned_attestation();
        let transcript = attestation.canonical_signing_transcript().unwrap();
        attestation.signatures.ed25519 = ed_signer.sign(&transcript).to_bytes();
        attestation.signatures.ml_dsa_65 = pq_signer.sign_ml_dsa(&transcript).to_vec();

        SignedSymthaeaReceiptAttestationV1 {
            attestation,
            ed25519_pubkey: ed_signer.identity_public_key_bytes(),
            ml_dsa_65_pubkey: pq_signer.ml_dsa_public_key_bytes().to_vec(),
        }
    }

    #[test]
    fn exact_hybrid_signatures_verify() {
        let signer = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let signed = signed_with(&signer, &signer);
        let verified = verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).unwrap();
        assert_eq!(
            verified.transcript(),
            verified
                .signed()
                .attestation
                .canonical_signing_transcript()
                .unwrap()
        );
    }

    #[test]
    fn receipt_substitution_fails_before_crypto_claim() {
        let signer = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let signed = signed_with(&signer, &signer);
        assert_eq!(
            verify_symthaea_attestation_signatures_v1(b"different-receipt", signed).unwrap_err(),
            SymthaeaAttestationVerifierError::ReceiptBindingMismatch
        );
    }

    #[test]
    fn metadata_substitution_breaks_signature_verification() {
        let signer = HandshakeManager::from_identity_seeds([0x31; 32], [0x32; 32]);
        let mut signed = signed_with(&signer, &signer);
        signed.attestation.provider_namespace = "other-provider".into();
        assert_eq!(
            verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).unwrap_err(),
            SymthaeaAttestationVerifierError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn one_bad_signature_fails_hybrid_verification() {
        let signer = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let mut bad_ed = signed_with(&signer, &signer);
        bad_ed.attestation.signatures.ed25519[0] ^= 1;
        assert_eq!(
            verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, bad_ed).unwrap_err(),
            SymthaeaAttestationVerifierError::Ed25519VerifyFailed
        );

        let mut bad_pq = signed_with(&signer, &signer);
        bad_pq.attestation.signatures.ml_dsa_65[0] ^= 1;
        assert_eq!(
            verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, bad_pq).unwrap_err(),
            SymthaeaAttestationVerifierError::MlDsaVerifyFailed
        );
    }

    #[test]
    fn individually_valid_mixed_pair_is_crypto_valid_but_not_enrollment_proof() {
        let classical = HandshakeManager::from_identity_seeds([0x51; 32], [0x52; 32]);
        let pq = HandshakeManager::from_identity_seeds([0x53; 32], [0x54; 32]);
        let signed = signed_with(&classical, &pq);

        // Both signatures really are valid over the same bytes. This tranche
        // intentionally accepts that cryptographic fact and makes no statement
        // that these keys are enrolled together. XENIA-SYM-001C owns that claim.
        assert!(verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).is_ok());
    }

    #[test]
    fn malformed_public_key_length_fails_closed() {
        let signer = HandshakeManager::from_identity_seeds([0x61; 32], [0x62; 32]);
        let mut signed = signed_with(&signer, &signer);
        signed.ml_dsa_65_pubkey.pop();
        assert_eq!(
            verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).unwrap_err(),
            SymthaeaAttestationVerifierError::MalformedKey
        );
    }
}
