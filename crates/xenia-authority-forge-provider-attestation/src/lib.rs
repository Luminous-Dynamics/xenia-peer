// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider provenance for fresh Forge-bound Xenia authentication receipts.
//!
//! This crate adds a theorem deliberately missing from the portable receipt:
//! the evidence was attested by one exact trusted Xenia verifier identity.
//! Its public signing entry point consumes [`VerifiedFreshForgeAuthenticationV1`]
//! rather than an arbitrary receipt, preserving the producer chain:
//!
//! ```text
//! one-time challenge consumed
//! + exact Forge-bound Ed25519 verified
//! + exact Forge-bound ML-DSA-65 verified
//! + exact current enrollment resolved
//!     ↓
//! VerifiedFreshForgeAuthenticationV1
//!     ↓
//! exact receipt bytes hybrid-signed by Xenia verifier identity
//!     ↓
//! XeniaProviderAttestedReceiptV1
//! ```
//!
//! A consumer must still decide which verifier identity it trusts. Merely
//! deserializing [`XeniaProviderAttestedReceiptV1`] proves nothing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_forge_auth_receipt::{Digest, ReceiptError, XeniaVerificationReceiptV1};
use xenia_forge_auth_verifier::VerifiedFreshForgeAuthenticationV1;
use xenia_handshake::{
    HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
};

const PROVIDER_ATTESTATION_DOMAIN_V1: &[u8] = b"xenia-forge-provider-attestation-v1\0";
const VERIFIER_IDENTITY_DOMAIN_V1: &[u8] = b"xenia-forge/verifier-identity/v1\0";

/// Hybrid provider attestation over one exact Xenia verification receipt.
///
/// The signing keys are intentionally not carried as authoritative data in
/// this envelope. A consumer supplies its independently trusted verifier keys
/// and verifies both signatures against those keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeniaProviderAttestedReceiptV1 {
    receipt: XeniaVerificationReceiptV1,
    verifier_identity_commitment: Digest,
    ed25519_signature: Vec<u8>,
    ml_dsa_65_signature: Vec<u8>,
}

impl XeniaProviderAttestedReceiptV1 {
    /// Exact portable Xenia verification receipt covered by both signatures.
    pub fn receipt(&self) -> &XeniaVerificationReceiptV1 {
        &self.receipt
    }

    /// Commitment to the exact hybrid verifier identity expected to validate
    /// this envelope.
    pub fn verifier_identity_commitment(&self) -> &Digest {
        &self.verifier_identity_commitment
    }

    /// Ed25519 signature bytes over the provider-attestation transcript.
    pub fn ed25519_signature(&self) -> &[u8] {
        &self.ed25519_signature
    }

    /// ML-DSA-65 signature bytes over the same provider-attestation transcript.
    pub fn ml_dsa_65_signature(&self) -> &[u8] {
        &self.ml_dsa_65_signature
    }
}

/// Positive provider-provenance result.
///
/// Construction is private; consumers obtain this only after both signatures
/// verify against one explicitly supplied trusted verifier identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedXeniaProviderAttestationV1 {
    envelope: XeniaProviderAttestedReceiptV1,
}

impl VerifiedXeniaProviderAttestationV1 {
    /// Exact receipt whose provider provenance has been verified.
    pub fn receipt(&self) -> &XeniaVerificationReceiptV1 {
        self.envelope.receipt()
    }

    /// Exact provider envelope that passed verification.
    pub fn envelope(&self) -> &XeniaProviderAttestedReceiptV1 {
        &self.envelope
    }

    /// Consume the positive result and recover the verified envelope.
    pub fn into_envelope(self) -> XeniaProviderAttestedReceiptV1 {
        self.envelope
    }
}

/// Commitment to one exact Xenia verifier hybrid identity.
pub fn verifier_identity_commitment_v1(
    ed25519_pubkey: &[u8; 32],
    ml_dsa_65_pubkey: &[u8; ML_DSA_65_PK_LEN],
) -> Result<Digest, ProviderAttestationError> {
    let mut out = Vec::new();
    out.extend_from_slice(VERIFIER_IDENTITY_DOMAIN_V1);
    push_bytes(&mut out, "verifier_ed25519_pubkey", ed25519_pubkey)?;
    push_bytes(&mut out, "verifier_ml_dsa_65_pubkey", ml_dsa_65_pubkey)?;
    Ok(Digest::of_bytes(&out))
}

/// Canonical bytes covered by both provider signatures.
///
/// Layout:
/// `domain || len(receipt canonical bytes) || receipt canonical bytes ||
/// len(verifier identity commitment bytes) || verifier identity commitment bytes`.
/// The commitment itself binds both trusted public keys.
pub fn provider_attestation_transcript_v1(
    receipt: &XeniaVerificationReceiptV1,
    verifier_identity_commitment: &Digest,
) -> Result<Vec<u8>, ProviderAttestationError> {
    let receipt_bytes = receipt.canonical_bytes()?;
    let mut out = Vec::new();
    out.extend_from_slice(PROVIDER_ATTESTATION_DOMAIN_V1);
    push_bytes(&mut out, "receipt", &receipt_bytes)?;
    push_bytes(
        &mut out,
        "verifier_identity_commitment",
        verifier_identity_commitment.as_bytes(),
    )?;
    Ok(out)
}

/// Attest one already-fresh, already-enrollment-bound Forge authentication
/// result with Xenia's exact verifier identity.
///
/// This is intentionally the only public production constructor for an
/// attested receipt. The input type cannot be constructed by deserializing a
/// receipt-shaped object; it comes from the real freshness/crypto verifier.
pub fn attest_verified_forge_authentication_v1(
    verifier_identity: &HandshakeManager,
    verified: VerifiedFreshForgeAuthenticationV1,
) -> Result<XeniaProviderAttestedReceiptV1, ProviderAttestationError> {
    let receipt = verified.into_receipt();
    let ed25519_pubkey = verifier_identity.identity_public_key_bytes();
    let ml_dsa_65_pubkey = verifier_identity.ml_dsa_public_key_bytes();
    let verifier_identity_commitment =
        verifier_identity_commitment_v1(&ed25519_pubkey, &ml_dsa_65_pubkey)?;
    let transcript =
        provider_attestation_transcript_v1(&receipt, &verifier_identity_commitment)?;

    Ok(XeniaProviderAttestedReceiptV1 {
        receipt,
        verifier_identity_commitment,
        ed25519_signature: verifier_identity.sign(&transcript).to_bytes().to_vec(),
        ml_dsa_65_signature: verifier_identity.sign_ml_dsa(&transcript).to_vec(),
    })
}

/// Verify provider provenance against one explicitly trusted Xenia verifier
/// hybrid identity.
///
/// Both signatures are required. The envelope's claimed verifier commitment
/// must first equal the commitment recomputed from the trusted keys, so an
/// attacker cannot substitute a self-generated signing identity.
pub fn verify_provider_attestation_v1(
    trusted_ed25519_pubkey: &[u8; 32],
    trusted_ml_dsa_65_pubkey: &[u8; ML_DSA_65_PK_LEN],
    envelope: XeniaProviderAttestedReceiptV1,
) -> Result<VerifiedXeniaProviderAttestationV1, ProviderAttestationError> {
    let expected_identity =
        verifier_identity_commitment_v1(trusted_ed25519_pubkey, trusted_ml_dsa_65_pubkey)?;
    if envelope.verifier_identity_commitment != expected_identity {
        return Err(ProviderAttestationError::VerifierIdentityMismatch);
    }

    let transcript = provider_attestation_transcript_v1(
        &envelope.receipt,
        &envelope.verifier_identity_commitment,
    )?;

    let ed_signature: [u8; 64] = envelope
        .ed25519_signature
        .as_slice()
        .try_into()
        .map_err(|_| ProviderAttestationError::MalformedEd25519Signature)?;
    let ed_pk = HandshakeManager::parse_peer_public_key(trusted_ed25519_pubkey)
        .map_err(|_| ProviderAttestationError::MalformedVerifierKey)?;
    HandshakeManager::verify(&ed_pk, &transcript, &Signature::from_bytes(&ed_signature))
        .map_err(|_| ProviderAttestationError::Ed25519VerificationFailed)?;

    let ml_signature: [u8; ML_DSA_65_SIG_LEN] = envelope
        .ml_dsa_65_signature
        .as_slice()
        .try_into()
        .map_err(|_| ProviderAttestationError::MalformedMlDsaSignature)?;
    HandshakeManager::verify_ml_dsa(trusted_ml_dsa_65_pubkey, &transcript, &ml_signature)
        .map_err(|_| ProviderAttestationError::MlDsaVerificationFailed)?;

    Ok(VerifiedXeniaProviderAttestationV1 { envelope })
}

fn push_bytes(
    out: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), ProviderAttestationError> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        ProviderAttestationError::CanonicalFieldTooLarge {
            field,
            len: bytes.len(),
            max: u32::MAX as usize,
        }
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Provider-attestation construction or verification failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProviderAttestationError {
    /// Underlying receipt canonicalization failed.
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    /// A canonical field exceeded the v1 u32 length bound.
    #[error("canonical field {field} is too large: {len} > {max}")]
    CanonicalFieldTooLarge {
        /// Field name.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Maximum length.
        max: usize,
    },
    /// Envelope was signed by a different verifier identity than the one the
    /// consumer explicitly trusts.
    #[error("Xenia Forge provider verifier identity does not match trusted identity")]
    VerifierIdentityMismatch,
    /// Trusted Ed25519 verifier key was malformed.
    #[error("trusted Xenia verifier Ed25519 key is malformed")]
    MalformedVerifierKey,
    /// Ed25519 provider signature had the wrong length.
    #[error("Xenia provider Ed25519 signature has the wrong length")]
    MalformedEd25519Signature,
    /// ML-DSA-65 provider signature had the wrong length.
    #[error("Xenia provider ML-DSA-65 signature has the wrong length")]
    MalformedMlDsaSignature,
    /// Ed25519 provider signature did not verify.
    #[error("Xenia provider Ed25519 signature verification failed")]
    Ed25519VerificationFailed,
    /// ML-DSA-65 provider signature did not verify.
    #[error("Xenia provider ML-DSA-65 signature verification failed")]
    MlDsaVerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_forge_auth_receipt::forge_auth_signing_transcript;
    use xenia_forge_auth_verifier::{
        EnrolledForgeIdentityV1, ForgeChallengeStoreV1, SignedForgeAuthV1,
        verify_fresh_forge_authentication_v1,
    };

    fn fresh_verified(
        operator: &HandshakeManager,
        request: [u8; 32],
        challenge: [u8; 32],
    ) -> VerifiedFreshForgeAuthenticationV1 {
        let ed25519_pubkey = operator.identity_public_key_bytes();
        let ml_dsa_65_pubkey = operator.ml_dsa_public_key_bytes().to_vec();
        let transcript = forge_auth_signing_transcript(
            &request,
            &challenge,
            &ed25519_pubkey,
            &ml_dsa_65_pubkey,
        )
        .unwrap();
        let signed = SignedForgeAuthV1 {
            forge_request_sha256: request,
            challenge,
            ed25519_pubkey,
            ml_dsa_65_pubkey: ml_dsa_65_pubkey.clone(),
            ed25519_signature: operator.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: operator.sign_ml_dsa(&transcript),
        };
        let enrollment = EnrolledForgeIdentityV1::new(
            "operator:alice".to_string(),
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            None,
        );
        let mut challenges = ForgeChallengeStoreV1::new();
        challenges.issue(challenge, 1_000, 60);
        verify_fresh_forge_authentication_v1(
            &mut challenges,
            1_010,
            signed,
            &enrollment,
        )
        .unwrap()
    }

    #[test]
    fn fresh_verified_receipt_is_hybrid_attested_and_verified() {
        let operator = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let verifier = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let verified = fresh_verified(&operator, [0x31; 32], [0x32; 32]);

        let envelope = attest_verified_forge_authentication_v1(&verifier, verified).unwrap();
        let positive = verify_provider_attestation_v1(
            &verifier.identity_public_key_bytes(),
            &verifier.ml_dsa_public_key_bytes(),
            envelope.clone(),
        )
        .unwrap();

        assert_eq!(positive.envelope(), &envelope);
    }

    #[test]
    fn a_different_trusted_verifier_identity_rejects_the_envelope() {
        let operator = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let verifier = HandshakeManager::from_identity_seeds([0x43; 32], [0x44; 32]);
        let wrong = HandshakeManager::from_identity_seeds([0x45; 32], [0x46; 32]);
        let envelope = attest_verified_forge_authentication_v1(
            &verifier,
            fresh_verified(&operator, [0x47; 32], [0x48; 32]),
        )
        .unwrap();

        assert_eq!(
            verify_provider_attestation_v1(
                &wrong.identity_public_key_bytes(),
                &wrong.ml_dsa_public_key_bytes(),
                envelope,
            )
            .unwrap_err(),
            ProviderAttestationError::VerifierIdentityMismatch
        );
    }

    #[test]
    fn signature_tampering_is_rejected() {
        let operator = HandshakeManager::from_identity_seeds([0x51; 32], [0x52; 32]);
        let verifier = HandshakeManager::from_identity_seeds([0x53; 32], [0x54; 32]);
        let mut envelope = attest_verified_forge_authentication_v1(
            &verifier,
            fresh_verified(&operator, [0x55; 32], [0x56; 32]),
        )
        .unwrap();
        envelope.ed25519_signature[0] ^= 1;

        assert_eq!(
            verify_provider_attestation_v1(
                &verifier.identity_public_key_bytes(),
                &verifier.ml_dsa_public_key_bytes(),
                envelope,
            )
            .unwrap_err(),
            ProviderAttestationError::Ed25519VerificationFailed
        );
    }

    #[test]
    fn serde_round_trip_preserves_exact_provider_envelope() {
        let operator = HandshakeManager::from_identity_seeds([0x61; 32], [0x62; 32]);
        let verifier = HandshakeManager::from_identity_seeds([0x63; 32], [0x64; 32]);
        let envelope = attest_verified_forge_authentication_v1(
            &verifier,
            fresh_verified(&operator, [0x65; 32], [0x66; 32]),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: XeniaProviderAttestedReceiptV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, envelope);
    }
}
