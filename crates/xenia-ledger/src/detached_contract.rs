// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic contract matching for verifier-owned detached-message proofs.
//!
//! A downstream authority bridge must not accidentally check only the message,
//! only the signature suite, or only the trusted verifier-key fingerprint. This
//! module provides one fail-closed operation that requires all three properties to
//! match the same opaque [`VerifiedDetachedMessage`] and retains that successful
//! match as an opaque verifier-owned witness.

use crate::{
    SignatureSuite, VerifiedDetachedMessage, verified_detached_message_digest,
};
use thiserror::Error;

/// Opaque witness that one existing verifier-owned detached proof matched one exact
/// downstream contract: exact message bytes, exact signature suite, and exact
/// trusted verifier-key fingerprint.
///
/// This type deliberately implements neither `Serialize` nor `Deserialize`, and
/// its fields are private. It can only be created by
/// [`require_verified_detached_message_contract`]. Crossing a process or storage
/// boundary therefore requires returning to raw evidence and re-running Xenia
/// verification plus contract matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDetachedMessageContractMatch {
    message_digest: [u8; 32],
    signature_suite: SignatureSuite,
    public_key_fingerprint: [u8; 32],
}

impl VerifiedDetachedMessageContractMatch {
    /// Proof-domain digest of the exact downstream message bytes that matched.
    pub fn message_digest(&self) -> [u8; 32] {
        self.message_digest
    }

    /// Signature suite required by the successfully matched downstream contract.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Trusted verifier-key fingerprint required by the matched contract.
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.public_key_fingerprint
    }

    /// Re-bind this witness to independently canonicalized downstream message bytes.
    pub fn matches_message(&self, message: &[u8]) -> bool {
        self.message_digest == verified_detached_message_digest(message)
    }
}

/// Require one opaque detached-message proof to satisfy an exact downstream
/// verification contract and return an opaque witness of that complete match.
///
/// This function performs no cryptography and cannot create cryptographically
/// verified state. It is only valid for a [`VerifiedDetachedMessage`] that was
/// already produced by Xenia's verifier. The caller supplies the independently
/// derived message bytes, required signature suite, and trusted public-key
/// fingerprint; all three must match the proof together before a witness exists.
pub fn require_verified_detached_message_contract(
    proof: &VerifiedDetachedMessage,
    expected_suite: SignatureSuite,
    expected_public_key_fingerprint: [u8; 32],
    expected_message: &[u8],
) -> Result<VerifiedDetachedMessageContractMatch, VerifiedDetachedMessageContractError> {
    if proof.signature_suite() != expected_suite {
        return Err(VerifiedDetachedMessageContractError::SignatureSuiteMismatch {
            expected: expected_suite,
            observed: proof.signature_suite(),
        });
    }
    if proof.public_key_fingerprint() != expected_public_key_fingerprint {
        return Err(
            VerifiedDetachedMessageContractError::TrustedPublicKeyFingerprintMismatch {
                expected: expected_public_key_fingerprint,
                observed: proof.public_key_fingerprint(),
            },
        );
    }
    if !proof.matches_message(expected_message) {
        return Err(VerifiedDetachedMessageContractError::MessageMismatch);
    }

    Ok(VerifiedDetachedMessageContractMatch {
        message_digest: proof.message_digest(),
        signature_suite: proof.signature_suite(),
        public_key_fingerprint: proof.public_key_fingerprint(),
    })
}

/// Failure to match an existing opaque detached proof against an exact downstream
/// verification contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifiedDetachedMessageContractError {
    /// The proof was authenticated under a different signature suite than policy
    /// requires.
    #[error("verified detached-message suite mismatch: expected {expected:?}, observed {observed:?}")]
    SignatureSuiteMismatch {
        /// Signature suite required by downstream policy.
        expected: SignatureSuite,
        /// Signature suite recorded in the verifier-owned proof.
        observed: SignatureSuite,
    },
    /// The proof was authenticated under a different trusted verifier key.
    #[error("verified detached-message public-key fingerprint does not match downstream trusted root")]
    TrustedPublicKeyFingerprintMismatch {
        /// Public-key fingerprint required by downstream policy.
        expected: [u8; 32],
        /// Public-key fingerprint recorded in the verifier-owned proof.
        observed: [u8; 32],
    },
    /// The proof belongs to different exact message bytes.
    #[error("verified detached-message proof does not match the required exact message bytes")]
    MessageMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Ed25519EvidenceSignatureBackend, EvidencePublicKeyBinding, SignatureEnvelope,
        verify_detached_message,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn proof_for(message: &[u8]) -> (VerifiedDetachedMessage, [u8; 32]) {
        let signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            signing_key.verifying_key().to_bytes(),
        );
        let signature = SignatureEnvelope::ed25519(signing_key.sign(message).to_bytes());
        let trusted = binding.public_key_fingerprint;
        let proof = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
            &signature,
            &binding,
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();
        (proof, trusted)
    }

    #[test]
    fn all_three_contract_dimensions_produce_opaque_match_witness() {
        let message = b"lineage-bearing profile authorization transition";
        let (proof, trusted) = proof_for(message);
        let matched = require_verified_detached_message_contract(
            &proof,
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
        )
        .unwrap();

        assert_eq!(matched.signature_suite(), SignatureSuite::Ed25519Rfc8032);
        assert_eq!(matched.public_key_fingerprint(), trusted);
        assert_eq!(matched.message_digest(), proof.message_digest());
        assert!(matched.matches_message(message));
        assert!(!matched.matches_message(b"different transition"));
    }

    #[test]
    fn different_message_is_rejected() {
        let message = b"authorization transition";
        let (proof, trusted) = proof_for(message);
        assert_eq!(
            require_verified_detached_message_contract(
                &proof,
                SignatureSuite::Ed25519Rfc8032,
                trusted,
                b"different transition",
            ),
            Err(VerifiedDetachedMessageContractError::MessageMismatch)
        );
    }

    #[test]
    fn different_suite_is_rejected_even_for_same_message_and_root() {
        let message = b"authorization transition";
        let (proof, trusted) = proof_for(message);
        assert_eq!(
            require_verified_detached_message_contract(
                &proof,
                SignatureSuite::MlDsa65Fips204,
                trusted,
                message,
            ),
            Err(VerifiedDetachedMessageContractError::SignatureSuiteMismatch {
                expected: SignatureSuite::MlDsa65Fips204,
                observed: SignatureSuite::Ed25519Rfc8032,
            })
        );
    }

    #[test]
    fn different_trusted_root_is_rejected_even_for_same_message_and_suite() {
        let message = b"authorization transition";
        let (proof, trusted) = proof_for(message);
        let mut different_root = trusted;
        different_root[0] ^= 0x01;
        assert_eq!(
            require_verified_detached_message_contract(
                &proof,
                SignatureSuite::Ed25519Rfc8032,
                different_root,
                message,
            ),
            Err(
                VerifiedDetachedMessageContractError::TrustedPublicKeyFingerprintMismatch {
                    expected: different_root,
                    observed: trusted,
                }
            )
        );
    }
}
