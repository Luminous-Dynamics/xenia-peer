// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic contract matching for verifier-owned detached-message proofs.
//!
//! A downstream authority bridge must not accidentally check only the message,
//! only the signature suite, or only the trusted verifier-key fingerprint. This
//! module provides one fail-closed operation that requires all three properties to
//! match the same opaque [`VerifiedDetachedMessage`].

use crate::{SignatureSuite, VerifiedDetachedMessage};
use thiserror::Error;

/// Require one opaque detached-message proof to satisfy an exact downstream
/// verification contract.
///
/// This function performs no cryptography and cannot create verified state. It is
/// only valid for a [`VerifiedDetachedMessage`] that was already produced by
/// Xenia's verifier. The caller supplies the independently derived message bytes,
/// required signature suite, and trusted public-key fingerprint; all three must
/// match the proof together.
pub fn require_verified_detached_message_contract(
    proof: &VerifiedDetachedMessage,
    expected_suite: SignatureSuite,
    expected_public_key_fingerprint: [u8; 32],
    expected_message: &[u8],
) -> Result<(), VerifiedDetachedMessageContractError> {
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
    Ok(())
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
    fn all_three_contract_dimensions_must_match_together() {
        let message = b"lineage-bearing profile authorization transition";
        let (proof, trusted) = proof_for(message);
        require_verified_detached_message_contract(
            &proof,
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
        )
        .unwrap();
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
