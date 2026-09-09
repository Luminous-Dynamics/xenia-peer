// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic downstream contract matching for verifier-owned detached-message proofs.
//!
//! Cryptographic authentication and application contract matching are separate
//! transitions. [`VerifiedDetachedMessage`] proves that Xenia authenticated exact
//! bytes under one exact suite and trusted public-key fingerprint. This module
//! requires an independently derived downstream contract to agree on all three
//! facts together before retaining an opaque matched witness.

use crate::{SignatureSuite, VerifiedDetachedMessage, verified_detached_message_digest};
use thiserror::Error;

/// Opaque witness that one existing Xenia cryptographic proof matched one exact
/// downstream contract: exact message bytes, exact signature suite, and exact
/// trusted verifier-key fingerprint.
///
/// This type deliberately implements neither `Serialize` nor `Deserialize`. Its
/// only production constructor is [`require_verified_detached_message_contract`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDetachedMessageContractMatch {
    message_digest: [u8; 32],
    signature_suite: SignatureSuite,
    public_key_fingerprint: [u8; 32],
}

impl VerifiedDetachedMessageContractMatch {
    /// Proof-domain digest of the exact message bytes that matched.
    pub fn message_digest(&self) -> [u8; 32] {
        self.message_digest
    }

    /// Signature suite required by the matched downstream contract.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Exact trusted verifier-key fingerprint required by the contract.
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.public_key_fingerprint
    }

    /// Re-bind this opaque witness to independently canonicalized message bytes.
    pub fn matches_message(&self, message: &[u8]) -> bool {
        self.message_digest == verified_detached_message_digest(message)
    }
}

/// Require one opaque Xenia detached proof to satisfy all dimensions of an exact
/// downstream verification contract and retain the successful match as an opaque
/// witness.
///
/// This operation performs no cryptography and cannot manufacture a
/// [`VerifiedDetachedMessage`]. The caller must independently derive the exact
/// expected message, signature suite, and trusted key fingerprint. All three must
/// match the same Xenia-owned proof.
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

/// Failure to bind an existing opaque detached proof to an exact downstream
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifiedDetachedMessageContractError {
    /// Cryptographic proof used a suite different from downstream policy.
    #[error("verified detached-message suite mismatch: expected {expected:?}, observed {observed:?}")]
    SignatureSuiteMismatch {
        /// Signature suite required by downstream policy.
        expected: SignatureSuite,
        /// Signature suite recorded in Xenia's verifier-owned proof.
        observed: SignatureSuite,
    },
    /// Cryptographic proof used a different trusted verifier key.
    #[error("verified detached-message public-key fingerprint does not match downstream trusted root")]
    TrustedPublicKeyFingerprintMismatch {
        /// Public-key fingerprint required by downstream policy.
        expected: [u8; 32],
        /// Public-key fingerprint recorded in Xenia's proof.
        observed: [u8; 32],
    },
    /// Cryptographic proof belongs to different exact message bytes.
    #[error("verified detached-message proof does not match the required exact message bytes")]
    MessageMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidencePublicKeyBinding, SignatureEnvelope, verify_detached_message};
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
