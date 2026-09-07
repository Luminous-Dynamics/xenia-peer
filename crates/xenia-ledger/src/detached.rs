// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proof-carrying verification for detached, application-defined messages.
//!
//! The raw message, signature envelope, and public-key binding are ordinary
//! serializable evidence inputs. [`VerifiedDetachedMessage`] is deliberately
//! different: its fields are private and it implements neither `Serialize` nor
//! `Deserialize`, so callers cannot turn untrusted wire bytes into verifier-owned
//! authority by deserializing a success-looking object.

use crate::binding::{EvidencePublicKeyBinding, EvidencePublicKeyBindingError};
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};
use thiserror::Error;

/// Domain used to bind the opaque proof to the exact verified message bytes.
pub const VERIFIED_DETACHED_MESSAGE_DIGEST_DOMAIN: &[u8] =
    b"xenia:verified-detached-message:v1\0";

/// Hash algorithm used for [`VerifiedDetachedMessage::message_digest`].
pub const VERIFIED_DETACHED_MESSAGE_DIGEST_ALGORITHM: &str = "blake3-256";

/// Verifier-owned proof that one exact detached message was authenticated under
/// one exact externally trusted public-key fingerprint and signature suite.
///
/// This type is intentionally not serializable. Crossing a process or persistence
/// boundary means crossing back into raw evidence and re-running verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDetachedMessage {
    message_digest: [u8; 32],
    signature_suite: SignatureSuite,
    public_key_fingerprint: [u8; 32],
}

impl VerifiedDetachedMessage {
    /// BLAKE3-256 digest over the verifier domain and exact verified message bytes.
    pub fn message_digest(&self) -> [u8; 32] {
        self.message_digest
    }

    /// Signature suite that successfully authenticated the message.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Fingerprint of the exact externally trusted verifier key whose signature succeeded.
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.public_key_fingerprint
    }

    /// Recompute the proof-domain digest and test whether this proof belongs to
    /// `message`. This lets downstream typed-policy code bind the opaque proof to
    /// its own independently canonicalized signing subject without exposing a
    /// constructor for this type.
    pub fn matches_message(&self, message: &[u8]) -> bool {
        self.message_digest == verified_detached_message_digest(message)
    }
}

/// Verify a detached signature under an explicitly trusted key fingerprint and
/// return an opaque proof of the exact successful verification.
///
/// Verification is fail-closed and ordered deliberately:
/// 1. the signature envelope must be well-shaped and declare `expected_suite`;
/// 2. the key binding must validate its schema, suite, key length, fingerprint,
///    and selected backend against that same expected suite;
/// 3. the now-validated key fingerprint must equal the externally trusted
///    `expected_public_key_fingerprint` policy input;
/// 4. only then does the selected backend authenticate the exact message bytes.
///
/// Both `expected_suite` and `expected_public_key_fingerprint` are policy inputs,
/// not values inferred from attacker-controlled evidence. This prevents both
/// algorithm downgrade and arbitrary-key self-authorization.
pub fn verify_detached_message(
    expected_suite: SignatureSuite,
    expected_public_key_fingerprint: [u8; 32],
    message: &[u8],
    signature: &SignatureEnvelope,
    key_binding: &EvidencePublicKeyBinding,
    backend: &impl EvidenceSignatureBackend,
) -> Result<VerifiedDetachedMessage, DetachedMessageVerifyError> {
    let signature_suite = signature.validate_shape()?;
    if signature_suite != expected_suite {
        return Err(DetachedMessageVerifyError::SignatureSuiteMismatch {
            expected: expected_suite,
            observed: signature_suite,
        });
    }

    key_binding.validate_against_signature_suite_and_backend(expected_suite, backend)?;

    if key_binding.public_key_fingerprint != expected_public_key_fingerprint {
        return Err(DetachedMessageVerifyError::TrustedPublicKeyMismatch {
            expected: expected_public_key_fingerprint,
            observed: key_binding.public_key_fingerprint,
        });
    }

    backend.verify_signature(
        &key_binding.public_key,
        message,
        &signature.signature,
    )?;

    Ok(VerifiedDetachedMessage {
        message_digest: verified_detached_message_digest(message),
        signature_suite: expected_suite,
        public_key_fingerprint: expected_public_key_fingerprint,
    })
}

/// Compute the internal proof digest for exact detached-message bytes.
///
/// The digest is not itself an authentication primitive; only
/// [`verify_detached_message`] can construct [`VerifiedDetachedMessage`].
pub fn verified_detached_message_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(VERIFIED_DETACHED_MESSAGE_DIGEST_DOMAIN);
    hasher.update(message);
    *hasher.finalize().as_bytes()
}

/// Failures surfaced before an opaque detached-message proof can exist.
#[derive(Debug, Error)]
pub enum DetachedMessageVerifyError {
    /// Signature envelope parsing or fixed-length validation failed.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),

    /// The signature envelope declared a suite different from verifier policy.
    #[error("detached signature suite mismatch: expected {expected:?}, observed {observed:?}")]
    SignatureSuiteMismatch {
        /// Suite required by verifier policy.
        expected: SignatureSuite,
        /// Suite declared by the signature envelope.
        observed: SignatureSuite,
    },

    /// Public-key binding schema/suite/fingerprint validation failed.
    #[error(transparent)]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),

    /// A valid key binding did not identify the externally trusted verifier key.
    #[error("detached signature verifier key does not match externally trusted fingerprint")]
    TrustedPublicKeyMismatch {
        /// Fingerprint required by external verifier policy.
        expected: [u8; 32],
        /// Fingerprint of the supplied, internally valid public-key binding.
        observed: [u8; 32],
    },

    /// Cryptographic signature verification failed in the selected backend.
    #[error(transparent)]
    SignatureBackend(#[from] EvidenceSignatureBackendError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::EvidencePublicKeyBinding;
    use crate::signature::{Ed25519EvidenceSignatureBackend, SignatureEnvelope};
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture_with_seed(
        message: &[u8],
        seed_byte: u8,
    ) -> (
        EvidencePublicKeyBinding,
        SignatureEnvelope,
        Ed25519EvidenceSignatureBackend,
    ) {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let signature = signing_key.sign(message).to_bytes();
        (
            EvidencePublicKeyBinding::new(
                SignatureSuite::Ed25519Rfc8032,
                signing_key.verifying_key().to_bytes(),
            ),
            SignatureEnvelope::ed25519(signature),
            Ed25519EvidenceSignatureBackend,
        )
    }

    fn fixture(
        message: &[u8],
    ) -> (
        EvidencePublicKeyBinding,
        SignatureEnvelope,
        Ed25519EvidenceSignatureBackend,
    ) {
        fixture_with_seed(message, 0x41)
    }

    #[test]
    fn genuine_signature_under_trusted_key_produces_message_bound_proof() {
        let message = b"symthaea canonical safety-profile authorization subject";
        let (binding, signature, backend) = fixture(message);
        let trusted = binding.public_key_fingerprint;

        let verified = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
            &signature,
            &binding,
            &backend,
        )
        .unwrap();

        assert!(verified.matches_message(message));
        assert!(!verified.matches_message(b"different subject"));
        assert_eq!(verified.signature_suite(), SignatureSuite::Ed25519Rfc8032);
        assert_eq!(verified.public_key_fingerprint(), trusted);
        assert_eq!(
            verified.message_digest(),
            verified_detached_message_digest(message)
        );
    }

    #[test]
    fn tampered_message_cannot_produce_proof() {
        let original = b"authorized subject";
        let (binding, signature, backend) = fixture(original);

        let result = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            binding.public_key_fingerprint,
            b"tampered subject",
            &signature,
            &binding,
            &backend,
        );
        assert!(matches!(
            result,
            Err(DetachedMessageVerifyError::SignatureBackend(_))
        ));
    }

    #[test]
    fn attacker_controlled_suite_cannot_downgrade_verifier_policy() {
        let message = b"profile authorization";
        let (binding, signature, backend) = fixture(message);

        let result = verify_detached_message(
            SignatureSuite::MlDsa65Fips204,
            binding.public_key_fingerprint,
            message,
            &signature,
            &binding,
            &backend,
        );
        assert!(matches!(
            result,
            Err(DetachedMessageVerifyError::SignatureSuiteMismatch {
                expected: SignatureSuite::MlDsa65Fips204,
                observed: SignatureSuite::Ed25519Rfc8032,
            })
        ));
    }

    #[test]
    fn self_consistent_untrusted_key_cannot_self_authorize() {
        let message = b"profile authorization";
        let (trusted_binding, _, _) = fixture_with_seed(message, 0x41);
        let (attacker_binding, attacker_signature, attacker_backend) =
            fixture_with_seed(message, 0x42);

        let result = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            trusted_binding.public_key_fingerprint,
            message,
            &attacker_signature,
            &attacker_binding,
            &attacker_backend,
        );
        assert!(matches!(
            result,
            Err(DetachedMessageVerifyError::TrustedPublicKeyMismatch { .. })
        ));
    }

    #[test]
    fn mutated_public_key_fingerprint_fails_before_trust_acceptance() {
        let message = b"profile authorization";
        let (mut binding, signature, backend) = fixture(message);
        let trusted = binding.public_key_fingerprint;
        binding.public_key_fingerprint[0] ^= 0x01;

        let result = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
            &signature,
            &binding,
            &backend,
        );
        assert!(matches!(
            result,
            Err(DetachedMessageVerifyError::PublicKeyBinding(
                EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch
            ))
        ));
    }

    #[test]
    fn signature_envelope_suite_must_match_backend_and_key_binding() {
        let message = b"profile authorization";
        let (binding, mut signature, backend) = fixture(message);
        signature.algorithm = SignatureSuite::MlDsa65Fips204.stable_label().to_owned();
        signature.signature = vec![0u8; 3309];

        let result = verify_detached_message(
            SignatureSuite::MlDsa65Fips204,
            binding.public_key_fingerprint,
            message,
            &signature,
            &binding,
            &backend,
        );
        assert!(matches!(
            result,
            Err(DetachedMessageVerifyError::PublicKeyBinding(_))
        ));
    }
}
