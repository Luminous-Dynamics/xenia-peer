// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detached signatures over typed evidence commitments.
//!
//! This module deliberately proves only a narrow proposition:
//! a particular verification key signed a particular typed 32-byte subject
//! commitment under a particular signature suite. It does not establish that
//! the signer is trusted, that the subject is true, that consent exists, or
//! that any action is authorized.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::binding::{
    EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM, EvidencePublicKeyBinding,
};
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, SignatureEnvelope, SignatureSuite,
};

/// Stable schema label for detached evidence attestations.
pub const DETACHED_EVIDENCE_ATTESTATION_SCHEMA: &str = "xenia-detached-evidence-attestation-v1";
/// Domain separator for the bytes signed by detached evidence attestations.
pub const DETACHED_EVIDENCE_ATTESTATION_MESSAGE_DOMAIN: &str =
    "xenia:detached-evidence-attestation:v1";

const MAX_SUBJECT_PROFILE_BYTES: usize = 256;

/// Algorithm-agile detached signature over a typed evidence commitment.
///
/// The subject itself is not embedded. `subject_profile` identifies the exact
/// commitment grammar/algorithm and `subject_digest` is the resulting 32-byte
/// commitment. The signer is bound by public-key fingerprint rather than by a
/// human identity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedEvidenceAttestation {
    /// Stable attestation schema label.
    pub schema: String,
    /// Stable commitment profile for the subject being signed.
    pub subject_profile: String,
    /// Exact 32-byte subject commitment under `subject_profile`.
    pub subject_digest: [u8; 32],
    /// Fingerprint algorithm used for the signer public key.
    pub signer_fingerprint_algorithm: String,
    /// Fingerprint of the public key expected to verify `signature`.
    pub signer_public_key_fingerprint: [u8; 32],
    /// Algorithm-tagged detached signature over [`detached_evidence_attestation_message`].
    pub signature: SignatureEnvelope,
}

impl DetachedEvidenceAttestation {
    /// Validate the portable attestation shape without treating its signature as verified.
    pub fn validate_shape(&self) -> Result<SignatureSuite, DetachedEvidenceAttestationError> {
        if self.schema != DETACHED_EVIDENCE_ATTESTATION_SCHEMA {
            return Err(DetachedEvidenceAttestationError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        validate_subject_profile(&self.subject_profile)?;
        if self.signer_fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
            return Err(DetachedEvidenceAttestationError::UnsupportedFingerprintAlgorithm {
                algorithm: self.signer_fingerprint_algorithm.clone(),
            });
        }
        self.signature.validate_shape().map_err(|error| {
            DetachedEvidenceAttestationError::InvalidSignatureEnvelope(error.to_string())
        })
    }
}

/// Build the exact domain-separated bytes covered by a detached attestation signature.
///
/// The signature bytes themselves are intentionally excluded. Every variable-length
/// component is length-prefixed so concatenation ambiguity is impossible.
pub fn detached_evidence_attestation_message(
    attestation: &DetachedEvidenceAttestation,
) -> Result<Vec<u8>, DetachedEvidenceAttestationError> {
    let suite = attestation.validate_shape()?;
    let mut message = Vec::new();
    push_bytes(
        &mut message,
        DETACHED_EVIDENCE_ATTESTATION_MESSAGE_DOMAIN.as_bytes(),
    )?;
    push_bytes(&mut message, attestation.schema.as_bytes())?;
    push_bytes(&mut message, attestation.subject_profile.as_bytes())?;
    push_bytes(&mut message, &attestation.subject_digest)?;
    push_bytes(
        &mut message,
        attestation.signer_fingerprint_algorithm.as_bytes(),
    )?;
    push_bytes(&mut message, &attestation.signer_public_key_fingerprint)?;
    push_bytes(&mut message, suite.stable_label().as_bytes())?;
    Ok(message)
}

/// Sign a typed evidence commitment with Ed25519.
///
/// This authenticates the key-to-subject statement only. It does not assign a
/// DID/person/organization identity to the key and does not grant trust or authority.
pub fn sign_detached_evidence_attestation_ed25519(
    subject_profile: impl Into<String>,
    subject_digest: [u8; 32],
    signing_key: &SigningKey,
) -> Result<DetachedEvidenceAttestation, DetachedEvidenceAttestationError> {
    let public_key = signing_key.verifying_key().to_bytes();
    let key_binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
    let mut attestation = unsigned_attestation(
        subject_profile.into(),
        subject_digest,
        &key_binding,
        SignatureSuite::Ed25519Rfc8032,
    )?;
    let message = detached_evidence_attestation_message(&attestation)?;
    attestation.signature = SignatureEnvelope::ed25519(signing_key.sign(&message).to_bytes());
    Ok(attestation)
}

/// Sign a typed evidence commitment with ML-DSA-65 when PQC signatures are enabled.
#[cfg(feature = "pqc-signatures")]
pub fn sign_detached_evidence_attestation_ml_dsa_65(
    subject_profile: impl Into<String>,
    subject_digest: [u8; 32],
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> Result<DetachedEvidenceAttestation, DetachedEvidenceAttestationError> {
    let verifying_key = signing_key.verifying_key().encode();
    let key_bytes: &[u8] = verifying_key.as_ref();
    let key_binding = EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, key_bytes);
    let mut attestation = unsigned_attestation(
        subject_profile.into(),
        subject_digest,
        &key_binding,
        SignatureSuite::MlDsa65Fips204,
    )?;
    let message = detached_evidence_attestation_message(&attestation)?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    attestation.signature = SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, signature_bytes);
    Ok(attestation)
}

/// Sign a typed evidence commitment with ML-DSA-87 when PQC signatures are enabled.
#[cfg(feature = "pqc-signatures")]
pub fn sign_detached_evidence_attestation_ml_dsa_87(
    subject_profile: impl Into<String>,
    subject_digest: [u8; 32],
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> Result<DetachedEvidenceAttestation, DetachedEvidenceAttestationError> {
    let verifying_key = signing_key.verifying_key().encode();
    let key_bytes: &[u8] = verifying_key.as_ref();
    let key_binding = EvidencePublicKeyBinding::new(SignatureSuite::MlDsa87Fips204, key_bytes);
    let mut attestation = unsigned_attestation(
        subject_profile.into(),
        subject_digest,
        &key_binding,
        SignatureSuite::MlDsa87Fips204,
    )?;
    let message = detached_evidence_attestation_message(&attestation)?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    attestation.signature = SignatureEnvelope::new(SignatureSuite::MlDsa87Fips204, signature_bytes);
    Ok(attestation)
}

/// Verify a detached attestation using an explicit algorithm backend and self-describing key binding.
///
/// Success means only that the supplied key binding is internally consistent and
/// its key verifies the attestation signature over the exact typed subject commitment.
pub fn verify_detached_evidence_attestation_with_backend(
    attestation: &DetachedEvidenceAttestation,
    key_binding: &EvidencePublicKeyBinding,
    backend: &impl EvidenceSignatureBackend,
) -> Result<SignatureSuite, DetachedEvidenceAttestationError> {
    let suite = attestation.validate_shape()?;
    if suite != backend.suite() {
        return Err(DetachedEvidenceAttestationError::SignatureBackendSuiteMismatch {
            attestation_suite: suite,
            backend_suite: backend.suite(),
        });
    }
    key_binding
        .validate_against_signature_suite_and_backend(suite, backend)
        .map_err(|error| DetachedEvidenceAttestationError::InvalidKeyBinding(error.to_string()))?;
    if key_binding.public_key_fingerprint != attestation.signer_public_key_fingerprint {
        return Err(DetachedEvidenceAttestationError::SignerFingerprintMismatch);
    }
    let message = detached_evidence_attestation_message(attestation)?;
    backend
        .verify_signature(
            &key_binding.public_key,
            &message,
            &attestation.signature.signature,
        )
        .map_err(|error| DetachedEvidenceAttestationError::SignatureVerification(error.to_string()))?;
    Ok(suite)
}

/// Verify an Ed25519 detached attestation using Xenia's current classical evidence backend.
pub fn verify_detached_evidence_attestation_ed25519(
    attestation: &DetachedEvidenceAttestation,
    key_binding: &EvidencePublicKeyBinding,
) -> Result<(), DetachedEvidenceAttestationError> {
    let suite = verify_detached_evidence_attestation_with_backend(
        attestation,
        key_binding,
        &Ed25519EvidenceSignatureBackend,
    )?;
    if suite != SignatureSuite::Ed25519Rfc8032 {
        return Err(DetachedEvidenceAttestationError::SignatureBackendSuiteMismatch {
            attestation_suite: suite,
            backend_suite: SignatureSuite::Ed25519Rfc8032,
        });
    }
    Ok(())
}

fn unsigned_attestation(
    subject_profile: String,
    subject_digest: [u8; 32],
    key_binding: &EvidencePublicKeyBinding,
    suite: SignatureSuite,
) -> Result<DetachedEvidenceAttestation, DetachedEvidenceAttestationError> {
    validate_subject_profile(&subject_profile)?;
    if key_binding.signature_suite != suite {
        return Err(DetachedEvidenceAttestationError::KeyBindingSuiteMismatch {
            expected: suite,
            found: key_binding.signature_suite,
        });
    }
    if key_binding.fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
        return Err(DetachedEvidenceAttestationError::UnsupportedFingerprintAlgorithm {
            algorithm: key_binding.fingerprint_algorithm.clone(),
        });
    }
    Ok(DetachedEvidenceAttestation {
        schema: DETACHED_EVIDENCE_ATTESTATION_SCHEMA.to_string(),
        subject_profile,
        subject_digest,
        signer_fingerprint_algorithm: EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM.to_string(),
        signer_public_key_fingerprint: key_binding.public_key_fingerprint,
        // Shape-valid placeholder; the real signature is installed before return.
        signature: SignatureEnvelope::new(
            suite,
            vec![0u8; suite.fixed_signature_len().ok_or(
                DetachedEvidenceAttestationError::UnsupportedVariableLengthSuite { suite },
            )?],
        ),
    })
}

fn validate_subject_profile(profile: &str) -> Result<(), DetachedEvidenceAttestationError> {
    if profile.is_empty() {
        return Err(DetachedEvidenceAttestationError::EmptySubjectProfile);
    }
    if profile.len() > MAX_SUBJECT_PROFILE_BYTES {
        return Err(DetachedEvidenceAttestationError::SubjectProfileTooLong {
            max: MAX_SUBJECT_PROFILE_BYTES,
            found: profile.len(),
        });
    }
    if profile.trim() != profile || profile.chars().any(char::is_control) {
        return Err(DetachedEvidenceAttestationError::NonCanonicalSubjectProfile);
    }
    Ok(())
}

fn push_bytes(
    target: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), DetachedEvidenceAttestationError> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| DetachedEvidenceAttestationError::MessageLengthOverflow)?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(bytes);
    Ok(())
}

/// Errors returned while constructing or verifying detached evidence attestations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DetachedEvidenceAttestationError {
    /// The serialized attestation used an unknown schema.
    #[error("unsupported detached evidence attestation schema: {schema}")]
    UnsupportedSchema { schema: String },
    /// Subject profile must be non-empty.
    #[error("detached evidence subject profile must not be empty")]
    EmptySubjectProfile,
    /// Subject profile exceeded the bounded identifier length.
    #[error("detached evidence subject profile exceeds {max} bytes: found {found}")]
    SubjectProfileTooLong { max: usize, found: usize },
    /// Subject profile contains whitespace/control ambiguity.
    #[error("detached evidence subject profile is not canonical")]
    NonCanonicalSubjectProfile,
    /// The public-key fingerprint algorithm is unsupported.
    #[error("unsupported signer fingerprint algorithm: {algorithm}")]
    UnsupportedFingerprintAlgorithm { algorithm: String },
    /// Signature envelope could not be validated.
    #[error("invalid detached evidence signature envelope: {0}")]
    InvalidSignatureEnvelope(String),
    /// Key binding suite disagrees with the intended signature suite.
    #[error("key binding signature suite mismatch: expected {expected:?}, found {found:?}")]
    KeyBindingSuiteMismatch {
        expected: SignatureSuite,
        found: SignatureSuite,
    },
    /// Selected backend does not implement the suite declared by the attestation.
    #[error("signature backend suite mismatch: attestation {attestation_suite:?}, backend {backend_suite:?}")]
    SignatureBackendSuiteMismatch {
        attestation_suite: SignatureSuite,
        backend_suite: SignatureSuite,
    },
    /// Public-key binding is malformed or does not match the selected suite/backend.
    #[error("invalid evidence public-key binding: {0}")]
    InvalidKeyBinding(String),
    /// The key binding fingerprint differs from the fingerprint signed by the attestation.
    #[error("detached evidence signer public-key fingerprint mismatch")]
    SignerFingerprintMismatch,
    /// Cryptographic signature verification failed.
    #[error("detached evidence signature verification failed: {0}")]
    SignatureVerification(String),
    /// This V1 helper cannot create a fixed placeholder for an unparameterized suite.
    #[error("detached evidence signing helper does not support variable-length suite {suite:?}")]
    UnsupportedVariableLengthSuite { suite: SignatureSuite },
    /// Message construction exceeded the portable length representation.
    #[error("detached evidence attestation message length overflow")]
    MessageLengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_binding(key: &SigningKey) -> EvidencePublicKeyBinding {
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, key.verifying_key().to_bytes())
    }

    #[test]
    fn ed25519_attestation_round_trip_verifies() {
        let key = test_key(7);
        let digest = [42u8; 32];
        let attestation = sign_detached_evidence_attestation_ed25519(
            "mycelix/streaming-import-record-v1",
            digest,
            &key,
        )
        .unwrap();
        verify_detached_evidence_attestation_ed25519(&attestation, &key_binding(&key)).unwrap();
    }

    #[test]
    fn changed_subject_digest_fails_signature_verification() {
        let key = test_key(9);
        let mut attestation = sign_detached_evidence_attestation_ed25519(
            "example/subject-v1",
            [1u8; 32],
            &key,
        )
        .unwrap();
        attestation.subject_digest = [2u8; 32];
        assert!(matches!(
            verify_detached_evidence_attestation_ed25519(&attestation, &key_binding(&key)),
            Err(DetachedEvidenceAttestationError::SignatureVerification(_))
        ));
    }

    #[test]
    fn changed_subject_profile_fails_signature_verification() {
        let key = test_key(11);
        let mut attestation = sign_detached_evidence_attestation_ed25519(
            "example/profile-v1",
            [3u8; 32],
            &key,
        )
        .unwrap();
        attestation.subject_profile = "example/profile-v2".into();
        assert!(matches!(
            verify_detached_evidence_attestation_ed25519(&attestation, &key_binding(&key)),
            Err(DetachedEvidenceAttestationError::SignatureVerification(_))
        ));
    }

    #[test]
    fn wrong_verifying_key_fails_before_signature_acceptance() {
        let signer = test_key(13);
        let wrong = test_key(14);
        let attestation = sign_detached_evidence_attestation_ed25519(
            "example/profile-v1",
            [4u8; 32],
            &signer,
        )
        .unwrap();
        assert_eq!(
            verify_detached_evidence_attestation_ed25519(&attestation, &key_binding(&wrong)),
            Err(DetachedEvidenceAttestationError::SignerFingerprintMismatch)
        );
    }

    #[test]
    fn signature_does_not_encode_trust_or_authority() {
        let key = test_key(15);
        let attestation = sign_detached_evidence_attestation_ed25519(
            "example/profile-v1",
            [5u8; 32],
            &key,
        )
        .unwrap();
        let json = serde_json::to_value(&attestation).unwrap();
        let object = json.as_object().unwrap();
        assert!(!object.contains_key("trust"));
        assert!(!object.contains_key("authority"));
        assert!(!object.contains_key("consent"));
        assert!(!object.contains_key("truth"));
    }
}
