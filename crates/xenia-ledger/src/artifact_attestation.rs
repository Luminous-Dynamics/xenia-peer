// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic signatures over content-addressed evidence artifacts.
//!
//! Xenia should authenticate evidence without needing to understand each evidence
//! domain's semantics. This module binds arbitrary artifact bytes to an explicit domain,
//! schema, subject reference, digest, signature suite, and verifier key.
//!
//! A valid attestation proves only that the selected key signed these exact bytes and
//! metadata. It does **not** prove the artifact is true, scientifically independent,
//! authorized for execution, or worthy of reputation/governance/financial effects.

#![deny(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::binding::{EvidencePublicKeyBinding, EvidencePublicKeyBindingError};
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema label for an artifact-content binding.
pub const EVIDENCE_ARTIFACT_BINDING_SCHEMA: &str = "xenia-evidence-artifact-binding-v1";
/// Stable schema label for a signed artifact attestation.
pub const EVIDENCE_ARTIFACT_ATTESTATION_SCHEMA: &str =
    "xenia-evidence-artifact-attestation-v1";
/// Hash algorithm used by the v1 artifact binding.
pub const EVIDENCE_ARTIFACT_DIGEST_ALGORITHM: &str = "blake3-256";
/// Domain separation for artifact-attestation signatures.
pub const EVIDENCE_ARTIFACT_ATTESTATION_DOMAIN: &[u8] =
    b"xenia:evidence-artifact-attestation:v1";

/// Maximum UTF-8 byte lengths for externally supplied semantic labels.
pub const MAX_ARTIFACT_DOMAIN_LEN: usize = 128;
pub const MAX_ARTIFACT_SCHEMA_LEN: usize = 256;
pub const MAX_ARTIFACT_SUBJECT_REF_LEN: usize = 1_024;

/// Content-addressed description of one external evidence artifact.
///
/// The digest covers `artifact_bytes`; the signed transcript additionally covers the
/// semantic namespace (`artifact_domain`), artifact schema, and subject reference. The
/// same bytes therefore cannot be replayed under a different meaning without invalidating
/// the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactBinding {
    /// Schema label for this binding shape.
    pub schema: String,
    /// Domain namespace, e.g. `symthaea-generativity-evidence`.
    pub artifact_domain: String,
    /// Domain-owned schema label for the serialized artifact bytes.
    pub artifact_schema: String,
    /// Exact subject the artifact claims to describe.
    pub subject_ref: String,
    /// Hash algorithm used for `artifact_digest`.
    pub digest_algorithm: String,
    /// Digest of the exact artifact bytes.
    pub artifact_digest: [u8; 32],
}

impl EvidenceArtifactBinding {
    /// Build a checked binding and compute its artifact digest.
    pub fn from_artifact(
        artifact_domain: impl Into<String>,
        artifact_schema: impl Into<String>,
        subject_ref: impl Into<String>,
        artifact_bytes: &[u8],
    ) -> Result<Self, EvidenceArtifactAttestationError> {
        let binding = Self {
            schema: EVIDENCE_ARTIFACT_BINDING_SCHEMA.to_string(),
            artifact_domain: artifact_domain.into(),
            artifact_schema: artifact_schema.into(),
            subject_ref: subject_ref.into(),
            digest_algorithm: EVIDENCE_ARTIFACT_DIGEST_ALGORITHM.to_string(),
            artifact_digest: compute_evidence_artifact_digest(artifact_bytes),
        };
        binding.validate_shape()?;
        Ok(binding)
    }

    /// Validate structural invariants without trusting the stored artifact digest.
    pub fn validate_shape(&self) -> Result<(), EvidenceArtifactAttestationError> {
        if self.schema != EVIDENCE_ARTIFACT_BINDING_SCHEMA {
            return Err(EvidenceArtifactAttestationError::UnsupportedBindingSchema {
                schema: self.schema.clone(),
            });
        }
        validate_bounded_label(
            "artifact_domain",
            &self.artifact_domain,
            MAX_ARTIFACT_DOMAIN_LEN,
        )?;
        validate_bounded_label(
            "artifact_schema",
            &self.artifact_schema,
            MAX_ARTIFACT_SCHEMA_LEN,
        )?;
        validate_bounded_label(
            "subject_ref",
            &self.subject_ref,
            MAX_ARTIFACT_SUBJECT_REF_LEN,
        )?;
        if self.digest_algorithm != EVIDENCE_ARTIFACT_DIGEST_ALGORITHM {
            return Err(
                EvidenceArtifactAttestationError::UnsupportedDigestAlgorithm {
                    algorithm: self.digest_algorithm.clone(),
                },
            );
        }
        Ok(())
    }

    /// Recompute the digest from authoritative artifact bytes and compare it to this binding.
    pub fn validate_artifact_bytes(
        &self,
        artifact_bytes: &[u8],
    ) -> Result<(), EvidenceArtifactAttestationError> {
        self.validate_shape()?;
        if compute_evidence_artifact_digest(artifact_bytes) != self.artifact_digest {
            return Err(EvidenceArtifactAttestationError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

/// Algorithm-tagged signature over one [`EvidenceArtifactBinding`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactAttestation {
    /// Schema label for this attestation shape.
    pub schema: String,
    /// Exact content/semantic binding being attested.
    pub binding: EvidenceArtifactBinding,
    /// Signature suite committed by the signed transcript.
    pub signature_suite: SignatureSuite,
    /// Algorithm-tagged signature bytes.
    pub signature: SignatureEnvelope,
}

impl EvidenceArtifactAttestation {
    /// Construct from a binding and signature, validating suite/shape consistency.
    pub fn from_parts(
        binding: EvidenceArtifactBinding,
        signature_suite: SignatureSuite,
        signature: SignatureEnvelope,
    ) -> Result<Self, EvidenceArtifactAttestationError> {
        binding.validate_shape()?;
        let envelope_suite = signature.validate_shape()?;
        if envelope_suite != signature_suite {
            return Err(EvidenceArtifactAttestationError::SignatureSuiteMismatch {
                declared_suite: signature_suite,
                envelope_suite,
            });
        }
        Ok(Self {
            schema: EVIDENCE_ARTIFACT_ATTESTATION_SCHEMA.to_string(),
            binding,
            signature_suite,
            signature,
        })
    }

    /// Validate structural consistency before cryptographic verification.
    pub fn validate_shape(&self) -> Result<(), EvidenceArtifactAttestationError> {
        if self.schema != EVIDENCE_ARTIFACT_ATTESTATION_SCHEMA {
            return Err(EvidenceArtifactAttestationError::UnsupportedAttestationSchema {
                schema: self.schema.clone(),
            });
        }
        self.binding.validate_shape()?;
        let envelope_suite = self.signature.validate_shape()?;
        if envelope_suite != self.signature_suite {
            return Err(EvidenceArtifactAttestationError::SignatureSuiteMismatch {
                declared_suite: self.signature_suite,
                envelope_suite,
            });
        }
        Ok(())
    }

    /// Verify authoritative artifact bytes, verifier-key binding, suite/backend agreement,
    /// and the signature over the domain-separated canonical transcript.
    ///
    /// The returned type is constructor-only and intentionally not deserializable. Key
    /// trust/identity resolution remains external: a valid signature proves possession of
    /// the supplied key, not that the key belongs to a socially trusted authority.
    pub fn verify(
        &self,
        artifact_bytes: &[u8],
        key_binding: &EvidencePublicKeyBinding,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<VerifiedEvidenceArtifactAttestation, EvidenceArtifactAttestationError> {
        self.validate_shape()?;
        self.binding.validate_artifact_bytes(artifact_bytes)?;
        key_binding.validate_against_signature_suite_and_backend(
            self.signature_suite,
            backend,
        )?;

        let message = evidence_artifact_attestation_message(&self.binding, self.signature_suite);
        backend.verify_signature(
            &key_binding.public_key,
            &message,
            &self.signature.signature,
        )?;

        Ok(VerifiedEvidenceArtifactAttestation {
            binding: self.binding.clone(),
            signature_suite: self.signature_suite,
            signer_public_key_fingerprint: key_binding.public_key_fingerprint,
        })
    }
}

/// Constructor-only verified view of a signed artifact binding.
///
/// Intentionally `Serialize` but not `Deserialize`: persisted input must pass through
/// [`EvidenceArtifactAttestation::verify`] again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedEvidenceArtifactAttestation {
    binding: EvidenceArtifactBinding,
    signature_suite: SignatureSuite,
    signer_public_key_fingerprint: [u8; 32],
}

impl VerifiedEvidenceArtifactAttestation {
    /// Verified artifact binding.
    pub fn binding(&self) -> &EvidenceArtifactBinding {
        &self.binding
    }

    /// Suite whose signature was successfully verified.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Fingerprint of the verifier key that passed signature verification.
    pub fn signer_public_key_fingerprint(&self) -> &[u8; 32] {
        &self.signer_public_key_fingerprint
    }
}

/// Compute the v1 content digest for arbitrary evidence artifact bytes.
pub fn compute_evidence_artifact_digest(artifact_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(artifact_bytes).as_bytes()
}

/// Canonical domain-separated signature transcript for an artifact binding.
///
/// Every variable-length component is length-prefixed. The signature-suite label is
/// committed so a valid signature cannot be reinterpreted under another algorithm tag.
pub fn evidence_artifact_attestation_message(
    binding: &EvidenceArtifactBinding,
    signature_suite: SignatureSuite,
) -> Vec<u8> {
    let mut message = Vec::new();
    push_bytes(&mut message, EVIDENCE_ARTIFACT_ATTESTATION_DOMAIN);
    push_bytes(&mut message, EVIDENCE_ARTIFACT_ATTESTATION_SCHEMA.as_bytes());
    push_bytes(&mut message, binding.schema.as_bytes());
    push_bytes(&mut message, binding.artifact_domain.as_bytes());
    push_bytes(&mut message, binding.artifact_schema.as_bytes());
    push_bytes(&mut message, binding.subject_ref.as_bytes());
    push_bytes(&mut message, binding.digest_algorithm.as_bytes());
    push_bytes(&mut message, &binding.artifact_digest);
    push_bytes(&mut message, signature_suite.stable_label().as_bytes());
    message
}

/// Sign an artifact binding with Ed25519.
pub fn sign_evidence_artifact_binding_ed25519(
    binding: EvidenceArtifactBinding,
    signing_key: &SigningKey,
) -> Result<EvidenceArtifactAttestation, EvidenceArtifactAttestationError> {
    binding.validate_shape()?;
    let suite = SignatureSuite::Ed25519Rfc8032;
    let message = evidence_artifact_attestation_message(&binding, suite);
    let signature = signing_key.sign(&message).to_bytes();
    EvidenceArtifactAttestation::from_parts(
        binding,
        suite,
        SignatureEnvelope::ed25519(signature),
    )
}

/// Sign an artifact binding with ML-DSA-65.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_artifact_binding_ml_dsa_65(
    binding: EvidenceArtifactBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> Result<EvidenceArtifactAttestation, EvidenceArtifactAttestationError> {
    binding.validate_shape()?;
    let suite = SignatureSuite::MlDsa65Fips204;
    let message = evidence_artifact_attestation_message(&binding, suite);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceArtifactAttestation::from_parts(
        binding,
        suite,
        SignatureEnvelope::new(suite, signature_bytes.to_vec()),
    )
}

/// Sign an artifact binding with ML-DSA-87.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_artifact_binding_ml_dsa_87(
    binding: EvidenceArtifactBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> Result<EvidenceArtifactAttestation, EvidenceArtifactAttestationError> {
    binding.validate_shape()?;
    let suite = SignatureSuite::MlDsa87Fips204;
    let message = evidence_artifact_attestation_message(&binding, suite);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceArtifactAttestation::from_parts(
        binding,
        suite,
        SignatureEnvelope::new(suite, signature_bytes.to_vec()),
    )
}

fn push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(bytes);
}

fn validate_bounded_label(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), EvidenceArtifactAttestationError> {
    if value.trim().is_empty() {
        return Err(EvidenceArtifactAttestationError::EmptyField(field));
    }
    if value.len() > max_len {
        return Err(EvidenceArtifactAttestationError::FieldTooLong {
            field,
            max: max_len,
            found: value.len(),
        });
    }
    Ok(())
}

/// Errors surfaced while constructing or verifying generic evidence artifact attestations.
#[derive(Debug, Error)]
pub enum EvidenceArtifactAttestationError {
    /// Artifact binding schema is unsupported.
    #[error("unsupported evidence artifact binding schema: {schema}")]
    UnsupportedBindingSchema {
        /// Schema found in the binding.
        schema: String,
    },
    /// Artifact attestation schema is unsupported.
    #[error("unsupported evidence artifact attestation schema: {schema}")]
    UnsupportedAttestationSchema {
        /// Schema found in the attestation.
        schema: String,
    },
    /// Digest algorithm is unsupported.
    #[error("unsupported evidence artifact digest algorithm: {algorithm}")]
    UnsupportedDigestAlgorithm {
        /// Algorithm found in the binding.
        algorithm: String,
    },
    /// Required semantic field was empty.
    #[error("required evidence artifact field is empty: {0}")]
    EmptyField(&'static str),
    /// Externally supplied semantic label exceeded its bound.
    #[error("evidence artifact field {field} is {found} bytes; maximum is {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum UTF-8 bytes.
        max: usize,
        /// Actual UTF-8 bytes.
        found: usize,
    },
    /// Recomputed artifact bytes did not match the stored digest.
    #[error("evidence artifact digest mismatch")]
    ArtifactDigestMismatch,
    /// Explicit suite disagreed with the algorithm-tagged envelope.
    #[error(
        "evidence artifact signature suite {declared_suite:?} does not match envelope {envelope_suite:?}"
    )]
    SignatureSuiteMismatch {
        /// Suite committed by the attestation.
        declared_suite: SignatureSuite,
        /// Suite declared by the signature envelope.
        envelope_suite: SignatureSuite,
    },
    /// Signature-envelope shape/algorithm validation failed.
    #[error("evidence artifact signature envelope invalid: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Public-key binding did not match the selected suite/backend.
    #[error("evidence artifact public-key binding invalid: {0}")]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),
    /// Cryptographic signature verification failed.
    #[error("evidence artifact signature verification failed: {0}")]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::binding::EvidencePublicKeyBinding;
    use crate::signature::Ed25519EvidenceSignatureBackend;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn binding(bytes: &[u8]) -> EvidenceArtifactBinding {
        EvidenceArtifactBinding::from_artifact(
            "symthaea-generativity-evidence",
            "symthaea-persisted-generativity-bundle-v1",
            "proposal:42",
            bytes,
        )
        .unwrap()
    }

    fn key_binding(key: &SigningKey) -> EvidencePublicKeyBinding {
        EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            key.verifying_key().to_bytes(),
        )
    }

    #[test]
    fn valid_ed25519_attestation_verifies_exact_artifact() {
        let artifact = br#"{\"assessment\":\"example\"}"#;
        let key = signing_key(7);
        let attestation = sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();

        let verified = attestation
            .verify(
                artifact,
                &key_binding(&key),
                &Ed25519EvidenceSignatureBackend,
            )
            .unwrap();

        assert_eq!(verified.binding().artifact_digest, compute_evidence_artifact_digest(artifact));
        assert_eq!(verified.signature_suite(), SignatureSuite::Ed25519Rfc8032);
        assert_eq!(
            verified.signer_public_key_fingerprint(),
            &key_binding(&key).public_key_fingerprint
        );
    }

    #[test]
    fn mutated_artifact_fails_before_signature_is_trusted() {
        let artifact = b"original";
        let key = signing_key(7);
        let attestation = sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();

        assert!(matches!(
            attestation.verify(
                b"mutated",
                &key_binding(&key),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(EvidenceArtifactAttestationError::ArtifactDigestMismatch)
        ));
    }

    #[test]
    fn semantic_metadata_tampering_breaks_signature() {
        let artifact = b"same bytes";
        let key = signing_key(7);
        let mut attestation =
            sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();
        attestation.binding.subject_ref = "proposal:43".into();

        assert!(matches!(
            attestation.verify(
                artifact,
                &key_binding(&key),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(EvidenceArtifactAttestationError::SignatureVerification(_))
        ));
    }

    #[test]
    fn wrong_verifier_key_does_not_authenticate_attestation() {
        let artifact = b"evidence";
        let signer = signing_key(7);
        let other = signing_key(9);
        let attestation =
            sign_evidence_artifact_binding_ed25519(binding(artifact), &signer).unwrap();

        assert!(matches!(
            attestation.verify(
                artifact,
                &key_binding(&other),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(EvidenceArtifactAttestationError::SignatureVerification(_))
        ));
    }

    #[test]
    fn signature_suite_is_committed_and_cannot_be_retagged() {
        let artifact = b"evidence";
        let key = signing_key(7);
        let mut attestation =
            sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();
        attestation.signature_suite = SignatureSuite::MlDsa65Fips204;

        assert!(matches!(
            attestation.validate_shape(),
            Err(EvidenceArtifactAttestationError::SignatureSuiteMismatch { .. })
        ));
    }

    #[test]
    fn key_fingerprint_tampering_fails_closed() {
        let artifact = b"evidence";
        let key = signing_key(7);
        let attestation = sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();
        let mut verifier_key = key_binding(&key);
        verifier_key.public_key_fingerprint[0] ^= 0x80;

        assert!(matches!(
            attestation.verify(
                artifact,
                &verifier_key,
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(EvidenceArtifactAttestationError::PublicKeyBinding(_))
        ));
    }

    #[test]
    fn domain_is_part_of_signed_semantics() {
        let artifact = b"same bytes";
        let key = signing_key(7);
        let mut attestation =
            sign_evidence_artifact_binding_ed25519(binding(artifact), &key).unwrap();
        let original_message = evidence_artifact_attestation_message(
            &attestation.binding,
            attestation.signature_suite,
        );
        attestation.binding.artifact_domain = "mycelix-attribution-lineage".into();
        let changed_message = evidence_artifact_attestation_message(
            &attestation.binding,
            attestation.signature_suite,
        );

        assert_ne!(original_message, changed_message);
        assert!(attestation
            .verify(
                artifact,
                &key_binding(&key),
                &Ed25519EvidenceSignatureBackend,
            )
            .is_err());
    }

    #[test]
    fn semantic_labels_are_bounded() {
        assert!(matches!(
            EvidenceArtifactBinding::from_artifact(
                "x".repeat(MAX_ARTIFACT_DOMAIN_LEN + 1),
                "schema",
                "subject",
                b"bytes",
            ),
            Err(EvidenceArtifactAttestationError::FieldTooLong {
                field: "artifact_domain",
                ..
            })
        ));
    }
}
