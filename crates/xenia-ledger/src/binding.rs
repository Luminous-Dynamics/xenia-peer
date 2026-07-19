// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::entry::{
    TranscriptBindingError, TranscriptSignatureError, compute_session_transcript_hash,
};
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{EvidenceSignatureBackend, SignatureEnvelope, SignatureSuite};

/// Stable schema label for evidence public-key bindings.
pub const EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA: &str = "xenia-evidence-public-key-binding-v1";

/// Fingerprint algorithm used to bind evidence exports to their verifier key.
pub const EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM: &str = "blake3-256";

/// Public-key material and fingerprint used to verify exported evidence.
///
/// Evidence verifiers already require a caller-provided public key, but raw bytes
/// alone are easy to mix up when full-PQC fixtures carry much larger ML-DSA keys.
/// This binding makes the key's signature suite and fingerprint explicit before
/// any ledger signature is trusted. It is intentionally separate from
/// [`EvidenceCryptoManifest`] because fingerprints are artifact-specific while
/// manifests describe the policy/profile class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePublicKeyBinding {
    /// Schema label for this binding shape.
    pub schema: String,
    /// Signature suite this public key verifies.
    pub signature_suite: SignatureSuite,
    /// Raw public/verifying-key bytes for `signature_suite`.
    pub public_key: Vec<u8>,
    /// Hash algorithm used for `public_key_fingerprint`.
    pub fingerprint_algorithm: String,
    /// Fingerprint over `public_key`.
    pub public_key_fingerprint: [u8; 32],
}

impl EvidencePublicKeyBinding {
    /// Build a public-key binding and compute its fingerprint.
    pub fn new(signature_suite: SignatureSuite, public_key: impl Into<Vec<u8>>) -> Self {
        let public_key = public_key.into();
        Self {
            schema: EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA.to_string(),
            signature_suite,
            public_key_fingerprint: compute_evidence_public_key_fingerprint(&public_key),
            public_key,
            fingerprint_algorithm: EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM.to_string(),
        }
    }

    /// Validate this key binding against a manifest and selected ledger signature backend.
    pub fn validate_against_manifest_and_backend(
        &self,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidencePublicKeyBindingError> {
        self.validate_against_signature_suite_and_backend(manifest.ledger_signature, backend)
    }

    /// Validate this key binding against an expected signature suite and backend.
    ///
    /// Use this when an artifact carries distinct verifier keys for different
    /// authority surfaces, such as transcript signatures and ledger signatures.
    pub fn validate_against_signature_suite_and_backend(
        &self,
        expected_suite: SignatureSuite,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidencePublicKeyBindingError> {
        if self.schema != EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA {
            return Err(EvidencePublicKeyBindingError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
            return Err(
                EvidencePublicKeyBindingError::UnsupportedFingerprintAlgorithm {
                    algorithm: self.fingerprint_algorithm.clone(),
                },
            );
        }
        if self.public_key.is_empty() {
            return Err(EvidencePublicKeyBindingError::EmptyPublicKey);
        }
        if self.signature_suite != expected_suite {
            return Err(
                EvidencePublicKeyBindingError::SignatureSuiteManifestMismatch {
                    manifest_suite: expected_suite,
                    binding_suite: self.signature_suite,
                },
            );
        }
        if self.signature_suite != backend.suite() {
            return Err(
                EvidencePublicKeyBindingError::SignatureSuiteBackendMismatch {
                    backend_suite: backend.suite(),
                    binding_suite: self.signature_suite,
                },
            );
        }
        if let Some(expected) = self.signature_suite.fixed_public_key_len() {
            let found = self.public_key.len();
            if found != expected {
                return Err(EvidencePublicKeyBindingError::BadPublicKeyLength {
                    signature_suite: self.signature_suite,
                    expected,
                    found,
                });
            }
        }
        let computed = compute_evidence_public_key_fingerprint(&self.public_key);
        if computed != self.public_key_fingerprint {
            return Err(EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch);
        }
        Ok(())
    }
}

/// Compute the stable fingerprint for an evidence verifier public key.
pub fn compute_evidence_public_key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

/// Errors surfaced while validating an evidence public-key binding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidencePublicKeyBindingError {
    /// The binding schema label is unknown to this verifier.
    #[error("unsupported evidence public-key binding schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the binding.
        schema: String,
    },
    /// The fingerprint algorithm is unknown to this verifier.
    #[error("unsupported evidence public-key fingerprint algorithm: {algorithm}")]
    UnsupportedFingerprintAlgorithm {
        /// Fingerprint algorithm label found in the binding.
        algorithm: String,
    },
    /// The public key was empty.
    #[error("evidence public key must not be empty")]
    EmptyPublicKey,
    /// The key binding's suite did not match the manifest ledger signature suite.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match public-key binding {binding_suite:?}"
    )]
    SignatureSuiteManifestMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the public-key binding.
        binding_suite: SignatureSuite,
    },
    /// The key binding's suite did not match the selected verifier backend.
    #[error(
        "verifier backend {backend_suite:?} does not match public-key binding {binding_suite:?}"
    )]
    SignatureSuiteBackendMismatch {
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
        /// Signature suite declared by the public-key binding.
        binding_suite: SignatureSuite,
    },
    /// The public key length did not match the fixed-size suite expectation.
    #[error("bad public-key length for {signature_suite:?}: expected {expected}, found {found}")]
    BadPublicKeyLength {
        /// Signature suite declared by the binding.
        signature_suite: SignatureSuite,
        /// Expected public-key length in bytes.
        expected: usize,
        /// Actual public-key length in bytes.
        found: usize,
    },
    /// The stored fingerprint did not match the supplied public-key bytes.
    #[error("evidence public-key fingerprint mismatch")]
    PublicKeyFingerprintMismatch,
}

/// Stable schema label for session transcript bindings.
pub const SESSION_TRANSCRIPT_BINDING_SCHEMA: &str = "xenia-session-transcript-binding-v1";

/// Hash algorithm used for session transcript bindings.
pub const SESSION_TRANSCRIPT_HASH_ALGORITHM: &str = "blake3-256";

/// Bind an evidence bundle to the handshake/session transcript it claims to describe.
///
/// This structure does not store the transcript itself. It stores the stable hash of
/// the canonical transcript bytes, the session UUID those bytes established, and the
/// transcript signature suite declared by the evidence manifest. Bundle verifiers can
/// then reject a valid ledger chain that is replayed next to a different session
/// transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTranscriptBinding {
    /// Schema label for this binding shape.
    pub schema: String,
    /// UUID of the session established by the canonical transcript.
    pub session_id: Uuid,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Signature suite used to authenticate the transcript.
    pub transcript_signature: SignatureSuite,
}

impl SessionTranscriptBinding {
    /// Build a binding from canonical transcript bytes.
    pub fn new(
        session_id: Uuid,
        transcript_bytes: &[u8],
        transcript_signature: SignatureSuite,
    ) -> Self {
        Self::from_hash(
            session_id,
            compute_session_transcript_hash(transcript_bytes),
            transcript_signature,
        )
    }

    /// Build a binding when the transcript hash was computed by another crate.
    pub fn from_hash(
        session_id: Uuid,
        transcript_hash: [u8; 32],
        transcript_signature: SignatureSuite,
    ) -> Self {
        Self {
            schema: SESSION_TRANSCRIPT_BINDING_SCHEMA.to_string(),
            session_id,
            transcript_hash_algorithm: SESSION_TRANSCRIPT_HASH_ALGORITHM.to_string(),
            transcript_hash,
            transcript_signature,
        }
    }

    /// Validate this binding against the declared evidence manifest.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), TranscriptBindingError> {
        if self.schema != SESSION_TRANSCRIPT_BINDING_SCHEMA {
            return Err(TranscriptBindingError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.transcript_hash_algorithm != SESSION_TRANSCRIPT_HASH_ALGORITHM {
            return Err(TranscriptBindingError::UnsupportedTranscriptHashAlgorithm {
                algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash == [0u8; 32] {
            return Err(TranscriptBindingError::EmptyTranscriptHash);
        }
        if self.transcript_signature != manifest.transcript_signature {
            return Err(TranscriptBindingError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                binding_suite: self.transcript_signature,
            });
        }
        Ok(())
    }
}

/// Stable schema label for session transcript signatures.
pub const SESSION_TRANSCRIPT_SIGNATURE_SCHEMA: &str = "xenia-session-transcript-signature-v1";

/// Algorithm-tagged signature over a session transcript binding.
///
/// This artifact makes the transcript authority explicit. A transcript hash can
/// bind a ledger to a session, but a full-PQC evidence bundle also needs a
/// signature over that transcript hash so the transcript authority cannot remain
/// classical or unsigned while the ledger entries are ML-DSA signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTranscriptSignature {
    /// Schema label for this signature artifact.
    pub schema: String,
    /// UUID of the session whose transcript was signed.
    pub session_id: Uuid,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Algorithm-tagged signature over `transcript_hash`.
    pub signature: SignatureEnvelope,
}

impl SessionTranscriptSignature {
    /// Build a transcript-signature artifact from an existing transcript binding.
    pub fn from_binding(binding: &SessionTranscriptBinding, signature: SignatureEnvelope) -> Self {
        Self {
            schema: SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.to_string(),
            session_id: binding.session_id,
            transcript_hash_algorithm: binding.transcript_hash_algorithm.clone(),
            transcript_hash: binding.transcript_hash,
            signature,
        }
    }

    /// Validate this transcript signature artifact before cryptographic verification.
    pub fn validate_against_binding_and_manifest(
        &self,
        binding: &SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SignatureSuite, TranscriptSignatureError> {
        if self.schema != SESSION_TRANSCRIPT_SIGNATURE_SCHEMA {
            return Err(TranscriptSignatureError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.transcript_hash_algorithm != SESSION_TRANSCRIPT_HASH_ALGORITHM {
            return Err(
                TranscriptSignatureError::UnsupportedTranscriptHashAlgorithm {
                    algorithm: self.transcript_hash_algorithm.clone(),
                },
            );
        }
        if self.session_id != binding.session_id {
            return Err(TranscriptSignatureError::BindingSessionMismatch {
                binding_session_id: binding.session_id,
                signature_session_id: self.session_id,
            });
        }
        if self.transcript_hash_algorithm != binding.transcript_hash_algorithm {
            return Err(TranscriptSignatureError::BindingHashAlgorithmMismatch {
                binding_algorithm: binding.transcript_hash_algorithm.clone(),
                signature_algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash != binding.transcript_hash {
            return Err(TranscriptSignatureError::BindingHashMismatch);
        }
        if self.transcript_hash == [0u8; 32] {
            return Err(TranscriptSignatureError::EmptyTranscriptHash);
        }

        let signature_suite = self.signature.validate_shape()?;
        if signature_suite != manifest.transcript_signature {
            return Err(TranscriptSignatureError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                signature_suite,
            });
        }

        Ok(signature_suite)
    }
}

/// Return the domain-separated message signed by transcript signature artifacts.
///
/// The raw transcript hash is intentionally not signed directly. Including the
/// schema, session UUID, hash algorithm, and hash under an Xenia-specific domain
/// prevents a transcript signature from being replayed as some other 32-byte
/// message signature.
pub fn session_transcript_signature_message(binding: &SessionTranscriptBinding) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        b"xenia:session-transcript-signature:v1".len()
            + SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.len()
            + SESSION_TRANSCRIPT_HASH_ALGORITHM.len()
            + 16
            + 32
            + 4,
    );
    message.extend_from_slice(b"xenia:session-transcript-signature:v1");
    message.push(0);
    message.extend_from_slice(SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(binding.session_id.as_bytes());
    message.extend_from_slice(binding.transcript_hash_algorithm.as_bytes());
    message.push(0);
    message.extend_from_slice(&binding.transcript_hash);
    message
}

/// Compute an Ed25519 transcript signature over an existing transcript binding.
pub fn sign_session_transcript_binding_ed25519(
    binding: &SessionTranscriptBinding,
    signing_key: &SigningKey,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).to_bytes();
    SessionTranscriptSignature::from_binding(binding, SignatureEnvelope::ed25519(signature))
}

/// Compute an ML-DSA-65 transcript signature over an existing transcript binding.
#[cfg(feature = "pqc-signatures")]
pub fn sign_session_transcript_binding_ml_dsa_65(
    binding: &SessionTranscriptBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    SessionTranscriptSignature::from_binding(
        binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, signature_bytes.to_vec()),
    )
}

/// Compute an ML-DSA-87 transcript signature over an existing transcript binding.
#[cfg(feature = "pqc-signatures")]
pub fn sign_session_transcript_binding_ml_dsa_87(
    binding: &SessionTranscriptBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    SessionTranscriptSignature::from_binding(
        binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa87Fips204, signature_bytes.to_vec()),
    )
}
