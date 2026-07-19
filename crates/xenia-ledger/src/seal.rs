// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::binding::{EvidencePublicKeyBinding, SessionTranscriptBinding};
use crate::entry::LedgerEntryExport;
use crate::policy::{CryptoPolicyProfile, EvidenceCryptoManifest};
use crate::signature::{SignatureEnvelope, SignatureEnvelopeError, SignatureSuite};

/// Stable schema label for signed evidence-bundle seals.
pub const EVIDENCE_BUNDLE_SEAL_SCHEMA: &str = "xenia-evidence-bundle-seal-v1";

/// Algorithm-tagged signature over the full evidence-bundle context.
///
/// Transcript signatures prove the handshake transcript hash. Ledger signatures
/// prove individual consent entries. This seal binds the remaining artifact
/// context together: manifest profile, signature suites, transcript hash,
/// verifier-key fingerprints, and the ledger-chain endpoints. It prevents
/// otherwise-valid pieces from being recombined across sessions or bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleSeal {
    /// Schema label for this seal shape.
    pub schema: String,
    /// UUID of the session described by the sealed bundle.
    pub session_id: Uuid,
    /// Evidence crypto policy profile declared by the manifest.
    pub profile: CryptoPolicyProfile,
    /// Signature suite authenticating the transcript authority surface.
    pub transcript_signature: SignatureSuite,
    /// Signature suite authenticating ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Fingerprint of the transcript verifier public key.
    pub transcript_public_key_fingerprint: [u8; 32],
    /// Fingerprint of the ledger verifier public key.
    pub ledger_public_key_fingerprint: [u8; 32],
    /// Number of ledger entries covered by this seal.
    pub ledger_entry_count: u64,
    /// Entry hash of the first ledger entry covered by this seal.
    pub ledger_first_entry_hash: [u8; 32],
    /// Entry hash of the final ledger entry covered by this seal.
    pub ledger_last_entry_hash: [u8; 32],
    /// Algorithm-tagged signature over this seal's canonical message.
    pub signature: SignatureEnvelope,
}

impl EvidenceBundleSeal {
    /// Build a bundle-seal artifact from the verified evidence-bundle parts.
    pub fn from_parts(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        signature: SignatureEnvelope,
    ) -> Result<Self, EvidenceBundleSealError> {
        let (ledger_entry_count, ledger_first_entry_hash, ledger_last_entry_hash) =
            ledger_chain_anchors(entries)?;
        Ok(Self {
            schema: EVIDENCE_BUNDLE_SEAL_SCHEMA.to_string(),
            session_id: transcript_binding.session_id,
            profile: manifest.profile,
            transcript_signature: manifest.transcript_signature,
            ledger_signature: manifest.ledger_signature,
            transcript_hash_algorithm: transcript_binding.transcript_hash_algorithm.clone(),
            transcript_hash: transcript_binding.transcript_hash,
            transcript_public_key_fingerprint: transcript_key_binding.public_key_fingerprint,
            ledger_public_key_fingerprint: ledger_key_binding.public_key_fingerprint,
            ledger_entry_count,
            ledger_first_entry_hash,
            ledger_last_entry_hash,
            signature,
        })
    }

    /// Validate this seal against the bundle parts it claims to cover.
    pub fn validate_against_bundle(
        &self,
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
    ) -> Result<SignatureSuite, EvidenceBundleSealError> {
        if self.schema != EVIDENCE_BUNDLE_SEAL_SCHEMA {
            return Err(EvidenceBundleSealError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.session_id != transcript_binding.session_id {
            return Err(EvidenceBundleSealError::SessionMismatch {
                binding_session_id: transcript_binding.session_id,
                seal_session_id: self.session_id,
            });
        }
        if self.profile != manifest.profile {
            return Err(EvidenceBundleSealError::ProfileMismatch {
                manifest_profile: manifest.profile,
                seal_profile: self.profile,
            });
        }
        if self.transcript_signature != manifest.transcript_signature {
            return Err(EvidenceBundleSealError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                seal_suite: self.transcript_signature,
            });
        }
        if self.ledger_signature != manifest.ledger_signature {
            return Err(EvidenceBundleSealError::LedgerSignatureSuiteMismatch {
                manifest_suite: manifest.ledger_signature,
                seal_suite: self.ledger_signature,
            });
        }
        if self.transcript_hash_algorithm != transcript_binding.transcript_hash_algorithm {
            return Err(EvidenceBundleSealError::TranscriptHashAlgorithmMismatch {
                binding_algorithm: transcript_binding.transcript_hash_algorithm.clone(),
                seal_algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash != transcript_binding.transcript_hash {
            return Err(EvidenceBundleSealError::TranscriptHashMismatch);
        }
        if self.transcript_public_key_fingerprint != transcript_key_binding.public_key_fingerprint {
            return Err(EvidenceBundleSealError::TranscriptPublicKeyFingerprintMismatch);
        }
        if self.ledger_public_key_fingerprint != ledger_key_binding.public_key_fingerprint {
            return Err(EvidenceBundleSealError::LedgerPublicKeyFingerprintMismatch);
        }

        let (ledger_entry_count, ledger_first_entry_hash, ledger_last_entry_hash) =
            ledger_chain_anchors(entries)?;
        if self.ledger_entry_count != ledger_entry_count {
            return Err(EvidenceBundleSealError::LedgerEntryCountMismatch {
                expected: ledger_entry_count,
                found: self.ledger_entry_count,
            });
        }
        if self.ledger_first_entry_hash != ledger_first_entry_hash {
            return Err(EvidenceBundleSealError::LedgerFirstEntryHashMismatch);
        }
        if self.ledger_last_entry_hash != ledger_last_entry_hash {
            return Err(EvidenceBundleSealError::LedgerLastEntryHashMismatch);
        }

        let signature_suite = self.signature.validate_shape()?;
        if signature_suite != manifest.transcript_signature {
            return Err(EvidenceBundleSealError::SealSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                seal_suite: signature_suite,
            });
        }
        Ok(signature_suite)
    }
}

/// Return the domain-separated message signed by evidence-bundle seals.
pub fn evidence_bundle_seal_message(seal: &EvidenceBundleSeal) -> Vec<u8> {
    let mut message = Vec::new();
    evidence_message_push_bytes(&mut message, b"xenia:evidence-bundle-seal:v1");
    evidence_message_push_bytes(&mut message, seal.schema.as_bytes());
    evidence_message_push_bytes(&mut message, seal.session_id.as_bytes());
    evidence_message_push_bytes(&mut message, seal.profile.stable_label().as_bytes());
    evidence_message_push_bytes(
        &mut message,
        seal.transcript_signature.stable_label().as_bytes(),
    );
    evidence_message_push_bytes(
        &mut message,
        seal.ledger_signature.stable_label().as_bytes(),
    );
    evidence_message_push_bytes(&mut message, seal.transcript_hash_algorithm.as_bytes());
    evidence_message_push_bytes(&mut message, &seal.transcript_hash);
    evidence_message_push_bytes(&mut message, &seal.transcript_public_key_fingerprint);
    evidence_message_push_bytes(&mut message, &seal.ledger_public_key_fingerprint);
    evidence_message_push_u64(&mut message, seal.ledger_entry_count);
    evidence_message_push_bytes(&mut message, &seal.ledger_first_entry_hash);
    evidence_message_push_bytes(&mut message, &seal.ledger_last_entry_hash);
    message
}

/// Return the domain-separated message for a seal over the provided bundle parts.
pub fn evidence_bundle_seal_message_from_parts(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
) -> Result<Vec<u8>, EvidenceBundleSealError> {
    let seal = EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(manifest.transcript_signature, Vec::<u8>::new()),
    )?;
    Ok(evidence_bundle_seal_message(&seal))
}

/// Compute an Ed25519 evidence-bundle seal signature.
pub fn sign_evidence_bundle_seal_ed25519(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &SigningKey,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).to_bytes();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::ed25519(signature),
    )
}

/// Compute an ML-DSA-65 evidence-bundle seal signature.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_bundle_seal_ml_dsa_65(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, signature_bytes.to_vec()),
    )
}

/// Compute an ML-DSA-87 evidence-bundle seal signature.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_bundle_seal_ml_dsa_87(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa87Fips204, signature_bytes.to_vec()),
    )
}

fn evidence_message_push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u64;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(bytes);
}

fn evidence_message_push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn ledger_chain_anchors(
    entries: &[LedgerEntryExport],
) -> Result<(u64, [u8; 32], [u8; 32]), EvidenceBundleSealError> {
    let first = entries
        .first()
        .ok_or(EvidenceBundleSealError::EmptyTranscriptBoundBundle)?;
    let last = entries
        .last()
        .ok_or(EvidenceBundleSealError::EmptyTranscriptBoundBundle)?;
    Ok((entries.len() as u64, first.entry_hash, last.entry_hash))
}

/// Errors surfaced while validating a signed evidence-bundle seal.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceBundleSealError {
    /// The bundle seal schema label is unknown to this verifier.
    #[error("unsupported evidence-bundle seal schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the seal.
        schema: String,
    },
    /// The seal session UUID did not match the transcript binding.
    #[error(
        "transcript binding session {binding_session_id} does not match bundle seal session {seal_session_id}"
    )]
    SessionMismatch {
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID declared by the bundle seal.
        seal_session_id: Uuid,
    },
    /// The seal profile did not match the manifest.
    #[error(
        "manifest profile {manifest_profile:?} does not match bundle seal profile {seal_profile:?}"
    )]
    ProfileMismatch {
        /// Crypto policy profile declared by the manifest.
        manifest_profile: CryptoPolicyProfile,
        /// Crypto policy profile declared by the seal.
        seal_profile: CryptoPolicyProfile,
    },
    /// The seal transcript signature suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match bundle seal transcript signature {seal_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal.
        seal_suite: SignatureSuite,
    },
    /// The seal ledger signature suite did not match the manifest.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match bundle seal ledger signature {seal_suite:?}"
    )]
    LedgerSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal.
        seal_suite: SignatureSuite,
    },
    /// The seal transcript hash algorithm did not match the transcript binding.
    #[error(
        "transcript binding hash algorithm {binding_algorithm} does not match bundle seal hash algorithm {seal_algorithm}"
    )]
    TranscriptHashAlgorithmMismatch {
        /// Hash algorithm declared by the transcript binding.
        binding_algorithm: String,
        /// Hash algorithm declared by the seal.
        seal_algorithm: String,
    },
    /// The seal transcript hash did not match the transcript binding.
    #[error("bundle seal transcript hash does not match transcript binding hash")]
    TranscriptHashMismatch,
    /// The seal transcript key fingerprint did not match the transcript key binding.
    #[error("bundle seal transcript public-key fingerprint mismatch")]
    TranscriptPublicKeyFingerprintMismatch,
    /// The seal ledger key fingerprint did not match the ledger key binding.
    #[error("bundle seal ledger public-key fingerprint mismatch")]
    LedgerPublicKeyFingerprintMismatch,
    /// The seal ledger entry count did not match the supplied entries.
    #[error("bundle seal ledger entry count mismatch: expected {expected}, found {found}")]
    LedgerEntryCountMismatch {
        /// Ledger entry count computed from the supplied entries.
        expected: u64,
        /// Ledger entry count declared by the seal.
        found: u64,
    },
    /// The seal first entry hash did not match the supplied entries.
    #[error("bundle seal first ledger entry hash mismatch")]
    LedgerFirstEntryHashMismatch,
    /// The seal last entry hash did not match the supplied entries.
    #[error("bundle seal last ledger entry hash mismatch")]
    LedgerLastEntryHashMismatch,
    /// The seal signature envelope was malformed.
    #[error("bundle seal signature envelope rejected artifact: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// The seal signature suite did not match the manifest transcript authority suite.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match bundle seal signature {seal_suite:?}"
    )]
    SealSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal signature envelope.
        seal_suite: SignatureSuite,
    },
    /// A sealed transcript-bound evidence bundle had no ledger entries to seal.
    #[error("sealed transcript-bound evidence bundle must contain at least one ledger entry")]
    EmptyTranscriptBoundBundle,
}
