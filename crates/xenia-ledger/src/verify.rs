// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};

use crate::binding::{
    EvidencePublicKeyBinding, SessionTranscriptBinding, SessionTranscriptSignature,
    session_transcript_signature_message,
};
use crate::entry::{LedgerEntry, LedgerEntryExport};
use crate::errors::{EvidenceBundleVerifyError, VerifyError};
use crate::hash::compute_entry_hash;
use crate::policy::{
    CURRENT_EVIDENCE_CRYPTO_MANIFEST, CURRENT_LEDGER_EVIDENCE_PROFILE, EvidenceCryptoManifest,
    EvidencePolicyError, LedgerEvidenceProfile,
};
use crate::seal::{EvidenceBundleSeal, evidence_bundle_seal_message};
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stateless verifier. Separate from [`crate::Chain`] so an auditor can verify
/// a chain using only the public key and the serialized entries, never
/// needing access to the signing key.
pub struct Verifier;

impl Verifier {
    /// Return the evidence-profile labels for the current ledger verifier.
    pub const fn evidence_profile() -> LedgerEvidenceProfile {
        CURRENT_LEDGER_EVIDENCE_PROFILE
    }

    /// Return the current end-to-end evidence crypto manifest.
    pub const fn evidence_crypto_manifest() -> EvidenceCryptoManifest {
        CURRENT_EVIDENCE_CRYPTO_MANIFEST
    }

    /// Validate that a manifest satisfies its declared policy.
    pub const fn verify_evidence_crypto_manifest(
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), EvidencePolicyError> {
        manifest.validate_against_policy()
    }

    /// Verify every entry in a chain: sequence continuity, hash link,
    /// entry_hash recomputation, and Ed25519 signature.
    ///
    /// An empty slice passes vacuously. Callers who require at least
    /// one entry should check length separately before calling this.
    pub fn verify_chain(
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), VerifyError> {
        let mut expected_prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(VerifyError::OutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
                return Err(VerifyError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(VerifyError::BrokenLink { seq: entry.seq });
            }

            let recomputed =
                compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                    .map_err(|_| VerifyError::EntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(VerifyError::EntryHashMismatch { seq: entry.seq });
            }

            let sig = Signature::from_bytes(&entry.signature);
            public_key
                .verify(&entry.entry_hash, &sig)
                .map_err(|_| VerifyError::BadSignature { seq: entry.seq })?;

            expected_prev = entry.entry_hash;
        }
        Ok(())
    }

    /// Verify an evidence manifest and its exported ledger entries as one bundle.
    ///
    /// This is the verifier entry point for long-lived evidence artifacts. It
    /// first enforces the manifest's crypto policy, then confirms every entry
    /// envelope declares the same ledger signature suite as the manifest, then
    /// runs the chain/hash/signature verifier. This prevents a forged artifact
    /// from attaching a `full-pqc-v1` manifest to an Ed25519 export or otherwise
    /// overstating the evidence's actual crypto surface.
    pub fn verify_evidence_bundle(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify an evidence manifest and exported ledger entries using an explicit
    /// signature backend.
    ///
    /// This is the verifier entry point for full-PQC evidence once a reviewed
    /// ML-DSA/SLH-DSA backend is selected. The manifest policy, the backend
    /// suite, and every entry envelope must agree before any signature bytes are
    /// trusted.
    pub fn verify_evidence_bundle_with_backend(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;

        if backend.suite() != manifest.ledger_signature {
            return Err(EvidenceBundleVerifyError::LedgerBackendSuiteMismatch {
                manifest_suite: manifest.ledger_signature,
                backend_suite: backend.suite(),
            });
        }

        for entry in entries {
            let entry_suite = entry_signature_suite(entry)?;
            if entry_suite != manifest.ledger_signature {
                return Err(EvidenceBundleVerifyError::LedgerSignatureSuiteMismatch {
                    seq: entry.seq,
                    manifest_suite: manifest.ledger_signature,
                    entry_suite,
                });
            }
        }

        Self::verify_exported_chain_with_backend(entries, public_key, backend)?;
        Ok(())
    }

    /// Verify an evidence bundle using a self-describing public-key binding.
    ///
    /// This is the preferred explicit-backend verifier for long-lived artifacts:
    /// it validates the manifest policy, selected backend, key suite, public-key
    /// length, and public-key fingerprint before any entry signature is checked.
    pub fn verify_evidence_bundle_with_key_binding(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        key_binding: &EvidencePublicKeyBinding,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;
        key_binding.validate_against_manifest_and_backend(manifest, backend)?;
        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &key_binding.public_key,
            backend,
        )
    }

    /// Verify a manifest, session transcript binding, and exported ledger as one artifact.
    ///
    /// This is the preferred verifier for evidence bundles that include a canonical
    /// handshake/session transcript hash. It prevents a valid exported ledger chain
    /// from being replayed beside a different transcript by requiring every ledger
    /// entry to carry the same `session_id` as the transcript binding before the
    /// ordinary bundle verifier is trusted.
    pub fn verify_transcript_bound_evidence_bundle(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_transcript_bound_evidence_bundle_with_backend(
            manifest,
            transcript_binding,
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify a transcript-bound evidence bundle with an explicit signature backend.
    ///
    /// Use this for future full-PQC bundles whose ledger entries are ML-DSA or
    /// SLH-DSA signed. It keeps transcript binding, manifest policy, entry-suite
    /// matching, and backend selection in one fail-closed path.
    pub fn verify_transcript_bound_evidence_bundle_with_backend(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        transcript_binding.validate_against_manifest(manifest)?;
        if manifest.profile.requires_post_quantum_signatures() {
            return Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc);
        }

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_backend(manifest, entries, public_key, backend)
    }

    /// Verify a transcript-bound evidence bundle using a self-describing public-key binding.
    ///
    /// This keeps the full verifier surface self-describing: manifest, transcript
    /// binding, public-key provenance, signature backend, and exported ledger must
    /// agree before the artifact is accepted.
    pub fn verify_transcript_bound_evidence_bundle_with_key_binding(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        key_binding: &EvidencePublicKeyBinding,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        transcript_binding.validate_against_manifest(manifest)?;
        if manifest.profile.requires_post_quantum_signatures() {
            return Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc);
        }
        key_binding.validate_against_manifest_and_backend(manifest, backend)?;

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &key_binding.public_key,
            backend,
        )
    }

    /// Verify a signed transcript-bound evidence bundle using explicit key bindings.
    ///
    /// This is the strict verifier for `full-pqc-v1` artifacts. It requires a
    /// signature over the transcript hash, validates the transcript verifier key
    /// against `manifest.transcript_signature`, validates the ledger verifier key
    /// against `manifest.ledger_signature`, and only then verifies ledger entries.
    #[allow(clippy::too_many_arguments)] // distinct verification inputs (manifest, bindings, signatures, key fingerprints); a bundle struct would just re-spread them
    pub fn verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_signature: &SessionTranscriptSignature,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        transcript_backend: &impl EvidenceSignatureBackend,
        ledger_backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;
        transcript_binding.validate_against_manifest(manifest)?;
        let transcript_signature_suite = transcript_signature
            .validate_against_binding_and_manifest(transcript_binding, manifest)?;

        if transcript_backend.suite() != manifest.transcript_signature {
            return Err(EvidenceBundleVerifyError::TranscriptBackendSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                backend_suite: transcript_backend.suite(),
            });
        }
        if transcript_signature_suite != transcript_backend.suite() {
            return Err(EvidenceBundleVerifyError::TranscriptBackendSuiteMismatch {
                manifest_suite: transcript_signature_suite,
                backend_suite: transcript_backend.suite(),
            });
        }
        transcript_key_binding.validate_against_signature_suite_and_backend(
            manifest.transcript_signature,
            transcript_backend,
        )?;
        ledger_key_binding.validate_against_manifest_and_backend(manifest, ledger_backend)?;

        transcript_backend
            .verify_signature(
                &transcript_key_binding.public_key,
                &session_transcript_signature_message(transcript_binding),
                &transcript_signature.signature.signature,
            )
            .map_err(
                |source| EvidenceBundleVerifyError::TranscriptSignatureBackend {
                    signature_suite: transcript_signature_suite,
                    source,
                },
            )?;

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_key_binding(
            manifest,
            entries,
            ledger_key_binding,
            ledger_backend,
        )
    }

    /// Verify a signed transcript-bound bundle plus a signed bundle-level seal.
    ///
    /// This is the strongest verifier path for long-lived audit artifacts. In
    /// addition to the signed transcript and signed ledger entries, it verifies a
    /// bundle seal over the manifest profile, signature suites, transcript hash,
    /// verifier-key fingerprints, and ledger-chain endpoints.
    #[allow(clippy::too_many_arguments)] // distinct verification inputs; a bundle struct would just re-spread them
    pub fn verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_signature: &SessionTranscriptSignature,
        bundle_seal: &EvidenceBundleSeal,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        transcript_backend: &impl EvidenceSignatureBackend,
        ledger_backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
            manifest,
            transcript_binding,
            transcript_signature,
            transcript_key_binding,
            entries,
            ledger_key_binding,
            transcript_backend,
            ledger_backend,
        )?;

        let seal_signature_suite = bundle_seal.validate_against_bundle(
            manifest,
            transcript_binding,
            transcript_key_binding,
            entries,
            ledger_key_binding,
        )?;

        transcript_backend
            .verify_signature(
                &transcript_key_binding.public_key,
                &evidence_bundle_seal_message(bundle_seal),
                &bundle_seal.signature.signature,
            )
            .map_err(
                |source| EvidenceBundleVerifyError::BundleSealSignatureBackend {
                    signature_suite: seal_signature_suite,
                    source,
                },
            )
    }

    /// Verify an export-safe chain whose signatures are algorithm-tagged.
    ///
    /// The current verifier accepts only Ed25519 envelopes. PQ signature suites
    /// are parsed and shape-checked, but return [`VerifyError::UnsupportedSignatureSuite`]
    /// until the ML-DSA/SLH-DSA verification backend lands.
    pub fn verify_exported_chain(
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), VerifyError> {
        for entry in entries {
            let suite = entry_signature_suite_for_verify(entry)?;
            if suite != SignatureSuite::Ed25519Rfc8032 {
                return Err(VerifyError::UnsupportedSignatureSuite {
                    seq: entry.seq,
                    signature_suite: suite,
                });
            }
        }

        Self::verify_exported_chain_with_backend(
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify an export-safe chain whose signatures are algorithm-tagged using
    /// an explicit signature backend and raw backend public key bytes.
    ///
    /// This keeps the legacy Ed25519 verifier stable while allowing full-PQC
    /// evidence verification to use ML-DSA backends under `pqc-signatures`.
    pub fn verify_exported_chain_with_backend(
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), VerifyError> {
        let mut expected_prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(VerifyError::OutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
                return Err(VerifyError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(VerifyError::BrokenLink { seq: entry.seq });
            }

            let recomputed =
                compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                    .map_err(|_| VerifyError::EntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(VerifyError::EntryHashMismatch { seq: entry.seq });
            }

            let suite = entry_signature_suite_for_verify(entry)?;
            if suite != backend.suite() {
                return Err(VerifyError::SignatureBackendSuiteMismatch {
                    seq: entry.seq,
                    entry_suite: suite,
                    backend_suite: backend.suite(),
                });
            }

            backend
                .verify_signature(public_key, &entry.entry_hash, &entry.signature.signature)
                .map_err(|err| backend_error_to_verify_error(entry.seq, suite, err))?;

            expected_prev = entry.entry_hash;
        }
        Ok(())
    }
}

fn entry_signature_suite_for_verify(
    entry: &LedgerEntryExport,
) -> Result<SignatureSuite, VerifyError> {
    entry
        .signature
        .validate_shape()
        .map_err(|err| signature_envelope_error_to_verify_error(entry.seq, err))
}

fn backend_error_to_verify_error(
    seq: u64,
    signature_suite: SignatureSuite,
    err: EvidenceSignatureBackendError,
) -> VerifyError {
    match err {
        EvidenceSignatureBackendError::BadPublicKeyLength { .. }
        | EvidenceSignatureBackendError::BadPublicKey => VerifyError::BadSignaturePublicKey {
            seq,
            signature_suite,
        },
        EvidenceSignatureBackendError::BadSignatureLength {
            expected, found, ..
        } => VerifyError::BadSignatureLength {
            seq,
            expected,
            found,
        },
        EvidenceSignatureBackendError::BadSignatureEncoding
        | EvidenceSignatureBackendError::BadSignature => VerifyError::BadSignature { seq },
    }
}

fn entry_signature_suite(
    entry: &LedgerEntryExport,
) -> Result<SignatureSuite, EvidenceBundleVerifyError> {
    entry.signature.validate_shape().map_err(|err| {
        EvidenceBundleVerifyError::ExportedChain(signature_envelope_error_to_verify_error(
            entry.seq, err,
        ))
    })
}

fn signature_envelope_error_to_verify_error(seq: u64, err: SignatureEnvelopeError) -> VerifyError {
    match err {
        SignatureEnvelopeError::UnknownSignatureSuite { algorithm } => {
            VerifyError::UnknownSignatureSuite { seq, algorithm }
        }
        SignatureEnvelopeError::BadSignatureLength {
            expected, found, ..
        } => VerifyError::BadSignatureLength {
            seq,
            expected,
            found,
        },
        SignatureEnvelopeError::UnsupportedLegacySuite { .. } => VerifyError::BadSignature { seq },
    }
}
