// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;
use uuid::Uuid;

use crate::binding::EvidencePublicKeyBindingError;
use crate::entry::{TranscriptBindingError, TranscriptSignatureError};
use crate::policy::EvidencePolicyError;
use crate::seal::EvidenceBundleSealError;
use crate::signature::{EvidenceSignatureBackendError, SignatureSuite};

/// Errors surfaced by [`crate::Chain`] operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Serialization of an entry's pre-hash payload failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),

    /// An entry was pushed but could not be read back from the chain.
    #[error("ledger append invariant failed: pushed entry missing")]
    AppendInvariant,
}

/// Why [`crate::Chain::append_transactional`] failed to commit an entry.
#[derive(Debug, Error)]
pub enum TransactionalAppendError<E> {
    /// The append itself failed (see [`LedgerError`]) -- persistence was
    /// never attempted.
    #[error("ledger append failed: {0}")]
    Ledger(LedgerError),
    /// The append succeeded in memory but `persist` failed; the entry was
    /// rolled back and the chain is exactly as it was before this call.
    #[error("ledger entry could not be durably persisted: {0}")]
    Persist(E),
}

/// Errors surfaced by [`crate::Verifier`] operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Chain was empty where at least one entry was required.
    #[error("chain is empty")]
    Empty,
    /// A sequence number was out of order (gaps, duplicates, reversal).
    #[error("sequence at index {index}: expected {expected}, found {found}")]
    OutOfOrder {
        /// Position in the slice where the bad sequence number was found.
        index: usize,
        /// The sequence number this entry should have had.
        expected: u64,
        /// The sequence number it actually had.
        found: u64,
    },
    /// An entry's `prev_hash` did not match the prior entry's `entry_hash`.
    #[error("broken hash link at seq {seq}")]
    BrokenLink {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's `entry_hash` does not match a freshly-computed hash over its fields.
    #[error("entry_hash mismatch at seq {seq} — tampering detected")]
    EntryHashMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's signature failed to verify under the provided public key.
    #[error("signature invalid at seq {seq}")]
    BadSignature {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// The current verifier does not support the envelope's signature suite.
    #[error("unsupported signature suite {signature_suite:?} at seq {seq}")]
    UnsupportedSignatureSuite {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the envelope.
        signature_suite: SignatureSuite,
    },
    /// The envelope declared a signature-suite label unknown to this verifier.
    #[error("unknown signature suite {algorithm} at seq {seq}")]
    UnknownSignatureSuite {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Unknown signature-suite label declared by the envelope.
        algorithm: String,
    },
    /// The envelope's signature bytes had an invalid length for the declared suite.
    #[error("bad signature length at seq {seq}: expected {expected}, found {found}")]
    BadSignatureLength {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length in bytes.
        found: usize,
    },
    /// The provided public key was rejected by the selected signature backend.
    #[error("signature public key rejected for {signature_suite:?} at seq {seq}")]
    BadSignaturePublicKey {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite selected for verification.
        signature_suite: SignatureSuite,
    },
    /// The selected backend does not match the entry's signature suite.
    #[error(
        "signature backend {backend_suite:?} does not match entry envelope {entry_suite:?} at seq {seq}"
    )]
    SignatureBackendSuiteMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the entry signature envelope.
        entry_suite: SignatureSuite,
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
    },
    /// The genesis entry's `prev_hash` was not all zeros.
    #[error("genesis prev_hash must be all zeros")]
    BadGenesis,
}

/// Errors surfaced when verifying an evidence manifest together with its exported chain.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceBundleVerifyError {
    /// The evidence manifest did not satisfy its declared policy.
    #[error("evidence manifest policy rejected artifact: {0}")]
    ManifestPolicy(#[from] EvidencePolicyError),
    /// The session transcript binding failed validation.
    #[error("session transcript binding rejected artifact: {0}")]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// A full-PQC transcript-bound verifier was called without a transcript signature artifact.
    #[error(
        "full-pqc-v1 transcript-bound evidence requires an explicit transcript signature artifact"
    )]
    MissingTranscriptSignatureInFullPqc,
    /// The session transcript signature artifact failed validation.
    #[error("session transcript signature rejected artifact: {0}")]
    TranscriptSignature(#[from] TranscriptSignatureError),
    /// The selected transcript signature backend does not satisfy the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript verifier backend {backend_suite:?}"
    )]
    TranscriptBackendSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite handled by the selected transcript verifier backend.
        backend_suite: SignatureSuite,
    },
    /// The transcript signature failed backend verification.
    #[error("transcript signature verification failed for {signature_suite:?}: {source}")]
    TranscriptSignatureBackend {
        /// Signature suite selected for transcript verification.
        signature_suite: SignatureSuite,
        /// Backend verification error.
        source: EvidenceSignatureBackendError,
    },
    /// The evidence-bundle seal failed validation.
    #[error("evidence-bundle seal rejected artifact: {0}")]
    BundleSeal(#[from] EvidenceBundleSealError),
    /// The bundle seal signature failed backend verification.
    #[error("bundle seal signature verification failed for {signature_suite:?}: {source}")]
    BundleSealSignatureBackend {
        /// Signature suite selected for bundle-seal verification.
        signature_suite: SignatureSuite,
        /// Backend verification error.
        source: EvidenceSignatureBackendError,
    },
    /// The public-key binding failed validation.
    #[error("evidence public-key binding rejected artifact: {0}")]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),
    /// A transcript-bound evidence bundle had no ledger entries to bind.
    #[error("transcript-bound evidence bundle must contain at least one ledger entry")]
    EmptyTranscriptBoundBundle,
    /// A ledger entry belongs to a different session than the transcript binding.
    #[error(
        "transcript binding session {binding_session_id} does not match entry session {entry_session_id} at seq {seq}"
    )]
    TranscriptSessionMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID carried by the ledger entry.
        entry_session_id: Uuid,
    },
    /// The exported chain failed structural, hash-link, or signature verification.
    #[error("exported chain verification failed: {0}")]
    ExportedChain(#[from] VerifyError),
    /// The selected signature backend does not satisfy the manifest's ledger signature suite.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match verifier backend {backend_suite:?}"
    )]
    LedgerBackendSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
    },
    /// The manifest's ledger signature suite did not match an entry signature envelope.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match entry envelope {entry_suite:?} at seq {seq}"
    )]
    LedgerSignatureSuiteMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the entry signature envelope.
        entry_suite: SignatureSuite,
    },
}
