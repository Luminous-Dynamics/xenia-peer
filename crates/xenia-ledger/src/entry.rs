// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{
    Keypair as MlDsaKeypair, MlDsa65, MlDsa87, MlDsaParams, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey,
};

#[cfg(feature = "pqc-signatures")]
use crate::errors::LedgerError;
#[cfg(feature = "pqc-signatures")]
use crate::hash::compute_entry_hash;
use crate::signature::{
    CURRENT_LEDGER_SIGNATURE_SUITE, SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};

/// Compute Xenia's stable session transcript binding hash.
pub fn compute_session_transcript_hash(transcript_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(transcript_bytes).as_bytes()
}

/// Errors surfaced while validating a session transcript binding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TranscriptBindingError {
    /// The binding schema label is unknown to this verifier.
    #[error("unsupported transcript binding schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the binding.
        schema: String,
    },
    /// The transcript hash algorithm is unknown to this verifier.
    #[error("unsupported transcript hash algorithm: {algorithm}")]
    UnsupportedTranscriptHashAlgorithm {
        /// Hash algorithm label found in the binding.
        algorithm: String,
    },
    /// The binding used an all-zero transcript hash placeholder.
    #[error("transcript hash must not be the all-zero placeholder")]
    EmptyTranscriptHash,
    /// The binding's transcript signature suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript binding {binding_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the transcript binding.
        binding_suite: SignatureSuite,
    },
}

/// Errors surfaced while validating a session transcript signature artifact.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TranscriptSignatureError {
    /// The transcript signature schema label is unknown to this verifier.
    #[error("unsupported transcript signature schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the signature artifact.
        schema: String,
    },
    /// The transcript hash algorithm is unknown to this verifier.
    #[error("unsupported transcript signature hash algorithm: {algorithm}")]
    UnsupportedTranscriptHashAlgorithm {
        /// Hash algorithm label found in the signature artifact.
        algorithm: String,
    },
    /// The signature artifact used an all-zero transcript hash placeholder.
    #[error("transcript signature hash must not be the all-zero placeholder")]
    EmptyTranscriptHash,
    /// The signature artifact's session UUID did not match the binding.
    #[error(
        "transcript binding session {binding_session_id} does not match transcript signature session {signature_session_id}"
    )]
    BindingSessionMismatch {
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID declared by the transcript signature artifact.
        signature_session_id: Uuid,
    },
    /// The signature artifact's hash algorithm did not match the binding.
    #[error(
        "transcript binding hash algorithm {binding_algorithm} does not match transcript signature algorithm {signature_algorithm}"
    )]
    BindingHashAlgorithmMismatch {
        /// Hash algorithm declared by the transcript binding.
        binding_algorithm: String,
        /// Hash algorithm declared by the transcript signature artifact.
        signature_algorithm: String,
    },
    /// The signature artifact's transcript hash did not match the binding.
    #[error("transcript signature hash does not match transcript binding hash")]
    BindingHashMismatch,
    /// The signature envelope was malformed.
    #[error("transcript signature envelope rejected artifact: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// The signature artifact's suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript signature artifact {signature_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the transcript signature artifact.
        signature_suite: SignatureSuite,
    },
}

/// The kind of consent event recorded in the ledger. Mirrors the
/// state-transitions surfaced by `xenia-wire`'s consent state machine
/// (`Request` / `Response{approved: bool}` / `Revocation` /
/// `ConsentProtocolViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentKind {
    /// Admin / operator requested a privileged action on the user's machine.
    Request,
    /// User approved the request.
    Approval,
    /// User denied the request (explicit negative response).
    Denial,
    /// User revoked a previously-approved session mid-flight.
    Revocation,
    /// Protocol violation detected (e.g., a contradictory Response after a prior Revocation).
    Violation,
    /// Automated action triggered by Athena AI triage.
    AthenaTriage,
}

impl ConsentKind {
    /// Stable dot-namespaced audit event name for this consent event kind.
    ///
    /// These names are part of the operator/admin audit contract. They are
    /// intentionally decoupled from Rust enum variant spelling so UI labels,
    /// release evidence, and downstream audit consumers do not depend on
    /// `Debug` formatting.
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Request => "consent.requested",
            Self::Approval => "consent.granted",
            Self::Denial => "consent.denied",
            Self::Revocation => "consent.revoked",
            Self::Violation => "consent.protocol_violation",
            Self::AthenaTriage => "admin.athena_triage",
        }
    }
}

/// A single consent event. Carries enough context for an auditor to
/// reconstruct which session, which request, and which party was
/// involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentEventRecord {
    /// DID-bound source identifier of the operator requesting access
    /// (32 bytes; typically a hash of the Ed25519 verifying key, but
    /// any 32-byte opaque identifier is acceptable to this crate).
    pub source_id: [u8; 32],
    /// UUID of the Xenia session the event belongs to.
    pub session_id: Uuid,
    /// UUID of the specific consent request within the session.
    pub request_id: Uuid,
    /// Kind of event.
    pub kind: ConsentKind,
    /// Optional human-readable scope description (e.g.
    /// `"view screen, inject input on /dev/tty1"`). Audit trails
    /// benefit from this; verification does not depend on it.
    pub scope: String,
}

impl ConsentEventRecord {
    /// Stable dot-namespaced audit event name for this record.
    pub const fn stable_name(&self) -> &'static str {
        self.kind.stable_name()
    }
}

/// A signed, chained ledger entry. Every field is covered by
/// `entry_hash`; `signature` is the operator's Ed25519 signature over
/// `entry_hash`. Exported evidence should prefer [`LedgerEntryExport`] so the
/// signature carries an explicit algorithm label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the operator.
    pub timestamp: SystemTime,
    /// The consent event itself.
    pub event: ConsentEventRecord,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`. Covers
    /// every field except `signature` itself (which signs this hash).
    pub entry_hash: [u8; 32],
    /// Ed25519 signature over `entry_hash`, 64 bytes.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Export-safe ledger entry with an algorithm-tagged signature envelope.
///
/// This mirrors [`LedgerEntry`] but replaces the legacy fixed-size Ed25519
/// signature field with [`SignatureEnvelope`]. Use this shape for JSON/CBOR
/// evidence bundles and long-lived verifier fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryExport {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the operator.
    pub timestamp: SystemTime,
    /// The consent event itself.
    pub event: ConsentEventRecord,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`.
    pub entry_hash: [u8; 32],
    /// Algorithm-tagged signature over `entry_hash`.
    pub signature: SignatureEnvelope,
}

impl LedgerEntryExport {
    /// Convert a current legacy Ed25519 entry into an export-safe envelope entry.
    pub fn from_legacy_entry(entry: &LedgerEntry) -> Self {
        Self {
            seq: entry.seq,
            prev_hash: entry.prev_hash,
            timestamp: entry.timestamp,
            event: entry.event.clone(),
            entry_hash: entry.entry_hash,
            signature: entry.signature_envelope(),
        }
    }

    /// Convert an export entry back into the current legacy Ed25519 entry shape.
    pub fn to_legacy_entry(&self) -> Result<LedgerEntry, SignatureEnvelopeError> {
        Ok(LedgerEntry {
            seq: self.seq,
            prev_hash: self.prev_hash,
            timestamp: self.timestamp,
            event: self.event.clone(),
            entry_hash: self.entry_hash,
            signature: self.signature.to_legacy_ed25519()?,
        })
    }
}

impl LedgerEntry {
    /// Return the signature suite used by this legacy ledger entry.
    pub const fn signature_suite(&self) -> SignatureSuite {
        CURRENT_LEDGER_SIGNATURE_SUITE
    }

    /// Return an algorithm-tagged signature envelope for this entry.
    pub fn signature_envelope(&self) -> SignatureEnvelope {
        SignatureEnvelope::ed25519(self.signature)
    }

    /// Convert this entry into the export-safe signature-envelope shape.
    pub fn to_export_entry(&self) -> LedgerEntryExport {
        LedgerEntryExport::from_legacy_entry(self)
    }
}

/// Feature-gated exported-evidence chain signed with ML-DSA.
///
/// This type deliberately produces only [`LedgerEntryExport`] entries. It does
/// not pretend to be the stable Ed25519 [`crate::Chain`] runtime shape; it exists to
/// make the full-PQC evidence path real enough for fixtures, verifier tests,
/// and future runtime promotion behind explicit policy gates.
#[cfg(feature = "pqc-signatures")]
pub struct MlDsaEvidenceChain<P: MlDsaParams> {
    entries: Vec<LedgerEntryExport>,
    signing_key: MlDsaSigningKey<P>,
    suite: SignatureSuite,
}

#[cfg(feature = "pqc-signatures")]
impl<P: MlDsaParams> MlDsaEvidenceChain<P> {
    /// Create an empty ML-DSA exported-evidence chain.
    fn new(signing_key: MlDsaSigningKey<P>, suite: SignatureSuite) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
            suite,
        }
    }

    /// Return the number of entries in the exported-evidence chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the exported-evidence chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` before genesis.
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32])
    }

    /// Return the raw encoded ML-DSA verifying key bytes for this chain.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let encoded = self.signing_key.verifying_key().encode();
        std::convert::AsRef::<[u8]>::as_ref(&encoded).to_vec()
    }

    /// Iterate over all exported entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntryExport> {
        self.entries.iter()
    }

    /// Return a cloned exported-entry vector for persistence or evidence bundles.
    pub fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.entries.clone()
    }

    /// Append a consent event, computing the same hash-chain preimage as the
    /// default ledger but signing the resulting entry hash with ML-DSA.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntryExport, LedgerError> {
        let entry_index = self.entries.len();
        let seq = entry_index as u64;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).encode();
        let signature_bytes: &[u8] = signature.as_ref();

        self.entries.push(LedgerEntryExport {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature: SignatureEnvelope::new(self.suite, signature_bytes.to_vec()),
        });
        self.entries
            .get(entry_index)
            .ok_or(LedgerError::AppendInvariant)
    }
}

/// ML-DSA-65 exported-evidence chain builder.
#[cfg(feature = "pqc-signatures")]
pub type MlDsa65EvidenceChain = MlDsaEvidenceChain<MlDsa65>;

/// ML-DSA-87 exported-evidence chain builder.
#[cfg(feature = "pqc-signatures")]
pub type MlDsa87EvidenceChain = MlDsaEvidenceChain<MlDsa87>;

/// Create an empty ML-DSA-65 exported-evidence chain.
#[cfg(feature = "pqc-signatures")]
pub fn new_ml_dsa_65_evidence_chain(signing_key: MlDsaSigningKey<MlDsa65>) -> MlDsa65EvidenceChain {
    MlDsaEvidenceChain::new(signing_key, SignatureSuite::MlDsa65Fips204)
}

/// Create an empty ML-DSA-87 exported-evidence chain.
#[cfg(feature = "pqc-signatures")]
pub fn new_ml_dsa_87_evidence_chain(signing_key: MlDsaSigningKey<MlDsa87>) -> MlDsa87EvidenceChain {
    MlDsaEvidenceChain::new(signing_key, SignatureSuite::MlDsa87Fips204)
}
