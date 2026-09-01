// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sovereign Intelligence Fabric (SIF) provenance adapter.
//!
//! This module intentionally contains no law-enforcement or surveillance policy.
//! It exposes a stable commitment to already-authenticated Xenia session/consent
//! provenance so an external accountability system (for example Mycelix SIF) can
//! bind a person-linked query receipt to the Xenia session that carried it.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{ConsentKind, LedgerEntry, SessionTranscriptBinding};

/// Stable schema for Xenia's SIF session-provenance commitment.
pub const SIF_SESSION_PROVENANCE_SCHEMA: &str = "xenia-sif-session-provenance-v1";

/// Cross-stack kind name consumed by SIF's generic provenance binding.
pub const SIF_PROVENANCE_KIND: &str = "xenia/session-provenance";

/// Cross-stack schema version consumed by SIF's generic provenance binding.
pub const SIF_PROVENANCE_VERSION: u16 = 1;

/// Stable, dependency-free export matching the semantic fields expected by a SIF
/// provenance adapter without depending on Mycelix protocol crates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProvenanceExport {
    /// Namespaced producer kind.
    pub kind: String,
    /// Producer schema version.
    pub version: u16,
    /// BLAKE3 commitment to the Xenia provenance record.
    pub digest: [u8; 32],
    /// Optional caller-supplied authorization/revocation epoch.
    pub authorization_epoch: Option<u64>,
}

/// Xenia data committed into a SIF subject-access receipt.
///
/// The raw handshake transcript and full ledger entry stay outside this object.
/// Their cryptographic hashes are enough to bind the external receipt back to the
/// independently verifiable Xenia evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifSessionProvenanceBinding {
    /// Stable schema label.
    pub schema: String,
    /// Xenia session identifier.
    pub session_id: Uuid,
    /// Consent request identifier inside the session.
    pub request_id: Uuid,
    /// DID/key-derived opaque source identifier from the consent ledger event.
    pub source_id: [u8; 32],
    /// Consent event that authorizes or records the relevant access operation.
    pub consent_kind: ConsentKind,
    /// Signed/hash-chained ledger entry hash covering the consent event.
    pub ledger_entry_hash: [u8; 32],
    /// Hash of the canonical authenticated session transcript.
    pub transcript_hash: [u8; 32],
    /// Optional external authorization/revocation epoch current for this action.
    pub authorization_epoch: Option<u64>,
}

impl SifSessionProvenanceBinding {
    /// Build a SIF provenance binding from an existing Xenia ledger entry and
    /// session-transcript binding.
    ///
    /// This constructor does not re-verify signatures. The normal Xenia evidence
    /// verification path remains authoritative for that. It does require both
    /// artifacts to name the same session and rejects placeholder hashes.
    pub fn from_ledger_entry(
        entry: &LedgerEntry,
        transcript: &SessionTranscriptBinding,
        authorization_epoch: Option<u64>,
    ) -> Result<Self, SifProvenanceError> {
        if entry.event.session_id != transcript.session_id {
            return Err(SifProvenanceError::SessionMismatch {
                ledger_session_id: entry.event.session_id,
                transcript_session_id: transcript.session_id,
            });
        }

        let binding = Self {
            schema: SIF_SESSION_PROVENANCE_SCHEMA.to_string(),
            session_id: entry.event.session_id,
            request_id: entry.event.request_id,
            source_id: entry.event.source_id,
            consent_kind: entry.event.kind,
            ledger_entry_hash: entry.entry_hash,
            transcript_hash: transcript.transcript_hash,
            authorization_epoch,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate structural invariants before exporting a cross-stack commitment.
    pub fn validate(&self) -> Result<(), SifProvenanceError> {
        if self.schema != SIF_SESSION_PROVENANCE_SCHEMA {
            return Err(SifProvenanceError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.source_id == [0; 32] {
            return Err(SifProvenanceError::EmptySourceId);
        }
        if self.ledger_entry_hash == [0; 32] {
            return Err(SifProvenanceError::EmptyLedgerEntryHash);
        }
        if self.transcript_hash == [0; 32] {
            return Err(SifProvenanceError::EmptyTranscriptHash);
        }
        Ok(())
    }

    /// Domain-separated message committed for SIF interoperability.
    pub fn commitment_message(&self) -> Result<Vec<u8>, SifProvenanceError> {
        self.validate()?;

        let consent_name = self.consent_kind.stable_name().as_bytes();
        let mut message = Vec::with_capacity(256);
        push_bytes(&mut message, b"xenia:sif-session-provenance:v1");
        push_bytes(&mut message, self.schema.as_bytes());
        message.extend_from_slice(self.session_id.as_bytes());
        message.extend_from_slice(self.request_id.as_bytes());
        message.extend_from_slice(&self.source_id);
        push_bytes(&mut message, consent_name);
        message.extend_from_slice(&self.ledger_entry_hash);
        message.extend_from_slice(&self.transcript_hash);
        match self.authorization_epoch {
            Some(epoch) => {
                message.push(1);
                message.extend_from_slice(&epoch.to_le_bytes());
            }
            None => message.push(0),
        }
        Ok(message)
    }

    /// BLAKE3-256 digest inserted into a SIF `ProvenanceBinding`.
    pub fn commitment(&self) -> Result<[u8; 32], SifProvenanceError> {
        Ok(*blake3::hash(&self.commitment_message()?).as_bytes())
    }

    /// Export only the generic fields needed by a cross-stack SIF adapter.
    pub fn export(&self) -> Result<SifProvenanceExport, SifProvenanceError> {
        Ok(SifProvenanceExport {
            kind: SIF_PROVENANCE_KIND.to_string(),
            version: SIF_PROVENANCE_VERSION,
            digest: self.commitment()?,
            authorization_epoch: self.authorization_epoch,
        })
    }
}

/// Structural errors in the SIF provenance adapter.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SifProvenanceError {
    /// Unknown binding schema.
    #[error("unsupported SIF provenance schema: {schema}")]
    UnsupportedSchema {
        /// Schema found on the binding.
        schema: String,
    },
    /// Ledger and transcript artifacts refer to different sessions.
    #[error(
        "ledger session {ledger_session_id} does not match transcript session {transcript_session_id}"
    )]
    SessionMismatch {
        /// Session from the ledger event.
        ledger_session_id: Uuid,
        /// Session from the transcript binding.
        transcript_session_id: Uuid,
    },
    /// The opaque source/operator identifier was a placeholder.
    #[error("SIF provenance source_id must not be all-zero")]
    EmptySourceId,
    /// The ledger entry hash was a placeholder.
    #[error("SIF provenance ledger entry hash must not be all-zero")]
    EmptyLedgerEntryHash,
    /// The session transcript hash was a placeholder.
    #[error("SIF provenance transcript hash must not be all-zero")]
    EmptyTranscriptHash,
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SifSessionProvenanceBinding {
        SifSessionProvenanceBinding {
            schema: SIF_SESSION_PROVENANCE_SCHEMA.to_string(),
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            source_id: [3; 32],
            consent_kind: ConsentKind::Approval,
            ledger_entry_hash: [4; 32],
            transcript_hash: [5; 32],
            authorization_epoch: Some(7),
        }
    }

    #[test]
    fn export_has_stable_cross_stack_shape() {
        let binding = binding();
        let export = binding.export().unwrap();
        assert_eq!(export.kind, SIF_PROVENANCE_KIND);
        assert_eq!(export.version, SIF_PROVENANCE_VERSION);
        assert_eq!(export.authorization_epoch, Some(7));
        assert_ne!(export.digest, [0; 32]);
    }

    #[test]
    fn commitment_binds_consent_semantics() {
        let approved = binding();
        let mut revoked = approved.clone();
        revoked.consent_kind = ConsentKind::Revocation;
        assert_ne!(approved.commitment().unwrap(), revoked.commitment().unwrap());
    }

    #[test]
    fn commitment_binds_authorization_epoch() {
        let current = binding();
        let mut newer_epoch = current.clone();
        newer_epoch.authorization_epoch = Some(8);
        assert_ne!(
            current.commitment().unwrap(),
            newer_epoch.commitment().unwrap()
        );
    }

    #[test]
    fn placeholders_are_rejected() {
        let mut value = binding();
        value.ledger_entry_hash = [0; 32];
        assert_eq!(
            value.commitment().unwrap_err(),
            SifProvenanceError::EmptyLedgerEntryHash
        );

        let mut value = binding();
        value.transcript_hash = [0; 32];
        assert_eq!(
            value.commitment().unwrap_err(),
            SifProvenanceError::EmptyTranscriptHash
        );
    }
}
