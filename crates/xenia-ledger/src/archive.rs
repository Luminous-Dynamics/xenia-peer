// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifiable bounded archive segments for consent-ledger retention.
//!
//! An archive segment commits to a signed base checkpoint, every intervening
//! signed entry, and a signed terminal checkpoint. It is suitable for moving
//! older evidence to colder storage while retaining independently verifiable
//! append-only continuity. This module intentionally does not truncate a live
//! daemon ledger: online compaction additionally needs replay indexes and
//! recovery summaries for old action IDs and grants.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Chain, CheckpointContinuityError, LedgerCheckpoint, LedgerEntry, Verifier,
    checkpoint_fingerprint,
};

/// Stable schema label for [`LedgerArchiveSegment`].
pub const LEDGER_ARCHIVE_SEGMENT_SCHEMA: &str = "xenia-ledger-archive-segment-v1";

/// Maximum entries carried in one archive segment.
pub const MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES: usize = 4_096;

/// A self-contained, append-only proof between two signed checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerArchiveSegment {
    /// Must equal [`LEDGER_ARCHIVE_SEGMENT_SCHEMA`].
    pub schema: String,
    /// Signed checkpoint immediately before `entries`.
    pub base_checkpoint: LedgerCheckpoint,
    /// Every signed entry after `base_checkpoint` through
    /// `terminal_checkpoint`.
    pub entries: Vec<LedgerEntry>,
    /// Signed checkpoint at the segment's terminal head.
    pub terminal_checkpoint: LedgerCheckpoint,
    /// BLAKE3 commitment to both exact checkpoints and every entry hash.
    pub segment_digest: [u8; 32],
}

/// Compute the stable archive-segment commitment.
pub fn ledger_archive_segment_digest(
    base_checkpoint: &LedgerCheckpoint,
    entries: &[LedgerEntry],
    terminal_checkpoint: &LedgerCheckpoint,
) -> Result<[u8; 32], LedgerArchiveError> {
    let base = checkpoint_fingerprint(base_checkpoint)?;
    let terminal = checkpoint_fingerprint(terminal_checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:ledger-archive-segment:v1");
    hasher.update(&[0]);
    hasher.update(LEDGER_ARCHIVE_SEGMENT_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(&base);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.seq.to_be_bytes());
        hasher.update(&entry.entry_hash);
        hasher.update(&entry.signature);
    }
    hasher.update(&terminal);
    Ok(*hasher.finalize().as_bytes())
}

impl LedgerArchiveSegment {
    /// Export one bounded suffix of `chain` beginning immediately after
    /// `base_checkpoint` and ending at the chain's current head.
    pub fn from_chain(
        chain: &Chain,
        base_checkpoint: LedgerCheckpoint,
        terminal_timestamp_unix_secs: u64,
    ) -> Result<Self, LedgerArchiveError> {
        let public_key = VerifyingKey::from_bytes(&base_checkpoint.ledger_public_key)
            .map_err(|_| LedgerArchiveError::BadLedgerPublicKey)?;
        let all_entries = chain.iter().cloned().collect::<Vec<_>>();
        Verifier::verify_checkpoint_prefix(&base_checkpoint, &all_entries, &public_key)?;
        let start = usize::try_from(base_checkpoint.entry_count)
            .map_err(|_| LedgerArchiveError::EntryCountOverflow)?;
        let entries = all_entries[start..].to_vec();
        if entries.len() > MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES {
            return Err(LedgerArchiveError::TooManyEntries {
                count: entries.len(),
                maximum: MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES,
            });
        }
        let terminal_checkpoint = chain.sign_checkpoint(terminal_timestamp_unix_secs);
        Verifier::verify_checkpoint_extension(
            &base_checkpoint,
            &terminal_checkpoint,
            &entries,
        )?;
        let segment_digest = ledger_archive_segment_digest(
            &base_checkpoint,
            &entries,
            &terminal_checkpoint,
        )?;
        Ok(Self {
            schema: LEDGER_ARCHIVE_SEGMENT_SCHEMA.to_string(),
            base_checkpoint,
            entries,
            terminal_checkpoint,
            segment_digest,
        })
    }
}

/// Why an archive segment was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerArchiveError {
    /// The archive schema is unknown.
    #[error("unsupported ledger archive segment schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the archive.
        schema: String,
    },
    /// The ledger key embedded in a checkpoint was malformed.
    #[error("archive segment ledger public key is malformed")]
    BadLedgerPublicKey,
    /// A checkpoint count could not fit in the local address space.
    #[error("archive segment checkpoint entry count overflow")]
    EntryCountOverflow,
    /// The requested archive exceeded the explicit per-segment bound.
    #[error("archive segment has {count} entries; maximum is {maximum}")]
    TooManyEntries {
        /// Requested entry count.
        count: usize,
        /// Maximum supported count.
        maximum: usize,
    },
    /// Signed checkpoint/entry continuity failed.
    #[error("archive segment continuity failure: {0}")]
    Continuity(#[from] CheckpointContinuityError),
    /// Checkpoint fingerprinting failed.
    #[error("archive segment checkpoint failure: {0}")]
    Checkpoint(#[from] crate::CheckpointError),
    /// The stored segment commitment did not recompute.
    #[error("archive segment digest mismatch")]
    DigestMismatch,
}

impl Verifier {
    /// Verify the schema, exact segment digest, and every signed entry between
    /// the two checkpoints.
    pub fn verify_ledger_archive_segment(
        segment: &LedgerArchiveSegment,
    ) -> Result<(), LedgerArchiveError> {
        if segment.schema != LEDGER_ARCHIVE_SEGMENT_SCHEMA {
            return Err(LedgerArchiveError::UnsupportedSchema {
                schema: segment.schema.clone(),
            });
        }
        if segment.entries.len() > MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES {
            return Err(LedgerArchiveError::TooManyEntries {
                count: segment.entries.len(),
                maximum: MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES,
            });
        }
        Verifier::verify_checkpoint_extension(
            &segment.base_checkpoint,
            &segment.terminal_checkpoint,
            &segment.entries,
        )?;
        let observed = ledger_archive_segment_digest(
            &segment.base_checkpoint,
            &segment.entries,
            &segment.terminal_checkpoint,
        )?;
        if observed != segment.segment_digest {
            return Err(LedgerArchiveError::DigestMismatch);
        }
        Ok(())
    }

    /// Verify that ordered archive segments form one continuous sequence.
    pub fn verify_ledger_archive_sequence(
        segments: &[LedgerArchiveSegment],
    ) -> Result<(), LedgerArchiveError> {
        for segment in segments {
            Self::verify_ledger_archive_segment(segment)?;
        }
        for pair in segments.windows(2) {
            if pair[0].terminal_checkpoint != pair[1].base_checkpoint {
                return Err(LedgerArchiveError::DigestMismatch);
            }
        }
        Ok(())
    }
}
