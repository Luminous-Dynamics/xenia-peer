// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! File-specific SIF disclosure binding.
//!
//! A generic committed release permit becomes authority for one exact outbound file
//! only when its minimum-necessary result commitment matches the canonical filename,
//! byte length and BLAKE3 content digest. The resulting tracker is move-only.
//!
//! Successful transport sends are accounted exactly. A carrier error is different:
//! ordinary stream/message transports do not promise an all-or-nothing network write,
//! so some prefix of the current sealed Chunk may already have left even when the send
//! future returns an error. [`CommittedFileDisclosure::note_transport_uncertain`] lets
//! the caller conservatively charge the full attempted file-content chunk. The numeric
//! `Partial.bytes_released` persisted by the existing release-journal schema is then an
//! upper bound rather than an understated exact count; [`FileDisclosureTerminal`] tells
//! local audit code which interpretation applies. A future journal schema can encode an
//! explicit min/max range without requiring this adapter to undercount today.

use thiserror::Error;
use uuid::Uuid;

use crate::disclosure_v2::{CommittedDisclosurePermit, DisclosureReleaseOutcome};

/// Canonical v1 file-result commitment profile.
pub const SIF_FILE_RESULT_PROFILE: &str = "xenia-sif-file-result-v1";

const SIF_FILE_RESULT_DOMAIN: &[u8] = b"xenia:sif-file-result:v1";

/// Compute the canonical result commitment for one outbound file disclosure.
///
/// The filename is the exact UTF-8 display name sent in the authenticated file
/// Offer, not a local source path. Length uses unsigned big-endian encoding.
pub fn sif_file_result_digest(
    display_name: &str,
    size: u64,
    content_blake3: [u8; 32],
) -> Result<[u8; 32], FileDisclosureError> {
    if display_name.is_empty() {
        return Err(FileDisclosureError::EmptyDisplayName);
    }
    let name = display_name.as_bytes();
    let name_len = u64::try_from(name.len()).map_err(|_| FileDisclosureError::NameTooLong)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(SIF_FILE_RESULT_DOMAIN);
    hasher.update(&[0]);
    hasher.update(SIF_FILE_RESULT_PROFILE.as_bytes());
    hasher.update(&[0]);
    hasher.update(&name_len.to_be_bytes());
    hasher.update(name);
    hasher.update(&size.to_be_bytes());
    hasher.update(&content_blake3);
    Ok(*hasher.finalize().as_bytes())
}

/// How to interpret a terminal file byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDisclosureByteAccounting {
    /// Every accounted byte was added only after a successful carrier send.
    Exact,
    /// At least one failed carrier send may have emitted an unknown prefix of the
    /// attempted Chunk. The persisted byte count conservatively includes that whole
    /// Chunk and is therefore an upper bound on file-content bytes that may have left.
    ConservativeUpperBound,
}

/// Move-only tracker for one already-committed file disclosure.
///
/// Construction consumes [`CommittedDisclosurePermit`], so the generic release token
/// cannot simultaneously authorize another output adapter. Call [`Self::note_emitted`]
/// only after the transport reports a chunk send as successful. If a Chunk send itself
/// fails ambiguously, call [`Self::note_transport_uncertain`] before consuming the
/// tracker with [`Self::interrupted`].
#[derive(Debug)]
pub struct CommittedFileDisclosure {
    permit: CommittedDisclosurePermit,
    expected_size: u64,
    accounted_bytes: u64,
    byte_accounting: FileDisclosureByteAccounting,
}

impl CommittedFileDisclosure {
    /// Bind a committed permit to exact authenticated file-offer metadata.
    pub fn new(
        permit: CommittedDisclosurePermit,
        display_name: &str,
        size: u64,
        content_blake3: [u8; 32],
    ) -> Result<Self, FileDisclosureError> {
        let expected = sif_file_result_digest(display_name, size, content_blake3)?;
        match permit.result_digest() {
            None => return Err(FileDisclosureError::MissingResultCommitment),
            Some(actual) if actual != expected => {
                return Err(FileDisclosureError::ResultCommitmentMismatch)
            }
            Some(_) => {}
        }
        Ok(Self {
            permit,
            expected_size: size,
            accounted_bytes: 0,
            byte_accounting: FileDisclosureByteAccounting::Exact,
        })
    }

    /// Release-journal identifier backing this file disclosure.
    pub const fn release_id(&self) -> Uuid {
        self.permit.release_id()
    }

    /// Signed release-journal Commit entry hash that created this output capability.
    ///
    /// This immutable commitment lets a protected wire Offer and later receiver
    /// delivery receipt join back to the exact durable authorization event without
    /// exposing any broader release-authority capability.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.permit.release_entry_hash()
    }

    /// Exact file length bound by the permit.
    pub const fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// File-content bytes currently charged to this release.
    ///
    /// When [`Self::byte_accounting`] is `Exact`, every byte was transport-confirmed.
    /// After an ambiguous carrier failure this is a conservative upper bound.
    pub const fn emitted_bytes(&self) -> u64 {
        self.accounted_bytes
    }

    /// Current interpretation of [`Self::emitted_bytes`].
    pub const fn byte_accounting(&self) -> FileDisclosureByteAccounting {
        self.byte_accounting
    }

    /// Record file-content bytes only after the transport send succeeds.
    pub fn note_emitted(&mut self, bytes: usize) -> Result<(), FileDisclosureError> {
        self.add_accounted_bytes(bytes)
    }

    /// Conservatively account one Chunk whose carrier send returned an error.
    ///
    /// Xenia cannot in general know whether the carrier wrote none, some, or all of
    /// that sealed envelope before failing. Charging the full attempted content chunk
    /// prevents the durable Partial outcome from understating possible disclosure.
    /// The session must still be treated as fatal after such a carrier error; this
    /// method is accounting, not permission to continue sending.
    pub fn note_transport_uncertain(&mut self, bytes: usize) -> Result<(), FileDisclosureError> {
        if bytes == 0 {
            return Err(FileDisclosureError::ZeroUncertainChunk);
        }
        self.add_accounted_bytes(bytes)?;
        self.byte_accounting = FileDisclosureByteAccounting::ConservativeUpperBound;
        Ok(())
    }

    fn add_accounted_bytes(&mut self, bytes: usize) -> Result<(), FileDisclosureError> {
        let bytes = u64::try_from(bytes).map_err(|_| FileDisclosureError::ByteCountOverflow)?;
        let accounted = self
            .accounted_bytes
            .checked_add(bytes)
            .ok_or(FileDisclosureError::ByteCountOverflow)?;
        if accounted > self.expected_size {
            return Err(FileDisclosureError::EmittedBeyondDeclaredSize {
                declared: self.expected_size,
                emitted: accounted,
            });
        }
        self.accounted_bytes = accounted;
        Ok(())
    }

    /// Consume the tracker after the source independently verified its final length
    /// and content hash and all protected file-content bytes were successfully sent.
    pub fn completed(self) -> Result<FileDisclosureTerminal, FileDisclosureError> {
        if self.byte_accounting != FileDisclosureByteAccounting::Exact {
            return Err(FileDisclosureError::CompletionAfterTransportUncertainty);
        }
        if self.accounted_bytes != self.expected_size {
            return Err(FileDisclosureError::IncompleteCompletion {
                expected: self.expected_size,
                emitted: self.accounted_bytes,
            });
        }
        Ok(FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome: DisclosureReleaseOutcome::Completed,
            byte_accounting: FileDisclosureByteAccounting::Exact,
        })
    }

    /// Consume the tracker when output stops before a verified complete send.
    ///
    /// Zero accounted file-content bytes maps to `Aborted`; otherwise the current
    /// count maps to `Partial`. Consult `byte_accounting` to distinguish an exact
    /// successful-prefix count from a conservative upper bound after carrier error.
    pub fn interrupted(self) -> FileDisclosureTerminal {
        let outcome = if self.accounted_bytes == 0 {
            DisclosureReleaseOutcome::Aborted
        } else {
            DisclosureReleaseOutcome::Partial {
                bytes_released: self.accounted_bytes,
            }
        };
        FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome,
            byte_accounting: self.byte_accounting,
        }
    }
}

/// Terminal journal observation produced by consuming a file-disclosure tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDisclosureTerminal {
    /// Release whose terminal outcome must be durably recorded.
    pub release_id: Uuid,
    /// Completed/Aborted/Partial release-journal outcome.
    pub outcome: DisclosureReleaseOutcome,
    /// Whether a Partial byte count is exact or a conservative upper bound.
    pub byte_accounting: FileDisclosureByteAccounting,
}

/// File-specific disclosure binding failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FileDisclosureError {
    /// Wire-visible filename is empty.
    #[error("SIF file disclosure display name must not be empty")]
    EmptyDisplayName,
    /// Filename length cannot be represented by the canonical profile.
    #[error("SIF file disclosure display name is too long")]
    NameTooLong,
    /// Committed permit has no result commitment.
    #[error("SIF file disclosure permit has no result commitment")]
    MissingResultCommitment,
    /// Permit result commitment is for different file metadata/content.
    #[error("SIF file disclosure result commitment does not match the outbound file")]
    ResultCommitmentMismatch,
    /// Byte accounting overflowed.
    #[error("SIF file disclosure byte counter overflow")]
    ByteCountOverflow,
    /// An ambiguous carrier send must correspond to a non-empty file-content Chunk.
    #[error("SIF file disclosure uncertain transport chunk must be non-empty")]
    ZeroUncertainChunk,
    /// Caller attempted to account more bytes than the committed file length.
    #[error("SIF file disclosure accounted {emitted} bytes beyond declared size {declared}")]
    EmittedBeyondDeclaredSize {
        /// Declared file size.
        declared: u64,
        /// Attempted release-accounted byte count.
        emitted: u64,
    },
    /// Completion cannot be claimed after an ambiguous carrier write.
    #[error("SIF file disclosure cannot claim completion after transport uncertainty")]
    CompletionAfterTransportUncertainty,
    /// Caller attempted to mark completion before all committed bytes were emitted.
    #[error("SIF file disclosure completion is incomplete: expected {expected}, emitted {emitted}")]
    IncompleteCompletion {
        /// Committed file length.
        expected: u64,
        /// Successfully emitted length.
        emitted: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_commitment_binds_name_size_and_content_hash() {
        let base = sif_file_result_digest("report.bin", 7, [1u8; 32]).unwrap();
        assert_ne!(
            base,
            sif_file_result_digest("other.bin", 7, [1u8; 32]).unwrap()
        );
        assert_ne!(
            base,
            sif_file_result_digest("report.bin", 8, [1u8; 32]).unwrap()
        );
        assert_ne!(
            base,
            sif_file_result_digest("report.bin", 7, [2u8; 32]).unwrap()
        );
    }

    #[test]
    fn empty_name_fails_closed() {
        assert_eq!(
            sif_file_result_digest("", 0, [1u8; 32]),
            Err(FileDisclosureError::EmptyDisplayName)
        );
    }

    #[test]
    fn uncertain_chunk_validation_is_fail_closed() {
        // The move-only tracker itself requires a real committed permit, which is
        // exercised by disclosure integration tests. Freeze the new local accounting
        // invariants here through their public error/enum semantics.
        assert_ne!(
            FileDisclosureByteAccounting::Exact,
            FileDisclosureByteAccounting::ConservativeUpperBound
        );
        assert_eq!(
            FileDisclosureError::ZeroUncertainChunk.to_string(),
            "SIF file disclosure uncertain transport chunk must be non-empty"
        );
        assert_eq!(
            FileDisclosureError::CompletionAfterTransportUncertainty.to_string(),
            "SIF file disclosure cannot claim completion after transport uncertainty"
        );
    }
}
