// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! File-specific SIF disclosure binding.
//!
//! A generic committed release permit becomes authority for one exact outbound file
//! only when its minimum-necessary result commitment matches the canonical filename,
//! byte length and BLAKE3 content digest. The resulting tracker is move-only and
//! records only bytes whose transport send was reported successful by the caller.

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

/// Move-only tracker for one already-committed file disclosure.
///
/// Construction consumes [`CommittedDisclosurePermit`], so the generic release token
/// cannot simultaneously authorize another output adapter. Call [`Self::note_emitted`]
/// only after the transport reports a chunk send as successful.
#[derive(Debug)]
pub struct CommittedFileDisclosure {
    permit: CommittedDisclosurePermit,
    expected_size: u64,
    emitted_bytes: u64,
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
            emitted_bytes: 0,
        })
    }

    /// Release-journal identifier backing this file disclosure.
    pub const fn release_id(&self) -> Uuid {
        self.permit.release_id()
    }

    /// Exact file length bound by the permit.
    pub const fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Protected file bytes successfully emitted so far.
    pub const fn emitted_bytes(&self) -> u64 {
        self.emitted_bytes
    }

    /// Record bytes only after the transport send succeeds.
    pub fn note_emitted(&mut self, bytes: usize) -> Result<(), FileDisclosureError> {
        let bytes = u64::try_from(bytes).map_err(|_| FileDisclosureError::ByteCountOverflow)?;
        let emitted = self
            .emitted_bytes
            .checked_add(bytes)
            .ok_or(FileDisclosureError::ByteCountOverflow)?;
        if emitted > self.expected_size {
            return Err(FileDisclosureError::EmittedBeyondDeclaredSize {
                declared: self.expected_size,
                emitted,
            });
        }
        self.emitted_bytes = emitted;
        Ok(())
    }

    /// Consume the tracker after the source independently verified its final length
    /// and content hash and all protected bytes were successfully sent.
    pub fn completed(self) -> Result<FileDisclosureTerminal, FileDisclosureError> {
        if self.emitted_bytes != self.expected_size {
            return Err(FileDisclosureError::IncompleteCompletion {
                expected: self.expected_size,
                emitted: self.emitted_bytes,
            });
        }
        Ok(FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome: DisclosureReleaseOutcome::Completed,
        })
    }

    /// Consume the tracker when output stops before a verified complete send.
    ///
    /// Zero emitted bytes maps to `Aborted`; otherwise the exact successful byte
    /// count maps to `Partial`.
    pub fn interrupted(self) -> FileDisclosureTerminal {
        let outcome = if self.emitted_bytes == 0 {
            DisclosureReleaseOutcome::Aborted
        } else {
            DisclosureReleaseOutcome::Partial {
                bytes_released: self.emitted_bytes,
            }
        };
        FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome,
        }
    }
}

/// Terminal journal observation produced by consuming a file-disclosure tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDisclosureTerminal {
    /// Release whose terminal outcome must be durably recorded.
    pub release_id: Uuid,
    /// Exact Completed/Aborted/Partial outcome.
    pub outcome: DisclosureReleaseOutcome,
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
    /// Successful byte accounting overflowed.
    #[error("SIF file disclosure byte counter overflow")]
    ByteCountOverflow,
    /// Caller attempted to account more bytes than the committed file length.
    #[error("SIF file disclosure emitted {emitted} bytes beyond declared size {declared}")]
    EmittedBeyondDeclaredSize {
        /// Declared file size.
        declared: u64,
        /// Attempted successful emitted byte count.
        emitted: u64,
    },
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
}
