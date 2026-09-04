// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned source binding for high-assurance SIF protected-file output.
//!
//! [`SourceBoundFileOfferAuthority`] composes one exact durable/session/profile-bound
//! Offer authority with one already-opened [`TransferSource`]. Construction requires the
//! source's exact byte length and initial BLAKE3 to match the authority-derived Offer.
//! The source then remains private and move-only: application callers cannot extract a
//! byte buffer, replace the source, or construct an alternate Offer from this type.
//!
//! `TransferSource` itself provides the second half of the invariant: desktop files are
//! hashed and later streamed from the same open handle, while a second streaming hash and
//! exact-length check must succeed before end-of-source. The subsequent sender tranche
//! must consume this type and drive `TransferSource::next_chunk` internally; this module
//! alone does not yet remove the older caller-byte sender API.

use std::path::Path;

use thiserror::Error;
use xenia_ledger::{SessionBoundFileOfferAuthority, SifProtectedFileOffer};
use xenia_peer_core::{TransferSource, TransferSourceError};

/// Move-only composition of exact protected Offer authority and its only allowed source.
#[derive(Debug)]
pub struct SourceBoundFileOfferAuthority {
    authority: SessionBoundFileOfferAuthority,
    source: TransferSource,
}

impl SourceBoundFileOfferAuthority {
    /// Open/hash one bounded file and bind that same retained handle to the Offer authority.
    pub async fn open_file_limited(
        authority: SessionBoundFileOfferAuthority,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Self, SourceBoundFileAuthorityError> {
        let source = TransferSource::open_file_limited(path, max_bytes).await?;
        Self::from_source(authority, source)
    }

    /// Bind an already-prepared source to exact durable Offer authority.
    ///
    /// This supports staged/content-addressed sources while preserving the same exact
    /// size/hash invariant. The source is consumed and cannot be reused elsewhere.
    pub fn from_source(
        authority: SessionBoundFileOfferAuthority,
        source: TransferSource,
    ) -> Result<Self, SourceBoundFileAuthorityError> {
        validate_source_matches_offer(&source, authority.offer())?;
        Ok(Self { authority, source })
    }

    /// Exact authority-derived Offer metadata.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.authority.offer()
    }

    /// Exact committed source length.
    pub fn size(&self) -> u64 {
        self.source.size()
    }

    /// Exact initially committed source BLAKE3.
    pub fn content_blake3(&self) -> [u8; 32] {
        self.source.blake3_hash()
    }

    /// Consume into crate-private sender components.
    ///
    /// Kept crate-private so application callers cannot separate the authority from its
    /// byte source; only the high-assurance sender implementation may drive the source.
    pub(crate) fn into_parts(self) -> (SessionBoundFileOfferAuthority, TransferSource) {
        (self.authority, self.source)
    }
}

fn validate_source_matches_offer(
    source: &TransferSource,
    offer: &SifProtectedFileOffer,
) -> Result<(), SourceBoundFileAuthorityError> {
    if source.size() != offer.size() {
        return Err(SourceBoundFileAuthorityError::SizeMismatch {
            authorized: offer.size(),
            source: source.size(),
        });
    }
    if source.blake3_hash() != offer.content_blake3() {
        return Err(SourceBoundFileAuthorityError::HashMismatch);
    }
    Ok(())
}

/// Fail-closed source/authority composition failures.
#[derive(Debug, Error)]
pub enum SourceBoundFileAuthorityError {
    /// Source preparation or second-level file I/O failed.
    #[error(transparent)]
    Source(#[from] TransferSourceError),
    /// Prepared source length differs from durable Offer authority.
    #[error("protected source length mismatch: authorized {authorized}, source {source}")]
    SizeMismatch {
        /// Byte length committed by the authority-derived Offer.
        authorized: u64,
        /// Byte length observed by the prepared source.
        source: u64,
    },
    /// Prepared source digest differs from durable Offer authority.
    #[error("protected source BLAKE3 does not match durable Offer authority")]
    HashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{SifProtectedFileOffer, sif_file_result_digest};

    fn offer_for(payload: &[u8]) -> SifProtectedFileOffer {
        let hash = *blake3::hash(payload).as_bytes();
        let result = sif_file_result_digest("evidence.bin", payload.len() as u64, hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(1),
            7,
            [0x22; 32],
            result,
            "evidence.bin",
            payload.len() as u64,
            hash,
        )
        .unwrap()
    }

    #[test]
    fn same_bytes_source_matches_exact_offer() {
        let payload = b"exact-authorized-bytes";
        let offer = offer_for(payload);
        let source = TransferSource::from_memory(payload.to_vec());
        assert!(validate_source_matches_offer(&source, &offer).is_ok());
    }

    #[test]
    fn same_length_different_bytes_fail_hash_binding() {
        let offer = offer_for(b"AAAA");
        let source = TransferSource::from_memory(b"BBBB".to_vec());
        assert!(matches!(
            validate_source_matches_offer(&source, &offer),
            Err(SourceBoundFileAuthorityError::HashMismatch)
        ));
    }

    #[test]
    fn different_length_fails_before_hash_comparison() {
        let offer = offer_for(b"AAAA");
        let source = TransferSource::from_memory(b"AAA".to_vec());
        assert!(matches!(
            validate_source_matches_offer(&source, &offer),
            Err(SourceBoundFileAuthorityError::SizeMismatch {
                authorized: 4,
                source: 3,
            })
        ));
    }
}
