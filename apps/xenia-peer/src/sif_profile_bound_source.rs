// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-assurance outbound source ownership for SIF protected files.
//!
//! This adapter composes three independently reviewed boundaries:
//! - [`xenia_ledger::ProfileBoundFileOfferAuthority`] proves one exact durable
//!   release/profile/file Offer;
//! - [`xenia_peer_core::TransferSource`] owns the exact source handle, performs the
//!   initial size/BLAKE3 commitment, and re-verifies length/BLAKE3 while streaming;
//! - [`xenia_ledger::SifProtectedFileSendState`] persists one exact Chunk identity
//!   before that Chunk may be exposed to a carrier.
//!
//! The adapter never accepts caller-authored content bytes. It reads Chunks only from
//! the owned [`TransferSource`], retains an exact candidate across transient CAS
//! failures, and exposes a Chunk only after the write-ahead `Prepared` transition is
//! durable. Carrier confirmation is separately persisted and is safely retryable after
//! a store failure because the exact prepared identity remains resident.
//!
//! This is an additive high-assurance path. The older accountable transfer API remains
//! available for compatibility and is not made equivalent to this stronger source-
//! owning contract by this module alone.

use thiserror::Error;
use xenia_ledger::{
    Chain, FileDisclosureTerminal, PreparedSifProtectedFileChunk,
    ProfileBoundCommittedFileDisclosure, ProfileBoundFileDisclosureError,
    ProfileBoundFileOfferAuthority, SifProtectedFileChunk, SifProtectedFileConfirmDisposition,
    SifProtectedFilePrepareDisposition, SifProtectedFileProtocolError, SifProtectedFileSendError,
    SifProtectedFileSendFrontier, SifProtectedFileSendState, SifProtectedFileSendStore,
    TransactionalSifProtectedFileSendError,
};
use xenia_peer_core::{TransferSource, TransferSourceError};

use crate::sif_accountable_transfer::ReadyAccountableSifSession;

/// Result of attempting to make the next exact source Chunk durably sendable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileBoundSourcePrepareDisposition {
    /// One exact source Chunk is durably prepared and may be sealed/sent.
    ChunkReady(SifProtectedFilePrepareDisposition),
    /// The owned source reached EOF and its second-pass length/BLAKE3 verification passed.
    EndOfSource,
}

/// Terminal disclosure observation produced by consuming the source-owning adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileBoundSourceTerminal {
    /// Existing release-journal terminal observation.
    pub file_terminal: FileDisclosureTerminal,
    /// Unique content bytes durably prepared before carrier I/O.
    pub possibly_disclosed_unique_bytes: u64,
    /// Unique content bytes whose carrier success is durably confirmed.
    pub confirmed_unique_bytes: u64,
}

/// Source/authority/lifecycle failure independent of a concrete CAS store error.
#[derive(Debug, Error)]
pub enum ProfileBoundOwnedSourceError {
    /// The actual authenticated SIF session negotiated a different profile.
    #[error("profile-bound source does not match the authenticated negotiated SIF profile")]
    NegotiatedProfileMismatch,
    /// The owned source length differs from the authority-derived Offer.
    #[error("profile-bound source length mismatch: Offer {offer_size}, source {source_size}")]
    SourceSizeMismatch {
        /// Exact size committed by the authority-derived Offer.
        offer_size: u64,
        /// Size reported by the owned source.
        source_size: u64,
    },
    /// The owned source BLAKE3 differs from the authority-derived Offer.
    #[error("profile-bound source BLAKE3 does not match the authority-derived Offer")]
    SourceHashMismatch,
    /// Caller attempted to prepare another Chunk while one durable Chunk is outstanding.
    #[error("profile-bound source already has a durably prepared Chunk outstanding")]
    PreparedChunkOutstanding,
    /// Caller attempted carrier confirmation/uncertainty without a prepared Chunk.
    #[error("profile-bound source has no durably prepared Chunk")]
    NoPreparedChunk,
    /// Completion was requested before the owned source reached verified EOF.
    #[error("profile-bound source has not reached verified end-of-source")]
    SourceNotExhausted,
    /// Completion frontiers do not equal the exact committed file length.
    #[error(
        "profile-bound source cannot complete: possible={possible}, confirmed={confirmed}, expected={expected}"
    )]
    IncompleteSendFrontiers {
        /// Write-ahead possible-disclosure frontier.
        possible: u64,
        /// Durable carrier-confirmed frontier.
        confirmed: u64,
        /// Exact authorized file length.
        expected: u64,
    },
    /// Owned source streaming or second-pass verification failed.
    #[error(transparent)]
    Source(#[from] TransferSourceError),
    /// Authority/file-accounting invariant failed.
    #[error(transparent)]
    File(#[from] ProfileBoundFileDisclosureError),
    /// Protected-file semantic construction failed.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Persisted send-journal semantic verification failed.
    #[error(transparent)]
    SendJournal(#[from] SifProtectedFileSendError),
}

/// Error while a source-owning transition also depends on an atomic CAS store.
#[derive(Debug)]
pub enum ProfileBoundSourceTransactionError<E> {
    /// Source/profile/semantic lifecycle failed before or around persistence.
    Protocol(ProfileBoundOwnedSourceError),
    /// The underlying signed write-ahead journal transition failed.
    Journal(TransactionalSifProtectedFileSendError<E>),
}

impl<E> From<ProfileBoundOwnedSourceError> for ProfileBoundSourceTransactionError<E> {
    fn from(value: ProfileBoundOwnedSourceError) -> Self {
        Self::Protocol(value)
    }
}

/// Move-only exact source + durable send-journal authority for one protected Offer.
///
/// A source Chunk is never externally reachable from this type until the matching
/// `Prepared` entry has been persisted successfully. A transient persistence failure
/// keeps an exact cloned candidate in memory so the next call retries the same bytes
/// without advancing the source a second time.
#[derive(Debug)]
pub struct ProfileBoundOwnedSource {
    offer: xenia_ledger::SifProtectedFileOffer,
    file: ProfileBoundCommittedFileDisclosure,
    source: TransferSource,
    send: SifProtectedFileSendState,
    candidate: Option<SifProtectedFileChunk>,
    prepared: Option<PreparedSifProtectedFileChunk>,
    source_exhausted: bool,
}

impl ProfileBoundOwnedSource {
    /// Consume exact release/file authority and one owned outbound source.
    ///
    /// The actual negotiated profile is read from `session`; callers do not provide a
    /// free profile digest. Source size/hash must also reproduce the authority-derived
    /// Offer before any write-ahead journal exists.
    pub fn new(
        authority: ProfileBoundFileOfferAuthority,
        source: TransferSource,
        session: &ReadyAccountableSifSession,
        chain: &Chain,
    ) -> Result<Self, ProfileBoundOwnedSourceError> {
        let (offer, file) = authority.into_parts();
        if session.profile_digest() != file.required_sif_profile_digest() {
            return Err(ProfileBoundOwnedSourceError::NegotiatedProfileMismatch);
        }
        if source.size() != offer.size() {
            return Err(ProfileBoundOwnedSourceError::SourceSizeMismatch {
                offer_size: offer.size(),
                source_size: source.size(),
            });
        }
        if source.blake3_hash() != offer.content_blake3() {
            return Err(ProfileBoundOwnedSourceError::SourceHashMismatch);
        }
        let send = SifProtectedFileSendState::new(offer.clone(), chain)?;
        Ok(Self {
            offer,
            file,
            source,
            send,
            candidate: None,
            prepared: None,
            source_exhausted: false,
        })
    }

    /// Exact authority-derived protected Offer.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        &self.offer
    }

    /// Current signed write-ahead send-journal frontier.
    pub fn send_frontier(&self) -> SifProtectedFileSendFrontier {
        self.send.frontier()
    }

    /// Unique bytes durably prepared before carrier I/O.
    pub fn possibly_disclosed_unique_bytes(&self) -> Result<u64, ProfileBoundOwnedSourceError> {
        Ok(self.send.possibly_disclosed_unique_bytes()?)
    }

    /// Unique bytes whose carrier success is durably confirmed.
    pub fn confirmed_unique_bytes(&self) -> Result<u64, ProfileBoundOwnedSourceError> {
        Ok(self.send.confirmed_unique_bytes()?)
    }

    /// Exact durably prepared Chunk currently permitted to reach a carrier.
    ///
    /// `None` means either no Chunk has been prepared yet or the previous Chunk was
    /// durably carrier-confirmed. The returned semantic object is source-generated.
    pub fn prepared_chunk(&self) -> Option<&SifProtectedFileChunk> {
        self.prepared.as_ref().map(PreparedSifProtectedFileChunk::chunk)
    }

    /// Stable retry identity for the currently prepared Chunk.
    pub fn prepared_idempotency_token(&self) -> Option<[u8; 32]> {
        self.prepared
            .as_ref()
            .map(PreparedSifProtectedFileChunk::idempotency_token)
    }

    /// Read and durably prepare the next exact source Chunk.
    ///
    /// The method does not return the bytes. After success the caller retrieves the
    /// exact durably-authorized semantic Chunk through [`Self::prepared_chunk`]. If CAS
    /// fails, the source has already advanced but `candidate` retains an exact clone;
    /// retrying this method attempts to persist that same candidate rather than reading
    /// another source range.
    pub async fn prepare_next_chunk<S: SifProtectedFileSendStore>(
        &mut self,
        chain: &Chain,
        store: &mut S,
        max_chunk_size: usize,
    ) -> Result<ProfileBoundSourcePrepareDisposition, ProfileBoundSourceTransactionError<S::Error>>
    {
        if self.prepared.is_some() {
            return Err(ProfileBoundOwnedSourceError::PreparedChunkOutstanding.into());
        }
        if self.source_exhausted {
            return Ok(ProfileBoundSourcePrepareDisposition::EndOfSource);
        }

        if self.candidate.is_none() {
            match self.source.next_chunk(max_chunk_size).await {
                Ok(Some(chunk)) => {
                    let semantic =
                        SifProtectedFileChunk::new(&self.offer, chunk.offset, chunk.data)
                            .map_err(ProfileBoundOwnedSourceError::from)?;
                    self.candidate = Some(semantic);
                }
                Ok(None) => {
                    self.source_exhausted = true;
                    return Ok(ProfileBoundSourcePrepareDisposition::EndOfSource);
                }
                Err(error) => return Err(ProfileBoundOwnedSourceError::Source(error).into()),
            }
        }

        let candidate = self
            .candidate
            .as_ref()
            .expect("candidate is populated before journal prepare")
            .clone();
        let prepared = self
            .send
            .prepare_chunk(chain, candidate, store)
            .map_err(ProfileBoundSourceTransactionError::Journal)?;
        let disposition = prepared.disposition();
        self.candidate = None;
        self.prepared = Some(prepared);
        Ok(ProfileBoundSourcePrepareDisposition::ChunkReady(disposition))
    }

    /// Durably record successful carrier transmission for the exact prepared Chunk.
    ///
    /// If the CAS confirmation fails, the prepared capability remains resident and the
    /// caller may safely retry this confirmation without retransmitting the Chunk.
    pub fn confirm_carrier_success<S: SifProtectedFileSendStore>(
        &mut self,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SifProtectedFileConfirmDisposition, ProfileBoundSourceTransactionError<S::Error>>
    {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(ProfileBoundOwnedSourceError::NoPreparedChunk)?;
        let content_len = prepared.chunk().data().len();
        let disposition = self
            .send
            .confirm_carrier_success(chain, prepared, store)
            .map_err(ProfileBoundSourceTransactionError::Journal)?;
        self.file
            .note_emitted(content_len)
            .map_err(ProfileBoundOwnedSourceError::from)?;
        self.prepared = None;
        Ok(disposition)
    }

    /// Consume after an ambiguous carrier result for the exact prepared Chunk.
    ///
    /// The write-ahead `Prepared` entry already makes the full Chunk part of the
    /// possible-disclosure frontier. The file tracker is conservatively charged by the
    /// same complete Chunk length, and no retry/source authority is returned.
    pub fn transport_uncertain(
        mut self,
    ) -> Result<ProfileBoundSourceTerminal, ProfileBoundOwnedSourceError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(ProfileBoundOwnedSourceError::NoPreparedChunk)?;
        self.file
            .note_transport_uncertain(prepared.chunk().data().len())?;
        self.into_terminal()
    }

    /// Consume a release that stops without an ambiguous current Chunk.
    ///
    /// This is suitable for a peer Reject, policy revocation, source failure, or other
    /// stop where the currently durable possible-disclosure frontier is already known.
    pub fn interrupted(self) -> Result<ProfileBoundSourceTerminal, ProfileBoundOwnedSourceError> {
        self.into_terminal()
    }

    /// Consume only after the owned source reached verified EOF and every source byte is
    /// both durably prepared and durably carrier-confirmed.
    pub fn completed(self) -> Result<ProfileBoundSourceTerminal, ProfileBoundOwnedSourceError> {
        if self.prepared.is_some() || self.candidate.is_some() || !self.source_exhausted {
            return Err(ProfileBoundOwnedSourceError::SourceNotExhausted);
        }
        let possible = self.send.possibly_disclosed_unique_bytes()?;
        let confirmed = self.send.confirmed_unique_bytes()?;
        let expected = self.offer.size();
        if possible != expected || confirmed != expected {
            return Err(ProfileBoundOwnedSourceError::IncompleteSendFrontiers {
                possible,
                confirmed,
                expected,
            });
        }
        let file_terminal = self.file.completed()?;
        Ok(ProfileBoundSourceTerminal {
            file_terminal,
            possibly_disclosed_unique_bytes: possible,
            confirmed_unique_bytes: confirmed,
        })
    }

    fn into_terminal(self) -> Result<ProfileBoundSourceTerminal, ProfileBoundOwnedSourceError> {
        let possible = self.send.possibly_disclosed_unique_bytes()?;
        let confirmed = self.send.confirmed_unique_bytes()?;
        let file_terminal = self.file.interrupted();
        Ok(ProfileBoundSourceTerminal {
            file_terminal,
            possibly_disclosed_unique_bytes: possible,
            confirmed_unique_bytes: confirmed,
        })
    }
}
