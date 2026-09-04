// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-owned, write-ahead SIF sender integration.
//!
//! This additive layer composes three already-separate security boundaries:
//!
//! 1. [`ProfileBoundFileOfferAuthority`] proves one exact file result is authorized by a
//!    durable profile-bound release Commit;
//! 2. [`TransferSource`] owns the same already-opened source handle, supplies bounded
//!    sequential chunks, and performs a second whole-source length/hash verification;
//! 3. [`SifProtectedFileSendState`] durably records the exact next Chunk identity before
//!    this module invokes the carrier and records carrier success afterward.
//!
//! The application therefore does not supply protected content bytes to the send loop.
//! A source Chunk is read locally, sealed locally, durably `Prepared`, then and only then
//! handed to [`SendEnvelope::send_envelope`]. A carrier error or failed durable
//! confirmation terminalizes from the journal's conservative possible-disclosure
//! frontier and returns no reusable streaming state.
//!
//! This tranche deliberately does not implement crash-resume of the same release. The
//! source handle and sealed AEAD nonce state are process-local. Recovery uses the durable
//! journal to account for what may have escaped, then a later release lineage may retry
//! under fresh authority.

use std::fmt;

use thiserror::Error;
use xenia_ledger::{
    Chain, DisclosureReleaseOutcome, FileDisclosureByteAccounting, FileDisclosureTerminal,
    MAX_SIF_PROTECTED_FILE_CHUNK_BYTES, ProfileBoundFileOfferAuthority,
    SifProtectedFileProtocolError, SifProtectedFileSendEntry, SifProtectedFileSendError,
    SifProtectedFileSendState, SifProtectedFileSendStore, TransactionalSifProtectedFileSendError,
    SifProtectedFileChunk, SifProtectedFileOffer,
};
use xenia_peer_core::transport::{SendEnvelope, TransportError};
use xenia_peer_core::{TransferSource, TransferSourceError};

use crate::sif_authorized_transfer::{
    AuthorizedOutboundAwaitingCustody, AuthorizedOutboundFailure, AuthorizedOutboundOfferOutcome,
    AuthorizedOutboundStreaming, AuthorizedReleaseTransportUncertain,
    PreparedAuthorizedOutboundComplete, PreparedAuthorizedOutboundOffer,
    ReadyAuthorizedSifSession, ResolvedRejectedAuthorizedRelease,
};

/// Exact durable file authority joined to one fresh, same-content source handle.
#[derive(Debug)]
pub struct SourceBoundFileAuthority {
    authority: ProfileBoundFileOfferAuthority,
    source: TransferSource,
    offer: SifProtectedFileOffer,
}

impl SourceBoundFileAuthority {
    /// Consume durable file authority and a fresh source only when their exact metadata agrees.
    pub fn bind(
        authority: ProfileBoundFileOfferAuthority,
        source: TransferSource,
    ) -> Result<Self, SourceBoundAuthorityError> {
        let offer = authority.offer().clone();
        if source.bytes_sent() != 0 {
            return Err(SourceBoundAuthorityError::SourceAlreadyAdvanced {
                bytes_sent: source.bytes_sent(),
            });
        }
        if source.size() != offer.size() {
            return Err(SourceBoundAuthorityError::SizeMismatch {
                authorized: offer.size(),
                source: source.size(),
            });
        }
        if source.blake3_hash() != offer.content_blake3() {
            return Err(SourceBoundAuthorityError::HashMismatch);
        }
        Ok(Self {
            authority,
            source,
            offer,
        })
    }

    /// Exact authority-derived Offer that will govern this source.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }
}

/// Bind a fresh source to a negotiated authorized session and seal the exact Offer.
pub fn prepare_source_bound_offer(
    ready: ReadyAuthorizedSifSession,
    bound: SourceBoundFileAuthority,
) -> Result<PreparedSourceBoundOffer, SourceBoundOfferFailure> {
    let SourceBoundFileAuthority {
        authority,
        source,
        offer,
    } = bound;
    match ready.prepare_outbound_offer(authority) {
        Ok(inner) => Ok(PreparedSourceBoundOffer {
            inner,
            source,
            offer,
        }),
        Err(error) => Err(SourceBoundOfferFailure::Authorized(error)),
    }
}

/// Authority/source binding failures before any protected transfer begins.
#[derive(Debug, Error)]
pub enum SourceBoundAuthorityError {
    /// Caller attempted to bind a source whose reader had already advanced.
    #[error("source-bound SIF authority requires a fresh source at offset zero, found {bytes_sent}")]
    SourceAlreadyAdvanced {
        /// Bytes already consumed from the supplied source.
        bytes_sent: u64,
    },
    /// Source length does not match the exact durable file authority.
    #[error("source-bound SIF size mismatch: authorized {authorized}, source {source}")]
    SizeMismatch {
        /// Exact length committed by durable authority.
        authorized: u64,
        /// Length committed by the supplied source.
        source: u64,
    },
    /// Source whole-file BLAKE3 does not match the exact durable file authority.
    #[error("source-bound SIF content hash does not match durable file authority")]
    HashMismatch,
}

/// Exact source-bound Offer sealed but not yet carrier-confirmed.
pub struct PreparedSourceBoundOffer {
    inner: PreparedAuthorizedOutboundOffer,
    source: TransferSource,
    offer: SifProtectedFileOffer,
}

impl PreparedSourceBoundOffer {
    /// Exact authority-derived Offer.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Sealed Offer envelope. Offer metadata contains no protected file-content bytes.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Advance after caller-owned carrier code confirms the complete Offer envelope.
    ///
    /// Content bytes are not exposed through such a caller-owned transition: after peer
    /// Accept, [`SourceBoundOutboundStreaming::send_next_chunk`] owns the content carrier
    /// call itself.
    pub fn confirm_sent(self) -> SourceBoundAwaitingResponse {
        SourceBoundAwaitingResponse {
            inner: self.inner.confirm_sent(),
            source: self.source,
            offer: self.offer,
        }
    }

    /// Terminalize an ambiguous Offer send. No content has been handed to the carrier.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Source-bound Offer awaiting the exact authenticated peer response.
pub struct SourceBoundAwaitingResponse {
    inner: crate::sif_authorized_transfer::AuthorizedOutboundAwaitingResponse,
    source: TransferSource,
    offer: SifProtectedFileOffer,
}

impl SourceBoundAwaitingResponse {
    /// Exact authority/source-bound Offer awaiting peer Accept/Reject.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Open peer response; only Accepted creates a write-ahead content sender.
    pub fn open_response(
        self,
        envelope: &[u8],
        chain: &Chain,
    ) -> Result<SourceBoundOfferOutcome, SourceBoundOfferFailure> {
        match self.inner.open_response(envelope) {
            Ok(AuthorizedOutboundOfferOutcome::Rejected(rejected)) => Ok(
                SourceBoundOfferOutcome::Rejected(rejected.into_ready()),
            ),
            Ok(AuthorizedOutboundOfferOutcome::Accepted(inner)) => {
                let send_state = SifProtectedFileSendState::new(self.offer.clone(), chain)
                    .map_err(|error| SourceBoundOfferFailure::JournalStart {
                        error,
                        release_terminal: zero_content_terminal(&self.offer),
                    })?;
                Ok(SourceBoundOfferOutcome::Accepted(
                    SourceBoundOutboundStreaming {
                        inner,
                        source: self.source,
                        offer: self.offer,
                        send_state,
                    },
                ))
            }
            Err(error) => Err(SourceBoundOfferFailure::Authorized(error)),
        }
    }
}

/// Peer disposition for a source-bound Offer.
pub enum SourceBoundOfferOutcome {
    /// Peer accepted; all later content carrier writes flow through write-ahead sender state.
    Accepted(SourceBoundOutboundStreaming),
    /// Peer rejected; reusable session is paired with the explicit Aborted release terminal.
    Rejected(ResolvedRejectedAuthorizedRelease),
}

/// Source-bound sender with write-ahead accounting for every actual content carrier call.
pub struct SourceBoundOutboundStreaming {
    inner: AuthorizedOutboundStreaming,
    source: TransferSource,
    offer: SifProtectedFileOffer,
    send_state: SifProtectedFileSendState,
}

impl SourceBoundOutboundStreaming {
    /// Exact protected Offer governing source, semantic Chunk and durable send journal.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Content bytes durably carrier-confirmed by the write-ahead journal.
    pub fn journal_confirmed_bytes(&self) -> u64 {
        self.send_state.confirmed_unique_bytes().unwrap_or(0)
    }

    /// Content bytes conservatively considered possibly disclosed by the journal.
    pub fn journal_possible_bytes(&self) -> u64 {
        self.send_state
            .possibly_disclosed_unique_bytes()
            .unwrap_or(self.offer.size())
    }

    /// Signed write-ahead entries accumulated for audit/persistence.
    pub fn send_journal_entries(&self) -> &[SifProtectedFileSendEntry] {
        self.send_state.entries()
    }

    /// Read, seal, durably prepare and send exactly one next source Chunk.
    ///
    /// The method owns the only content carrier call in this source-bound state. A
    /// successful return either advances to another streaming state or proves the final
    /// same-handle source length/hash before Complete becomes available.
    pub async fn send_next_chunk<T, S>(
        mut self,
        send: &mut T,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SourceBoundSendProgress, SourceBoundChunkFailure<S::Error>>
    where
        T: SendEnvelope,
        S: SifProtectedFileSendStore,
    {
        if let Err(error) = require_aligned_frontiers(&self) {
            let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
            return Err(SourceBoundChunkFailure::new(
                SourceBoundChunkFailureKind::Frontier(error),
                terminal,
            ));
        }

        let chunk = match self
            .source
            .next_chunk(MAX_SIF_PROTECTED_FILE_CHUNK_BYTES)
            .await
        {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                return Ok(SourceBoundSendProgress::SourceVerified(
                    SourceBoundReadyToComplete {
                        inner: self.inner,
                        offer: self.offer,
                        send_state: self.send_state,
                    },
                ));
            }
            Err(error) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::Source(error),
                    terminal,
                ));
            }
        };

        let chunk_len_u64 = u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
        let expected_end = chunk
            .offset
            .checked_add(chunk_len_u64)
            .unwrap_or(u64::MAX);
        let semantic_chunk = match SifProtectedFileChunk::new(
            &self.offer,
            chunk.offset,
            chunk.data.clone(),
        ) {
            Ok(chunk) => chunk,
            Err(error) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::Semantic(error),
                    terminal,
                ));
            }
        };

        let prepared_inner = match self.inner.prepare_next_chunk(chunk.data) {
            Ok(prepared) => prepared,
            Err(error) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::Authorized(error),
                    terminal,
                ));
            }
        };
        if prepared_inner.content_range() != (chunk.offset, expected_end) {
            let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
            return Err(SourceBoundChunkFailure::new(
                SourceBoundChunkFailureKind::Frontier(
                    SourceBoundFrontierError::SemanticRangeMismatch {
                        source_start: chunk.offset,
                        source_end: expected_end,
                        semantic_start: prepared_inner.content_range().0,
                        semantic_end: prepared_inner.content_range().1,
                    },
                ),
                terminal,
            ));
        }

        let prepared_journal = match self.send_state.prepare_chunk(chain, semantic_chunk, store) {
            Ok(prepared) => prepared,
            Err(TransactionalSifProtectedFileSendError::Protocol(error)) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::JournalProtocol(error),
                    terminal,
                ));
            }
            Err(TransactionalSifProtectedFileSendError::Persist(error)) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::JournalPersist(error),
                    terminal,
                ));
            }
        };

        if let Err(error) = send.send_envelope(prepared_inner.envelope()).await {
            let terminal = terminal_from_possible(&self.send_state, &self.offer);
            // Best-effort alignment of the parent in-memory file tracker. The durable
            // send journal is authoritative for the failure terminal returned here.
            let _ = prepared_inner.transport_uncertain();
            return Err(SourceBoundChunkFailure::new(
                SourceBoundChunkFailureKind::Carrier(error),
                terminal,
            ));
        }

        match self
            .send_state
            .confirm_carrier_success(chain, &prepared_journal, store)
        {
            Ok(_) => {}
            Err(TransactionalSifProtectedFileSendError::Protocol(error)) => {
                let terminal = terminal_from_possible(&self.send_state, &self.offer);
                let _ = prepared_inner.transport_uncertain();
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::JournalProtocol(error),
                    terminal,
                ));
            }
            Err(TransactionalSifProtectedFileSendError::Persist(error)) => {
                let terminal = terminal_from_possible(&self.send_state, &self.offer);
                let _ = prepared_inner.transport_uncertain();
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::JournalPersist(error),
                    terminal,
                ));
            }
        }

        let next_inner = match prepared_inner.confirm_sent() {
            Ok(inner) => inner,
            Err(error) => {
                let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                return Err(SourceBoundChunkFailure::new(
                    SourceBoundChunkFailureKind::Authorized(error),
                    terminal,
                ));
            }
        };
        self.inner = next_inner;

        if let Err(error) = require_aligned_frontiers(&self) {
            let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
            return Err(SourceBoundChunkFailure::new(
                SourceBoundChunkFailureKind::Frontier(error),
                terminal,
            ));
        }

        if self.source.bytes_sent() == self.source.size() {
            match self
                .source
                .next_chunk(MAX_SIF_PROTECTED_FILE_CHUNK_BYTES)
                .await
            {
                Ok(None) => {
                    return Ok(SourceBoundSendProgress::SourceVerified(
                        SourceBoundReadyToComplete {
                            inner: self.inner,
                            offer: self.offer,
                            send_state: self.send_state,
                        },
                    ));
                }
                Ok(Some(_)) => {
                    let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                    return Err(SourceBoundChunkFailure::new(
                        SourceBoundChunkFailureKind::Frontier(
                            SourceBoundFrontierError::UnexpectedChunkAfterDeclaredEnd,
                        ),
                        terminal,
                    ));
                }
                Err(error) => {
                    // All declared bytes may already have left, but source-integrity
                    // verification failed. This remains Partial(size), never Completed.
                    let terminal = terminal_from_confirmed(&self.send_state, &self.offer);
                    return Err(SourceBoundChunkFailure::new(
                        SourceBoundChunkFailureKind::Source(error),
                        terminal,
                    ));
                }
            }
        }

        Ok(SourceBoundSendProgress::More(self))
    }
}

/// Result of one source-owned content-send step.
pub enum SourceBoundSendProgress {
    /// More committed source content remains.
    More(SourceBoundOutboundStreaming),
    /// Final same-handle length/hash re-verification succeeded; Complete may now be sealed.
    SourceVerified(SourceBoundReadyToComplete),
}

/// All content was carrier-confirmed and the source passed final length/hash verification.
pub struct SourceBoundReadyToComplete {
    inner: AuthorizedOutboundStreaming,
    offer: SifProtectedFileOffer,
    send_state: SifProtectedFileSendState,
}

impl SourceBoundReadyToComplete {
    /// Exact Offer whose source and write-ahead content stream are complete.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Final signed write-ahead entries for audit/persistence.
    pub fn send_journal_entries(&self) -> &[SifProtectedFileSendEntry] {
        self.send_state.entries()
    }

    /// Seal Complete only when durable possible/confirmed frontiers both equal file size.
    pub fn prepare_complete(
        self,
    ) -> Result<PreparedSourceBoundComplete, SourceBoundCompleteFailure> {
        let possible = self
            .send_state
            .possibly_disclosed_unique_bytes()
            .unwrap_or(self.offer.size());
        let confirmed = self.send_state.confirmed_unique_bytes().unwrap_or(0);
        if possible != self.offer.size() || confirmed != self.offer.size() {
            return Err(SourceBoundCompleteFailure::Frontier {
                possible,
                confirmed,
                expected: self.offer.size(),
                release_terminal: terminal_from_possible(&self.send_state, &self.offer),
            });
        }
        match self.inner.prepare_complete() {
            Ok(inner) => Ok(PreparedSourceBoundComplete {
                inner,
                send_state: self.send_state,
            }),
            Err(error) => Err(SourceBoundCompleteFailure::Authorized(error)),
        }
    }
}

/// Complete marker after source verification and exact write-ahead content completion.
pub struct PreparedSourceBoundComplete {
    inner: PreparedAuthorizedOutboundComplete,
    send_state: SifProtectedFileSendState,
}

impl PreparedSourceBoundComplete {
    /// Sealed Complete envelope. No file-content bytes are carried by this marker.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Final write-ahead content journal before Complete transport.
    pub fn send_journal_entries(&self) -> &[SifProtectedFileSendEntry] {
        self.send_state.entries()
    }

    /// Confirm Complete carrier success and enter receiver-custody verification.
    pub fn confirm_sent(
        self,
    ) -> Result<AuthorizedOutboundAwaitingCustody, AuthorizedOutboundFailure> {
        self.inner.confirm_sent()
    }

    /// Complete transport ambiguity leaves content accounting Completed while protocol
    /// closure remains uncertain.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Failure while moving from authority-derived Offer to accepted source-bound streaming.
#[derive(Debug)]
pub enum SourceBoundOfferFailure {
    /// Parent authorized facade rejected session/profile/phase state.
    Authorized(AuthorizedOutboundFailure),
    /// Accepted Offer could not initialize its signed write-ahead journal.
    JournalStart {
        /// Journal protocol/validation failure.
        error: SifProtectedFileSendError,
        /// Zero-content release terminal for the failed start.
        release_terminal: FileDisclosureTerminal,
    },
}

impl SourceBoundOfferFailure {
    /// Release terminal that must be durably handled before the failed release is forgotten.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        match self {
            Self::Authorized(error) => error.release_terminal(),
            Self::JournalStart {
                release_terminal, ..
            } => *release_terminal,
        }
    }
}

impl fmt::Display for SourceBoundOfferFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized(error) => error.fmt(formatter),
            Self::JournalStart { error, .. } => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SourceBoundOfferFailure {}

/// Internal frontier divergence detected while composing source, phase and journal state.
#[derive(Debug, Error)]
pub enum SourceBoundFrontierError {
    /// Parent phase, local file tracker, source offset and durable journal disagree.
    #[error(
        "source-bound SIF frontier mismatch: phase={phase}, release={release}, source={source}, journal={journal}"
    )]
    StateMismatch {
        /// Parent phase carrier-confirmed bytes.
        phase: u64,
        /// Parent release-accounted bytes.
        release: u64,
        /// Source bytes consumed into candidate Chunks.
        source: u64,
        /// Durable journal carrier-confirmed bytes.
        journal: u64,
    },
    /// Source-derived semantic range did not match the parent's exact prepared range.
    #[error(
        "source-bound SIF semantic range mismatch: source={source_start}..{source_end}, semantic={semantic_start}..{semantic_end}"
    )]
    SemanticRangeMismatch {
        /// Source Chunk start.
        source_start: u64,
        /// Source Chunk end.
        source_end: u64,
        /// Parent semantic Chunk start.
        semantic_start: u64,
        /// Parent semantic Chunk end.
        semantic_end: u64,
    },
    /// TransferSource produced content after its declared end.
    #[error("source-bound SIF source produced a Chunk after declared end")]
    UnexpectedChunkAfterDeclaredEnd,
}

/// Cause of a terminal source-owned content-send failure.
#[derive(Debug)]
pub enum SourceBoundChunkFailureKind<E> {
    /// Same-handle source read or final verification failed.
    Source(TransferSourceError),
    /// Exact SIF semantic Chunk construction failed.
    Semantic(SifProtectedFileProtocolError),
    /// Parent authorized typestate/accounting failed.
    Authorized(AuthorizedOutboundFailure),
    /// Signed write-ahead journal rejected a transition.
    JournalProtocol(SifProtectedFileSendError),
    /// Atomic journal persistence failed.
    JournalPersist(E),
    /// Carrier send failed after durable Prepared.
    Carrier(TransportError),
    /// Composed source/phase/journal frontiers diverged.
    Frontier(SourceBoundFrontierError),
}

/// Terminal content-send failure paired with conservative durable release truth.
#[derive(Debug)]
pub struct SourceBoundChunkFailure<E> {
    kind: SourceBoundChunkFailureKind<E>,
    release_terminal: FileDisclosureTerminal,
}

impl<E> SourceBoundChunkFailure<E> {
    fn new(kind: SourceBoundChunkFailureKind<E>, release_terminal: FileDisclosureTerminal) -> Self {
        Self {
            kind,
            release_terminal,
        }
    }

    /// Concrete failure cause.
    pub fn kind(&self) -> &SourceBoundChunkFailureKind<E> {
        &self.kind
    }

    /// Release terminal derived from the last trustworthy durable journal frontier.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }
}

impl<E: fmt::Debug> fmt::Display for SourceBoundChunkFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "source-bound protected send failed: {:?}", self.kind)
    }
}

impl<E: fmt::Debug> std::error::Error for SourceBoundChunkFailure<E> {}

/// Failure after final source verification while preparing Complete.
#[derive(Debug)]
pub enum SourceBoundCompleteFailure {
    /// Durable content journal did not exactly close at the Offer size.
    Frontier {
        /// Possible-disclosure frontier.
        possible: u64,
        /// Carrier-confirmed frontier.
        confirmed: u64,
        /// Exact Offer size.
        expected: u64,
        /// Conservative local release terminal.
        release_terminal: FileDisclosureTerminal,
    },
    /// Parent authorized Complete preparation failed.
    Authorized(AuthorizedOutboundFailure),
}

impl SourceBoundCompleteFailure {
    /// Release terminal attached to this fail-closed completion attempt.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        match self {
            Self::Frontier {
                release_terminal, ..
            } => *release_terminal,
            Self::Authorized(error) => error.release_terminal(),
        }
    }
}

fn require_aligned_frontiers(
    state: &SourceBoundOutboundStreaming,
) -> Result<(), SourceBoundFrontierError> {
    let journal = state
        .send_state
        .confirmed_unique_bytes()
        .unwrap_or(u64::MAX);
    let phase = state.inner.confirmed_content_bytes();
    let release = state.inner.accounted_content_bytes();
    let source = state.source.bytes_sent();
    if phase != release || phase != journal || phase != source {
        return Err(SourceBoundFrontierError::StateMismatch {
            phase,
            release,
            source,
            journal,
        });
    }
    Ok(())
}

fn zero_content_terminal(offer: &SifProtectedFileOffer) -> FileDisclosureTerminal {
    FileDisclosureTerminal {
        release_id: offer.release_id(),
        outcome: DisclosureReleaseOutcome::Aborted,
        byte_accounting: FileDisclosureByteAccounting::Exact,
    }
}

fn terminal_from_confirmed(
    state: &SifProtectedFileSendState,
    offer: &SifProtectedFileOffer,
) -> FileDisclosureTerminal {
    match state.confirmed_unique_bytes() {
        Ok(0) => zero_content_terminal(offer),
        Ok(bytes) => FileDisclosureTerminal {
            release_id: offer.release_id(),
            outcome: DisclosureReleaseOutcome::Partial {
                bytes_released: bytes.min(offer.size()),
            },
            byte_accounting: FileDisclosureByteAccounting::Exact,
        },
        Err(_) => full_conservative_terminal(offer),
    }
}

fn terminal_from_possible(
    state: &SifProtectedFileSendState,
    offer: &SifProtectedFileOffer,
) -> FileDisclosureTerminal {
    let possible = match state.possibly_disclosed_unique_bytes() {
        Ok(bytes) => bytes.min(offer.size()),
        Err(_) => return full_conservative_terminal(offer),
    };
    let confirmed = state.confirmed_unique_bytes().unwrap_or(0).min(possible);
    if possible == 0 {
        return zero_content_terminal(offer);
    }
    FileDisclosureTerminal {
        release_id: offer.release_id(),
        outcome: DisclosureReleaseOutcome::Partial {
            bytes_released: possible,
        },
        byte_accounting: if confirmed == possible {
            FileDisclosureByteAccounting::Exact
        } else {
            FileDisclosureByteAccounting::ConservativeUpperBound
        },
    }
}

fn full_conservative_terminal(offer: &SifProtectedFileOffer) -> FileDisclosureTerminal {
    if offer.size() == 0 {
        return FileDisclosureTerminal {
            release_id: offer.release_id(),
            outcome: DisclosureReleaseOutcome::Aborted,
            byte_accounting: FileDisclosureByteAccounting::ConservativeUpperBound,
        };
    }
    FileDisclosureTerminal {
        release_id: offer.release_id(),
        outcome: DisclosureReleaseOutcome::Partial {
            bytes_released: offer.size(),
        },
        byte_accounting: FileDisclosureByteAccounting::ConservativeUpperBound,
    }
}
