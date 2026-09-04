// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-owned, write-ahead high-assurance SIF protected-file sender.
//!
//! This is the public outbound authority surface. Application callers never supply an
//! Offer or content bytes. The sender consumes [`SourceBoundFileOfferAuthority`], reads
//! each bounded Chunk from its private [`TransferSource`], persists PR #283's exact
//! `Prepared` identity before exposing a sealed envelope, and persists
//! `CarrierConfirmed` before advancing protocol/file-accounting authority.
//!
//! If carrier confirmation persistence fails after the carrier reported success, the
//! returned retry state deliberately exposes **no envelope**: only the durable
//! confirmation step may be retried. If the carrier result itself is ambiguous, the
//! already-durable `Prepared` entry remains the conservative possible-disclosure fact and
//! no network retry authority is returned.

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    Chain, ProfileBoundReleaseState, ProfileReleaseSignerError, SifProtectedFileChunk,
    SifProtectedFileProtocolError, SifProtectedFileSendError, SifProtectedFileSendState,
    SifProtectedFileSendStore, TransactionalSifProtectedFileSendError,
    VerifiedProfileReleaseSigner, MAX_SIF_PROTECTED_FILE_CHUNK_BYTES,
    verify_profile_release_signer_for_offer,
};
use xenia_peer_core::{SifProtectedFileWireRole, TransferSource, TransferSourceError};

use crate::sif_authorized_transfer::{
    AuthorizedChunkTransportUncertain, AuthorizedInboundOfferPending,
    AuthorizedOutboundAwaitingCustody, AuthorizedOutboundAwaitingResponse,
    AuthorizedOutboundOfferOutcome, AuthorizedOutboundStreaming, AuthorizedSifError,
    ClosedAuthorizedOutboundRelease, PendingAuthorizedSifSession,
    PreparedAuthorizedOutboundChunk, PreparedAuthorizedOutboundComplete,
    PreparedAuthorizedOutboundOffer, ReadyAuthorizedSifSession,
};
use crate::sif_source_authority::SourceBoundFileOfferAuthority;

pub use crate::sif_authorized_transfer::{
    AuthorizedCustodyTransportUncertain, AuthorizedInboundCustodyPending,
    AuthorizedInboundReceiving, ClosedAuthorizedInboundRelease,
    PreparedAuthorizedCustodyReceipt, PreparedAuthorizedInboundAccept,
    PreparedAuthorizedInboundReject,
};

/// Pre-negotiation public SIF session for source-owned protected transfer.
pub struct PendingSourceOwnedSifSession {
    inner: PendingAuthorizedSifSession,
}

impl PendingSourceOwnedSifSession {
    /// Create a fresh protected sub-session for one authenticated Xenia session.
    pub fn new(
        role: SifProtectedFileWireRole,
        session: xenia_ledger::SessionTranscriptBinding,
        manifest: xenia_ledger::EvidenceCryptoManifest,
    ) -> Self {
        Self {
            inner: PendingAuthorizedSifSession::new(role, session, manifest),
        }
    }

    /// Endpoint role fixed for this SIF sub-session.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.inner.role()
    }

    /// Exact authenticated Xenia session transcript generation.
    pub fn session(&self) -> &xenia_ledger::SessionTranscriptBinding {
        self.inner.session()
    }

    /// Install one explicit initial control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.inner.install_control_key(key);
    }

    /// Install the transcript-derived initial control schedule.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.inner.install_schedule(schedule);
    }

    /// Seal this endpoint's exact compiled SIF profile capability.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, SourceOwnedSendError> {
        Ok(self.inner.seal_local_capability()?)
    }

    /// Consume pending state after exact authenticated peer profile negotiation.
    pub fn accept_peer_capability(
        self,
        envelope: &[u8],
    ) -> Result<ReadySourceOwnedSifSession, SourceOwnedSendError> {
        Ok(ReadySourceOwnedSifSession {
            inner: self.inner.accept_peer_capability(envelope)?,
        })
    }
}

/// Negotiated public SIF session with no active release.
pub struct ReadySourceOwnedSifSession {
    inner: ReadyAuthorizedSifSession,
}

impl ReadySourceOwnedSifSession {
    /// Exact authenticated protected-transfer profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.inner.profile_digest()
    }

    /// Exact authenticated Xenia session generation.
    pub fn session(&self) -> &xenia_ledger::SessionTranscriptBinding {
        self.inner.session()
    }

    /// Rotate negotiated control keys while no protected release is active.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.inner.install_rekey_keys(keys);
    }

    /// Begin one outbound release only from exact source + durable authority.
    ///
    /// The complete profile-release journal is first verified under the supplied
    /// `Chain` signer and the Offer's release-Commit hash must resolve exactly. The send
    /// journal is then created under that same `Chain`, composing one signer lineage.
    pub fn prepare_outbound_source_offer(
        self,
        authority: SourceBoundFileOfferAuthority,
        chain: &Chain,
        release_state: &ProfileBoundReleaseState,
    ) -> Result<PreparedSourceOwnedOffer, SourceOwnedSendError> {
        let offer = authority.offer().clone();
        let signer = verify_profile_release_signer_for_offer(chain, release_state, &offer)?;
        signer.validate_offer(&offer)?;
        let send_journal = SifProtectedFileSendState::new(offer, chain)?;
        let (offer_authority, source) = authority.into_parts();
        let inner = self
            .inner
            .prepare_outbound_authorized_offer(offer_authority)?;
        Ok(PreparedSourceOwnedOffer {
            inner,
            source,
            send_journal,
            signer,
        })
    }

    /// Open one authenticated inbound Offer using the existing durable-custody receiver.
    pub fn open_inbound_offer(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedInboundOfferPending, SourceOwnedSendError> {
        Ok(self.inner.open_inbound_offer(envelope)?)
    }
}

/// Authority-derived Offer sealed but not yet carrier-confirmed.
pub struct PreparedSourceOwnedOffer {
    inner: PreparedAuthorizedOutboundOffer,
    source: TransferSource,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl PreparedSourceOwnedOffer {
    /// Exact authority/source-derived Offer.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Sealed Offer envelope. No content bytes are exposed by this state.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Confirm complete carrier handoff of the Offer and wait for peer response.
    pub fn confirm_sent(self) -> SourceOwnedAwaitingResponse {
        SourceOwnedAwaitingResponse {
            inner: self.inner.confirm_sent(),
            source: self.source,
            send_journal: self.send_journal,
            signer: self.signer,
        }
    }

    /// Consume ambiguous Offer transport. No file-content bytes were prepared.
    pub fn transport_uncertain(self) -> crate::sif_authorized_transfer::AuthorizedOfferTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Confirmed authority-derived Offer awaiting exact peer decision.
pub struct SourceOwnedAwaitingResponse {
    inner: AuthorizedOutboundAwaitingResponse,
    source: TransferSource,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedAwaitingResponse {
    /// Open the exact authenticated peer response.
    pub fn open_response(
        self,
        envelope: &[u8],
    ) -> Result<SourceOwnedOfferOutcome, SourceOwnedSendError> {
        match self.inner.open_response(envelope)? {
            AuthorizedOutboundOfferOutcome::Accepted(inner) => {
                Ok(SourceOwnedOfferOutcome::Accepted(SourceOwnedStreaming {
                    inner,
                    source: self.source,
                    send_journal: self.send_journal,
                    signer: self.signer,
                }))
            }
            AuthorizedOutboundOfferOutcome::Rejected(rejected) => {
                Ok(SourceOwnedOfferOutcome::Rejected(SourceOwnedRejected {
                    terminal: rejected.into_terminal(),
                    send_journal: self.send_journal,
                    signer: self.signer,
                }))
            }
        }
    }
}

/// Peer decision for one source-owned protected release.
pub enum SourceOwnedOfferOutcome {
    /// Exact Offer accepted; only private-source streaming may now produce content.
    Accepted(SourceOwnedStreaming),
    /// Exact Offer rejected; the durable release must close as zero-byte Aborted.
    Rejected(SourceOwnedRejected),
}

/// Rejected source-owned release with no reusable outbound authority.
pub struct SourceOwnedRejected {
    terminal: xenia_ledger::FileDisclosureTerminal,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedRejected {
    /// Zero-byte terminal that must be durably recorded in the release journal.
    pub const fn terminal(&self) -> xenia_ledger::FileDisclosureTerminal {
        self.terminal
    }

    /// Send journal remains empty because no content was ever prepared.
    pub fn send_entries(&self) -> &[xenia_ledger::SifProtectedFileSendEntry] {
        self.send_journal.entries()
    }

    /// Release signer verified before this rejected Offer was emitted.
    pub const fn release_signer(&self) -> &VerifiedProfileReleaseSigner {
        &self.signer
    }
}

/// Accepted release whose next content can only come from its private source.
pub struct SourceOwnedStreaming {
    inner: AuthorizedOutboundStreaming,
    source: TransferSource,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedStreaming {
    /// Carrier-confirmed content frontier in the semantic phase machine.
    pub const fn confirmed_content_bytes(&self) -> u64 {
        self.inner.confirmed_content_bytes()
    }

    /// Conservative unique bytes durably prepared before possible carrier I/O.
    pub fn possibly_disclosed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.possibly_disclosed_unique_bytes()?)
    }

    /// Unique bytes whose carrier success is durably recorded.
    pub fn carrier_confirmed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.confirmed_unique_bytes()?)
    }

    /// Read and durably prepare the next exact source Chunk, or prove end-of-source.
    ///
    /// No sealed Chunk envelope exists until the exact source bytes have a CAS-durable
    /// `Prepared` identity in the send journal.
    pub async fn prepare_next_source_chunk<S: SifProtectedFileSendStore>(
        self,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SourceOwnedStreamStep, SourceOwnedPrepareError<S::Error>> {
        let mut this = self;
        this.require_idle_frontiers()
            .map_err(SourceOwnedPrepareError::Protocol)?;

        let Some(source_chunk) = this
            .source
            .next_chunk(MAX_SIF_PROTECTED_FILE_CHUNK_BYTES)
            .await
            .map_err(SourceOwnedSendError::Source)
            .map_err(SourceOwnedPrepareError::Protocol)?
        else {
            this.require_verified_end()
                .map_err(SourceOwnedPrepareError::Protocol)?;
            return Ok(SourceOwnedStreamStep::EndVerified(SourceOwnedEndVerified {
                inner: this.inner,
                send_journal: this.send_journal,
                signer: this.signer,
            }));
        };

        let expected = this.inner.confirmed_content_bytes();
        if source_chunk.offset != expected {
            return Err(SourceOwnedPrepareError::Protocol(
                SourceOwnedSendError::FrontierMismatch {
                    source: source_chunk.offset,
                    protocol: expected,
                    possible: this.send_journal.possibly_disclosed_unique_bytes()?,
                    confirmed: this.send_journal.confirmed_unique_bytes()?,
                },
            ));
        }

        let semantic = SifProtectedFileChunk::new(
            this.send_journal.offer(),
            source_chunk.offset,
            source_chunk.data,
        )
        .map_err(SourceOwnedSendError::Protocol)
        .map_err(SourceOwnedPrepareError::Protocol)?;

        let prepared = match this.send_journal.prepare_chunk(chain, semantic, store) {
            Ok(prepared) => prepared,
            Err(TransactionalSifProtectedFileSendError::Protocol(error)) => {
                return Err(SourceOwnedPrepareError::Protocol(
                    SourceOwnedSendError::SendJournal(error),
                ));
            }
            Err(TransactionalSifProtectedFileSendError::Persist(error)) => {
                return Err(SourceOwnedPrepareError::Persist(error));
            }
        };

        // The private phase engine receives only the exact bytes already named by the
        // durable Prepared capability. No application-supplied content enters here.
        let bytes = prepared.chunk().data().to_vec();
        let inner = this
            .inner
            .prepare_next_chunk(bytes)
            .map_err(SourceOwnedSendError::Authorized)
            .map_err(SourceOwnedPrepareError::Protocol)?;
        let (start, end) = inner.content_range();
        if start != prepared.chunk().offset()
            || end != start.saturating_add(prepared.chunk().data().len() as u64)
        {
            return Err(SourceOwnedPrepareError::Protocol(
                SourceOwnedSendError::PreparedChunkMismatch,
            ));
        }

        Ok(SourceOwnedStreamStep::Prepared(PreparedSourceOwnedChunk {
            inner,
            source: this.source,
            send_journal: this.send_journal,
            prepared,
            signer: this.signer,
        }))
    }

    fn require_idle_frontiers(&self) -> Result<(), SourceOwnedSendError> {
        let source = self.source.bytes_sent();
        let protocol = self.inner.confirmed_content_bytes();
        let possible = self.send_journal.possibly_disclosed_unique_bytes()?;
        let confirmed = self.send_journal.confirmed_unique_bytes()?;
        if source != protocol || protocol != possible || possible != confirmed {
            return Err(SourceOwnedSendError::FrontierMismatch {
                source,
                protocol,
                possible,
                confirmed,
            });
        }
        Ok(())
    }

    fn require_verified_end(&self) -> Result<(), SourceOwnedSendError> {
        let expected = self.send_journal.offer().size();
        let source = self.source.bytes_sent();
        let protocol = self.inner.confirmed_content_bytes();
        let possible = self.send_journal.possibly_disclosed_unique_bytes()?;
        let confirmed = self.send_journal.confirmed_unique_bytes()?;
        if source != expected
            || protocol != expected
            || possible != expected
            || confirmed != expected
        {
            return Err(SourceOwnedSendError::EndFrontierMismatch {
                expected,
                source,
                protocol,
                possible,
                confirmed,
            });
        }
        Ok(())
    }
}

/// Result of asking the private source for its next Chunk.
pub enum SourceOwnedStreamStep {
    /// One exact source Chunk is durably prepared and sealed for one carrier attempt.
    Prepared(PreparedSourceOwnedChunk),
    /// The source reached EOF and its second length/BLAKE3 verification succeeded.
    EndVerified(SourceOwnedEndVerified),
}

/// One exact source Chunk durably prepared before carrier I/O.
pub struct PreparedSourceOwnedChunk {
    inner: PreparedAuthorizedOutboundChunk,
    source: TransferSource,
    send_journal: SifProtectedFileSendState,
    prepared: xenia_ledger::PreparedSifProtectedFileChunk,
    signer: VerifiedProfileReleaseSigner,
}

impl PreparedSourceOwnedChunk {
    /// Sealed envelope corresponding exactly to the durably prepared source bytes.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Stable idempotency identity for this exact prepared Chunk.
    pub const fn idempotency_token(&self) -> [u8; 32] {
        self.prepared.idempotency_token()
    }

    /// Exact file-content range represented by this prepared Chunk.
    pub const fn content_range(&self) -> (u64, u64) {
        self.inner.content_range()
    }

    /// Report carrier success and durably confirm it before protocol authority advances.
    pub fn carrier_succeeded<S: SifProtectedFileSendStore>(
        self,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SourceOwnedStreaming, SourceOwnedCarrierConfirmError<S::Error>> {
        CarrierConfirmationPending {
            inner: self.inner,
            source: self.source,
            send_journal: self.send_journal,
            prepared: self.prepared,
            signer: self.signer,
        }
        .persist(chain, store)
    }

    /// Consume ambiguous carrier result. No envelope/retry authority is returned.
    ///
    /// The send journal retains the already-durable unconfirmed `Prepared` event, while
    /// the file tracker conservatively charges the complete attempted content Chunk.
    pub fn carrier_uncertain(
        self,
    ) -> Result<SourceOwnedChunkTransportUncertain, SourceOwnedSendError> {
        let transport = self.inner.transport_uncertain()?;
        Ok(SourceOwnedChunkTransportUncertain {
            transport,
            send_journal: self.send_journal,
            signer: self.signer,
        })
    }
}

/// Carrier succeeded, but durable confirmation may still need retry after store failure.
///
/// This state intentionally exposes no envelope bytes, preventing blind retransmission of
/// a Chunk that the carrier already accepted.
pub struct CarrierConfirmationPending {
    inner: PreparedAuthorizedOutboundChunk,
    source: TransferSource,
    send_journal: SifProtectedFileSendState,
    prepared: xenia_ledger::PreparedSifProtectedFileChunk,
    signer: VerifiedProfileReleaseSigner,
}

impl CarrierConfirmationPending {
    /// Retry only the durable `CarrierConfirmed` transition; network send is no longer available.
    pub fn retry_persist<S: SifProtectedFileSendStore>(
        self,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SourceOwnedStreaming, SourceOwnedCarrierConfirmError<S::Error>> {
        self.persist(chain, store)
    }

    /// Stable idempotency token of the carrier-succeeded exact Chunk.
    pub const fn idempotency_token(&self) -> [u8; 32] {
        self.prepared.idempotency_token()
    }

    fn persist<S: SifProtectedFileSendStore>(
        mut self,
        chain: &Chain,
        store: &mut S,
    ) -> Result<SourceOwnedStreaming, SourceOwnedCarrierConfirmError<S::Error>> {
        match self
            .send_journal
            .confirm_carrier_success(chain, &self.prepared, store)
        {
            Ok(_) => {}
            Err(TransactionalSifProtectedFileSendError::Protocol(error)) => {
                return Err(SourceOwnedCarrierConfirmError::Protocol(
                    SourceOwnedSendError::SendJournal(error),
                ));
            }
            Err(TransactionalSifProtectedFileSendError::Persist(error)) => {
                return Err(SourceOwnedCarrierConfirmError::Persist {
                    error,
                    pending: self,
                });
            }
        }

        let expected_end = self.inner.content_range().1;
        let confirmed = self
            .send_journal
            .confirmed_unique_bytes()
            .map_err(SourceOwnedSendError::SendJournal)
            .map_err(SourceOwnedCarrierConfirmError::Protocol)?;
        if confirmed != expected_end {
            return Err(SourceOwnedCarrierConfirmError::Protocol(
                SourceOwnedSendError::PreparedChunkMismatch,
            ));
        }

        let inner = self
            .inner
            .confirm_sent()
            .map_err(SourceOwnedSendError::Authorized)
            .map_err(SourceOwnedCarrierConfirmError::Protocol)?;
        if inner.confirmed_content_bytes() != confirmed {
            return Err(SourceOwnedCarrierConfirmError::Protocol(
                SourceOwnedSendError::PreparedChunkMismatch,
            ));
        }

        Ok(SourceOwnedStreaming {
            inner,
            source: self.source,
            send_journal: self.send_journal,
            signer: self.signer,
        })
    }
}

/// Terminal ambiguous Chunk transport with durable possible-disclosure evidence.
pub struct SourceOwnedChunkTransportUncertain {
    transport: AuthorizedChunkTransportUncertain,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedChunkTransportUncertain {
    /// Conservative file/release terminal from the high-assurance phase engine.
    pub fn transport(&self) -> &AuthorizedChunkTransportUncertain {
        &self.transport
    }

    /// Unique bytes that may have escaped according to the durable write-ahead journal.
    pub fn possibly_disclosed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.possibly_disclosed_unique_bytes()?)
    }

    /// Unique bytes whose carrier success was durably confirmed before ambiguity.
    pub fn carrier_confirmed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.confirmed_unique_bytes()?)
    }

    /// Exact release signer governing both release and send evidence.
    pub const fn release_signer(&self) -> &VerifiedProfileReleaseSigner {
        &self.signer
    }
}

/// Source reached EOF and second whole-file verification succeeded.
pub struct SourceOwnedEndVerified {
    inner: AuthorizedOutboundStreaming,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedEndVerified {
    /// Prepare the Complete marker only after source and both durable frontiers equal size.
    pub fn prepare_complete(self) -> Result<PreparedSourceOwnedComplete, SourceOwnedSendError> {
        Ok(PreparedSourceOwnedComplete {
            inner: self.inner.prepare_complete()?,
            send_journal: self.send_journal,
            signer: self.signer,
        })
    }
}

/// Complete marker sealed after second-pass source verification and full carrier confirmation.
pub struct PreparedSourceOwnedComplete {
    inner: PreparedAuthorizedOutboundComplete,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl PreparedSourceOwnedComplete {
    /// Sealed Complete control envelope.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Enter custody wait after Complete carrier success.
    pub fn confirm_sent(self) -> SourceOwnedAwaitingCustody {
        SourceOwnedAwaitingCustody {
            inner: self.inner.confirm_sent(),
            send_journal: self.send_journal,
            signer: self.signer,
        }
    }

    /// Complete-control ambiguity is terminal; all file bytes were already carrier-confirmed.
    pub fn transport_uncertain(self) -> crate::sif_authorized_transfer::AuthorizedCompleteTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Sender waiting for independently verified receiver custody after source-verified output.
pub struct SourceOwnedAwaitingCustody {
    inner: AuthorizedOutboundAwaitingCustody,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl SourceOwnedAwaitingCustody {
    /// Verify receiver custody and close this one-shot protected sub-session.
    pub fn verify_custody(
        self,
        envelope: &[u8],
        backend: &impl xenia_ledger::EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<ClosedSourceOwnedRelease, SourceOwnedSendError> {
        Ok(ClosedSourceOwnedRelease {
            inner: self.inner.verify_custody(
                envelope,
                backend,
                trusted_receiver_public_key,
            )?,
            send_journal: self.send_journal,
            signer: self.signer,
        })
    }
}

/// Closed source-owned release after sender-verified receiver custody evidence.
pub struct ClosedSourceOwnedRelease {
    inner: ClosedAuthorizedOutboundRelease,
    send_journal: SifProtectedFileSendState,
    signer: VerifiedProfileReleaseSigner,
}

impl ClosedSourceOwnedRelease {
    /// Receiver's cryptographically verified terminal disposition.
    pub const fn disposition(&self) -> xenia_ledger::SifDeliveryDisposition {
        self.inner.disposition()
    }

    /// Exact sender-reconstructed custody binding.
    pub fn binding(&self) -> &xenia_ledger::SifDeliveryReceiptBinding {
        self.inner.binding()
    }

    /// Final possible-disclosure frontier; equal to file size on this path.
    pub fn possibly_disclosed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.possibly_disclosed_unique_bytes()?)
    }

    /// Final durable carrier-confirmed frontier; equal to file size on this path.
    pub fn carrier_confirmed_unique_bytes(&self) -> Result<u64, SourceOwnedSendError> {
        Ok(self.send_journal.confirmed_unique_bytes()?)
    }

    /// Signed write-ahead entries for archive/independent verification.
    pub fn send_entries(&self) -> &[xenia_ledger::SifProtectedFileSendEntry] {
        self.send_journal.entries()
    }

    /// Release signer proven to govern both release and send journals.
    pub const fn release_signer(&self) -> &VerifiedProfileReleaseSigner {
        &self.signer
    }
}

/// Fail-closed source-owned sender errors that do not depend on a persistence backend.
#[derive(Debug, Error)]
pub enum SourceOwnedSendError {
    /// Existing durable-authority/accountable phase semantics failed.
    #[error(transparent)]
    Authorized(#[from] AuthorizedSifError),
    /// Release-journal signer/Commit verification failed.
    #[error(transparent)]
    ReleaseSigner(#[from] ProfileReleaseSignerError),
    /// Write-ahead protected-file journal failed.
    #[error(transparent)]
    SendJournal(#[from] SifProtectedFileSendError),
    /// Private source preparation/streaming verification failed.
    #[error(transparent)]
    Source(#[from] TransferSourceError),
    /// Protected semantic Chunk construction failed.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Source, semantic and durable disclosure frontiers diverged.
    #[error(
        "source-owned sender frontier mismatch: source={source}, protocol={protocol}, possible={possible}, confirmed={confirmed}"
    )]
    FrontierMismatch {
        /// Bytes consumed from the private source.
        source: u64,
        /// Carrier-confirmed semantic content frontier.
        protocol: u64,
        /// Durable possible-disclosure frontier.
        possible: u64,
        /// Durable carrier-confirmed frontier.
        confirmed: u64,
    },
    /// End-of-source verification succeeded but final frontiers do not equal file size.
    #[error(
        "source-owned sender end frontier mismatch: expected={expected}, source={source}, protocol={protocol}, possible={possible}, confirmed={confirmed}"
    )]
    EndFrontierMismatch {
        /// Exact Offer size.
        expected: u64,
        /// Bytes consumed from source.
        source: u64,
        /// Semantic carrier-confirmed bytes.
        protocol: u64,
        /// Durable possible-disclosure bytes.
        possible: u64,
        /// Durable carrier-confirmed bytes.
        confirmed: u64,
    },
    /// Private semantic and durable prepared Chunk identities unexpectedly diverged.
    #[error("source-owned sender prepared Chunk identity mismatch")]
    PreparedChunkMismatch,
}

/// Error while durably preparing a next source Chunk.
#[derive(Debug)]
pub enum SourceOwnedPrepareError<E> {
    /// Semantic/source/journal invariant failed before an envelope became available.
    Protocol(SourceOwnedSendError),
    /// CAS persistence of the write-ahead Prepared event failed; no envelope is returned.
    Persist(E),
}

/// Error while persisting carrier success after the network operation completed.
#[derive(Debug)]
pub enum SourceOwnedCarrierConfirmError<E> {
    /// Semantic/signer/journal invariant failed closed.
    Protocol(SourceOwnedSendError),
    /// Durable confirmation failed. The embedded state permits only confirmation retry.
    Persist {
        /// Store-specific CAS/persistence failure.
        error: E,
        /// Move-only retry state with no access to the already-sent envelope.
        pending: CarrierConfirmationPending,
    },
}
