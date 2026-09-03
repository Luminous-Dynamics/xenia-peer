// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Move-only protocol-phase typestates for one active SIF protected-file transfer.
//!
//! Authenticated profile negotiation is necessary but not sufficient: a negotiated
//! channel must still refuse protected content until an exact Offer was emitted and the
//! peer returned an authenticated Accept. This module is the public application surface
//! above `sif_negotiation` and serializes one active transfer per channel.
//!
//! Outbound operations also distinguish **prepared/sealed** from **transport-confirmed**.
//! AEAD sealing advances nonce state, while an ordinary transport send can fail after an
//! unknown prefix may have left the process. A prepared Offer/Chunk/Complete therefore
//! advances only via `confirm_sent()`. `transport_uncertain()` consumes the state and
//! yields a terminal uncertainty record with no reusable channel, preventing blind retry
//! of a message the peer may already have accepted.
//!
//! On receive, local private staging is created before an Accept envelope is prepared.
//! If staging cannot begin, no Accept can be produced through this API. Once Accept is
//! transport-confirmed, the move-only receive state accepts exact contiguous Chunks and
//! joins them to the crash-durable custody runtime from `sif_receive_runtime`.

use std::path::Path;

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    SifProtectedFileChunk, SifProtectedFileComplete, SifProtectedFileOffer,
    SifProtectedFileOfferDecision, SifProtectedFileOfferResponse, SifProtectedFileProtocolError,
};
use xenia_peer_core::SifProtectedFileWireRole;

use crate::sif_negotiation::{
    NegotiatedSifProtectedFileChannel, PendingSifProtectedFileChannel, SifNegotiationError,
};
use crate::sif_receive_runtime::{
    SifReceiveRuntime, SifReceiveRuntimeError, SifReceiveRuntimeTerminal,
};

/// Pending authenticated-profile negotiation exposed to application/session code.
pub struct PendingSifProtectedSession {
    inner: PendingSifProtectedFileChannel,
}

impl PendingSifProtectedSession {
    /// Create a pending SIF session with fresh capability and transfer wire metadata.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            inner: PendingSifProtectedFileChannel::new(role),
        }
    }

    /// Create deterministic pending state for qualification tests.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            inner: PendingSifProtectedFileChannel::with_fixture(role, source_id, epoch),
        }
    }

    /// Endpoint role fixed for this SIF session.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.inner.role()
    }

    /// Install one explicit initial control key into capability and transfer domains.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.inner.install_control_key(key);
    }

    /// Install the initial transcript-derived control schedule.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.inner.install_schedule(schedule);
    }

    /// Advance previous-key grace expiry while capability negotiation is pending.
    pub fn tick(&mut self) {
        self.inner.tick();
    }

    /// Seal this endpoint's exact compiled SIF capability profile.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, SifTransferFlowError> {
        Ok(self.inner.seal_local_capability()?)
    }

    /// Consume pending negotiation and enter the only reusable ready transfer state.
    pub fn accept_peer_capability(
        self,
        envelope: &[u8],
    ) -> Result<ReadySifProtectedSession, SifTransferFlowError> {
        Ok(ReadySifProtectedSession {
            inner: self.inner.accept_peer_capability(envelope)?,
        })
    }
}

/// Negotiated SIF session with no active protected-file transfer.
///
/// This state intentionally does not expose raw Chunk/Complete methods. A caller must
/// first prepare and confirm an Offer, then receive an authenticated Accept.
pub struct ReadySifProtectedSession {
    inner: NegotiatedSifProtectedFileChannel,
}

impl ReadySifProtectedSession {
    /// Endpoint role fixed for this negotiated session.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.inner.role()
    }

    /// Exact compiled SIF profile authenticated during negotiation.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.inner.profile_digest()
    }

    /// Install a negotiated rekey epoch while no transfer is active.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.inner.install_rekey_keys(keys);
    }

    /// Advance previous-key grace expiry.
    pub fn tick(&mut self) {
        self.inner.tick();
    }

    /// Seal one outbound Offer without yet claiming it was transported.
    pub fn prepare_outbound_offer(
        mut self,
        offer: SifProtectedFileOffer,
    ) -> Result<PreparedOutboundSifOffer, SifTransferFlowError> {
        let envelope = self.inner.seal_offer(&offer)?;
        Ok(PreparedOutboundSifOffer {
            channel: self.inner,
            offer,
            envelope,
        })
    }

    /// Open one authenticated inbound Offer and enter its decision state.
    pub fn open_inbound_offer(
        mut self,
        envelope: &[u8],
    ) -> Result<InboundSifOfferPending, SifTransferFlowError> {
        let offer = self.inner.open_offer(envelope)?;
        Ok(InboundSifOfferPending {
            channel: self.inner,
            offer,
        })
    }
}

/// Outbound Offer that has been sealed but not yet confirmed sent by the transport.
pub struct PreparedOutboundSifOffer {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    envelope: Vec<u8>,
}

impl PreparedOutboundSifOffer {
    /// Exact Offer represented by this prepared envelope.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Sealed bytes the transport must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Confirm that the transport reported the complete Offer envelope as sent.
    pub fn confirm_sent(self) -> OutboundSifAwaitingResponse {
        OutboundSifAwaitingResponse {
            channel: self.channel,
            offer: self.offer,
        }
    }

    /// Consume an ambiguously failed Offer send into a terminal uncertainty record.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        SifTransferTransportUncertain::new(
            SifTransportUncertainPhase::Offer,
            self.offer,
            0,
        )
    }
}

/// Confirmed outbound Offer waiting for the exact peer Accept/Reject response.
pub struct OutboundSifAwaitingResponse {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
}

impl OutboundSifAwaitingResponse {
    /// Exact Offer awaiting a peer decision.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Open the peer response and transition to Accepted streaming or Rejected ready state.
    pub fn open_response(
        mut self,
        envelope: &[u8],
    ) -> Result<OutboundSifOfferOutcome, SifTransferFlowError> {
        let response = self
            .channel
            .open_response_for_offer(envelope, &self.offer)?;
        match response.decision() {
            SifProtectedFileOfferDecision::Accept => {
                Ok(OutboundSifOfferOutcome::Accepted(OutboundSifStreaming {
                    channel: self.channel,
                    offer: self.offer,
                    confirmed_content_bytes: 0,
                }))
            }
            SifProtectedFileOfferDecision::Reject => {
                Ok(OutboundSifOfferOutcome::Rejected(RejectedOutboundSifOffer {
                    session: ReadySifProtectedSession {
                        inner: self.channel,
                    },
                    offer: self.offer,
                    response,
                }))
            }
        }
    }
}

/// Authenticated peer decision for an outbound protected Offer.
pub enum OutboundSifOfferOutcome {
    /// Peer authenticated and accepted the exact Offer; content may now be prepared.
    Accepted(OutboundSifStreaming),
    /// Peer rejected the exact Offer; no content authority was unlocked.
    Rejected(RejectedOutboundSifOffer),
}

/// Rejected outbound Offer with the negotiated session safely returned to ready state.
pub struct RejectedOutboundSifOffer {
    session: ReadySifProtectedSession,
    offer: SifProtectedFileOffer,
    response: SifProtectedFileOfferResponse,
}

impl RejectedOutboundSifOffer {
    /// Exact Offer the peer rejected.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Authenticated rejection response, including its bounded reason.
    pub fn response(&self) -> &SifProtectedFileOfferResponse {
        &self.response
    }

    /// Recover the negotiated idle session after confirmed rejection.
    pub fn into_ready_session(self) -> ReadySifProtectedSession {
        self.session
    }
}

/// Accepted outbound transfer with a contiguous confirmed-content frontier.
pub struct OutboundSifStreaming {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    confirmed_content_bytes: u64,
}

impl OutboundSifStreaming {
    /// Exact accepted Offer governing this content stream.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Content bytes whose sealed Chunk envelopes the transport confirmed sent.
    pub const fn confirmed_content_bytes(&self) -> u64 {
        self.confirmed_content_bytes
    }

    /// Seal the next contiguous content Chunk without yet advancing the confirmed frontier.
    ///
    /// The caller supplies bytes only; the protocol offset is derived from the confirmed
    /// frontier so application code cannot create a gap or overlap through this API.
    pub fn prepare_next_chunk(
        mut self,
        data: Vec<u8>,
    ) -> Result<PreparedOutboundSifChunk, SifTransferFlowError> {
        let chunk = SifProtectedFileChunk::new(&self.offer, self.confirmed_content_bytes, data)?;
        let content_end = self
            .confirmed_content_bytes
            .checked_add(chunk.data().len() as u64)
            .ok_or(SifTransferFlowError::ContentFrontierOverflow)?;
        let envelope = self.channel.seal_chunk_for_offer(&chunk, &self.offer)?;
        Ok(PreparedOutboundSifChunk {
            channel: self.channel,
            offer: self.offer,
            envelope,
            content_start: self.confirmed_content_bytes,
            content_end,
        })
    }

    /// Seal Complete only when every declared content byte was transport-confirmed.
    pub fn prepare_complete(
        mut self,
    ) -> Result<PreparedOutboundSifComplete, SifTransferFlowError> {
        if self.confirmed_content_bytes != self.offer.size() {
            return Err(SifTransferFlowError::ContentNotFullyConfirmed {
                confirmed: self.confirmed_content_bytes,
                expected: self.offer.size(),
            });
        }
        let complete = SifProtectedFileComplete::new(&self.offer)?;
        let envelope = self
            .channel
            .seal_complete_for_offer(&complete, &self.offer)?;
        Ok(PreparedOutboundSifComplete {
            channel: self.channel,
            offer: self.offer,
            envelope,
        })
    }
}

/// One outbound content Chunk sealed at the next exact offset but not yet confirmed sent.
pub struct PreparedOutboundSifChunk {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    envelope: Vec<u8>,
    content_start: u64,
    content_end: u64,
}

impl PreparedOutboundSifChunk {
    /// Sealed bytes the transport must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Inclusive start offset of file content in this Chunk.
    pub const fn content_start(&self) -> u64 {
        self.content_start
    }

    /// Exclusive end offset of file content in this Chunk.
    pub const fn content_end(&self) -> u64 {
        self.content_end
    }

    /// Number of file-content bytes represented by this prepared Chunk.
    pub const fn content_len(&self) -> u64 {
        self.content_end - self.content_start
    }

    /// Advance the contiguous sender frontier only after transport success.
    pub fn confirm_sent(self) -> OutboundSifStreaming {
        OutboundSifStreaming {
            channel: self.channel,
            offer: self.offer,
            confirmed_content_bytes: self.content_end,
        }
    }

    /// Consume an ambiguously failed Chunk send into a terminal uncertainty record.
    ///
    /// No retry state is returned because the receiver may already have accepted this
    /// exact Chunk even though the sender observed an error.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        SifTransferTransportUncertain::new(
            SifTransportUncertainPhase::Chunk,
            self.offer,
            self.content_end,
        )
    }
}

/// Outbound Complete marker sealed only after all content Chunks were confirmed sent.
pub struct PreparedOutboundSifComplete {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    envelope: Vec<u8>,
}

impl PreparedOutboundSifComplete {
    /// Sealed Complete envelope the transport must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Confirm the Complete envelope was reported sent.
    ///
    /// The resulting state intentionally does not return to Ready: portable receiver
    /// custody evidence is the next missing closure boundary and should be integrated
    /// before the same protected channel is recycled for another release.
    pub fn confirm_sent(self) -> OutboundSifCompleteSent {
        OutboundSifCompleteSent {
            channel: self.channel,
            offer: self.offer,
        }
    }

    /// Consume an ambiguously failed Complete send into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        let expected = self.offer.size();
        SifTransferTransportUncertain::new(
            SifTransportUncertainPhase::Complete,
            self.offer,
            expected,
        )
    }
}

/// Sender state after confirmed Complete, intentionally waiting for receipt integration.
pub struct OutboundSifCompleteSent {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
}

impl OutboundSifCompleteSent {
    /// Exact completed Offer for which receiver custody evidence is now expected.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Exact authenticated SIF profile under which the transfer completed.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.channel.profile_digest()
    }
}

/// Inbound Offer waiting for the local application to Accept or Reject.
pub struct InboundSifOfferPending {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
}

impl InboundSifOfferPending {
    /// Exact authenticated Offer awaiting a local decision.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Create private receive staging first, then seal an Accept response.
    ///
    /// If staging cannot begin, no Accept envelope is produced. The returned prepared
    /// state still requires transport confirmation before content may be processed.
    pub fn prepare_accept(
        mut self,
        receive_directory: &Path,
    ) -> Result<PreparedInboundSifAccept, SifTransferFlowError> {
        let runtime = SifReceiveRuntime::begin(self.offer.clone(), receive_directory)?;
        let response = SifProtectedFileOfferResponse::accept(&self.offer)?;
        let envelope = self
            .channel
            .seal_response_for_offer(&response, &self.offer)?;
        Ok(PreparedInboundSifAccept {
            channel: self.channel,
            offer: self.offer,
            runtime,
            envelope,
        })
    }

    /// Seal a bounded Reject response without unlocking content receive authority.
    pub fn prepare_reject(
        mut self,
        reason: impl Into<String>,
    ) -> Result<PreparedInboundSifReject, SifTransferFlowError> {
        let response = SifProtectedFileOfferResponse::reject(&self.offer, reason)?;
        let envelope = self
            .channel
            .seal_response_for_offer(&response, &self.offer)?;
        Ok(PreparedInboundSifReject {
            channel: self.channel,
            offer: self.offer,
            response,
            envelope,
        })
    }
}

/// Inbound Accept sealed after staging succeeded but not yet transport-confirmed.
pub struct PreparedInboundSifAccept {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    runtime: SifReceiveRuntime,
    envelope: Vec<u8>,
}

impl PreparedInboundSifAccept {
    /// Sealed Accept envelope the transport must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Confirm the Accept was sent and unlock exact content receive processing.
    pub fn confirm_sent(self) -> InboundSifReceiving {
        InboundSifReceiving {
            channel: self.channel,
            offer: self.offer,
            runtime: self.runtime,
        }
    }

    /// Consume an ambiguously failed Accept send into terminal uncertainty.
    ///
    /// Dropping this state also drops/cleans private staging. No receiving state is
    /// returned because the sender may or may not have observed the Accept.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        SifTransferTransportUncertain::new(
            SifTransportUncertainPhase::Accept,
            self.offer,
            0,
        )
    }
}

/// Inbound Reject sealed but not yet transport-confirmed.
pub struct PreparedInboundSifReject {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    response: SifProtectedFileOfferResponse,
    envelope: Vec<u8>,
}

impl PreparedInboundSifReject {
    /// Sealed Reject envelope the transport must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Authenticated rejection semantics carried by this envelope.
    pub fn response(&self) -> &SifProtectedFileOfferResponse {
        &self.response
    }

    /// Confirm Reject send and safely return to the negotiated idle session.
    pub fn confirm_sent(self) -> ReadySifProtectedSession {
        ReadySifProtectedSession {
            inner: self.channel,
        }
    }

    /// Consume an ambiguously failed Reject send into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        SifTransferTransportUncertain::new(
            SifTransportUncertainPhase::Reject,
            self.offer,
            0,
        )
    }
}

/// Receiver state unlocked only after local staging succeeded and Accept was sent.
pub struct InboundSifReceiving {
    channel: NegotiatedSifProtectedFileChannel,
    offer: SifProtectedFileOffer,
    runtime: SifReceiveRuntime,
}

impl InboundSifReceiving {
    /// Exact accepted Offer governing this receive state.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Content bytes jointly accepted by semantic verification and private disk staging.
    pub fn received_bytes(&self) -> u64 {
        self.runtime.received_bytes()
    }

    /// Consume the receive state while accepting one exact next Chunk envelope.
    ///
    /// Any carrier, semantic, ordering, integrity, or disk-staging failure consumes the
    /// whole state and prevents continuation from a split frontier.
    pub fn open_next_chunk(
        self,
        envelope: &[u8],
    ) -> Result<Self, SifTransferFlowError> {
        let Self {
            mut channel,
            offer,
            runtime,
        } = self;
        let chunk = channel.open_chunk_for_offer(envelope, &offer)?;
        let runtime = runtime.accept_chunk(&chunk)?;
        Ok(Self {
            channel,
            offer,
            runtime,
        })
    }

    /// Consume the receive state on the exact Offer-bound Complete marker.
    pub fn finish_with_complete(
        self,
        envelope: &[u8],
    ) -> Result<InboundSifReceiveTerminal, SifTransferFlowError> {
        let Self {
            mut channel,
            offer,
            runtime,
        } = self;
        let complete = channel.open_complete_for_offer(envelope, &offer)?;
        let observation = runtime.finish_with_complete(&complete)?;
        Ok(InboundSifReceiveTerminal {
            session: ReadySifProtectedSession { inner: channel },
            offer,
            observation,
        })
    }
}

/// Terminal receiver observation after a valid Complete marker.
pub struct InboundSifReceiveTerminal {
    session: ReadySifProtectedSession,
    offer: SifProtectedFileOffer,
    observation: SifReceiveRuntimeTerminal,
}

impl InboundSifReceiveTerminal {
    /// Exact Offer whose receive attempt reached a terminal observation.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Typed semantic+persistence terminal observation for receipt generation.
    pub fn observation(&self) -> &SifReceiveRuntimeTerminal {
        &self.observation
    }

    /// Consume terminal state into the reusable session and custody observation.
    pub fn into_parts(self) -> (ReadySifProtectedSession, SifReceiveRuntimeTerminal) {
        (self.session, self.observation)
    }
}

/// Phase in which an outbound/inbound control or content envelope became transport-uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifTransportUncertainPhase {
    /// Outbound Offer envelope.
    Offer,
    /// Inbound Accept response envelope.
    Accept,
    /// Inbound Reject response envelope.
    Reject,
    /// Outbound content Chunk envelope.
    Chunk,
    /// Outbound Complete envelope.
    Complete,
}

/// Terminal state for a transport operation whose delivery may have partially occurred.
///
/// This intentionally retains no negotiated channel, so application code cannot blindly
/// retry or start another protected transfer while the peer's phase is unknown.
pub struct SifTransferTransportUncertain {
    phase: SifTransportUncertainPhase,
    offer: SifProtectedFileOffer,
    content_bytes_may_have_been_confirmed_through: u64,
}

impl SifTransferTransportUncertain {
    fn new(
        phase: SifTransportUncertainPhase,
        offer: SifProtectedFileOffer,
        content_bytes_may_have_been_confirmed_through: u64,
    ) -> Self {
        Self {
            phase,
            offer,
            content_bytes_may_have_been_confirmed_through,
        }
    }

    /// Protocol phase whose transport result became ambiguous.
    pub const fn phase(&self) -> SifTransportUncertainPhase {
        self.phase
    }

    /// Exact Offer associated with the uncertain operation.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Conservative content frontier potentially reached by the peer.
    ///
    /// For Chunk uncertainty this is the attempted Chunk end. For Complete it is the
    /// full declared size. Offer/Accept/Reject carry no file-content bytes and report 0.
    pub const fn content_bytes_may_have_been_confirmed_through(&self) -> u64 {
        self.content_bytes_may_have_been_confirmed_through
    }
}

/// Fail-closed SIF transfer-phase errors.
#[derive(Debug, Error)]
pub enum SifTransferFlowError {
    /// Authenticated capability negotiation or protected semantic carrier failed.
    #[error(transparent)]
    Negotiation(#[from] SifNegotiationError),
    /// Ledger semantic construction/validation failed while building phase messages.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Joined semantic+filesystem receive runtime failed.
    #[error(transparent)]
    ReceiveRuntime(#[from] SifReceiveRuntimeError),
    /// Sender content frontier arithmetic overflowed.
    #[error("SIF sender content frontier overflow")]
    ContentFrontierOverflow,
    /// Complete was requested before every declared content byte was confirmed sent.
    #[error("cannot complete SIF transfer: confirmed {confirmed} of {expected} content bytes")]
    ContentNotFullyConfirmed {
        /// Transport-confirmed content bytes.
        confirmed: u64,
        /// Exact file size declared by the Offer.
        expected: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, SessionTranscriptBinding, SifDeliveryDisposition,
        SignatureSuite, sif_file_result_digest,
    };

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn pending_pair() -> (PendingSifProtectedSession, PendingSifProtectedSession) {
        let mut host = PendingSifProtectedSession::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = PendingSifProtectedSession::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    fn ready_pair() -> (ReadySifProtectedSession, ReadySifProtectedSession) {
        let (mut host, mut viewer) = pending_pair();
        let host_cap = host.seal_local_capability().unwrap();
        let viewer_cap = viewer.seal_local_capability().unwrap();
        let host = host.accept_peer_capability(&viewer_cap).unwrap();
        let viewer = viewer.accept_peer_capability(&host_cap).unwrap();
        (host, viewer)
    }

    fn offer_for(payload: &[u8]) -> SifProtectedFileOffer {
        let content_hash = *blake3::hash(payload).as_bytes();
        let result_digest =
            sif_file_result_digest("evidence.bin", payload.len() as u64, content_hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(1),
            7,
            [0x22; 32],
            result_digest,
            "evidence.bin",
            payload.len() as u64,
            content_hash,
        )
        .unwrap()
    }

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-sif-phase-flow-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn accepted_streaming_pair(
        payload: &[u8],
    ) -> (OutboundSifStreaming, InboundSifReceiving) {
        let offer = offer_for(payload);
        let (host, viewer) = ready_pair();
        let prepared_offer = host.prepare_outbound_offer(offer.clone()).unwrap();
        let offer_envelope = prepared_offer.envelope().to_vec();
        let awaiting = prepared_offer.confirm_sent();
        let inbound_pending = viewer.open_inbound_offer(&offer_envelope).unwrap();
        let dir = temp_dir();
        let prepared_accept = inbound_pending.prepare_accept(&dir).unwrap();
        let accept_envelope = prepared_accept.envelope().to_vec();
        let receiving = prepared_accept.confirm_sent();
        let outcome = awaiting.open_response(&accept_envelope).unwrap();
        let streaming = match outcome {
            OutboundSifOfferOutcome::Accepted(streaming) => streaming,
            OutboundSifOfferOutcome::Rejected(_) => panic!("expected Accept"),
        };
        // Keep the receive directory alive for the caller; it can be recovered from
        // the Offer basename's parent only through test-owned bookkeeping, so leak the
        // temporary directory here and let the process temp cleaner handle this small
        // fixture. The full terminal test below performs explicit cleanup.
        std::mem::forget(dir);
        (streaming, receiving)
    }

    #[test]
    fn rejection_never_unlocks_chunk_streaming_and_returns_ready_session() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let (host, viewer) = ready_pair();
        let prepared_offer = host.prepare_outbound_offer(offer.clone()).unwrap();
        let offer_envelope = prepared_offer.envelope().to_vec();
        let awaiting = prepared_offer.confirm_sent();
        let pending = viewer.open_inbound_offer(&offer_envelope).unwrap();
        let prepared_reject = pending.prepare_reject("local policy denied").unwrap();
        let reject_envelope = prepared_reject.envelope().to_vec();
        let _viewer_ready = prepared_reject.confirm_sent();
        let outcome = awaiting.open_response(&reject_envelope).unwrap();
        match outcome {
            OutboundSifOfferOutcome::Rejected(rejected) => {
                assert_eq!(rejected.response().reason(), Some("local policy denied"));
                let _host_ready = rejected.into_ready_session();
            }
            OutboundSifOfferOutcome::Accepted(_) => panic!("Reject must not unlock streaming"),
        }
    }

    #[test]
    fn complete_is_refused_until_every_content_byte_is_transport_confirmed() {
        let payload = b"abcdefghij";
        let (streaming, _receiving) = accepted_streaming_pair(payload);
        assert!(matches!(
            streaming.prepare_complete(),
            Err(SifTransferFlowError::ContentNotFullyConfirmed {
                confirmed: 0,
                expected: 10,
            })
        ));
    }

    #[test]
    fn sender_derives_contiguous_chunk_offsets_from_confirmed_frontier() {
        let payload = b"abcdefghij";
        let (streaming, _receiving) = accepted_streaming_pair(payload);
        let first = streaming.prepare_next_chunk(b"abcd".to_vec()).unwrap();
        assert_eq!(first.content_start(), 0);
        assert_eq!(first.content_end(), 4);
        let streaming = first.confirm_sent();
        assert_eq!(streaming.confirmed_content_bytes(), 4);
        let second = streaming.prepare_next_chunk(b"efghij".to_vec()).unwrap();
        assert_eq!(second.content_start(), 4);
        assert_eq!(second.content_end(), 10);
    }

    #[test]
    fn ambiguous_chunk_send_becomes_terminal_uncertainty_without_retry_state() {
        let payload = b"abcdefghij";
        let (streaming, _receiving) = accepted_streaming_pair(payload);
        let prepared = streaming.prepare_next_chunk(b"abcd".to_vec()).unwrap();
        let uncertain = prepared.transport_uncertain();
        assert_eq!(uncertain.phase(), SifTransportUncertainPhase::Chunk);
        assert_eq!(
            uncertain.content_bytes_may_have_been_confirmed_through(),
            4
        );
    }

    #[cfg(unix)]
    #[test]
    fn full_negotiated_phase_gated_chain_reaches_durable_positive_receipt() {
        let payload = b"abcdefghijklmnop";
        let offer = offer_for(payload);
        let (host, viewer) = ready_pair();

        let prepared_offer = host.prepare_outbound_offer(offer.clone()).unwrap();
        let offer_envelope = prepared_offer.envelope().to_vec();
        let awaiting = prepared_offer.confirm_sent();
        let inbound_pending = viewer.open_inbound_offer(&offer_envelope).unwrap();

        let dir = temp_dir();
        let final_path = dir.join(offer.display_name());
        let prepared_accept = inbound_pending.prepare_accept(&dir).unwrap();
        assert!(!final_path.exists());
        let accept_envelope = prepared_accept.envelope().to_vec();
        let mut receiving = prepared_accept.confirm_sent();
        let outcome = awaiting.open_response(&accept_envelope).unwrap();
        let mut streaming = match outcome {
            OutboundSifOfferOutcome::Accepted(streaming) => streaming,
            OutboundSifOfferOutcome::Rejected(_) => panic!("expected Accept"),
        };

        for bytes in [&payload[..6], &payload[6..]] {
            let prepared_chunk = streaming.prepare_next_chunk(bytes.to_vec()).unwrap();
            let chunk_envelope = prepared_chunk.envelope().to_vec();
            streaming = prepared_chunk.confirm_sent();
            receiving = receiving.open_next_chunk(&chunk_envelope).unwrap();
        }
        assert_eq!(streaming.confirmed_content_bytes(), payload.len() as u64);
        assert_eq!(receiving.received_bytes(), payload.len() as u64);

        let prepared_complete = streaming.prepare_complete().unwrap();
        let complete_envelope = prepared_complete.envelope().to_vec();
        let complete_sent = prepared_complete.confirm_sent();
        assert_eq!(complete_sent.offer(), &offer);
        let terminal = receiving.finish_with_complete(&complete_envelope).unwrap();
        let (_viewer_ready, observation) = terminal.into_parts();
        let durable = match observation {
            SifReceiveRuntimeTerminal::DurableVerified(durable) => durable,
            other => panic!("expected durable verified custody, got {other:?}"),
        };
        assert_eq!(std::fs::read(&final_path).unwrap(), payload);

        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let binding = durable
            .into_delivery_receipt_binding(
                session,
                SignatureSuite::Ed25519Rfc8032,
                &[0x55; 32],
                1_780_000_000_600,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        assert_eq!(binding.disposition(), SifDeliveryDisposition::PersistedVerified);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
