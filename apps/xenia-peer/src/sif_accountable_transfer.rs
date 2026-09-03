// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Full accountable SIF protected-file lifecycle.
//!
//! This is the public application surface above capability negotiation, transfer-phase
//! typestate, crash-durable receive custody and the receiver-signed custody lane.
//! Lower transfer/custody channels remain crate-private so application code cannot skip
//! Offer acceptance, transport confirmation, durable custody, or receiver signature
//! verification.
//!
//! v0.1 deliberately permits at most one *completed* protected release per negotiated
//! accountable SIF sub-session. A rejected Offer may return to Ready because no content
//! authority was unlocked. Once a release reaches Complete/custody, both peers retire
//! the protected sub-session after the signed custody exchange. A later protected
//! release must perform fresh SIF capability negotiation. This conservative rule avoids
//! stale phase/replay ambiguity while the live-routing integration is still pre-alpha.

use std::path::Path;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    CURRENT_EVIDENCE_CRYPTO_MANIFEST, Ed25519EvidenceSignatureBackend, EvidenceCryptoManifest,
    EvidenceSignatureBackend, SessionTranscriptBinding, SifDeliveryDisposition,
    SifDeliveryReceipt, SifDeliveryReceiptBinding, SifProtectedFileOffer,
    sign_sif_delivery_receipt_ed25519,
};
use xenia_peer_core::SifProtectedFileWireRole;

use crate::sif_custody_wire::{
    SifCustodyObservationMessage, SifCustodySemanticChannel, SifCustodySemanticError,
    VerifiedSifCustodyObservation,
};
use crate::sif_transfer_flow::{
    InboundSifOfferPending, InboundSifReceiveTerminal, InboundSifReceiving,
    OutboundSifAwaitingResponse, OutboundSifCompleteSent, OutboundSifOfferOutcome,
    OutboundSifStreaming, PendingSifProtectedSession, PreparedInboundSifAccept,
    PreparedInboundSifReject, PreparedOutboundSifChunk, PreparedOutboundSifComplete,
    PreparedOutboundSifOffer, ReadySifProtectedSession, RejectedOutboundSifOffer,
    SifTransferFlowError, SifTransferTransportUncertain,
};

/// Pre-negotiation accountable SIF session.
pub struct PendingAccountableSifSession {
    transfer: PendingSifProtectedSession,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PendingAccountableSifSession {
    /// Create a fresh accountable SIF sub-session for an authenticated Xenia session.
    pub fn new(
        role: SifProtectedFileWireRole,
        session: SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Self {
        Self {
            transfer: PendingSifProtectedSession::new(role),
            custody: SifCustodySemanticChannel::new(role),
            session,
            manifest,
        }
    }

    /// Deterministic constructor for qualification tests.
    pub fn with_fixture(
        role: SifProtectedFileWireRole,
        source_id: [u8; 8],
        epoch: u8,
        session: SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Self {
        Self {
            transfer: PendingSifProtectedSession::with_fixture(role, source_id, epoch),
            custody: SifCustodySemanticChannel::with_fixture(role, source_id, epoch),
            session,
            manifest,
        }
    }

    /// Endpoint role fixed for transfer and custody domains.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.transfer.role()
    }

    /// Authenticated Xenia session transcript used by eventual custody evidence.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Install one explicit control key into transfer/capability/custody domains.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.transfer.install_control_key(key);
        self.custody.install_control_key(key);
    }

    /// Install the transcript-derived control schedule.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.transfer.install_schedule(schedule);
        self.custody.install_control_key(schedule.control);
    }

    /// Seal this endpoint's exact protected-transfer capability profile.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, AccountableSifError> {
        Ok(self.transfer.seal_local_capability()?)
    }

    /// Consume pending state after exact peer capability authentication.
    pub fn accept_peer_capability(
        self,
        envelope: &[u8],
    ) -> Result<ReadyAccountableSifSession, AccountableSifError> {
        Ok(ReadyAccountableSifSession {
            transfer: self.transfer.accept_peer_capability(envelope)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }
}

/// Negotiated accountable SIF sub-session with no active protected release.
pub struct ReadyAccountableSifSession {
    transfer: ReadySifProtectedSession,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl ReadyAccountableSifSession {
    /// Authenticated exact protected-transfer profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.transfer.profile_digest()
    }

    /// Authenticated Xenia session transcript used for custody closure.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Rotate the negotiated control key under the same semantic profile.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.transfer.install_rekey_keys(keys);
        self.custody.install_control_key(keys.control);
    }

    /// Prepare one outbound protected Offer. No content API exists in this state.
    pub fn prepare_outbound_offer(
        self,
        offer: SifProtectedFileOffer,
    ) -> Result<PreparedAccountableOutboundOffer, AccountableSifError> {
        Ok(PreparedAccountableOutboundOffer {
            transfer: self.transfer.prepare_outbound_offer(offer)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }

    /// Open one authenticated inbound Offer and enter local decision state.
    pub fn open_inbound_offer(
        self,
        envelope: &[u8],
    ) -> Result<AccountableInboundOfferPending, AccountableSifError> {
        Ok(AccountableInboundOfferPending {
            transfer: self.transfer.open_inbound_offer(envelope)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }
}

/// Outbound Offer sealed but not yet transport-confirmed.
pub struct PreparedAccountableOutboundOffer {
    transfer: PreparedOutboundSifOffer,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PreparedAccountableOutboundOffer {
    /// Exact Offer represented by the prepared envelope.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.transfer.offer()
    }

    /// Sealed bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.transfer.envelope()
    }

    /// Advance only after the carrier reports the complete envelope sent.
    pub fn confirm_sent(self) -> AccountableOutboundAwaitingResponse {
        AccountableOutboundAwaitingResponse {
            transfer: self.transfer.confirm_sent(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }

    /// Consume ambiguous carrier result into terminal uncertainty with no retry state.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.transfer.transport_uncertain()
    }
}

/// Confirmed Offer awaiting exact peer Accept/Reject.
pub struct AccountableOutboundAwaitingResponse {
    transfer: OutboundSifAwaitingResponse,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableOutboundAwaitingResponse {
    /// Exact Offer awaiting an authenticated peer decision.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.transfer.offer()
    }

    /// Open the peer response. Only Accept creates a streaming state.
    pub fn open_response(
        self,
        envelope: &[u8],
    ) -> Result<AccountableOutboundOfferOutcome, AccountableSifError> {
        match self.transfer.open_response(envelope)? {
            OutboundSifOfferOutcome::Accepted(transfer) => {
                Ok(AccountableOutboundOfferOutcome::Accepted(
                    AccountableOutboundStreaming {
                        transfer,
                        custody: self.custody,
                        session: self.session,
                        manifest: self.manifest,
                    },
                ))
            }
            OutboundSifOfferOutcome::Rejected(rejected) => {
                Ok(AccountableOutboundOfferOutcome::Rejected(
                    RejectedAccountableOutboundOffer {
                        rejected,
                        custody: self.custody,
                        session: self.session,
                        manifest: self.manifest,
                    },
                ))
            }
        }
    }
}

/// Authenticated peer decision for one outbound Offer.
pub enum AccountableOutboundOfferOutcome {
    /// Exact Offer accepted; protected content may now be prepared.
    Accepted(AccountableOutboundStreaming),
    /// Exact Offer rejected; no content authority was unlocked.
    Rejected(RejectedAccountableOutboundOffer),
}

/// Rejected Offer. Since no protected content was released, the sub-session may return Ready.
pub struct RejectedAccountableOutboundOffer {
    rejected: RejectedOutboundSifOffer,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl RejectedAccountableOutboundOffer {
    /// Authenticated rejected Offer.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.rejected.offer()
    }

    /// Recover Ready after a confirmed Reject and zero content release.
    pub fn into_ready(self) -> ReadyAccountableSifSession {
        ReadyAccountableSifSession {
            transfer: self.rejected.into_ready_session(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }
}

/// Accepted outbound release with a contiguous transport-confirmed content frontier.
pub struct AccountableOutboundStreaming {
    transfer: OutboundSifStreaming,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableOutboundStreaming {
    /// Transport-confirmed protected content bytes.
    pub const fn confirmed_content_bytes(&self) -> u64 {
        self.transfer.confirmed_content_bytes()
    }

    /// Prepare the next contiguous Chunk; its offset is derived by the phase machine.
    pub fn prepare_next_chunk(
        self,
        data: Vec<u8>,
    ) -> Result<PreparedAccountableOutboundChunk, AccountableSifError> {
        Ok(PreparedAccountableOutboundChunk {
            transfer: self.transfer.prepare_next_chunk(data)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }

    /// Prepare Complete only after every declared byte was transport-confirmed.
    pub fn prepare_complete(self) -> Result<PreparedAccountableOutboundComplete, AccountableSifError> {
        Ok(PreparedAccountableOutboundComplete {
            transfer: self.transfer.prepare_complete()?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }
}

/// One sealed outbound Chunk awaiting carrier confirmation.
pub struct PreparedAccountableOutboundChunk {
    transfer: PreparedOutboundSifChunk,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PreparedAccountableOutboundChunk {
    /// Sealed Chunk bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.transfer.envelope()
    }

    /// Exact file-content range represented by this Chunk.
    pub const fn content_range(&self) -> (u64, u64) {
        (self.transfer.content_start(), self.transfer.content_end())
    }

    /// Advance the sender frontier after confirmed transport success.
    pub fn confirm_sent(self) -> AccountableOutboundStreaming {
        AccountableOutboundStreaming {
            transfer: self.transfer.confirm_sent(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }

    /// Consume ambiguous carrier result into terminal uncertainty without retry authority.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.transfer.transport_uncertain()
    }
}

/// Sealed Complete marker awaiting carrier confirmation.
pub struct PreparedAccountableOutboundComplete {
    transfer: PreparedOutboundSifComplete,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PreparedAccountableOutboundComplete {
    /// Sealed Complete bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.transfer.envelope()
    }

    /// Enter custody-waiting state after confirmed Complete transport.
    pub fn confirm_sent(self) -> AccountableOutboundAwaitingCustody {
        AccountableOutboundAwaitingCustody {
            transfer: self.transfer.confirm_sent(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }

    /// Consume ambiguous Complete transport into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.transfer.transport_uncertain()
    }
}

/// Sender state after Complete, waiting for independently verifiable receiver custody.
pub struct AccountableOutboundAwaitingCustody {
    transfer: OutboundSifCompleteSent,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableOutboundAwaitingCustody {
    /// Exact completed Offer whose remote custody must be proven.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.transfer.offer()
    }

    /// Open and cryptographically verify the receiver's custody envelope.
    ///
    /// This consumes the completed transfer state. No reusable SIF sub-session is
    /// returned even on success: v0.1 requires fresh capability negotiation for the
    /// next protected release.
    pub fn verify_custody(
        mut self,
        envelope: &[u8],
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<ClosedAccountableOutboundRelease, AccountableSifError> {
        let message = self.custody.open_observation(envelope)?;
        let verified = message.verify_for_sender_state(
            self.transfer.offer(),
            self.session,
            self.manifest,
            backend,
            trusted_receiver_public_key,
        )?;
        Ok(ClosedAccountableOutboundRelease { verified })
    }
}

/// Sender-verified remote custody closure for one protected release.
pub struct ClosedAccountableOutboundRelease {
    verified: VerifiedSifCustodyObservation,
}

impl ClosedAccountableOutboundRelease {
    /// Receiver's cryptographically verified disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.verified.disposition()
    }

    /// Exact verified delivery binding reconstructed from sender-owned context.
    pub fn binding(&self) -> &SifDeliveryReceiptBinding {
        self.verified.binding()
    }

    /// Consume closure into its canonical verified delivery statement.
    pub fn into_binding(self) -> SifDeliveryReceiptBinding {
        self.verified.into_binding()
    }
}

/// Authenticated inbound Offer awaiting local Accept/Reject.
pub struct AccountableInboundOfferPending {
    transfer: InboundSifOfferPending,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableInboundOfferPending {
    /// Exact authenticated Offer awaiting local policy/custody decision.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.transfer.offer()
    }

    /// Create private staging first, then prepare Accept.
    pub fn prepare_accept(
        self,
        receive_directory: &Path,
    ) -> Result<PreparedAccountableInboundAccept, AccountableSifError> {
        Ok(PreparedAccountableInboundAccept {
            transfer: self.transfer.prepare_accept(receive_directory)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }

    /// Prepare a bounded Reject. No content receive authority is unlocked.
    pub fn prepare_reject(
        self,
        reason: impl Into<String>,
    ) -> Result<PreparedAccountableInboundReject, AccountableSifError> {
        Ok(PreparedAccountableInboundReject {
            transfer: self.transfer.prepare_reject(reason)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }
}

/// Sealed Accept awaiting carrier confirmation.
pub struct PreparedAccountableInboundAccept {
    transfer: PreparedInboundSifAccept,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PreparedAccountableInboundAccept {
    /// Sealed Accept bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.transfer.envelope()
    }

    /// Unlock protected content receive processing after confirmed Accept transport.
    pub fn confirm_sent(self) -> AccountableInboundReceiving {
        AccountableInboundReceiving {
            transfer: self.transfer.confirm_sent(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }

    /// Consume ambiguous Accept transport into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.transfer.transport_uncertain()
    }
}

/// Sealed Reject awaiting carrier confirmation.
pub struct PreparedAccountableInboundReject {
    transfer: PreparedInboundSifReject,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl PreparedAccountableInboundReject {
    /// Sealed Reject bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.transfer.envelope()
    }

    /// Confirm Reject and safely return Ready because no content was authorized.
    pub fn confirm_sent(self) -> ReadyAccountableSifSession {
        ReadyAccountableSifSession {
            transfer: self.transfer.confirm_sent(),
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        }
    }

    /// Consume ambiguous Reject transport into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.transfer.transport_uncertain()
    }
}

/// Receiver state unlocked only after staging exists and Accept was confirmed sent.
pub struct AccountableInboundReceiving {
    transfer: InboundSifReceiving,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableInboundReceiving {
    /// Joint semantic+disk content frontier.
    pub fn received_bytes(&self) -> u64 {
        self.transfer.received_bytes()
    }

    /// Consume state while accepting one exact next protected Chunk envelope.
    pub fn open_next_chunk(self, envelope: &[u8]) -> Result<Self, AccountableSifError> {
        Ok(Self {
            transfer: self.transfer.open_next_chunk(envelope)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }

    /// Consume exact Complete into a terminal local custody observation.
    pub fn finish_with_complete(
        self,
        envelope: &[u8],
    ) -> Result<AccountableInboundCustodyPending, AccountableSifError> {
        Ok(AccountableInboundCustodyPending {
            terminal: self.transfer.finish_with_complete(envelope)?,
            custody: self.custody,
            session: self.session,
            manifest: self.manifest,
        })
    }
}

/// Receiver terminal observation that must be signed and sent before closure.
pub struct AccountableInboundCustodyPending {
    terminal: InboundSifReceiveTerminal,
    custody: SifCustodySemanticChannel,
    session: SessionTranscriptBinding,
    manifest: EvidenceCryptoManifest,
}

impl AccountableInboundCustodyPending {
    /// Exact Offer whose terminal observation is awaiting signed custody export.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.terminal.offer()
    }

    /// Construct, sign and seal the receiver custody receipt using current Ed25519 profile.
    ///
    /// The lower reusable transfer session is deliberately discarded here. If receipt
    /// construction fails (including post-publication durability uncertainty), there is
    /// no protected channel reuse. A successful receipt still requires carrier
    /// confirmation before local closure is returned.
    pub fn prepare_ed25519_custody_receipt(
        self,
        signing_key: &SigningKey,
        observed_at_unix_ms: u64,
    ) -> Result<PreparedAccountableCustodyReceipt, AccountableSifError> {
        let offer = self.terminal.offer().clone();
        let (_retired_transfer, observation) = self.terminal.into_parts();
        let receiver_public_key = signing_key.verifying_key().to_bytes();
        let binding = observation.into_delivery_receipt_binding(
            self.session.clone(),
            xenia_ledger::SignatureSuite::Ed25519Rfc8032,
            &receiver_public_key,
            observed_at_unix_ms,
            self.manifest,
        )?;
        let receipt = sign_sif_delivery_receipt_ed25519(binding, signing_key, self.manifest)?;
        let message = SifCustodyObservationMessage::from_signed_receipt(
            &receipt,
            &offer,
            &self.session,
            self.manifest,
        )?;
        let mut custody = self.custody;
        let envelope = custody.seal_observation(&message)?;
        Ok(PreparedAccountableCustodyReceipt {
            receipt,
            offer,
            envelope,
        })
    }
}

/// Signed receiver custody receipt sealed but not yet transport-confirmed.
pub struct PreparedAccountableCustodyReceipt {
    receipt: SifDeliveryReceipt,
    offer: SifProtectedFileOffer,
    envelope: Vec<u8>,
}

impl PreparedAccountableCustodyReceipt {
    /// Exact Offer closed by this receipt.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Portable signed receipt retained for local archive/export.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        &self.receipt
    }

    /// Sealed custody bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Confirm custody receipt transport and close this one-shot accountable sub-session.
    pub fn confirm_sent(self) -> ClosedAccountableInboundRelease {
        ClosedAccountableInboundRelease {
            receipt: self.receipt,
        }
    }

    /// Ambiguous custody-receipt transport is terminal: the sender may already have
    /// verified it, so this API returns no retry or reusable protected channel.
    pub fn transport_uncertain(self) -> AccountableCustodyTransportUncertain {
        AccountableCustodyTransportUncertain { offer: self.offer }
    }
}

/// Receiver-side closure after the signed custody receipt was transport-confirmed.
pub struct ClosedAccountableInboundRelease {
    receipt: SifDeliveryReceipt,
}

impl ClosedAccountableInboundRelease {
    /// Portable signed receiver receipt for archival/accountability use.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        &self.receipt
    }

    /// Receiver-observed terminal disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.receipt.binding().disposition()
    }

    /// Consume closure into the portable signed receipt.
    pub fn into_receipt(self) -> SifDeliveryReceipt {
        self.receipt
    }
}

/// Terminal uncertainty when the custody receipt itself may or may not have arrived.
pub struct AccountableCustodyTransportUncertain {
    offer: SifProtectedFileOffer,
}

impl AccountableCustodyTransportUncertain {
    /// Exact Offer whose receipt-delivery state is unknown.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }
}

/// Fail-closed full-lifecycle errors.
#[derive(Debug, Error)]
pub enum AccountableSifError {
    /// Negotiation/phase/custody preparation failed.
    #[error(transparent)]
    Transfer(#[from] SifTransferFlowError),
    /// Online custody carrier/semantic verification failed.
    #[error(transparent)]
    Custody(#[from] SifCustodySemanticError),
    /// Local receive/custody receipt projection failed.
    #[error(transparent)]
    Receive(#[from] crate::sif_receive_runtime::SifReceiveRuntimeError),
    /// Portable delivery receipt signing/validation failed.
    #[error(transparent)]
    Receipt(#[from] xenia_ledger::SifDeliveryReceiptError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{SifDeliveryReceiptBinding, sif_file_result_digest};

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn session() -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        )
    }

    fn pending_pair() -> (PendingAccountableSifSession, PendingAccountableSifSession) {
        let mut host = PendingAccountableSifSession::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
            session(),
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        );
        let mut viewer = PendingAccountableSifSession::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
            session(),
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    fn ready_pair() -> (ReadyAccountableSifSession, ReadyAccountableSifSession) {
        let (mut host, mut viewer) = pending_pair();
        let host_cap = host.seal_local_capability().unwrap();
        let viewer_cap = viewer.seal_local_capability().unwrap();
        (
            host.accept_peer_capability(&viewer_cap).unwrap(),
            viewer.accept_peer_capability(&host_cap).unwrap(),
        )
    }

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

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-sif-accountable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn rejected_offer_can_return_ready_without_custody_receipt() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let (host, viewer) = ready_pair();
        let prepared = host.prepare_outbound_offer(offer).unwrap();
        let offer_envelope = prepared.envelope().to_vec();
        let awaiting = prepared.confirm_sent();
        let pending = viewer.open_inbound_offer(&offer_envelope).unwrap();
        let rejected = pending.prepare_reject("policy denied").unwrap();
        let envelope = rejected.envelope().to_vec();
        let _viewer_ready = rejected.confirm_sent();
        match awaiting.open_response(&envelope).unwrap() {
            AccountableOutboundOfferOutcome::Rejected(rejected) => {
                let _host_ready = rejected.into_ready();
            }
            AccountableOutboundOfferOutcome::Accepted(_) => panic!("expected rejection"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn full_release_closes_only_after_receiver_receipt_signature_verifies() {
        let payload = b"abcdefghijklmnop";
        let offer = offer_for(payload);
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let receiver_public_key = signing_key.verifying_key().to_bytes();
        let (host, viewer) = ready_pair();

        let prepared_offer = host.prepare_outbound_offer(offer.clone()).unwrap();
        let offer_envelope = prepared_offer.envelope().to_vec();
        let awaiting = prepared_offer.confirm_sent();
        let inbound = viewer.open_inbound_offer(&offer_envelope).unwrap();
        let dir = temp_dir();
        let final_path = dir.join(offer.display_name());
        let accept = inbound.prepare_accept(&dir).unwrap();
        let accept_envelope = accept.envelope().to_vec();
        let mut receiving = accept.confirm_sent();
        let mut streaming = match awaiting.open_response(&accept_envelope).unwrap() {
            AccountableOutboundOfferOutcome::Accepted(streaming) => streaming,
            AccountableOutboundOfferOutcome::Rejected(_) => panic!("expected Accept"),
        };

        for bytes in [&payload[..6], &payload[6..]] {
            let chunk = streaming.prepare_next_chunk(bytes.to_vec()).unwrap();
            let envelope = chunk.envelope().to_vec();
            streaming = chunk.confirm_sent();
            receiving = receiving.open_next_chunk(&envelope).unwrap();
        }

        let complete = streaming.prepare_complete().unwrap();
        let complete_envelope = complete.envelope().to_vec();
        let awaiting_custody = complete.confirm_sent();
        let custody_pending = receiving.finish_with_complete(&complete_envelope).unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), payload);

        let prepared_receipt = custody_pending
            .prepare_ed25519_custody_receipt(&signing_key, 1_780_000_000_800)
            .unwrap();
        let custody_envelope = prepared_receipt.envelope().to_vec();
        assert_eq!(
            prepared_receipt.receipt().binding().disposition(),
            SifDeliveryDisposition::PersistedVerified
        );
        let receiver_closed = prepared_receipt.confirm_sent();
        assert_eq!(receiver_closed.disposition(), SifDeliveryDisposition::PersistedVerified);

        let sender_closed = awaiting_custody
            .verify_custody(
                &custody_envelope,
                &Ed25519EvidenceSignatureBackend,
                &receiver_public_key,
            )
            .unwrap();
        assert_eq!(sender_closed.disposition(), SifDeliveryDisposition::PersistedVerified);
        assert_eq!(sender_closed.binding().release_id(), offer.release_id());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sender_rejects_custody_signature_under_wrong_receiver_key() {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let wrong_key = SigningKey::from_bytes(&[0x45; 32]);
        let offer = offer_for(b"abcde");
        let binding = SifDeliveryReceiptBinding::new(
            offer.release_id(),
            offer.transfer_id(),
            session(),
            offer.sender_release_entry_hash(),
            offer.display_name(),
            offer.size(),
            offer.content_blake3(),
            xenia_ledger::SignatureSuite::Ed25519Rfc8032,
            &signing_key.verifying_key().to_bytes(),
            SifDeliveryDisposition::PersistedVerified,
            offer.size(),
            Some(offer.content_blake3()),
            1_780_000_000_801,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let receipt = sign_sif_delivery_receipt_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let message = SifCustodyObservationMessage::from_signed_receipt(
            &receipt,
            &offer,
            &session(),
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        assert!(message
            .verify_for_sender_state(
                &offer,
                session(),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &wrong_key.verifying_key().to_bytes(),
            )
            .is_err());
    }
}
