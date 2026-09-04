// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-assurance public SIF protected-transfer surface.
//!
//! The underlying accountable phase/custody engine remains crate-private. This wrapper
//! removes its caller-authored Offer entry point: outbound protected transfer can begin
//! only by consuming [`SessionBoundFileOfferAuthority`], which already proves durable
//! release Commit, exact file result, required SIF profile, and exact authenticated
//! session transcript generation.
//!
//! The move-only [`ProfileBoundCommittedFileDisclosure`] is retained across outbound
//! states. Confirmed Chunk sends advance exact byte accounting; ambiguous Chunk sends
//! conservatively charge the whole attempted Chunk before terminalizing. A rejected
//! Offer retires the one-shot release and exposes a zero-byte terminal rather than
//! returning a committed release to Ready.
//!
//! This layer deliberately does not yet eliminate caller-provided Chunk bytes. A child
//! source-ownership tranche must make Xenia own the committed source and construct each
//! Chunk internally before the end-to-end "authorized bytes only" claim is established.

use std::path::Path;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    Ed25519EvidenceSignatureBackend, EvidenceCryptoManifest, EvidenceSignatureBackend,
    FileDisclosureTerminal, ProfileBoundCommittedFileDisclosure, ProfileBoundFileDisclosureError,
    SessionBoundFileOfferAuthority, SessionTranscriptBinding, SifDeliveryDisposition,
    SifDeliveryReceipt, SifDeliveryReceiptBinding,
};
use xenia_peer_core::SifProtectedFileWireRole;

use crate::sif_accountable_transfer::{
    AccountableCustodyTransportUncertain, AccountableInboundCustodyPending,
    AccountableInboundOfferPending, AccountableInboundReceiving,
    AccountableOutboundAwaitingCustody, AccountableOutboundAwaitingResponse,
    AccountableOutboundOfferOutcome, AccountableOutboundStreaming, AccountableSifError,
    ClosedAccountableInboundRelease, ClosedAccountableOutboundRelease,
    PendingAccountableSifSession, PreparedAccountableCustodyReceipt,
    PreparedAccountableInboundAccept, PreparedAccountableInboundReject,
    PreparedAccountableOutboundChunk, PreparedAccountableOutboundComplete,
    PreparedAccountableOutboundOffer, ReadyAccountableSifSession,
    RejectedAccountableOutboundOffer,
};
use crate::sif_transfer_flow::SifTransferTransportUncertain;

/// Pre-negotiation high-assurance SIF session.
pub struct PendingAuthorizedSifSession {
    inner: PendingAccountableSifSession,
}

impl PendingAuthorizedSifSession {
    /// Create a fresh high-assurance SIF sub-session for an authenticated Xenia session.
    pub fn new(
        role: SifProtectedFileWireRole,
        session: SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Self {
        Self {
            inner: PendingAccountableSifSession::new(role, session, manifest),
        }
    }

    /// Endpoint role fixed for this SIF session.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.inner.role()
    }

    /// Authenticated Xenia session transcript used by release/custody evidence.
    pub fn session(&self) -> &SessionTranscriptBinding {
        self.inner.session()
    }

    /// Install one explicit initial control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.inner.install_control_key(key);
    }

    /// Install the transcript-derived control schedule.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.inner.install_schedule(schedule);
    }

    /// Seal this endpoint's exact compiled SIF capability profile.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, AuthorizedSifError> {
        Ok(self.inner.seal_local_capability()?)
    }

    /// Consume pending state after exact peer capability authentication.
    pub fn accept_peer_capability(
        self,
        envelope: &[u8],
    ) -> Result<ReadyAuthorizedSifSession, AuthorizedSifError> {
        Ok(ReadyAuthorizedSifSession {
            inner: self.inner.accept_peer_capability(envelope)?,
        })
    }
}

/// Negotiated high-assurance SIF session with no active protected release.
pub struct ReadyAuthorizedSifSession {
    inner: ReadyAccountableSifSession,
}

impl ReadyAuthorizedSifSession {
    /// Authenticated exact protected-transfer profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.inner.profile_digest()
    }

    /// Authenticated Xenia session transcript generation.
    pub fn session(&self) -> &SessionTranscriptBinding {
        self.inner.session()
    }

    /// Rotate the negotiated control key while idle.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.inner.install_rekey_keys(keys);
    }

    /// Prepare one outbound Offer only from exact durable session/profile/file authority.
    pub fn prepare_outbound_authorized_offer(
        self,
        authority: SessionBoundFileOfferAuthority,
    ) -> Result<PreparedAuthorizedOutboundOffer, AuthorizedSifError> {
        let expected_session = self.inner.session().clone();
        let expected_profile = self.inner.profile_digest();
        let (offer, file, authorized_session) = authority.into_parts();

        if authorized_session != expected_session {
            return Err(AuthorizedSifError::SessionGenerationMismatch);
        }
        if file.required_sif_profile_digest() != expected_profile {
            return Err(AuthorizedSifError::ProfileMismatch);
        }

        Ok(PreparedAuthorizedOutboundOffer {
            inner: self.inner.prepare_outbound_offer(offer)?,
            file,
        })
    }

    /// Open one authenticated inbound Offer and enter local decision state.
    pub fn open_inbound_offer(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedInboundOfferPending, AuthorizedSifError> {
        Ok(AuthorizedInboundOfferPending {
            inner: self.inner.open_inbound_offer(envelope)?,
        })
    }
}

/// Outbound authorized Offer sealed but not yet transport-confirmed.
pub struct PreparedAuthorizedOutboundOffer {
    inner: PreparedAccountableOutboundOffer,
    file: ProfileBoundCommittedFileDisclosure,
}

impl PreparedAuthorizedOutboundOffer {
    /// Exact authority-derived Offer represented by this envelope.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Sealed bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Advance only after the carrier reports the complete Offer envelope sent.
    pub fn confirm_sent(self) -> AuthorizedOutboundAwaitingResponse {
        AuthorizedOutboundAwaitingResponse {
            inner: self.inner.confirm_sent(),
            file: self.file,
        }
    }

    /// Consume ambiguous Offer transport into a zero-content terminal release.
    pub fn transport_uncertain(self) -> AuthorizedOfferTransportUncertain {
        AuthorizedOfferTransportUncertain {
            transport: self.inner.transport_uncertain(),
            terminal: self.file.interrupted(),
        }
    }
}

/// Confirmed authority-derived Offer awaiting exact peer Accept/Reject.
pub struct AuthorizedOutboundAwaitingResponse {
    inner: AccountableOutboundAwaitingResponse,
    file: ProfileBoundCommittedFileDisclosure,
}

impl AuthorizedOutboundAwaitingResponse {
    /// Exact Offer awaiting a peer decision.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Open the authenticated peer response.
    pub fn open_response(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedOutboundOfferOutcome, AuthorizedSifError> {
        match self.inner.open_response(envelope)? {
            AccountableOutboundOfferOutcome::Accepted(inner) => {
                Ok(AuthorizedOutboundOfferOutcome::Accepted(
                    AuthorizedOutboundStreaming {
                        inner,
                        file: self.file,
                    },
                ))
            }
            AccountableOutboundOfferOutcome::Rejected(inner) => {
                Ok(AuthorizedOutboundOfferOutcome::Rejected(
                    RejectedAuthorizedOutboundRelease {
                        inner,
                        file: self.file,
                    },
                ))
            }
        }
    }
}

/// Authenticated peer decision for one durable-authority outbound Offer.
pub enum AuthorizedOutboundOfferOutcome {
    /// Exact Offer accepted; content phase may begin.
    Accepted(AuthorizedOutboundStreaming),
    /// Exact Offer rejected; the committed release is retired rather than reused.
    Rejected(RejectedAuthorizedOutboundRelease),
}

/// Rejected committed release. No Ready session is returned through this API.
pub struct RejectedAuthorizedOutboundRelease {
    inner: RejectedAccountableOutboundOffer,
    file: ProfileBoundCommittedFileDisclosure,
}

impl RejectedAuthorizedOutboundRelease {
    /// Exact Offer the peer rejected.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Consume into the zero-byte terminal that must be recorded in the release journal.
    pub fn into_terminal(self) -> FileDisclosureTerminal {
        self.file.interrupted()
    }
}

/// Accepted outbound release with exact confirmed-byte accounting.
pub struct AuthorizedOutboundStreaming {
    inner: AccountableOutboundStreaming,
    file: ProfileBoundCommittedFileDisclosure,
}

impl AuthorizedOutboundStreaming {
    /// Transport-confirmed protected content bytes.
    pub const fn confirmed_content_bytes(&self) -> u64 {
        self.inner.confirmed_content_bytes()
    }

    /// Bytes charged exactly or conservatively to this durable release.
    pub const fn accounted_content_bytes(&self) -> u64 {
        self.file.emitted_bytes()
    }

    /// Prepare the next contiguous Chunk.
    ///
    /// Caller-supplied bytes remain an explicit temporary gap. A child source-ownership
    /// tranche will remove this parameter from the high-assurance public API.
    pub fn prepare_next_chunk(
        self,
        data: Vec<u8>,
    ) -> Result<PreparedAuthorizedOutboundChunk, AuthorizedSifError> {
        Ok(PreparedAuthorizedOutboundChunk {
            inner: self.inner.prepare_next_chunk(data)?,
            file: self.file,
        })
    }

    /// Prepare Complete only when protocol and durable file accounting agree exactly.
    pub fn prepare_complete(self) -> Result<PreparedAuthorizedOutboundComplete, AuthorizedSifError> {
        if self.inner.confirmed_content_bytes() != self.file.emitted_bytes() {
            return Err(AuthorizedSifError::AccountingFrontierMismatch {
                protocol: self.inner.confirmed_content_bytes(),
                accounted: self.file.emitted_bytes(),
            });
        }
        Ok(PreparedAuthorizedOutboundComplete {
            inner: self.inner.prepare_complete()?,
            file: self.file,
        })
    }
}

/// One sealed outbound Chunk awaiting carrier confirmation.
pub struct PreparedAuthorizedOutboundChunk {
    inner: PreparedAccountableOutboundChunk,
    file: ProfileBoundCommittedFileDisclosure,
}

impl PreparedAuthorizedOutboundChunk {
    /// Sealed Chunk bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Exact file-content range represented by this Chunk.
    pub const fn content_range(&self) -> (u64, u64) {
        self.inner.content_range()
    }

    /// Advance sender state after carrier success and charge the exact content bytes.
    pub fn confirm_sent(mut self) -> Result<AuthorizedOutboundStreaming, AuthorizedSifError> {
        let (start, end) = self.inner.content_range();
        let len = end
            .checked_sub(start)
            .ok_or(AuthorizedSifError::ContentRangeInvariant)?;
        let len = usize::try_from(len).map_err(|_| AuthorizedSifError::ContentRangeInvariant)?;
        self.file.note_emitted(len)?;
        Ok(AuthorizedOutboundStreaming {
            inner: self.inner.confirm_sent(),
            file: self.file,
        })
    }

    /// Conservatively charge an ambiguously transported Chunk and retire the release.
    pub fn transport_uncertain(
        mut self,
    ) -> Result<AuthorizedChunkTransportUncertain, AuthorizedSifError> {
        let (start, end) = self.inner.content_range();
        let len = end
            .checked_sub(start)
            .ok_or(AuthorizedSifError::ContentRangeInvariant)?;
        let len = usize::try_from(len).map_err(|_| AuthorizedSifError::ContentRangeInvariant)?;
        self.file.note_transport_uncertain(len)?;
        Ok(AuthorizedChunkTransportUncertain {
            transport: self.inner.transport_uncertain(),
            terminal: self.file.interrupted(),
        })
    }
}

/// Sealed Complete marker awaiting carrier confirmation.
pub struct PreparedAuthorizedOutboundComplete {
    inner: PreparedAccountableOutboundComplete,
    file: ProfileBoundCommittedFileDisclosure,
}

impl PreparedAuthorizedOutboundComplete {
    /// Sealed Complete bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Enter custody-waiting state after confirmed Complete transport.
    pub fn confirm_sent(self) -> AuthorizedOutboundAwaitingCustody {
        AuthorizedOutboundAwaitingCustody {
            inner: self.inner.confirm_sent(),
            file: self.file,
        }
    }

    /// Complete-control transport ambiguity is terminal, but source verification has not
    /// yet occurred, so no misleading Completed/Partial file terminal is fabricated.
    pub fn transport_uncertain(self) -> AuthorizedCompleteTransportUncertain {
        AuthorizedCompleteTransportUncertain {
            transport: self.inner.transport_uncertain(),
            confirmed_file_bytes: self.file.emitted_bytes(),
        }
    }
}

/// Sender state waiting for independently verifiable receiver custody.
pub struct AuthorizedOutboundAwaitingCustody {
    inner: AccountableOutboundAwaitingCustody,
    file: ProfileBoundCommittedFileDisclosure,
}

impl AuthorizedOutboundAwaitingCustody {
    /// Exact completed Offer whose remote custody must be proven.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Open and verify the receiver custody envelope.
    pub fn verify_custody(
        self,
        envelope: &[u8],
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<ClosedAuthorizedOutboundRelease, AuthorizedSifError> {
        Ok(ClosedAuthorizedOutboundRelease {
            inner: self.inner.verify_custody(
                envelope,
                backend,
                trusted_receiver_public_key,
            )?,
            file: self.file,
        })
    }
}

/// Sender-verified custody closure retaining local file authority for source verification.
pub struct ClosedAuthorizedOutboundRelease {
    inner: ClosedAccountableOutboundRelease,
    file: ProfileBoundCommittedFileDisclosure,
}

impl ClosedAuthorizedOutboundRelease {
    /// Receiver's cryptographically verified disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.inner.disposition()
    }

    /// Exact verified delivery binding reconstructed from sender-owned context.
    pub fn binding(&self) -> &SifDeliveryReceiptBinding {
        self.inner.binding()
    }

    /// Exact carrier-confirmed file bytes retained in local release accounting.
    pub const fn confirmed_file_bytes(&self) -> u64 {
        self.file.emitted_bytes()
    }
}

/// Offer carrier ambiguity with a truthful zero-content terminal.
pub struct AuthorizedOfferTransportUncertain {
    transport: SifTransferTransportUncertain,
    terminal: FileDisclosureTerminal,
}

impl AuthorizedOfferTransportUncertain {
    /// Underlying phase-level transport uncertainty.
    pub fn transport(&self) -> &SifTransferTransportUncertain {
        &self.transport
    }

    /// Zero-content release terminal that must be durably recorded.
    pub const fn terminal(&self) -> FileDisclosureTerminal {
        self.terminal
    }
}

/// Chunk carrier ambiguity with conservative possible-disclosure accounting.
pub struct AuthorizedChunkTransportUncertain {
    transport: SifTransferTransportUncertain,
    terminal: FileDisclosureTerminal,
}

impl AuthorizedChunkTransportUncertain {
    /// Underlying phase-level transport uncertainty.
    pub fn transport(&self) -> &SifTransferTransportUncertain {
        &self.transport
    }

    /// Conservative release terminal that must be durably recorded.
    pub const fn terminal(&self) -> FileDisclosureTerminal {
        self.terminal
    }
}

/// Complete-marker ambiguity after all file bytes were carrier-confirmed.
pub struct AuthorizedCompleteTransportUncertain {
    transport: SifTransferTransportUncertain,
    confirmed_file_bytes: u64,
}

impl AuthorizedCompleteTransportUncertain {
    /// Underlying Complete-phase transport uncertainty.
    pub fn transport(&self) -> &SifTransferTransportUncertain {
        &self.transport
    }

    /// Exact file bytes already carrier-confirmed before Complete was attempted.
    pub const fn confirmed_file_bytes(&self) -> u64 {
        self.confirmed_file_bytes
    }
}

// Receiver wrappers preserve the existing accountable receive/custody semantics while
// preventing the private lower session types from leaking through the public API.

/// Authenticated inbound Offer awaiting local Accept/Reject.
pub struct AuthorizedInboundOfferPending {
    inner: AccountableInboundOfferPending,
}

impl AuthorizedInboundOfferPending {
    /// Exact authenticated Offer awaiting local policy/custody decision.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Create private staging first, then prepare Accept.
    pub fn prepare_accept(
        self,
        receive_directory: &Path,
    ) -> Result<PreparedAuthorizedInboundAccept, AuthorizedSifError> {
        Ok(PreparedAuthorizedInboundAccept {
            inner: self.inner.prepare_accept(receive_directory)?,
        })
    }

    /// Prepare a bounded Reject.
    pub fn prepare_reject(
        self,
        reason: impl Into<String>,
    ) -> Result<PreparedAuthorizedInboundReject, AuthorizedSifError> {
        Ok(PreparedAuthorizedInboundReject {
            inner: self.inner.prepare_reject(reason)?,
        })
    }
}

/// Sealed Accept awaiting carrier confirmation.
pub struct PreparedAuthorizedInboundAccept {
    inner: PreparedAccountableInboundAccept,
}

impl PreparedAuthorizedInboundAccept {
    /// Sealed Accept bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Unlock protected receive processing after confirmed Accept transport.
    pub fn confirm_sent(self) -> AuthorizedInboundReceiving {
        AuthorizedInboundReceiving {
            inner: self.inner.confirm_sent(),
        }
    }

    /// Consume ambiguous Accept transport into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Sealed Reject awaiting carrier confirmation.
pub struct PreparedAuthorizedInboundReject {
    inner: PreparedAccountableInboundReject,
}

impl PreparedAuthorizedInboundReject {
    /// Sealed Reject bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Confirm Reject and return a ready receiver session; no durable sender release is local here.
    pub fn confirm_sent(self) -> ReadyAuthorizedSifSession {
        ReadyAuthorizedSifSession {
            inner: self.inner.confirm_sent(),
        }
    }

    /// Consume ambiguous Reject transport into terminal uncertainty.
    pub fn transport_uncertain(self) -> SifTransferTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Receiver state unlocked only after staging exists and Accept was confirmed sent.
pub struct AuthorizedInboundReceiving {
    inner: AccountableInboundReceiving,
}

impl AuthorizedInboundReceiving {
    /// Joint semantic+disk content frontier.
    pub fn received_bytes(&self) -> u64 {
        self.inner.received_bytes()
    }

    /// Consume state while accepting one exact next protected Chunk envelope.
    pub fn open_next_chunk(self, envelope: &[u8]) -> Result<Self, AuthorizedSifError> {
        Ok(Self {
            inner: self.inner.open_next_chunk(envelope)?,
        })
    }

    /// Consume exact Complete into terminal local custody observation.
    pub fn finish_with_complete(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedInboundCustodyPending, AuthorizedSifError> {
        Ok(AuthorizedInboundCustodyPending {
            inner: self.inner.finish_with_complete(envelope)?,
        })
    }
}

/// Receiver terminal observation awaiting signed custody export.
pub struct AuthorizedInboundCustodyPending {
    inner: AccountableInboundCustodyPending,
}

impl AuthorizedInboundCustodyPending {
    /// Exact Offer whose observation awaits signed custody export.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Construct, sign and seal the current Ed25519 custody receipt.
    pub fn prepare_ed25519_custody_receipt(
        self,
        signing_key: &SigningKey,
        observed_at_unix_ms: u64,
    ) -> Result<PreparedAuthorizedCustodyReceipt, AuthorizedSifError> {
        Ok(PreparedAuthorizedCustodyReceipt {
            inner: self
                .inner
                .prepare_ed25519_custody_receipt(signing_key, observed_at_unix_ms)?,
        })
    }
}

/// Signed receiver custody receipt sealed but not yet transport-confirmed.
pub struct PreparedAuthorizedCustodyReceipt {
    inner: PreparedAccountableCustodyReceipt,
}

impl PreparedAuthorizedCustodyReceipt {
    /// Exact Offer closed by this receipt.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Portable signed receipt retained for local archive/export.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        self.inner.receipt()
    }

    /// Sealed custody bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Confirm custody receipt transport and close this one-shot sub-session.
    pub fn confirm_sent(self) -> ClosedAuthorizedInboundRelease {
        ClosedAuthorizedInboundRelease {
            inner: self.inner.confirm_sent(),
        }
    }

    /// Ambiguous custody-receipt transport is terminal.
    pub fn transport_uncertain(self) -> AuthorizedCustodyTransportUncertain {
        AuthorizedCustodyTransportUncertain {
            inner: self.inner.transport_uncertain(),
        }
    }
}

/// Receiver-side closure after signed custody receipt transport confirmation.
pub struct ClosedAuthorizedInboundRelease {
    inner: ClosedAccountableInboundRelease,
}

impl ClosedAuthorizedInboundRelease {
    /// Portable signed receiver receipt.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        self.inner.receipt()
    }

    /// Receiver-observed terminal disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.inner.disposition()
    }

    /// Consume into the portable signed receipt.
    pub fn into_receipt(self) -> SifDeliveryReceipt {
        self.inner.into_receipt()
    }
}

/// Terminal uncertainty when custody receipt delivery may or may not have occurred.
pub struct AuthorizedCustodyTransportUncertain {
    inner: AccountableCustodyTransportUncertain,
}

impl AuthorizedCustodyTransportUncertain {
    /// Exact Offer whose receipt-delivery state is unknown.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }
}

/// Fail-closed high-assurance transfer errors.
#[derive(Debug, Error)]
pub enum AuthorizedSifError {
    /// Existing accountable transfer/custody semantics failed.
    #[error(transparent)]
    Accountable(#[from] AccountableSifError),
    /// Profile-bound file accounting failed.
    #[error(transparent)]
    File(#[from] ProfileBoundFileDisclosureError),
    /// Offer authority names a different authenticated session generation.
    #[error("authorized Offer session generation does not match negotiated session")]
    SessionGenerationMismatch,
    /// Offer authority requires a different authenticated SIF profile.
    #[error("authorized Offer profile does not match negotiated SIF profile")]
    ProfileMismatch,
    /// Protocol and release-accounting byte frontiers diverged.
    #[error("protected sender frontier mismatch: protocol={protocol}, accounted={accounted}")]
    AccountingFrontierMismatch {
        /// Protocol carrier-confirmed content bytes.
        protocol: u64,
        /// Durable file-accounting bytes.
        accounted: u64,
    },
    /// Prepared Chunk content range was internally inconsistent.
    #[error("protected sender content range invariant failed")]
    ContentRangeInvariant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_assurance_error_distinguishes_session_and_profile_mismatch() {
        assert_ne!(
            AuthorizedSifError::SessionGenerationMismatch.to_string(),
            AuthorizedSifError::ProfileMismatch.to_string()
        );
    }

    #[test]
    fn ed25519_backend_remains_available_for_sender_custody_verification() {
        let _ = Ed25519EvidenceSignatureBackend;
    }
}
