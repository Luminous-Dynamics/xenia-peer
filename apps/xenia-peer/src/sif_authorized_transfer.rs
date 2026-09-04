// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-assurance accountable SIF transfer surface.
//!
//! The historical accountable phase engine remains crate-private. This module is the
//! public authority-bearing facade: outbound release can begin only by consuming a
//! [`ProfileBoundFileOfferAuthority`] derived from a durable profile-bound release
//! Commit. The facade rechecks the durable authority's authenticated session UUID and
//! required SIF profile against the current negotiated accountable session before the
//! exact derived Offer is allowed into the phase engine.
//!
//! The move-only file disclosure tracker then follows the outbound phase machine. Every
//! rejection or ambiguous transport exit exposes an explicit [`FileDisclosureTerminal`]
//! instead of silently dropping release-accounting state. Confirmed Chunk transitions
//! advance the file tracker from the exact phase-derived content range.
//!
//! This tranche does **not** yet make Xenia own the source file or integrate the
//! crash-safe write-ahead Chunk journal. `prepare_next_chunk` still accepts caller-owned
//! bytes. The next hardening layer must join immutable source ownership with
//! `SifProtectedFileSendState` so bytes are durably prepared before carrier I/O.
//!
//! The durable file capability currently retains the authenticated session UUID but not
//! the complete transcript binding. The UUID comparison here therefore prevents moving
//! authority between different session IDs, while exact transcript-generation retention
//! remains a subsequent strengthening step.

use std::fmt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    DisclosureReleaseOutcome, EvidenceCryptoManifest, EvidenceSignatureBackend,
    FileDisclosureByteAccounting, FileDisclosureTerminal, ProfileBoundCommittedFileDisclosure,
    ProfileBoundFileDisclosureError, ProfileBoundFileOfferAuthority, SessionTranscriptBinding,
    SifDeliveryDisposition, SifDeliveryReceipt, SifDeliveryReceiptBinding, SifProtectedFileOffer,
};
use xenia_peer_core::SifProtectedFileWireRole;

use crate::sif_accountable_transfer as inner;

pub use crate::sif_transfer_flow::{SifTransferTransportUncertain, SifTransportUncertainPhase};
pub use inner::AccountableSifError;

/// Pre-negotiation high-assurance accountable SIF session.
pub struct PendingAuthorizedSifSession {
    inner: inner::PendingAccountableSifSession,
}

impl PendingAuthorizedSifSession {
    /// Create a fresh high-assurance accountable SIF sub-session.
    pub fn new(
        role: SifProtectedFileWireRole,
        session: SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Self {
        Self {
            inner: inner::PendingAccountableSifSession::new(role, session, manifest),
        }
    }

    /// Endpoint role fixed for transfer and custody domains.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.inner.role()
    }

    /// Authenticated Xenia session transcript used by custody evidence and authority checks.
    pub fn session(&self) -> &SessionTranscriptBinding {
        self.inner.session()
    }

    /// Install the transcript-derived control schedule.
    ///
    /// The high-assurance facade intentionally does not expose the lower raw-key fixture
    /// constructor or `install_control_key` convenience path.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.inner.install_schedule(schedule);
    }

    /// Seal this endpoint's exact compiled SIF capability profile.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, AccountableSifError> {
        self.inner.seal_local_capability()
    }

    /// Consume pending state after exact peer capability authentication.
    pub fn accept_peer_capability(
        self,
        envelope: &[u8],
    ) -> Result<ReadyAuthorizedSifSession, AccountableSifError> {
        Ok(ReadyAuthorizedSifSession {
            inner: self.inner.accept_peer_capability(envelope)?,
        })
    }
}

/// Negotiated high-assurance accountable session with no active release.
pub struct ReadyAuthorizedSifSession {
    inner: inner::ReadyAccountableSifSession,
}

impl ReadyAuthorizedSifSession {
    /// Exact authenticated protected-transfer profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.inner.profile_digest()
    }

    /// Authenticated Xenia session transcript used by custody and release checks.
    pub fn session(&self) -> &SessionTranscriptBinding {
        self.inner.session()
    }

    /// Rotate the negotiated control key while no transfer is active.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.inner.install_rekey_keys(keys);
    }

    /// Begin outbound release only from the exact move-only durable file authority.
    ///
    /// This replaces the public caller-authored `SifProtectedFileOffer` boundary. The
    /// derived Offer cannot enter the phase engine unless both session UUID and exact
    /// negotiated profile still match the authority that created it.
    pub fn prepare_outbound_offer(
        self,
        authority: ProfileBoundFileOfferAuthority,
    ) -> Result<PreparedAuthorizedOutboundOffer, AuthorizedOutboundFailure> {
        if authority.authorized_session_id() != self.inner.session().session_id {
            let (_, file) = authority.into_parts();
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::AuthorizedSessionMismatch,
                terminalize_file(file),
            ));
        }
        if authority.required_sif_profile_digest() != self.inner.profile_digest() {
            let (_, file) = authority.into_parts();
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::AuthorizedProfileMismatch,
                terminalize_file(file),
            ));
        }

        let (offer, file) = authority.into_parts();
        match self.inner.prepare_outbound_offer(offer) {
            Ok(inner) => Ok(PreparedAuthorizedOutboundOffer { inner, file }),
            Err(error) => Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::Accountable(error),
                terminalize_file(file),
            )),
        }
    }

    /// Open one authenticated inbound Offer and enter local decision state.
    pub fn open_inbound_offer(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedInboundOfferPending, AccountableSifError> {
        Ok(AuthorizedInboundOfferPending {
            inner: self.inner.open_inbound_offer(envelope)?,
        })
    }
}

/// Outbound authorized Offer sealed but not yet carrier-confirmed.
pub struct PreparedAuthorizedOutboundOffer {
    inner: inner::PreparedAccountableOutboundOffer,
    file: ProfileBoundCommittedFileDisclosure,
}

impl PreparedAuthorizedOutboundOffer {
    /// Exact authority-derived Offer represented by this envelope.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Sealed bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Advance after the carrier reports complete Offer-envelope success.
    pub fn confirm_sent(self) -> AuthorizedOutboundAwaitingResponse {
        AuthorizedOutboundAwaitingResponse {
            inner: self.inner.confirm_sent(),
            file: self.file,
        }
    }

    /// Terminalize an ambiguous Offer send with explicit zero-content release accounting.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        AuthorizedReleaseTransportUncertain {
            transfer: self.inner.transport_uncertain(),
            release_terminal: terminalize_file(self.file),
        }
    }
}

/// Confirmed authorized Offer awaiting exact authenticated peer decision.
pub struct AuthorizedOutboundAwaitingResponse {
    inner: inner::AccountableOutboundAwaitingResponse,
    file: ProfileBoundCommittedFileDisclosure,
}

impl AuthorizedOutboundAwaitingResponse {
    /// Exact authority-derived Offer awaiting peer Accept/Reject.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Open the peer response while retaining the same move-only file authority.
    pub fn open_response(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedOutboundOfferOutcome, AuthorizedOutboundFailure> {
        match self.inner.open_response(envelope) {
            Ok(inner::AccountableOutboundOfferOutcome::Accepted(inner)) => {
                Ok(AuthorizedOutboundOfferOutcome::Accepted(
                    AuthorizedOutboundStreaming {
                        inner,
                        file: self.file,
                    },
                ))
            }
            Ok(inner::AccountableOutboundOfferOutcome::Rejected(inner)) => {
                Ok(AuthorizedOutboundOfferOutcome::Rejected(
                    RejectedAuthorizedOutboundOffer {
                        inner,
                        file: self.file,
                    },
                ))
            }
            Err(error) => Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::Accountable(error),
                terminalize_file(self.file),
            )),
        }
    }
}

/// Authenticated peer decision for an authority-derived Offer.
pub enum AuthorizedOutboundOfferOutcome {
    /// Exact Offer accepted; protected content may now be prepared.
    Accepted(AuthorizedOutboundStreaming),
    /// Exact Offer rejected; no protected content authority was exercised.
    Rejected(RejectedAuthorizedOutboundOffer),
}

/// Rejected authority-derived Offer retaining an explicit release terminal.
pub struct RejectedAuthorizedOutboundOffer {
    inner: inner::RejectedAccountableOutboundOffer,
    file: ProfileBoundCommittedFileDisclosure,
}

impl RejectedAuthorizedOutboundOffer {
    /// Exact Offer rejected by the authenticated peer.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Return to negotiated Ready while surfacing the release's zero-content terminal.
    ///
    /// The caller must durably record this terminal in the profile-bound release journal
    /// before treating the release lineage as resolved.
    pub fn into_ready(self) -> ResolvedRejectedAuthorizedRelease {
        ResolvedRejectedAuthorizedRelease {
            ready: ReadyAuthorizedSifSession {
                inner: self.inner.into_ready(),
            },
            release_terminal: terminalize_file(self.file),
        }
    }
}

/// Rejected release result carrying both reusable session and explicit journal terminal.
pub struct ResolvedRejectedAuthorizedRelease {
    ready: ReadyAuthorizedSifSession,
    release_terminal: FileDisclosureTerminal,
}

impl ResolvedRejectedAuthorizedRelease {
    /// Release terminal that must be durably recorded before lineage reuse.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }

    /// Consume into the negotiated session after the caller has handled the terminal.
    pub fn into_ready(self) -> ReadyAuthorizedSifSession {
        self.ready
    }
}

/// Accepted authorized release with aligned transport and release-accounting frontiers.
pub struct AuthorizedOutboundStreaming {
    inner: inner::AccountableOutboundStreaming,
    file: ProfileBoundCommittedFileDisclosure,
}

impl AuthorizedOutboundStreaming {
    /// Transport-confirmed protected content bytes.
    pub const fn confirmed_content_bytes(&self) -> u64 {
        self.inner.confirmed_content_bytes()
    }

    /// Release-accounted protected content bytes.
    pub const fn accounted_content_bytes(&self) -> u64 {
        self.file.emitted_bytes()
    }

    /// Prepare the next contiguous Chunk.
    ///
    /// This still accepts caller-owned bytes; source ownership is the next hardening
    /// tranche. The facade does require the transport and release-accounting frontiers
    /// to agree before allowing another Chunk to be sealed.
    pub fn prepare_next_chunk(
        self,
        data: Vec<u8>,
    ) -> Result<PreparedAuthorizedOutboundChunk, AuthorizedOutboundFailure> {
        if self.inner.confirmed_content_bytes() != self.file.emitted_bytes() {
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::AccountingFrontierMismatch {
                    transport_confirmed: self.inner.confirmed_content_bytes(),
                    release_accounted: self.file.emitted_bytes(),
                },
                terminalize_file(self.file),
            ));
        }
        match self.inner.prepare_next_chunk(data) {
            Ok(inner) => Ok(PreparedAuthorizedOutboundChunk {
                inner,
                file: self.file,
            }),
            Err(error) => Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::Accountable(error),
                terminalize_file(self.file),
            )),
        }
    }

    /// Prepare Complete only when both transport and release accounting cover the file.
    pub fn prepare_complete(
        self,
    ) -> Result<PreparedAuthorizedOutboundComplete, AuthorizedOutboundFailure> {
        if self.inner.confirmed_content_bytes() != self.file.emitted_bytes() {
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::AccountingFrontierMismatch {
                    transport_confirmed: self.inner.confirmed_content_bytes(),
                    release_accounted: self.file.emitted_bytes(),
                },
                terminalize_file(self.file),
            ));
        }
        match self.inner.prepare_complete() {
            Ok(inner) => Ok(PreparedAuthorizedOutboundComplete {
                inner,
                file: self.file,
            }),
            Err(error) => Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::Accountable(error),
                terminalize_file(self.file),
            )),
        }
    }
}

/// One authorized outbound Chunk sealed but not yet carrier-confirmed.
pub struct PreparedAuthorizedOutboundChunk {
    inner: inner::PreparedAccountableOutboundChunk,
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

    /// Advance both transport and release-accounting frontiers after carrier success.
    pub fn confirm_sent(mut self) -> Result<AuthorizedOutboundStreaming, AuthorizedOutboundFailure> {
        let (start, end) = self.inner.content_range();
        let len = match end.checked_sub(start).and_then(|value| usize::try_from(value).ok()) {
            Some(len) => len,
            None => {
                return Err(AuthorizedOutboundFailure::new(
                    AuthorizedAccountableSifError::ChunkLengthOverflow,
                    conservative_terminal_after_attempt(self.file, u64::MAX),
                ));
            }
        };
        if let Err(error) = self.file.note_emitted(len) {
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::File(error),
                conservative_terminal_after_attempt(self.file, len as u64),
            ));
        }
        Ok(AuthorizedOutboundStreaming {
            inner: self.inner.confirm_sent(),
            file: self.file,
        })
    }

    /// Consume an ambiguous carrier write into conservative release accounting.
    pub fn transport_uncertain(
        mut self,
    ) -> Result<AuthorizedReleaseTransportUncertain, AuthorizedOutboundFailure> {
        let (start, end) = self.inner.content_range();
        let len = match end.checked_sub(start).and_then(|value| usize::try_from(value).ok()) {
            Some(len) => len,
            None => {
                return Err(AuthorizedOutboundFailure::new(
                    AuthorizedAccountableSifError::ChunkLengthOverflow,
                    conservative_terminal_after_attempt(self.file, u64::MAX),
                ));
            }
        };
        if let Err(error) = self.file.note_transport_uncertain(len) {
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::File(error),
                conservative_terminal_after_attempt(self.file, len as u64),
            ));
        }
        Ok(AuthorizedReleaseTransportUncertain {
            transfer: self.inner.transport_uncertain(),
            release_terminal: terminalize_file(self.file),
        })
    }
}

/// Authorized Complete marker sealed after all content was carrier-confirmed and accounted.
pub struct PreparedAuthorizedOutboundComplete {
    inner: inner::PreparedAccountableOutboundComplete,
    file: ProfileBoundCommittedFileDisclosure,
}

impl PreparedAuthorizedOutboundComplete {
    /// Sealed Complete envelope the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Enter custody waiting and freeze the file release as Completed.
    pub fn confirm_sent(self) -> Result<AuthorizedOutboundAwaitingCustody, AuthorizedOutboundFailure> {
        let release_terminal = terminalize_file(self.file);
        if release_terminal.outcome != DisclosureReleaseOutcome::Completed {
            return Err(AuthorizedOutboundFailure::new(
                AuthorizedAccountableSifError::CompleteWithoutCompletedRelease,
                release_terminal,
            ));
        }
        Ok(AuthorizedOutboundAwaitingCustody {
            inner: self.inner.confirm_sent(),
            release_terminal,
        })
    }

    /// Complete-envelope uncertainty does not change already-confirmed file-content truth.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        AuthorizedReleaseTransportUncertain {
            transfer: self.inner.transport_uncertain(),
            release_terminal: terminalize_file(self.file),
        }
    }
}

/// Sender state after content release completion, awaiting receiver custody proof.
pub struct AuthorizedOutboundAwaitingCustody {
    inner: inner::AccountableOutboundAwaitingCustody,
    release_terminal: FileDisclosureTerminal,
}

impl AuthorizedOutboundAwaitingCustody {
    /// Exact completed Offer whose remote custody must be proven.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Completed release terminal to persist independently of custody verification.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }

    /// Verify receiver custody under the sender-owned trusted key expectation.
    pub fn verify_custody(
        self,
        envelope: &[u8],
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<ClosedAuthorizedOutboundRelease, AuthorizedCustodyFailure> {
        match self
            .inner
            .verify_custody(envelope, backend, trusted_receiver_public_key)
        {
            Ok(inner) => Ok(ClosedAuthorizedOutboundRelease {
                inner,
                release_terminal: self.release_terminal,
            }),
            Err(error) => Err(AuthorizedCustodyFailure {
                error,
                release_terminal: self.release_terminal,
            }),
        }
    }
}

/// Sender-verified custody closure plus exact local release terminal.
pub struct ClosedAuthorizedOutboundRelease {
    inner: inner::ClosedAccountableOutboundRelease,
    release_terminal: FileDisclosureTerminal,
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

    /// Exact local release terminal that must be durably recorded.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }

    /// Consume closure into portable custody binding and local release terminal.
    pub fn into_parts(self) -> (SifDeliveryReceiptBinding, FileDisclosureTerminal) {
        (self.inner.into_binding(), self.release_terminal)
    }
}

/// Authenticated inbound Offer awaiting local Accept/Reject.
pub struct AuthorizedInboundOfferPending {
    inner: inner::AccountableInboundOfferPending,
}

impl AuthorizedInboundOfferPending {
    /// Exact authenticated Offer awaiting local decision.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Create private staging first, then prepare Accept.
    pub fn prepare_accept(
        self,
        receive_directory: &Path,
    ) -> Result<PreparedAuthorizedInboundAccept, AccountableSifError> {
        Ok(PreparedAuthorizedInboundAccept {
            inner: self.inner.prepare_accept(receive_directory)?,
        })
    }

    /// Prepare a bounded Reject without unlocking content receive authority.
    pub fn prepare_reject(
        self,
        reason: impl Into<String>,
    ) -> Result<PreparedAuthorizedInboundReject, AccountableSifError> {
        Ok(PreparedAuthorizedInboundReject {
            inner: self.inner.prepare_reject(reason)?,
        })
    }
}

/// Sealed inbound Accept awaiting carrier confirmation.
pub struct PreparedAuthorizedInboundAccept {
    inner: inner::PreparedAccountableInboundAccept,
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

/// Sealed inbound Reject awaiting carrier confirmation.
pub struct PreparedAuthorizedInboundReject {
    inner: inner::PreparedAccountableInboundReject,
}

impl PreparedAuthorizedInboundReject {
    /// Sealed Reject bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Return to the high-assurance Ready facade after confirmed Reject transport.
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
    inner: inner::AccountableInboundReceiving,
}

impl AuthorizedInboundReceiving {
    /// Joint semantic + durable staging frontier.
    pub fn received_bytes(&self) -> u64 {
        self.inner.received_bytes()
    }

    /// Consume state while accepting one exact next protected Chunk envelope.
    pub fn open_next_chunk(self, envelope: &[u8]) -> Result<Self, AccountableSifError> {
        Ok(Self {
            inner: self.inner.open_next_chunk(envelope)?,
        })
    }

    /// Consume exact Complete into terminal local custody observation.
    pub fn finish_with_complete(
        self,
        envelope: &[u8],
    ) -> Result<AuthorizedInboundCustodyPending, AccountableSifError> {
        Ok(AuthorizedInboundCustodyPending {
            inner: self.inner.finish_with_complete(envelope)?,
        })
    }
}

/// Receiver terminal observation awaiting signed custody export.
pub struct AuthorizedInboundCustodyPending {
    inner: inner::AccountableInboundCustodyPending,
}

impl AuthorizedInboundCustodyPending {
    /// Exact Offer whose terminal observation awaits custody export.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Construct, sign and seal the receiver custody receipt using current Ed25519 profile.
    pub fn prepare_ed25519_custody_receipt(
        self,
        signing_key: &SigningKey,
        observed_at_unix_ms: u64,
    ) -> Result<PreparedAuthorizedCustodyReceipt, AccountableSifError> {
        Ok(PreparedAuthorizedCustodyReceipt {
            inner: self
                .inner
                .prepare_ed25519_custody_receipt(signing_key, observed_at_unix_ms)?,
        })
    }
}

/// Signed receiver custody receipt sealed but not yet carrier-confirmed.
pub struct PreparedAuthorizedCustodyReceipt {
    inner: inner::PreparedAccountableCustodyReceipt,
}

impl PreparedAuthorizedCustodyReceipt {
    /// Exact Offer closed by this receipt.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Portable signed receipt retained for archive/export.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        self.inner.receipt()
    }

    /// Sealed custody bytes the carrier must attempt exactly once.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Confirm receipt transport and close the receiver sub-session.
    pub fn confirm_sent(self) -> ClosedAuthorizedInboundRelease {
        ClosedAuthorizedInboundRelease {
            inner: self.inner.confirm_sent(),
        }
    }

    /// Ambiguous receipt transport is terminal and returns no reusable session.
    pub fn transport_uncertain(self) -> AuthorizedCustodyTransportUncertain {
        AuthorizedCustodyTransportUncertain {
            inner: self.inner.transport_uncertain(),
        }
    }
}

/// Receiver closure after signed custody receipt transport was confirmed.
pub struct ClosedAuthorizedInboundRelease {
    inner: inner::ClosedAccountableInboundRelease,
}

impl ClosedAuthorizedInboundRelease {
    /// Portable signed receiver receipt for archival/accountability use.
    pub fn receipt(&self) -> &SifDeliveryReceipt {
        self.inner.receipt()
    }

    /// Receiver-observed terminal disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.inner.disposition()
    }

    /// Consume closure into the portable signed receipt.
    pub fn into_receipt(self) -> SifDeliveryReceipt {
        self.inner.into_receipt()
    }
}

/// Terminal uncertainty when the receiver custody receipt may or may not have arrived.
pub struct AuthorizedCustodyTransportUncertain {
    inner: inner::AccountableCustodyTransportUncertain,
}

impl AuthorizedCustodyTransportUncertain {
    /// Exact Offer whose receipt-delivery state is unknown.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }
}

/// Transport uncertainty plus the exact local release terminal to persist.
pub struct AuthorizedReleaseTransportUncertain {
    transfer: SifTransferTransportUncertain,
    release_terminal: FileDisclosureTerminal,
}

impl AuthorizedReleaseTransportUncertain {
    /// Protocol phase whose transport result became ambiguous.
    pub const fn phase(&self) -> SifTransportUncertainPhase {
        self.transfer.phase()
    }

    /// Exact Offer associated with the uncertain operation.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.transfer.offer()
    }

    /// Conservative content frontier potentially reached by the peer.
    pub const fn content_bytes_may_have_been_confirmed_through(&self) -> u64 {
        self.transfer
            .content_bytes_may_have_been_confirmed_through()
    }

    /// Exact local release terminal that must be durably recorded.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }
}

/// High-assurance sender integration failures.
#[derive(Debug, Error)]
pub enum AuthorizedAccountableSifError {
    /// Existing negotiated transfer/custody state machine failed.
    #[error(transparent)]
    Accountable(#[from] AccountableSifError),
    /// Durable file authority/accounting invariant failed.
    #[error(transparent)]
    File(#[from] ProfileBoundFileDisclosureError),
    /// Durable release authority names a different authenticated session UUID.
    #[error("durable file authority does not belong to this authenticated Xenia session")]
    AuthorizedSessionMismatch,
    /// Durable release authority requires a different negotiated SIF profile.
    #[error("durable file authority does not match this negotiated SIF profile")]
    AuthorizedProfileMismatch,
    /// Transport-confirmed and release-accounted content frontiers diverged.
    #[error(
        "authorized SIF accounting frontier mismatch: transport={transport_confirmed}, release={release_accounted}"
    )]
    AccountingFrontierMismatch {
        /// Content bytes transport-confirmed by the phase machine.
        transport_confirmed: u64,
        /// Content bytes charged to the durable release tracker.
        release_accounted: u64,
    },
    /// Prepared Chunk range could not be represented as a host `usize`.
    #[error("authorized SIF Chunk length overflow")]
    ChunkLengthOverflow,
    /// Complete was reached without a locally Completed file-release terminal.
    #[error("authorized SIF Complete reached without completed release accounting")]
    CompleteWithoutCompletedRelease,
}

/// Sender failure paired with the release terminal that must be durably recorded.
#[derive(Debug)]
pub struct AuthorizedOutboundFailure {
    error: AuthorizedAccountableSifError,
    release_terminal: FileDisclosureTerminal,
}

impl AuthorizedOutboundFailure {
    fn new(error: AuthorizedAccountableSifError, release_terminal: FileDisclosureTerminal) -> Self {
        Self {
            error,
            release_terminal,
        }
    }

    /// Underlying protocol/authority failure.
    pub fn error(&self) -> &AuthorizedAccountableSifError {
        &self.error
    }

    /// Release terminal that must be durably recorded after this fail-closed exit.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }
}

impl fmt::Display for AuthorizedOutboundFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AuthorizedOutboundFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Custody-verification failure retaining already-finalized local release truth.
#[derive(Debug)]
pub struct AuthorizedCustodyFailure {
    error: AccountableSifError,
    release_terminal: FileDisclosureTerminal,
}

impl AuthorizedCustodyFailure {
    /// Custody transport/signature verification failure.
    pub fn error(&self) -> &AccountableSifError {
        &self.error
    }

    /// Local content-release terminal, unaffected by remote custody verification failure.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        self.release_terminal
    }
}

impl fmt::Display for AuthorizedCustodyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AuthorizedCustodyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

fn terminalize_file(file: ProfileBoundCommittedFileDisclosure) -> FileDisclosureTerminal {
    if file.byte_accounting() == FileDisclosureByteAccounting::Exact
        && file.emitted_bytes() == file.expected_size()
    {
        FileDisclosureTerminal {
            release_id: file.release_id(),
            outcome: DisclosureReleaseOutcome::Completed,
            byte_accounting: FileDisclosureByteAccounting::Exact,
        }
    } else {
        file.interrupted()
    }
}

fn conservative_terminal_after_attempt(
    file: ProfileBoundCommittedFileDisclosure,
    attempted_bytes: u64,
) -> FileDisclosureTerminal {
    let upper = file
        .emitted_bytes()
        .saturating_add(attempted_bytes)
        .min(file.expected_size());
    if upper == 0 {
        return FileDisclosureTerminal {
            release_id: file.release_id(),
            outcome: DisclosureReleaseOutcome::Aborted,
            byte_accounting: FileDisclosureByteAccounting::ConservativeUpperBound,
        };
    }
    FileDisclosureTerminal {
        release_id: file.release_id(),
        outcome: DisclosureReleaseOutcome::Partial {
            bytes_released: upper,
        },
        byte_accounting: FileDisclosureByteAccounting::ConservativeUpperBound,
    }
}
