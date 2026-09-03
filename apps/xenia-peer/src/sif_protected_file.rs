// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-file SIF-protected outbound transfer boundary.
//!
//! A prepared disclosure permit is not durably committed until its signed
//! minimum-necessary `result_digest` is proven to describe the exact outbound
//! filename, byte length and BLAKE3 digest held by one already-opened
//! [`xenia_peer_core::TransferSource`]. The source is consumed into the prepared
//! object, so callers cannot validate file A and substitute file B before Commit.
//!
//! Commit revalidates the **current live M1 runtime** through
//! [`crate::sif_m1_authority::commit_disclosure_from_current_runtime`] and only
//! success yields [`CommittedProtectedFileDisclosure`]. Network output exists only
//! on that committed type and its later typestates:
//!
//! `Committed -> Offer sent -> peer Accepted -> streaming -> terminal journal`.
//!
//! Every content Chunk is sealed first, then the live M1 runtime guard is acquired,
//! the file-send permission transition is checked, and that guard remains held through
//! the carrier send. This linearizes a concurrent revocation either before the Chunk
//! (no bytes sent) or after it (the Chunk was authorized); revocation cannot land in
//! the gap between M1 authorization and carrier output.
//!
//! Successful sends are exact byte accounting. A failed carrier send is not assumed
//! atomic: the full attempted content Chunk is conservatively charged through
//! `CommittedFileDisclosure::note_transport_uncertain`, and the session is terminal.
//! Source/read/M1/seal failures before carrier output retain an exact successful-prefix
//! Partial. Completion requires `TransferSource`'s independent second length/hash
//! verification before a `Completed` release outcome can be persisted.

#![allow(dead_code)]

use std::path::Path;

use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use xenia_ledger::{
    AccountabilityDisclosureError, AccountabilityDisclosurePermit, CommittedFileDisclosure,
    DisclosureReleaseOutcome, DisclosureReleaseState, FileDisclosureByteAccounting,
    FileDisclosureError, FileDisclosureTerminal, TransactionalDisclosureError,
    sif_file_result_digest,
};
use xenia_peer_core::transport::SendEnvelope;
use xenia_peer_core::{
    FILE_TRANSFER_CHUNK_SIZE, FileTransferMessage, LaneSession, M1SessionState, TransferSource,
};

use crate::m1_runtime::M1RuntimeSession;
use crate::sif_m1_authority::{
    M1SifAuthorityError, M1SifCommitError, M1SifOutcomeAuthority,
    commit_disclosure_from_current_runtime,
};
use crate::sif_release_store::{FileSifReleaseStore, SifReleaseStoreError};

/// Prepared exact outbound file whose result commitment has been checked before
/// any durable release Commit. No network operation is available from this type.
pub(crate) struct PreparedProtectedFileDisclosure {
    permit: AccountabilityDisclosurePermit,
    source: TransferSource,
    display_name: String,
    transfer_id: u64,
}

impl PreparedProtectedFileDisclosure {
    /// Consume the already-opened/hash-bound source and prove that the signed
    /// prepared permit names exactly this wire-visible file.
    pub(crate) fn new(
        permit: AccountabilityDisclosurePermit,
        source: TransferSource,
        display_name: impl Into<String>,
        transfer_id: u64,
    ) -> Result<Self, ProtectedFilePrepareError> {
        if transfer_id == 0 {
            return Err(ProtectedFilePrepareError::ZeroTransferId);
        }
        let display_name = display_name.into();
        require_exact_precommit_result(
            permit.binding().result_digest(),
            &display_name,
            source.size(),
            source.blake3_hash(),
        )?;
        Ok(Self {
            permit,
            source,
            display_name,
            transfer_id,
        })
    }

    /// Exact authenticated Offer metadata already bound by the permit.
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    pub(crate) fn size(&self) -> u64 {
        self.source.size()
    }

    pub(crate) fn content_blake3(&self) -> [u8; 32] {
        self.source.blake3_hash()
    }

    /// Revalidate current live M1 consent and durably CAS-commit this exact file.
    ///
    /// The caller must hold the live daemon's `AsyncMutex<M1RuntimeSession>` guard
    /// while passing `runtime`, preventing a consent transition from interleaving
    /// between fresh M1 reconstruction and the synchronous release-store CAS.
    pub(crate) fn commit(
        self,
        runtime: &M1RuntimeSession,
        m1_key_path: &Path,
        release_state: &mut DisclosureReleaseState,
        release_store: &mut FileSifReleaseStore,
    ) -> Result<CommittedProtectedFileDisclosure, ProtectedFileCommitError> {
        let Self {
            permit,
            source,
            display_name,
            transfer_id,
        } = self;

        let committed = commit_disclosure_from_current_runtime(
            runtime,
            m1_key_path,
            release_state,
            permit,
            release_store,
        )
        .map_err(map_commit_error)?;
        let (committed_permit, outcome_authority) = committed.into_parts();
        let release_id = committed_permit.release_id();

        match CommittedFileDisclosure::new(
            committed_permit,
            &display_name,
            source.size(),
            source.blake3_hash(),
        ) {
            Ok(disclosure) => Ok(CommittedProtectedFileDisclosure {
                core: ProtectedFileCore {
                    source,
                    display_name,
                    transfer_id,
                    disclosure,
                    outcome_authority,
                },
            }),
            Err(binding) => {
                match outcome_authority.record_outcome(
                    release_state,
                    release_id,
                    DisclosureReleaseOutcome::Aborted,
                    release_store,
                ) {
                    Ok(()) => Err(ProtectedFileCommitError::PostCommitBindingAborted(binding)),
                    Err(TransactionalDisclosureError::Protocol(outcome)) => {
                        Err(ProtectedFileCommitError::PostCommitBindingOutcomeProtocol {
                            binding,
                            outcome,
                        })
                    }
                    Err(TransactionalDisclosureError::Persist(store)) => {
                        Err(ProtectedFileCommitError::PostCommitBindingOutcomeStore {
                            binding,
                            store,
                        })
                    }
                }
            }
        }
    }
}

struct ProtectedFileCore {
    source: TransferSource,
    display_name: String,
    transfer_id: u64,
    disclosure: CommittedFileDisclosure,
    outcome_authority: M1SifOutcomeAuthority,
}

impl ProtectedFileCore {
    fn interrupted_terminal(self) -> (FileDisclosureTerminal, M1SifOutcomeAuthority) {
        let Self {
            source: _,
            display_name: _,
            transfer_id: _,
            disclosure,
            outcome_authority,
        } = self;
        (disclosure.interrupted(), outcome_authority)
    }

    /// Fallback used only after an accounting invariant itself fails. `TransferSource`
    /// advances when the Chunk is read, so its position is the exact prefix after a
    /// carrier-successful Chunk and the conservative full-attempt prefix after an
    /// ambiguous carrier failure.
    fn fallback_terminal(
        &self,
        byte_accounting: FileDisclosureByteAccounting,
    ) -> FileDisclosureTerminal {
        let accounted = self.source.bytes_sent();
        FileDisclosureTerminal {
            release_id: self.disclosure.release_id(),
            outcome: if accounted == 0 {
                DisclosureReleaseOutcome::Aborted
            } else {
                DisclosureReleaseOutcome::Partial {
                    bytes_released: accounted,
                }
            },
            byte_accounting,
        }
    }
}

/// Move-only exact-file output capability produced only after durable SIF Commit.
pub(crate) struct CommittedProtectedFileDisclosure {
    core: ProtectedFileCore,
}

impl CommittedProtectedFileDisclosure {
    pub(crate) fn release_id(&self) -> uuid::Uuid {
        self.core.disclosure.release_id()
    }
    pub(crate) fn transfer_id(&self) -> u64 {
        self.core.transfer_id
    }
    pub(crate) fn display_name(&self) -> &str {
        &self.core.display_name
    }
    pub(crate) fn size(&self) -> u64 {
        self.core.source.size()
    }
    pub(crate) fn content_blake3(&self) -> [u8; 32] {
        self.core.source.blake3_hash()
    }
    pub(crate) fn emitted_bytes(&self) -> u64 {
        self.core.disclosure.emitted_bytes()
    }

    /// The first network-capable transition in the protected-file type graph.
    pub(crate) async fn send_offer<T: SendEnvelope>(
        self,
        send: &mut T,
        session: &AsyncMutex<LaneSession>,
        m1_runtime: &AsyncMutex<M1RuntimeSession>,
        release_state: &mut DisclosureReleaseState,
        release_store: &mut FileSifReleaseStore,
    ) -> Result<OfferedProtectedFileDisclosure, ProtectedFileSendError> {
        let offer = FileTransferMessage::Offer {
            transfer_id: self.core.transfer_id,
            name: self.core.display_name.clone(),
            size: self.core.source.size(),
            blake3_hash: self.core.source.blake3_hash(),
        };
        let envelope = match session.lock().await.seal_file_transfer_message(offer, true) {
            Ok(envelope) => envelope,
            Err(error) => {
                return Err(terminalize_interrupted_error(
                    self.core,
                    format!("failed to seal protected file Offer: {error}"),
                    release_state,
                    release_store,
                ));
            }
        };

        let mut m1 = m1_runtime.lock().await;
        if let Err(error) = m1.allow_file_send_flow() {
            drop(m1);
            return Err(terminalize_interrupted_error(
                self.core,
                format!("M1 rejected protected file Offer: {error}"),
                release_state,
                release_store,
            ));
        }
        if let Err(error) = send.send_envelope(&envelope).await {
            drop(m1);
            return Err(terminalize_interrupted_error(
                self.core,
                format!("carrier failed protected file Offer: {error}"),
                release_state,
                release_store,
            ));
        }
        drop(m1);
        Ok(OfferedProtectedFileDisclosure { core: self.core })
    }
}

pub(crate) struct OfferedProtectedFileDisclosure {
    core: ProtectedFileCore,
}

impl OfferedProtectedFileDisclosure {
    pub(crate) fn handle_offer_response(
        self,
        response: FileTransferMessage,
        release_state: &mut DisclosureReleaseState,
        release_store: &mut FileSifReleaseStore,
    ) -> Result<ProtectedFileOfferDisposition, ProtectedFileSendError> {
        match classify_offer_response(self.core.transfer_id, &response) {
            Ok(OfferPeerDecision::Accept) => Ok(ProtectedFileOfferDisposition::Accepted(
                AcceptedProtectedFileDisclosure { core: self.core },
            )),
            Ok(OfferPeerDecision::Reject) => {
                let reason = match response {
                    FileTransferMessage::Reject { reason, .. } => reason,
                    _ => unreachable!("classification already fixed Reject variant"),
                };
                let terminal = persist_interrupted(self.core, release_state, release_store)
                    .map_err(|outcome| ProtectedFileSendError::TerminalPersistence {
                        cause: "peer rejected protected file Offer".to_string(),
                        outcome,
                    })?;
                Ok(ProtectedFileOfferDisposition::Rejected { reason, terminal })
            }
            Err(()) => {
                let terminal = persist_interrupted(self.core, release_state, release_store)
                    .map_err(|outcome| ProtectedFileSendError::TerminalPersistence {
                        cause: "unexpected protected file Offer response".to_string(),
                        outcome,
                    })?;
                Err(ProtectedFileSendError::Interrupted {
                    cause: "unexpected or wrong-transfer response to protected file Offer".to_string(),
                    terminal,
                })
            }
        }
    }
}

pub(crate) enum ProtectedFileOfferDisposition {
    Accepted(AcceptedProtectedFileDisclosure),
    Rejected {
        reason: String,
        terminal: ProtectedFileTerminalReceipt,
    },
}

pub(crate) struct AcceptedProtectedFileDisclosure {
    core: ProtectedFileCore,
}

impl AcceptedProtectedFileDisclosure {
    /// Terminal streaming operation. It never returns an in-progress sender.
    pub(crate) async fn send_contents<T: SendEnvelope>(
        mut self,
        send: &mut T,
        session: &AsyncMutex<LaneSession>,
        m1_runtime: &AsyncMutex<M1RuntimeSession>,
        release_state: &mut DisclosureReleaseState,
        release_store: &mut FileSifReleaseStore,
    ) -> Result<ProtectedFileTerminalReceipt, ProtectedFileSendError> {
        loop {
            if m1_runtime.lock().await.state() != M1SessionState::Active {
                return Err(terminalize_interrupted_error(
                    self.core,
                    "M1 session became inactive before protected file source read".to_string(),
                    release_state,
                    release_store,
                ));
            }

            let chunk = match self.core.source.next_chunk(FILE_TRANSFER_CHUNK_SIZE).await {
                Ok(chunk) => chunk,
                Err(error) => {
                    return Err(terminalize_interrupted_error(
                        self.core,
                        format!("protected file source verification/read failed: {error}"),
                        release_state,
                        release_store,
                    ));
                }
            };
            let Some(chunk) = chunk else {
                break;
            };

            let content_len = chunk.data.len();
            let message = FileTransferMessage::Chunk {
                transfer_id: self.core.transfer_id,
                offset: chunk.offset,
                data: chunk.data,
            };
            let envelope = match session.lock().await.seal_file_transfer_message(message, true) {
                Ok(envelope) => envelope,
                Err(error) => {
                    return Err(terminalize_interrupted_error(
                        self.core,
                        format!("failed to seal protected file Chunk: {error}"),
                        release_state,
                        release_store,
                    ));
                }
            };

            let mut m1 = m1_runtime.lock().await;
            if let Err(error) = m1.allow_file_send_flow() {
                drop(m1);
                return Err(terminalize_interrupted_error(
                    self.core,
                    format!("M1 rejected protected file Chunk: {error}"),
                    release_state,
                    release_store,
                ));
            }

            match send.send_envelope(&envelope).await {
                Ok(()) => {
                    if let Err(error) = self.core.disclosure.note_emitted(content_len) {
                        drop(m1);
                        let terminal = self
                            .core
                            .fallback_terminal(FileDisclosureByteAccounting::Exact);
                        return Err(terminalize_explicit_error(
                            self.core.outcome_authority,
                            terminal,
                            format!("protected file exact byte accounting failed after carrier success: {error}"),
                            release_state,
                            release_store,
                        ));
                    }
                    drop(m1);
                }
                Err(error) => {
                    let accounting_error = self
                        .core
                        .disclosure
                        .note_transport_uncertain(content_len)
                        .err();
                    drop(m1);
                    if let Some(accounting) = accounting_error {
                        let terminal = self
                            .core
                            .fallback_terminal(FileDisclosureByteAccounting::ConservativeUpperBound);
                        return Err(terminalize_explicit_error(
                            self.core.outcome_authority,
                            terminal,
                            format!(
                                "carrier failed protected file Chunk: {error}; conservative byte accounting also failed: {accounting}"
                            ),
                            release_state,
                            release_store,
                        ));
                    }
                    return Err(terminalize_interrupted_error(
                        self.core,
                        format!("carrier failed protected file Chunk: {error}"),
                        release_state,
                        release_store,
                    ));
                }
            }
        }

        let release_id = self.core.disclosure.release_id();
        let emitted = self.core.disclosure.emitted_bytes();
        let accounting = self.core.disclosure.byte_accounting();
        let ProtectedFileCore {
            source: _,
            display_name: _,
            transfer_id,
            disclosure,
            outcome_authority,
        } = self.core;
        let terminal = match disclosure.completed() {
            Ok(terminal) => terminal,
            Err(error) => {
                let fallback = FileDisclosureTerminal {
                    release_id,
                    outcome: if emitted == 0 {
                        DisclosureReleaseOutcome::Aborted
                    } else {
                        DisclosureReleaseOutcome::Partial {
                            bytes_released: emitted,
                        }
                    },
                    byte_accounting: accounting,
                };
                return Err(terminalize_explicit_error(
                    outcome_authority,
                    fallback,
                    format!("protected file completion invariant failed after verified source end: {error}"),
                    release_state,
                    release_store,
                ));
            }
        };

        let complete_signal =
            send_complete_signal(transfer_id, send, session, m1_runtime).await;

        persist_terminal(
            &outcome_authority,
            terminal,
            complete_signal,
            release_state,
            release_store,
        )
        .map_err(|outcome| ProtectedFileSendError::TerminalPersistence {
            cause: "all protected file content was emitted but Completed outcome persistence failed"
                .to_string(),
            outcome,
        })
    }
}

async fn send_complete_signal<T: SendEnvelope>(
    transfer_id: u64,
    send: &mut T,
    session: &AsyncMutex<LaneSession>,
    m1_runtime: &AsyncMutex<M1RuntimeSession>,
) -> ProtectedFileCompletionSignalStatus {
    let complete = FileTransferMessage::Complete { transfer_id };
    let envelope = match session.lock().await.seal_file_transfer_message(complete, true) {
        Ok(envelope) => envelope,
        Err(_) => return ProtectedFileCompletionSignalStatus::SealFailed,
    };
    let m1 = m1_runtime.lock().await;
    if m1.state() != M1SessionState::Active {
        return ProtectedFileCompletionSignalStatus::SuppressedByM1;
    }
    match send.send_envelope(&envelope).await {
        Ok(()) => ProtectedFileCompletionSignalStatus::Sent,
        Err(_) => ProtectedFileCompletionSignalStatus::CarrierFailed,
    }
}

fn terminalize_interrupted_error(
    core: ProtectedFileCore,
    cause: String,
    release_state: &mut DisclosureReleaseState,
    release_store: &mut FileSifReleaseStore,
) -> ProtectedFileSendError {
    match persist_interrupted(core, release_state, release_store) {
        Ok(terminal) => ProtectedFileSendError::Interrupted { cause, terminal },
        Err(outcome) => ProtectedFileSendError::TerminalPersistence { cause, outcome },
    }
}

fn terminalize_explicit_error(
    outcome_authority: M1SifOutcomeAuthority,
    terminal: FileDisclosureTerminal,
    cause: String,
    release_state: &mut DisclosureReleaseState,
    release_store: &mut FileSifReleaseStore,
) -> ProtectedFileSendError {
    match persist_terminal(
        &outcome_authority,
        terminal,
        ProtectedFileCompletionSignalStatus::NotApplicable,
        release_state,
        release_store,
    ) {
        Ok(terminal) => ProtectedFileSendError::Interrupted { cause, terminal },
        Err(outcome) => ProtectedFileSendError::TerminalPersistence { cause, outcome },
    }
}

fn persist_interrupted(
    core: ProtectedFileCore,
    release_state: &mut DisclosureReleaseState,
    release_store: &mut FileSifReleaseStore,
) -> Result<ProtectedFileTerminalReceipt, ProtectedFileOutcomeError> {
    let (terminal, outcome_authority) = core.interrupted_terminal();
    persist_terminal(
        &outcome_authority,
        terminal,
        ProtectedFileCompletionSignalStatus::NotApplicable,
        release_state,
        release_store,
    )
}

fn persist_terminal(
    outcome_authority: &M1SifOutcomeAuthority,
    terminal: FileDisclosureTerminal,
    completion_signal: ProtectedFileCompletionSignalStatus,
    release_state: &mut DisclosureReleaseState,
    release_store: &mut FileSifReleaseStore,
) -> Result<ProtectedFileTerminalReceipt, ProtectedFileOutcomeError> {
    outcome_authority
        .record_outcome(
            release_state,
            terminal.release_id,
            terminal.outcome,
            release_store,
        )
        .map_err(|error| match error {
            TransactionalDisclosureError::Protocol(protocol) => {
                ProtectedFileOutcomeError::Protocol(protocol)
            }
            TransactionalDisclosureError::Persist(store) => ProtectedFileOutcomeError::Store(store),
        })?;
    Ok(ProtectedFileTerminalReceipt {
        release_id: terminal.release_id,
        outcome: terminal.outcome,
        byte_accounting: terminal.byte_accounting,
        completion_signal,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfferPeerDecision {
    Accept,
    Reject,
}

fn classify_offer_response(
    expected_transfer_id: u64,
    response: &FileTransferMessage,
) -> Result<OfferPeerDecision, ()> {
    match response {
        FileTransferMessage::Accept { transfer_id } if *transfer_id == expected_transfer_id => {
            Ok(OfferPeerDecision::Accept)
        }
        FileTransferMessage::Reject { transfer_id, .. } if *transfer_id == expected_transfer_id => {
            Ok(OfferPeerDecision::Reject)
        }
        _ => Err(()),
    }
}

fn require_exact_precommit_result(
    permit_result_digest: Option<[u8; 32]>,
    display_name: &str,
    size: u64,
    content_blake3: [u8; 32],
) -> Result<[u8; 32], ProtectedFilePrepareError> {
    let expected = sif_file_result_digest(display_name, size, content_blake3)?;
    match permit_result_digest {
        None => Err(ProtectedFilePrepareError::MissingResultCommitment),
        Some(actual) if actual != expected => Err(ProtectedFilePrepareError::ResultMismatch),
        Some(_) => Ok(expected),
    }
}

fn map_commit_error(
    error: M1SifCommitError<SifReleaseStoreError>,
) -> ProtectedFileCommitError {
    match error {
        M1SifCommitError::Authority(authority) => ProtectedFileCommitError::Authority(authority),
        M1SifCommitError::Release(TransactionalDisclosureError::Protocol(protocol)) => {
            ProtectedFileCommitError::Protocol(protocol)
        }
        M1SifCommitError::Release(TransactionalDisclosureError::Persist(store)) => {
            ProtectedFileCommitError::Store(store)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtectedFileTerminalReceipt {
    pub(crate) release_id: uuid::Uuid,
    pub(crate) outcome: DisclosureReleaseOutcome,
    pub(crate) byte_accounting: FileDisclosureByteAccounting,
    pub(crate) completion_signal: ProtectedFileCompletionSignalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedFileCompletionSignalStatus {
    NotApplicable,
    Sent,
    SuppressedByM1,
    SealFailed,
    CarrierFailed,
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFilePrepareError {
    #[error("SIF protected file transfer id must be non-zero")]
    ZeroTransferId,
    #[error("SIF protected file prepared permit has no result commitment")]
    MissingResultCommitment,
    #[error("SIF protected file does not match the prepared permit result commitment")]
    ResultMismatch,
    #[error(transparent)]
    FileBinding(#[from] FileDisclosureError),
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFileCommitError {
    #[error("current M1 authority rejected SIF protected-file Commit: {0}")]
    Authority(#[source] M1SifAuthorityError),
    #[error("SIF release protocol rejected protected-file Commit: {0}")]
    Protocol(#[source] AccountabilityDisclosureError),
    #[error("SIF durable release store rejected protected-file Commit: {0}")]
    Store(#[source] SifReleaseStoreError),
    #[error("post-Commit exact-file invariant failed; Aborted outcome was durably recorded: {0}")]
    PostCommitBindingAborted(#[source] FileDisclosureError),
    #[error("post-Commit exact-file invariant failed and Aborted protocol transition also failed: binding={binding}; outcome={outcome}")]
    PostCommitBindingOutcomeProtocol {
        binding: FileDisclosureError,
        outcome: AccountabilityDisclosureError,
    },
    #[error("post-Commit exact-file invariant failed and Aborted persistence also failed: binding={binding}; store={store}")]
    PostCommitBindingOutcomeStore {
        binding: FileDisclosureError,
        store: SifReleaseStoreError,
    },
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFileOutcomeError {
    #[error("SIF protected-file terminal transition rejected by release protocol: {0}")]
    Protocol(#[source] AccountabilityDisclosureError),
    #[error("SIF protected-file terminal outcome failed durable persistence: {0}")]
    Store(#[source] SifReleaseStoreError),
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFileSendError {
    #[error("SIF protected-file send interrupted: {cause}; durable terminal={terminal:?}")]
    Interrupted {
        cause: String,
        terminal: ProtectedFileTerminalReceipt,
    },
    #[error("SIF protected-file send failed and terminal persistence also failed: {cause}; outcome_error={outcome}")]
    TerminalPersistence {
        cause: String,
        #[source]
        outcome: ProtectedFileOutcomeError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precommit_result_requires_exact_name_size_and_hash() {
        let exact = sif_file_result_digest("report.bin", 7, [0xA5; 32]).unwrap();
        assert_eq!(
            require_exact_precommit_result(Some(exact), "report.bin", 7, [0xA5; 32]).unwrap(),
            exact
        );
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "other.bin", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "report.bin", 8, [0xA5; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "report.bin", 7, [0xB6; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
    }

    #[test]
    fn precommit_result_rejects_missing_commitment_and_empty_name() {
        assert!(matches!(
            require_exact_precommit_result(None, "report.bin", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::MissingResultCommitment)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some([1u8; 32]), "", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::FileBinding(
                FileDisclosureError::EmptyDisplayName
            ))
        ));
    }

    #[test]
    fn offer_response_accepts_only_exact_transfer_id() {
        assert_eq!(
            classify_offer_response(7, &FileTransferMessage::Accept { transfer_id: 7 }),
            Ok(OfferPeerDecision::Accept)
        );
        assert_eq!(
            classify_offer_response(
                7,
                &FileTransferMessage::Reject {
                    transfer_id: 7,
                    reason: "no".to_string(),
                }
            ),
            Ok(OfferPeerDecision::Reject)
        );
        assert_eq!(
            classify_offer_response(7, &FileTransferMessage::Accept { transfer_id: 8 }),
            Err(())
        );
        assert_eq!(
            classify_offer_response(7, &FileTransferMessage::Complete { transfer_id: 7 }),
            Err(())
        );
    }

    #[test]
    fn release_completion_and_receiver_signal_are_separate_claims() {
        assert_ne!(
            ProtectedFileCompletionSignalStatus::Sent,
            ProtectedFileCompletionSignalStatus::CarrierFailed
        );
        assert_ne!(
            ProtectedFileCompletionSignalStatus::Sent,
            ProtectedFileCompletionSignalStatus::SuppressedByM1
        );
    }
}
