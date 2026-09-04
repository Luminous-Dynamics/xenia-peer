// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strongest current SIF outbound composition: release context + owned source + write-ahead send.
//!
//! This layer wraps [`crate::sif_source_bound_sender`] with the complete runtime context
//! retained by [`xenia_ledger::ContextBoundFileOfferAuthority`]. It adds two checks that
//! intentionally sit above the historical signed artifact formats:
//!
//! - exact authenticated [`xenia_ledger::SessionTranscriptBinding`] equality, not merely
//!   equal session UUID; and
//! - live consent-generation freshness under the exact release-ledger verifier key.
//!
//! For each novel content Chunk, [`ContextBoundOutboundStreaming::send_next_chunk`] locks
//! the caller-supplied authoritative `tokio::sync::Mutex<Chain>`, verifies that the exact
//! Approval generation is still current, and **keeps that guard held** while the
//! source-owned sender performs write-ahead `Prepared`, the actual carrier send and
//! durable `CarrierConfirmed`.
//!
//! This gives an in-process linearization rule when the same mutex is also the only path
//! for consent mutations: a Revocation occurs either before the Chunk (and blocks it) or
//! after the Chunk's carrier operation (and the Chunk is already truthfully accounted).
//! The type cannot prove that an application has no second independent `Chain` writer;
//! deployments must treat the supplied mutex as the authoritative live consent state.

use std::fmt;

use tokio::sync::Mutex;
use xenia_ledger::{
    AuthorizedReleaseContext, Chain, ContextBoundFileOfferAuthority,
    CurrentReleaseAuthorizationError, DisclosureReleaseOutcome, FileDisclosureByteAccounting,
    FileDisclosureTerminal, ProfileBoundReleaseStore, SifProtectedFileSendStore,
};
use xenia_peer_core::TransferSource;
use xenia_peer_core::transport::SendEnvelope;

use crate::sif_authorized_transfer::{
    AuthorizedOutboundAwaitingCustody, AuthorizedOutboundFailure, AuthorizedReleaseTransportUncertain,
    ReadyAuthorizedSifSession, ResolvedRejectedAuthorizedRelease,
};
use crate::sif_source_bound_sender::{
    PreparedSourceBoundComplete, PreparedSourceBoundOffer, SourceBoundAuthorityError,
    SourceBoundAwaitingResponse, SourceBoundChunkFailure, SourceBoundCompleteFailure,
    SourceBoundFileAuthority, SourceBoundOfferFailure, SourceBoundOfferOutcome,
    SourceBoundOutboundStreaming, SourceBoundReadyToComplete, SourceBoundSendProgress,
    prepare_source_bound_offer,
};

/// Exact context-retaining durable file authority joined to one fresh source handle.
#[derive(Debug)]
pub struct ContextBoundSourceAuthority {
    inner: SourceBoundFileAuthority,
    context: AuthorizedReleaseContext,
}

impl ContextBoundSourceAuthority {
    /// Bind a context-retaining durable file authority to a fresh exact-content source.
    pub fn bind(
        authority: ContextBoundFileOfferAuthority,
        source: TransferSource,
    ) -> Result<Self, SourceBoundAuthorityError> {
        let (authority, context) = authority.into_parts();
        Ok(Self {
            inner: SourceBoundFileAuthority::bind(authority, source)?,
            context,
        })
    }

    /// Complete runtime authorization context captured at durable release Commit.
    pub fn context(&self) -> &AuthorizedReleaseContext {
        &self.context
    }
}

/// Bind the context/source authority to the exact current negotiated SIF session.
pub fn prepare_context_bound_offer(
    ready: ReadyAuthorizedSifSession,
    bound: ContextBoundSourceAuthority,
) -> Result<PreparedContextBoundOffer, ContextBoundOfferFailure> {
    let ContextBoundSourceAuthority { inner, context } = bound;
    if context.session() != ready.session() {
        return Err(ContextBoundOfferFailure::ContextMismatch {
            kind: ContextBoundContextMismatch::SessionTranscript,
            release_terminal: zero_content_terminal(inner.offer().release_id()),
        });
    }
    if context.required_sif_profile_digest() != ready.profile_digest() {
        return Err(ContextBoundOfferFailure::ContextMismatch {
            kind: ContextBoundContextMismatch::SifProfile,
            release_terminal: zero_content_terminal(inner.offer().release_id()),
        });
    }
    match prepare_source_bound_offer(ready, inner) {
        Ok(inner) => Ok(PreparedContextBoundOffer { inner, context }),
        Err(error) => Err(ContextBoundOfferFailure::Source(error)),
    }
}

/// Context mismatch found before the authority-derived Offer can become active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextBoundContextMismatch {
    /// Current accountable session is not the exact transcript generation that authorized release.
    SessionTranscript,
    /// Current negotiated SIF profile differs from the exact upstream-required profile.
    SifProfile,
}

/// Failure before an exact context-bound Offer becomes active.
#[derive(Debug)]
pub enum ContextBoundOfferFailure {
    /// Full runtime context did not match the current negotiated session.
    ContextMismatch {
        /// Exact context field that differed.
        kind: ContextBoundContextMismatch,
        /// Zero-content terminal for the already-committed release.
        release_terminal: FileDisclosureTerminal,
    },
    /// Existing source-bound/authorized Offer preparation failed.
    Source(SourceBoundOfferFailure),
}

impl ContextBoundOfferFailure {
    /// Release terminal that must be durably handled before the failed release is forgotten.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        match self {
            Self::ContextMismatch {
                release_terminal, ..
            } => *release_terminal,
            Self::Source(error) => error.release_terminal(),
        }
    }
}

/// Exact context-bound Offer sealed but not yet carrier-confirmed.
pub struct PreparedContextBoundOffer {
    inner: PreparedSourceBoundOffer,
    context: AuthorizedReleaseContext,
}

impl PreparedContextBoundOffer {
    /// Exact authority-derived Offer.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Sealed Offer envelope. No file-content bytes are contained here.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Advance after carrier confirmation of the Offer envelope.
    pub fn confirm_sent(self) -> ContextBoundAwaitingResponse {
        ContextBoundAwaitingResponse {
            inner: self.inner.confirm_sent(),
            context: self.context,
        }
    }

    /// Ambiguous Offer transport terminalizes zero protected-content bytes.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        self.inner.transport_uncertain()
    }
}

/// Context-bound Offer awaiting authenticated peer Accept/Reject.
pub struct ContextBoundAwaitingResponse {
    inner: SourceBoundAwaitingResponse,
    context: AuthorizedReleaseContext,
}

impl ContextBoundAwaitingResponse {
    /// Exact authority/source/context-bound Offer.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Open the authenticated peer decision and initialize the exact-ledger send journal.
    ///
    /// The current authorization generation is checked here as an early refusal. Accepted
    /// streaming rechecks it under the live mutex immediately before every content write.
    pub fn open_response(
        self,
        envelope: &[u8],
        chain: &Chain,
    ) -> Result<ContextBoundOfferOutcome, ContextBoundResponseFailure> {
        if let Err(error) = self.context.require_current_authorization(chain) {
            return Err(ContextBoundResponseFailure::Authorization {
                error,
                release_terminal: zero_content_terminal(self.inner.offer().release_id()),
            });
        }
        match self.inner.open_response(envelope, chain) {
            Ok(SourceBoundOfferOutcome::Rejected(rejected)) => {
                Ok(ContextBoundOfferOutcome::Rejected(rejected))
            }
            Ok(SourceBoundOfferOutcome::Accepted(inner)) => {
                Ok(ContextBoundOfferOutcome::Accepted(ContextBoundOutboundStreaming {
                    inner,
                    context: self.context,
                }))
            }
            Err(error) => Err(ContextBoundResponseFailure::Source(error)),
        }
    }
}

/// Peer disposition for one context-bound source Offer.
pub enum ContextBoundOfferOutcome {
    /// Peer accepted; every content write now requires live authorization freshness.
    Accepted(ContextBoundOutboundStreaming),
    /// Peer rejected; no protected content was released.
    Rejected(ResolvedRejectedAuthorizedRelease),
}

/// Failure while opening an Offer response under retained release context.
#[derive(Debug)]
pub enum ContextBoundResponseFailure {
    /// Live consent generation no longer matches the committed release.
    Authorization {
        /// Freshness/signer mismatch.
        error: CurrentReleaseAuthorizationError,
        /// Exact zero-content terminal for this committed release.
        release_terminal: FileDisclosureTerminal,
    },
    /// Underlying source-bound Offer/journal transition failed.
    Source(SourceBoundOfferFailure),
}

impl ContextBoundResponseFailure {
    /// Release terminal that must be durably handled.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        match self {
            Self::Authorization {
                release_terminal, ..
            } => *release_terminal,
            Self::Source(error) => error.release_terminal(),
        }
    }
}

/// Strongest current outbound content state.
pub struct ContextBoundOutboundStreaming {
    inner: SourceBoundOutboundStreaming,
    context: AuthorizedReleaseContext,
}

impl ContextBoundOutboundStreaming {
    /// Exact release runtime context enforced before every novel content write.
    pub fn context(&self) -> &AuthorizedReleaseContext {
        &self.context
    }

    /// Exact protected Offer governing this release.
    pub fn offer(&self) -> &xenia_ledger::SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Send exactly one next source Chunk while holding the authoritative consent lock.
    ///
    /// `authorization_chain` must be the same mutex through which all consent mutations
    /// for this live ledger are serialized. The guard is retained across write-ahead
    /// prepare, carrier I/O and durable carrier confirmation.
    pub async fn send_next_chunk<T, S>(
        self,
        send: &mut T,
        authorization_chain: &Mutex<Chain>,
        store: &mut S,
    ) -> Result<ContextBoundSendProgress, ContextBoundChunkFailure<S::Error>>
    where
        T: SendEnvelope,
        S: SifProtectedFileSendStore,
    {
        let guard = authorization_chain.lock().await;
        if let Err(error) = self.context.require_current_authorization(&guard) {
            let terminal = exact_confirmed_terminal(&self.inner);
            return Err(ContextBoundChunkFailure::Authorization {
                error,
                release_terminal: terminal,
            });
        }

        match self.inner.send_next_chunk(send, &guard, store).await {
            Ok(SourceBoundSendProgress::More(inner)) => {
                Ok(ContextBoundSendProgress::More(Self {
                    inner,
                    context: self.context,
                }))
            }
            Ok(SourceBoundSendProgress::SourceVerified(inner)) => {
                Ok(ContextBoundSendProgress::SourceVerified(
                    ContextBoundReadyToComplete {
                        inner,
                        context: self.context,
                    },
                ))
            }
            Err(error) => Err(ContextBoundChunkFailure::Source(error)),
        }
    }
}

/// Result of one context-bound content-send step.
pub enum ContextBoundSendProgress {
    /// More authorized source content remains.
    More(ContextBoundOutboundStreaming),
    /// Final source verification succeeded; no more content bytes remain to disclose.
    SourceVerified(ContextBoundReadyToComplete),
}

/// Content-send failure under the exact retained authorization context.
#[derive(Debug)]
pub enum ContextBoundChunkFailure<E> {
    /// Consent/signer generation changed before the next novel content write.
    Authorization {
        /// Exact freshness failure.
        error: CurrentReleaseAuthorizationError,
        /// Exact already-confirmed release prefix; no new Chunk was Prepared.
        release_terminal: FileDisclosureTerminal,
    },
    /// Source/write-ahead/carrier composition failed after freshness admission.
    Source(SourceBoundChunkFailure<E>),
}

impl<E> ContextBoundChunkFailure<E> {
    /// Release terminal derived from the strongest durable disclosure fact available.
    pub const fn release_terminal(&self) -> FileDisclosureTerminal {
        match self {
            Self::Authorization {
                release_terminal, ..
            } => *release_terminal,
            Self::Source(error) => error.release_terminal(),
        }
    }
}

impl<E: fmt::Debug> fmt::Display for ContextBoundChunkFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization { error, .. } => error.fmt(formatter),
            Self::Source(error) => error.fmt(formatter),
        }
    }
}

impl<E: fmt::Debug> std::error::Error for ContextBoundChunkFailure<E> {}

/// All file-content bytes are carrier-confirmed and same-handle source verification passed.
pub struct ContextBoundReadyToComplete {
    inner: SourceBoundReadyToComplete,
    context: AuthorizedReleaseContext,
}

impl ContextBoundReadyToComplete {
    /// Runtime release context retained through content completion.
    pub fn context(&self) -> &AuthorizedReleaseContext {
        &self.context
    }

    /// Prepare the non-content Complete marker.
    ///
    /// A post-content Revocation does not erase already-disclosed bytes and does not need
    /// to block a protocol closure marker that contains no protected file content.
    pub fn prepare_complete(
        self,
    ) -> Result<PreparedContextBoundComplete, SourceBoundCompleteFailure> {
        Ok(PreparedContextBoundComplete {
            inner: self.inner.prepare_complete()?,
            context: self.context,
        })
    }
}

/// Complete marker after context-fresh content emission and final source verification.
pub struct PreparedContextBoundComplete {
    inner: PreparedSourceBoundComplete,
    context: AuthorizedReleaseContext,
}

impl PreparedContextBoundComplete {
    /// Sealed non-content Complete envelope.
    pub fn envelope(&self) -> &[u8] {
        self.inner.envelope()
    }

    /// Release context preserved for audit/custody association.
    pub fn context(&self) -> &AuthorizedReleaseContext {
        &self.context
    }

    /// Confirm Complete and enter remote custody verification.
    pub fn confirm_sent(
        self,
    ) -> Result<AuthorizedOutboundAwaitingCustody, AuthorizedOutboundFailure> {
        self.inner.confirm_sent()
    }

    /// Ambiguous Complete delivery leaves already-completed content accounting intact.
    pub fn transport_uncertain(self) -> AuthorizedReleaseTransportUncertain {
        self.inner.transport_uncertain()
    }
}

fn exact_confirmed_terminal(state: &SourceBoundOutboundStreaming) -> FileDisclosureTerminal {
    let confirmed = state.journal_confirmed_bytes().min(state.offer().size());
    if confirmed == 0 {
        return zero_content_terminal(state.offer().release_id());
    }
    FileDisclosureTerminal {
        release_id: state.offer().release_id(),
        outcome: DisclosureReleaseOutcome::Partial {
            bytes_released: confirmed,
        },
        byte_accounting: FileDisclosureByteAccounting::Exact,
    }
}

fn zero_content_terminal(release_id: uuid::Uuid) -> FileDisclosureTerminal {
    FileDisclosureTerminal {
        release_id,
        outcome: DisclosureReleaseOutcome::Aborted,
        byte_accounting: FileDisclosureByteAccounting::Exact,
    }
}
