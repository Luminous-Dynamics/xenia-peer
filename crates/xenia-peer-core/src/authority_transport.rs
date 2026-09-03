// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Authenticated transport admission for receiver authority-rekey Ack handoff.
//!
//! The receiver rekey barrier may treat a successful local carrier handoff as
//! sufficient to resume *local* authority only when later dependent traffic is
//! constrained to the same reliable ordered Xenia envelope stream. This module
//! makes that assumption executable without changing authenticated transport
//! profile bytes.
//!
//! Crucially, public admission is minted only from
//! [`crate::handshake::AuthenticatedSessionSurface`], which retains the exact
//! transport profile committed into the authenticated negotiated-session
//! context. Callers cannot mint admission from a fresh post-handshake
//! `Transport::transport_profile()` query and accidentally substitute a profile
//! that was not the one authenticated for this session.
//!
//! Current TCP, WebSocket, and QUIC profiles all expose one reliable ordered
//! logical Xenia stream. Their `send_envelope(...).await -> Ok(())` result is a
//! local handoff/completion signal for that stream; it is **not** proof that the
//! peer received, authenticated, or applied the envelope.
//!
//! Future transport revisions that add unordered delivery, unreliable delivery,
//! or multiple independent logical streams must fail this admission until they
//! define and qualify an explicit remote epoch/order barrier.

use thiserror::Error;

use crate::handshake::AuthenticatedSessionSurface;
use crate::transport::{TransportKind, TransportProfileV1};

/// Why an authenticated transport profile cannot currently host the local
/// receiver-rekey authority handoff barrier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthorityRekeyTransportAdmissionError {
    /// The transport does not promise reliable delivery while connected.
    #[error("authority rekey requires a reliable transport profile")]
    Unreliable,
    /// The transport does not preserve Xenia envelope order.
    #[error("authority rekey requires an ordered transport profile")]
    Unordered,
    /// The profile exposes a number of logical Xenia envelope streams other
    /// than exactly one, so local call order is not sufficient to establish one
    /// remote envelope order.
    #[error(
        "authority rekey requires exactly one logical Xenia envelope stream, got {logical_streams}"
    )]
    MultipleOrderingDomains {
        /// Logical stream count from the authenticated profile.
        logical_streams: u16,
    },
    /// The profile is not the exact currently-supported profile for its carrier.
    /// Unknown revisions must not inherit authority-barrier semantics implicitly.
    #[error("authority rekey refuses an unknown or non-current transport profile")]
    UnknownProfileRevision,
}

/// Immutable proof that one capability-authenticated session surface carries a
/// transport profile satisfying Xenia's current local ordering prerequisites for
/// receiver-rekey Ack handoff.
///
/// This value is **not** a writer reservation and conveys no live authority. The
/// peer must separately hold the exclusive fail-closed writer lease across Wire
/// commit and Ack handoff. It also does not prove remote receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRekeyTransportAdmissionV1 {
    kind: TransportKind,
    authenticated_context_hash: [u8; 32],
}

impl AuthorityRekeyTransportAdmissionV1 {
    /// Carrier kind whose exact authenticated profile passed admission.
    pub const fn kind(self) -> TransportKind {
        self.kind
    }

    /// Canonical authenticated session-context hash from the surface that
    /// supplied the admitted profile.
    ///
    /// This binds the static admission record to one authenticated session
    /// context for audit/composition. It is not itself authority to use that
    /// session.
    pub const fn authenticated_context_hash(self) -> [u8; 32] {
        self.authenticated_context_hash
    }
}

impl AuthenticatedSessionSurface {
    /// Admit this authenticated session's exact bound transport profile for the
    /// current local receiver-rekey Ack handoff barrier.
    ///
    /// Admission requires, in order:
    ///
    /// 1. reliable delivery while connected;
    /// 2. ordered Xenia envelope delivery;
    /// 3. exactly one logical Xenia envelope stream/order domain;
    /// 4. the exact currently-supported profile for the declared carrier kind.
    ///
    /// The final exact-profile check prevents a future profile revision from
    /// silently inheriting this security property merely because its coarse
    /// fields happen to match today's values.
    pub fn authority_rekey_transport_admission(
        &self,
    ) -> Result<AuthorityRekeyTransportAdmissionV1, AuthorityRekeyTransportAdmissionError> {
        admit_profile(self.transport_profile(), self.context_hash())
    }
}

fn admit_profile(
    profile: &TransportProfileV1,
    authenticated_context_hash: [u8; 32],
) -> Result<AuthorityRekeyTransportAdmissionV1, AuthorityRekeyTransportAdmissionError> {
    if !profile.reliable {
        return Err(AuthorityRekeyTransportAdmissionError::Unreliable);
    }
    if !profile.ordered {
        return Err(AuthorityRekeyTransportAdmissionError::Unordered);
    }
    if profile.logical_streams != 1 {
        return Err(
            AuthorityRekeyTransportAdmissionError::MultipleOrderingDomains {
                logical_streams: profile.logical_streams,
            },
        );
    }
    if !profile.is_current_supported_profile() {
        return Err(AuthorityRekeyTransportAdmissionError::UnknownProfileRevision);
    }

    Ok(AuthorityRekeyTransportAdmissionV1 {
        kind: profile.kind,
        authenticated_context_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT_HASH: [u8; 32] = [0xA5; 32];

    #[test]
    fn all_current_carriers_have_one_admitted_ordering_domain() {
        for kind in [
            TransportKind::Tcp,
            TransportKind::WebSocket,
            TransportKind::Quic,
        ] {
            let profile = TransportProfileV1::current(kind);
            let admission = admit_profile(&profile, CONTEXT_HASH).unwrap();
            assert_eq!(admission.kind(), kind);
            assert_eq!(admission.authenticated_context_hash(), CONTEXT_HASH);
            assert!(profile.reliable);
            assert!(profile.ordered);
            assert_eq!(profile.logical_streams, 1);
        }
    }

    #[test]
    fn unreliable_profile_fails_closed() {
        let mut profile = TransportProfileV1::current(TransportKind::Tcp);
        profile.reliable = false;
        assert_eq!(
            admit_profile(&profile, CONTEXT_HASH),
            Err(AuthorityRekeyTransportAdmissionError::Unreliable)
        );
    }

    #[test]
    fn unordered_profile_fails_closed() {
        let mut profile = TransportProfileV1::current(TransportKind::WebSocket);
        profile.ordered = false;
        assert_eq!(
            admit_profile(&profile, CONTEXT_HASH),
            Err(AuthorityRekeyTransportAdmissionError::Unordered)
        );
    }

    #[test]
    fn multiple_logical_streams_fail_closed() {
        let mut profile = TransportProfileV1::current(TransportKind::Quic);
        profile.logical_streams = 2;
        assert_eq!(
            admit_profile(&profile, CONTEXT_HASH),
            Err(
                AuthorityRekeyTransportAdmissionError::MultipleOrderingDomains {
                    logical_streams: 2,
                }
            )
        );
    }

    #[test]
    fn zero_logical_streams_fail_closed() {
        let mut profile = TransportProfileV1::current(TransportKind::Tcp);
        profile.logical_streams = 0;
        assert_eq!(
            admit_profile(&profile, CONTEXT_HASH),
            Err(
                AuthorityRekeyTransportAdmissionError::MultipleOrderingDomains {
                    logical_streams: 0,
                }
            )
        );
    }

    #[test]
    fn unknown_profile_revision_does_not_inherit_authority_semantics() {
        let mut profile = TransportProfileV1::current(TransportKind::Quic);
        profile.protocol_version = profile.protocol_version.saturating_add(1);
        assert_eq!(
            admit_profile(&profile, CONTEXT_HASH),
            Err(AuthorityRekeyTransportAdmissionError::UnknownProfileRevision)
        );
    }
}
