// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Authenticated connection-generation binding for receiver authority rekey.
//!
//! A negotiated session-context hash authenticates *what* carrier/profile and
//! capabilities were accepted, but equal contexts can recur across independent
//! handshakes. Receiver authority rekey therefore also binds to the canonical
//! handshake transcript hash for the exact connection generation.
//!
//! The generation is captured **before** capability authentication. This avoids
//! a post-hoc binding API where an already-authenticated surface from handshake
//! A could be relabeled with handshake B merely because both handshakes happened
//! to negotiate the same context.

use thiserror::Error;

use crate::frame::RawCapabilities;
use crate::handshake::{
    AuthenticatedSessionSurface, CapabilityAcceptanceError, HandshakeOutcome, PendingSessionSurface,
};
use crate::transport::{
    TransportAvailabilityProfileV1, TransportPreSessionProfileV1, TransportProfileV1,
};

/// Stable identifier for one authenticated handshake generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticatedHandshakeGenerationV1([u8; 32]);

impl AuthenticatedHandshakeGenerationV1 {
    /// Canonical public handshake-transcript hash for this generation.
    pub const fn transcript_hash(self) -> [u8; 32] {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_test_hash(transcript_hash: [u8; 32]) -> Self {
        Self(transcript_hash)
    }
}

/// Failure while constructing or authenticating a generation-bound authority
/// surface.
#[derive(Debug, Error)]
pub enum AuthorityGenerationBindingError {
    /// The handshake did not commit a negotiated session context, so no
    /// receiver-rekey generation can be constructed from it.
    #[error("handshake did not commit an authenticated negotiated session context")]
    MissingNegotiatedContext,
    /// The ordinary capability-authentication boundary rejected the exact
    /// carrier/profile/capability composition.
    #[error(transparent)]
    Capability(#[from] CapabilityAcceptanceError),
}

/// Pre-capability authority surface bound to one exact authenticated handshake
/// generation.
///
/// This type is the only public path to [`AuthenticatedAuthorityGenerationV1`].
/// It captures the transcript generation before capabilities are authenticated
/// and owns the corresponding [`PendingSessionSurface`] whose expected context
/// is the one committed by the handshake.
#[derive(Debug)]
pub struct PendingAuthorityGenerationV1 {
    pending: PendingSessionSurface,
    generation: AuthenticatedHandshakeGenerationV1,
}

impl PendingAuthorityGenerationV1 {
    /// Construct the receiver-authority pending surface from the completed
    /// handshake and the exact live carrier policy profiles.
    ///
    /// The handshake must have committed a negotiated session context. The
    /// supplied profiles are then checked by [`PendingSessionSurface`] and the
    /// later capability frame must authenticate to that exact committed context.
    pub fn new_with_profiles(
        handshake: &HandshakeOutcome,
        transport_profile: TransportProfileV1,
        pre_session_profile: TransportPreSessionProfileV1,
        availability_profile: TransportAvailabilityProfileV1,
    ) -> Result<Self, AuthorityGenerationBindingError> {
        Self::new_with_values(
            handshake.negotiated_context_hash,
            handshake.transcript_hash,
            transport_profile,
            pre_session_profile,
            availability_profile,
        )
    }

    fn new_with_values(
        expected_context_hash: Option<[u8; 32]>,
        transcript_hash: [u8; 32],
        transport_profile: TransportProfileV1,
        pre_session_profile: TransportPreSessionProfileV1,
        availability_profile: TransportAvailabilityProfileV1,
    ) -> Result<Self, AuthorityGenerationBindingError> {
        let expected_context_hash = expected_context_hash
            .ok_or(AuthorityGenerationBindingError::MissingNegotiatedContext)?;
        let pending = PendingSessionSurface::new_with_profiles(
            Some(expected_context_hash),
            transport_profile,
            pre_session_profile,
            availability_profile,
        )?;
        Ok(Self {
            pending,
            generation: AuthenticatedHandshakeGenerationV1(transcript_hash),
        })
    }

    /// Authenticate the one authoritative capabilities frame and produce the
    /// generation-bound surface used to mint receiver-rekey admission.
    pub fn authenticate_capabilities(
        self,
        capabilities: RawCapabilities,
    ) -> Result<AuthenticatedAuthorityGenerationV1, AuthorityGenerationBindingError> {
        let surface = self.pending.authenticate_capabilities(capabilities)?;
        Ok(AuthenticatedAuthorityGenerationV1 {
            surface,
            generation: self.generation,
        })
    }
}

/// A capability-authenticated session surface bound by construction to the exact
/// authenticated handshake generation that created it.
///
/// Receiver-rekey admission is minted from this type rather than directly from
/// [`AuthenticatedSessionSurface`]. There is intentionally no public API that
/// accepts an already-authenticated surface plus an independently supplied
/// handshake outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAuthorityGenerationV1 {
    surface: AuthenticatedSessionSurface,
    generation: AuthenticatedHandshakeGenerationV1,
}

impl AuthenticatedAuthorityGenerationV1 {
    /// Exact authenticated handshake generation for this surface.
    pub const fn generation(&self) -> AuthenticatedHandshakeGenerationV1 {
        self.generation
    }

    /// Capability-authenticated session surface carried by this generation.
    pub const fn surface(&self) -> &AuthenticatedSessionSurface {
        &self.surface
    }

    /// Consume the generation wrapper and recover the ordinary authenticated
    /// application surface. This deliberately discards receiver-rekey
    /// generation evidence; admission cannot be minted after doing so.
    pub fn into_surface(self) -> AuthenticatedSessionSurface {
        self.surface
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        INPUT_EVENT_SCHEMA_VERSION, LANE_ENVELOPE_MAGIC, LANE_ENVELOPE_SCHEMA_VERSION, PixelFormat,
    };
    use crate::transport::TransportKind;

    fn canonical_capabilities() -> RawCapabilities {
        RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1,
            audio: None,
            video_format: PixelFormat::Rgba8,
            telemetry_enabled: false,
            input_control_enabled: true,
            clipboard_enabled: true,
            input_event_schema_version: INPUT_EVENT_SCHEMA_VERSION,
            lane_envelope_version: LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: LANE_ENVELOPE_MAGIC,
        }
    }

    fn exact_profiles(
        kind: TransportKind,
    ) -> (
        TransportProfileV1,
        TransportPreSessionProfileV1,
        TransportAvailabilityProfileV1,
    ) {
        (
            TransportProfileV1::current(kind),
            TransportPreSessionProfileV1::current(kind),
            TransportAvailabilityProfileV1::current(kind),
        )
    }

    fn expected_context_hash(kind: TransportKind, capabilities: RawCapabilities) -> [u8; 32] {
        let (transport, pre_session, availability) = exact_profiles(kind);
        PendingSessionSurface::new_with_profiles(None, transport, pre_session, availability)
            .unwrap()
            .authenticate_capabilities(capabilities)
            .unwrap()
            .context_hash()
    }

    #[test]
    fn equal_contexts_from_distinct_handshakes_remain_distinct_generations() {
        let capabilities = canonical_capabilities();
        let context_hash = expected_context_hash(TransportKind::Tcp, capabilities.clone());
        let (transport_a, pre_a, availability_a) = exact_profiles(TransportKind::Tcp);
        let (transport_b, pre_b, availability_b) = exact_profiles(TransportKind::Tcp);

        let a = PendingAuthorityGenerationV1::new_with_values(
            Some(context_hash),
            [0xA1; 32],
            transport_a,
            pre_a,
            availability_a,
        )
        .unwrap()
        .authenticate_capabilities(capabilities.clone())
        .unwrap();
        let b = PendingAuthorityGenerationV1::new_with_values(
            Some(context_hash),
            [0xB2; 32],
            transport_b,
            pre_b,
            availability_b,
        )
        .unwrap()
        .authenticate_capabilities(capabilities)
        .unwrap();

        assert_eq!(a.surface().context_hash(), b.surface().context_hash());
        assert_ne!(a.generation(), b.generation());
    }

    #[test]
    fn context_mismatch_fails_during_capability_authentication() {
        let capabilities = canonical_capabilities();
        let mut wrong_context =
            expected_context_hash(TransportKind::WebSocket, capabilities.clone());
        wrong_context[0] ^= 0xFF;
        let (transport, pre_session, availability) = exact_profiles(TransportKind::WebSocket);
        let pending = PendingAuthorityGenerationV1::new_with_values(
            Some(wrong_context),
            [0x33; 32],
            transport,
            pre_session,
            availability,
        )
        .unwrap();

        assert!(matches!(
            pending.authenticate_capabilities(capabilities),
            Err(AuthorityGenerationBindingError::Capability(
                CapabilityAcceptanceError::ContextHashMismatch
            ))
        ));
    }

    #[test]
    fn missing_handshake_context_cannot_create_pending_rekey_generation() {
        let (transport, pre_session, availability) = exact_profiles(TransportKind::Quic);
        assert!(matches!(
            PendingAuthorityGenerationV1::new_with_values(
                None,
                [0x44; 32],
                transport,
                pre_session,
                availability,
            ),
            Err(AuthorityGenerationBindingError::MissingNegotiatedContext)
        ));
    }

    #[test]
    fn generation_is_fixed_before_capability_authentication() {
        let capabilities = canonical_capabilities();
        let context_hash = expected_context_hash(TransportKind::Tcp, capabilities.clone());
        let (transport, pre_session, availability) = exact_profiles(TransportKind::Tcp);
        let pending = PendingAuthorityGenerationV1::new_with_values(
            Some(context_hash),
            [0x55; 32],
            transport,
            pre_session,
            availability,
        )
        .unwrap();
        let authenticated = pending.authenticate_capabilities(capabilities).unwrap();
        assert_eq!(authenticated.generation().transcript_hash(), [0x55; 32]);
    }
}
