// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Non-secret evidence projection for fully authenticated Xenia sessions.
//!
//! A cryptographic handshake is necessary but not sufficient to expose an
//! application surface: Xenia separately authenticates the negotiated transport,
//! pre-session/availability policy, and the sealed capabilities frame. This module
//! preserves that distinction and exports a narrow, opaque type that downstream
//! subsystems can require instead of trusting booleans such as `authenticated`.
//!
//! The evidence types here intentionally do **not** implement `Deserialize` and do
//! not expose public constructors. They are local type-state tokens, not portable
//! certificates. If evidence must cross a process or trust boundary, its canonical
//! bytes/digest must be carried inside a separately authenticated or signed channel.

use serde::Serialize;
use xenia_handshake::{
    HANDSHAKE_POLICY_PROFILE, HANDSHAKE_TRANSCRIPT_SCHEMA, HandshakeManager,
    SESSION_KEY_SCHEDULE_SCHEMA, host_identity_fingerprint,
};

use crate::handshake::{
    AuthenticatedSessionSurface, HandshakeOutcome, VerifiedPeerIdentity,
    perform_host_handshake_authenticating_peer, perform_viewer_handshake_with_transcript,
};
use crate::transport::Transport;

/// Stable schema for [`AuthenticatedSessionEvidenceV1`].
pub const AUTHENTICATED_SESSION_EVIDENCE_SCHEMA: &str = "xenia-authenticated-session-evidence-v1";
/// Domain separator for canonical evidence commitments.
pub const AUTHENTICATED_SESSION_EVIDENCE_DOMAIN: &[u8] =
    b"xenia-authenticated-session-evidence-v1\0";

/// Role played by the remote peer authenticated by Xenia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AuthenticatedPeerRole {
    /// Remote peer is the controlled/serving host.
    Host,
    /// Remote peer is the viewer/operator side.
    Viewer,
}

/// Opaque proof-of-path that a real Xenia handshake authenticated a peer.
///
/// This type is intentionally not serializable/deserializable as a claim object and
/// has no public constructor. It can only be produced by the wrapper handshake
/// functions in this module, which delegate to Xenia's existing hybrid handshake
/// verification before retaining the non-secret binding material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHandshakeEvidence {
    peer_role: AuthenticatedPeerRole,
    peer_identity_fingerprint: [u8; 32],
    transcript_hash: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
}

impl AuthenticatedHandshakeEvidence {
    /// Authenticated remote role.
    pub const fn peer_role(&self) -> AuthenticatedPeerRole {
        self.peer_role
    }

    /// BLAKE3-256 fingerprint of the authenticated remote signing identity.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Canonical public handshake transcript hash.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Context hash committed into the handshake, if the session used one.
    pub const fn negotiated_context_hash(&self) -> Option<[u8; 32]> {
        self.negotiated_context_hash
    }

    /// Bind this verified handshake to Xenia's capability-authenticated application
    /// surface. Current strong evidence requires the handshake to have committed the
    /// exact surface context hash; legacy/context-free handshakes fail closed.
    pub fn bind_authenticated_surface(
        &self,
        surface: &AuthenticatedSessionSurface,
    ) -> Result<AuthenticatedSessionEvidenceV1, AuthenticatedSessionEvidenceError> {
        let expected = self
            .negotiated_context_hash
            .ok_or(AuthenticatedSessionEvidenceError::MissingNegotiatedContext)?;
        if expected != surface.context_hash() {
            return Err(AuthenticatedSessionEvidenceError::ContextHashMismatch);
        }

        Ok(AuthenticatedSessionEvidenceV1 {
            schema: AUTHENTICATED_SESSION_EVIDENCE_SCHEMA.to_string(),
            peer_role: self.peer_role,
            peer_identity_fingerprint: self.peer_identity_fingerprint,
            transcript_hash: self.transcript_hash,
            session_context_hash: surface.context_hash(),
            handshake_policy_profile: HANDSHAKE_POLICY_PROFILE.to_string(),
            handshake_transcript_schema: HANDSHAKE_TRANSCRIPT_SCHEMA.to_string(),
            session_key_schedule_schema: SESSION_KEY_SCHEDULE_SCHEMA.to_string(),
            telemetry_enabled: surface.capabilities().telemetry_enabled,
            input_control_enabled: surface.capabilities().input_control_enabled,
        })
    }
}

/// Non-secret projection of a fully authenticated Xenia application session.
///
/// The fields are private and the type deliberately omits `Deserialize`, preventing
/// downstream code from manufacturing a trusted token from arbitrary bytes. Use the
/// read-only accessors or [`Self::canonical_bytes`] / [`Self::digest`] for binding
/// another in-process security decision to the exact authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedSessionEvidenceV1 {
    schema: String,
    peer_role: AuthenticatedPeerRole,
    peer_identity_fingerprint: [u8; 32],
    transcript_hash: [u8; 32],
    session_context_hash: [u8; 32],
    handshake_policy_profile: String,
    handshake_transcript_schema: String,
    session_key_schedule_schema: String,
    telemetry_enabled: bool,
    input_control_enabled: bool,
}

impl AuthenticatedSessionEvidenceV1 {
    /// Stable schema label.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Authenticated remote role.
    pub const fn peer_role(&self) -> AuthenticatedPeerRole {
        self.peer_role
    }

    /// Fingerprint of the authenticated remote Ed25519 + ML-DSA-65 identity.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Canonical handshake transcript hash.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Exact authenticated application-session context hash.
    pub const fn session_context_hash(&self) -> [u8; 32] {
        self.session_context_hash
    }

    /// Whether the sealed capabilities frame enabled telemetry.
    pub const fn telemetry_enabled(&self) -> bool {
        self.telemetry_enabled
    }

    /// Whether the sealed capabilities frame enabled remote input/control.
    pub const fn input_control_enabled(&self) -> bool {
        self.input_control_enabled
    }

    /// Canonical bincode-v1 encoding for local evidence binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedSessionEvidenceError> {
        bincode::serialize(self).map_err(AuthenticatedSessionEvidenceError::Encoding)
    }

    /// Domain-separated BLAKE3-256 commitment to the complete evidence projection.
    pub fn digest(&self) -> Result<[u8; 32], AuthenticatedSessionEvidenceError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUTHENTICATED_SESSION_EVIDENCE_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Errors while projecting authenticated Xenia session state.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedSessionEvidenceError {
    /// Strong application evidence requires a context-bound handshake.
    #[error("handshake did not commit a negotiated session context")]
    MissingNegotiatedContext,
    /// The capability-authenticated surface does not match the context committed
    /// by the cryptographic handshake.
    #[error("authenticated session surface does not match handshake context")]
    ContextHashMismatch,
    /// Canonical evidence encoding failed.
    #[error("authenticated session evidence encoding failed: {0}")]
    Encoding(#[from] bincode::Error),
}

/// Perform the host side of Xenia's hybrid handshake and return an opaque token
/// proving which viewer identity was actually verified by that handshake.
pub async fn perform_host_handshake_with_evidence<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
    negotiated_context_hash: Option<[u8; 32]>,
) -> Result<(HandshakeOutcome, AuthenticatedHandshakeEvidence), Box<dyn std::error::Error>> {
    let (outcome, peer) = perform_host_handshake_authenticating_peer(
        transport,
        mgr,
        peer_id,
        negotiated_context_hash,
    )
    .await?;
    let evidence = host_handshake_evidence(&outcome, &peer);
    Ok((outcome, evidence))
}

/// Perform the viewer side of Xenia's hybrid handshake and return an opaque token
/// proving the host identity whose finalize signatures were verified.
pub async fn perform_viewer_handshake_with_evidence<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<(HandshakeOutcome, AuthenticatedHandshakeEvidence), Box<dyn std::error::Error>> {
    let outcome = perform_viewer_handshake_with_transcript(transport, mgr, peer_id).await?;
    let evidence = AuthenticatedHandshakeEvidence {
        peer_role: AuthenticatedPeerRole::Host,
        peer_identity_fingerprint: outcome.host_identity_fingerprint,
        transcript_hash: outcome.transcript_hash,
        negotiated_context_hash: outcome.negotiated_context_hash,
    };
    Ok((outcome, evidence))
}

fn host_handshake_evidence(
    outcome: &HandshakeOutcome,
    peer: &VerifiedPeerIdentity,
) -> AuthenticatedHandshakeEvidence {
    AuthenticatedHandshakeEvidence {
        peer_role: AuthenticatedPeerRole::Viewer,
        peer_identity_fingerprint: host_identity_fingerprint(&peer.ed25519_pk, &peer.ml_dsa_pk),
        transcript_hash: outcome.transcript_hash,
        negotiated_context_hash: outcome.negotiated_context_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        INPUT_EVENT_SCHEMA_VERSION, LANE_ENVELOPE_MAGIC, LANE_ENVELOPE_SCHEMA_VERSION, PixelFormat,
        RawCapabilities,
    };
    use crate::handshake::PendingSessionSurface;
    use crate::transport::{TransportKind, TransportProfileV1};

    fn capabilities(telemetry_enabled: bool) -> RawCapabilities {
        RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1,
            audio: None,
            video_format: PixelFormat::Passthrough,
            telemetry_enabled,
            input_control_enabled: false,
            clipboard_enabled: false,
            input_event_schema_version: INPUT_EVENT_SCHEMA_VERSION,
            lane_envelope_version: LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: LANE_ENVELOPE_MAGIC,
        }
    }

    fn authenticated_surface(telemetry_enabled: bool) -> AuthenticatedSessionSurface {
        PendingSessionSurface::new(None, TransportProfileV1::current(TransportKind::Tcp))
            .unwrap()
            .authenticate_capabilities(capabilities(telemetry_enabled))
            .unwrap()
    }

    fn handshake_evidence(context_hash: Option<[u8; 32]>) -> AuthenticatedHandshakeEvidence {
        AuthenticatedHandshakeEvidence {
            peer_role: AuthenticatedPeerRole::Host,
            peer_identity_fingerprint: [0x11; 32],
            transcript_hash: [0x22; 32],
            negotiated_context_hash: context_hash,
        }
    }

    #[test]
    fn context_free_handshake_cannot_mint_application_evidence() {
        let surface = authenticated_surface(true);
        let evidence = handshake_evidence(None);
        assert!(matches!(
            evidence.bind_authenticated_surface(&surface),
            Err(AuthenticatedSessionEvidenceError::MissingNegotiatedContext)
        ));
    }

    #[test]
    fn mismatched_surface_context_fails_closed() {
        let surface = authenticated_surface(true);
        let evidence = handshake_evidence(Some([0x55; 32]));
        assert!(matches!(
            evidence.bind_authenticated_surface(&surface),
            Err(AuthenticatedSessionEvidenceError::ContextHashMismatch)
        ));
    }

    #[test]
    fn exact_context_mints_opaque_session_evidence() {
        let surface = authenticated_surface(true);
        let evidence = handshake_evidence(Some(surface.context_hash()));
        let bound = evidence.bind_authenticated_surface(&surface).unwrap();
        assert_eq!(bound.peer_role(), AuthenticatedPeerRole::Host);
        assert_eq!(bound.peer_identity_fingerprint(), [0x11; 32]);
        assert_eq!(bound.transcript_hash(), [0x22; 32]);
        assert_eq!(bound.session_context_hash(), surface.context_hash());
        assert!(bound.telemetry_enabled());
        assert_ne!(bound.digest().unwrap(), [0u8; 32]);
    }

    #[test]
    fn evidence_commitment_changes_with_authenticated_capabilities() {
        let surface_a = authenticated_surface(false);
        let surface_b = authenticated_surface(true);
        let evidence_a = handshake_evidence(Some(surface_a.context_hash()));
        let evidence_b = handshake_evidence(Some(surface_b.context_hash()));
        let bound_a = evidence_a.bind_authenticated_surface(&surface_a).unwrap();
        let bound_b = evidence_b.bind_authenticated_surface(&surface_b).unwrap();
        assert_ne!(bound_a.digest().unwrap(), bound_b.digest().unwrap());
    }
}
