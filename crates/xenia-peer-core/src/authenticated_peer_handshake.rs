// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Non-forgeable-by-external-code binding between one completed Xenia host
//! handshake and the hybrid peer identity authenticated by that same handshake.
//!
//! [`crate::handshake::VerifiedPeerIdentity`] intentionally exposes its public
//! key bytes for policy lookup and compatibility, which also means external Rust
//! code can construct that value directly. Security-sensitive integrations must
//! therefore not treat the bare identity struct as proof that a Xenia handshake
//! authenticated it.
//!
//! [`AuthenticatedPeerHandshakeV1`] closes that type-level gap. Its fields and
//! constructor are private to this module, and the only public creation path is
//! [`perform_host_handshake_authenticated_peer_v1`], which obtains both the
//! [`HandshakeOutcome`] and [`VerifiedPeerIdentity`] from one invocation of
//! Xenia's real hybrid host handshake.
//!
//! This type proves handshake authentication at one generation. It deliberately
//! does **not** claim that the underlying transport is still live; a downstream
//! connection adapter must preserve transport ownership/liveness separately.

use crate::{
    handshake::{
        HandshakeOutcome, VerifiedPeerIdentity, perform_host_handshake_authenticating_peer,
    },
    transport::Transport,
};
use xenia_handshake::HandshakeManager;

/// One completed host-side Xenia handshake bound to the exact hybrid peer
/// identity authenticated during that same handshake.
///
/// This type has no public constructor, `Default`, deserializer, or `From`
/// implementation. External code can inspect the authenticated facts but
/// cannot synthesize this wrapper from an arbitrary public-key pair or an
/// independently obtained handshake outcome.
///
/// The wrapper is authentication evidence for a handshake generation, not a
/// liveness token for a currently open transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeerHandshakeV1 {
    outcome: HandshakeOutcome,
    peer_identity: VerifiedPeerIdentity,
}

impl AuthenticatedPeerHandshakeV1 {
    fn from_authenticated_parts(
        outcome: HandshakeOutcome,
        peer_identity: VerifiedPeerIdentity,
    ) -> Self {
        Self {
            outcome,
            peer_identity,
        }
    }

    /// Exact completed handshake outcome that authenticated this peer.
    pub const fn outcome(&self) -> &HandshakeOutcome {
        &self.outcome
    }

    /// Exact Ed25519 + ML-DSA-65 peer public keys whose signatures were
    /// authenticated by this handshake.
    pub const fn peer_identity(&self) -> &VerifiedPeerIdentity {
        &self.peer_identity
    }

    /// Canonical public transcript generation for this exact handshake.
    ///
    /// This is a connection-generation identity, not an application principal
    /// identifier. Callers must not derive user/party identity from it.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.outcome.transcript_hash
    }

    /// Negotiated authenticated session-context commitment, when present.
    pub const fn negotiated_context_hash(&self) -> Option<[u8; 32]> {
        self.outcome.negotiated_context_hash
    }

    /// Exact peer Ed25519 verifying key authenticated by the handshake.
    pub const fn peer_ed25519_public_key(&self) -> [u8; 32] {
        self.peer_identity.ed25519_pk
    }

    /// Exact peer ML-DSA-65 verifying key authenticated by the handshake.
    pub fn peer_ml_dsa_public_key(&self) -> &[u8] {
        &self.peer_identity.ml_dsa_pk
    }
}

/// Perform the real host-side hybrid handshake and return a sealed binding
/// between the completed outcome and the exact peer key pair authenticated by
/// that same invocation.
///
/// Security-sensitive downstream adapters should prefer this function over the
/// legacy tuple-returning handshake API whenever the Rust type itself is being
/// used as evidence that peer identity was authenticated.
pub async fn perform_host_handshake_authenticated_peer_v1<T: Transport>(
    transport: &mut T,
    manager: &mut HandshakeManager,
    peer_id: &str,
    negotiated_context_hash: Option<[u8; 32]>,
) -> Result<AuthenticatedPeerHandshakeV1, Box<dyn std::error::Error>> {
    let (outcome, peer_identity) = perform_host_handshake_authenticating_peer(
        transport,
        manager,
        peer_id,
        negotiated_context_hash,
    )
    .await?;

    Ok(AuthenticatedPeerHandshakeV1::from_authenticated_parts(
        outcome,
        peer_identity,
    ))
}
