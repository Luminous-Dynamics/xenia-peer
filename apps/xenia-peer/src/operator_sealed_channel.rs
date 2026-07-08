// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-side establishment of an authenticated, `xenia-wire`-sealed operator
//! channel (Slice 2 of `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`).
//!
//! [`establish_operator_channel`] runs the PQC-hybrid host handshake over a
//! transport (typically a WebSocket the console opened), then authorizes the
//! *authenticated* peer against the [`OperatorPolicy`]. Because the handshake
//! already proved possession of the peer's Ed25519 + ML-DSA-65 keys, a
//! successful policy lookup means "this live, confidential channel belongs to
//! enrolled operator X with role R" — the handshake *is* the proof-of-possession
//! the `/auth` ceremony used to provide, and the resulting key schedule seals
//! every subsequent operator payload.
//!
//! Fail-closed: a cryptographically valid handshake from a key that is not
//! enrolled is still refused. Not yet wired into `main.rs` — the
//! `--operator-sealed` endpoint that drives this is the next slice.

#![allow(dead_code)]

use xenia_handshake::SessionKeySchedule;
use xenia_peer_core::handshake::perform_host_handshake_authenticating_peer;
use xenia_peer_core::transport::Transport;
use xenia_peer_core::HandshakeManager;

use crate::operator::{OperatorPolicy, OperatorRole};

/// An authenticated, sealed operator channel. The handshake proved the peer's
/// key possession and the peer was found in the operator policy, so we know the
/// operator id + role and hold the transcript-bound key schedule used to
/// seal/open operator payloads on this channel.
pub(crate) struct AuthenticatedOperatorChannel {
    /// The enrolled operator this channel is authenticated as.
    pub(crate) operator_id: String,
    /// The role the operator is enrolled with (gates privileged actions).
    pub(crate) role: OperatorRole,
    /// The transcript-bound key schedule for sealing this channel's payloads.
    pub(crate) key_schedule: SessionKeySchedule,
}

/// Why establishing an operator channel failed. Both are denials, kept distinct
/// for audit/messaging.
#[derive(Debug)]
pub(crate) enum OperatorChannelError {
    /// The PQC-hybrid handshake itself failed (bad signature, transport error).
    Handshake(String),
    /// The handshake was cryptographically valid, but the peer's key is not an
    /// enrolled operator — refused fail-closed.
    NotEnrolled,
}

impl std::fmt::Display for OperatorChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorChannelError::Handshake(e) => write!(f, "operator handshake failed: {e}"),
            OperatorChannelError::NotEnrolled => {
                write!(f, "authenticated peer is not an enrolled operator")
            }
        }
    }
}

impl std::error::Error for OperatorChannelError {}

/// Establish an authenticated sealed operator channel over `transport`: run the
/// host handshake, then authorize the authenticated peer against `policy`.
pub(crate) async fn establish_operator_channel<T: Transport>(
    transport: &mut T,
    host_mgr: &mut HandshakeManager,
    policy: &OperatorPolicy,
) -> Result<AuthenticatedOperatorChannel, OperatorChannelError> {
    let (outcome, peer) =
        perform_host_handshake_authenticating_peer(transport, host_mgr, "operator", None)
            .await
            .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;

    match policy.lookup(&peer.ed25519_pk) {
        Some(op) => Ok(AuthenticatedOperatorChannel {
            operator_id: op.operator_id.clone(),
            role: op.role,
            key_schedule: outcome.key_schedule,
        }),
        None => Err(OperatorChannelError::NotEnrolled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::EnrolledOperator;
    use tokio::net::{TcpListener, TcpStream};
    use xenia_peer_core::handshake::perform_viewer_handshake_with_transcript;
    use xenia_peer_core::transport::TcpTransport;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_operator_establishes_a_usable_sealed_channel() {
        let op_ed_seed = [3u8; 32];
        let op_ml_seed = [4u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "bob".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::new();
            establish_operator_channel(&mut t, &mut mgr, &policy).await
        });
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
            perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon")
                .await
                .unwrap()
        });

        let channel = host
            .await
            .unwrap()
            .expect("enrolled operator establishes a channel");
        let viewer_outcome = viewer.await.unwrap();

        // The channel is authenticated as the enrolled operator, with its role.
        assert_eq!(channel.operator_id, "bob");
        assert_eq!(channel.role, OperatorRole::Operator);
        // Both sides hold the same sealed-channel key.
        assert_eq!(channel.key_schedule.aead, viewer_outcome.key_schedule.aead);

        // The channel actually carries sealed operator payloads: seal a consent
        // decision host-side, open it viewer-side.
        let mut host_sess = xenia_wire::Session::with_source_id([0x5a; 8], 1);
        host_sess.install_key(channel.key_schedule.aead);
        let mut viewer_sess = xenia_wire::Session::with_source_id([0x5a; 8], 1);
        viewer_sess.install_key(viewer_outcome.key_schedule.aead);

        let payload = br#"{"action":"Approve"}"#;
        let envelope = host_sess
            .seal(payload, xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .expect("seal operator payload");
        let opened = viewer_sess.open(&envelope).expect("open operator payload");
        assert_eq!(opened, *payload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unenrolled_peer_is_refused_after_a_valid_handshake() {
        // A valid operator identity that is simply NOT in the policy.
        let stranger_ed = [5u8; 32];
        let stranger_ml = [6u8; 32];
        // Empty policy: nobody is enrolled.
        let policy = OperatorPolicy::from_operators(vec![]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::new();
            establish_operator_channel(&mut t, &mut mgr, &policy).await
        });
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(stranger_ed, stranger_ml);
            // The viewer's own handshake still completes (the crypto is valid);
            // the host is the one that refuses on policy. Discard the result so
            // the task output is `Send` (Box<dyn Error> is not).
            let _ = perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon").await;
        });

        let result = host.await.unwrap();
        viewer.await.unwrap();
        assert!(
            matches!(result, Err(OperatorChannelError::NotEnrolled)),
            "a valid handshake from an un-enrolled key must be refused"
        );
    }
}
