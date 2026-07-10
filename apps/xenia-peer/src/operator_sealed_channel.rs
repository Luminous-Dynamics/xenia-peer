// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The daemon-side `xenia-wire`-sealed operator channel (Slices 2–3 +
//! endpoint of `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`).
//!
//! [`establish_operator_channel`] runs the PQC-hybrid host handshake over a
//! transport (the WebSocket the console opened), then authorizes the
//! *authenticated* peer against the [`OperatorPolicy`]. Because the handshake
//! already proved possession of the peer's Ed25519 + ML-DSA-65 keys, a
//! successful policy lookup means "this live, confidential channel belongs to
//! enrolled operator X with role R" — the handshake *is* the proof-of-possession
//! the `/auth` ceremony used to provide, and the resulting key schedule seals
//! every subsequent operator payload. [`serve_sealed_operator_channel`] then
//! reads sealed consent decisions over it, and [`run_sealed_operator_endpoint`]
//! is the `--operator-sealed` daemon endpoint that drives the whole thing.
//!
//! Fail-closed: a cryptographically valid handshake from a key that is not
//! enrolled is still refused.

#![allow(dead_code)]

use tokio::net::TcpListener;
use xenia_handshake::SessionKeySchedule;
use xenia_peer_core::HandshakeManager;
use xenia_peer_core::handshake::perform_host_handshake_authenticating_peer;
use xenia_peer_core::transport::Transport;
use xenia_transport_ws::WsTransport;

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

/// Fixed `xenia-wire` source id for the operator channel, shared by the daemon
/// (opener) and the console (sealer) so the sealed-envelope nonces line up.
const OPERATOR_CHANNEL_SOURCE_ID: [u8; 8] = *b"xnaopch1";

/// Everything the sealed consent serve loop needs once the channel is up —
/// the same session-scoped state the plaintext consent server takes.
pub(crate) struct SealedConsentDeps {
    pub(crate) require_operator_auth: bool,
    pub(crate) auth_state: std::sync::Arc<crate::operator_http::OperatorAuthState>,
    pub(crate) session_id: [u8; 16],
    pub(crate) session_uuid: uuid::Uuid,
    pub(crate) ledger: std::sync::Arc<tokio::sync::Mutex<xenia_ledger::Chain>>,
    pub(crate) grant_tx: tokio::sync::oneshot::Sender<bool>,
    pub(crate) revoked: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Serve one sealed operator channel over `transport`: establish the
/// authenticated channel (handshake + policy), then read sealed consent
/// envelopes. Each envelope opens (with the channel key) to the **same** message
/// the plaintext consent port accepts, decoded via `decode_consent_decision` —
/// so this adds PQC confidentiality + handshake channel-auth while auth,
/// per-action non-repudiation, and ledger attribution are preserved unchanged.
/// Drives the grant/revoke via the shared `apply_consent_decision`.
pub(crate) async fn serve_sealed_operator_channel<T: Transport>(
    transport: &mut T,
    host_mgr: &mut HandshakeManager,
    policy: &OperatorPolicy,
    deps: SealedConsentDeps,
) -> Result<(), OperatorChannelError> {
    let channel = establish_operator_channel(transport, host_mgr, policy).await?;
    tracing::info!(
        operator = %channel.operator_id,
        role = ?channel.role,
        "sealed operator channel established"
    );

    let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
    session.install_key(channel.key_schedule.aead);

    let SealedConsentDeps {
        require_operator_auth,
        auth_state,
        session_id,
        session_uuid,
        ledger,
        grant_tx,
        revoked,
    } = deps;
    let mut grant_tx = Some(grant_tx);

    // Read sealed consent decisions for the life of the channel.
    while let Ok(envelope) = transport.recv_envelope().await {
        let Ok(plaintext) = session.open(&envelope) else {
            tracing::warn!("failed to open sealed consent envelope");
            continue;
        };
        let Ok(text) = std::str::from_utf8(&plaintext) else {
            continue;
        };
        let Some(decoded) =
            crate::decode_consent_decision(text, require_operator_auth, &auth_state, &session_id)
        else {
            continue;
        };
        match crate::consent_server::apply_consent_decision(
            decoded,
            &mut grant_tx,
            &revoked,
            &ledger,
            session_uuid,
        )
        .await
        {
            crate::consent_server::ConsentFollowup::KeepServing => {}
            crate::consent_server::ConsentFollowup::Stop => break,
        }
    }
    Ok(())
}

/// The `--operator-sealed` daemon endpoint (v1): accept **one** WebSocket
/// connection over `listener`, wrap it as a `WsTransport`, and serve the sealed
/// operator channel over it. Fail-closed and simple — a failed handshake or an
/// un-enrolled peer just ends the channel, and the session's consent then times
/// out (deny). v1 is single-connection: no accept-loop reconnect (unlike the
/// plaintext `ConsentServer`); that, and letting a rejected first connection
/// yield to a later legitimate one, is the next increment.
pub(crate) async fn run_sealed_operator_endpoint(
    listener: TcpListener,
    mut host_mgr: HandshakeManager,
    policy: OperatorPolicy,
    deps: SealedConsentDeps,
) {
    let (stream, peer) = match listener.accept().await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::error!(error = %err, "sealed operator endpoint accept failed");
            return;
        }
    };
    stream.set_nodelay(true).ok();
    let mut transport = match WsTransport::accept_stream(stream).await {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(error = %err, "sealed operator websocket upgrade failed");
            return;
        }
    };
    tracing::info!(peer = %peer, "sealed operator channel connection accepted");
    if let Err(err) =
        serve_sealed_operator_channel(&mut transport, &mut host_mgr, &policy, deps).await
    {
        tracing::warn!(error = %err, "sealed operator channel ended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::EnrolledOperator;
    use crate::operator_auth::{AUTH_RATE_MAX, AUTH_RATE_WINDOW_SECS, ChallengeStore, RateLimiter};
    use crate::operator_http::OperatorAuthState;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex as TokioMutex, oneshot};
    use uuid::Uuid;
    use xenia_ledger::Chain;
    use xenia_peer_core::handshake::perform_viewer_handshake_with_transcript;
    // `Transport` (for `send_envelope`) comes in via `use super::*`.
    use xenia_peer_core::transport::TcpTransport;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_channel_serves_a_consent_decision() {
        // An enrolled operator drives the whole path: establish the sealed
        // channel, then send a sealed consent decision over it.
        let op_ed = [11u8; 32];
        let op_ml = [12u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "carol".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        let revoked_daemon = revoked.clone();

        // Daemon: establish the channel, then serve sealed consent.
        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::new();
            let daemon = SigningKey::generate(&mut rand::thread_rng());
            let auth_state = Arc::new(OperatorAuthState {
                policy: OperatorPolicy::default(),
                challenges: TokioMutex::new(ChallengeStore::new()),
                daemon_key: daemon.clone(),
                rate_limiter: TokioMutex::new(RateLimiter::new(
                    AUTH_RATE_MAX,
                    AUTH_RATE_WINDOW_SECS,
                )),
            });
            let ledger = Arc::new(TokioMutex::new(Chain::new(daemon)));
            let deps = SealedConsentDeps {
                // Auth off: the sealed payload is a plaintext action, so this
                // exercises the sealed transport + serve wiring (the token/auth
                // path is covered by operator_http/operator_live_smoke).
                require_operator_auth: false,
                auth_state,
                session_id: [0x5a; 16],
                session_uuid: Uuid::from_u128(3),
                ledger,
                grant_tx,
                revoked: revoked_daemon,
            };
            serve_sealed_operator_channel(&mut t, &mut mgr, &policy, deps).await
        });

        // Console (viewer): handshake with the enrolled identity, then seal an
        // "Approve" over the channel key.
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(op_ed, op_ml);
            let outcome = perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon")
                .await
                .unwrap();
            let mut sess = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
            sess.install_key(outcome.key_schedule.aead);
            let envelope = sess
                .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
                .unwrap();
            t.send_envelope(&envelope).await.unwrap();
            // Hold the connection open briefly so the daemon reads the decision.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        assert!(
            grant_rx.await.unwrap(),
            "a sealed Approve resolves the grant to true"
        );
        assert!(!revoked.load(Ordering::SeqCst));
        let _ = viewer.await;
        let _ = host.await;
    }

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
