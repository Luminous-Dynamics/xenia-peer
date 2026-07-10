// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keystone proof for the sealed operator channel
//! (`docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`).
//!
//! Proves the design's central claim: **the `xenia-wire` handshake IS the
//! operator authentication.** An operator's *enrolled* Ed25519 + ML-DSA-65
//! identity (the exact keys in the daemon's operator policy, reconstructed from
//! the two seeds the console persists) drives the viewer side of the handshake
//! against a daemon host; both derive identical sealed-channel keys, and the
//! host learns the peer's verified identity, so it can authorize the operator
//! from its policy in one step — no separate `/auth/challenge` + `/auth/verify`
//! proof-of-possession needed.
//!
//! This is the native (no-browser) counterpart of what the WASM console would
//! do; the browser already runs this same viewer handshake against the daemon's
//! video channel (`xenia-wire/xenia-viewer-web`).

use tokio::net::{TcpListener, TcpStream};

use xenia_peer_core::HandshakeManager;
use xenia_peer_core::handshake::{
    perform_host_handshake_authenticating_peer, perform_viewer_handshake_with_transcript,
};
use xenia_peer_core::transport::TcpTransport;

use crate::operator::{EnrolledOperator, OperatorPolicy, OperatorRole};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_identity_drives_the_sealed_channel_handshake() {
    // The operator's persisted identity seeds -- exactly what the console keeps
    // in localStorage (operator_session.rs ED_SEED_KEY / ML_SEED_KEY).
    let op_ed_seed = [7u8; 32];
    let op_ml_seed = [9u8; 32];
    let operator = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
    let operator_ed_pk = operator.identity_public_key_bytes();
    let operator_ml_pk = operator.ml_dsa_public_key_bytes().to_vec();

    // The daemon enrolls that identity with a role -- the same policy the RBAC
    // ceremony uses.
    let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
        operator_id: "alice".to_string(),
        ed25519_pubkey: operator_ed_pk,
        ml_dsa_pubkey: operator_ml_pk.clone(),
        role: OperatorRole::Admin,
    }])
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Daemon (host) side: fresh host identity, capture the authenticated peer.
    let host_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        let mut transport = TcpTransport::new(stream);
        let mut host_mgr = HandshakeManager::new();
        perform_host_handshake_authenticating_peer(&mut transport, &mut host_mgr, "operator", None)
            .await
            .expect("host handshake")
    });

    // Console (viewer) side: driven by the operator's enrolled identity.
    let viewer_task = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).ok();
        let mut transport = TcpTransport::new(stream);
        let mut viewer_mgr = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
        perform_viewer_handshake_with_transcript(&mut transport, &mut viewer_mgr, "daemon")
            .await
            .expect("viewer handshake")
    });

    let (host_outcome, verified_peer) = host_task.await.unwrap();
    let viewer_outcome = viewer_task.await.unwrap();

    // 1. Both sides derived the SAME sealed-channel keys (confidentiality works).
    assert_eq!(
        host_outcome.session_key, viewer_outcome.session_key,
        "host and operator-driven viewer must derive the same AEAD key"
    );
    assert_eq!(
        host_outcome.key_schedule.aead, viewer_outcome.key_schedule.aead,
        "lane schedules must agree"
    );

    // 2. The handshake authenticated the operator's EXACT enrolled keys.
    assert_eq!(verified_peer.ed25519_pk, operator_ed_pk);
    assert_eq!(verified_peer.ml_dsa_pk, operator_ml_pk);

    // 3. So the daemon authorizes the peer straight from its operator policy --
    //    the handshake IS the proof-of-possession the ceremony used to do.
    let enrolled = policy
        .lookup(&verified_peer.ed25519_pk)
        .expect("the authenticated handshake peer is an enrolled operator");
    assert_eq!(enrolled.operator_id, "alice");
    assert_eq!(enrolled.role, OperatorRole::Admin);

    // 4. A non-enrolled identity would authenticate its own handshake but fail
    //    policy lookup -- fail-closed, same as the RBAC path.
    let stranger = HandshakeManager::new();
    assert!(
        policy
            .lookup(&stranger.identity_public_key_bytes())
            .is_none(),
        "an un-enrolled operator identity is refused"
    );
}
