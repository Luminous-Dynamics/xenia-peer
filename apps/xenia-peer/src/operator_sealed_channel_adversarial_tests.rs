// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live adversarial tests for the hardened sealed operator endpoint.
//!
//! These use the real WebSocket carrier, real PQC-hybrid ViewerHandshake, real
//! operator policy lookup, real rekey Proposal emission, and the production
//! endpoint loop. They prove that protocol ambiguity tears down the current
//! authenticated connection and that authority resumes only after a fresh
//! handshake on a new connection.

use super::*;

use crate::operator::{EnrolledOperator, OperatorRole};
use crate::operator_auth::{AUTH_RATE_MAX, AUTH_RATE_WINDOW_SECS};
use crate::operator_http::OperatorAuthState;
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex as TokioMutex, oneshot};
use uuid::Uuid;
use xenia_handshake::HandshakeManager;
use xenia_ledger::Chain;
use xenia_peer_core::transport::Transport;
use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};

fn fixture(
    op_ed: [u8; 32],
    op_ml: [u8; 32],
    session_uuid: Uuid,
    rekey_interval: Duration,
) -> (OperatorPolicy, SealedConsentDeps, Arc<AtomicBool>) {
    let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
    let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
        operator_id: format!("adversarial-rekey-{session_uuid}"),
        ed25519_pubkey: operator.identity_public_key_bytes(),
        ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
        ml_dsa_87_pubkey: None,
        role: OperatorRole::Operator,
    }])
    .unwrap();

    let revoked = Arc::new(AtomicBool::new(false));
    let daemon = SigningKey::generate(&mut rand::thread_rng());
    let auth_state = Arc::new(OperatorAuthState::new(
        OperatorPolicy::default(),
        daemon.clone(),
        xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
        HandshakeManager::new(),
        AUTH_RATE_MAX,
        AUTH_RATE_WINDOW_SECS,
    ));
    let ledger_path = std::env::temp_dir().join(format!(
        "xenia-sealed-adversarial-{}.ledger",
        session_uuid.as_u128()
    ));
    let deps = SealedConsentDeps {
        require_operator_auth: false,
        auth_state,
        session_id: *session_uuid.as_bytes(),
        scope_digest: [0u8; 32],
        session_uuid,
        ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
        ledger_persister: Arc::new(
            crate::consent_ledger_persistence::CompleteConsentLedgerPersister::new(ledger_path),
        ),
        revoked: revoked.clone(),
        revocations: crate::operator_revocations::OperatorRevocations::empty(),
        rekey_interval: Some(rekey_interval),
    };
    (policy, deps, revoked)
}

async fn browser_handshake(
    addr: std::net::SocketAddr,
    op_ed: &[u8; 32],
    op_ml: &[u8; 32],
) -> (WsTransport, xenia_wire::handshake::SessionKeySchedule) {
    let mut transport = WsTransport::connect(&format!("ws://{addr}"))
        .await
        .unwrap();
    let mut hs = xenia_wire::handshake::ViewerHandshake::from_identity(op_ed, op_ml).unwrap();
    let hello = transport.recv_envelope().await.unwrap();
    let response = hs.begin(&hello).unwrap();
    transport.send_envelope(&response).await.unwrap();
    let finalize = transport.recv_envelope().await.unwrap();
    let schedule = hs.finish(&finalize).unwrap();
    (transport, schedule)
}

async fn receive_epoch_one_proposal(
    transport: &mut WsTransport,
    initial_key: [u8; 32],
) -> OperatorRekeyMessage {
    let proposal_envelope = tokio::time::timeout(Duration::from_secs(2), transport.recv_envelope())
        .await
        .expect("daemon should emit rekey Proposal")
        .expect("rekey Proposal transport receive should succeed");
    assert_eq!(
        xenia_wire::envelope_payload_type(&proposal_envelope),
        Some(operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
    );
    assert_eq!(
        &proposal_envelope[..6],
        &OPERATOR_HOST_SOURCE_ID[..6],
        "daemon Proposal must use the host transmit nonce domain"
    );
    assert_eq!(proposal_envelope[7], OPERATOR_SESSION_EPOCH);

    let mut receiver =
        xenia_wire::Session::with_source_id(OPERATOR_HOST_SOURCE_ID, OPERATOR_SESSION_EPOCH);
    receiver.install_key(initial_key);
    let plaintext = receiver.open(&proposal_envelope).unwrap();
    let proposal = OperatorRekeyMessage::decode(&plaintext).unwrap();
    let OperatorRekeyMessage::Proposal {
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    } = proposal
    else {
        panic!("expected rekey Proposal");
    };
    assert_eq!(key_epoch, 1);
    operator_rekey::verify_proposal_epoch_hash(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    )
    .expect("Proposal epoch hash must verify");
    OperatorRekeyMessage::Proposal {
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    }
}

async fn expect_connection_teardown(transport: &mut WsTransport) {
    let result = tokio::time::timeout(Duration::from_secs(2), transport.recv_envelope())
        .await
        .expect("hardened endpoint should tear the failed connection down promptly");
    assert!(
        result.is_err(),
        "failed rekey connection must close rather than continue carrying authority"
    );
}

async fn wait_for_protocol_failure(
    metrics: &crate::operator_channel_metrics::OperatorChannelMetrics,
    expected: u64,
) {
    for _ in 0..100 {
        if metrics.snapshot().post_handshake_protocol_failures >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("post-handshake protocol failure metric did not reach {expected}");
}

async fn approve_after_fresh_handshake(
    addr: std::net::SocketAddr,
    op_ed: &[u8; 32],
    op_ml: &[u8; 32],
) {
    let (mut transport, schedule) = browser_handshake(addr, op_ed, op_ml).await;
    let mut sender =
        xenia_wire::Session::with_source_id(OPERATOR_CONSOLE_SOURCE_ID, OPERATOR_SESSION_EPOCH);
    sender.install_key(schedule.aead);
    let approve = sender
        .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    transport.send_envelope(&approve).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_key_forged_ack_tears_down_and_requires_fresh_handshake() {
    let op_ed = [71u8; 32];
    let op_ml = [72u8; 32];
    let session_uuid = Uuid::from_u128(71);
    let (policy, deps, revoked) = fixture(
        op_ed,
        op_ml,
        session_uuid,
        Duration::from_millis(100),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (grant_tx, grant_rx) = oneshot::channel();
    let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());
    let endpoint_metrics = metrics.clone();
    tokio::spawn(run_sealed_operator_endpoint_with_ack_timeout(
        listener,
        OperatorHostIdentity::Standard(Box::new(HandshakeManager::new())),
        policy,
        deps,
        grant_tx,
        endpoint_metrics,
        Duration::from_millis(60),
    ));

    let (mut transport, schedule) = browser_handshake(addr, &op_ed, &op_ml).await;
    let proposal = receive_epoch_one_proposal(&mut transport, schedule.aead).await;
    let OperatorRekeyMessage::Proposal {
        key_epoch,
        epoch_hash,
        ..
    } = proposal
    else {
        unreachable!()
    };

    // Forge the syntactically perfect Ack with the *old* handshake key. The
    // hardened daemon has already rebuilt authority RX with only the new key.
    let mut old_key_sender =
        xenia_wire::Session::with_source_id(OPERATOR_CONSOLE_SOURCE_ID, OPERATOR_SESSION_EPOCH);
    old_key_sender.install_key(schedule.aead);
    let forged_ack = old_key_sender
        .seal(
            &OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            }
            .encode()
            .unwrap(),
            operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY,
        )
        .unwrap();
    assert_eq!(&forged_ack[8..12], &[0, 0, 0, 0]);
    transport.send_envelope(&forged_ack).await.unwrap();

    expect_connection_teardown(&mut transport).await;
    wait_for_protocol_failure(&metrics, 1).await;
    assert_eq!(metrics.snapshot().connections_accepted, 1);

    // Authority may resume only through a brand-new authenticated channel.
    approve_after_fresh_handshake(addr, &op_ed, &op_ml).await;
    assert!(grant_rx.await.unwrap());
    assert!(!revoked.load(Ordering::SeqCst));
    assert_eq!(metrics.snapshot().connections_accepted, 2);
    assert_eq!(metrics.snapshot().post_handshake_protocol_failures, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_ack_deadline_tears_down_and_requires_fresh_handshake() {
    let op_ed = [81u8; 32];
    let op_ml = [82u8; 32];
    let session_uuid = Uuid::from_u128(81);
    let (policy, deps, revoked) = fixture(
        op_ed,
        op_ml,
        session_uuid,
        Duration::from_millis(100),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (grant_tx, grant_rx) = oneshot::channel();
    let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());
    let endpoint_metrics = metrics.clone();
    tokio::spawn(run_sealed_operator_endpoint_with_ack_timeout(
        listener,
        OperatorHostIdentity::Standard(Box::new(HandshakeManager::new())),
        policy,
        deps,
        grant_tx,
        endpoint_metrics,
        Duration::from_millis(40),
    ));

    let (mut transport, schedule) = browser_handshake(addr, &op_ed, &op_ml).await;
    let _proposal = receive_epoch_one_proposal(&mut transport, schedule.aead).await;

    // Deliberately send nothing. The absolute Ack deadline must close the
    // authenticated channel; unrelated traffic cannot extend it.
    expect_connection_teardown(&mut transport).await;
    wait_for_protocol_failure(&metrics, 1).await;
    assert_eq!(metrics.snapshot().connections_accepted, 1);

    approve_after_fresh_handshake(addr, &op_ed, &op_ml).await;
    assert!(grant_rx.await.unwrap());
    assert!(!revoked.load(Ordering::SeqCst));
    assert_eq!(metrics.snapshot().connections_accepted, 2);
    assert_eq!(metrics.snapshot().post_handshake_protocol_failures, 1);
}
