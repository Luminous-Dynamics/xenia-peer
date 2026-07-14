// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-socket smoke test of the operator-auth ceremony (the E2E verification
//! for `OPERATOR_RBAC_PLAN.md` Phase 5, minus the browser).
//!
//! Where `operator_rbac_smoke` drives the axum handlers in-process via
//! `tower::oneshot`, this serves the *real* `operator_http::router` over an
//! actual TCP socket (`axum::serve`) and drives it with a real HTTP client
//! (`reqwest`) — the exact transport the browser console uses. It proves the
//! challenge → sign(Ed25519 + ML-DSA-65) → verify → role-scoped-token ceremony
//! works end-to-end over the wire, using the shared `xenia_operator_proto`
//! transcript the console also signs. This is the automated stand-in for the
//! live daemon + `trunk serve` walkthrough (which additionally needs a browser
//! and a human clicking Approve/Revoke).

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use xenia_handshake::HandshakeManager;
use xenia_operator_proto::challenge_transcript;

use crate::operator::{EnrolledOperator, OperatorPolicy, OperatorRole};
use crate::operator_auth::{AUTH_RATE_MAX, AUTH_RATE_WINDOW_SECS};
use crate::operator_http::{OperatorAuthState, router};

#[tokio::test]
async fn operator_auth_ceremony_works_over_real_http() {
    // --- enroll an operator + stand up the real auth router on a real port ---
    let op = HandshakeManager::new();
    let daemon = SigningKey::generate(&mut rand::thread_rng());
    let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
        operator_id: "alice".to_string(),
        ed25519_pubkey: op.identity_public_key_bytes(),
        ml_dsa_pubkey: op.ml_dsa_public_key_bytes().to_vec(),
        ml_dsa_87_pubkey: None,
        role: OperatorRole::Admin,
    }])
    .unwrap();
    let state = Arc::new(OperatorAuthState::new(
        policy,
        daemon,
        HandshakeManager::new(),
        AUTH_RATE_MAX,
        AUTH_RATE_WINDOW_SECS,
    ));

    let ledger = Arc::new(tokio::sync::Mutex::new(xenia_ledger::Chain::new(
        SigningKey::generate(&mut rand::thread_rng()),
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router(
                state,
                crate::operator_revocations::OperatorRevocations::empty(),
                ledger,
            ),
        )
        .await;
    });

    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // --- 1. GET a challenge over real HTTP ---
    let chal: serde_json::Value = client
        .post(format!("{base}/auth/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("challenge request sends")
        .json()
        .await
        .expect("challenge response is JSON");
    let nonce_hex = chal["nonce"].as_str().unwrap();
    let nonce: [u8; 32] = hex::decode(nonce_hex).unwrap().try_into().unwrap();

    // --- 2. sign the shared transcript with BOTH keys, exactly as the console
    //        does (same xenia_operator_proto::challenge_transcript) ---
    let ml_pk = op.ml_dsa_public_key_bytes().to_vec();
    let transcript = challenge_transcript(&nonce, &op.identity_public_key_bytes(), &ml_pk);
    let verify_body = serde_json::json!({
        "nonce": nonce_hex,
        "ed_pubkey": hex::encode(op.identity_public_key_bytes()),
        "ml_dsa_pubkey": hex::encode(&ml_pk),
        "ed_signature": hex::encode(op.sign(&transcript).to_bytes()),
        "ml_dsa_signature": hex::encode(op.sign_ml_dsa(&transcript)),
    });

    // --- 3. exchange it for a daemon-signed, role-scoped token ---
    let resp = client
        .post(format!("{base}/auth/verify"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify request sends");
    assert_eq!(resp.status(), 200, "verify should succeed over real HTTP");
    let token: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(token["operator_id"], "alice");
    assert_eq!(token["role"], "Admin");
    assert!(token["token_nonce"].as_str().is_some());
    assert!(token["signature"].as_str().is_some());

    // --- 4. a garbage signature is refused (401) over the same wire ---
    let bad_body = serde_json::json!({
        "nonce": nonce_hex, // already consumed anyway
        "ed_pubkey": hex::encode(op.identity_public_key_bytes()),
        "ml_dsa_pubkey": hex::encode(&ml_pk),
        "ed_signature": hex::encode([0u8; 64]),
        "ml_dsa_signature": hex::encode(vec![0u8; ml_pk.len().min(64)]),
    });
    let bad = client
        .post(format!("{base}/auth/verify"))
        .json(&bad_body)
        .send()
        .await
        .expect("second verify sends");
    assert_ne!(
        bad.status(),
        200,
        "a forged/replayed response must not mint a token"
    );
}
