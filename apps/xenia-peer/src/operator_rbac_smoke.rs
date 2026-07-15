// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end smoke test of the operator-RBAC chain (Phase 3-4 of
//! `docs/security/OPERATOR_RBAC_PLAN.md`), exercising the *real* code paths
//! wired together rather than in isolation:
//!
//!   enroll -> `/auth/challenge` -> sign (Ed25519 + ML-DSA) -> `/auth/verify`
//!   -> daemon-signed token -> authenticated `Approve` -> the daemon's own
//!   `decode_consent_decision` (auth-on) -> authorize -> ledger attribution
//!   -> hash-chain verifies.
//!
//! The HTTP hops go through the actual `operator_http::router` (via
//! `tower::oneshot`, so the whole axum extractor/handler/JSON stack runs) and
//! the consent decision goes through the binary's real
//! `crate::decode_consent_decision`. This is an in-process integration test of
//! the full subsystem -- the strongest verification achievable without the
//! browser console/viewer harness -- proving the pieces chain correctly (the
//! token minted by `/auth/verify` really authorizes a consent action, and the
//! authorized operator really flows into a verifiable ledger entry), which the
//! isolated unit tests can't show.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use ed25519_dalek::SigningKey;
use tower::ServiceExt;
use uuid::Uuid;

use xenia_handshake::HandshakeManager;
use xenia_ledger::{Chain, Verifier};

use crate::operator::{EnrolledOperator, OperatorPolicy, OperatorRole};
use crate::operator_audit::operator_consent_audit_event;
use crate::operator_auth::{
    AUTH_RATE_MAX, AUTH_RATE_WINDOW_SECS, ConsentAction, challenge_transcript,
    consent_action_transcript,
};
use crate::operator_http::{OperatorAuthState, router};

async fn post(router: &axum::Router, path: &str, body: String) -> (u16, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn operator_rbac_full_chain_smoke() {
    // --- enroll an operator + stand up the real auth surface ---
    let op = HandshakeManager::new();
    let daemon = SigningKey::generate(&mut rand::thread_rng());
    let daemon_pk = daemon.verifying_key();

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
        daemon.clone(),
        xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
        HandshakeManager::new(),
        AUTH_RATE_MAX,
        AUTH_RATE_WINDOW_SECS,
    ));
    // A separate, throwaway ledger for the router's new `/v1/audit/*`
    // routes -- this test verifies ledger attribution via its own `chain`
    // below (built from `crate::decode_consent_decision`'s real output),
    // not via those routes.
    let router_ledger = Arc::new(tokio::sync::Mutex::new(Chain::new(SigningKey::generate(
        &mut rand::thread_rng(),
    ))));
    let http = router(
        state.clone(),
        crate::operator_revocations::OperatorRevocations::empty(),
        router_ledger,
        Arc::new(Vec::new()),
    );

    // --- 1. GET a challenge from the real endpoint ---
    let (status, body) = post(&http, "/auth/challenge", "{}".to_string()).await;
    assert_eq!(status, 200);
    let chal: serde_json::Value = serde_json::from_str(&body).unwrap();
    let nonce_hex = chal["nonce"].as_str().unwrap();
    let nonce: [u8; 32] = hex::decode(nonce_hex).unwrap().try_into().unwrap();

    // --- 2. sign the challenge with both keys and verify -> token ---
    let ml_pk = op.ml_dsa_public_key_bytes().to_vec();
    let transcript = challenge_transcript(&nonce, &op.identity_public_key_bytes(), &ml_pk);
    let verify_body = serde_json::json!({
        "nonce": nonce_hex,
        "ed_pubkey": hex::encode(op.identity_public_key_bytes()),
        "ml_dsa_pubkey": hex::encode(&ml_pk),
        "ed_signature": hex::encode(op.sign(&transcript).to_bytes()),
        "ml_dsa_signature": hex::encode(op.sign_ml_dsa(&transcript)),
    })
    .to_string();
    let (status, body) = post(&http, "/auth/verify", verify_body).await;
    assert_eq!(status, 200, "verify failed: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(token["operator_id"], "alice");
    assert_eq!(token["role"], "Admin");

    // --- 3. build an authenticated Approve, signed for a specific session ---
    let session_id = [0x5a_u8; 16];
    let token_nonce: [u8; 16] = hex::decode(token["token_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let action_transcript =
        consent_action_transcript(ConsentAction::Approve, &session_id, &token_nonce);
    let consent_json = serde_json::json!({
        "token": token,
        "action": "Approve",
        "action_signature": hex::encode(op.sign(&action_transcript).to_bytes()),
        "ml_dsa_action_signature": hex::encode(op.sign_ml_dsa(&action_transcript)),
    })
    .to_string();

    // --- 4. run it through the daemon's OWN consent-decision path ---
    let no_revocations = crate::operator_revocations::OperatorRevocations::empty();
    let decoded =
        crate::decode_consent_decision(&consent_json, true, &state, &session_id, &no_revocations)
            .expect("authenticated Approve must be authorized");
    assert_eq!(decoded.action, ConsentAction::Approve);
    let authorized = decoded
        .authorized
        .expect("an authenticated decision carries operator attribution");
    assert_eq!(authorized.operator_id, "alice");
    assert_eq!(authorized.role, OperatorRole::Admin);
    assert_eq!(authorized.ed25519_pubkey, op.identity_public_key_bytes());

    // --- 4b. once alice is revoked, the SAME valid, unexpired signed action is
    //         refused on the consent path (not just on the sealed channel) ---
    let revocations = crate::operator_revocations::OperatorRevocations::empty();
    revocations.revoke("alice");
    assert!(
        crate::decode_consent_decision(&consent_json, true, &state, &session_id, &revocations)
            .is_none(),
        "a revoked operator's signed action must be refused on the consent path"
    );

    // --- 5. attribute it in the ledger and verify the hash chain ---
    let event = operator_consent_audit_event(&authorized, Uuid::from_u128(1), Uuid::from_u128(2));
    let mut chain = Chain::new(daemon);
    chain.append(event).expect("audit entry appends");
    assert_eq!(chain.len(), 1);
    let entries: Vec<_> = chain.iter().cloned().collect();
    Verifier::verify_chain(&entries, &daemon_pk).expect("operator-action audit chain verifies");

    // --- 6. a tampered/replayed decision is refused by the same path ---
    // Wrong session id: the per-action signature no longer binds.
    let bad =
        crate::decode_consent_decision(&consent_json, true, &state, &[0u8; 16], &no_revocations);
    assert!(
        bad.is_none(),
        "a decision signed for another session is refused"
    );
}
