// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Executable regressions for the exact cryptographic provider boundary frozen
//! by XEN-CRYPTO-FV-001A/001B.
//!
//! These tests establish only the named behaviors on the selected locked
//! provider graph. They are not exhaustive primitive-security proofs.

use xenia_handshake::{
    HandshakeError, HandshakeManager, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
};

const PEER: &str = "provider-regression-peer";
const NONCE: [u8; 32] = [0x42; 32];

#[test]
fn generated_ml_kem_key_is_accepted_and_installs_session_state() {
    let mut initiator = HandshakeManager::from_identity_seeds([0x11; 32], [0x21; 32]);
    let mut responder = HandshakeManager::from_identity_seeds([0x12; 32], [0x22; 32]);

    let valid_key = responder.generate_kem_public_key("initiator");
    assert_eq!(valid_key.len(), ML_KEM_768_PK_LEN);

    initiator
        .receive_kem_public_key(PEER, &valid_key)
        .expect("exact-length generated ML-KEM key should be admitted as pending material");
    assert!(
        initiator.session_key(PEER).is_none(),
        "mere public-key admission must not install session state"
    );

    let ciphertext = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect("provider-generated ML-KEM key must pass provider parsing and encapsulation");

    assert_eq!(ciphertext.len(), ML_KEM_768_CT_LEN);
    assert!(
        initiator.session_key(PEER).is_some(),
        "successful provider parsing + encapsulation should install initiator session state"
    );
}

#[test]
fn full_length_noncanonical_ml_kem_key_is_rejected_before_session_install() {
    let mut initiator = HandshakeManager::from_identity_seeds([0x31; 32], [0x41; 32]);

    // Every three 0xff bytes decode to 12-bit coefficients 0xfff (4095),
    // outside ML-KEM's q=3329 field. The input is deliberately the correct
    // ML-KEM-768 byte length so this exercises provider key validation rather
    // than Xenia's earlier wire-length gate.
    let invalid_key = [0xff; ML_KEM_768_PK_LEN];

    initiator
        .receive_kem_public_key(PEER, &invalid_key)
        .expect("length admission intentionally treats the key as untrusted pending bytes");
    assert!(
        initiator.session_key(PEER).is_none(),
        "untrusted pending key material must not install session state"
    );

    let err = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect_err("non-canonical ML-KEM public key must fail provider TryKeyInit");
    assert!(
        matches!(
            err,
            HandshakeError::InvalidKemPublicKey { got } if got == ML_KEM_768_PK_LEN
        ),
        "expected provider key-validation failure, got: {err}"
    );
    assert!(
        initiator.session_key(PEER).is_none(),
        "provider rejection must not leave a derived session behind"
    );

    // encapsulate_for_peer consumes the pending bytes before provider parsing.
    // Reusing rejected material therefore requires explicit re-admission rather
    // than silently retrying stale attacker-controlled state.
    let retry = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect_err("rejected pending key must have been consumed");
    assert!(
        matches!(retry, HandshakeError::UnknownPeer(ref peer) if peer == PEER),
        "rejected key should not remain pending: {retry}"
    );
}
