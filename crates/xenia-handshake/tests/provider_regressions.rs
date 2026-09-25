// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use xenia_handshake::{HandshakeError, HandshakeManager, ML_KEM_768_PK_LEN};

/// Provider-regression subject for XEN-CRYPTO-FV-001C1.
///
/// This deliberately exercises the public Xenia initiator boundary rather than
/// calling RustCrypto directly:
///
/// exact-length wire admission
/// != cryptographic ML-KEM public-key validity
/// != installed session state.
#[test]
fn noncanonical_full_length_ml_kem_public_key_is_consumed_and_rejected() {
    const PEER: &str = "provider-regression-peer";
    const NONCE: [u8; 32] = [0xC1; 32];

    let mut initiator = HandshakeManager::new();
    let noncanonical = [0xffu8; ML_KEM_768_PK_LEN];

    // Wire-shape admission is intentionally only a length boundary. A full-size
    // candidate remains untrusted until the provider parses it during
    // encapsulation.
    initiator
        .receive_kem_public_key(PEER, &noncanonical)
        .expect("exact-length untrusted KEM material should pass wire admission");
    assert!(
        initiator.session_key(PEER).is_none(),
        "admission alone must not install a session key"
    );

    let err = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect_err("non-canonical ML-KEM-768 public key must fail provider parsing");
    assert!(matches!(
        err,
        HandshakeError::InvalidKemPublicKey {
            got: ML_KEM_768_PK_LEN
        }
    ));
    assert!(
        initiator.session_key(PEER).is_none(),
        "provider rejection must not leave session state behind"
    );

    // encapsulate_for_peer consumes the pending candidate before parsing it.
    // A failed key therefore cannot be retried implicitly: a caller must
    // explicitly re-admit material before another provider parse occurs.
    let retry_without_readmission = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect_err("failed pending key must have been consumed");
    assert!(matches!(
        retry_without_readmission,
        HandshakeError::UnknownPeer(ref peer) if peer == PEER
    ));
    assert!(initiator.session_key(PEER).is_none());

    // Explicitly re-admitting the same bytes reaches the same cryptographic
    // rejection boundary rather than being treated as authenticated state.
    initiator
        .receive_kem_public_key(PEER, &noncanonical)
        .expect("explicit re-admission should still pass only the length gate");
    let repeated_err = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect_err("same non-canonical key must remain invalid");
    assert!(matches!(
        repeated_err,
        HandshakeError::InvalidKemPublicKey {
            got: ML_KEM_768_PK_LEN
        }
    ));
    assert!(initiator.session_key(PEER).is_none());
}

/// Positive control for the same public API path.
#[test]
fn generated_ml_kem_public_key_still_establishes_initiator_session() {
    const PEER: &str = "provider-regression-valid-peer";
    const NONCE: [u8; 32] = [0x5A; 32];

    let mut initiator = HandshakeManager::new();
    let mut responder = HandshakeManager::new();
    let valid_public_key = responder.generate_kem_public_key("initiator");

    assert_eq!(valid_public_key.len(), ML_KEM_768_PK_LEN);
    initiator
        .receive_kem_public_key(PEER, &valid_public_key)
        .expect("generated ML-KEM public key should pass admission");
    assert!(initiator.session_key(PEER).is_none());

    let ciphertext = initiator
        .encapsulate_for_peer(PEER, &NONCE)
        .expect("generated ML-KEM public key should parse and encapsulate");
    assert!(!ciphertext.is_empty());
    assert!(
        initiator.session_key(PEER).is_some(),
        "successful provider parse + encapsulation should install session state"
    );
}
