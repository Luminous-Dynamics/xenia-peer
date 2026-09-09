#![cfg(feature = "pqc-signatures")]

use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};
use xenia_ledger::{
    DetachedMessageVerifyError, EvidencePublicKeyBinding, SignatureEnvelope, SignatureSuite,
    compute_evidence_public_key_fingerprint, require_verified_detached_message_contract,
    verify_detached_message,
};

const SYMTHAEA_PROFILE_AUTHORIZATION_V1_HEX: &str =
    "73796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e3a7631000000002873796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e2d763100000006617574682d3100000006726f6f742d31000000046e6f6465000000000000000100000000000003e800000000000007d00000000f746573742d70726f66696c652d7631013333333333333333333333333333333333333333333333333333333333333333012222222222222222222222222222222222222222222222222222222222222222";

const SYMTHAEA_PROFILE_AUTHORIZATION_TRANSITION_V1_HEX: &str =
    "73796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e2d7472616e736974696f6e3a7631000000003373796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e2d7472616e736974696f6e2d763100000000de73796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e3a7631000000002873796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e2d763100000006617574682d3100000006726f6f742d31000000046e6f6465000000000000000100000000000003e800000000000007d00000000f746573742d70726f66696c652d7631013333333333333333333333333333333333333333333333333333333333333333012222222222222222222222222222222222222222222222222222222222222222";

fn fixture_for(message: Vec<u8>) -> (Vec<u8>, EvidencePublicKeyBinding, SignatureEnvelope) {
    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let public_key = signing_key.verifying_key().encode();
    let signature = signing_key.sign(&message).encode();

    let binding = EvidencePublicKeyBinding::new(
        SignatureSuite::MlDsa65Fips204,
        public_key.iter().copied().collect::<Vec<u8>>(),
    );
    let envelope = SignatureEnvelope::new(
        SignatureSuite::MlDsa65Fips204,
        signature.iter().copied().collect::<Vec<u8>>(),
    );

    (message, binding, envelope)
}

fn subject_fixture() -> (Vec<u8>, EvidencePublicKeyBinding, SignatureEnvelope) {
    fixture_for(hex_bytes(SYMTHAEA_PROFILE_AUTHORIZATION_V1_HEX))
}

#[test]
fn v1_authority_root_is_blake3_of_raw_ml_dsa_65_verifier_key_bytes() {
    let (message, binding, envelope) = subject_fixture();

    assert_eq!(binding.public_key.len(), 1952);

    let direct_raw_key_hash = *blake3::hash(&binding.public_key).as_bytes();
    assert_eq!(
        binding.public_key_fingerprint,
        direct_raw_key_hash,
        "the v1 authority root must be BLAKE3-256 over only the raw ML-DSA-65 verifier key bytes"
    );
    assert_eq!(
        compute_evidence_public_key_fingerprint(&binding.public_key),
        direct_raw_key_hash
    );

    let verified = verify_detached_message(
        SignatureSuite::MlDsa65Fips204,
        direct_raw_key_hash,
        &message,
        &envelope,
        &binding,
    )
    .expect("the exact Symthaea v1 authorization bytes must verify under the exact raw-key root");

    let matched = require_verified_detached_message_contract(
        &verified,
        SignatureSuite::MlDsa65Fips204,
        direct_raw_key_hash,
        &message,
    )
    .expect("the cryptographic proof must match the exact independently derived Symthaea contract");

    assert!(matched.matches_message(&message));
    assert_eq!(matched.signature_suite(), SignatureSuite::MlDsa65Fips204);
    assert_eq!(matched.public_key_fingerprint(), direct_raw_key_hash);
}

#[test]
fn lineage_bearing_transition_is_the_runtime_authenticated_message() {
    let transition = hex_bytes(SYMTHAEA_PROFILE_AUTHORIZATION_TRANSITION_V1_HEX);
    let (message, binding, envelope) = fixture_for(transition);
    let trusted_root = binding.public_key_fingerprint;

    let verified = verify_detached_message(
        SignatureSuite::MlDsa65Fips204,
        trusted_root,
        &message,
        &envelope,
        &binding,
    )
    .expect("the exact Symthaea lineage-bearing transition bytes must verify");

    let matched = require_verified_detached_message_contract(
        &verified,
        SignatureSuite::MlDsa65Fips204,
        trusted_root,
        &message,
    )
    .expect("the verified transition must match exact message/suite/root policy together");

    assert!(matched.matches_message(&message));
    assert_eq!(matched.public_key_fingerprint(), trusted_root);

    let mut tampered_transition = message.clone();
    let bootstrap_tag_offset = 107;
    tampered_transition[bootstrap_tag_offset] ^= 0x01;
    assert!(!matched.matches_message(&tampered_transition));
    assert!(matches!(
        verify_detached_message(
            SignatureSuite::MlDsa65Fips204,
            trusted_root,
            &tampered_transition,
            &envelope,
            &binding,
        ),
        Err(DetachedMessageVerifyError::SignatureBackend(_))
    ));
}

#[test]
fn prefixed_key_hash_is_not_the_same_trust_root() {
    let (message, binding, envelope) = subject_fixture();

    let mut prefixed = b"ml-dsa-65-fips204".to_vec();
    prefixed.extend_from_slice(&binding.public_key);
    let wrong_root = *blake3::hash(&prefixed).as_bytes();

    assert_ne!(wrong_root, binding.public_key_fingerprint);
    assert!(matches!(
        verify_detached_message(
            SignatureSuite::MlDsa65Fips204,
            wrong_root,
            &message,
            &envelope,
            &binding,
        ),
        Err(DetachedMessageVerifyError::TrustedPublicKeyMismatch { .. })
    ));
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| (from_hex(pair[0]) << 4) | from_hex(pair[1]))
        .collect()
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid hex byte"),
    }
}
