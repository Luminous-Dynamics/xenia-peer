#![cfg(feature = "pqc-signatures")]

use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};
use xenia_ledger::{
    EvidencePublicKeyBinding, MlDsa65EvidenceSignatureBackend, SignatureEnvelope,
    SignatureSuite, require_distinct_verified_detached_message_contract_pair,
    require_verified_detached_message_contract, verify_detached_message,
};

const SYMTHAEA_PROFILE_AUTHORIZATION_TRANSITION_V1_HEX: &str =
    "73796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e2d7472616e736974696f6e3a7631000000003373796d74686165612d7361666574792d70726f66696c652d617574686f72697a6174696f6e2d7472616e736974696f6e2d763100000000de73796d74686165613a7361666574792d70726f66696c652d617574686f72697a6174696f6e3a7631000000002873796d74686165612d7361666574792d70726f66696c652d617574686f72697a6174696f6e2d763100000006617574682d3100000006726f6f742d31000000046e6f6465000000000000000100000000000003e800000000000007d00000000f746573742d70726f66696c652d7631013333333333333333333333333333333333333333333333333333333333333333012222222222222222222222222222222222222222222222222222222222222222";

const SYMTHAEA_FROZEN_CONFIGURATION_OBSERVATION_V1_HEX: &str =
    "73796d74686165613a7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e3a7631000000003373796d74686165612d7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e2d763100000000000000010000000000000001000000ee73796d74686165613a7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e3a7631000000002c73796d74686165612d7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e2d7631000000056f62732d310000000a6f627365727665722d31000000047261636b000000000000000700000000000005dc0144444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555016666666666666666666666666666666666666666666666666666666666666666";

fn fixture_for_seed(
    message: Vec<u8>,
    seed_byte: u8,
) -> (
    Vec<u8>,
    EvidencePublicKeyBinding,
    SignatureEnvelope,
    MlDsa65EvidenceSignatureBackend,
) {
    let mut seed = ml_dsa::B32::default();
    seed.copy_from_slice(&[seed_byte; 32]);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let public_key = signing_key.verifying_key().encode();
    let signature = signing_key.sign(&message).encode();

    let binding = EvidencePublicKeyBinding::new(
        SignatureSuite::MlDsa65Fips204,
        public_key.as_ref().to_vec(),
    );
    let envelope = SignatureEnvelope::new(
        SignatureSuite::MlDsa65Fips204,
        signature.as_ref().to_vec(),
    );

    (
        message,
        binding,
        envelope,
        MlDsa65EvidenceSignatureBackend,
    )
}

#[test]
fn distinct_real_symthaea_messages_require_distinct_ml_dsa_65_authorities() {
    let observer_bytes = hex_bytes(SYMTHAEA_FROZEN_CONFIGURATION_OBSERVATION_V1_HEX);
    let profile_bytes = hex_bytes(SYMTHAEA_PROFILE_AUTHORIZATION_TRANSITION_V1_HEX);

    let (observer_message, observer_binding, observer_signature, observer_backend) =
        fixture_for_seed(observer_bytes, 0x31);
    let observer_root = observer_binding.public_key_fingerprint;
    let observer_verified = verify_detached_message(
        SignatureSuite::MlDsa65Fips204,
        observer_root,
        &observer_message,
        &observer_signature,
        &observer_binding,
        &observer_backend,
    )
    .expect("the pinned frozen-observation bytes must verify under the observer root");
    let observer_match = require_verified_detached_message_contract(
        &observer_verified,
        SignatureSuite::MlDsa65Fips204,
        observer_root,
        &observer_message,
    )
    .expect("the observer proof must retain the exact pinned frozen-observation contract");

    let (profile_message, profile_binding, profile_signature, profile_backend) =
        fixture_for_seed(profile_bytes, 0x52);
    let profile_root = profile_binding.public_key_fingerprint;
    let profile_verified = verify_detached_message(
        SignatureSuite::MlDsa65Fips204,
        profile_root,
        &profile_message,
        &profile_signature,
        &profile_binding,
        &profile_backend,
    )
    .expect("the pinned profile-transition bytes must verify under the profile root");
    let profile_match = require_verified_detached_message_contract(
        &profile_verified,
        SignatureSuite::MlDsa65Fips204,
        profile_root,
        &profile_message,
    )
    .expect("the profile proof must retain the exact pinned transition contract");

    assert_ne!(observer_root, profile_root);

    let pair = require_distinct_verified_detached_message_contract_pair(
        "configuration-observer",
        &observer_match,
        &observer_message,
        "profile-authority",
        &profile_match,
        &profile_message,
    )
    .expect("two distinct real ML-DSA-65 Symthaea contracts must compose as one opaque pair");

    assert_eq!(pair.first_role_id(), "configuration-observer");
    assert_eq!(pair.second_role_id(), "profile-authority");
    assert_eq!(pair.first().signature_suite(), SignatureSuite::MlDsa65Fips204);
    assert_eq!(pair.second().signature_suite(), SignatureSuite::MlDsa65Fips204);
    assert!(pair.first().matches_message(&observer_message));
    assert!(pair.second().matches_message(&profile_message));
    assert_ne!(
        pair.first().public_key_fingerprint(),
        pair.second().public_key_fingerprint()
    );
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
