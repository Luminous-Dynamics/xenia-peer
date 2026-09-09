#![cfg(feature = "pqc-signatures")]

use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};
use xenia_ledger::{
    EvidencePublicKeyBinding, MlDsa65EvidenceSignatureBackend, SignatureEnvelope,
    SignatureSuite, VerifiedDetachedMessageContractMatch,
    require_distinct_verified_detached_message_contract_pair,
    require_verified_detached_message_contract, verify_detached_message,
};

const SYMTHAEA_FROZEN_OBSERVATION_TEMPLATE_V1_HEX: &str =
    "73796d74686165613a7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e3a7631000000003373796d74686165612d7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e2d763100000000000000010000000000000001000000f473796d74686165613a7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e3a7631000000002c73796d74686165612d7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e2d7631000000056f62732d310000000a6f627365727665722d31000000047261636b000000000000000100000000000005dc016666666666666666666666666666666666666666666666666666666666666666777777777777777777777777777777777777777777777777777777777777777701457c1c3b055335df8335a717f08ee09d3f0b38533240a2479ea4302785d0365e";

const SYMTHAEA_OBSERVED_COMMISSIONING_TEMPLATE_V1_HEX: &str =
    "73796d74686165613a6f627365727665642d636f6d6d697373696f6e696e672d617574686f72697a6174696f6e3a7631000000003073796d74686165612d6f627365727665642d636f6d6d697373696f6e696e672d617574686f72697a6174696f6e2d7631000001df73796d74686165613a636f6d6d697373696f6e696e672d617574686f72697a6174696f6e2d7472616e736974696f6e3a7631000000003373796d74686165612d636f6d6d697373696f6e696e672d617574686f72697a6174696f6e2d7472616e736974696f6e2d7631000000000000017173796d74686165613a636f6d6d697373696f6e696e672d617574686f72697a6174696f6e3a7631000000002973796d74686165612d636f6d6d697373696f6e696e672d617574686f72697a6174696f6e2d763100000011636f6d6d697373696f6e2d617574682d3100000012636f6d6d697373696f6e2d726f6f742d7631000000047261636b000000000000000100000000000004b000000000000009c401555555555555555555555555555555555555555555555555555555555555555501137b801f68dfce0863e6f5959b5ec1dc599f8931fce91b4c332adbbbb93a780601457c1c3b055335df8335a717f08ee09d3f0b38533240a2479ea4302785d0365e00000022636f6d707574652d636f6d6d6f6e732d6175746f6e6f6d6f75732d6e6f64652d76310164ec08e2079b55cfcb509d0b57e4f6be310c900a0099ffd919fefa1f087af01b0000000000000001010e8f59cc49a8fb1ea81c803220a5036bcced15e4304edcc266667be83d0ba6ee0000016d73796d74686165613a7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e3a7631000000003373796d74686165612d7361666574792d636f6e66696775726174696f6e2d66726f7a656e2d6f62736572766174696f6e2d763100000000000000010000000000000001000000f473796d74686165613a7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e3a7631000000002c73796d74686165612d7361666574792d636f6e66696775726174696f6e2d6f62736572766174696f6e2d7631000000056f62732d310000000a6f627365727665722d31000000047261636b000000000000000100000000000005dc016666666666666666666666666666666666666666666666666666666666666666777777777777777777777777777777777777777777777777777777777777777701457c1c3b055335df8335a717f08ee09d3f0b38533240a2479ea4302785d0365e";

const SYMTHAEA_OBSERVED_COMMISSIONING_TEMPLATE_V1_DIGEST_HEX: &str =
    "3cd5ef1b3bd0358e8bdbcfd6a1745cb7ab41683aa3b7877c929f91556dee0295";

fn key_and_binding(seed_byte: u8) -> (SigningKey<MlDsa65>, EvidencePublicKeyBinding) {
    let mut seed = ml_dsa::B32::default();
    seed.copy_from_slice(&[seed_byte; 32]);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let public_key = signing_key.verifying_key().encode();
    let binding = EvidencePublicKeyBinding::new(
        SignatureSuite::MlDsa65Fips204,
        public_key.as_ref().to_vec(),
    );
    (signing_key, binding)
}

fn verify_contract(
    signing_key: &SigningKey<MlDsa65>,
    binding: &EvidencePublicKeyBinding,
    message: &[u8],
) -> VerifiedDetachedMessageContractMatch {
    let signature = signing_key.sign(message).encode();
    let envelope = SignatureEnvelope::new(
        SignatureSuite::MlDsa65Fips204,
        signature.as_ref().to_vec(),
    );
    let trusted_root = binding.public_key_fingerprint;

    let verified = verify_detached_message(
        SignatureSuite::MlDsa65Fips204,
        trusted_root,
        message,
        &envelope,
        binding,
        &MlDsa65EvidenceSignatureBackend,
    )
    .expect("the exact Symthaea message must verify under its provisioned ML-DSA-65 root");

    require_verified_detached_message_contract(
        &verified,
        SignatureSuite::MlDsa65Fips204,
        trusted_root,
        message,
    )
    .expect("the verifier-owned proof must retain message + suite + root atomically")
}

fn replace_unique_root_placeholder(
    bytes: &mut [u8],
    placeholder_byte: u8,
    trusted_root: [u8; 32],
) {
    let placeholder = [placeholder_byte; 32];
    let position = {
        let mut positions = bytes
            .windows(placeholder.len())
            .enumerate()
            .filter_map(|(index, window)| (window == placeholder).then_some(index));
        let first = positions
            .next()
            .expect("the canonical Symthaea template must contain the expected root placeholder");
        assert!(
            positions.next().is_none(),
            "the root placeholder must occur exactly once in this canonical message"
        );
        first
    };
    bytes[position..position + trusted_root.len()].copy_from_slice(&trusted_root);
}

#[test]
fn frozen_observation_and_observed_commissioning_require_distinct_ml_dsa_65_authorities() {
    let frozen_template = hex_bytes(SYMTHAEA_FROZEN_OBSERVATION_TEMPLATE_V1_HEX);
    let commissioning_template = hex_bytes(SYMTHAEA_OBSERVED_COMMISSIONING_TEMPLATE_V1_HEX);

    assert_eq!(frozen_template.len(), 365);
    assert_eq!(commissioning_template.len(), 953);
    assert_eq!(
        hex_string(blake3::hash(&commissioning_template).as_bytes()),
        SYMTHAEA_OBSERVED_COMMISSIONING_TEMPLATE_V1_DIGEST_HEX
    );

    let (observer_key, observer_binding) = key_and_binding(0x31);
    let observer_root = observer_binding.public_key_fingerprint;
    let (commissioning_key, commissioning_binding) = key_and_binding(0x52);
    let commissioning_root = commissioning_binding.public_key_fingerprint;

    assert_ne!(observer_root, commissioning_root);
    assert_ne!(observer_root, [0x66; 32]);
    assert_ne!(commissioning_root, [0x55; 32]);

    // The pinned Symthaea vector uses obvious placeholder roots so the wire bytes
    // are readable. For crypto integration, bind the exact deterministic Xenia
    // verifier fingerprints into those same canonical root slots before signing.
    let mut observer_message = frozen_template;
    replace_unique_root_placeholder(&mut observer_message, 0x66, observer_root);

    let mut commissioning_message = commissioning_template;
    replace_unique_root_placeholder(&mut commissioning_message, 0x55, commissioning_root);
    replace_unique_root_placeholder(&mut commissioning_message, 0x66, observer_root);

    // The observer proof must be over the exact frozen observation that the
    // commissioning authority embeds and relies upon, not merely another valid
    // observation for the same configuration.
    assert!(
        commissioning_message
            .windows(observer_message.len())
            .any(|window| window == observer_message.as_slice()),
        "the exact observer-authenticated frozen message must be nested in the commissioning message"
    );

    let observer_match = verify_contract(&observer_key, &observer_binding, &observer_message);
    let commissioning_match =
        verify_contract(&commissioning_key, &commissioning_binding, &commissioning_message);

    assert_eq!(observer_match.public_key_fingerprint(), observer_root);
    assert_eq!(
        commissioning_match.public_key_fingerprint(),
        commissioning_root
    );

    let pair = require_distinct_verified_detached_message_contract_pair(
        "configuration-observer",
        &observer_match,
        &observer_message,
        "commissioning-authority",
        &commissioning_match,
        &commissioning_message,
    )
    .expect("observer + commissioner must compose only as two distinct verified authorities");

    assert_eq!(pair.first_role_id(), "configuration-observer");
    assert_eq!(pair.second_role_id(), "commissioning-authority");
    assert_eq!(
        pair.first().signature_suite(),
        SignatureSuite::MlDsa65Fips204
    );
    assert_eq!(
        pair.second().signature_suite(),
        SignatureSuite::MlDsa65Fips204
    );
    assert!(pair.first().matches_message(&observer_message));
    assert!(pair.second().matches_message(&commissioning_message));
    assert_ne!(
        pair.first().public_key_fingerprint(),
        pair.second().public_key_fingerprint()
    );

    let mut tampered_commissioning = commissioning_message.clone();
    tampered_commissioning[0] ^= 0x01;
    assert!(!pair.second().matches_message(&tampered_commissioning));
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| (from_hex(pair[0]) << 4) | from_hex(pair[1]))
        .collect()
}

fn hex_string(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid hex byte"),
    }
}
