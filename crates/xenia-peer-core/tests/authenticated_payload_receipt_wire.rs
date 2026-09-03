// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cross-repository wire oracle for Xenia authenticated-payload receipt body v1.
//!
//! The expected canonical byte string was constructed independently from bincode
//! 1.3's documented helper-function format, not emitted by this crate. Downstream
//! relying parties can consume the same literal vector to prove byte identity.

use xenia_peer_core::{
    AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN, AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA,
    AuthenticatedPayloadReceiptBodyV1, ReceiptPeerRoleV1,
};

const EXPECTED_HEX: &str = include_str!("test-vectors/authenticated-payload-receipt-body-v1.hex");
const EXPECTED_CANONICAL_LEN: usize = 354;

fn sequence(start: u8) -> [u8; 32] {
    std::array::from_fn(|index| start.wrapping_add(index as u8))
}

fn neutral_body() -> AuthenticatedPayloadReceiptBodyV1 {
    AuthenticatedPayloadReceiptBodyV1 {
        schema: AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA.to_owned(),
        attestor_id: "xenia-host-a".to_owned(),
        key_id: "transport-attestor-1".to_owned(),
        signature_algorithm: "ed25519-rfc8032+ml-dsa-65-fips204".to_owned(),
        session_evidence_digest: sequence(0x01),
        peer_role: ReceiptPeerRoleV1::Viewer,
        peer_identity_fingerprint: sequence(0x21),
        transcript_hash: sequence(0x41),
        session_context_hash: sequence(0x61),
        telemetry_enabled: true,
        input_control_enabled: false,
        payload_type: 0x70,
        payload_len: 0x1234,
        payload_digest: sequence(0x81),
        sealed_envelope_digest: sequence(0xA1),
        opened_at_unix_ms: 0x0102_0304_0506_0708,
        expires_at_unix_ms: 0x0102_0304_0506_17E9,
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "wire vector hex must have even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex byte in committed receipt-body vector"),
    }
}

#[test]
fn xenia_body_matches_neutral_bincode_v1_wire_bytes_exactly() {
    let body = neutral_body();
    let expected = decode_hex(EXPECTED_HEX);
    assert_eq!(expected.len(), EXPECTED_CANONICAL_LEN);

    let actual = body.canonical_bytes().expect("neutral receipt body is valid");
    assert_eq!(actual.len(), EXPECTED_CANONICAL_LEN);
    assert_eq!(actual, expected);
}

#[test]
fn neutral_wire_bytes_round_trip_to_the_exact_typed_body() {
    let expected = decode_hex(EXPECTED_HEX);
    let decoded: AuthenticatedPayloadReceiptBodyV1 =
        bincode::deserialize(&expected).expect("neutral wire vector must decode under bincode v1");

    assert_eq!(decoded, neutral_body());
    assert_eq!(
        bincode::serialize(&decoded).expect("decoded neutral body must reserialize"),
        expected
    );
}

#[test]
fn signing_digest_is_blake3_of_exact_domain_and_neutral_wire_bytes() {
    let body = neutral_body();
    let expected = decode_hex(EXPECTED_HEX);
    let mut preimage = Vec::with_capacity(AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN.len() + expected.len());
    preimage.extend_from_slice(AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN);
    preimage.extend_from_slice(&expected);

    assert_eq!(
        body.signing_digest().expect("neutral body signing digest"),
        *blake3::hash(&preimage).as_bytes()
    );
}

#[test]
fn semantically_relevant_field_mutation_changes_wire_bytes_and_signing_digest() {
    let body = neutral_body();
    let baseline_bytes = body.canonical_bytes().unwrap();
    let baseline_digest = body.signing_digest().unwrap();

    let mut changed = neutral_body();
    changed.input_control_enabled = true;

    assert_ne!(changed.canonical_bytes().unwrap(), baseline_bytes);
    assert_ne!(changed.signing_digest().unwrap(), baseline_digest);
}
