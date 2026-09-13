// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use xenia_ledger::{
    StateCommitment, ZERO_STATE_COMMITMENT, state_commitment_fingerprint,
    state_commitment_message,
};

const GENESIS_MESSAGE_HEX: &str = concat!(
    "000000000000001978656e69613a73746174652d636f6d6d69746d656e743a7631",
    "000000000000001978656e69612d73746174652d636f6d6d69746d656e742d7631",
    "000000000000001f73796d74686165612e72736b2e736368656d612d72656769737472792e7631",
    "00000000000000201111111111111111111111111111111111111111111111111111111111111111",
    "00000000000000202222222222222222222222222222222222222222222222222222222222222222",
    "0000000000000000",
    "00000000000000200000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000203333333333333333333333333333333333333333333333333333333333333333",
    "00000000000000204444444444444444444444444444444444444444444444444444444444444444",
    "000000006b49d200",
);

const GENESIS_FINGERPRINT_HEX: &str =
    "fb25e02988d821351fafec3dbf3beadadd7214c90a3d8bca80eb5cf21780e0b3";

const SEQUENCE_ONE_MESSAGE_HEX: &str = concat!(
    "000000000000001978656e69613a73746174652d636f6d6d69746d656e743a7631",
    "000000000000001978656e69612d73746174652d636f6d6d69746d656e742d7631",
    "000000000000001f73796d74686165612e72736b2e736368656d612d72656769737472792e7631",
    "00000000000000201111111111111111111111111111111111111111111111111111111111111111",
    "00000000000000202222222222222222222222222222222222222222222222222222222222222222",
    "0000000000000001",
    "0000000000000020fb25e02988d821351fafec3dbf3beadadd7214c90a3d8bca80eb5cf21780e0b3",
    "00000000000000206666666666666666666666666666666666666666666666666666666666666666",
    "00000000000000204444444444444444444444444444444444444444444444444444444444444444",
    "000000006b49d201",
);

const SEQUENCE_ONE_FINGERPRINT_HEX: &str =
    "332b79517c2ff123e0b8fc67e6c2963a27a63ef4c76938a4ce3b66e7aefda44c";

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("valid hex") as u8;
            let low = (pair[1] as char).to_digit(16).expect("valid hex") as u8;
            (high << 4) | low
        })
        .collect()
}

#[test]
fn rsk_counter_zero_commitment_has_stable_wire_bytes_and_fingerprint() {
    let commitment = StateCommitment::new(
        "symthaea.rsk.schema-registry.v1",
        [0x11; 32],
        [0x22; 32],
        0,
        ZERO_STATE_COMMITMENT,
        [0x33; 32],
        [0x44; 32],
        1_800_000_000,
    )
    .expect("valid genesis commitment");

    let message = state_commitment_message(&commitment).expect("canonical message");
    assert_eq!(message.len(), 321);
    assert_eq!(message, decode_hex(GENESIS_MESSAGE_HEX));
    assert_eq!(
        state_commitment_fingerprint(&commitment)
            .expect("stable fingerprint")
            .to_vec(),
        decode_hex(GENESIS_FINGERPRINT_HEX)
    );
}

#[test]
fn rsk_sequence_one_binds_exact_counter_zero_fingerprint() {
    let previous: [u8; 32] = decode_hex(GENESIS_FINGERPRINT_HEX)
        .try_into()
        .expect("32-byte predecessor");
    let commitment = StateCommitment::new(
        "symthaea.rsk.schema-registry.v1",
        [0x11; 32],
        [0x22; 32],
        1,
        previous,
        [0x66; 32],
        [0x44; 32],
        1_800_000_001,
    )
    .expect("valid sequence-one commitment");

    let message = state_commitment_message(&commitment).expect("canonical message");
    assert_eq!(message.len(), 321);
    assert_eq!(message, decode_hex(SEQUENCE_ONE_MESSAGE_HEX));
    assert_eq!(
        state_commitment_fingerprint(&commitment)
            .expect("stable fingerprint")
            .to_vec(),
        decode_hex(SEQUENCE_ONE_FINGERPRINT_HEX)
    );
}
