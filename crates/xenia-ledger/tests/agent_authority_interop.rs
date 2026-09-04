// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen Xenia/Symthaea interoperability vector for agent authority v1.

use ed25519_dalek::{Signer, SigningKey};
use xenia_ledger::{
    AGENT_CAPABILITY_AUTHORIZATION_SCHEMA_VERSION, AgentCapabilityAuthorizationV1,
    AgentCheckpointAnchorV1, TranscriptSignatureSuiteV1,
};

const EXPECTED_PUBLIC_KEY: [u8; 32] = [
    0xed, 0x49, 0x28, 0xc6, 0x28, 0xd1, 0xc2, 0xc6, 0xea, 0xe9, 0x03, 0x38, 0x90, 0x59,
    0x95, 0x61, 0x29, 0x59, 0x27, 0x3a, 0x5c, 0x63, 0xf9, 0x36, 0x36, 0xc1, 0x46, 0x14,
    0xac, 0x87, 0x37, 0xd1,
];

const EXPECTED_SIGNATURE: [u8; 64] = [
    0xf3, 0x42, 0x66, 0xc5, 0x84, 0xae, 0xa2, 0x6f, 0x84, 0x94, 0xf5, 0x05, 0xe3, 0xfa,
    0xba, 0xc4, 0x90, 0xce, 0xd1, 0x92, 0xc6, 0x04, 0xb0, 0x4c, 0x97, 0x63, 0xe2, 0xd1,
    0x2d, 0xcb, 0xce, 0xa9, 0xf6, 0x65, 0x24, 0x9f, 0xaa, 0xd3, 0x7d, 0x1e, 0xae, 0xf1,
    0x7b, 0x7b, 0x00, 0x11, 0x8a, 0xc3, 0xd2, 0x3d, 0x47, 0xd1, 0x6c, 0x22, 0x66, 0x36,
    0xdb, 0xc7, 0xd2, 0x0a, 0x05, 0x71, 0x7c, 0x01,
];

fn vector_authorization() -> AgentCapabilityAuthorizationV1 {
    AgentCapabilityAuthorizationV1 {
        schema_version: AGENT_CAPABILITY_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id: [1; 16],
        session_id: [2; 16],
        session_transcript_hash: [3; 32],
        session_signature_suite: TranscriptSignatureSuiteV1::Ed25519Rfc8032,
        capability_digest: [4; 32],
        executor_workload_digest: [5; 32],
        authority_epoch: 7,
        issued_at_unix_s: 100,
        expires_at_unix_s: 160,
        nonce: [6; 16],
        ledger_entry_count: 12,
        ledger_head_hash: [7; 32],
        prior_checkpoint: Some(AgentCheckpointAnchorV1 {
            sequence: 9,
            digest: [8; 32],
        }),
    }
}

#[test]
fn frozen_v1_canonical_message_and_signature_vector() {
    let message = vector_authorization().canonical_message().unwrap();
    assert_eq!(message.len(), 292, "canonical byte length is part of v1");

    let signing_key = SigningKey::from_bytes(&[3; 32]);
    assert_eq!(signing_key.verifying_key().to_bytes(), EXPECTED_PUBLIC_KEY);
    assert_eq!(signing_key.sign(&message).to_bytes(), EXPECTED_SIGNATURE);
}
