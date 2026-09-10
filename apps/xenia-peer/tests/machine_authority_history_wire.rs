// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde_json::json;
use xenia_peer_core::{
    MachineAuthorityHistoryEventV1, SignedMachineAuthorityHistoryHeadV1,
};

fn bytes32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

#[test]
fn portable_history_v1_rejects_unknown_event_fields() {
    let event = json!({
        "schema_version": 1,
        "sequence": 0,
        "previous_event_digest": null,
        "peer_identity_fingerprint": bytes32(0x55),
        "recorded_at_ms": 100,
        "transition": {
            "grant": {
                "authority_epoch": 9,
                "valid_from_ms": 100,
                "valid_until_ms": 1_000
            }
        },
        "authority_override": true
    });

    assert!(serde_json::from_value::<MachineAuthorityHistoryEventV1>(event).is_err());
}

#[test]
fn portable_history_v1_rejects_unknown_signed_head_fields() {
    let signed_head = json!({
        "head": {
            "schema_version": 1,
            "peer_identity_fingerprint": bytes32(0x55),
            "head_sequence": 0,
            "head_digest": bytes32(0x22),
            "observed_through_ms": 200,
            "fresh_until_ms": 300
        },
        "signature": {
            "ed25519": vec![0x11_u8; 64]
        },
        "live_authority": true
    });

    assert!(serde_json::from_value::<SignedMachineAuthorityHistoryHeadV1>(signed_head).is_err());
}
