// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use ed25519_dalek::SigningKey;
use serde_json::json;
use xenia_peer_core::{
    MachineAuthorityHistoryEventV1, MachineSessionAdmissionReceiptError,
    SignedMachineAuthorityHistoryHeadV1, VerifiedMachineSessionEvidenceV1,
    sign_machine_session_admission_receipt, verify_machine_session_admission_receipt,
};

const SESSION_FIXTURE: &str = include_str!(
    "../../../crates/xenia-peer-core/fixtures/verified-machine-session-evidence-v1.json"
);

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

#[test]
fn deserialized_session_claims_cannot_reuse_a_provider_admission_receipt() {
    let evidence: VerifiedMachineSessionEvidenceV1 = serde_json::from_str(SESSION_FIXTURE).unwrap();
    let authority = SigningKey::from_bytes(&[0x42; 32]);
    let receipt = sign_machine_session_admission_receipt(&evidence, &authority).unwrap();

    let mut fabricated_value: serde_json::Value = serde_json::from_str(SESSION_FIXTURE).unwrap();
    fabricated_value["session_id"] = json!("fabricated-session");
    let fabricated: VerifiedMachineSessionEvidenceV1 =
        serde_json::from_value(fabricated_value).unwrap();

    assert_eq!(
        verify_machine_session_admission_receipt(
            &fabricated,
            &receipt,
            &authority.verifying_key(),
        ),
        Err(MachineSessionAdmissionReceiptError::EvidenceDigestMismatch)
    );
}
