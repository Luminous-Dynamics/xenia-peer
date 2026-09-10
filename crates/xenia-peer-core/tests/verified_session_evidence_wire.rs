// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use xenia_handshake::derive_session_key_schedule;
use xenia_peer_core::{
    MachineAuthorityPolicyV1, MachineAuthorityRecordV1,
    VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1, VerifiedMachineSessionEvidenceV1,
};
use xenia_peer_core::handshake::{HandshakeOutcome, VerifiedPeerIdentity};

const EVIDENCE_FIXTURE: &str =
    include_str!("../fixtures/verified-machine-session-evidence-v1.json");

fn fixture_peer() -> VerifiedPeerIdentity {
    VerifiedPeerIdentity {
        ed25519_pk: [0x55; 32],
        ml_dsa_pk: vec![0x66; xenia_handshake::ML_DSA_65_PK_LEN],
    }
}

fn fixture_outcome() -> HandshakeOutcome {
    let transcript_hash = [0x22; 32];
    HandshakeOutcome {
        session_key: [0x11; 32],
        transcript_hash,
        key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
        negotiated_context_hash: Some([0x33; 32]),
        host_identity_fingerprint: [0x44; 32],
    }
}

fn fixture_policy(peer: &VerifiedPeerIdentity) -> MachineAuthorityPolicyV1 {
    MachineAuthorityPolicyV1::new(
        [MachineAuthorityRecordV1 {
            peer_identity_fingerprint: peer.signing_identity_fingerprint(),
            authority_epoch: 9,
            valid_from_ms: 1_699_999_000_000,
            valid_until_ms: 1_700_001_000_000,
            revoked: false,
        }],
        60_000,
    )
    .unwrap()
}

#[test]
fn portable_evidence_fixture_is_exact_production_constructor_output() {
    let fixture: VerifiedMachineSessionEvidenceV1 =
        serde_json::from_str(EVIDENCE_FIXTURE).unwrap();
    let peer = fixture_peer();
    let outcome = fixture_outcome();
    let policy = fixture_policy(&peer);
    let admission = policy
        .admit_verified_session(&peer, &outcome, 1_700_000_000_000, true)
        .unwrap();
    let produced = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
        &outcome,
        &peer,
        "session-fixture-001",
        &admission,
    )
    .unwrap();

    let fixture_value: serde_json::Value = serde_json::from_str(EVIDENCE_FIXTURE).unwrap();
    let produced_value = serde_json::to_value(&produced).unwrap();
    assert_eq!(
        produced_value, fixture_value,
        "golden fixture drifted from the production admission + handshake projection"
    );
}

#[test]
fn portable_evidence_fixture_pins_v1_wire_shape_without_secret_material() {
    let evidence: VerifiedMachineSessionEvidenceV1 = serde_json::from_str(EVIDENCE_FIXTURE).unwrap();

    assert_eq!(evidence.schema(), VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1);
    assert_eq!(evidence.session_id(), "session-fixture-001");
    assert_eq!(evidence.authenticated_at_ms(), 1_700_000_000_000);
    assert_eq!(evidence.expires_at_ms(), 1_700_000_060_000);
    assert_eq!(evidence.authority_epoch(), 9);
    assert_eq!(evidence.validate_shape(), Ok(()));
    assert!(evidence
        .peer_identity_binding()
        .starts_with("xenia-signing-identity-v1:blake3-256:"));
    assert!(evidence
        .evidence_binding()
        .starts_with("xenia-handshake-transcript-v1:blake3-256:"));
    assert!(evidence
        .negotiated_context_binding()
        .is_some_and(|binding| binding.starts_with("xenia-negotiated-session-context:blake3-256:")));

    let original: serde_json::Value = serde_json::from_str(EVIDENCE_FIXTURE).unwrap();
    let reencoded = serde_json::to_value(&evidence).unwrap();
    assert_eq!(reencoded, original);

    let encoded = serde_json::to_string(&evidence).unwrap();
    for forbidden in [
        "session_key",
        "key_schedule",
        "rekey",
        "control_key",
        "video_key",
        "audio_key",
        "telemetry_key",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "portable evidence leaked forbidden field name: {forbidden}"
        );
    }
}

#[test]
fn live_authority_context_is_minted_by_machine_policy() {
    let peer = fixture_peer();
    let outcome = fixture_outcome();
    let policy = fixture_policy(&peer);
    let admission = policy
        .admit_verified_session(&peer, &outcome, 1_700_000_000_000, true)
        .unwrap();
    let context = policy.context_for(&admission, 1_700_000_030_000, true);

    assert_eq!(context.now_ms(), 1_700_000_030_000);
    assert_eq!(context.authority_epoch(), 9);
    assert!(context.trusted_time_available());
    assert!(!context.revoked());
}
