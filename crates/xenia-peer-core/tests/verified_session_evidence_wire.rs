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
fn fixture_pins_expected_v1_wire_vocabulary_without_secret_fields() {
    for required in [
        "\"schema\": \"xenia-verified-machine-session-evidence-v1\"",
        "\"session_id\": \"session-fixture-001\"",
        "\"peer_identity_binding\"",
        "\"authenticated_at_ms\": 1700000000000",
        "\"expires_at_ms\": 1700000060000",
        "\"authority_epoch\": 9",
        "\"evidence_binding\"",
        "\"negotiated_context_binding\"",
    ] {
        assert!(EVIDENCE_FIXTURE.contains(required), "missing fixture field: {required}");
    }

    for forbidden in [
        "session_key",
        "key_schedule",
        "rekey",
        "control_key",
        "video_key",
        "audio_key",
        "telemetry_key",
        "revoked",
        "trusted_time_available",
    ] {
        assert!(
            !EVIDENCE_FIXTURE.contains(forbidden),
            "portable evidence leaked forbidden field name: {forbidden}"
        );
    }
}

#[test]
fn production_constructor_matches_fixture_authority_and_transcript_claims() {
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

    assert_eq!(produced.schema(), VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1);
    assert_eq!(produced.session_id(), "session-fixture-001");
    assert_eq!(produced.authenticated_at_ms(), 1_700_000_000_000);
    assert_eq!(produced.expires_at_ms(), 1_700_000_060_000);
    assert_eq!(produced.authority_epoch(), 9);
    assert_eq!(
        produced.evidence_binding(),
        "xenia-handshake-transcript-v1:blake3-256:2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert_eq!(
        produced.negotiated_context_binding(),
        Some("xenia-negotiated-session-context:blake3-256:3333333333333333333333333333333333333333333333333333333333333333")
    );

    let fixture_identity_line = EVIDENCE_FIXTURE
        .lines()
        .find(|line| line.contains("\"peer_identity_binding\""))
        .expect("peer_identity_binding fixture line");
    assert!(
        fixture_identity_line.contains(produced.peer_identity_binding()),
        "provider fixture peer identity binding drifted; production={}",
        produced.peer_identity_binding()
    );
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
