// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use xenia_peer_core::{
    MachineSessionAuthorityContextV1, VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1,
    VerifiedMachineSessionEvidenceV1,
};

const EVIDENCE_FIXTURE: &str =
    include_str!("../fixtures/verified-machine-session-evidence-v1.json");

#[test]
fn portable_evidence_fixture_pins_v1_wire_shape_without_secret_material() {
    let evidence: VerifiedMachineSessionEvidenceV1 = serde_json::from_str(EVIDENCE_FIXTURE).unwrap();

    assert_eq!(evidence.schema, VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1);
    assert_eq!(evidence.session_id, "session-fixture-001");
    assert_eq!(evidence.authenticated_at_ms, 1_700_000_000_000);
    assert_eq!(evidence.expires_at_ms, 1_700_000_060_000);
    assert_eq!(evidence.authority_epoch, 9);
    assert_eq!(evidence.validate_shape(), Ok(()));
    assert!(evidence
        .peer_identity_binding
        .starts_with("xenia-signing-identity-v1:blake3-256:"));
    assert!(evidence
        .evidence_binding
        .starts_with("xenia-handshake-transcript-v1:blake3-256:"));
    assert!(evidence
        .negotiated_context_binding
        .as_deref()
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
fn live_authority_context_is_a_local_point_of_use_value() {
    // Intentionally constructed in-process rather than decoded from a fixture.
    // Current revocation/time state must be refreshed locally, not replayed from
    // a portable `revoked = false` artifact.
    let context = MachineSessionAuthorityContextV1 {
        now_ms: 1_700_000_030_000,
        authority_epoch: 9,
        trusted_time_available: true,
        revoked: false,
    };

    assert_eq!(context.now_ms, 1_700_000_030_000);
    assert_eq!(context.authority_epoch, 9);
    assert!(context.trusted_time_available);
    assert!(!context.revoked);
}
