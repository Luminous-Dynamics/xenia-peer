// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use xenia_peer_core::{
    VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1, VerifiedMachineSessionEvidenceV1,
};

const FIXTURE: &str = include_str!("../fixtures/verified-machine-session-v1.json");

#[test]
fn canonical_provider_fixture_round_trips_without_secret_material() {
    let evidence: VerifiedMachineSessionEvidenceV1 = serde_json::from_str(FIXTURE).unwrap();

    assert_eq!(evidence.schema, VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1);
    assert_eq!(evidence.session_id, "session-fixture-01");
    assert_eq!(evidence.authenticated_at_ms, 1_700_000_000_000);
    assert_eq!(evidence.expires_at_ms, 1_700_000_300_000);
    assert_eq!(evidence.authority_epoch, 9);
    assert!(evidence.peer_identity_binding.starts_with("xenia-signing-identity-v1:blake3-256:"));
    assert!(evidence.evidence_binding.starts_with("xenia-handshake-transcript-v1:blake3-256:"));
    assert!(evidence.negotiated_context_binding.as_deref().is_some_and(|binding| {
        binding.starts_with("xenia-negotiated-session-context:blake3-256:")
    }));

    let encoded = serde_json::to_string(&evidence).unwrap();
    let reparsed: VerifiedMachineSessionEvidenceV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(reparsed, evidence);

    // These key-bearing fields belong to HandshakeOutcome/SessionKeySchedule and
    // must never appear in this portable evidence schema.
    assert!(!encoded.contains("session_key"));
    assert!(!encoded.contains("key_schedule"));
    assert!(!encoded.contains("control"));
    assert!(!encoded.contains("video"));
    assert!(!encoded.contains("telemetry"));
}
