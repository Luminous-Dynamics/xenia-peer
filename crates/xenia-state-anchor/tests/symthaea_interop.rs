// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use xenia_state_anchor::{STATE_ANCHOR_SCHEMA, StateAnchorRecord};

const EXPECTED_XENIA_SCHEMA: &str = "xenia-state-anchor-v1";
const SYMTHAEA_NAMESPACE: &str = "symthaea.episodic-continuity.xenia-anchor.v1";
const SYMTHAEA_POLICY_COMMITMENT: [u8; 32] = [
    0xa7, 0xd9, 0x7c, 0xf9, 0x2f, 0xfc, 0x98, 0x61,
    0x4c, 0x3a, 0x63, 0x87, 0x54, 0x37, 0x8a, 0x76,
    0x2e, 0x9a, 0x5f, 0x77, 0x22, 0xe7, 0x19, 0x3c,
    0x6a, 0xe2, 0x7b, 0x5d, 0xfd, 0x6d, 0x1e, 0x39,
];

#[test]
fn symthaea_v1_record_shape_is_accepted_without_consent_schema_overload() {
    assert_eq!(STATE_ANCHOR_SCHEMA, EXPECTED_XENIA_SCHEMA);

    let record = StateAnchorRecord {
        schema: EXPECTED_XENIA_SCHEMA.into(),
        namespace: SYMTHAEA_NAMESPACE.into(),
        object_id: "symthaea:self:episodic-memory".into(),
        revision: 1,
        previous_anchor_fingerprint: None,
        state_commitment: [0x11; 32],
        policy_commitment: Some(SYMTHAEA_POLICY_COMMITMENT),
        timestamp_unix_secs: 1_800_000_001,
    };

    record.validate().expect("Symthaea interoperability vector must remain valid");
    assert_eq!(record.namespace, SYMTHAEA_NAMESPACE);
    assert_eq!(record.policy_commitment, Some(SYMTHAEA_POLICY_COMMITMENT));
}
