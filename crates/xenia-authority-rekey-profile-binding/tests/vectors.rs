// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use xenia_authority_activation_evidence::AuthorityActivationReceiptV1;
use xenia_authority_rekey_profile_binding::AuthorityRekeyProfileBindingV1;
use xenia_authority_rekey_transition_evidence::RekeyTransitionProfileV1;
use xenia_negotiation::{NegotiatedCapabilityV1, NegotiatedContextV1};

fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
}

fn selected() -> NegotiatedContextV1 {
    NegotiatedContextV1::from_capabilities([
        cap(b"xenia.causal-authority", b"draft-04"),
        cap(b"xenia.operator-rekey", b"v1"),
    ])
    .unwrap()
}

fn activation(selected: &NegotiatedContextV1) -> AuthorityActivationReceiptV1 {
    AuthorityActivationReceiptV1 {
        schema_version: 1,
        handshake_transcript_hash: [0x11; 32],
        base_v4_context_hash: [0x22; 32],
        final_v5_context_hash: [0x33; 32],
        host_offer_hash: [0x44; 32],
        viewer_offer_hash: [0x55; 32],
        selected_context_hash: selected.hash(),
        negotiation_binding_hash: [0x77; 32],
        local_policy_hash: [0x88; 32],
        host_identity_fingerprint: [0x99; 32],
        lineage_id: [0xaa; 32],
        activation_id: [0xbb; 32],
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn rekey_profile_binding_ids_match_wire_and_node_vectors() {
    let selected = selected();
    let activation = activation(&selected);

    let lane = AuthorityRekeyProfileBindingV1::new(
        &activation,
        &selected,
        RekeyTransitionProfileV1::LaneSessionV1,
    )
    .unwrap();
    let operator = AuthorityRekeyProfileBindingV1::new(
        &activation,
        &selected,
        RekeyTransitionProfileV1::OperatorChannelV1,
    )
    .unwrap();

    assert_eq!(
        hex(&lane.binding_id),
        "72de9b13331335d95f31a007c2eb37e97a4e890caa277f6a83e85c07cd1858a7"
    );
    assert_eq!(
        hex(&operator.binding_id),
        "d1a0eca840e4dbb803466203d20ff2d7a31b9e97967eb84a4fff41b29375cafd"
    );
    assert_ne!(lane.binding_id, operator.binding_id);
}
