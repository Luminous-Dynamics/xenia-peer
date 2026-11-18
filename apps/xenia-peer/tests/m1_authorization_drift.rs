//! Structural known-answer checks for the Xenia M1 authorization-drift adapter.
//!
//! This verifies fixture integrity and lane mapping only. It does not execute
//! an agent, enforce Mycelix ROS-005, or observe host/network side effects.

use std::collections::BTreeSet;

use serde_json::Value;
use xenia_peer_core::{M1DataDirection, M1Permission};

const FIXTURE: &str =
    include_str!("../../../research/m1-authorization-drift-v0.1/scenarios.json");

#[test]
fn fixture_has_sixteen_unique_dual_path_known_answer_scenarios() {
    let fixture: Value =
        serde_json::from_str(FIXTURE).expect("M1 authorization-drift fixture must be valid JSON");
    assert_eq!(
        fixture["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-drift-adapter")
    );
    assert_eq!(fixture["schema_version"].as_str(), Some("0.1.0"));
    assert_eq!(
        fixture["status"].as_str(),
        Some("research_fixture_unqualified")
    );
    assert_eq!(
        fixture["claim_ceiling"].as_str().is_some(),
        true,
        "the fixture must state its qualification ceiling"
    );

    let scenarios = fixture["scenarios"]
        .as_array()
        .expect("scenarios must be an array");
    assert_eq!(scenarios.len(), 16, "the seed denominator is frozen at 16");

    let mut ids = BTreeSet::new();
    for scenario in scenarios {
        let id = scenario["id"]
            .as_str()
            .expect("every scenario needs a stable ID");
        assert!(ids.insert(id), "duplicate scenario ID: {id}");
        assert!(
            scenario["task"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "{id}: task text is required"
        );
        assert!(
            scenario["compliant_path"]
                .as_array()
                .is_some_and(|steps| !steps.is_empty()),
            "{id}: a compliant path must be executable"
        );
        assert!(
            scenario["unauthorized_shortcut"]["tempting_action"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
            "{id}: tempting shortcut must be explicit"
        );
        for field in [
            "task_success_on_compliant_path",
            "agent_drift_attempt",
            "pep_disposition",
            "protected_effect",
        ] {
            assert!(
                !scenario["expected"][field].is_null(),
                "{id}: expected.{field} is required"
            );
        }
        assert!(
            scenario["current_runtime_coverage"].as_str().is_some(),
            "{id}: implementation coverage must be explicit"
        );
    }
}

#[test]
fn fixture_lane_action_and_direction_match_m1_permission_source() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenarios = fixture["scenarios"].as_array().unwrap();

    let mut represented = BTreeSet::new();
    for scenario in scenarios {
        let lane = scenario["permission"].as_str().unwrap();
        let action_id = scenario["action_id"].as_str().unwrap();
        let direction = scenario["direction"].as_str().unwrap();

        let permission = M1Permission::ALL
            .into_iter()
            .find(|permission| format!("{permission:?}") == lane)
            .unwrap_or_else(|| panic!("unknown M1 permission {lane}"));

        assert_eq!(permission.action_id(), action_id, "{lane}: action ID drift");
        let expected_direction = match permission.direction() {
            M1DataDirection::HostToViewer => "host_to_viewer",
            M1DataDirection::ViewerToHost => "viewer_to_host",
        };
        assert_eq!(direction, expected_direction, "{lane}: direction drift");
        represented.insert(lane.to_string());
    }

    let expected: BTreeSet<String> = M1Permission::ALL
        .into_iter()
        .map(|permission| format!("{permission:?}"))
        .collect();
    assert_eq!(
        represented, expected,
        "the adapter must represent every one of the eight M1 lanes"
    );
}
