//! Structural integrity checks for the preregistered M1 authorization benchmark seed.
//!
//! These checks validate fixture shape, IDs and action/direction crosswalk only.
//! They are not the independent scenario oracle and do not evaluate runtime
//! authorization or effect outcomes.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use xenia_peer_core::{M1DataDirection, M1Permission};

const CORPUS: &str =
    include_str!("../../../docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_CORPUS_V0_2.json");

fn lane(value: &str) -> M1Permission {
    match value {
        "StreamFrame" => M1Permission::StreamFrame,
        "StreamTelemetry" => M1Permission::StreamTelemetry,
        "StreamAudio" => M1Permission::StreamAudio,
        "InjectInput" => M1Permission::InjectInput,
        "ReadHostClipboard" => M1Permission::ReadHostClipboard,
        "WriteHostClipboard" => M1Permission::WriteHostClipboard,
        "SendFileToViewer" => M1Permission::SendFileToViewer,
        "ReceiveFileFromViewer" => M1Permission::ReceiveFileFromViewer,
        other => panic!("unknown M1 lane in benchmark corpus: {other}"),
    }
}

fn direction(value: &str) -> M1DataDirection {
    match value {
        "host_to_viewer" => M1DataDirection::HostToViewer,
        "viewer_to_host" => M1DataDirection::ViewerToHost,
        other => panic!("unknown M1 direction in benchmark corpus: {other}"),
    }
}

#[test]
fn benchmark_corpus_has_64_unique_cases_and_balanced_families() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    assert_eq!(
        root["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-assurance-corpus")
    );
    assert_eq!(root["schema_version"].as_str(), Some("0.2.0"));
    assert_eq!(
        root["status"].as_str(),
        Some("preregistration_seed_not_results")
    );
    assert_eq!(root["oracle_separate_from_candidate"].as_bool(), Some(false));
    assert_eq!(
        root["oracle_status"].as_str(),
        Some("not_yet_implemented_independent_owner_oracle_required")
    );
    assert_eq!(root["scenario_count"].as_u64(), Some(64));

    let scenarios = root["scenarios"]
        .as_array()
        .expect("scenarios must be an array");
    assert_eq!(scenarios.len(), 64);

    let mut ids = BTreeSet::new();
    let mut family_counts = BTreeMap::<String, usize>::new();
    for scenario in scenarios {
        let id = scenario["id"].as_str().expect("scenario ID is required");
        assert!(ids.insert(id), "duplicate benchmark scenario ID: {id}");

        let family = scenario["family"]
            .as_str()
            .expect("scenario family is required");
        *family_counts.entry(family.to_owned()).or_default() += 1;

        let lane_name = scenario["lane"].as_str().expect("lane is required");
        let permission = lane(lane_name);
        let action_id = scenario["action_id"]
            .as_str()
            .expect("action ID is required");
        assert_eq!(
            action_id,
            permission.action_id(),
            "action mapping mismatch in {id}"
        );

        let observed_direction = direction(
            scenario["direction"]
                .as_str()
                .expect("direction is required"),
        );
        assert_eq!(
            observed_direction,
            permission.direction(),
            "direction mapping mismatch in {id}"
        );

        if let Some(source_lane) = scenario["source_lane"].as_str() {
            let source_permission = lane(source_lane);
            assert_ne!(
                source_permission, permission,
                "cross-lane negative must identify distinct source and target lanes: {id}"
            );
        }
        if let Some(attempted_direction) = scenario["attempted_direction"].as_str() {
            assert_ne!(
                direction(attempted_direction),
                permission.direction(),
                "direction-confusion case must differ from the canonical lane: {id}"
            );
        }

        let disposition = scenario["expected_disposition"]
            .as_str()
            .expect("expected disposition is required");
        assert!(
            matches!(disposition, "PERMIT" | "DENY" | "HOLD"),
            "invalid disposition in {id}: {disposition}"
        );

        for field in [
            "description",
            "authority",
            "consent",
            "route",
            "task_result",
            "expected_effect",
            "expected_reconciliation",
        ] {
            assert!(
                scenario[field].as_str().is_some(),
                "missing {field} in {id}"
            );
        }

        if matches!(
            family,
            "authorization_drift"
                | "bounded_authorization_completeness"
                | "harness_and_workflow_refusal"
                | "restoration_and_replay"
        ) {
            assert!(
                scenario["execution_layer"].as_str().is_some(),
                "new assurance case must identify execution layer: {id}"
            );
        }
        if family == "authorization_drift" {
            assert!(
                matches!(
                    scenario["drift_dimension"].as_str(),
                    Some("data" | "tool" | "scope" | "time")
                ),
                "invalid ADB drift dimension in {id}"
            );
        }
    }

    assert_eq!(ids.len(), 64);
    assert_eq!(
        family_counts,
        BTreeMap::from([
            ("authorization_drift".to_owned(), 8),
            ("bounded_authorization_completeness".to_owned(), 8),
            ("effect_and_outcome".to_owned(), 8),
            ("freshness_and_propagation".to_owned(), 8),
            ("harness_and_workflow_refusal".to_owned(), 8),
            ("positive_control".to_owned(), 8),
            ("restoration_and_replay".to_owned(), 8),
            ("scope_or_consent_negative".to_owned(), 8),
        ])
    );
}

#[test]
fn cross_lane_and_direction_mismatch_controls_are_explicit() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    let scenarios = root["scenarios"].as_array().unwrap();

    let cross_lane = scenarios.iter().find(|scenario| scenario["id"] == "M1-D01").unwrap();
    assert_eq!(cross_lane["lane"].as_str(), Some("InjectInput"));
    assert_eq!(cross_lane["source_lane"].as_str(), Some("StreamFrame"));
    assert_ne!(cross_lane["lane"], cross_lane["source_lane"]);

    let direction = scenarios.iter().find(|scenario| scenario["id"] == "M1-D02").unwrap();
    assert_eq!(direction["lane"].as_str(), Some("InjectInput"));
    assert_eq!(direction["direction"].as_str(), Some("viewer_to_host"));
    assert_eq!(direction["attempted_direction"].as_str(), Some("host_to_viewer"));
}

#[test]
fn authorization_drift_panel_covers_data_tool_scope_and_time() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    let mut dimensions = BTreeMap::<String, usize>::new();
    for scenario in root["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|scenario| scenario["family"] == "authorization_drift")
    {
        let dimension = scenario["drift_dimension"].as_str().unwrap();
        *dimensions.entry(dimension.to_owned()).or_default() += 1;
        assert_eq!(scenario["expected_disposition"].as_str(), Some("DENY"));
        assert_eq!(scenario["expected_effect"].as_str(), Some("NOT_ATTEMPTED"));
    }
    assert_eq!(
        dimensions,
        BTreeMap::from([
            ("data".to_owned(), 2),
            ("scope".to_owned(), 2),
            ("time".to_owned(), 2),
            ("tool".to_owned(), 2),
        ])
    );
}

#[test]
fn approved_work_completeness_has_eight_positive_effect_obligations() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    let scenarios = root["scenarios"].as_array().unwrap();
    let cases: Vec<_> = scenarios
        .iter()
        .filter(|scenario| scenario["family"] == "bounded_authorization_completeness")
        .collect();
    assert_eq!(cases.len(), M1Permission::ALL.len());
    for scenario in cases {
        let id = scenario["id"].as_str().unwrap();
        assert_eq!(scenario["expected_disposition"].as_str(), Some("PERMIT"), "{id}");
        assert_eq!(scenario["task_result"].as_str(), Some("complete"), "{id}");
        assert_eq!(
            scenario["approval_horizon"].as_str(),
            Some("valid_through_effect_boundary"),
            "{id}"
        );
        assert_ne!(scenario["expected_effect"].as_str(), Some("NOT_ATTEMPTED"), "{id}");
    }
}

#[test]
fn workflow_refusal_cases_do_not_allow_protected_effects() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    let scenarios = root["scenarios"].as_array().unwrap();
    let cases: Vec<_> = scenarios
        .iter()
        .filter(|scenario| scenario["family"] == "harness_and_workflow_refusal")
        .collect();
    assert_eq!(cases.len(), 8);
    for scenario in cases {
        let id = scenario["id"].as_str().unwrap();
        assert_eq!(scenario["expected_disposition"].as_str(), Some("DENY"), "{id}");
        assert_eq!(scenario["expected_effect"].as_str(), Some("NOT_ATTEMPTED"), "{id}");
    }
}

#[test]
fn positive_controls_cover_each_lane_exactly_once() {
    let root: Value = serde_json::from_str(CORPUS).expect("benchmark corpus must be valid JSON");
    let scenarios = root["scenarios"].as_array().unwrap();
    let mut positive_lanes = BTreeSet::new();

    for scenario in scenarios
        .iter()
        .filter(|scenario| scenario["family"] == "positive_control")
    {
        let id = scenario["id"].as_str().unwrap();
        let lane_name = scenario["lane"].as_str().unwrap();
        assert!(
            positive_lanes.insert(lane_name),
            "duplicate positive control for lane {lane_name}"
        );
        assert_eq!(
            scenario["expected_disposition"].as_str(),
            Some("PERMIT"),
            "positive control must permit: {id}"
        );
        assert_eq!(
            scenario["expected_reconciliation"].as_str(),
            Some("known"),
            "positive control must have a known local result: {id}"
        );
    }

    assert_eq!(positive_lanes.len(), M1Permission::ALL.len());
    for permission in M1Permission::ALL {
        assert!(positive_lanes.contains(permission_name(permission)));
    }
}

fn permission_name(permission: M1Permission) -> &'static str {
    match permission {
        M1Permission::StreamFrame => "StreamFrame",
        M1Permission::StreamTelemetry => "StreamTelemetry",
        M1Permission::StreamAudio => "StreamAudio",
        M1Permission::InjectInput => "InjectInput",
        M1Permission::ReadHostClipboard => "ReadHostClipboard",
        M1Permission::WriteHostClipboard => "WriteHostClipboard",
        M1Permission::SendFileToViewer => "SendFileToViewer",
        M1Permission::ReceiveFileFromViewer => "ReceiveFileFromViewer",
    }
}
