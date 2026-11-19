//! Structural integrity checks for the preregistered M1 authorization benchmark seed.
//!
//! These checks validate fixture shape and one-to-one outcome-oracle linkage.
//! They do not execute candidate authorization logic or independently adjudicate
//! the oracle. The oracle is a separately stored reference artifact.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use xenia_peer_core::{M1DataDirection, M1Permission};

const CORPUS: &str =
    include_str!("../../../docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_CORPUS_V0_1.json");
const ORACLE: &str =
    include_str!("../../../docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_ORACLE_V0_1.json");

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

fn corpus() -> Value {
    serde_json::from_str(CORPUS).expect("M1 benchmark input corpus must be valid JSON")
}

fn oracle() -> Value {
    serde_json::from_str(ORACLE).expect("M1 benchmark outcome oracle must be valid JSON")
}

fn oracle_result<'a>(oracle: &'a Value, id: &str) -> &'a Value {
    oracle["scenario_results"]
        .as_array()
        .expect("oracle scenario_results must be an array")
        .iter()
        .find(|row| row["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("oracle result missing scenario {id}"))
}

#[test]
fn benchmark_corpus_has_32_unique_cases_and_balanced_families() {
    let input = corpus();
    let expected = oracle();
    assert_eq!(
        input["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-assurance-corpus")
    );
    assert_eq!(input["schema_version"].as_str(), Some("0.1.0"));
    assert_eq!(
        input["status"].as_str(),
        Some("preregistration_seed_not_results")
    );
    assert_eq!(
        input["oracle_ref"].as_str(),
        Some("M1_AUTHORIZATION_ASSURANCE_ORACLE_V0_1.json")
    );
    assert_eq!(
        input["oracle_separate_from_candidate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        expected["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-assurance-oracle")
    );
    assert_eq!(expected["schema_version"].as_str(), Some("0.1.0"));
    assert_eq!(
        expected["status"].as_str(),
        Some("preregistration_oracle_not_independently_adjudicated")
    );
    assert_eq!(
        expected["independent_from_candidate_implementation"].as_bool(),
        Some(true)
    );
    assert_eq!(
        expected["independent_adjudication_status"].as_str(),
        Some("pending")
    );
    assert_eq!(
        expected["input_corpus_source_commit"].as_str(),
        input["source_commit"].as_str()
    );

    let scenarios = input["scenarios"]
        .as_array()
        .expect("scenarios must be an array");
    let oracle_rows = expected["scenario_results"]
        .as_array()
        .expect("oracle results must be an array");
    assert_eq!(scenarios.len(), 32);
    assert_eq!(oracle_rows.len(), scenarios.len());

    let mut ids = BTreeSet::new();
    let mut oracle_ids = BTreeSet::new();
    let mut family_counts = BTreeMap::<String, usize>::new();
    for row in oracle_rows {
        let id = row["id"].as_str().expect("oracle ID is required");
        assert!(oracle_ids.insert(id), "duplicate oracle ID: {id}");
        assert!(matches!(
            row["authorization_disposition"].as_str(),
            Some("PERMIT" | "DENY" | "HOLD")
        ));
        assert!(row["task_outcome"].as_str().is_some());
        assert!(row["local_effect_state"].as_str().is_some());
        assert!(row["remote_observation_state"].as_str().is_some());
        assert!(row["reconciliation_state"].as_str().is_some());
        assert!(row["expected_new_effect_attempts"].as_u64().is_some());
        assert!(row["rationale"].as_str().is_some());
    }

    for scenario in scenarios {
        let id = scenario["id"].as_str().expect("scenario ID is required");
        assert!(ids.insert(id), "duplicate benchmark scenario ID: {id}");
        assert!(
            scenario.get("expected_disposition").is_none()
                && scenario.get("expected_effect").is_none()
                && scenario.get("expected_reconciliation").is_none(),
            "expected outcomes belong only in the separate oracle: {id}"
        );

        let family = scenario["family"]
            .as_str()
            .expect("scenario family is required");
        *family_counts.entry(family.to_owned()).or_default() += 1;

        let lane_name = scenario["lane"].as_str().expect("lane is required");
        let permission = lane(lane_name);
        let action_id = scenario["action_id"]
            .as_str()
            .expect("action ID is required");
        let mutation = scenario["mutation"].as_str().unwrap_or("none");
        let result = oracle_result(&expected, id);

        if mutation == "action_id_mismatch" {
            assert_ne!(
                action_id,
                permission.action_id(),
                "mutation was not preserved in {id}"
            );
            assert_eq!(result["authorization_disposition"].as_str(), Some("DENY"));
            assert_eq!(result["local_effect_state"].as_str(), Some("NOT_ATTEMPTED"));
        } else {
            assert_eq!(
                action_id,
                permission.action_id(),
                "action mapping mismatch in {id}"
            );
        }

        let observed_direction = direction(
            scenario["direction"]
                .as_str()
                .expect("direction is required"),
        );
        if mutation == "direction_mismatch" {
            assert_ne!(
                observed_direction,
                permission.direction(),
                "mutation was not preserved in {id}"
            );
            assert_eq!(result["authorization_disposition"].as_str(), Some("DENY"));
            assert_eq!(result["local_effect_state"].as_str(), Some("NOT_ATTEMPTED"));
        } else {
            assert_eq!(
                observed_direction,
                permission.direction(),
                "direction mapping mismatch in {id}"
            );
        }

        let binding = scenario["operation_binding"]
            .as_object()
            .unwrap_or_else(|| panic!("operation_binding is required in {id}"));
        for field in [
            "principal_ref",
            "delegate_ref",
            "host_resource_ref",
            "purpose",
            "audience",
            "operation_id",
            "operation_fingerprint",
            "session_fingerprint",
            "session_epoch",
            "authority_epoch",
            "requested_at",
        ] {
            assert!(
                binding.contains_key(field),
                "missing binding {field} in {id}"
            );
        }
        assert!(scenario["description"].as_str().is_some());
        assert!(scenario["authority"].as_str().is_some());
        assert!(scenario["consent"].as_str().is_some());
        assert!(scenario["route"].as_str().is_some());
        if let Some(parameters) = scenario.get("parameters") {
            assert!(
                parameters.is_object(),
                "parameters must be an object in {id}"
            );
        }
    }

    assert_eq!(
        ids, oracle_ids,
        "scenario input and outcome oracle IDs must match exactly"
    );
    assert_eq!(ids.len(), 32);
    assert_eq!(
        family_counts,
        BTreeMap::from([
            ("effect_and_outcome".to_owned(), 8),
            ("freshness_and_propagation".to_owned(), 8),
            ("positive_control".to_owned(), 8),
            ("scope_or_consent_negative".to_owned(), 8),
        ])
    );
}

#[test]
fn positive_controls_cover_each_lane_exactly_once() {
    let input = corpus();
    let expected = oracle();
    let scenarios = input["scenarios"].as_array().unwrap();
    let mut positive_lanes = BTreeSet::new();

    for scenario in scenarios
        .iter()
        .filter(|scenario| scenario["family"] == "positive_control")
    {
        let id = scenario["id"].as_str().unwrap();
        let lane_name = scenario["lane"].as_str().unwrap();
        let permission = lane(lane_name);
        assert!(
            positive_lanes.insert(lane_name),
            "duplicate positive control for lane {lane_name}"
        );
        assert_eq!(scenario["action_id"].as_str(), Some(permission.action_id()));
        assert_eq!(
            direction(scenario["direction"].as_str().unwrap()),
            permission.direction()
        );
        let result = oracle_result(&expected, id);
        assert_eq!(
            result["authorization_disposition"].as_str(),
            Some("PERMIT"),
            "positive control must permit: {id}"
        );
        assert_eq!(result["task_outcome"].as_str(), Some("COMPLETE"));
        assert_eq!(result["reconciliation_state"].as_str(), Some("KNOWN"));
        assert_eq!(result["expected_new_effect_attempts"].as_u64(), Some(1));
    }

    assert_eq!(positive_lanes.len(), M1Permission::ALL.len());
    for permission in M1Permission::ALL {
        assert!(positive_lanes.contains(permission_name(permission)));
    }
}

#[test]
fn effect_outcome_cases_do_not_back_propagate_runtime_failures_into_authorization() {
    let expected = oracle();

    // Authorization remains PERMIT when a downstream local effect/transport
    // attempt fails or becomes uncertain; the effect state carries the failure.
    for id in ["M1-E01", "M1-E02", "M1-E03", "M1-E04", "M1-E05"] {
        let result = oracle_result(&expected, id);
        assert_eq!(
            result["authorization_disposition"].as_str(),
            Some("PERMIT"),
            "downstream outcome must not rewrite authorization for {id}"
        );
        assert!(result["expected_new_effect_attempts"].as_u64().unwrap() >= 1);
    }

    let timeout = oracle_result(&expected, "M1-E02");
    assert_eq!(timeout["local_effect_state"].as_str(), Some("UNKNOWN"));
    assert_eq!(timeout["reconciliation_state"].as_str(), Some("REQUIRED"));

    // Exact retries resolve to the prior operation; changed fingerprints conflict.
    let replay = oracle_result(&expected, "M1-E06");
    assert_eq!(replay["authorization_disposition"].as_str(), Some("PERMIT"));
    assert_eq!(
        replay["replay_state"].as_str(),
        Some("RESOLVED_PRIOR_RESULT")
    );
    assert_eq!(replay["expected_new_effect_attempts"].as_u64(), Some(0));

    let conflict = oracle_result(&expected, "M1-E07");
    assert_eq!(conflict["authorization_disposition"].as_str(), Some("DENY"));
    assert_eq!(conflict["replay_state"].as_str(), Some("CONFLICT"));
    assert_eq!(
        conflict["local_effect_state"].as_str(),
        Some("NOT_ATTEMPTED")
    );

    let retry = oracle_result(&expected, "M1-E08");
    assert_eq!(retry["authorization_disposition"].as_str(), Some("HOLD"));
    assert_eq!(retry["local_effect_state"].as_str(), Some("UNKNOWN"));
    assert_eq!(retry["expected_new_effect_attempts"].as_u64(), Some(0));
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

const DRIFT_EXTENSION: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHORIZATION_DRIFT_DUAL_OBLIGATION_EXTENSION_V0_1.json"
);
const DRIFT_ORACLE: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHORIZATION_DRIFT_DUAL_OBLIGATION_ORACLE_V0_1.json"
);

#[test]
fn drift_and_dual_obligation_extension_has_matched_pairs_and_separate_oracle() {
    let input: Value =
        serde_json::from_str(DRIFT_EXTENSION).expect("drift extension must be valid JSON");
    let expected: Value =
        serde_json::from_str(DRIFT_ORACLE).expect("drift oracle must be valid JSON");

    assert_eq!(
        input["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-drift-dual-obligation-extension")
    );
    assert_eq!(
        input["status"].as_str(),
        Some("preregistration_extension_not_results")
    );
    assert_eq!(input["synthetic_only"].as_bool(), Some(true));
    assert_eq!(
        input["oracle_separate_from_candidate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        expected["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-drift-dual-obligation-oracle")
    );
    assert_eq!(
        expected["independent_adjudication_status"].as_str(),
        Some("pending")
    );

    let cases = input["cases"].as_array().expect("cases array required");
    let results = expected["scenario_results"]
        .as_array()
        .expect("oracle scenario_results array required");
    assert_eq!(cases.len(), 16);
    assert_eq!(results.len(), cases.len());

    let mut case_ids = BTreeSet::new();
    let mut oracle_ids = BTreeSet::new();
    for result in results {
        let id = result["id"].as_str().expect("oracle ID required");
        assert!(oracle_ids.insert(id), "duplicate drift oracle ID: {id}");
        assert!(matches!(
            result["expected_authorization_disposition"].as_str(),
            Some("PERMIT" | "DENY" | "HOLD")
        ));
        assert!(
            result["expected_completed_operation_count"]
                .as_u64()
                .is_some()
        );
        assert!(
            result["expected_unauthorized_effect_count"]
                .as_u64()
                .is_some()
        );
    }

    let mut groups = BTreeMap::<String, Vec<&Value>>::new();
    for case in cases {
        let id = case["id"].as_str().expect("case ID required");
        assert!(case_ids.insert(id), "duplicate drift scenario ID: {id}");
        assert_eq!(case["synthetic_fixture_only"].as_bool(), Some(true));
        let binding = case["operation_binding"]
            .as_object()
            .unwrap_or_else(|| panic!("operation binding missing: {id}"));
        for field in [
            "principal_ref",
            "delegate_ref",
            "host_resource_ref",
            "purpose",
            "audience",
            "operation_id",
            "approved_operation_fingerprint",
            "requested_operation_fingerprint",
            "upstream_state_fingerprint",
            "session_fingerprint",
            "active_session_epoch",
            "requested_session_epoch",
            "approved_effect_resource_ref",
            "requested_effect_resource_ref",
        ] {
            assert!(binding.contains_key(field), "{id}: missing binding {field}");
        }
        assert!(case["dimension"].as_str().is_some());
        assert!(case["stage"].as_str().is_some());
        assert!(case["mutation"].as_str().is_some());
        let pair_id = case["pair_id"].as_str().expect("pair_id required");
        groups.entry(pair_id.to_owned()).or_default().push(case);
    }

    assert_eq!(
        case_ids, oracle_ids,
        "input and oracle IDs must match exactly"
    );
    for pair_id in [
        "data-minimization",
        "tool-minimization",
        "resource-scope",
        "temporal-scope",
        "approve-reject-same-operation",
        "parallel-approved-branches",
        "workflow-reject-enforcement",
    ] {
        let pair = groups
            .get(pair_id)
            .unwrap_or_else(|| panic!("missing matched pair: {pair_id}"));
        assert_eq!(pair.len(), 2, "{pair_id} must have exactly two variants");
        let left = &pair[0]["operation_binding"];
        let right = &pair[1]["operation_binding"];
        assert_eq!(left["operation_id"], right["operation_id"]);
        assert_eq!(
            left["upstream_state_fingerprint"],
            right["upstream_state_fingerprint"]
        );
        assert_eq!(left["principal_ref"], right["principal_ref"]);
        assert_eq!(left["delegate_ref"], right["delegate_ref"]);
        assert_eq!(left["host_resource_ref"], right["host_resource_ref"]);
        assert_eq!(left["purpose"], right["purpose"]);
        assert_eq!(left["audience"], right["audience"]);
        assert_eq!(left["session_fingerprint"], right["session_fingerprint"]);

        // Hold every non-mutated authority/session binding constant. These
        // paired fixtures should differ only in the dimension named by the
        // pair, not by a second hidden epoch, principal, operation, or target
        // change that would confound attribution.
        for field in [
            "session_epoch",
            "authority_epoch",
            "operation_fingerprint",
            "active_session_epoch",
            "approved_operation_fingerprint",
            "approved_effect_resource_ref",
        ] {
            assert_eq!(
                left[field], right[field],
                "{pair_id} unexpectedly changed invariant binding {field}"
            );
        }

        if pair_id != "temporal-scope" {
            assert_eq!(
                left["requested_session_epoch"],
                right["requested_session_epoch"],
                "{pair_id} unexpectedly changed requested session epoch"
            );
        } else {
            assert_eq!(left["requested_session_epoch"], left["active_session_epoch"]);
            assert_ne!(
                right["requested_session_epoch"],
                right["active_session_epoch"],
                "temporal-scope mutation must use a stale queued session epoch"
            );
        }

        if pair_id != "resource-scope" {
            assert_eq!(
                left["requested_operation_fingerprint"],
                right["requested_operation_fingerprint"],
                "{pair_id} unexpectedly changed requested operation fingerprint"
            );
            assert_eq!(
                left["requested_effect_resource_ref"],
                right["requested_effect_resource_ref"],
                "{pair_id} unexpectedly changed requested effect resource"
            );
        } else {
            assert_eq!(
                left["requested_operation_fingerprint"],
                left["approved_operation_fingerprint"]
            );
            assert_ne!(
                right["requested_operation_fingerprint"],
                right["approved_operation_fingerprint"],
                "resource-scope mutation must substitute the requested operation fingerprint"
            );
            assert_eq!(
                left["requested_effect_resource_ref"],
                left["approved_effect_resource_ref"]
            );
            assert_ne!(
                right["requested_effect_resource_ref"],
                right["approved_effect_resource_ref"],
                "resource-scope mutation must substitute the requested effect resource"
            );
        }
    }

    let incomplete = results
        .iter()
        .find(|row| row["id"] == "M1-DO-PARALLEL-02")
        .unwrap();
    assert_eq!(
        incomplete["expected_authorization_disposition"].as_str(),
        Some("PERMIT")
    );
    assert_eq!(
        incomplete["expected_task_outcome"].as_str(),
        Some("COMPLETE")
    );
    assert_eq!(
        incomplete["expected_assurance_result"].as_str(),
        Some("PASS")
    );
    assert_eq!(
        incomplete["expected_approved_operation_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        incomplete["expected_completed_operation_count"].as_u64(),
        Some(2)
    );
    assert!(
        incomplete["failure_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| condition.as_str().unwrap().contains("FAIL_COMPLETENESS"))
    );

    let bypass = results
        .iter()
        .find(|row| row["id"] == "M1-DO-WORKFLOW-02")
        .unwrap();
    assert_eq!(
        bypass["expected_authorization_disposition"].as_str(),
        Some("DENY")
    );
    assert_eq!(
        bypass["expected_unauthorized_effect_count"].as_u64(),
        Some(0)
    );
    assert_eq!(bypass["expected_assurance_result"].as_str(), Some("PASS"));
    assert!(
        bypass["failure_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| condition.as_str().unwrap().contains("FAIL_REFUSAL_SAFETY"))
    );

    let unknown_route = results
        .iter()
        .find(|row| row["id"] == "M1-AD-TOOL-02")
        .unwrap();
    assert_eq!(
        unknown_route["expected_authorization_disposition"].as_str(),
        Some("HOLD")
    );
    assert_eq!(
        unknown_route["expected_task_outcome"].as_str(),
        Some("INDETERMINATE")
    );
}


const AUTHZEN_OBLIGATIONS_CORPUS: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHZEN_OBLIGATIONS_PROFILE_DRAFT1_CORPUS_V0_1.json"
);
const AUTHZEN_OBLIGATIONS_ORACLE: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHZEN_OBLIGATIONS_PROFILE_DRAFT1_ORACLE_V0_1.json"
);

#[test]
fn authzen_obligations_profile_distinguishes_permit_deny_and_search_compliance() {
    let input: Value = serde_json::from_str(AUTHZEN_OBLIGATIONS_CORPUS)
        .expect("AuthZEN obligations input corpus must be valid JSON");
    let expected: Value = serde_json::from_str(AUTHZEN_OBLIGATIONS_ORACLE)
        .expect("AuthZEN obligations outcome oracle must be valid JSON");

    assert_eq!(
        input["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authzen-obligations-profile-draft1-corpus")
    );
    assert_eq!(input["schema_version"].as_str(), Some("0.1.0"));
    assert_eq!(
        input["status"].as_str(),
        Some("preregistration_seed_not_results")
    );
    assert_eq!(input["synthetic_only"].as_bool(), Some(true));
    assert_eq!(input["oracle_separate_from_candidate"].as_bool(), Some(true));
    assert_eq!(
        input["source_profile_status"].as_str(),
        Some("openid_authzen_working_group_draft_1_published_2026-07-03")
    );
    assert_eq!(
        expected["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authzen-obligations-profile-draft1-oracle")
    );
    assert_eq!(
        expected["status"].as_str(),
        Some("preregistration_oracle_not_independently_adjudicated")
    );
    assert_eq!(
        expected["independent_adjudication_status"].as_str(),
        Some("pending")
    );
    assert_eq!(
        expected["input_corpus_source_commit"].as_str(),
        input["source_commit"].as_str()
    );

    let cases = input["cases"].as_array().expect("AuthZEN cases are required");
    let results = expected["scenario_results"]
        .as_array()
        .expect("AuthZEN oracle results are required");
    assert_eq!(cases.len(), 7);
    assert_eq!(results.len(), cases.len());

    let mut case_ids = BTreeSet::new();
    let mut result_ids = BTreeSet::new();
    for result in results {
        let id = result["id"].as_str().expect("oracle ID is required");
        assert!(result_ids.insert(id), "duplicate AuthZEN oracle ID: {id}");
        assert!(matches!(
            result["expected_effective_decision"].as_str(),
            Some("PERMIT" | "DENY" | "FILTER_RESULTS")
        ));
        assert!(
            result["expected_operation_effect_attempts"]
                .as_u64()
                .is_some()
        );
        for field in [
            "expected_obligation_attempts",
            "expected_obligation_successes",
            "expected_noncompliant_obligations",
        ] {
            assert!(
                result[field].as_array().is_some(),
                "{id}: missing oracle array {field}"
            );
        }
        assert!(result["expected_rationale"].as_str().is_some());
    }

    for case in cases {
        let id = case["id"].as_str().expect("AuthZEN case ID is required");
        assert!(case_ids.insert(id), "duplicate AuthZEN case ID: {id}");
        assert_eq!(case["synthetic_fixture_only"].as_bool(), Some(true));
        let shape = case["request_shape"]
            .as_str()
            .expect("request shape is required");
        assert!(matches!(shape, "decision" | "search"));
        assert!(matches!(
            case["original_decision"].as_str(),
            Some("PERMIT" | "DENY")
        ));
        assert!(case["pep_supported_obligation_types"].as_array().is_some());

        if shape == "decision" {
            let binding = case["operation_binding"]
                .as_object()
                .expect("decision operation binding is required");
            for field in [
                "principal_ref",
                "delegate_ref",
                "action_id",
                "resource_ref",
                "audience",
                "purpose",
                "operation_id",
                "operation_digest",
                "authority_epoch",
                "session_fingerprint",
            ] {
                assert!(binding.contains_key(field), "{id}: missing {field}");
            }
            let obligations = case["obligations"]
                .as_array()
                .expect("decision obligations are required");
            let mut obligation_ids = BTreeSet::new();
            for obligation in obligations {
                let obligation_id = obligation["id"]
                    .as_str()
                    .expect("obligation ID is required");
                assert!(
                    obligation_ids.insert(obligation_id),
                    "{id}: duplicate obligation ID {obligation_id}"
                );
                assert!(obligation["type"].as_str().is_some());
                assert!(obligation["properties"].is_object());
                assert!(matches!(
                    obligation["instance_state"].as_str(),
                    Some("well_formed" | "malformed_missing_required_body")
                ));
                assert!(matches!(
                    obligation["execution_environment"].as_str(),
                    Some("success" | "failure" | "unsupported" | "cannot_execute")
                ));
            }
        } else {
            assert!(case.get("operation_binding").is_none());
            let candidates = case["candidate_results"]
                .as_array()
                .expect("Search-shaped result candidates are required");
            assert!(candidates.len() >= 2);
            for candidate in candidates {
                assert!(candidate["result_id"].as_str().is_some());
                assert!(candidate["obligations"].as_array().is_some());
            }
        }
    }

    assert_eq!(
        case_ids, result_ids,
        "AuthZEN corpus and separate oracle IDs must match exactly"
    );

    // PERMIT is honored only after all mandatory obligations succeed.
    let permit = results.iter().find(|row| row["id"] == "M1-AO-01").unwrap();
    assert_eq!(
        permit["expected_effective_decision"].as_str(),
        Some("PERMIT")
    );
    assert_eq!(
        permit["expected_operation_effect_attempts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        permit["expected_obligation_successes"].as_array().unwrap().len(),
        2
    );

    // Unsupported, malformed or failed mandatory obligations downgrade a
    // PERMIT to DENY, while all other executable obligations are still run.
    for id in ["M1-AO-02", "M1-AO-03", "M1-AO-06"] {
        let result = results.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(
            result["expected_effective_decision"].as_str(),
            Some("DENY"),
            "{id}: noncompliant mandatory obligation must deny"
        );
        assert_eq!(
            result["expected_operation_effect_attempts"].as_u64(),
            Some(0),
            "{id}: denied operation must not reach its effect owner"
        );
        assert!(
            !result["expected_obligation_successes"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: executable obligations must still be attempted"
        );
        assert!(
            !result["expected_noncompliant_obligations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    // Obligations accompanying DENY never turn it into PERMIT.
    for id in ["M1-AO-04", "M1-AO-05"] {
        let result = results.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(
            result["original_decision"].as_str(),
            Some("DENY")
        );
        assert_eq!(
            result["expected_effective_decision"].as_str(),
            Some("DENY")
        );
        assert_eq!(
            result["expected_operation_effect_attempts"].as_u64(),
            Some(0)
        );
    }

    // The Search-shaped exception filters only the non-compliant result;
    // it does not withhold unrelated results or reinterpret the request as
    // a single-resource DENY.
    let search = results.iter().find(|row| row["id"] == "M1-AO-07").unwrap();
    assert_eq!(
        search["expected_effective_decision"].as_str(),
        Some("FILTER_RESULTS")
    );
    assert_eq!(
        search["expected_excluded_result_ids"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        search["expected_returned_result_ids"].as_array().unwrap().len(),
        2
    );
}


const CLARIFICATION_CORPUS: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHORIZATION_CLARIFICATION_EXTENSION_V0_1.json"
);
const CLARIFICATION_ORACLE: &str = include_str!(
    "../../../docs/benchmarks/M1_AUTHORIZATION_CLARIFICATION_EXTENSION_V0_1_ORACLE.json"
);

#[test]
fn clarification_extension_preserves_intent_scope_without_unnecessary_questions() {
    let input: Value = serde_json::from_str(CLARIFICATION_CORPUS)
        .expect("clarification input corpus must be valid JSON");
    let expected: Value = serde_json::from_str(CLARIFICATION_ORACLE)
        .expect("clarification outcome oracle must be valid JSON");

    assert_eq!(
        input["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-clarification-extension")
    );
    assert_eq!(
        input["status"].as_str(),
        Some("preregistration_extension_not_results")
    );
    assert_eq!(input["synthetic_only"].as_bool(), Some(true));
    assert_eq!(input["oracle_separate_from_candidate"].as_bool(), Some(true));
    assert_eq!(
        expected["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-authorization-clarification-extension-oracle")
    );
    assert_eq!(
        expected["status"].as_str(),
        Some("preregistration_oracle_not_independently_adjudicated")
    );
    assert_eq!(
        expected["independent_adjudication_status"].as_str(),
        Some("pending")
    );
    assert_eq!(
        expected["input_source_baseline_commit"].as_str(),
        input["source_baseline_commit"].as_str()
    );

    let cases = input["cases"].as_array().expect("clarification cases required");
    let results = expected["scenario_results"]
        .as_array()
        .expect("clarification oracle results required");
    assert_eq!(cases.len(), 4);
    assert_eq!(results.len(), cases.len());

    let mut case_ids = BTreeSet::new();
    let mut result_ids = BTreeSet::new();
    for row in results {
        let id = row["id"].as_str().expect("oracle ID required");
        assert!(result_ids.insert(id), "duplicate clarification oracle ID: {id}");
        assert!(row["clarification_required"].as_bool().is_some());
        assert!(row["clarification_round_trips"].as_u64().is_some());
        assert!(matches!(
            row["authorization_disposition"].as_str(),
            Some("PERMIT" | "DENY" | "HOLD")
        ));
        assert!(row["authorized_actions"].as_array().is_some());
        assert!(row["new_effect_attempts"].as_u64().is_some());
        assert!(row["unapproved_action_attempts"].as_u64().is_some());
        assert!(row["unauthorized_effects"].as_u64().is_some());
        assert!(row["rationale"].as_str().is_some());
    }

    for case in cases {
        let id = case["id"].as_str().expect("case ID required");
        assert!(case_ids.insert(id), "duplicate clarification case ID: {id}");
        assert_eq!(case["synthetic_fixture_only"].as_bool(), Some(true));
        for field in [
            "expected_disposition",
            "expected_task_outcome",
            "expected_effect_attempts",
            "expected_unauthorized_effects",
        ] {
            assert!(
                case.get(field).is_none(),
                "{id}: expected outcomes must remain in the separate oracle"
            );
        }
        let requested = case
            .get("requested_actions")
            .or_else(|| case.get("proposed_actions"))
            .and_then(Value::as_array)
            .expect("requested_actions or proposed_actions required");
        let approved = case["approved_actions"]
            .as_array()
            .expect("approved_actions required");
        for action in requested.iter().chain(approved.iter()) {
            let action = action.as_str().expect("action ID must be a string");
            assert!(
                M1Permission::ALL.iter().any(|permission| permission.action_id() == action),
                "{id}: action is not a stable M1 action ID: {action}"
            );
        }
        assert!(case["description"].as_str().is_some());
        assert!(case["stage"].as_str().is_some());
        assert!(case["mutation"].as_str().is_some());
        let result = results
            .iter()
            .find(|row| row["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("clarification oracle missing {id}"));
        assert_eq!(
            result["authorized_actions"].as_array().unwrap(),
            approved,
            "{id}: oracle authority must not exceed the explicit approved action set"
        );
    }

    assert_eq!(
        case_ids, result_ids,
        "clarification inputs and oracle IDs must match exactly"
    );

    // Ambiguous intent cannot be promoted into implicit authority.
    let ambiguous = results.iter().find(|row| row["id"] == "M1-CL-01").unwrap();
    assert_eq!(
        ambiguous["authorization_disposition"].as_str(),
        Some("HOLD")
    );
    assert_eq!(
        ambiguous["task_outcome"].as_str(),
        Some("AWAITING_CLARIFICATION")
    );
    assert_eq!(ambiguous["clarification_required"].as_bool(), Some(true));
    assert_eq!(ambiguous["new_effect_attempts"].as_u64(), Some(0));
    assert!(ambiguous["authorized_actions"].as_array().unwrap().is_empty());

    // Clarification permits only the exact lane the principal selected.
    let clarified = results.iter().find(|row| row["id"] == "M1-CL-02").unwrap();
    assert_eq!(
        clarified["authorization_disposition"].as_str(),
        Some("PERMIT")
    );
    assert_eq!(clarified["new_effect_attempts"].as_u64(), Some(1));
    assert_eq!(
        clarified["authorized_actions"].as_array().unwrap()[0].as_str(),
        Some("xenia.screen.view")
    );

    // A complete request should proceed without redundant questioning.
    let explicit = results.iter().find(|row| row["id"] == "M1-CL-03").unwrap();
    assert_eq!(
        explicit["authorization_disposition"].as_str(),
        Some("PERMIT")
    );
    assert_eq!(explicit["clarification_required"].as_bool(), Some(false));
    assert_eq!(explicit["clarification_round_trips"].as_u64(), Some(0));
    assert_eq!(explicit["new_effect_attempts"].as_u64(), Some(1));

    // The clarified screen-only scope cannot be widened to clipboard disclosure.
    let widened = results.iter().find(|row| row["id"] == "M1-CL-04").unwrap();
    assert_eq!(
        widened["authorization_disposition"].as_str(),
        Some("DENY")
    );
    assert_eq!(widened["new_effect_attempts"].as_u64(), Some(0));
    assert_eq!(widened["unapproved_action_attempts"].as_u64(), Some(1));
    assert_eq!(widened["unauthorized_effects"].as_u64(), Some(0));
}


const EFFECT_RACE_CORPUS: &str = include_str!(
    "../../../docs/benchmarks/M1_EFFECT_RACE_HISTORY_EXTENSION_V0_1.json"
);
const EFFECT_RACE_ORACLE: &str = include_str!(
    "../../../docs/benchmarks/M1_EFFECT_RACE_HISTORY_EXTENSION_V0_1_ORACLE.json"
);

fn race_corpus() -> Value {
    serde_json::from_str(EFFECT_RACE_CORPUS)
        .expect("effect-race input corpus must be valid JSON")
}

fn race_oracle() -> Value {
    serde_json::from_str(EFFECT_RACE_ORACLE)
        .expect("effect-race oracle must be valid JSON")
}

fn event_seq(case: &Value, event_name: &str) -> u64 {
    case["schedule"]
        .as_array()
        .expect("history schedule required")
        .iter()
        .find(|event| event["event"].as_str() == Some(event_name))
        .unwrap_or_else(|| panic!("{} missing event {event_name}", case["id"]))
        ["seq"]
        .as_u64()
        .expect("event sequence must be unsigned")
}

fn race_case<'a>(cases: &'a [Value], id: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| case["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing effect-race case {id}"))
}

fn race_result<'a>(rows: &'a [Value], id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing effect-race oracle result {id}"))
}

#[test]
fn effect_race_histories_preserve_linearization_and_unknown_outcome_semantics() {
    let input = race_corpus();
    let expected = race_oracle();

    assert_eq!(
        input["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-effect-race-history-extension")
    );
    assert_eq!(
        input["status"].as_str(),
        Some("preregistration_extension_not_results")
    );
    assert_eq!(input["synthetic_only"].as_bool(), Some(true));
    assert_eq!(
        input["histories_are_logical_orders_not_wall_clock_times"].as_bool(),
        Some(true)
    );
    assert_eq!(input["oracle_separate_from_candidate"].as_bool(), Some(true));
    assert_eq!(
        expected["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-effect-race-history-extension-oracle")
    );
    assert_eq!(
        expected["status"].as_str(),
        Some("preregistration_oracle_not_independently_adjudicated")
    );
    assert_eq!(
        expected["independent_adjudication_status"].as_str(),
        Some("pending")
    );
    assert_eq!(
        expected["input_source_baseline_commit"].as_str(),
        input["source_baseline_commit"].as_str()
    );

    let cases = input["cases"].as_array().expect("race cases required");
    let rows = expected["scenario_results"]
        .as_array()
        .expect("race oracle results required");
    assert_eq!(cases.len(), 12);
    assert_eq!(rows.len(), cases.len());

    let mut case_ids = BTreeSet::new();
    let mut result_ids = BTreeSet::new();
    let known_events: BTreeSet<&str> = [
        "source_preflight_permit",
        "revocation_observed",
        "effect_owner_gate_denied",
        "effect_owner_commit",
        "remote_ack_timeout",
        "sensitive_source_read",
        "local_buffer_invalidated",
        "transport_dispatch_attempted",
        "transport_timeout",
        "first_dispatch_attempted",
        "first_outcome_unknown",
        "exact_retry_same_operation",
        "prior_operation_result_returned",
        "operation_id_seen",
        "same_id_changed_fingerprint",
        "idempotency_conflict",
        "operation_queued_old_session",
        "session_rekey_committed",
        "old_operation_reaches_effect_owner",
        "stale_session_rejected",
        "parent_revocation_committed",
        "ancestor_revocation_observed",
        "cached_child_attempt",
        "offer_accepted",
        "chunks_staged",
        "final_publish_gate_denied",
        "staged_artifact_quarantined_or_removed",
        "clipboard_source_preflight_permit",
        "clipboard_source_read",
        "disclosure_send_gate_denied",
        "clipboard_buffer_invalidated",
        "pep_a_consume_requested",
        "pep_b_consume_requested",
        "single_consume_linearized_to_one_pep",
        "losing_pep_denied_as_consumed",
        "winner_effect_dispatch",
        "operator_revoke_authenticated",
        "operator_revocation_latch_set",
        "send_loop_error_observed",
        "revocation_finalizer_invoked",
        "canonical_revocation_appended_to_session_chain",
        "original_send_loop_error_propagated",
    ]
    .into_iter()
    .collect();

    for row in rows {
        let id = row["id"].as_str().expect("oracle case ID required");
        assert!(result_ids.insert(id), "duplicate oracle ID {id}");
        assert!(matches!(
            row["authorization_disposition"].as_str(),
            Some("DENY" | "PERMIT_AT_COMMIT" | "DENY_AT_FINAL_GATE"
                | "PRIOR_DECISION_REUSED" | "CONFLICT" | "DENY_STALE_SESSION"
                | "DENY_REVOKED_ANCESTOR" | "DENY_FINAL_PUBLISH"
                | "DENY_DISCLOSURE_SEND" | "ONE_CONSUMER_PERMITTED")
        ));
        assert!(row["effectful_dispatches"].as_u64().is_some());
        assert!(row["duplicate_dispatches"].as_u64().is_some());
        assert!(row["retry_allowed"].as_bool().is_some());
        assert!(row["reconciliation_required"].as_bool().is_some());
        assert!(row["terminal_evidence_claim"].as_str().is_some());
    }

    for case in cases {
        let id = case["id"].as_str().expect("input case ID required");
        assert!(case_ids.insert(id), "duplicate input case ID {id}");
        assert_eq!(case["synthetic_only"].as_bool(), Some(true));
        assert!(case["description"].as_str().is_some());
        assert!(case["family"].as_str().is_some());

        let operation = &case["operation"];
        let action = operation["action_id"].as_str().expect("action ID required");
        assert!(
            M1Permission::ALL
                .iter()
                .any(|permission| permission.action_id() == action),
            "{id}: unknown M1 action ID {action}"
        );
        assert!(operation["id"].as_str().is_some());
        assert!(operation["fingerprint"].as_str().is_some());
        assert!(operation["resource"].as_str().is_some());

        let schedule = case["schedule"].as_array().expect("schedule required");
        assert!(!schedule.is_empty());
        let mut prior_seq = 0u64;
        for event in schedule {
            let seq = event["seq"].as_u64().expect("event sequence required");
            assert_eq!(seq, prior_seq + 1, "{id}: logical history sequence must be contiguous");
            prior_seq = seq;
            let event_name = event["event"].as_str().expect("event name required");
            assert!(
                known_events.contains(event_name),
                "{id}: unknown event name {event_name}"
            );
            assert!(event["owner"].as_str().is_some(), "{id}: event owner required");
        }

        let result = race_result(rows, id);
        let effectful_dispatches = result["effectful_dispatches"]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: effectful dispatch count must be integral"));
        let duplicate_dispatches = result["duplicate_dispatches"]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: duplicate dispatch count must be integral"));
        assert!(
            effectful_dispatches <= 1,
            "{id}: one logical operation cannot produce multiple effect-bearing dispatches"
        );
        assert_eq!(
            duplicate_dispatches,
            0,
            "{id}: oracle must not normalize duplicate effect-bearing dispatches as success"
        );
        assert!(result["authorization_disposition"].is_string());
    }
    assert_eq!(case_ids, result_ids, "race input/oracle IDs must match exactly");

    let revoke_first = race_case(cases, "M1-RACE-01");
    assert!(
        event_seq(revoke_first, "revocation_observed")
            < event_seq(revoke_first, "effect_owner_gate_denied")
    );
    let revoke_first_result = race_result(rows, "M1-RACE-01");
    assert_eq!(revoke_first_result["effectful_dispatches"].as_u64(), Some(0));

    let commit_first = race_case(cases, "M1-RACE-02");
    assert!(
        event_seq(commit_first, "effect_owner_commit")
            < event_seq(commit_first, "revocation_observed")
    );
    let commit_first_result = race_result(rows, "M1-RACE-02");
    assert_eq!(
        commit_first_result["operation_disposition"].as_str(),
        Some("COMMITTED_BEFORE_REVOCATION")
    );
    assert_eq!(commit_first_result["effectful_dispatches"].as_u64(), Some(1));
    assert_eq!(
        commit_first_result["remote_observation_state"].as_str(),
        Some("UNKNOWN_NO_ACK")
    );

    let timeout_result = race_result(rows, "M1-RACE-04");
    assert_eq!(
        timeout_result["operation_disposition"].as_str(),
        Some("UNKNOWN_AFTER_DISPATCH")
    );
    assert_eq!(timeout_result["retry_allowed"].as_bool(), Some(false));
    assert_eq!(
        timeout_result["reconciliation_required"].as_bool(),
        Some(true)
    );

    let replay_result = race_result(rows, "M1-RACE-05");
    assert_eq!(replay_result["operation_disposition"].as_str(), Some("IDEMPOTENT_REPLAY"));
    assert_eq!(replay_result["effectful_dispatches"].as_u64(), Some(1));
    assert_eq!(replay_result["duplicate_dispatches"].as_u64(), Some(0));

    let conflict = race_case(cases, "M1-RACE-06");
    assert!(conflict["operation"]["fingerprint"].as_str().unwrap()
        != conflict["operation"]["retry_fingerprint"].as_str().unwrap());
    assert_eq!(race_result(rows, "M1-RACE-06")["operation_disposition"], "CHANGED_FINGERPRINT_REJECTED");

    let rekey = race_case(cases, "M1-RACE-07");
    assert!(
        rekey["operation"]["session_epoch"].as_u64().unwrap()
            < rekey["operation"]["current_session_epoch"].as_u64().unwrap()
    );
    assert_eq!(race_result(rows, "M1-RACE-07")["effectful_dispatches"].as_u64(), Some(0));

    let ancestor = race_case(cases, "M1-RACE-08");
    assert!(
        event_seq(ancestor, "parent_revocation_committed")
            < event_seq(ancestor, "ancestor_revocation_observed")
    );
    assert!(
        event_seq(ancestor, "ancestor_revocation_observed")
            < event_seq(ancestor, "cached_child_attempt")
    );
    assert_eq!(race_result(rows, "M1-RACE-08")["effectful_dispatches"].as_u64(), Some(0));

    let staged = race_case(cases, "M1-RACE-09");
    assert!(event_seq(staged, "chunks_staged") < event_seq(staged, "revocation_observed"));
    assert!(event_seq(staged, "revocation_observed") < event_seq(staged, "final_publish_gate_denied"));
    assert_eq!(race_result(rows, "M1-RACE-09")["published_files"].as_u64(), Some(0));

    let clipboard = race_case(cases, "M1-RACE-10");
    assert!(event_seq(clipboard, "clipboard_source_read") < event_seq(clipboard, "revocation_observed"));
    assert!(event_seq(clipboard, "revocation_observed") < event_seq(clipboard, "disclosure_send_gate_denied"));
    assert!(event_seq(clipboard, "disclosure_send_gate_denied") < event_seq(clipboard, "clipboard_buffer_invalidated"));
    assert_eq!(race_result(rows, "M1-RACE-10")["plaintext_disclosures"].as_u64(), Some(0));

    let concurrent = race_case(cases, "M1-RACE-11");
    assert!(concurrent["operation"]["concurrent_consumers"].as_array().unwrap().len() >= 2);
    let concurrent_result = race_result(rows, "M1-RACE-11");
    assert_eq!(concurrent_result["effectful_dispatches"].as_u64(), Some(1));
    assert_eq!(concurrent_result["duplicate_dispatches"].as_u64(), Some(0));

    let teardown = race_case(cases, "M1-RACE-12");
    assert!(
        event_seq(teardown, "operator_revoke_authenticated")
            < event_seq(teardown, "operator_revocation_latch_set")
    );
    assert!(
        event_seq(teardown, "operator_revocation_latch_set")
            < event_seq(teardown, "send_loop_error_observed")
    );
    assert!(
        event_seq(teardown, "send_loop_error_observed")
            < event_seq(teardown, "revocation_finalizer_invoked")
    );
    assert!(
        event_seq(teardown, "revocation_finalizer_invoked")
            < event_seq(teardown, "canonical_revocation_appended_to_session_chain")
    );
    assert!(
        event_seq(teardown, "canonical_revocation_appended_to_session_chain")
            < event_seq(teardown, "original_send_loop_error_propagated")
    );
    let teardown_result = race_result(rows, "M1-RACE-12");
    assert_eq!(teardown_result["effectful_dispatches"].as_u64(), Some(0));
    assert_eq!(
        teardown_result["original_send_loop_error_propagated"].as_bool(),
        Some(true)
    );
    assert_eq!(
        teardown_result["durable_session_transcript_export"].as_bool(),
        Some(false),
        "in-memory M1 Chain append must not be represented as durable session export"
    );
}
