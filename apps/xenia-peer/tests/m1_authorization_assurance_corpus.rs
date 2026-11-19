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
