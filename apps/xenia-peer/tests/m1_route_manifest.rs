//! Source-backed checks for the M1 route inventory.
//!
//! These tests detect stale source references and obvious gate/effect ordering
//! drift. They do not prove complete mediation, AST-level control flow,
//! runtime reachability, or atomicity between a local check and an OS/network
//! effect. Those remain separate qualification obligations.

use serde_json::Value;
use std::collections::BTreeSet;

const MANIFEST: &str = include_str!("../../../docs/M1_ROUTE_MEDIATION_INVENTORY_V0_1.json");
const MAIN: &str = include_str!("../src/main.rs");
const FILE_TRANSFER: &str = include_str!("../src/file_transfer.rs");
const CONSENT_SERVER: &str = include_str!("../src/consent_server.rs");
const OPERATOR_HTTP: &str = include_str!("../src/operator_http.rs");
const SEALED_OPERATOR: &str = include_str!("../src/operator_sealed_channel.rs");
const M1_RUNTIME: &str = include_str!("../src/m1_runtime.rs");
const M1_SESSION: &str = include_str!("../../../crates/xenia-peer-core/src/m1_session.rs");

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).expect("M1 route manifest must remain valid JSON")
}

fn source(path: &str) -> &'static str {
    match path {
        "apps/xenia-peer/src/main.rs" => MAIN,
        "apps/xenia-peer/src/file_transfer.rs" => FILE_TRANSFER,
        "apps/xenia-peer/src/consent_server.rs" => CONSENT_SERVER,
        "apps/xenia-peer/src/operator_http.rs" => OPERATOR_HTTP,
        "apps/xenia-peer/src/operator_sealed_channel.rs" => SEALED_OPERATOR,
        "apps/xenia-peer/src/m1_runtime.rs" => M1_RUNTIME,
        "crates/xenia-peer-core/src/m1_session.rs" => M1_SESSION,
        other => panic!("unrecognized source path in M1 route manifest: {other}"),
    }
}

fn assert_ordered_occurrence(
    route_id: &str,
    source_text: &str,
    gate: &str,
    effect: &str,
    occurrence: usize,
) {
    let gate_position = source_text
        .match_indices(gate)
        .nth(occurrence)
        .map(|(position, _)| position)
        .unwrap_or_else(|| {
            panic!("{route_id}: gate occurrence {occurrence} was not found: {gate}")
        });
    let after_gate = &source_text[gate_position + gate.len()..];
    assert!(
        after_gate.contains(effect),
        "{route_id}: effect token '{effect}' must occur after gate '{gate}' occurrence {occurrence}"
    );
}

#[test]
fn manifest_identity_and_eight_lane_crosswalk_match_rust_source() {
    let manifest = manifest();
    assert_eq!(
        manifest["schema_id"].as_str(),
        Some("org.luminousdynamics.xenia.m1-route-inventory")
    );
    assert_eq!(manifest["schema_version"].as_str(), Some("0.1.0"));
    assert_eq!(
        manifest["claim"]["status"].as_str(),
        Some("source_inventoried_incomplete"),
        "the current source manifest must not promote itself to complete mediation"
    );
    assert_eq!(
        manifest["claim"]["complete_mediation"].as_str(),
        Some("not_claimed")
    );

    let expected = [
        ("StreamFrame", "xenia.screen.view", "host_to_viewer"),
        ("StreamTelemetry", "xenia.host.telemetry", "host_to_viewer"),
        ("StreamAudio", "xenia.audio.capture", "host_to_viewer"),
        ("InjectInput", "xenia.input.inject", "viewer_to_host"),
        (
            "ReadHostClipboard",
            "xenia.clipboard.read",
            "host_to_viewer",
        ),
        (
            "WriteHostClipboard",
            "xenia.clipboard.write",
            "viewer_to_host",
        ),
        ("SendFileToViewer", "xenia.file.send", "host_to_viewer"),
        (
            "ReceiveFileFromViewer",
            "xenia.file.receive",
            "viewer_to_host",
        ),
    ];

    let routes = manifest["data_plane_routes"]
        .as_array()
        .expect("data_plane_routes must be an array");
    assert_eq!(
        routes.len(),
        expected.len(),
        "all eight M1 lanes must be present"
    );

    let mut route_ids = BTreeSet::new();
    let mut action_ids = BTreeSet::new();
    for (route, (lane, action_id, direction)) in routes.iter().zip(expected) {
        assert_eq!(route["lane"].as_str(), Some(lane));
        assert_eq!(route["action_id"].as_str(), Some(action_id));
        assert_eq!(route["direction"].as_str(), Some(direction));
        assert!(
            route_ids.insert(route["route_id"].as_str().unwrap().to_owned()),
            "route IDs must be unique"
        );
        assert!(
            action_ids.insert(action_id),
            "delegated action IDs must be unique"
        );
        let action_mapping = format!("Self::{lane} => \"{action_id}\"");
        assert!(
            M1_SESSION.contains(action_mapping.as_str()),
            "M1Permission::action_id must agree with the manifest for {lane}"
        );
        assert!(
            M1_SESSION.contains(&format!("M1Permission::{lane}")),
            "permission variant {lane} must exist in the M1 core"
        );
    }

    assert_eq!(action_ids.len(), 8);
}

#[test]
fn every_manifest_source_check_resolves_and_preserves_gate_before_effect_order() {
    let manifest = manifest();
    let checks = manifest["source_checks"]
        .as_array()
        .expect("source_checks must be an array");
    assert!(
        !checks.is_empty(),
        "the source inventory needs executable source checks"
    );

    let known_routes: BTreeSet<String> = manifest["data_plane_routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| route["route_id"].as_str().unwrap().to_owned())
        .collect();

    for check in checks {
        let route_id = check["route_id"]
            .as_str()
            .expect("source check must identify a route");
        assert!(
            known_routes.contains(route_id),
            "source check refers to an unknown route: {route_id}"
        );
        let path = check["source"]
            .as_str()
            .expect("source check must identify a source file");
        let source_text = source(path);

        for token in check["must_exist"]
            .as_array()
            .expect("must_exist must be an array")
        {
            let token = token.as_str().unwrap();
            assert!(
                source_text.contains(token),
                "{route_id}: source {path} no longer contains '{token}'"
            );
        }

        for ordered in check["ordered"]
            .as_array()
            .expect("ordered must be an array")
        {
            let gate = ordered["gate"].as_str().unwrap();
            let effect = ordered["effect"].as_str().unwrap();
            let occurrence = ordered["occurrence"].as_u64().unwrap() as usize;
            assert_ordered_occurrence(route_id, source_text, gate, effect, occurrence);
        }
    }

    let checked_routes: BTreeSet<String> = checks
        .iter()
        .map(|check| check["route_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        checked_routes, known_routes,
        "every data-plane route must have at least one source check"
    );
}

#[test]
fn control_plane_routes_are_separate_and_source_backed() {
    let manifest = manifest();
    let surfaces = manifest["control_plane_surfaces"]
        .as_array()
        .expect("control_plane_surfaces must be an array");
    assert_eq!(surfaces.len(), 6);

    assert!(CONSENT_SERVER.contains("ConsentServer"));
    assert!(CONSENT_SERVER.contains("apply_consent_decision"));
    assert!(SEALED_OPERATOR.contains("serve_sealed_operator_channel"));

    for surface in surfaces {
        let id = surface["surface_id"].as_str().unwrap();
        match id {
            "operator.consent_socket.v1" => {
                let implementation = surface["implementation"].as_str().unwrap();
                assert!(implementation.contains("consent_server.rs"));
                for action in surface["actions"].as_array().unwrap() {
                    let action = action.as_str().unwrap();
                    assert!(
                        CONSENT_SERVER.contains(action),
                        "consent action missing from source: {action}"
                    );
                }
            }
            "operator.sealed_channel.v1" => {
                assert!(SEALED_OPERATOR.contains("serve_sealed_operator_channel"));
                for required in ["authenticated", "rekey", "revocations"] {
                    assert!(SEALED_OPERATOR.contains(required));
                }
            }
            "admin.http.v1" => {
                for route in surface["routes"].as_array().unwrap() {
                    let route = route.as_str().unwrap();
                    let route_literal = format!("\"{route}\"");
                    assert!(
                        OPERATOR_HTTP.contains(route_literal.as_str()),
                        "admin HTTP route missing from router source: {route}"
                    );
                }
            }
            "admin.websocket.v1" => {
                for route in surface["routes"].as_array().unwrap() {
                    let route = route.as_str().unwrap();
                    let route_literal = format!("\"{route}\"");
                    assert!(
                        MAIN.contains(route_literal.as_str()),
                        "admin websocket route missing from daemon source: {route}"
                    );
                }
            }
            "data_session_transport.v1" => {
                for transport in surface["transports"].as_array().unwrap() {
                    let transport = transport.as_str().unwrap();
                    let enum_variant = match transport {
                        "tcp" => "TransportChoice::Tcp",
                        "websocket" => "TransportChoice::Ws",
                        "quic" => "TransportChoice::Quic",
                        "auto" => "TransportChoice::Auto",
                        other => panic!("unrecognized manifest transport: {other}"),
                    };
                    assert!(MAIN.contains(enum_variant));
                }
            }
            "file_transfer_dispatch.v1" => {
                for message_type in surface["message_types"].as_array().unwrap() {
                    let message_type = message_type.as_str().unwrap();
                    assert!(
                        FILE_TRANSFER.contains(&format!("FileTransferMessage::{message_type}")),
                        "file-transfer message variant missing: {message_type}"
                    );
                }
            }
            other => panic!("unrecognized control-plane surface: {other}"),
        }
    }
}

#[test]
fn operator_revocation_finalizer_runs_after_send_loop_errors_are_captured() {
    let capture = MAIN
        .find("let send_loop_result: Result<(), Box<dyn std::error::Error>> = async")
        .expect("send loop must be captured as a result so `?` cannot bypass teardown");
    let finalizer_call = MAIN
        .find("finalize_m1_send_loop(&revoked, &m1_runtime, send_loop_result).await?")
        .expect("normal and error exits must converge on the revocation finalizer");
    let finalizer_fn = MAIN
        .find("async fn finalize_m1_send_loop(")
        .expect("the send-loop finalizer implementation must remain present");
    let append_fn = MAIN
        .find("async fn append_operator_revocation_if_observed(")
        .expect("operator revocation append helper must remain present");
    assert!(
        capture < finalizer_call && finalizer_call < finalizer_fn,
        "the finalizer call must follow result capture and precede its implementation"
    );
    assert!(
        finalizer_fn < append_fn,
        "the finalizer implementation must precede the append helper implementation"
    );
    assert!(
        MAIN[finalizer_fn..append_fn].contains("append_operator_revocation_if_observed"),
        "the finalizer must invoke the idempotent append helper"
    );

    let ensure = M1_RUNTIME
        .find("pub(crate) fn ensure_revocation_recorded(")
        .expect("runtime must expose retryable revocation transcript append");
    let ensure_body = &M1_RUNTIME[ensure..];
    assert!(
        ensure_body.find("self.flush_new_audit_events()").is_some(),
        "retryable revocation append must flush pending audit entries"
    );
    assert!(MAIN.contains("operator_revocation_is_appended_when_send_loop_returns_error"));
}
