use std::collections::HashSet;

use xenia_peer_core::{M1DataDirection, M1Permission};

const ROUTE_INVENTORY: &str = include_str!("../../../docs/security/M1_ROUTE_INVENTORY_V0_1.toml");
const DAEMON_SOURCE: &str = include_str!("../../../apps/xenia-peer/src/main.rs");
const FILE_TRANSFER_SOURCE: &str = include_str!("../../../apps/xenia-peer/src/file_transfer.rs");
const RUNTIME_SOURCE: &str = include_str!("../../../apps/xenia-peer/src/m1_runtime.rs");

fn source_section<'a>(source: &'a str, route: &str, start: &str, end: &str) -> &'a str {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("{route}: missing source section start {start:?}"));
    let tail = &source[start_index..];
    let end_index = tail
        .find(end)
        .unwrap_or_else(|| panic!("{route}: missing source section end {end:?}"));
    &tail[..end_index + end.len()]
}

fn assert_source_order(source: &str, route: &str, markers: &[&str]) {
    let mut cursor = 0;
    for marker in markers {
        let relative = source[cursor..]
            .find(marker)
            .unwrap_or_else(|| panic!("{route}: missing or out-of-order source marker {marker:?}"));
        cursor += relative + marker.len();
    }
}

#[test]
fn route_inventory_is_complete_for_the_declared_eight_lane_census() {
    let manifest: toml::Value =
        toml::from_str(ROUTE_INVENTORY).expect("M1 route inventory must be valid TOML");

    assert_eq!(
        manifest.get("schema").and_then(toml::Value::as_str),
        Some("xenia-m1-route-inventory-v1")
    );
    assert_eq!(
        manifest.get("version").and_then(toml::Value::as_integer),
        Some(1)
    );
    assert_eq!(
        manifest.get("status").and_then(toml::Value::as_str),
        Some("partial_source_census")
    );

    let reviewed_commit = manifest
        .get("reviewed_commit")
        .and_then(toml::Value::as_str)
        .expect("reviewed_commit is required");
    assert!(
        is_git_sha(reviewed_commit),
        "reviewed_commit must be a full Git SHA"
    );

    let source_files = manifest
        .get("source_files")
        .and_then(toml::Value::as_table)
        .expect("source_files table is required");
    assert!(!source_files.is_empty());
    for (name, value) in source_files {
        let source_ref = value
            .as_str()
            .unwrap_or_else(|| panic!("source_files.{name} must be a string"));
        let (path, sha) = source_ref
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("source_files.{name} must be path@sha"));
        assert!(
            !path.is_empty(),
            "source_files.{name} path must not be empty"
        );
        assert!(
            is_git_sha(sha),
            "source_files.{name} must use a full Git SHA"
        );
    }

    let routes = manifest
        .get("routes")
        .and_then(toml::Value::as_array)
        .expect("routes array is required");
    assert_eq!(
        routes.len(),
        M1Permission::ALL.len(),
        "every M1 lane must have exactly one route"
    );

    let mut route_ids = HashSet::new();
    let mut action_ids = HashSet::new();
    let mut permission_names = HashSet::new();

    for permission in M1Permission::ALL {
        let permission_name = format!("{permission:?}");
        assert!(
            permission_names.insert(permission_name.clone()),
            "M1 permission names must be unique"
        );

        let route = routes
            .iter()
            .find(|route| {
                route.get("permission").and_then(toml::Value::as_str)
                    == Some(permission_name.as_str())
            })
            .unwrap_or_else(|| panic!("missing route for M1 permission {permission_name}"));

        let required_fields = [
            "id",
            "effect",
            "entrypoint",
            "source_api",
            "direction",
            "permission",
            "action_id",
            "resource",
            "source_preflight",
            "final_gate",
            "effect_owner",
            "transport_boundary",
            "coverage",
            "negative_bypass_controls",
            "maximum_evidence_claim",
        ];
        for field in required_fields {
            let value = route
                .get(field)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("route for {permission_name} is missing {field}"));
            assert!(
                !value.trim().is_empty(),
                "route for {permission_name} has an empty {field}"
            );
        }

        let id = route["id"].as_str().unwrap();
        assert!(route_ids.insert(id), "duplicate M1 route ID: {id}");

        let action_id = route["action_id"].as_str().unwrap();
        assert_eq!(
            action_id,
            permission.action_id(),
            "route action ID drifted for {permission_name}"
        );
        assert!(
            action_ids.insert(action_id),
            "duplicate M1 action ID: {action_id}"
        );

        let expected_direction = match permission.direction() {
            M1DataDirection::HostToViewer => "host_to_viewer",
            M1DataDirection::ViewerToHost => "viewer_to_host",
        };
        assert_eq!(
            route["direction"].as_str(),
            Some(expected_direction),
            "route direction drifted for {permission_name}"
        );

        assert_eq!(
            route["coverage"].as_str(),
            Some("source_reviewed"),
            "route coverage must remain explicitly source_reviewed"
        );
    }

    let unknown_routes = manifest
        .get("unknown_routes")
        .and_then(toml::Value::as_array)
        .expect("unknown_routes array is required");
    for route in unknown_routes {
        for field in ["id", "status", "description"] {
            let value = route
                .get(field)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("unknown route is missing {field}"));
            assert!(!value.trim().is_empty());
        }
    }

    let has_unimplemented_bypass_control = routes.iter().any(|route| {
        route
            .get("negative_bypass_controls")
            .and_then(toml::Value::as_str)
            == Some("not_yet_implemented")
    });
    if !unknown_routes.is_empty() || has_unimplemented_bypass_control {
        assert_eq!(
            manifest.get("completeness").and_then(toml::Value::as_str),
            Some("indeterminate"),
            "unknown routes or unimplemented bypass controls must prevent a complete claim"
        );
        let qualification = manifest
            .get("qualification")
            .and_then(toml::Value::as_array)
            .and_then(|entries| entries.first())
            .expect("qualification record is required");
        assert_eq!(
            qualification.get("result").and_then(toml::Value::as_str),
            Some("INDETERMINATE"),
            "incomplete route evidence must remain INDETERMINATE"
        );
    }
}

fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
/// Guard the reviewed source ordering against accidental removal or movement
/// of an M1 lane preflight/final check. Each assertion is scoped to the actual
/// match arm or send-loop block, so a gate in a different branch cannot satisfy
/// the test. This is not proof that every platform/plugin/alternate route is
/// inventoried or unreachable; those remain explicitly INDETERMINATE.
#[test]
fn sensitive_source_routes_keep_preflight_and_final_lane_gates_in_order() {
    let runtime_mappings = [
        "preflight_frame_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::StreamFrame)",
        "preflight_telemetry_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::StreamTelemetry)",
        "preflight_audio_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::StreamAudio)",
        "preflight_host_clipboard_read_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::ReadHostClipboard)",
        "preflight_input_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::InjectInput)",
        "preflight_file_send_flow(&self) -> Result<(), M1RuntimeError> {\n        self.preflight_permission(M1Permission::SendFileToViewer)",
    ];
    for mapping in runtime_mappings {
        assert!(
            RUNTIME_SOURCE.contains(mapping),
            "runtime preflight no longer maps to its exact M1 lane: {mapping}"
        );
    }

    let telemetry = source_section(
        DAEMON_SOURCE,
        "telemetry disclosure",
        "if args.telemetry_level != TelemetryLevel::Off",
        "if let Some(audio) = &mut audio",
    );
    assert_source_order(
        telemetry,
        "telemetry disclosure",
        &[
            "preflight_telemetry_flow()",
            "telemetry.poll_samples()",
            "seal_frame(&telemetry_frame)",
            "allow_telemetry_flow()",
            "send_half.send_envelope(&envelope)",
        ],
    );

    let audio = source_section(
        DAEMON_SOURCE,
        "audio disclosure",
        "if let Some(audio) = &mut audio",
        "if args.clipboard != ClipboardMode::Off",
    );
    assert_source_order(
        audio,
        "audio disclosure",
        &[
            "preflight_audio_flow()",
            "audio.next_raw_audio(now_ms())?",
            "seal_frame(&audio_frame)",
            "allow_audio_flow()",
            "send_half.send_envelope(&envelope)",
        ],
    );

    let clipboard = source_section(
        DAEMON_SOURCE,
        "clipboard disclosure",
        "if args.clipboard != ClipboardMode::Off",
        "if let Err(err) = m1_runtime.lock().await.preflight_frame_flow()",
    );
    assert_source_order(
        clipboard,
        "clipboard disclosure",
        &[
            "preflight_host_clipboard_read_flow()",
            "&& let Some(text) = read_host_clipboard_text()",
            "seal_frame(&clipboard_frame)",
            "allow_host_clipboard_read_flow()",
            "send_half.send_envelope(&envelope)",
        ],
    );

    let screen_capture = source_section(
        DAEMON_SOURCE,
        "screen capture admission",
        "if let Err(err) = m1_runtime.lock().await.preflight_frame_flow()",
        "let Some(encoder) = encoder.as_mut()",
    );
    assert_source_order(
        screen_capture,
        "screen capture admission",
        &["preflight_frame_flow()", "capture.capture()"],
    );
    let screen_send = source_section(
        DAEMON_SOURCE,
        "screen frame send",
        "let envelope = session.lock().await.seal_frame(&raw)?",
        "match tokio::time::timeout(send_deadline, send_half.send_envelope(&envelope)).await",
    );
    assert_source_order(
        screen_send,
        "screen frame send",
        &["seal_frame(&raw)", "allow_frame_flow()", "send_half.send_envelope(&envelope)"],
    );

    let input = source_section(
        DAEMON_SOURCE,
        "input injection",
        "if let Err(err) = m1_runtime.lock().await.preflight_input_flow()",
        "match injector.process_events(std::slice::from_ref(&event))",
    );
    assert_source_order(
        input,
        "input injection",
        &[
            "preflight_input_flow()",
            "bincode::deserialize(&input.payload)",
            "allow_input_flow()",
            "injector.process_events(std::slice::from_ref(&event))",
        ],
    );

    let initial_offer = source_section(
        DAEMON_SOURCE,
        "initial file offer",
        "if let Some(path) = &args.send_file {",
        "// Updated by the send loop below",
    );
    assert_source_order(
        initial_offer,
        "initial file offer",
        &[
            "preflight_file_send_flow()",
            "TransferSource::open_file_limited(",
            "seal_file_transfer_message(offer, true)",
            "allow_file_send_flow()",
            "send_half.send_envelope(&envelope)",
        ],
    );

    let incoming_offer = source_section(
        FILE_TRANSFER_SOURCE,
        "incoming file offer",
        "FileTransferMessage::Offer {",
        "FileTransferMessage::Accept { transfer_id } =>",
    );
    assert_source_order(
        incoming_offer,
        "incoming file offer",
        &["allow_file_receive_flow()", "IncomingFileStager::create("],
    );

    let outgoing_chunks = source_section(
        FILE_TRANSFER_SOURCE,
        "outgoing file chunks",
        "FileTransferMessage::Accept { transfer_id } =>",
        "FileTransferMessage::Reject {",
    );
    assert_source_order(
        outgoing_chunks,
        "outgoing file chunks",
        &[
            "preflight_file_send_flow()",
            "transfer.source.next_chunk(FILE_TRANSFER_CHUNK_SIZE)",
            "seal_file_transfer_message(msg, true)",
            "allow_file_send_flow()",
            "send_half.send_envelope(&envelope)",
        ],
    );

    let incoming_chunks = source_section(
        FILE_TRANSFER_SOURCE,
        "incoming file chunks",
        "FileTransferMessage::Chunk {",
        "FileTransferMessage::Complete { transfer_id } =>",
    );
    assert_source_order(
        incoming_chunks,
        "incoming file chunks",
        &["allow_file_receive_flow()", "transfer.stager.append(offset, &data)"],
    );

    let incoming_publication = source_section(
        FILE_TRANSFER_SOURCE,
        "incoming file publication",
        "FileTransferMessage::Complete { transfer_id } =>",
        "FileTransferMessage::Verified {",
    );
    assert_source_order(
        incoming_publication,
        "incoming file publication",
        &["allow_file_receive_flow()", "transfer.stager.finish()"],
    );
}
