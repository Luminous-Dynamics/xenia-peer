use serde_json::{Value, json};
use std::{
    collections::HashSet,
    env,
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const HARNESS_VERSION: &str = "0.1.0";
const PROFILE_SCHEMA: &str = "xenia-benchmark-profile/v0.1";
const RUN_SCHEMA: &str = "xenia-benchmark-run/v1";

type AppResult<T> = Result<T, Box<dyn Error>>;

fn app_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xenia-bench: {error}");
        std::process::exit(2);
    }
}

fn run() -> AppResult<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Err(app_error("missing command"));
    };

    match command.as_str() {
        "validate-profile" => {
            let path = args
                .next()
                .ok_or_else(|| app_error("missing profile path"))?;
            reject_extra(args)?;
            let bytes = fs::read(&path)?;
            let profile: Value = serde_json::from_slice(&bytes)?;
            validate_profile(&profile)?;
            let digest = sha256_file(Path::new(&path))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "validation": "VALID",
                    "schema_version": PROFILE_SCHEMA,
                    "profile_sha256": digest,
                    "network_profiles": profile["network_profiles"].as_array().map_or(0, Vec::len),
                    "measurement": "not_performed"
                }))?
            );
            Ok(())
        }
        "prepare-run" => {
            let options = parse_options(args)?;
            let profile_path = required_option(&options, "--profile")?;
            let profile_id = required_option(&options, "--profile-id")?;
            let repo = PathBuf::from(options.get("--repo").map(String::as_str).unwrap_or("."));
            let output = PathBuf::from(required_option(&options, "--out")?);
            let host_label = options.get("--host-label").cloned();

            let profile_bytes = fs::read(&profile_path)?;
            let profile: Value = serde_json::from_slice(&profile_bytes)?;
            validate_profile(&profile)?;
            let selected = find_profile(&profile, &profile_id)?;
            let profile_digest = sha256_file(Path::new(&profile_path))?;
            let source = git_snapshot(&repo);
            let host = host_snapshot(host_label);

            let mut blockers = vec![
                "No Xenia capture-to-display / input-to-photon measurement adapter is registered; this command prepares an evidence packet only.".to_string(),
            ];
            if source["commit_sha"].is_null() {
                blockers.push(
                    "Could not identify an exact Git commit for the supplied repository path."
                        .to_string(),
                );
            }
            if source["dirty_tree"] != Value::Bool(false) {
                blockers.push(
                    "The source checkout is dirty or its cleanliness could not be established."
                        .to_string(),
                );
            }

            let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
            let commit_short = source["commit_sha"]
                .as_str()
                .and_then(|s| s.get(..12))
                .unwrap_or("unknown");
            let run_id = format!("{profile_id}-{now_ms}-{commit_short}");
            let required = required_measurements(&profile_id)?;

            let packet = json!({
                "schema_version": RUN_SCHEMA,
                "run_id": run_id,
                "harness_version": HARNESS_VERSION,
                "generated_unix_ms": now_ms,
                "qualification_scope": "PERFORMANCE_PROFILE_ONLY",
                "result_state": "BLOCKED",
                "profile_id": profile_id,
                "profile_sha256": profile_digest,
                "profile_configuration": selected,
                "source": source,
                "host": host,
                "required_measurements": required,
                "measurement_adapter": {
                    "id": "none",
                    "state": "NOT_CONFIGURED"
                },
                "sample_count": null,
                "measurements": null,
                "threshold_checks": [],
                "artifacts": [],
                "blockers": blockers
            });

            let rendered = serde_json::to_vec_pretty(&packet)?;
            write_new_file(&output, &rendered)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "result_state": "BLOCKED",
                    "run_id": run_id,
                    "output": output.display().to_string(),
                    "profile_sha256": profile_digest,
                    "required_measurements": required,
                    "blockers": blockers
                }))?
            );
            Ok(())
        }
        "check-run" => {
            let path = args
                .next()
                .ok_or_else(|| app_error("missing run packet path"))?;
            reject_extra(args)?;
            let bytes = fs::read(path)?;
            let packet: Value = serde_json::from_slice(&bytes)?;
            validate_run_packet(&packet)?;
            let state = packet["result_state"].as_str().unwrap_or("UNKNOWN");
            let result = json!({
                "validation": "CONSISTENT",
                "result_state": state,
                "qualification_scope": packet["qualification_scope"],
                "note": "Consistency check only; this tool does not independently attest measurements or artifact authorship."
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
            if state == "FAIL" {
                std::process::exit(1);
            }
            Ok(())
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Err(app_error(format!("unknown command: {command}")))
        }
    }
}

fn print_usage() {
    eprintln!(
        "Xenia benchmark evidence tool\n\
         \n\
         Commands:\n\
           validate-profile <profile.json>\n\
           prepare-run --profile <profile.json> --profile-id <id> --repo <path> --out <run.json> [--host-label <label>]\n\
           check-run <run.json>\n"
    );
}

fn reject_extra(mut args: impl Iterator<Item = String>) -> AppResult<()> {
    if let Some(extra) = args.next() {
        return Err(app_error(format!("unexpected argument: {extra}")));
    }
    Ok(())
}

fn parse_options(
    args: impl Iterator<Item = String>,
) -> AppResult<std::collections::BTreeMap<String, String>> {
    let values: Vec<String> = args.collect();
    if values.len() % 2 != 0 {
        return Err(app_error("options must be supplied as --name value pairs"));
    }
    let mut options = std::collections::BTreeMap::new();
    let mut iter = values.into_iter();
    while let Some(key) = iter.next() {
        if !key.starts_with("--") {
            return Err(app_error(format!("expected an option, got {key}")));
        }
        let value = iter
            .next()
            .ok_or_else(|| app_error(format!("missing value for {key}")))?;
        if options.insert(key.clone(), value).is_some() {
            return Err(app_error(format!("duplicate option: {key}")));
        }
    }
    for key in options.keys() {
        if ![
            "--profile",
            "--profile-id",
            "--repo",
            "--out",
            "--host-label",
        ]
        .contains(&key.as_str())
        {
            return Err(app_error(format!("unknown option: {key}")));
        }
    }
    Ok(options)
}

fn required_option<'a>(
    options: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> AppResult<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| app_error(format!("required option {key} is missing")))
}

fn validate_profile(profile: &Value) -> AppResult<()> {
    if profile["schema_version"].as_str() != Some(PROFILE_SCHEMA) {
        return Err(app_error(format!(
            "expected schema_version {PROFILE_SCHEMA}"
        )));
    }
    if profile["status"].as_str() != Some("proposed_targets_not_measurements") {
        return Err(app_error(
            "profile status must explicitly identify proposed, unmeasured targets",
        ));
    }

    let profiles = profile["network_profiles"]
        .as_array()
        .ok_or_else(|| app_error("network_profiles must be an array"))?;
    if profiles.is_empty() {
        return Err(app_error("network_profiles must not be empty"));
    }

    let mut ids = HashSet::new();
    for item in profiles {
        let id = item["id"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| app_error("each network profile needs a non-empty id"))?;
        if !ids.insert(id.to_string()) {
            return Err(app_error(format!("duplicate network profile id: {id}")));
        }
        if item["kind"].as_str().is_none() {
            return Err(app_error(format!("profile {id} has no kind")));
        }
        let network = &item["network"];
        let rtt = &network["rtt_ms"];
        if !rtt["min"].is_number() || !rtt["max"].is_number() {
            return Err(app_error(format!("profile {id} needs numeric RTT bounds")));
        }
        if rtt["min"].as_f64().unwrap_or(f64::NAN) > rtt["max"].as_f64().unwrap_or(f64::NAN) {
            return Err(app_error(format!("profile {id} has inverted RTT bounds")));
        }
        let loss = network["packet_loss_fraction"]
            .as_f64()
            .ok_or_else(|| app_error(format!("profile {id} needs packet_loss_fraction")))?;
        if !(0.0..=1.0).contains(&loss) {
            return Err(app_error(format!(
                "profile {id} packet loss must be in [0, 1]"
            )));
        }
        let _ = required_measurements(id)?;
    }

    if profile["corpus"].as_array().is_none_or(Vec::is_empty) {
        return Err(app_error("corpus must be a non-empty array"));
    }
    if profile["security_and_correctness_targets"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        return Err(app_error(
            "security_and_correctness_targets must be a non-empty array",
        ));
    }

    let states = profile["evidence_contract"]["allowed_result_states"]
        .as_array()
        .ok_or_else(|| app_error("allowed_result_states must be an array"))?;
    for required in ["PASS", "FAIL", "BLOCKED", "ENVIRONMENT_FAILURE"] {
        if !states.iter().any(|v| v.as_str() == Some(required)) {
            return Err(app_error(format!(
                "evidence contract omits state {required}"
            )));
        }
    }
    if profile["evidence_contract"]["missing_measurements_are_not_zero"] != Value::Bool(true)
        || profile["evidence_contract"]["queued_skipped_cancelled_or_stale_ci_is_not_pass"]
            != Value::Bool(true)
    {
        return Err(app_error(
            "evidence contract must preserve fail-closed missing/CI semantics",
        ));
    }
    Ok(())
}

fn find_profile<'a>(profile: &'a Value, id: &str) -> AppResult<&'a Value> {
    profile["network_profiles"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"].as_str() == Some(id)))
        .ok_or_else(|| app_error(format!("profile id not found: {id}")))
}

fn required_measurements(profile_id: &str) -> AppResult<Vec<&'static str>> {
    let names = match profile_id {
        "lan_interactive" => vec![
            "displayed_fps",
            "frame_age_p95_ms",
            "input_to_photon_p95_ms",
            "avg_bitrate_mbps",
            "visual_quality_acceptable",
            "direct_connect_to_first_authorized_frame_s",
            "post_approval_to_first_authorized_frame_s",
            "queue_high_water",
            "queue_capacity",
            "cpu_percent",
            "rss_bytes",
        ],
        "regional_interactive" => vec![
            "displayed_fps",
            "input_to_photon_p95_ms",
            "control_message_delivery_p95_ms",
            "avg_bitrate_mbps",
            "visual_quality_acceptable",
            "queue_high_water",
            "queue_capacity",
            "cpu_percent",
            "rss_bytes",
        ],
        "degraded_wan" => vec![
            "displayed_fps",
            "control_message_delivery_p95_ms",
            "avg_bitrate_mbps",
            "visual_quality_acceptable",
            "stale_video_dropped_count",
            "queue_high_water",
            "queue_capacity",
            "reconnect_recovery_ms",
            "queue_age_p95_ms",
            "control_message_p95_under_media_saturation_ms",
            "control_message_p95_under_tcp_cross_traffic_ms",
            "adaptation_convergence_seconds",
            "tcp_goodput_vs_fq_reference_ratio",
            "cpu_percent",
            "rss_bytes",
        ],
        "constrained_link" => vec![
            "displayed_fps",
            "control_message_delivery_p95_ms",
            "visual_quality_acceptable",
            "stale_video_dropped_count",
            "queue_high_water",
            "queue_capacity",
            "reconnect_recovery_ms",
            "cpu_percent",
            "rss_bytes",
        ],
        "long_session_soak" => vec![
            "duration_hours",
            "crash_count",
            "rss_growth_after_warmup_percent",
            "unbounded_queue_count",
            "nonce_or_replay_invariant_violations",
            "authority_drift_count",
        ],
        _ => {
            return Err(app_error(format!(
                "no measurement contract for profile {profile_id}"
            )));
        }
    };
    Ok(names)
}

fn validate_run_packet(packet: &Value) -> AppResult<()> {
    if packet["schema_version"].as_str() != Some(RUN_SCHEMA) {
        return Err(app_error(format!("expected schema_version {RUN_SCHEMA}")));
    }
    if packet["qualification_scope"].as_str() != Some("PERFORMANCE_PROFILE_ONLY") {
        return Err(app_error(
            "run packet must be scoped to one performance profile",
        ));
    }
    let state = packet["result_state"]
        .as_str()
        .ok_or_else(|| app_error("result_state is missing"))?;
    if !["PASS", "FAIL", "BLOCKED", "ENVIRONMENT_FAILURE"].contains(&state) {
        return Err(app_error(format!("invalid result_state: {state}")));
    }
    let profile_id = packet["profile_id"]
        .as_str()
        .ok_or_else(|| app_error("profile_id is missing"))?;
    let required = required_measurements(profile_id)?;
    let supplied: Vec<&str> = packet["required_measurements"]
        .as_array()
        .ok_or_else(|| app_error("required_measurements must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if supplied != required {
        return Err(app_error(
            "required_measurements does not match the runner's canonical contract",
        ));
    }

    if state != "PASS" {
        return Ok(());
    }

    let digest = packet["profile_sha256"].as_str().unwrap_or_default();
    if !is_hex_digest(digest, 64) {
        return Err(app_error("PASS requires a 64-character profile SHA-256"));
    }
    let commit = packet["source"]["commit_sha"].as_str().unwrap_or_default();
    if !is_hex_digest(commit, 40) {
        return Err(app_error(
            "PASS requires an exact 40-character Git commit SHA",
        ));
    }
    if packet["source"]["dirty_tree"] != Value::Bool(false) {
        return Err(app_error(
            "PASS requires a source snapshot with a clean working tree",
        ));
    }
    if packet["measurement_adapter"]["state"].as_str() != Some("EXECUTED")
        || packet["measurement_adapter"]["id"]
            .as_str()
            .is_none_or(|s| s == "none")
    {
        return Err(app_error(
            "PASS requires an identified, executed measurement adapter",
        ));
    }
    if packet["sample_count"].as_u64().unwrap_or(0) < 100 {
        return Err(app_error("PASS requires at least 100 measured samples"));
    }

    let measurements = packet["measurements"]
        .as_object()
        .ok_or_else(|| app_error("PASS requires a measurements object"))?;
    for name in &required {
        let value = measurements
            .get(*name)
            .ok_or_else(|| app_error(format!("PASS is missing measurement {name}")))?;
        if !(value.is_number() || value.is_boolean()) {
            return Err(app_error(format!(
                "measurement {name} must be numeric or boolean"
            )));
        }
    }

    let artifacts = packet["artifacts"]
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or_else(|| app_error("PASS requires at least one raw evidence artifact"))?;
    for artifact in artifacts {
        let hash = artifact["sha256"].as_str().unwrap_or_default();
        if !is_hex_digest(hash, 64) || artifact["path"].as_str().is_none() {
            return Err(app_error(
                "each PASS artifact requires a path and SHA-256 digest",
            ));
        }
    }
    validate_physical_latency_evidence(packet, artifacts)?;

    let checks = evaluate_thresholds(profile_id, &Value::Object(measurements.clone()))?;
    if checks
        .iter()
        .any(|item| item["passed"] != Value::Bool(true))
    {
        let failed: Vec<String> = checks
            .iter()
            .filter(|item| item["passed"] != Value::Bool(true))
            .filter_map(|item| item["metric"].as_str().map(str::to_string))
            .collect();
        return Err(app_error(format!(
            "result claims PASS but profile thresholds failed: {}",
            failed.join(", ")
        )));
    }
    Ok(())
}

fn validate_physical_latency_evidence(packet: &Value, artifacts: &[Value]) -> AppResult<()> {
    let profile_id = packet["profile_id"].as_str().unwrap_or_default();
    let required = required_measurements(profile_id)?;
    if !required.contains(&"input_to_photon_p95_ms") {
        return Ok(());
    }

    let evidence = &packet["latency_measurement"];
    let method = evidence["method"]
        .as_str()
        .ok_or_else(|| app_error("input-to-photon PASS requires a physical latency instrument"))?;
    if evidence["calibrated"] != Value::Bool(true) {
        return Err(app_error("physical latency instrument must have a current calibration"));
    }
    if evidence["event_id_join_verified"] != Value::Bool(true) {
        return Err(app_error("physical latency evidence must bind each sensor transition to its input event ID"));
    }
    let trials = evidence["sample_count"]
        .as_u64()
        .ok_or_else(|| app_error("physical latency evidence is missing sample_count"))?;
    if trials < 300 {
        return Err(app_error("physical input-to-photon PASS requires at least 300 valid trials"));
    }
    if evidence["instrument_id"].as_str().is_none_or(|s| s.trim().is_empty()) {
        return Err(app_error("physical latency evidence requires an instrument identifier"));
    }
    if !matches!(
        evidence["sensor_position"].as_str(),
        Some("top" | "centre" | "bottom")
    ) {
        return Err(app_error("physical latency evidence requires sensor_position top, centre or bottom"));
    }

    match method {
        "photodiode" => {
            let resolution = evidence["clock_resolution_ns"]
                .as_u64()
                .ok_or_else(|| app_error("photodiode evidence requires clock_resolution_ns"))?;
            if resolution > 1_000 {
                return Err(app_error("photodiode timer resolution must be 1000 ns or better"));
            }
            let bandwidth = evidence["sensor_bandwidth_hz"]
                .as_u64()
                .ok_or_else(|| app_error("photodiode evidence requires sensor_bandwidth_hz"))?;
            if bandwidth < 10_000 {
                return Err(app_error("photodiode sensor bandwidth must be at least 10 kHz"));
            }
        }
        "high_speed_camera" => {
            let fps = evidence["frame_rate_fps"]
                .as_u64()
                .ok_or_else(|| app_error("high-speed camera evidence requires frame_rate_fps"))?;
            if fps < 1_000 {
                return Err(app_error("high-speed camera evidence requires at least 1000 fps"));
            }
        }
        _ => return Err(app_error("physical latency method must be photodiode or high_speed_camera")),
    }

    for (role, digest_key) in [
        ("physical_latency_trace", "raw_trace_sha256"),
        ("instrument_calibration", "calibration_sha256"),
    ] {
        let expected = evidence[digest_key].as_str().unwrap_or_default();
        if !is_hex_digest(expected, 64) {
            return Err(app_error(format!("physical latency evidence requires {digest_key}")));
        }
        let bound = artifacts.iter().any(|artifact| {
            artifact["role"].as_str() == Some(role)
                && artifact["sha256"].as_str() == Some(expected)
        });
        if !bound {
            return Err(app_error(format!(
                "physical latency {role} digest must bind to a PASS evidence artifact"
            )));
        }
    }
    Ok(())
}

fn evaluate_thresholds(profile_id: &str, measurements: &Value) -> AppResult<Vec<Value>> {
    let mut checks = Vec::new();
    match profile_id {
        "lan_interactive" => {
            numeric_check(&mut checks, measurements, "displayed_fps", ">=", 57.0)?;
            numeric_check(&mut checks, measurements, "frame_age_p95_ms", "<=", 60.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "input_to_photon_p95_ms",
                "<=",
                80.0,
            )?;
            numeric_check(&mut checks, measurements, "avg_bitrate_mbps", "<=", 15.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "direct_connect_to_first_authorized_frame_s",
                "<=",
                5.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "post_approval_to_first_authorized_frame_s",
                "<=",
                1.0,
            )?;
            bool_check(&mut checks, measurements, "visual_quality_acceptable", true)?;
            bounded_queue_check(&mut checks, measurements)?;
        }
        "regional_interactive" => {
            numeric_check(&mut checks, measurements, "displayed_fps", ">=", 57.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "input_to_photon_p95_ms",
                "<=",
                120.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "control_message_delivery_p95_ms",
                "<=",
                150.0,
            )?;
            bool_check(&mut checks, measurements, "visual_quality_acceptable", true)?;
            bounded_queue_check(&mut checks, measurements)?;
        }
        "degraded_wan" => {
            numeric_check(&mut checks, measurements, "displayed_fps", ">=", 20.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "control_message_delivery_p95_ms",
                "<=",
                250.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "control_message_p95_under_media_saturation_ms",
                "<=",
                250.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "control_message_p95_under_tcp_cross_traffic_ms",
                "<=",
                250.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "adaptation_convergence_seconds",
                "<=",
                2.0,
            )?;
            numeric_check(&mut checks, measurements, "queue_age_p95_ms", "<=", 100.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "tcp_goodput_vs_fq_reference_ratio",
                ">=",
                0.8,
            )?;
            bool_check(&mut checks, measurements, "visual_quality_acceptable", true)?;
            bounded_queue_check(&mut checks, measurements)?;
        }
        "constrained_link" => {
            numeric_check(&mut checks, measurements, "displayed_fps", ">=", 8.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "control_message_delivery_p95_ms",
                "<=",
                300.0,
            )?;
            bool_check(&mut checks, measurements, "visual_quality_acceptable", true)?;
            bounded_queue_check(&mut checks, measurements)?;
        }
        "long_session_soak" => {
            numeric_check(&mut checks, measurements, "duration_hours", ">=", 24.0)?;
            numeric_check(&mut checks, measurements, "crash_count", "==", 0.0)?;
            numeric_check(
                &mut checks,
                measurements,
                "rss_growth_after_warmup_percent",
                "<=",
                5.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "unbounded_queue_count",
                "==",
                0.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "nonce_or_replay_invariant_violations",
                "==",
                0.0,
            )?;
            numeric_check(
                &mut checks,
                measurements,
                "authority_drift_count",
                "==",
                0.0,
            )?;
        }
        _ => {
            return Err(app_error(format!(
                "no threshold contract for profile {profile_id}"
            )));
        }
    }
    Ok(checks)
}

fn numeric_check(
    checks: &mut Vec<Value>,
    measurements: &Value,
    metric: &str,
    operator: &str,
    target: f64,
) -> AppResult<()> {
    let actual = measurements[metric]
        .as_f64()
        .ok_or_else(|| app_error(format!("missing numeric measurement {metric}")))?;
    let passed = match operator {
        ">=" => actual >= target,
        "<=" => actual <= target,
        "==" => (actual - target).abs() <= f64::EPSILON,
        _ => return Err(app_error(format!("unsupported operator {operator}"))),
    };
    checks.push(json!({
        "metric": metric,
        "operator": operator,
        "target": target,
        "actual": actual,
        "passed": passed
    }));
    Ok(())
}

fn bool_check(
    checks: &mut Vec<Value>,
    measurements: &Value,
    metric: &str,
    target: bool,
) -> AppResult<()> {
    let actual = measurements[metric]
        .as_bool()
        .ok_or_else(|| app_error(format!("missing boolean measurement {metric}")))?;
    checks.push(json!({
        "metric": metric,
        "operator": "==",
        "target": target,
        "actual": actual,
        "passed": actual == target
    }));
    Ok(())
}

fn bounded_queue_check(checks: &mut Vec<Value>, measurements: &Value) -> AppResult<()> {
    let high = measurements["queue_high_water"]
        .as_u64()
        .ok_or_else(|| app_error("missing queue_high_water"))?;
    let capacity = measurements["queue_capacity"]
        .as_u64()
        .ok_or_else(|| app_error("missing queue_capacity"))?;
    checks.push(json!({
        "metric": "queue_high_water",
        "operator": "<=",
        "target": capacity,
        "actual": high,
        "passed": high <= capacity && capacity > 0
    }));
    Ok(())
}

fn is_hex_digest(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn git_snapshot(repo: &Path) -> Value {
    let commit = command_output(
        "git",
        &[
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("HEAD"),
        ],
    );
    let status = command_output(
        "git",
        &[
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("status"),
            OsStr::new("--porcelain"),
            OsStr::new("--untracked-files=all"),
        ],
    );
    let branch = command_output(
        "git",
        &[
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("branch"),
            OsStr::new("--show-current"),
        ],
    );
    let dirty = status.as_ref().map(|s| !s.trim().is_empty());
    let changed_count = status
        .as_ref()
        .map(|s| s.lines().filter(|line| !line.trim().is_empty()).count());
    json!({
        "repository_path": repo.display().to_string(),
        "commit_sha": commit.map(|s| s.trim().to_string()),
        "branch": branch.map(|s| s.trim().to_string()),
        "dirty_tree": dirty,
        "changed_path_count": changed_count,
        "status_semantics": "Only a clean, exact commit can qualify a PASS result."
    })
}

fn host_snapshot(label: Option<String>) -> Value {
    let os_release = fs::read_to_string("/etc/os-release").ok();
    let kernel = command_text("uname", &["-srmo"]);
    let cpu = command_text("lscpu", &[]);
    let gpu = command_text(
        "nvidia-smi",
        &[
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader",
        ],
    );
    let rustc = command_text("rustc", &["--version"]);
    let cargo = command_text("cargo", &["--version"]);
    let tools = [
        "xenia-peer",
        "xenia-viewer",
        "ffmpeg",
        "iperf3",
        "tc",
        "vainfo",
        "nvidia-smi",
    ];
    let available_tools: Vec<&str> = tools
        .iter()
        .copied()
        .filter(|tool| executable_in_path(tool))
        .collect();

    json!({
        "label": label,
        "os": env::consts::OS,
        "architecture": env::consts::ARCH,
        "kernel": kernel,
        "os_release": os_release.map(|s| s.chars().take(3000).collect::<String>()),
        "cpu_summary": cpu.map(|s| s.chars().take(5000).collect::<String>()),
        "nvidia_gpu_summary": gpu,
        "rustc": rustc,
        "cargo": cargo,
        "available_tools": available_tools,
        "privacy": "No hostname, username, IP address, screen contents or input events are collected."
    })
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn command_output(program: &str, args: &[&OsStr]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn executable_in_path(program: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| {
            let path = dir.join(program);
            if path.is_file() {
                return true;
            }
            #[cfg(windows)]
            {
                ["exe", "cmd", "bat"]
                    .iter()
                    .any(|ext| dir.join(format!("{program}.{ext}")).is_file())
            }
            #[cfg(not(windows))]
            {
                false
            }
        })
}

fn sha256_file(path: &Path) -> AppResult<String> {
    #[cfg(windows)]
    let candidates: Vec<(&str, Vec<&OsStr>)> = vec![(
        "certutil",
        vec![
            OsStr::new("-hashfile"),
            path.as_os_str(),
            OsStr::new("SHA256"),
        ],
    )];
    #[cfg(not(windows))]
    let candidates: Vec<(&str, Vec<&OsStr>)> = vec![
        ("sha256sum", vec![path.as_os_str()]),
        (
            "shasum",
            vec![OsStr::new("-a"), OsStr::new("256"), path.as_os_str()],
        ),
    ];

    for (program, args) in candidates {
        let output = match Command::new(program).args(&args).output() {
            Ok(output) if output.status.success() => output,
            _ => continue,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        for token in text.split_whitespace() {
            let candidate = token.trim_matches(|c: char| !c.is_ascii_hexdigit());
            if is_hex_digest(candidate, 64) {
                return Ok(candidate.to_ascii_lowercase());
            }
        }
    }
    Err(app_error(
        "no working SHA-256 utility found (need sha256sum, shasum, or certutil)",
    ))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot create {} without overwriting: {error}",
                    path.display()
                ),
            )
        })?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_measurements(profile: &str) -> Value {
        match profile {
            "lan_interactive" => json!({
                "displayed_fps": 60, "frame_age_p95_ms": 45,
                "input_to_photon_p95_ms": 70, "avg_bitrate_mbps": 12,
                "visual_quality_acceptable": true,
                "direct_connect_to_first_authorized_frame_s": 3.0,
                "post_approval_to_first_authorized_frame_s": 0.5,
                "queue_high_water": 2, "queue_capacity": 4,
                "cpu_percent": 30, "rss_bytes": 500000000
            }),
            "regional_interactive" => json!({
                "displayed_fps": 60, "input_to_photon_p95_ms": 110,
                "control_message_delivery_p95_ms": 100,
                "avg_bitrate_mbps": 14, "visual_quality_acceptable": true,
                "queue_high_water": 2, "queue_capacity": 4,
                "cpu_percent": 30, "rss_bytes": 500000000
            }),
            "degraded_wan" => json!({
                "displayed_fps": 25, "control_message_delivery_p95_ms": 220,
                "avg_bitrate_mbps": 8, "visual_quality_acceptable": true,
                "stale_video_dropped_count": 100,
                "queue_high_water": 2, "queue_capacity": 4,
                "reconnect_recovery_ms": 800, "queue_age_p95_ms": 60,
                "control_message_p95_under_media_saturation_ms": 200,
                "control_message_p95_under_tcp_cross_traffic_ms": 220,
                "adaptation_convergence_seconds": 1.5,
                "tcp_goodput_vs_fq_reference_ratio": 0.9,
                "cpu_percent": 40, "rss_bytes": 600000000
            }),
            "constrained_link" => json!({
                "displayed_fps": 10, "control_message_delivery_p95_ms": 280,
                "visual_quality_acceptable": true, "stale_video_dropped_count": 300,
                "queue_high_water": 2, "queue_capacity": 4,
                "reconnect_recovery_ms": 1000, "cpu_percent": 45, "rss_bytes": 600000000
            }),
            "long_session_soak" => json!({
                "duration_hours": 24, "crash_count": 0,
                "rss_growth_after_warmup_percent": 3, "unbounded_queue_count": 0,
                "nonce_or_replay_invariant_violations": 0, "authority_drift_count": 0
            }),
            _ => panic!("unknown profile"),
        }
    }

    #[test]
    fn required_measurement_contracts_exist_for_every_profile() {
        for id in [
            "lan_interactive",
            "regional_interactive",
            "degraded_wan",
            "constrained_link",
            "long_session_soak",
        ] {
            assert!(!required_measurements(id).unwrap().is_empty());
        }
    }

    #[test]
    fn target_profiles_accept_threshold_compliant_synthetic_fixtures() {
        for id in [
            "lan_interactive",
            "regional_interactive",
            "degraded_wan",
            "constrained_link",
            "long_session_soak",
        ] {
            let measurements = minimal_measurements(id);
            let checks = evaluate_thresholds(id, &measurements).unwrap();
            assert!(
                checks
                    .iter()
                    .all(|check| check["passed"] == Value::Bool(true)),
                "fixture for {id} should meet thresholds: {checks:?}"
            );
        }
    }

    #[test]
    fn lan_profile_rejects_input_latency_over_target() {
        let mut measurements = minimal_measurements("lan_interactive");
        measurements["input_to_photon_p95_ms"] = json!(80.01);
        let checks = evaluate_thresholds("lan_interactive", &measurements).unwrap();
        assert!(checks.iter().any(|check| {
            check["metric"] == "input_to_photon_p95_ms" && check["passed"] == Value::Bool(false)
        }));
    }

    #[test]
    fn soak_profile_rejects_any_authority_drift() {
        let mut measurements = minimal_measurements("long_session_soak");
        measurements["authority_drift_count"] = json!(1);
        let checks = evaluate_thresholds("long_session_soak", &measurements).unwrap();
        assert!(checks.iter().any(|check| {
            check["metric"] == "authority_drift_count" && check["passed"] == Value::Bool(false)
        }));
    }

    #[test]
    fn pass_result_requires_physical_latency_evidence_and_raw_artifacts() {
        let mut packet = json!({
            "schema_version": RUN_SCHEMA,
            "qualification_scope": "PERFORMANCE_PROFILE_ONLY",
            "result_state": "PASS",
            "profile_id": "lan_interactive",
            "profile_sha256": "a".repeat(64),
            "source": { "commit_sha": "b".repeat(40), "dirty_tree": false },
            "measurement_adapter": { "id": "test-adapter", "state": "EXECUTED" },
            "sample_count": 1000,
            "required_measurements": required_measurements("lan_interactive").unwrap(),
            "measurements": minimal_measurements("lan_interactive"),
            "latency_measurement": {
                "method": "photodiode",
                "instrument_id": "lab-photodiode-01",
                "sensor_bandwidth_hz": 100000,
                "calibrated": true,
                "event_id_join_verified": true,
                "sample_count": 300,
                "clock_resolution_ns": 1000,
                "sensor_position": "centre",
                "raw_trace_sha256": "d".repeat(64),
                "calibration_sha256": "e".repeat(64)
            },
            "artifacts": [
                { "role": "run_samples", "path": "raw-samples.jsonl", "sha256": "c".repeat(64) },
                { "role": "physical_latency_trace", "path": "latency-trace.csv", "sha256": "d".repeat(64) },
                { "role": "instrument_calibration", "path": "instrument-calibration.json", "sha256": "e".repeat(64) }
            ]
        });
        validate_run_packet(&packet).unwrap();

        packet["latency_measurement"]["sample_count"] = json!(299);
        assert!(validate_run_packet(&packet).is_err());
        packet["latency_measurement"]["sample_count"] = json!(300);

        packet["latency_measurement"]["method"] = json!("high_speed_camera");
        packet["latency_measurement"]["frame_rate_fps"] = json!(240);
        assert!(validate_run_packet(&packet).is_err());
        packet["latency_measurement"]["method"] = json!("photodiode");
        packet["latency_measurement"].as_object_mut().unwrap().remove("frame_rate_fps");

        packet["latency_measurement"]["sensor_bandwidth_hz"] = json!(5000);
        assert!(validate_run_packet(&packet).is_err());
        packet["latency_measurement"]["sensor_bandwidth_hz"] = json!(100000);

        packet["artifacts"] = json!([]);
        assert!(validate_run_packet(&packet).is_err());
        packet["artifacts"] = json!([
            { "role": "run_samples", "path": "raw-samples.jsonl", "sha256": "c".repeat(64) },
            { "role": "physical_latency_trace", "path": "latency-trace.csv", "sha256": "d".repeat(64) },
            { "role": "instrument_calibration", "path": "instrument-calibration.json", "sha256": "e".repeat(64) }
        ]);
        packet["source"]["dirty_tree"] = json!(true);
        assert!(validate_run_packet(&packet).is_err());
    }
}
