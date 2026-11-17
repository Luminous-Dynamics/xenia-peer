use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const HARNESS_VERSION: &str = "0.1.0";
const PROFILE_SCHEMA: &str = "xenia-benchmark-profile/v0.1";
const RUN_SCHEMA: &str = "xenia-benchmark-run/v1";
const I2P_TRACE_SCHEMA: &str = "xenia-i2p-trace/v1";
const I2P_CALIBRATION_SCHEMA: &str = "xenia-i2p-calibration/v1";
const I2P_MIN_VALID_TRIALS: usize = 300;
const I2P_BOOTSTRAP_RESAMPLES: usize = 2_000;

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

            let profile_bytes = fs::read(profile_path)?;
            let profile: Value = serde_json::from_slice(&profile_bytes)?;
            validate_profile(&profile)?;
            let selected = find_profile(&profile, profile_id)?;
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
            let required = required_measurements(profile_id)?;
            let output_dir = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let profile_artifact_name = format!("{run_id}.profile.json");
            let profile_artifact_path = output_dir.join(&profile_artifact_name);
            if output == profile_artifact_path {
                return Err(app_error(
                    "run packet path collides with its embedded profile artifact",
                ));
            }
            write_new_file(&profile_artifact_path, &profile_bytes)?;
            let profile_digest = match sha256_file(&profile_artifact_path) {
                Ok(digest) => digest,
                Err(error) => {
                    let _ = fs::remove_file(&profile_artifact_path);
                    return Err(error);
                }
            };

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
                "artifacts": [{ "role": "qualification_profile", "path": profile_artifact_name, "sha256": profile_digest }],
                "blockers": blockers
            });

            let rendered = serde_json::to_vec_pretty(&packet)?;
            if let Err(error) = write_new_file(&output, &rendered) {
                let _ = fs::remove_file(&profile_artifact_path);
                return Err(error);
            }
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
        "import-i2p" => {
            let options = parse_options(args)?;
            import_i2p(&options)
        }
        "check-run" => {
            let path = args
                .next()
                .ok_or_else(|| app_error("missing run packet path"))?;
            reject_extra(args)?;
            let run_path = PathBuf::from(path);
            let bytes = fs::read(&run_path)?;
            let packet: Value = serde_json::from_slice(&bytes)?;
            validate_run_packet(&packet)?;
            let state = packet["result_state"].as_str().unwrap_or("UNKNOWN");
            let run_dir = run_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if packet["artifacts"].as_array().is_none_or(Vec::is_empty) {
                return Err(app_error(
                    "run packet requires an embedded qualification profile artifact",
                ));
            }
            verify_artifacts_on_disk(&packet, run_dir)?;
            verify_profile_binding(&packet, run_dir)?;
            verify_physical_latency_binding(&packet, run_dir)?;
            let result = json!({
                "validation": "CONSISTENT",
                "result_state": state,
                "qualification_scope": packet["qualification_scope"],
                "note": "Artifact bytes and path containment are checked locally. This does not independently attest measurement correctness, instrument authenticity or artifact authorship."
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
           check-run <run.json>\n\
           import-i2p --run <run.json> --trace <trace.json> --calibration <calibration.json> --out <updated-run.json>\n"
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
    if !values.len().is_multiple_of(2) {
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
            "--run",
            "--trace",
            "--calibration",
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
        if !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        }) {
            return Err(app_error(format!(
                "profile id contains disallowed characters: {id}"
            )));
        }
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

/// Import a physically measured input-to-photon trace into a new, BLOCKED run packet.
///
/// Raw trace and calibration bytes are copied verbatim into digest-named artifacts
/// beside the output packet. Existing input files and the source run packet are
/// never overwritten.
fn import_i2p(options: &std::collections::BTreeMap<String, String>) -> AppResult<()> {
    let run_path = PathBuf::from(required_option(options, "--run")?);
    let trace_path = PathBuf::from(required_option(options, "--trace")?);
    let calibration_path = PathBuf::from(required_option(options, "--calibration")?);
    let output_path = PathBuf::from(required_option(options, "--out")?);

    let run_bytes = fs::read(&run_path)?;
    let trace_bytes = fs::read(&trace_path)?;
    let calibration_bytes = fs::read(&calibration_path)?;
    let mut packet: Value = serde_json::from_slice(&run_bytes)
        .map_err(|error| app_error(format!("run packet is invalid JSON: {error}")))?;
    let trace: Value = serde_json::from_slice(&trace_bytes)
        .map_err(|error| app_error(format!("I2P trace is invalid JSON: {error}")))?;
    let calibration: Value = serde_json::from_slice(&calibration_bytes)
        .map_err(|error| app_error(format!("calibration artifact is invalid JSON: {error}")))?;

    validate_run_packet(&packet)?;
    if packet["result_state"].as_str() != Some("BLOCKED") {
        return Err(app_error(
            "I2P import only accepts a BLOCKED run packet; it never mutates a PASS or FAIL result",
        ));
    }
    let profile_id = packet["profile_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if !required_measurements(&profile_id)?.contains(&"input_to_photon_p95_ms") {
        return Err(app_error(format!(
            "profile {profile_id} does not require physical input-to-photon measurement"
        )));
    }

    let run_dir = run_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let run_dir = fs::canonicalize(run_dir)?;
    verify_artifacts_on_disk(&packet, &run_dir)?;
    verify_profile_binding(&packet, &run_dir)?;

    let run_file = fs::canonicalize(&run_path)?;
    let output_parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output_parent = fs::canonicalize(output_parent)?;
    if output_parent != run_dir {
        return Err(app_error(
            "the output run packet must be written beside the original packet so all relative artifact paths remain contained",
        ));
    }
    let output_name = output_path
        .file_name()
        .ok_or_else(|| app_error("output run packet must have a file name"))?;
    if run_dir.join(output_name) == run_file {
        return Err(app_error(
            "I2P import must write a new run packet; the source packet is immutable",
        ));
    }
    if output_path.exists() {
        return Err(app_error(
            "output run packet already exists; refusing to overwrite",
        ));
    }

    let trace_digest = sha256_file(&trace_path)?;
    let calibration_digest = sha256_file(&calibration_path)?;
    let summary = validate_i2p_trace(
        &trace,
        &calibration,
        &trace_digest,
        &calibration_digest,
        &packet,
    )?;

    let trace_name = format!("physical-i2p-trace-{trace_digest}.json");
    let calibration_name = format!("physical-i2p-calibration-{calibration_digest}.json");
    write_or_verify_artifact_copy(&run_dir.join(&trace_name), &trace_bytes, &trace_digest)?;
    write_or_verify_artifact_copy(
        &run_dir.join(&calibration_name),
        &calibration_bytes,
        &calibration_digest,
    )?;

    let artifacts = packet["artifacts"]
        .as_array_mut()
        .ok_or_else(|| app_error("run packet artifact list is missing"))?;
    if artifacts.iter().any(|artifact| {
        matches!(
            artifact["role"].as_str(),
            Some("physical_latency_trace" | "instrument_calibration")
        )
    }) {
        return Err(app_error(
            "run packet already contains a physical latency trace; create a fresh run packet for a new instrument run",
        ));
    }
    artifacts.push(json!({
        "role": "physical_latency_trace",
        "path": trace_name,
        "sha256": trace_digest
    }));
    artifacts.push(json!({
        "role": "instrument_calibration",
        "path": calibration_name,
        "sha256": calibration_digest
    }));

    let p95_ms = summary["p95_ms"]
        .as_f64()
        .ok_or_else(|| app_error("internal I2P summary has no p95_ms"))?;
    if !packet["measurements"].is_object() {
        packet["measurements"] = json!({});
    }
    packet["measurements"]["input_to_photon_p50_ms"] = summary["p50_ms"].clone();
    packet["measurements"]["input_to_photon_p95_ms"] = json!(p95_ms);
    packet["measurements"]["input_to_photon_p99_ms"] = summary["p99_ms"].clone();
    packet["measurements"]["input_to_photon_max_ms"] = summary["max_ms"].clone();
    packet["measurements"]["input_to_photon_p95_ci95_lower_ms"] =
        summary["p95_ci_95_ms"]["lower"].clone();
    packet["measurements"]["input_to_photon_p95_ci95_upper_ms"] =
        summary["p95_ci_95_ms"]["upper"].clone();
    packet["latency_measurement"] = summary.clone();
    packet["physical_latency_import"] = json!({
        "state": "IMPORTED_PARTIAL_EVIDENCE",
        "trace_sha256": trace_digest,
        "calibration_sha256": calibration_digest,
        "valid_trial_count": summary["valid_trial_count"],
        "rejected_trial_count": summary["rejected_trial_count"]
    });

    // Importing one measurement must not elevate the overall run. The adapter,
    // full sample packet, remaining metrics and profile thresholds still need
    // independent evidence.
    packet["result_state"] = json!("BLOCKED");
    if !packet["blockers"].is_array() {
        packet["blockers"] = json!([]);
    }
    let blockers = packet["blockers"]
        .as_array_mut()
        .ok_or_else(|| app_error("blockers must be an array"))?;
    for blocker in blockers.iter_mut() {
        if blocker.as_str()
            == Some(
                "No Xenia capture-to-display / input-to-photon measurement adapter is registered; this command prepares an evidence packet only.",
            )
        {
            *blocker = json!(
                "No full Xenia performance measurement adapter is registered. A physical I2P trace may be imported separately, but the complete profile remains unmeasured."
            );
        }
    }
    blockers.push(json!("Physical I2P evidence imported. Overall qualification remains BLOCKED until every other required metric and adapter evidence is supplied."));

    let rendered = serde_json::to_vec_pretty(&packet)?;
    write_new_file(&output_path, &rendered)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "import_state": "IMPORTED_PARTIAL_EVIDENCE",
            "result_state": "BLOCKED",
            "profile_id": profile_id,
            "valid_trial_count": summary["valid_trial_count"],
            "rejected_trial_count": summary["rejected_trial_count"],
            "input_to_photon_p50_ms": summary["p50_ms"],
            "input_to_photon_p95_ms": summary["p95_ms"],
            "input_to_photon_p99_ms": summary["p99_ms"],
            "input_to_photon_p95_ci95_ms": summary["p95_ci_95_ms"],
            "output": output_path.display().to_string(),
            "trace_sha256": trace_digest,
            "calibration_sha256": calibration_digest
        }))?
    );
    Ok(())
}

fn write_or_verify_artifact_copy(
    path: &Path,
    bytes: &[u8],
    expected_digest: &str,
) -> AppResult<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(app_error(
                "digest-named evidence artifact must be a regular file, not a symlink or special file",
            ));
        }
        let observed = sha256_file(path)?;
        if !observed.eq_ignore_ascii_case(expected_digest) {
            return Err(app_error(format!(
                "digest-named evidence artifact already exists with different bytes: {}",
                path.display()
            )));
        }
        return Ok(());
    }
    write_new_file(path, bytes)?;
    let observed = sha256_file(path)?;
    if !observed.eq_ignore_ascii_case(expected_digest) {
        let _ = fs::remove_file(path);
        return Err(app_error(
            "copied evidence artifact failed its post-write digest check",
        ));
    }
    Ok(())
}

fn validate_i2p_trace(
    trace: &Value,
    calibration: &Value,
    trace_digest: &str,
    calibration_digest: &str,
    packet: &Value,
) -> AppResult<Value> {
    if trace["schema_version"].as_str() != Some(I2P_TRACE_SCHEMA) {
        return Err(app_error(format!(
            "expected I2P trace schema_version {I2P_TRACE_SCHEMA}"
        )));
    }
    if calibration["schema_version"].as_str() != Some(I2P_CALIBRATION_SCHEMA) {
        return Err(app_error(format!(
            "expected calibration schema_version {I2P_CALIBRATION_SCHEMA}"
        )));
    }
    if !is_hex_digest(trace_digest, 64) || !is_hex_digest(calibration_digest, 64) {
        return Err(app_error(
            "trace and calibration must have verified SHA-256 digests",
        ));
    }
    if trace["calibration_sha256"].as_str() != Some(calibration_digest) {
        return Err(app_error(
            "trace calibration_sha256 does not match the supplied calibration artifact bytes",
        ));
    }

    let run_id = packet["run_id"]
        .as_str()
        .ok_or_else(|| app_error("run packet run_id is missing"))?;
    if trace["run_id"].as_str() != Some(run_id) {
        return Err(app_error(
            "I2P trace run_id does not match the target run packet",
        ));
    }
    let profile_id = packet["profile_id"]
        .as_str()
        .ok_or_else(|| app_error("run packet profile_id is missing"))?;
    if trace["profile_id"].as_str() != Some(profile_id) {
        return Err(app_error(
            "I2P trace profile_id does not match the target run packet",
        ));
    }
    if trace["condition_id"]
        .as_str()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(app_error("I2P trace requires a non-empty condition_id"));
    }

    let measured_at = trace["measurement_unix_ms"]
        .as_u64()
        .ok_or_else(|| app_error("I2P trace requires measurement_unix_ms"))?;
    let instrument = &trace["instrument"];
    let instrument_id = instrument["id"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| app_error("I2P trace requires instrument.id"))?;
    let firmware_version = instrument["firmware_version"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| app_error("I2P trace requires instrument.firmware_version"))?;
    let tool_version = instrument["tool_version"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| app_error("I2P trace requires instrument.tool_version"))?;
    let method = instrument["method"]
        .as_str()
        .ok_or_else(|| app_error("I2P trace requires instrument.method"))?;
    if calibration["instrument_id"].as_str() != Some(instrument_id) {
        return Err(app_error(
            "calibration instrument_id does not match the trace instrument",
        ));
    }
    if calibration["method"].as_str() != Some(method) {
        return Err(app_error(
            "calibration method does not match the trace method",
        ));
    }
    let calibration_id = calibration["calibration_id"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| app_error("calibration requires calibration_id"))?;
    let valid_from = calibration["valid_from_unix_ms"]
        .as_u64()
        .ok_or_else(|| app_error("calibration requires valid_from_unix_ms"))?;
    let valid_until = calibration["valid_until_unix_ms"]
        .as_u64()
        .ok_or_else(|| app_error("calibration requires valid_until_unix_ms"))?;
    if valid_from > valid_until || measured_at < valid_from || measured_at > valid_until {
        return Err(app_error(
            "calibration is expired or not yet valid at the trace measurement time",
        ));
    }
    let calibration_uncertainty = calibration["uncertainty_ns"]
        .as_u64()
        .ok_or_else(|| app_error("calibration requires uncertainty_ns"))?;

    let timebase = &trace["timebase"];
    let clock_source = timebase["clock_source"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| app_error("I2P trace requires timebase.clock_source"))?;
    let counter_frequency_hz = timebase["counter_frequency_hz"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| app_error("timebase.counter_frequency_hz must be a positive integer"))?;
    let clock_uncertainty = timebase["uncertainty_ns"]
        .as_u64()
        .ok_or_else(|| app_error("timebase requires uncertainty_ns"))?;
    let total_uncertainty_ns = clock_uncertainty
        .checked_add(calibration_uncertainty)
        .ok_or_else(|| app_error("combined instrument uncertainty overflows u64"))?;

    let sensor = &trace["sensor"];
    let position = sensor["position"]
        .as_str()
        .filter(|value| matches!(*value, "top" | "centre" | "bottom"))
        .ok_or_else(|| app_error("sensor.position must be top, centre or bottom"))?;
    let clock_resolution_ns = sensor["clock_resolution_ns"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| app_error("sensor.clock_resolution_ns must be a positive integer"))?;
    match method {
        "photodiode" => {
            if clock_resolution_ns > 1_000 {
                return Err(app_error(
                    "photodiode timer resolution must be 1000 ns or better",
                ));
            }
            let bandwidth = sensor["bandwidth_hz"]
                .as_u64()
                .ok_or_else(|| app_error("photodiode trace requires sensor.bandwidth_hz"))?;
            if bandwidth < 10_000 {
                return Err(app_error(
                    "photodiode sensor bandwidth must be at least 10 kHz",
                ));
            }
        }
        "high_speed_camera" => {
            let frame_rate = sensor["frame_rate_fps"]
                .as_u64()
                .ok_or_else(|| app_error("camera trace requires sensor.frame_rate_fps"))?;
            if frame_rate < 1_000 {
                return Err(app_error(
                    "high-speed camera must record at least 1000 frames per second",
                ));
            }
        }
        _ => {
            return Err(app_error(
                "instrument.method must be photodiode or high_speed_camera",
            ));
        }
    }

    let display = &trace["display"];
    let width = display["width_px"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| app_error("display.width_px must be positive"))?;
    let height = display["height_px"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| app_error("display.height_px must be positive"))?;
    let refresh_hz = display["refresh_rate_hz"]
        .as_f64()
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| app_error("display.refresh_rate_hz must be positive"))?;
    let vrr_enabled = display["vrr_enabled"]
        .as_bool()
        .ok_or_else(|| app_error("display.vrr_enabled must be boolean"))?;
    let hdr_enabled = display["hdr_enabled"]
        .as_bool()
        .ok_or_else(|| app_error("display.hdr_enabled must be boolean"))?;

    let triggers = trace["triggers"]
        .as_array()
        .ok_or_else(|| app_error("I2P trace triggers must be an array"))?;
    let transitions = trace["transitions"]
        .as_array()
        .ok_or_else(|| app_error("I2P trace transitions must be an array"))?;
    if triggers.len() != transitions.len() {
        return Err(app_error(
            "every trigger must have exactly one sensor transition; unmatched event IDs are rejected",
        ));
    }

    let mut event_ids = HashSet::new();
    let mut trigger_markers = HashSet::new();
    let mut transition_markers = HashSet::new();
    let mut previous_sequence = None::<u64>;
    let mut previous_trigger_tick = None::<u64>;
    let mut previous_sensor_tick = None::<u64>;
    let mut latency_ns = Vec::with_capacity(triggers.len());
    let mut rejected_reasons = BTreeMap::<String, u64>::new();

    for (index, trigger) in triggers.iter().enumerate() {
        let transition = &transitions[index];
        let event_id = trigger["event_id"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| app_error(format!("trigger {index} requires event_id")))?;
        if !event_ids.insert(event_id.to_string()) {
            return Err(app_error(format!("duplicate trigger event_id: {event_id}")));
        }
        if transition["event_id"].as_str() != Some(event_id) {
            return Err(app_error(format!(
                "trigger/transition event-ID join mismatch at index {index}"
            )));
        }

        let sequence = trigger["sequence"]
            .as_u64()
            .ok_or_else(|| app_error(format!("trigger {event_id} requires sequence")))?;
        if transition["sequence"].as_u64() != Some(sequence) {
            return Err(app_error(format!(
                "trigger/transition sequence mismatch for {event_id}"
            )));
        }
        if previous_sequence.is_some_and(|previous| sequence <= previous) {
            return Err(app_error("trigger sequence is duplicate or out of order"));
        }
        previous_sequence = Some(sequence);

        let marker_id = trigger["expected_marker_id"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| app_error(format!("trigger {event_id} requires expected_marker_id")))?;
        if !trigger_markers.insert(marker_id.to_string()) {
            return Err(app_error(format!(
                "duplicate expected marker ID: {marker_id}"
            )));
        }
        let observed_marker_id = transition["observed_marker_id"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                app_error(format!("transition {event_id} requires observed_marker_id"))
            })?;
        if observed_marker_id != marker_id {
            return Err(app_error(format!(
                "stale or wrong visual marker for event {event_id}"
            )));
        }
        if !transition_markers.insert(observed_marker_id.to_string()) {
            return Err(app_error(format!(
                "visual marker was replayed: {observed_marker_id}"
            )));
        }

        let trigger_tick = trigger["trigger_tick"].as_u64().ok_or_else(|| {
            app_error(format!(
                "trigger {event_id} requires non-negative trigger_tick"
            ))
        })?;
        let sensor_tick = transition["sensor_tick"].as_u64().ok_or_else(|| {
            app_error(format!(
                "transition {event_id} requires non-negative sensor_tick"
            ))
        })?;
        if previous_trigger_tick.is_some_and(|previous| trigger_tick <= previous) {
            return Err(app_error(
                "trigger counter ticks are duplicate or out of order",
            ));
        }
        if previous_sensor_tick.is_some_and(|previous| sensor_tick <= previous) {
            return Err(app_error(
                "sensor counter ticks are duplicate or out of order",
            ));
        }
        previous_trigger_tick = Some(trigger_tick);
        previous_sensor_tick = Some(sensor_tick);
        if sensor_tick < trigger_tick {
            return Err(app_error(format!(
                "negative input-to-photon duration for event {event_id}"
            )));
        }

        let valid = transition["valid"]
            .as_bool()
            .ok_or_else(|| app_error(format!("transition {event_id} requires boolean valid")))?;
        if valid {
            if !transition["rejection_reason"].is_null() {
                return Err(app_error(format!(
                    "valid transition {event_id} must not carry a rejection_reason"
                )));
            }
            let delta_ticks = sensor_tick - trigger_tick;
            let duration = (delta_ticks as u128)
                .checked_mul(1_000_000_000)
                .ok_or_else(|| app_error("I2P duration conversion overflow"))?
                / (counter_frequency_hz as u128);
            let duration = u64::try_from(duration)
                .map_err(|_| app_error("I2P duration exceeds supported nanosecond range"))?;
            latency_ns.push(duration);
        } else {
            let reason = transition["rejection_reason"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    app_error(format!(
                        "invalid transition {event_id} requires rejection_reason"
                    ))
                })?;
            *rejected_reasons.entry(reason.to_string()).or_insert(0) += 1;
        }
    }

    if latency_ns.len() < I2P_MIN_VALID_TRIALS {
        return Err(app_error(format!(
            "physical I2P import requires at least {I2P_MIN_VALID_TRIALS} valid trials; observed {} ({} rejected)",
            latency_ns.len(),
            rejected_reasons.values().sum::<u64>()
        )));
    }

    latency_ns.sort_unstable();
    let p50 = nearest_rank_percentile(&latency_ns, 50, 100);
    let p95 = nearest_rank_percentile(&latency_ns, 95, 100);
    let p99 = nearest_rank_percentile(&latency_ns, 99, 100);
    let max = *latency_ns.last().ok_or_else(|| {
        app_error("at least one valid trial is required for percentile calculation")
    })?;
    let seed = u64::from_str_radix(&trace_digest[..16], 16)
        .map_err(|_| app_error("cannot derive deterministic bootstrap seed from trace digest"))?;
    let (ci_lower, ci_upper) =
        bootstrap_percentile_ci(&latency_ns, 95, 100, I2P_BOOTSTRAP_RESAMPLES, seed);

    Ok(json!({
        "method": method,
        "instrument_id": instrument_id,
        "firmware_version": firmware_version,
        "tool_version": tool_version,
        "calibration_id": calibration_id,
        "calibration_sha256": calibration_digest,
        "calibrated": true,
        "event_id_join_verified": true,
        "sample_count": latency_ns.len(),
        "clock_resolution_ns": clock_resolution_ns,
        "sensor_bandwidth_hz": sensor["bandwidth_hz"],
        "frame_rate_fps": sensor["frame_rate_fps"],
        "raw_trace_sha256": trace_digest,
        "condition_id": trace["condition_id"],
        "measurement_unix_ms": measured_at,
        "clock_source": clock_source,
        "counter_frequency_hz": counter_frequency_hz,
        "clock_uncertainty_ns": clock_uncertainty,
        "calibration_uncertainty_ns": calibration_uncertainty,
        "combined_uncertainty_bound_ns": total_uncertainty_ns,
        "sensor_position": position,
        "sensor_clock_resolution_ns": clock_resolution_ns,
        "display": {
            "width_px": width,
            "height_px": height,
            "refresh_rate_hz": refresh_hz,
            "vrr_enabled": vrr_enabled,
            "hdr_enabled": hdr_enabled
        },
        "valid_trial_count": latency_ns.len(),
        "rejected_trial_count": rejected_reasons.values().sum::<u64>(),
        "rejected_reasons": rejected_reasons,
        "percentile_method": "nearest_rank",
        "confidence_interval_method": "deterministic nonparametric bootstrap percentile interval for p95",
        "bootstrap_resamples": I2P_BOOTSTRAP_RESAMPLES,
        "bootstrap_seed_hex": format!("{seed:016x}"),
        "p50_ns": p50,
        "p95_ns": p95,
        "p99_ns": p99,
        "max_ns": max,
        "p50_ms": p50 as f64 / 1_000_000.0,
        "p95_ms": p95 as f64 / 1_000_000.0,
        "p99_ms": p99 as f64 / 1_000_000.0,
        "max_ms": max as f64 / 1_000_000.0,
        "p95_ci_95_ms": {
            "lower": ci_lower as f64 / 1_000_000.0,
            "upper": ci_upper as f64 / 1_000_000.0
        }
    }))
}

fn nearest_rank_percentile(sorted: &[u64], numerator: u64, denominator: u64) -> u64 {
    debug_assert!(!sorted.is_empty());
    let count = sorted.len() as u128;
    let rank = (count * numerator as u128).div_ceil(denominator as u128);
    sorted[(rank.max(1).min(count) - 1) as usize]
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn bootstrap_percentile_ci(
    sorted_samples: &[u64],
    percentile_numerator: u64,
    percentile_denominator: u64,
    resamples: usize,
    seed: u64,
) -> (u64, u64) {
    debug_assert!(!sorted_samples.is_empty());
    debug_assert!(resamples > 0);
    let mut state = if seed == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        seed
    };
    let mut estimates = Vec::with_capacity(resamples);
    let mut sample = Vec::with_capacity(sorted_samples.len());
    for _ in 0..resamples {
        sample.clear();
        for _ in 0..sorted_samples.len() {
            let index = (xorshift64(&mut state) % sorted_samples.len() as u64) as usize;
            sample.push(sorted_samples[index]);
        }
        sample.sort_unstable();
        estimates.push(nearest_rank_percentile(
            &sample,
            percentile_numerator,
            percentile_denominator,
        ));
    }
    estimates.sort_unstable();
    (
        nearest_rank_percentile(&estimates, 25, 1_000),
        nearest_rank_percentile(&estimates, 975, 1_000),
    )
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
        if !is_hex_digest(hash, 64)
            || artifact["path"]
                .as_str()
                .is_none_or(|path| path.trim().is_empty())
        {
            return Err(app_error(
                "each PASS artifact requires a non-empty path and SHA-256 digest",
            ));
        }
    }
    let profile_digest = packet["profile_sha256"].as_str().unwrap_or_default();
    if !artifacts.iter().any(|artifact| {
        artifact["role"].as_str() == Some("qualification_profile")
            && artifact["sha256"].as_str() == Some(profile_digest)
    }) {
        return Err(app_error(
            "PASS requires the exact qualification profile to be bound as an artifact",
        ));
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

fn resolve_artifact_path(base: &Path, artifact: &Value) -> AppResult<PathBuf> {
    let relative = Path::new(
        artifact["path"]
            .as_str()
            .ok_or_else(|| app_error("artifact path is missing"))?,
    );
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(app_error(
            "artifact paths must be relative and remain inside the run directory",
        ));
    }

    let resolved = fs::canonicalize(base.join(relative)).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "artifact {} cannot be resolved: {error}",
                relative.display()
            ),
        )
    })?;
    if !resolved.starts_with(base) {
        return Err(app_error("artifact resolves outside the run directory"));
    }
    if !resolved.is_file() {
        return Err(app_error("artifact path must resolve to a regular file"));
    }
    Ok(resolved)
}

fn verify_artifacts_on_disk(packet: &Value, run_dir: &Path) -> AppResult<()> {
    let base = fs::canonicalize(run_dir)?;
    let artifacts = packet["artifacts"]
        .as_array()
        .ok_or_else(|| app_error("artifact list is missing"))?;

    for artifact in artifacts {
        let relative = Path::new(
            artifact["path"]
                .as_str()
                .ok_or_else(|| app_error("artifact path is missing"))?,
        );
        let resolved = resolve_artifact_path(&base, artifact)?;
        let expected = artifact["sha256"].as_str().unwrap_or_default();
        if !is_hex_digest(expected, 64) {
            return Err(app_error(
                "artifact SHA-256 must be 64 hexadecimal characters",
            ));
        }
        let observed = sha256_file(&resolved)?;
        if !observed.eq_ignore_ascii_case(expected) {
            return Err(app_error(format!(
                "artifact digest mismatch for {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn verify_profile_binding(packet: &Value, run_dir: &Path) -> AppResult<()> {
    let artifacts = packet["artifacts"]
        .as_array()
        .ok_or_else(|| app_error("artifact list is missing"))?;
    let matches: Vec<&Value> = artifacts
        .iter()
        .filter(|artifact| artifact["role"].as_str() == Some("qualification_profile"))
        .collect();
    if matches.len() != 1 {
        return Err(app_error(
            "run packet must contain exactly one qualification_profile artifact",
        ));
    }

    let artifact = matches[0];
    let expected_digest = packet["profile_sha256"]
        .as_str()
        .filter(|digest| is_hex_digest(digest, 64))
        .ok_or_else(|| app_error("run packet profile_sha256 is missing or invalid"))?;
    if artifact["sha256"].as_str() != Some(expected_digest) {
        return Err(app_error(
            "qualification profile artifact digest does not match profile_sha256",
        ));
    }

    let base = fs::canonicalize(run_dir)?;
    let resolved = resolve_artifact_path(&base, artifact)?;
    let bytes = fs::read(&resolved)?;
    let observed_digest = sha256_file(&resolved)?;
    if !observed_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(app_error("embedded qualification profile digest mismatch"));
    }

    let profile: Value = serde_json::from_slice(&bytes).map_err(|error| {
        app_error(format!(
            "embedded qualification profile is invalid JSON: {error}"
        ))
    })?;
    validate_profile(&profile)?;
    let profile_id = packet["profile_id"]
        .as_str()
        .ok_or_else(|| app_error("run packet profile_id is missing"))?;
    let selected = find_profile(&profile, profile_id)?;
    if &packet["profile_configuration"] != selected {
        return Err(app_error(
            "run packet profile_configuration differs from its embedded profile",
        ));
    }
    Ok(())
}

/// Re-open and re-validate imported physical evidence whenever a run packet is
/// checked. Digest presence alone is not enough: the raw trace and calibration
/// files must still produce the exact summary recorded in the packet.
fn verify_physical_latency_binding(packet: &Value, run_dir: &Path) -> AppResult<()> {
    if !packet["latency_measurement"].is_object() {
        if packet["result_state"].as_str() == Some("PASS")
            && required_measurements(packet["profile_id"].as_str().unwrap_or_default())?
                .contains(&"input_to_photon_p95_ms")
        {
            return Err(app_error(
                "PASS requires an imported physical latency summary",
            ));
        }
        return Ok(());
    }

    let artifacts = packet["artifacts"]
        .as_array()
        .ok_or_else(|| app_error("physical I2P evidence requires an artifact list"))?;
    let trace_matches = artifacts
        .iter()
        .filter(|item| item["role"].as_str() == Some("physical_latency_trace"))
        .collect::<Vec<_>>();
    let calibration_matches = artifacts
        .iter()
        .filter(|item| item["role"].as_str() == Some("instrument_calibration"))
        .collect::<Vec<_>>();
    if trace_matches.len() != 1 || calibration_matches.len() != 1 {
        return Err(app_error(
            "imported physical evidence requires exactly one trace and one calibration artifact",
        ));
    }

    let base = fs::canonicalize(run_dir)?;
    let trace_path = resolve_artifact_path(&base, trace_matches[0])?;
    let calibration_path = resolve_artifact_path(&base, calibration_matches[0])?;
    let trace_digest = sha256_file(&trace_path)?;
    let calibration_digest = sha256_file(&calibration_path)?;
    if trace_matches[0]["sha256"].as_str() != Some(trace_digest.as_str())
        || calibration_matches[0]["sha256"].as_str() != Some(calibration_digest.as_str())
    {
        return Err(app_error(
            "physical I2P artifact digest changed after import",
        ));
    }

    let trace: Value = serde_json::from_slice(&fs::read(&trace_path)?)
        .map_err(|error| app_error(format!("stored physical trace is invalid JSON: {error}")))?;
    let calibration: Value = serde_json::from_slice(&fs::read(&calibration_path)?)
        .map_err(|error| app_error(format!("stored calibration is invalid JSON: {error}")))?;
    let recomputed = validate_i2p_trace(
        &trace,
        &calibration,
        &trace_digest,
        &calibration_digest,
        packet,
    )?;
    if recomputed != packet["latency_measurement"] {
        return Err(app_error(
            "latency_measurement summary differs from the recomputed raw-trace result",
        ));
    }
    if packet["physical_latency_import"]["trace_sha256"].as_str() != Some(trace_digest.as_str())
        || packet["physical_latency_import"]["calibration_sha256"].as_str()
            != Some(calibration_digest.as_str())
        || packet["physical_latency_import"]["state"].as_str() != Some("IMPORTED_PARTIAL_EVIDENCE")
    {
        return Err(app_error(
            "physical_latency_import metadata does not bind the exact raw evidence",
        ));
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
        return Err(app_error(
            "physical latency instrument must have a current calibration",
        ));
    }
    if evidence["event_id_join_verified"] != Value::Bool(true) {
        return Err(app_error(
            "physical latency evidence must bind each sensor transition to its input event ID",
        ));
    }
    let trials = evidence["sample_count"]
        .as_u64()
        .ok_or_else(|| app_error("physical latency evidence is missing sample_count"))?;
    if trials < 300 {
        return Err(app_error(
            "physical input-to-photon PASS requires at least 300 valid trials",
        ));
    }
    if evidence["instrument_id"]
        .as_str()
        .is_none_or(|s| s.trim().is_empty())
    {
        return Err(app_error(
            "physical latency evidence requires an instrument identifier",
        ));
    }
    if !matches!(
        evidence["sensor_position"].as_str(),
        Some("top" | "centre" | "bottom")
    ) {
        return Err(app_error(
            "physical latency evidence requires sensor_position top, centre or bottom",
        ));
    }

    match method {
        "photodiode" => {
            let resolution = evidence["clock_resolution_ns"]
                .as_u64()
                .ok_or_else(|| app_error("photodiode evidence requires clock_resolution_ns"))?;
            if resolution > 1_000 {
                return Err(app_error(
                    "photodiode timer resolution must be 1000 ns or better",
                ));
            }
            let bandwidth = evidence["sensor_bandwidth_hz"]
                .as_u64()
                .ok_or_else(|| app_error("photodiode evidence requires sensor_bandwidth_hz"))?;
            if bandwidth < 10_000 {
                return Err(app_error(
                    "photodiode sensor bandwidth must be at least 10 kHz",
                ));
            }
        }
        "high_speed_camera" => {
            let fps = evidence["frame_rate_fps"]
                .as_u64()
                .ok_or_else(|| app_error("high-speed camera evidence requires frame_rate_fps"))?;
            if fps < 1_000 {
                return Err(app_error(
                    "high-speed camera evidence requires at least 1000 fps",
                ));
            }
        }
        _ => {
            return Err(app_error(
                "physical latency method must be photodiode or high_speed_camera",
            ));
        }
    }

    for (role, digest_key) in [
        ("physical_latency_trace", "raw_trace_sha256"),
        ("instrument_calibration", "calibration_sha256"),
    ] {
        let expected = evidence[digest_key].as_str().unwrap_or_default();
        if !is_hex_digest(expected, 64) {
            return Err(app_error(format!(
                "physical latency evidence requires {digest_key}"
            )));
        }
        let bound = artifacts.iter().any(|artifact| {
            artifact["role"].as_str() == Some(role) && artifact["sha256"].as_str() == Some(expected)
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
    let repository_label = repo
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "repository".to_string());
    let dirty = status.as_ref().map(|s| !s.trim().is_empty());
    let changed_count = status
        .as_ref()
        .map(|s| s.lines().filter(|line| !line.trim().is_empty()).count());
    json!({
        "repository_label": repository_label,
        "commit_sha": commit.map(|s| s.trim().to_string()),
        "dirty_tree": dirty,
        "changed_path_count": changed_count,
        "status_semantics": "Only a clean, exact commit can qualify a PASS result. Absolute checkout paths and Git branch names are intentionally omitted."
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

    fn fixture_sha256(bytes: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!(
            "xenia-i2p-calibration-fixture-{}-{:?}-{}.json",
            std::process::id(),
            std::thread::current().id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, bytes).unwrap();
        let digest = sha256_file(&path).unwrap();
        fs::remove_file(path).unwrap();
        digest
    }

    fn rebind_fixture_calibration_digest(trace: &mut Value, calibration: &Value) {
        let bytes = serde_json::to_vec_pretty(calibration).unwrap();
        trace["calibration_sha256"] = json!(fixture_sha256(&bytes));
    }

    fn synthetic_i2p_fixture(valid_count: usize) -> (Value, Value, Value) {
        let run_id = "synthetic-i2p-run";
        let mut triggers = Vec::new();
        let mut transitions = Vec::new();
        for index in 0..300_u64 {
            let event_id = format!("event-{index:04}");
            let marker_id = format!("marker-{index:04}");
            let sequence = index + 1;
            let trigger_tick = sequence * 100_000;
            let duration_ticks = 50_000 + (index % 17) * 1_000;
            triggers.push(json!({
                "event_id": event_id,
                "sequence": sequence,
                "trigger_tick": trigger_tick,
                "expected_marker_id": marker_id
            }));
            transitions.push(json!({
                "event_id": event_id,
                "sequence": sequence,
                "sensor_tick": trigger_tick + duration_ticks,
                "observed_marker_id": marker_id,
                "valid": (index as usize) < valid_count,
                "rejection_reason": if (index as usize) < valid_count { Value::Null } else { json!("synthetic-blink-rejection") }
            }));
        }

        let calibration = json!({
            "schema_version": I2P_CALIBRATION_SCHEMA,
            "instrument_id": "synthetic-photodiode-01",
            "method": "photodiode",
            "calibration_id": "synthetic-cal-2026-01",
            "valid_from_unix_ms": 1_000,
            "valid_until_unix_ms": 2_000,
            "uncertainty_ns": 100
        });
        let calibration_digest = fixture_sha256(&serde_json::to_vec_pretty(&calibration).unwrap());
        let trace = json!({
            "schema_version": I2P_TRACE_SCHEMA,
            "run_id": run_id,
            "profile_id": "lan_interactive",
            "condition_id": "lan-static-ui-1080p60",
            "measurement_unix_ms": 1_500,
            "instrument": {
                "id": "synthetic-photodiode-01",
                "firmware_version": "synthetic-fw-1",
                "tool_version": "synthetic-generator-1",
                "method": "photodiode"
            },
            "timebase": {
                "clock_source": "synthetic-shared-counter",
                "counter_frequency_hz": 1_000_000,
                "uncertainty_ns": 200
            },
            "sensor": {
                "position": "centre",
                "clock_resolution_ns": 100,
                "bandwidth_hz": 20_000
            },
            "display": {
                "width_px": 1920,
                "height_px": 1080,
                "refresh_rate_hz": 60.0,
                "vrr_enabled": false,
                "hdr_enabled": false
            },
            "calibration_sha256": calibration_digest,
            "triggers": triggers,
            "transitions": transitions,
            "fixture_notice": "SYNTHETIC_TEST_DATA_NOT_A_PHYSICAL_MEASUREMENT"
        });
        let packet = json!({
            "run_id": run_id,
            "profile_id": "lan_interactive",
            "profile_configuration": { "id": "lan_interactive" }
        });
        (trace, calibration, packet)
    }

    #[test]
    fn i2p_import_accepts_calibrated_synthetic_fixture_but_only_yields_partial_measurement() {
        let (trace, calibration, packet) = synthetic_i2p_fixture(300);
        let calibration_digest = trace["calibration_sha256"]
            .as_str()
            .expect("synthetic fixture binds the calibration digest");
        let summary = validate_i2p_trace(
            &trace,
            &calibration,
            &"a".repeat(64),
            calibration_digest,
            &packet,
        )
        .unwrap();
        assert_eq!(summary["valid_trial_count"], 300);
        assert_eq!(summary["rejected_trial_count"], 0);
        assert_eq!(summary["p50_ms"].as_f64().unwrap(), 58.0);
        assert_eq!(summary["p95_ms"].as_f64().unwrap(), 66.0);
        assert_eq!(summary["p99_ms"].as_f64().unwrap(), 66.0);
        assert_eq!(
            summary["confidence_interval_method"],
            "deterministic nonparametric bootstrap percentile interval for p95"
        );
        assert!(summary["p95_ci_95_ms"]["lower"].is_number());
        assert!(summary["p95_ci_95_ms"]["upper"].is_number());
        // The importer is not allowed to set the run state. It only returns
        // one partial metric; the caller always preserves BLOCKED.
        assert_eq!(packet["profile_id"], "lan_interactive");
    }

    #[test]
    fn i2p_import_rejects_duplicate_or_unmatched_event_ids() {
        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        let duplicate_event_id = trace["triggers"][0]["event_id"].clone();
        trace["triggers"][1]["event_id"] = duplicate_event_id;
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_rejects_wrong_or_replayed_visual_markers() {
        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["transitions"][12]["observed_marker_id"] = json!("marker-from-another-event");
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        let replayed_marker_id = trace["transitions"][0]["observed_marker_id"].clone();
        trace["transitions"][1]["observed_marker_id"] = replayed_marker_id;
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_rejects_out_of_order_and_negative_durations() {
        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["triggers"][9]["sequence"] = json!(1);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["transitions"][0]["sensor_tick"] = json!(0);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_rejects_less_than_three_hundred_valid_trials() {
        let (trace, calibration, packet) = synthetic_i2p_fixture(299);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_rejects_expired_calibration_and_digest_mismatch() {
        let (mut trace, mut calibration, packet) = synthetic_i2p_fixture(300);
        calibration["valid_until_unix_ms"] = json!(1_499);
        rebind_fixture_calibration_digest(&mut trace, &calibration);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        let (trace, calibration, packet) = synthetic_i2p_fixture(300);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                &"c".repeat(64),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_enforces_photodiode_constraints_and_counter_frequency() {
        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["sensor"]["bandwidth_hz"] = json!(9_999);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["sensor"]["clock_resolution_ns"] = json!(1_001);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        let (mut trace, calibration, packet) = synthetic_i2p_fixture(300);
        trace["timebase"]["counter_frequency_hz"] = json!(0);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );
    }

    #[test]
    fn i2p_import_enforces_high_speed_camera_frame_rate() {
        let (mut trace, mut calibration, packet) = synthetic_i2p_fixture(300);
        trace["instrument"]["method"] = json!("high_speed_camera");
        trace["sensor"]["frame_rate_fps"] = json!(999);
        calibration["method"] = json!("high_speed_camera");
        rebind_fixture_calibration_digest(&mut trace, &calibration);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_err()
        );

        trace["sensor"]["frame_rate_fps"] = json!(1_000);
        assert!(
            validate_i2p_trace(
                &trace,
                &calibration,
                &"a".repeat(64),
                trace["calibration_sha256"].as_str().unwrap(),
                &packet
            )
            .is_ok()
        );
    }

    #[test]
    fn i2p_physical_binding_recomputes_summary_from_raw_artifacts() {
        let (trace, calibration, identity) = synthetic_i2p_fixture(300);
        let run_dir = std::env::temp_dir().join(format!(
            "xenia-i2p-binding-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).unwrap();
        let trace_path = run_dir.join("physical-trace.json");
        let calibration_path = run_dir.join("calibration.json");
        write_new_file(&trace_path, &serde_json::to_vec_pretty(&trace).unwrap()).unwrap();
        write_new_file(
            &calibration_path,
            &serde_json::to_vec_pretty(&calibration).unwrap(),
        )
        .unwrap();
        let trace_digest = sha256_file(&trace_path).unwrap();
        let calibration_digest = sha256_file(&calibration_path).unwrap();
        let summary = validate_i2p_trace(
            &trace,
            &calibration,
            &trace_digest,
            &calibration_digest,
            &identity,
        )
        .unwrap();
        let packet = json!({
            "run_id": identity["run_id"],
            "profile_id": identity["profile_id"],
            "result_state": "BLOCKED",
            "latency_measurement": summary,
            "physical_latency_import": {
                "state": "IMPORTED_PARTIAL_EVIDENCE",
                "trace_sha256": trace_digest,
                "calibration_sha256": calibration_digest
            },
            "artifacts": [
                { "role": "physical_latency_trace", "path": "physical-trace.json", "sha256": trace_digest },
                { "role": "instrument_calibration", "path": "calibration.json", "sha256": calibration_digest }
            ]
        });
        verify_physical_latency_binding(&packet, &run_dir).unwrap();

        let mut tampered_summary = packet.clone();
        tampered_summary["latency_measurement"]["p95_ms"] = json!(999.0);
        assert!(verify_physical_latency_binding(&tampered_summary, &run_dir).is_err());

        fs::remove_dir_all(run_dir).unwrap();
    }

    #[test]
    fn i2p_bootstrap_interval_is_deterministic_for_a_fixed_seed() {
        let samples = (0..300_u64)
            .map(|value| 10_000 + value * 7)
            .collect::<Vec<_>>();
        let first = bootstrap_percentile_ci(&samples, 95, 100, 500, 0x1234_5678);
        let second = bootstrap_percentile_ci(&samples, 95, 100, 500, 0x1234_5678);
        assert_eq!(first, second);
        assert!(first.0 <= first.1);
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
    fn pass_artifact_check_verifies_bytes_and_rejects_path_escape() {
        let run_dir = std::env::temp_dir().join(format!(
            "xenia-bench-artifact-check-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).unwrap();
        let raw_path = run_dir.join("samples.jsonl");
        fs::write(&raw_path, br#"{"sample":1}"#).unwrap();
        let digest = sha256_file(&raw_path).unwrap();

        let mut packet = json!({
            "result_state": "PASS",
            "artifacts": [{
                "path": "samples.jsonl",
                "sha256": digest
            }]
        });
        verify_artifacts_on_disk(&packet, &run_dir).unwrap();

        packet["artifacts"][0]["sha256"] = json!("0".repeat(64));
        assert!(verify_artifacts_on_disk(&packet, &run_dir).is_err());

        packet["artifacts"][0]["path"] = json!("../samples.jsonl");
        packet["artifacts"][0]["sha256"] = json!(digest);
        assert!(verify_artifacts_on_disk(&packet, &run_dir).is_err());

        fs::remove_dir_all(run_dir).unwrap();
    }

    #[test]
    fn run_packet_profile_is_bound_to_exact_embedded_profile_bytes() {
        let run_dir = std::env::temp_dir().join(format!(
            "xenia-bench-profile-binding-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).unwrap();

        let selected = json!({
            "id": "lan_interactive",
            "kind": "performance_target",
            "network": {
                "rtt_ms": { "min": 1, "max": 5 },
                "packet_loss_fraction": 0.0
            }
        });
        let profile = json!({
            "schema_version": PROFILE_SCHEMA,
            "status": "proposed_targets_not_measurements",
            "network_profiles": [selected],
            "corpus": [{ "id": "synthetic-test-corpus" }],
            "security_and_correctness_targets": [{ "id": "synthetic-target" }],
            "evidence_contract": {
                "allowed_result_states": ["PASS", "FAIL", "BLOCKED", "ENVIRONMENT_FAILURE"],
                "missing_measurements_are_not_zero": true,
                "queued_skipped_cancelled_or_stale_ci_is_not_pass": true
            }
        });
        validate_profile(&profile).unwrap();

        let profile_path = run_dir.join("fixture.profile.json");
        write_new_file(&profile_path, &serde_json::to_vec_pretty(&profile).unwrap()).unwrap();
        let digest = sha256_file(&profile_path).unwrap();
        let packet = json!({
            "profile_id": "lan_interactive",
            "profile_sha256": digest,
            "profile_configuration": selected,
            "artifacts": [{
                "role": "qualification_profile",
                "path": "fixture.profile.json",
                "sha256": digest
            }]
        });

        verify_artifacts_on_disk(&packet, &run_dir).unwrap();
        verify_profile_binding(&packet, &run_dir).unwrap();

        let mut altered = packet.clone();
        altered["profile_configuration"]["network"]["rtt_ms"]["max"] = json!(999);
        assert!(verify_profile_binding(&altered, &run_dir).is_err());

        let mut missing_role = packet.clone();
        missing_role["artifacts"][0]["role"] = json!("other");
        assert!(verify_profile_binding(&missing_role, &run_dir).is_err());

        fs::remove_dir_all(run_dir).unwrap();
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
                { "role": "qualification_profile", "path": "qualification-profile.json", "sha256": "a".repeat(64) },
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
        packet["latency_measurement"]
            .as_object_mut()
            .unwrap()
            .remove("frame_rate_fps");

        packet["latency_measurement"]["sensor_bandwidth_hz"] = json!(5000);
        assert!(validate_run_packet(&packet).is_err());
        packet["latency_measurement"]["sensor_bandwidth_hz"] = json!(100000);

        packet["artifacts"] = json!([]);
        assert!(validate_run_packet(&packet).is_err());
        packet["artifacts"] = json!([
            { "role": "qualification_profile", "path": "qualification-profile.json", "sha256": "a".repeat(64) },
            { "role": "run_samples", "path": "raw-samples.jsonl", "sha256": "c".repeat(64) },
            { "role": "physical_latency_trace", "path": "latency-trace.csv", "sha256": "d".repeat(64) },
            { "role": "instrument_calibration", "path": "instrument-calibration.json", "sha256": "e".repeat(64) }
        ]);
        packet["source"]["dirty_tree"] = json!(true);
        assert!(validate_run_packet(&packet).is_err());
    }
}
