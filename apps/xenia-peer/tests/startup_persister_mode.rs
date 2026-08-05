// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real subprocess/CLI-level test of the daemon's startup path: arg parsing
//! -> persister-mode switch -> (optional) continuity verification ->
//! persister construction -> reaching "daemon listening" -- or, for the
//! negative cases, failing closed before ever getting there.
//!
//! Phase C of the consent-ledger compacted-boot-mode follow-up (Phase A:
//! daemon-startup persister-mode switch, Phase B: continuity checks +
//! mutual-exclusion guards). No such test existed anywhere before this --
//! not in Phase A/B's own hand-verification (real, but ad hoc and manual),
//! not in the original, unported PR #99. `main()` isn't factored into a
//! separately-testable function (see the Phase A/B PR descriptions), so a
//! real subprocess spawn of the compiled binary is the only way to prove
//! the whole chain actually works together, rather than each piece in
//! isolation.
//!
//! Unlike `consent_ceremony_end_to_end_tests.rs` (which calls `pub(crate)`
//! functions directly, in-process, because it needs the maintenance
//! ceremony types), this file only ever talks to `xenia-peer` as a black
//! box: `env!("CARGO_BIN_EXE_xenia-peer")`, real CLI args, real stdout/
//! stderr, real exit codes. Every fixture used below is built the same
//! way an operator would build one -- chained one-shot CLI invocations,
//! not crate-internal test helpers -- so this test also doubles as
//! end-to-end coverage of the CLI-to-CLI composition Phase 4 wired.
//!
//! The daemon has no SIGTERM/ctrl-c handler (only SIGHUP, for revocation
//! reload) -- confirmed by reading `main.rs` for any `tokio::signal` use.
//! So "clean shutdown" here doesn't mean graceful termination; it means
//! the daemon ran the whole startup sequence with no panic and no
//! `ERROR`-level line before we killed it, which is what these tests
//! actually check.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xenia-peer"))
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "xenia-peer-startup-test-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs a one-shot CLI operation (anything that exits on its own -- every
/// consent-ledger maintenance operation does) and returns its outcome.
fn run_one_shot(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn xenia-peer");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

struct CompactedFixture {
    key_path: PathBuf,
    active_path: PathBuf,
}

/// Builds a real, cryptographically genuine activated compacted-state file
/// entirely through the daemon's own one-shot CLI operations, chained
/// exactly as an operator would: genesis checkpoint -> archive segment ->
/// compaction bundle -> compacted snapshot -> activation. Degenerate (0
/// resident entries -- no CLI operation can append a real consent decision
/// without a live operator session), but every artifact is real, signed,
/// and independently re-verified by each downstream step; nothing here is
/// hand-constructed or bypasses the daemon's own code.
fn build_compacted_fixture(dir: &Path) -> CompactedFixture {
    let key_path = dir.join("operator.key");
    let ledger_path = dir.join("consent.ledger");
    let genesis = dir.join("genesis-checkpoint.json");
    let archive = dir.join("archive-segment.json");
    let bundle = dir.join("compaction-bundle.json");
    let snapshot = dir.join("compacted-snapshot.json");
    let active_path = dir.join("active-state.json");

    let key = key_path.to_str().unwrap();
    let ledger = ledger_path.to_str().unwrap();

    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key,
        "--consent-ledger-path",
        ledger,
        "--advance-consent-ledger-checkpoint",
        genesis.to_str().unwrap(),
    ]);
    assert!(ok, "genesis checkpoint export failed: {err}");

    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key,
        "--consent-ledger-path",
        ledger,
        "--export-consent-ledger-archive-segment",
        archive.to_str().unwrap(),
        "--consent-ledger-archive-base-checkpoint",
        genesis.to_str().unwrap(),
    ]);
    assert!(ok, "archive segment export failed: {err}");

    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key,
        "--consent-ledger-path",
        ledger,
        "--export-consent-ledger-compaction-bundle",
        bundle.to_str().unwrap(),
        "--consent-ledger-compaction-archive-segment",
        archive.to_str().unwrap(),
    ]);
    assert!(ok, "compaction bundle export failed: {err}");

    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key,
        "--consent-ledger-path",
        ledger,
        "--export-consent-ledger-compacted-snapshot",
        snapshot.to_str().unwrap(),
        "--consent-ledger-compaction-bundle-input",
        bundle.to_str().unwrap(),
    ]);
    assert!(ok, "compacted snapshot export failed: {err}");

    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key,
        "--activate-consent-ledger-compacted-state",
        active_path.to_str().unwrap(),
        "--consent-ledger-activation-snapshot",
        snapshot.to_str().unwrap(),
        "--consent-ledger-activation-archive-segment",
        archive.to_str().unwrap(),
    ]);
    assert!(ok, "compacted-state activation failed: {err}");

    CompactedFixture {
        key_path,
        active_path,
    }
}

/// Spawns the real daemon with `extra_args` (plus ephemeral ports on every
/// listener so parallel test runs never collide), waits up to `timeout` for
/// a stderr line containing `expect_substring`, then kills the process.
/// Returns whether the substring was seen and every line captured up to
/// that point (or up to the timeout/exit, if it was never seen) -- callers
/// can inspect the full captured prefix, not just the match.
///
/// Runs with `dir` as the working directory: several daemon keys besides
/// `--operator-key-path` (`--host-identity-key-path`,
/// `--http-auth-ml-dsa-key-path`, `--m1-consent-key-path`) default to
/// relative `xenia-peer-state/...` paths and are auto-created on first use
/// -- without an explicit `current_dir`, a first run of this test scatters
/// real (if test-only) key material into the crate's own working directory,
/// which `scripts/xenia-hygiene-audit.sh` correctly flags as a runtime
/// secret/state file left in the tree. Found by hand running this suite.
fn spawn_and_wait_for(
    dir: &Path,
    extra_args: &[&str],
    expect_substring: &str,
    timeout: Duration,
) -> (bool, Vec<String>) {
    let mut child = Command::new(bin())
        .current_dir(dir)
        .args(extra_args)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--admin-port",
            "0",
            "--consent-port",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn xenia-peer daemon");

    // `init_tracing` (main.rs) writes to stdout (plus an optional log file
    // for a non-terminal-attached process, e.g. `.and(non_blocking)`) --
    // NOT stderr. Confirmed by reading `init_tracing`'s `.with_writer(...)`
    // call directly rather than assuming the tracing-crate convention.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut lines = Vec::new();
    let mut found = false;
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                let hit = line.contains(expect_substring);
                lines.push(line);
                if hit {
                    found = true;
                    break;
                }
            }
            Err(_) => break, // channel disconnected (process exited) or timed out
        }
    }

    // Best-effort: the daemon has no graceful-shutdown handler (see module
    // doc comment), so a hard kill is the only option and is expected.
    let _ = child.kill();
    let _ = child.wait();

    (found, lines)
}

fn assert_no_error_lines(lines: &[String]) {
    for line in lines {
        assert!(
            !line.contains("panicked at") && !line.to_ascii_uppercase().contains(" ERROR "),
            "unexpected error/panic line during startup: {line}"
        );
    }
}

#[test]
fn compacted_boot_reaches_daemon_listening_with_no_errors() {
    let dir = scratch_dir("compacted-happy");
    let fixture = build_compacted_fixture(&dir);

    let log_file = dir.join("daemon.log");
    let (reached_listening, lines) = spawn_and_wait_for(
        &dir,
        &[
            "--operator-key-path",
            fixture.key_path.to_str().unwrap(),
            "--consent-ledger-compacted-state",
            fixture.active_path.to_str().unwrap(),
            "--log-file",
            log_file.to_str().unwrap(),
        ],
        "xenia-peer daemon listening",
        Duration::from_secs(20),
    );

    assert!(
        reached_listening,
        "daemon never logged \"xenia-peer daemon listening\"; captured:\n{}",
        lines.join("\n")
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("compacted consent ledger loaded and verified")),
        "daemon reached listening without logging the compacted-load line; captured:\n{}",
        lines.join("\n")
    );
    assert_no_error_lines(&lines);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_boot_reaches_daemon_listening_with_no_errors() {
    let dir = scratch_dir("plain-happy");
    let key_path = dir.join("operator.key");
    let ledger_path = dir.join("consent.ledger");

    let log_file = dir.join("daemon.log");
    let (reached_listening, lines) = spawn_and_wait_for(
        &dir,
        &[
            "--operator-key-path",
            key_path.to_str().unwrap(),
            "--consent-ledger-path",
            ledger_path.to_str().unwrap(),
            "--log-file",
            log_file.to_str().unwrap(),
        ],
        "xenia-peer daemon listening",
        Duration::from_secs(20),
    );

    assert!(
        reached_listening,
        "daemon never logged \"xenia-peer daemon listening\"; captured:\n{}",
        lines.join("\n")
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("consent ledger loaded and verified") && !l.contains("compacted")),
        "daemon reached listening without logging the plain-load line; captured:\n{}",
        lines.join("\n")
    );
    assert_no_error_lines(&lines);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compacted_boot_rejects_a_guarded_export_operation_before_listening() {
    let dir = scratch_dir("compacted-guard");
    let fixture = build_compacted_fixture(&dir);

    // Reuse the fixture's own archive segment as a stand-in
    // --consent-ledger-archive-base-checkpoint input -- its content is
    // irrelevant, since the Phase B guard must reject this combination
    // before the daemon ever reads it.
    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        fixture.key_path.to_str().unwrap(),
        "--consent-ledger-compacted-state",
        fixture.active_path.to_str().unwrap(),
        "--export-consent-ledger-archive-segment",
        dir.join("scratch-segment.json").to_str().unwrap(),
        "--consent-ledger-archive-base-checkpoint",
        dir.join("genesis-checkpoint.json").to_str().unwrap(),
    ]);

    assert!(
        !ok,
        "expected the compacted-mode export guard to reject this invocation"
    );
    assert!(
        err.contains("archive and compaction-preflight operations currently require a complete"),
        "unexpected error text: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compacted_boot_rejects_active_state_signed_under_a_different_key() {
    let dir = scratch_dir("compacted-wrongkey");
    let fixture = build_compacted_fixture(&dir);

    // A second daemon key, never used to build the fixture -- booting
    // against it must fail signature verification, a real (not
    // hand-constructed) rollback/substitution-class rejection.
    let other_key_path = dir.join("other-operator.key");
    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        other_key_path.to_str().unwrap(),
        "--consent-ledger-compacted-state",
        fixture.active_path.to_str().unwrap(),
    ]);

    assert!(
        !ok,
        "expected boot to fail: the compacted state was signed under a different key"
    );
    assert!(
        err.contains("failed to load --consent-ledger-compacted-state"),
        "unexpected error text: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_boot_rejects_a_trusted_checkpoint_signed_under_a_different_key() {
    let dir = scratch_dir("plain-wrongkey");
    let key_path = dir.join("operator.key");
    let ledger_path = dir.join("consent.ledger");
    let checkpoint_path = dir.join("checkpoint.json");

    // A genesis checkpoint for THIS daemon's own (about-to-be-created) key
    // and ledger.
    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        key_path.to_str().unwrap(),
        "--consent-ledger-path",
        ledger_path.to_str().unwrap(),
        "--advance-consent-ledger-checkpoint",
        checkpoint_path.to_str().unwrap(),
    ]);
    assert!(ok, "genesis checkpoint export failed: {err}");

    // A second daemon key/ledger pair, with its own independently
    // generated checkpoint -- structurally identical (both cover an empty
    // ledger) but signed under a different key, so it must not verify as
    // extending the first checkpoint.
    let other_key_path = dir.join("other-operator.key");
    let other_ledger_path = dir.join("other-consent.ledger");
    let other_checkpoint_path = dir.join("other-checkpoint.json");
    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        other_key_path.to_str().unwrap(),
        "--consent-ledger-path",
        other_ledger_path.to_str().unwrap(),
        "--advance-consent-ledger-checkpoint",
        other_checkpoint_path.to_str().unwrap(),
    ]);
    assert!(ok, "second genesis checkpoint export failed: {err}");

    // Boot the SECOND daemon (its own key/ledger) but trust the FIRST
    // daemon's checkpoint -- a real key mismatch the continuity check must
    // reject.
    let (ok, _out, err) = run_one_shot(&[
        "--operator-key-path",
        other_key_path.to_str().unwrap(),
        "--consent-ledger-path",
        other_ledger_path.to_str().unwrap(),
        "--trusted-consent-ledger-checkpoint",
        checkpoint_path.to_str().unwrap(),
        // Forces an early, listener-free exit right after the continuity
        // check runs, whichever way it resolves.
        "--advance-consent-ledger-checkpoint",
        dir.join("scratch-advance.json").to_str().unwrap(),
    ]);

    assert!(
        !ok,
        "expected the continuity check to reject a checkpoint signed under a different key"
    );
    assert!(
        err.contains("does not extend --trusted-consent-ledger-checkpoint"),
        "unexpected error text: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
