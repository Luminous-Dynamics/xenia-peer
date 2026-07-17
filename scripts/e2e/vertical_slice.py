#!/usr/bin/env python3
"""Item 6 (docs/security/POST_DELEGATION_HARDENING_PLAN.md) real
browser-driven vertical slice.

One sequential scenario -- not 13 independent tests -- because the steps
are causally ordered: pairing before enrollment, enrollment before
operator auth, auth before consent, consent before frame/input flow,
etc. Each `stage_*` function proves one or more of the plan's 13
numbered properties and is meant to be read top-to-bottom as the
narrative of a single real session.

Launched by scripts/xenia-e2e-vertical-slice.sh, which builds the real
binaries and the real compiled sovereign-admin console first. This
script owns runtime process orchestration (the daemon, the operator
agent under a real pseudo-terminal via pexpect, a static file server for
the console, and -- from Stage 6 onward -- a real xenia-viewer) plus the
Playwright browser automation.

Run only inside `nix develop .#e2e` / `nix run .#e2e` (provides
Playwright's browser binaries + pexpect).
"""

from __future__ import annotations

import contextlib
import http.server
import itertools
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pexpect
from playwright.sync_api import sync_playwright

ROOT = Path(os.environ["XENIA_E2E_ROOT"])
# Binaries are spawned with cwd=<per-run temp work_dir>, not ROOT, so a
# relative TARGET_DIR ("target", the default when CARGO_TARGET_DIR isn't
# set) must be resolved against ROOT here, not left relative -- otherwise
# it resolves against whatever cwd happens to be active at spawn time.
# Found live: this worked locally only because this session's
# CARGO_TARGET_DIR happens to always be an absolute path (a per-session
# dev-environment convention, not something CI has); the first real CI
# run failed with "No such file or directory: target/debug/xenia-operator-agent"
# because there CARGO_TARGET_DIR is unset and the relative path resolved
# against the wrong directory.
TARGET_DIR = Path(os.environ.get("XENIA_E2E_TARGET_DIR", "target"))
if not TARGET_DIR.is_absolute():
    TARGET_DIR = ROOT / TARGET_DIR
LOG_DIR = Path(os.environ["XENIA_E2E_LOG_DIR"])
DIST_DIR = Path(os.environ["XENIA_E2E_DIST_DIR"])

CONSOLE_PORT = 8134
CONSOLE_ORIGIN = f"http://127.0.0.1:{CONSOLE_PORT}"

PEER_BIN = TARGET_DIR / "debug" / "xenia-peer"
AGENT_BIN = TARGET_DIR / "debug" / "xenia-operator-agent"
VIEWER_BIN = TARGET_DIR / "debug" / "xenia-viewer"

# The scaffold DID gate (apps/sovereign-admin/src/auth.rs) is explicitly
# documented as having "no cryptographic verification yet" -- it is a
# route gate, not a security boundary, and predates/duplicates the real
# operator-RBAC ceremony this test exercises (OperatorAuthPanel's
# challenge/verify ceremony against the agent + daemon). Standing up a
# real Holochain conductor + mycelix-identity zome just to satisfy this
# scaffold gate would add a large, unrelated dependency this item's 13
# numbered properties never mention. Seeding it directly is the
# pragmatic choice; it does not touch or weaken any of the real
# cryptographic paths (pairing, host-trust, sealed handshake, consent,
# rekey, revocation) this test actually proves.
SEED_DID_SCRIPT = """
window.localStorage.setItem('xenia-admin.did', 'did:key:e2e-test-operator');
"""


def log(msg: str) -> None:
    print(f"[vertical_slice] {msg}", file=sys.stderr, flush=True)


def pick_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_tcp(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {host}:{port} to listen: {last_err}")


def wait_for_pattern(path: Path, pattern: str, timeout: float = 20.0) -> str:
    regex = re.compile(pattern)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text(errors="replace")
            m = regex.search(text)
            if m:
                return text
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for pattern {pattern!r} in {path}")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass


def serve_dist(directory: Path, port: int) -> http.server.ThreadingHTTPServer:
    handler = lambda *a, **kw: QuietHandler(*a, directory=str(directory), **kw)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


class Procs:
    """Tracks every process/handle this run owns so cleanup is total and
    ordered (agent last, since the daemon/viewer may still be mid-request
    against it during teardown)."""

    def __init__(self) -> None:
        self.http_server: http.server.ThreadingHTTPServer | None = None
        self.daemon: subprocess.Popen | None = None
        self.viewer: subprocess.Popen | None = None
        self.agent: pexpect.spawn | None = None

    def cleanup(self) -> None:
        if self.http_server is not None:
            with contextlib.suppress(Exception):
                self.http_server.shutdown()
        if self.viewer is not None and self.viewer.poll() is None:
            with contextlib.suppress(Exception):
                self.viewer.send_signal(signal.SIGTERM)
                self.viewer.wait(timeout=5)
        if self.daemon is not None and self.daemon.poll() is None:
            with contextlib.suppress(Exception):
                self.daemon.send_signal(signal.SIGTERM)
                self.daemon.wait(timeout=5)
        if self.agent is not None and self.agent.isalive():
            with contextlib.suppress(Exception):
                self.agent.close(force=True)


def dump_logs_and_die(procs: Procs, work_dir: Path, message: str) -> None:
    log(f"FAILED: {message}")
    # daemon-N.log (one per restart) and viewer-<label>.log (one per
    # connection) -- glob rather than a fixed name, and show all of them
    # in creation order so a failure mid-scenario still shows the full
    # restart history, not just whichever incarnation happened to be
    # named "daemon.log".
    paths = sorted(work_dir.glob("daemon-*.log"), key=lambda p: p.stat().st_mtime)
    paths += sorted(work_dir.glob("viewer-*.log"), key=lambda p: p.stat().st_mtime)
    paths += [work_dir / "agent.log", LOG_DIR / "network.log"]
    for path in paths:
        if path.exists():
            log(f"--- {path.name} (last 60 lines) ---")
            lines = path.read_text(errors="replace").splitlines()[-60:]
            for line in lines:
                print(f"  {line}", file=sys.stderr)
    procs.cleanup()
    sys.exit(1)


# ─── Stage 2: process orchestration skeleton ────────────────────────────


def spawn_agent(work_dir: Path, port: int) -> tuple[pexpect.spawn, str]:
    """Spawn xenia-operator-agent attached to a real PTY (required -- see
    module docstring / the plan: host_trust::confirm()'s is_terminal()
    check fails closed on a plain pipe) and capture its printed pairing
    token."""
    log_path = work_dir / "agent.log"
    args = [
        str(AGENT_BIN),
        "--port",
        str(port),
        "--identity-path",
        str(work_dir / "agent-identity.key"),
        "--token-path",
        str(work_dir / "agent-token.key"),
        "--pin-store-path",
        str(work_dir / "agent-host-trust.json"),
    ]
    child = pexpect.spawn(
        args[0],
        args[1:],
        cwd=str(work_dir),
        encoding="utf-8",
        timeout=30,
        env={**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info"), "NO_COLOR": "1"},
    )
    child.logfile = open(log_path, "w")
    child.expect(r"pairing token \(paste into the console's agent settings once, to pair\):")
    child.expect(r"\s*([0-9a-fA-F]{16,})\r?\n")
    token = child.match.group(1)
    child.expect(r"token also persisted at:")
    log(f"agent up on 127.0.0.1:{port}, pairing token captured ({len(token)} hex chars)")
    return child, token


_daemon_counter = itertools.count(1)


def spawn_daemon(
    work_dir: Path,
    ports: dict,
    operators_file: Path | None = None,
    host_identity_key_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> tuple[subprocess.Popen, Path]:
    # Each restart gets its own uniquely numbered log file (rather than
    # truncating a shared "daemon.log") so a later stage's log-grep can't
    # accidentally match a marker left over from a prior daemon
    # incarnation, and dump_logs_and_die can still show history across
    # restarts on failure.
    log_path = work_dir / f"daemon-{next(_daemon_counter)}.log"
    log_f = open(log_path, "w")
    args = [
        str(PEER_BIN),
        "--listen",
        f"127.0.0.1:{ports['listen']}",
        # Must match the viewer's --transport exactly. Default "auto"
        # runs an initial QUIC-advertisement discovery/probe exchange
        # before falling back to TCP; a viewer started with --transport
        # tcp skips that and speaks the raw handshake immediately, which
        # the daemon then misreads as a discovery probe -- found live via
        # a real bincode deserialization error ("invalid value: integer
        # ..., expected variant index 0 <= i < 3") followed by the
        # daemon's own handshake later failing with BrokenPipe once the
        # viewer had already exited. scripts/xenia-audio-e2e-smoke.sh
        # avoids this the same way: explicit --transport on both sides.
        "--transport",
        "tcp",
        "--admin-port",
        str(ports["admin"]),
        "--consent-port",
        str(ports["consent"]),
        "--frames",
        "0",
        "--telemetry-level",
        "off",
        "--operator-key-path",
        str(work_dir / "operator.key"),
        "--consent-ledger-path",
        str(work_dir / "consent.ledger"),
        "--m1-consent-key-path",
        str(work_dir / "consent-ledger.key"),
        "--host-identity-key-path",
        str(host_identity_key_path or (work_dir / "host-identity.key")),
        "--http-auth-ml-dsa-key-path",
        str(work_dir / "operator-http-ml-dsa.key"),
    ]
    if operators_file is not None:
        args += ["--operators-file", str(operators_file), "--require-operator-auth"]
    if extra_args:
        args += extra_args
    env = {**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info"), "NO_COLOR": "1"}
    proc = subprocess.Popen(args, cwd=str(work_dir), stdout=log_f, stderr=subprocess.STDOUT, env=env)
    return proc, log_path


def restart_daemon(
    procs: Procs,
    work_dir: Path,
    operators_file: Path | None = None,
    host_identity_key_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> tuple[dict, Path]:
    """Terminate the current daemon (if any) and start a genuinely fresh
    one on new ports, reusing the same persisted identity/ledger/key files
    in `work_dir`. OperatorPolicy and --operator-sealed are startup-only
    (not SIGHUP-reloadable), so every config change in this scenario goes
    through a real restart, never a live reload. Returns the new ports and
    this incarnation's own log file path."""
    if procs.daemon is not None and procs.daemon.poll() is None:
        procs.daemon.send_signal(signal.SIGTERM)
        procs.daemon.wait(timeout=5)
    ports = {
        "listen": pick_port(),
        "admin": pick_port(),
        "consent": pick_port(),
    }
    procs.daemon, log_path = spawn_daemon(
        work_dir,
        ports,
        operators_file=operators_file,
        host_identity_key_path=host_identity_key_path,
        extra_args=extra_args,
    )
    wait_for_tcp("127.0.0.1", ports["admin"])
    return ports, log_path


def reconnect_console_to(page, ports: dict) -> None:
    page.fill('[data-testid="daemon-endpoint-input"]', f"http://127.0.0.1:{ports['admin']}")
    page.fill('[data-testid="daemon-consent-port-input"]', str(ports["consent"]))
    if "sealed" in ports:
        page.check('[data-testid="use-sealed-channel-checkbox"]')
        page.fill('[data-testid="daemon-sealed-port-input"]', str(ports["sealed"]))
    page.click('[data-testid="save-reconnect-button"]')


def operator_sign_in(procs: Procs, page, expect_name_substring: str = "e2e-operator") -> str:
    """Click the operator sign-in button and complete the Track-A
    challenge/verify ceremony. Note this is NOT the same host-trust check
    Track B's sealed handshake does: `enforce_host_trust` on the agent
    scopes its pin by the caller's exact `daemon_endpoint` string (the
    admin HTTP URL for Track A, the sealed WS URL for Track B -- see
    `xenia-operator-agent::enforce_host_trust`'s doc comment), so every
    `restart_daemon` (new admin port) needs a *fresh* Track-A confirmation
    here even if Track B was already trusted for the same daemon identity
    (or vice versa). Found live: the first attempt at operator sign-in hung
    forever with the button stuck on "Authenticating..." -- the network
    trace showed `POST /v1/sign/challenge` sent to the agent with no
    response ever logged, because the agent was blocked on exactly this
    same PTY confirmation prompt this function now answers."""
    # OperatorSessionCtx is independent, page-lifetime browser state --
    # reconnect_console_to() changing the daemon config does NOT clear a
    # still-unexpired session from an earlier daemon incarnation, so the
    # sign-in button simply isn't rendered (the signed-in branch is) and a
    # blind click here would just time out. Found live: stage 4's sign-in
    # attempt timed out waiting for "operator-signin-button" because
    # stage 3's session was still considered valid. Sign out first so
    # every call gets a fresh session correctly scoped to the *current*
    # daemon.
    if page.locator('[data-testid="operator-role-chip"]').count() > 0:
        page.click('[data-testid="operator-signout-button"]')
    page.click('[data-testid="operator-signin-button"]')
    procs.agent.expect(r"Type 'yes' to confirm, anything else to refuse: ", timeout=20)
    log("operator_sign_in: agent prompted for Track-A host trust; approving")
    procs.agent.sendline("yes")
    page.wait_for_selector(
        f'[data-testid="operator-role-chip"]:has-text("{expect_name_substring}")',
        timeout=15_000,
    )
    return page.text_content('[data-testid="operator-role-chip"]')


def spawn_viewer(work_dir: Path, listen_port: int, label: str, frames: int = 1, extra_args: list[str] | None = None) -> subprocess.Popen:
    log_path = work_dir / f"viewer-{label}.log"
    log_f = open(log_path, "w")
    args = [
        str(VIEWER_BIN),
        "--connect",
        f"127.0.0.1:{listen_port}",
        "--transport",
        "tcp",
        "--frames",
        str(frames),
    ]
    if extra_args:
        args += extra_args
    env = {**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info"), "NO_COLOR": "1"}
    return subprocess.Popen(args, cwd=str(work_dir), stdout=log_f, stderr=subprocess.STDOUT, env=env)


def new_work_dir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="xenia-e2e-"))
    return d


def stage2_process_orchestration(procs: Procs, work_dir: Path, page, ctx: dict) -> None:
    """Process orchestration skeleton: agent + daemon (no operators-file
    yet, so no privileged surface active) + the static console. Verifies
    the Sessions page loads and the Agent URL field is fillable."""
    ports = {
        "listen": pick_port(),
        "admin": pick_port(),
        "consent": pick_port(),
    }
    agent_port = pick_port()

    procs.agent, pairing_token = spawn_agent(work_dir, agent_port)
    procs.daemon, daemon_log = spawn_daemon(work_dir, ports)
    wait_for_tcp("127.0.0.1", ports["admin"])
    log(f"daemon admin surface up on 127.0.0.1:{ports['admin']}")

    page.goto(CONSOLE_ORIGIN + "/")
    page.wait_for_selector("text=Sovereign", timeout=10_000)
    page.click('a[href="/sessions"]')
    page.wait_for_selector('h1:has-text("Sovereign Audit Console")', timeout=10_000)

    page.fill('[data-testid="agent-url-input"]', f"http://127.0.0.1:{agent_port}")
    filled = page.input_value('[data-testid="agent-url-input"]')
    assert filled == f"http://127.0.0.1:{agent_port}", f"agent URL field did not accept input: {filled!r}"

    page.screenshot(path=str(LOG_DIR / "stage2-sessions-page.png"))
    log("stage 2 OK: sessions page loaded, agent URL field fillable")

    ctx["ports"] = ports
    ctx["agent_port"] = agent_port
    ctx["pairing_token"] = pairing_token
    ctx["daemon_log"] = daemon_log


# ─── Stage 3: pairing + JSON-path enrollment + operator auth (steps 1-3) ─


def stage3_pairing_enrollment_auth(procs: Procs, work_dir: Path, page, ctx: dict) -> None:
    """Property 1 (agent pairs with the console), 2 (public identity
    enrolled through the actual JSON path), 3 (operator authenticates)."""

    # 1. Pairing: paste the real pairing token the agent printed, exchange
    # it for a session (POST /v1/pair).
    page.fill('[data-testid="pairing-token-input"]', ctx["pairing_token"])
    page.click('[data-testid="pair-button"]')
    page.wait_for_selector(
        '[data-testid="agent-identity-status"]:has-text("Connected. Fingerprint:")',
        timeout=15_000,
    )
    log("stage 3: paired with agent (real /v1/pair exchange)")

    # 2. Enrollment through the actual JSON path: read the agent's own
    # GET /identity enrollment_record_json off the DOM (not re-derived
    # locally), fill in a real operator_id + Admin role (Admin is needed
    # later for revocation), and write the daemon's --operators-file --
    # the exact artifact an admin would hand-edit and deploy.
    record_text = page.text_content('[data-testid="operator-enrollment-record"]')
    assert record_text, "enrollment record JSON was empty"
    record = json.loads(record_text)
    assert record["operator_id"] == "your-operator-id", f"unexpected placeholder: {record}"
    record["operator_id"] = "e2e-operator"
    record["role"] = "Admin"
    operators_file = work_dir / "operators.json"
    operators_file.write_text(json.dumps({"operators": [record]}))
    log(f"stage 3: wrote --operators-file from the agent's real enrollment JSON: {operators_file}")

    # Genuine first start with the operators file (OperatorPolicy loads
    # once at startup, not SIGHUP-reloadable -- see host_pin/operator
    # module docs) -- kill the pairing-only daemon and start a real one.
    new_ports, daemon_log = restart_daemon(procs, work_dir, operators_file=operators_file)
    log(f"stage 3: daemon restarted with --operators-file, admin surface on 127.0.0.1:{new_ports['admin']}")
    ctx["ports"] = new_ports
    ctx["operators_file"] = operators_file
    ctx["daemon_log"] = daemon_log

    reconnect_console_to(page, new_ports)

    # 3. Operator authenticates: the real challenge -> agent-sign ->
    # verify ceremony against the daemon's /auth/* routes. This is the
    # *first* Track-A host-trust check for this daemon endpoint (a fresh
    # admin port from the restart above), so operator_sign_in() answers
    # the agent's native confirmation prompt as part of it.
    role_chip = operator_sign_in(procs, page)
    assert "Admin" in role_chip, f"expected Admin role chip, got: {role_chip!r}"
    page.screenshot(path=str(LOG_DIR / "stage3-operator-signed-in.png"))
    log(f"stage 3 OK: operator authenticated as {role_chip!r}")


# ─── Stage 4/5: sealed handshake, host trust, consent, frame/input gating ─
# (steps 4-8) -- these fuse into one real action in the actual UI: approving
# a sealed-channel consent decision IS what drives the agent's first-use
# host-trust check and completes the hybrid handshake, so there is no
# separate "do the handshake" click to test in isolation.


def stage4_5_sealed_handshake_and_consent(procs: Procs, work_dir: Path, page, ctx: dict) -> None:
    """Property 4 (first host trust requires native approval), 5 (hybrid
    sealed handshake completes), 6 (consent is approved), 7 (frames flow
    only afterward)."""
    sealed_port = pick_port()
    ports, daemon_log = restart_daemon(
        procs,
        work_dir,
        operators_file=ctx["operators_file"],
        extra_args=["--operator-sealed", "--operator-sealed-port", str(sealed_port)],
    )
    ports["sealed"] = sealed_port
    ctx["ports"] = ports
    ctx["daemon_log"] = daemon_log
    log(f"stage 4: daemon restarted with --operator-sealed, sealed port 127.0.0.1:{sealed_port}")

    reconnect_console_to(page, ports)
    role_chip = operator_sign_in(procs, page)
    log(f"stage 4: operator re-authenticated against the sealed-capable daemon: {role_chip!r}")

    procs.viewer = spawn_viewer(work_dir, ports["listen"], label="consent-approve")

    page.wait_for_selector('[data-testid="consent-modal"]', timeout=20_000)
    page.screenshot(path=str(LOG_DIR / "stage4-consent-modal.png"))
    log("stage 4: consent prompt broadcast to console and modal opened")

    page.click('[data-testid="consent-approve-button"]')

    # Property 4: the agent's native, terminal-gated confirmation for the
    # first-ever trust of this daemon's sealed-channel host identity --
    # host_trust::confirm() blocks on a real PTY read, which is exactly
    # what pexpect gives this process (see module docstring).
    procs.agent.expect(r"Type 'yes' to confirm, anything else to refuse: ", timeout=20)
    log("stage 4: agent prompted for first-use host trust; approving")
    procs.agent.sendline("yes")

    # Property 5: the daemon's own log confirms the hybrid sealed handshake
    # completed (channel established) using the agent-derived key.
    wait_for_pattern(daemon_log, r"sealed operator channel established", timeout=20)
    log("stage 4 OK: sealed operator channel established after native host-trust approval")

    # Property 6 (consent granted) and 7 (frames only flow afterward),
    # proven by ordering the daemon log's two markers -- the file is
    # append-only for this process's lifetime, so an index from an earlier
    # (shorter) read remains a valid offset into a later (longer) read.
    consent_text = wait_for_pattern(
        daemon_log, r"M1 consent granted; only the operator-enabled tiers unlocked", timeout=20
    )
    consent_idx = consent_text.index("M1 consent granted; only the operator-enabled tiers unlocked")
    frame_text = wait_for_pattern(daemon_log, r"frame encoded, sealed, and sent", timeout=20)
    frame_idx = frame_text.index("frame encoded, sealed, and sent")
    assert consent_idx < frame_idx, "frame flow logged before consent was granted"
    log("stage 5 OK: frames flow only after consent (log order verified)")

    procs.viewer.wait(timeout=15)
    assert procs.viewer.returncode == 0, (
        f"viewer exited {procs.viewer.returncode}, see {work_dir}/viewer-consent-approve.log"
    )
    log("stage 5: viewer received its frame and exited cleanly")


# ─── Stage 6: rekey, revocation, changed-identity refusal (steps 9-11) ──


def stage6_rekey_revocation_changed_identity(procs: Procs, work_dir: Path, page, ctx: dict) -> None:
    """Property 9 (rekey succeeds), 10 (revocation terminates authority
    immediately), 11 (changed daemon identity is refused)."""

    # 9. Rekey: a longer viewer session crosses the daemon's default
    # --rekey-frames threshold (4), forcing a real session-encryption
    # epoch rekey (xenia_wire session epochs, the same mechanism
    # scripts/xenia-audio-e2e-smoke.sh already validates for the
    # non-operator-gated path). This is distinct from the operator
    # CHANNEL's own forward-secrecy rekey (--operator-rekey-interval-secs)
    # -- sealed_consent.rs's module doc comment is explicit that the
    # console's sealed-channel driver is a one-shot connect/decide/close
    # and never calls handle_operator_rekey_envelope, so that mechanism
    # has no browser-reachable path yet (a real, documented gap for a
    # future persistent-console mode -- out of scope here). The viewer-
    # session rekey below is real, wire-verified, and reached through the
    # same real consent-approval click, so it's what this test proves for
    # "rekey succeeds".
    #
    # The daemon accepts exactly one transport connection per process
    # lifetime (found live: a second viewer against stage 4/5's daemon got
    # "Connection refused" -- nothing re-listens after the first session
    # ends), so every subsequent viewer connection in this stage needs its
    # own fresh daemon restart, same as every other property here. Reusing
    # the *same* sealed port keeps Track B's host-trust pin valid (no new
    # PTY prompt); Track A always needs a fresh one since the admin port
    # changes, which operator_sign_in() already handles.
    ports, daemon_log = restart_daemon(
        procs,
        work_dir,
        operators_file=ctx["operators_file"],
        extra_args=["--operator-sealed", "--operator-sealed-port", str(ctx["ports"]["sealed"])],
    )
    ports["sealed"] = ctx["ports"]["sealed"]
    ctx["ports"] = ports
    ctx["daemon_log"] = daemon_log
    reconnect_console_to(page, ports)
    operator_sign_in(procs, page)

    procs.viewer = spawn_viewer(work_dir, ctx["ports"]["listen"], label="rekey", frames=8)
    page.wait_for_selector('[data-testid="consent-modal"]', timeout=20_000)
    page.click('[data-testid="consent-approve-button"]')
    viewer_log = work_dir / "viewer-rekey.log"
    wait_for_pattern(viewer_log, r"session rekey installed key_epoch=1\b", timeout=20)
    wait_for_pattern(ctx["daemon_log"], r"session rekey acknowledged key_epoch=1\b", timeout=20)
    procs.viewer.wait(timeout=15)
    assert procs.viewer.returncode == 0, f"rekey viewer exited {procs.viewer.returncode}, see {viewer_log}"
    log("stage 6 OK: viewer session rekey verified (property 9)")

    # 10. Revocation: the Admin-permitted operator revokes their own
    # operator_id live -- POST /operator/revoke mutates the daemon's
    # shared OperatorRevocations in-process, no restart/SIGHUP needed.
    # Effective on the *next* sealed-channel connection attempt (checked
    # once, right after establish_operator_channel succeeds) -- prove it
    # terminates authority by attempting one more consent decision and
    # confirming the daemon refuses it.
    #
    # Fresh daemon first (single-connection-per-process, see property 9's
    # comment) -- and *before* revoking, not after: OperatorRevocations is
    # in-memory only (no --revoked-operators-file here), so revoking then
    # restarting would wipe it and the "post-revoke" viewer would wrongly
    # succeed against a fresh, unaware daemon. Revoke against this same,
    # not-yet-connected-to incarnation instead. Same sealed port again
    # keeps Track B's host-trust pin valid; Track A needs (and gets, via
    # operator_sign_in) a fresh confirmation for the new admin port.
    ports, daemon_log = restart_daemon(
        procs,
        work_dir,
        operators_file=ctx["operators_file"],
        extra_args=["--operator-sealed", "--operator-sealed-port", str(ctx["ports"]["sealed"])],
    )
    ports["sealed"] = ctx["ports"]["sealed"]
    ctx["ports"] = ports
    ctx["daemon_log"] = daemon_log
    reconnect_console_to(page, ports)
    operator_sign_in(procs, page)

    page.fill('[data-testid="revoke-operator-input"]', "e2e-operator")
    page.click('[data-testid="revoke-operator-button"]')
    # Revoke is a privileged action: the agent runs its OWN mandatory
    # native confirmation for it (host_trust::confirm_action) on top of
    # (and separate from) the host-identity check operator_sign_in()
    # already answered -- see build_revoke_request's doc comment. Found
    # live: the revoke request hung forever on this exact unanswered
    # prompt while the test kept waiting on the wrong signal (see next
    # comment).
    procs.agent.expect(r"Type 'yes' to confirm, anything else to refuse: ", timeout=20)
    log("stage 6: agent prompted for the revoke action itself; approving")
    procs.agent.sendline("yes")
    # Wait for the *actual* completion text ("Revoked '...'."), not just
    # non-empty text -- set_revoke_status is set synchronously to
    # "Revoking '...'…" the instant the button is clicked, well before the
    # real request resolves, so a bare non-empty check passes immediately
    # regardless of whether the revoke ever actually completes. Found
    # live: this bug masked the hang above -- the log line below printed
    # the placeholder text as if it were a real result.
    page.wait_for_selector('[data-testid="revoke-status"]:has-text("Revoked \'e2e-operator\'.")', timeout=15_000)
    revoke_status = page.text_content('[data-testid="revoke-status"]')
    log(f"stage 6: revoke response: {revoke_status!r}")

    procs.viewer = spawn_viewer(work_dir, ctx["ports"]["listen"], label="post-revoke")
    page.wait_for_selector('[data-testid="consent-modal"]', timeout=20_000)
    page.click('[data-testid="consent-approve-button"]')
    wait_for_pattern(ctx["daemon_log"], r"revoked operator attempted the sealed operator channel", timeout=20)
    log("stage 6 OK: revocation terminated authority immediately (property 10)")
    if procs.viewer.poll() is None:
        procs.viewer.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            procs.viewer.wait(timeout=5)

    # 11. Changed daemon identity is refused: restart the daemon on the
    # *same* sealed port but with a brand-new --host-identity-key-path,
    # so its fingerprint changes. The agent already pinned the old
    # fingerprint (TOFU in stage 4) -- host_trust::check() sees a
    # mismatch and prompts "Daemon identity changed" instead of silently
    # trusting or silently refusing; answer anything but "yes" and
    # confirm the channel never establishes.
    #
    # Re-enrolls the *same* operator identity (unaffected by the
    # self-revocation above -- a brand-new daemon process starts with an
    # empty OperatorRevocations regardless of what the previous
    # incarnation's live revocation list held) against the new daemon so
    # only the host identity differs, isolating this to property 11.
    new_host_key = work_dir / "host-identity-2.key"
    ports2, daemon_log2 = restart_daemon(
        procs,
        work_dir,
        operators_file=ctx["operators_file"],
        host_identity_key_path=new_host_key,
        extra_args=["--operator-sealed", "--operator-sealed-port", str(ctx["ports"]["sealed"])],
    )
    ports2["sealed"] = ctx["ports"]["sealed"]
    ctx["ports"] = ports2
    ctx["daemon_log"] = daemon_log2
    reconnect_console_to(page, ports2)
    operator_sign_in(procs, page)

    procs.viewer = spawn_viewer(work_dir, ports2["listen"], label="changed-identity")
    page.wait_for_selector('[data-testid="consent-modal"]', timeout=20_000)
    page.click('[data-testid="consent-approve-button"]')
    procs.agent.expect(r"Type 'yes' to confirm, anything else to refuse: ", timeout=20)
    log("stage 6: agent prompted for changed daemon identity; refusing")
    procs.agent.sendline("no")
    time.sleep(2)  # let the refusal propagate; no log line to block on for a negative case
    # "sealed operator channel established" is NOT the right signal here --
    # found live: it logs regardless of the agent's trust decision, since
    # it only reflects the wire-level crypto handshake completing (the
    # console dutifully relays HostHello/HostFinalize bytes through the
    # agent either way; POST /v1/handshake/finish even answers 200 with a
    # failure encoded in the body, not an HTTP error status). What the
    # agent's refusal actually prevents is releasing session key material,
    # so no consent decision is ever sealed and sent -- the real signal is
    # that "M1 consent granted" never appears, and the viewer never
    # receives its frame.
    daemon_text = daemon_log2.read_text(errors="replace")
    assert "M1 consent granted" not in daemon_text, (
        "consent was granted despite a refused changed-identity confirmation"
    )
    assert procs.viewer.poll() is None, "viewer exited (should still be blocked waiting for a frame that never arrives)"
    procs.viewer.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        procs.viewer.wait(timeout=5)
    log("stage 6 OK: changed daemon identity refused, channel never established (property 11)")


def fetch_checkpoint(admin_port: int) -> dict:
    url = f"http://127.0.0.1:{admin_port}/v1/audit/checkpoint"
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - fixed loopback test URL
        return json.loads(resp.read())


# ─── Stage 7: restart recovery + no-durable-secrets-in-storage (steps 12-13) ─


def stage7_restart_recovery_and_storage_check(procs: Procs, work_dir: Path, page, ctx: dict) -> None:
    """Property 12 (daemon and agent restart recover the intended state)
    and 13 (no browser storage contains operator keys, HMAC secrets, or
    durable signing capabilities)."""

    pre_restart_checkpoint = fetch_checkpoint(ctx["ports"]["admin"])
    pre_restart_count = pre_restart_checkpoint["entry_count"]
    log(f"stage 7: pre-restart ledger checkpoint: entry_count={pre_restart_count}")

    # Real restart of BOTH processes -- not a reload. The agent reuses its
    # persisted identity/token/pin-store files (same paths), so pairing,
    # host identity, and the host-trust pin all need to survive purely
    # because they're durable files, not in-memory state.
    if procs.agent is not None and procs.agent.isalive():
        procs.agent.close(force=True)
    agent_port = ctx["agent_port"]
    procs.agent, _reused_pairing_token = spawn_agent(work_dir, agent_port)
    log("stage 7: agent restarted (same identity/token/pin-store files)")

    # The original host identity (not stage 6's host-identity-2.key) --
    # this is the identity/ledger file set every stage before stage 6's
    # property-11 restart used, and the one the agent's pin store already
    # trusts from stage 4. Crucially, reuse the *same* sealed port
    # (ctx["ports"]["sealed"], unchanged throughout stage 6's property
    # 9/10/11) rather than picking a fresh one -- host_alias is keyed by
    # the full sealed WS URL including port, so a fresh port would make
    # this a genuinely new (never-pinned) host_alias and trivially require
    # a fresh confirmation regardless of whether the pin store file
    # actually survived the restart, which is the thing property 12 needs
    # to prove. Found live: this exact mistake made stage 7 fail on a
    # false positive ("the pin store did not survive") when the real bug
    # was the test's own port choice, not the app.
    sealed_port = ctx["ports"]["sealed"]
    ports, daemon_log = restart_daemon(
        procs,
        work_dir,
        operators_file=ctx["operators_file"],
        host_identity_key_path=work_dir / "host-identity.key",
        extra_args=["--operator-sealed", "--operator-sealed-port", str(sealed_port)],
    )
    ports["sealed"] = sealed_port
    ctx["ports"] = ports
    ctx["daemon_log"] = daemon_log
    log(f"stage 7: daemon restarted with original host identity, admin on 127.0.0.1:{ports['admin']}")

    reconnect_console_to(page, ports)
    role_chip = operator_sign_in(procs, page)
    log(f"stage 7: operator authenticated against the restarted daemon: {role_chip!r}")

    post_restart_checkpoint = fetch_checkpoint(ports["admin"])
    post_restart_count = post_restart_checkpoint["entry_count"]
    log(f"stage 7: post-restart ledger checkpoint: entry_count={post_restart_count}")
    assert post_restart_count >= pre_restart_count, (
        f"ledger entry count regressed across restart: {pre_restart_count} -> {post_restart_count}"
    )
    if post_restart_count == pre_restart_count:
        assert post_restart_checkpoint["head_hash"] == pre_restart_checkpoint["head_hash"], (
            "restarted daemon's ledger head diverged from the pre-restart ledger without adding entries"
        )

    # The agent's host-trust pin for the *original* host identity should
    # already be trusted from stage 4 -- approving this consent should
    # reach "sealed operator channel established" WITHOUT a new PTY
    # confirmation prompt. Snapshot the agent log's length *before* this
    # click so the check below only looks at newly-appended content --
    # the whole file already legitimately contains the Track-A
    # "confirmation required" prompt from operator_sign_in() a few lines
    # up in this same stage (a fresh admin port always needs its own
    # confirmation), so checking the full file was a false positive found
    # live on the first attempt at this check.
    agent_log_path = work_dir / "agent.log"
    agent_log_offset = agent_log_path.stat().st_size
    procs.viewer = spawn_viewer(work_dir, ports["listen"], label="post-restart")
    page.wait_for_selector('[data-testid="consent-modal"]', timeout=20_000)
    page.click('[data-testid="consent-approve-button"]')
    wait_for_pattern(daemon_log, r"sealed operator channel established", timeout=10)
    with open(agent_log_path, "rb") as f:
        f.seek(agent_log_offset)
        new_agent_log_text = f.read().decode(errors="replace")
    assert "confirmation required" not in new_agent_log_text, (
        "agent re-prompted for host trust after restart -- the pin store did not survive"
    )
    procs.viewer.wait(timeout=15)
    assert procs.viewer.returncode == 0
    log("stage 7 OK: daemon + agent restart recovered ledger state and the host-trust pin (property 12)")

    # Property 13: no browser storage holds operator seeds, HMAC secrets,
    # or a durable signing capability -- only public/expiring state
    # (daemon connection settings, the agent's URL, an *expiring* agent
    # session token, a scaffold DID string, and public host-fingerprint
    # pins for TOFU).
    storage = page.evaluate(
        "() => Object.fromEntries(Object.entries(localStorage))"
    )
    log(f"stage 7: full localStorage dump for manual review: {json.dumps(storage, indent=2)}")

    pairing_token = ctx["pairing_token"]
    for key, value in storage.items():
        assert pairing_token not in value, f"raw pairing token leaked into localStorage[{key}]"
        assert not re.search(r"seed|secret|hmac", key, re.IGNORECASE), (
            f"localStorage key {key!r} suggests durable secret material"
        )
    assert "xenia-admin.agent.session" in storage, (
        "expected the (expiring) agent session token to be the only agent credential in storage"
    )
    log("stage 7 OK: no durable secrets found in browser storage (property 13)")


def main() -> None:
    work_dir = new_work_dir()
    log(f"work dir: {work_dir}")
    log(f"log dir: {LOG_DIR}")

    procs = Procs()
    httpd = serve_dist(DIST_DIR, CONSOLE_PORT)
    procs.http_server = httpd
    wait_for_tcp("127.0.0.1", CONSOLE_PORT)
    log(f"console served at {CONSOLE_ORIGIN}")

    ctx: dict = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            context.add_init_script(SEED_DID_SCRIPT)
            page = context.new_page()

            net_log = open(LOG_DIR / "network.log", "w")

            def log_request(req):
                print(f"--> {req.method} {req.url}", file=net_log, flush=True)

            def log_response(resp):
                print(f"<-- {resp.status} {resp.url}", file=net_log, flush=True)

            def log_request_failed(req):
                print(f"xxx FAILED {req.method} {req.url} :: {req.failure}", file=net_log, flush=True)

            page.on("request", log_request)
            page.on("response", log_response)
            page.on("requestfailed", log_request_failed)

            # try/except INSIDE the sync_playwright `with` block, not
            # outside it -- `with sync_playwright()`'s __exit__ tears down
            # the browser driver connection, so any diagnostic capture
            # attempted after that block has already exited silently fails
            # (found live: an earlier version of this handler sat outside
            # the `with` and every page.screenshot()/page.content() call
            # in it was swallowed by its own contextlib.suppress, leaving
            # zero failure diagnostics despite "succeeding").
            try:
                stage2_process_orchestration(procs, work_dir, page, ctx)
                stage3_pairing_enrollment_auth(procs, work_dir, page, ctx)
                stage4_5_sealed_handshake_and_consent(procs, work_dir, page, ctx)
                stage6_rekey_revocation_changed_identity(procs, work_dir, page, ctx)
                stage7_restart_recovery_and_storage_check(procs, work_dir, page, ctx)
            except Exception as e:  # noqa: BLE001 - top-level orchestration failure path
                with contextlib.suppress(Exception):
                    page.screenshot(path=str(LOG_DIR / "FAILURE.png"))
                with contextlib.suppress(Exception):
                    (LOG_DIR / "FAILURE.html").write_text(page.content())
                with contextlib.suppress(Exception):
                    storage = page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
                    log(f"localStorage at failure: {json.dumps(storage, indent=2)}")
                browser.close()
                dump_logs_and_die(procs, work_dir, str(e))

            browser.close()
    finally:
        procs.cleanup()

    log("ALL STAGES PASSED")


if __name__ == "__main__":
    main()
