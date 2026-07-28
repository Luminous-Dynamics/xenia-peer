#!/usr/bin/env bash
set -euo pipefail

# Regression test for the pre-authentication denial of service documented as
# F1 in docs/roadmap/XENIA_COMPREHENSIVE_REVIEW_2026-07-28.md.
#
# The property under test, stated plainly:
#
#   A peer that connects and never completes the handshake must not prevent a
#   legitimate viewer from obtaining a session.
#
# Before the fix, the daemon called accept_transport() exactly once (not in a
# loop) and awaited the handshake with no timeout, bottoming out in a
# read_exact with no read deadline. So a single idle TCP socket parked the
# daemon's only session slot permanently -- a remote, unauthenticated,
# trivially-triggered DoS costing the attacker nothing but an open fd.
#
# Two things had to be true to fix it, and this script fails if either
# regresses:
#
#   1. the handshake carries a deadline (--handshake-timeout-secs), and
#   2. the daemon goes back and accepts the *next* peer afterwards.
#
# A deadline without the retry would only convert a silent hang into an exit,
# which is still a denial of service. So the assertion here is deliberately
# end-to-end -- a real viewer must complete a real verified session -- rather
# than just grepping for a timeout log line.
#
# The stalled connection is held open for the entire run, not closed early, so
# this genuinely tests recovery-while-occupied rather than recovery-after-the-
# attacker-gives-up.
#
# Cheap by design (loopback only, no namespaces, no privileges, no compositor),
# so it belongs on every CI invocation alongside the Tier 0 chaos smoke.

export NO_COLOR=1

ROOT="${1:-.}"
cd "$ROOT"
ROOT="$(pwd)"

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
case "$TARGET_DIR" in
  /*) ;;
  *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac

LOG_DIR="${XENIA_STALLED_PEER_LOG_DIR:-/tmp/xenia-stalled-peer-smoke}"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

PEER_BIN="$TARGET_DIR/debug/xenia-peer"
VIEWER_BIN="$TARGET_DIR/debug/xenia-viewer"

# Short enough to keep the test fast, long enough that a loaded CI box does
# not trip it spuriously for a *legitimate* peer.
HANDSHAKE_TIMEOUT_SECS=5
FRAMES=8

# Always build rather than skipping when the binaries merely exist: a
# xenia-peer built without `preprod-fixtures` still *accepts*
# --m1-preprod-auto-consent on the command line and only refuses it at
# runtime, so a stale binary from an unrelated build would fail this test
# with a misleading consent error instead of the availability result it is
# supposed to report. Cargo is a no-op when everything is already current.
echo "==> building xenia-peer + xenia-viewer (preprod-fixtures for auto-consent)" >&2
cargo build --locked -p xenia-peer -p xenia-viewer \
  --features "xenia-peer/preprod-fixtures" >/dev/null

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Waits for the daemon's listener by inspecting the socket table, NOT by
# opening a probe connection.
#
# Two reasons to avoid a probe here. A throwaway connection is itself accepted
# by the daemon as a peer (the network-chaos smoke script's comments record a
# probe crashing the single-session daemon for exactly this reason), so it
# would burn an accept cycle and muddy what this test asserts. And a failed
# `exec 9<>/dev/tcp/...` is a redirection failure, which a non-interactive
# shell may treat as fatal rather than as a value we can retry on -- so the
# real connection below must only be attempted once we know it will succeed.
wait_for_listen() {
  local port="$1" i
  for i in $(seq 1 100); do
    if ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_log() {
  local file="$1" pattern="$2" i
  for i in $(seq 1 "$3"); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

cleanup() {
  # Release the stalled socket first so the daemon isn't wedged on shutdown.
  exec 9<&- 2>/dev/null || true
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

LISTEN_PORT="$(pick_port)"
ADMIN_PORT="$(pick_port)"
CONSENT_PORT="$(pick_port)"
PEER_LOG="$LOG_DIR/peer.log"
VIEWER_LOG="$LOG_DIR/viewer.log"
STATE_DIR="$LOG_DIR/state"
mkdir -p "$STATE_DIR"

echo "==> starting daemon (handshake deadline ${HANDSHAKE_TIMEOUT_SECS}s)"
RUST_LOG="${RUST_LOG:-info}" "$PEER_BIN" \
  --transport tcp \
  --listen "127.0.0.1:${LISTEN_PORT}" \
  --admin-port "$ADMIN_PORT" \
  --consent-port "$CONSENT_PORT" \
  --handshake-timeout-secs "$HANDSHAKE_TIMEOUT_SECS" \
  --frames "$FRAMES" \
  --fps 30 \
  --codec passthrough \
  --telemetry-level off \
  --m1-preprod-auto-consent \
  --operator-key-path "$STATE_DIR/operator.key" \
  --consent-ledger-path "$STATE_DIR/consent.ledger" \
  --m1-consent-key-path "$STATE_DIR/consent-ledger.key" \
  --host-identity-key-path "$STATE_DIR/host-identity.key" \
  --http-auth-ml-dsa-key-path "$STATE_DIR/operator-http-ml-dsa.key" \
  >"$PEER_LOG" 2>&1 &
DAEMON_PID="$!"

# The attack: connect, send nothing at all, and hold the socket open. fd 9
# stays open for the rest of the script -- the stalled peer never goes away.
echo "==> opening a stalled peer connection (connects, sends nothing, holds)"
if ! wait_for_listen "$LISTEN_PORT"; then
  echo "FAIL: daemon never listened on ${LISTEN_PORT}" >&2
  tail -40 "$PEER_LOG" >&2 || true
  exit 1
fi
exec 9<>"/dev/tcp/127.0.0.1/${LISTEN_PORT}"

# The daemon must notice and move on. Allow generous wall-clock slack over the
# deadline itself: this box is routinely under heavy multi-session load.
if ! wait_for_log "$PEER_LOG" "did not complete the handshake before the deadline" 150; then
  echo "FAIL: daemon did not time out the stalled peer within ~30s." >&2
  echo "      This is the F1 regression: the handshake has no deadline." >&2
  tail -40 "$PEER_LOG" >&2 || true
  exit 1
fi
echo "    daemon dropped the stalled peer"

# The log line is emitted just before the daemon re-enters accept_transport,
# which rebinds the listener. That leaves a sub-millisecond window where a
# connect would be refused; settle briefly so a spurious ECONNREFUSED isn't
# misreported as the regression this script exists to catch.
sleep 0.5

# The real assertion: a legitimate viewer still gets a full verified session
# while the stalled peer is *still connected*.
echo "==> connecting a real viewer (stalled peer still attached)"
if ! timeout 120 "$VIEWER_BIN" \
  --connect "127.0.0.1:${LISTEN_PORT}" \
  --frames "$FRAMES" \
  --codec passthrough \
  --verify \
  >"$VIEWER_LOG" 2>&1; then
  echo "FAIL: viewer could not complete a session after a stalled peer." >&2
  echo "      This is the F1 regression: the daemon accepts only once, so an" >&2
  echo "      unauthenticated peer permanently occupies the session slot." >&2
  echo "--- peer log ---" >&2; tail -40 "$PEER_LOG" >&2 || true
  echo "--- viewer log ---" >&2; tail -40 "$VIEWER_LOG" >&2 || true
  exit 1
fi

echo "PASS: stalled peer was dropped and a real viewer completed ${FRAMES} verified frames"
