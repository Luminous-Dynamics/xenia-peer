#!/usr/bin/env bash
set -euo pipefail

# Tier 0 of the "real-world reliability" test plan (see the session notes
# referenced from ROADMAP.md's next-steps): proves the wire protocol
# tolerates realistic network degradation -- packet loss, latency, jitter,
# reordering -- not just a clean loopback round trip. Every other smoke
# test in this repo (xenia-audio-e2e-smoke.sh, xenia-m1-runtime-smoke.sh)
# runs daemon and viewer on the same 127.0.0.1 with no network conditions
# in between; this is the one that actually degrades the link.
#
# Deliberately does NOT use a VM. Two Linux network namespaces joined by a
# single veth pair give the same genuine two-endpoint separation a 2-VM
# test would, at a fraction of the cost (no boot time, no disk image, no
# QEMU) -- `tc netem` on the veth interfaces injects the chaos. This is
# Tier 0 specifically because of that cost profile: cheap enough to run on
# every CI invocation. Tier 1 (genuine multi-host nixosTest scenarios --
# daemon restart, NAT-style address change, hundreds of reconnect cycles)
# is a separate, heavier follow-up, not this script.
#
# Requires CAP_NET_ADMIN (passwordless sudo covers this on a normal dev
# box and on GitHub Actions' ubuntu-latest runners without extra
# configuration). Fails loud with a clear message if unavailable, rather
# than silently skipping -- matching this repo's fail-closed conventions
# elsewhere (see e.g. operator_revocations.rs's reload() fix).

export NO_COLOR=1

ROOT="${1:-.}"
cd "$ROOT"
ROOT="$(pwd)"

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
# Must be absolute: `sudo ip netns exec` invokes the binary path verbatim,
# not resolved against this script's CWD the way a plain subshell would.
case "$TARGET_DIR" in
  /*) ;;
  *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac
LOG_DIR="${XENIA_CHAOS_SMOKE_LOG_DIR:-/tmp/xenia-network-chaos-smoke}"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

PEER_BIN="$TARGET_DIR/debug/xenia-peer"
VIEWER_BIN="$TARGET_DIR/debug/xenia-viewer"

DAEMON_NS="xenia-chaos-daemon"
VIEWER_NS="xenia-chaos-viewer"
VETH_DAEMON="xchaos-d0"
VETH_VIEWER="xchaos-v0"
DAEMON_IP="10.99.0.1"
VIEWER_IP="10.99.0.2"
LISTEN_PORT=17890

require_tools() {
  local missing=()
  for tool in ip tc sudo; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "missing required tools: ${missing[*]}" >&2
    exit 1
  fi
  if ! sudo -n true 2>/dev/null; then
    echo "passwordless sudo is required for network-namespace setup (ip netns/tc need CAP_NET_ADMIN)." >&2
    echo "on GitHub Actions ubuntu-latest this works with no extra config; locally, configure passwordless sudo or run as a user who has it." >&2
    exit 1
  fi
}

build_binaries() {
  echo "=== building xenia-peer, xenia-viewer (preprod-fixtures for --m1-preprod-auto-consent) ===" >&2
  cargo build --locked -p xenia-peer -p xenia-viewer --features "xenia-peer/preprod-fixtures" >&2
}

teardown_netns() {
  # Idempotent: never fails the script if things are already gone.
  sudo ip netns del "$VIEWER_NS" >/dev/null 2>&1 || true
  sudo ip netns del "$DAEMON_NS" >/dev/null 2>&1 || true
  sudo ip link del "$VETH_DAEMON" >/dev/null 2>&1 || true
}

setup_netns() {
  teardown_netns
  sudo ip netns add "$DAEMON_NS"
  sudo ip netns add "$VIEWER_NS"
  sudo ip link add "$VETH_DAEMON" type veth peer name "$VETH_VIEWER"
  sudo ip link set "$VETH_DAEMON" netns "$DAEMON_NS"
  sudo ip link set "$VETH_VIEWER" netns "$VIEWER_NS"
  sudo ip netns exec "$DAEMON_NS" ip addr add "${DAEMON_IP}/30" dev "$VETH_DAEMON"
  sudo ip netns exec "$VIEWER_NS" ip addr add "${VIEWER_IP}/30" dev "$VETH_VIEWER"
  sudo ip netns exec "$DAEMON_NS" ip link set "$VETH_DAEMON" up
  sudo ip netns exec "$VIEWER_NS" ip link set "$VETH_VIEWER" up
  sudo ip netns exec "$DAEMON_NS" ip link set lo up
  sudo ip netns exec "$VIEWER_NS" ip link set lo up
}

# Applies the same netem profile to both ends of the veth pair so chaos
# hits data (daemon -> viewer) and acks/control (viewer -> daemon) alike --
# a real link degrades both directions, and netem is egress-only per
# interface, so this needs setting on both sides, not just one.
apply_netem() {
  local profile="$1"
  sudo ip netns exec "$DAEMON_NS" tc qdisc add dev "$VETH_DAEMON" root netem $profile
  sudo ip netns exec "$VIEWER_NS" tc qdisc add dev "$VETH_VIEWER" root netem $profile
}

clear_netem() {
  sudo ip netns exec "$DAEMON_NS" tc qdisc del dev "$VETH_DAEMON" root >/dev/null 2>&1 || true
  sudo ip netns exec "$VIEWER_NS" tc qdisc del dev "$VETH_VIEWER" root >/dev/null 2>&1 || true
}

wait_for_tcp_listen_in_ns() {
  # Must NOT actually connect() -- xenia-peer accepts the first inbound
  # TCP connection as a real client and starts handshaking it. A probe
  # connection followed by an immediate close looks to the daemon exactly
  # like a client that vanished mid-handshake (BrokenPipe), and this
  # single-session daemon then exits -- so the real viewer that connects
  # right after finds nothing listening. Read /proc/net/tcp's LISTEN
  # (state 0A) entries instead, mirroring xenia-audio-e2e-smoke.sh's
  # wait_for_tcp_listen, just executed inside the namespace so it sees
  # that namespace's socket table.
  local ns="$1" port="$2"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if sudo ip netns exec "$ns" python3 -c "
import sys
want = f'{${port}:04X}'
for path in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
        lines = open(path, 'r', encoding='utf-8').read().splitlines()[1:]
    except FileNotFoundError:
        continue
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            port_hex = parts[1].rsplit(':', 1)[1].upper()
        except IndexError:
            continue
        if port_hex == want and parts[3] == '0A':
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for daemon to listen on ${DAEMON_IP}:${port}" >&2
  return 1
}

cleanup_pid() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  sudo kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
}

# Runs one full daemon+viewer session under `$1` (a human label) with
# netem profile already applied to both veth ends. `$2` is a generous
# per-attempt timeout in seconds -- degraded profiles need real slack for
# TCP retransmission, not just clean-network latency. `$3` is the frame
# count: kept low under harsher profiles not to weaken the proof (every
# frame that arrives is still byte-verified against the mirror) but to
# bound wall-clock time -- passthrough's uncompressed ~256 KB/frame
# genuinely takes tens of seconds per frame to retransmit-complete under
# double-digit loss, a real, disclosed characteristic this test surfaced,
# not a harness bug (an earlier draft asked for 8 frames at 15% loss +
# 200ms latency and the *protocol* was still byte-correct, just needed
# far more than 90s to prove it for that many frames).
run_profile() {
  local label="$1" timeout_secs="$2" frames="${3:-8}"
  local peer_log="$LOG_DIR/${label}-peer.log"
  local viewer_log="$LOG_DIR/${label}-viewer.log"
  # The daemon runs as root inside its netns (sudo ip netns exec), so
  # everything it writes -- state dir included -- is root-owned. Scope it
  # under $LOG_DIR (already wiped wholesale at script start, and never the
  # repo working tree) rather than the default relative xenia-peer-state/,
  # which would otherwise leave root-owned cruft in the repo root that a
  # plain `rm -rf` from an unprivileged shell can't even remove.
  local state_dir="$LOG_DIR/${label}-state"
  mkdir -p "$state_dir"
  rm -f "$peer_log" "$viewer_log"

  echo "=== profile: $label ===" >&2

  sudo ip netns exec "$DAEMON_NS" env RUST_LOG="${RUST_LOG:-info}" "$PEER_BIN" \
    --transport tcp \
    --listen "${DAEMON_IP}:${LISTEN_PORT}" \
    --admin-port 0 \
    --consent-port 0 \
    --frames "$((frames + 4))" \
    --fps 30 \
    --telemetry-level off \
    --m1-preprod-auto-consent \
    --operator-key-path "$state_dir/operator.key" \
    --consent-ledger-path "$state_dir/consent.ledger" \
    --m1-consent-key-path "$state_dir/consent-ledger.key" \
    --host-identity-key-path "$state_dir/host-identity.key" \
    --http-auth-ml-dsa-key-path "$state_dir/operator-http-ml-dsa.key" \
    >"$peer_log" 2>&1 &
  local daemon_pid="$!"
  trap 'cleanup_pid "$daemon_pid"' RETURN

  if ! wait_for_tcp_listen_in_ns "$DAEMON_NS" "$LISTEN_PORT"; then
    echo "--- $peer_log ---" >&2
    cat "$peer_log" >&2 || true
    return 1
  fi

  if ! sudo timeout "$timeout_secs" ip netns exec "$VIEWER_NS" "$VIEWER_BIN" \
    --transport tcp \
    --connect "${DAEMON_IP}:${LISTEN_PORT}" \
    --frames "$frames" \
    --codec passthrough \
    --verify \
    >"$viewer_log" 2>&1; then
    echo "--- $peer_log ---" >&2
    cat "$peer_log" >&2 || true
    echo "--- $viewer_log ---" >&2
    cat "$viewer_log" >&2 || true
    return 1
  fi

  wait "$daemon_pid" 2>/dev/null || true
  daemon_pid=""
  trap - RETURN

  if grep -qiE 'verify.*fail|mismatch|panic' "$viewer_log"; then
    echo "verification failure detected in $viewer_log under profile '$label':" >&2
    grep -iE 'verify.*fail|mismatch|panic' "$viewer_log" >&2
    return 1
  fi

  echo "profile '$label': OK" >&2
}

main() {
  require_tools
  build_binaries
  trap teardown_netns EXIT
  setup_netns

  local failures=0

  # Baseline: no chaos at all. If this fails, the harness itself (netns +
  # veth wiring) is broken, not the protocol -- fix that before trusting
  # any of the chaos profiles below.
  run_profile "baseline" 30 8 || failures=$((failures + 1))

  clear_netem
  apply_netem "delay 20ms loss 1%"
  run_profile "light" 45 8 || failures=$((failures + 1))

  clear_netem
  apply_netem "delay 80ms 20ms distribution normal loss 5% reorder 1%"
  run_profile "moderate" 60 6 || failures=$((failures + 1))

  # Deliberately gentler than the first draft (was 15% loss / 200ms):
  # tc netem's loss is randomized per-packet, and passthrough's
  # uncompressed ~256 KB/frame means a single frame is ~180 TCP segments
  # -- at 15% per-segment loss the odds of a frame completing without a
  # retransmission are near zero, so completion time swings wildly run to
  # run (observed anywhere from ~5s to well over 90s for the same
  # profile). That's a real, useful finding about passthrough's viability
  # under a genuinely bad link, but it makes a *tight* CI timeout an
  # unreliable pass/fail signal, not a meaningful one. 10% loss still
  # meaningfully exceeds real-world worst-case conditions (home wifi
  # congestion ~1-3%, saturated mobile ~5-10%) while keeping completion
  # time bounded enough for a stable CI check.
  clear_netem
  apply_netem "delay 150ms 40ms distribution normal loss 10% reorder 4%"
  run_profile "harsh" 150 2 || failures=$((failures + 1))

  clear_netem

  if [[ "$failures" -ne 0 ]]; then
    echo "$failures profile(s) failed -- see $LOG_DIR for logs" >&2
    exit 1
  fi
  echo "all network-chaos profiles passed" >&2
}

main "$@"
