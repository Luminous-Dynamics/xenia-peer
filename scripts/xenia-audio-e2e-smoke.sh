#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
WITH_OPUS=0
if [[ "${2:-}" == "--with-opus" ]]; then
  WITH_OPUS=1
fi
cd "$ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
LOG_DIR="${XENIA_AUDIO_SMOKE_LOG_DIR:-/tmp/xenia-audio-e2e-smoke}"
mkdir -p "$LOG_DIR"

PEER_BIN="$TARGET_DIR/debug/xenia-peer"
VIEWER_BIN="$TARGET_DIR/debug/xenia-viewer"

build_binaries() {
  if [[ "$WITH_OPUS" -eq 1 ]]; then
    cargo build -p xenia-peer -p xenia-viewer --features "xenia-peer/audio-opus xenia-viewer/audio-opus xenia-peer/preprod-fixtures" >/dev/null
  else
    cargo build -p xenia-peer -p xenia-viewer --features "xenia-peer/preprod-fixtures" >/dev/null
  fi
}

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_pattern() {
  local pattern="$1"
  local file="$2"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if grep -qE "$pattern" "$file"; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for pattern '$pattern' in $file" >&2
  return 1
}

cleanup_pid() {
  local pid="${1:-}"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

assert_audio_summary() {
  local viewer_log="$1"
  local summary
  summary="$(grep 'audio summary:' "$viewer_log" | tail -1 || true)"
  if [[ -z "$summary" ]]; then
    echo "missing audio summary in $viewer_log" >&2
    return 1
  fi
  SUMMARY="$summary" python3 - <<'PY'
import os
import re
import sys

summary = os.environ["SUMMARY"]
values = {key: int(value) for key, value in re.findall(r"([a-z_]+)=([0-9]+)", summary)}
required = ["decoded", "inserted", "emitted", "played", "samples"]
missing = [key for key in required if key not in values]
if missing:
    print(f"missing audio counters: {missing}: {summary}", file=sys.stderr)
    sys.exit(1)
if values["decoded"] < 2 or values["inserted"] < 2 or values["emitted"] < 1:
    print(f"audio timing counters too low: {summary}", file=sys.stderr)
    sys.exit(1)
if values["played"] < 1 or values["samples"] == 0:
    print(f"audio playback counters too low: {summary}", file=sys.stderr)
    sys.exit(1)
if values.get("duplicates", 0) != 0 or values.get("late", 0) != 0:
    print(f"unexpected duplicate/late frames: {summary}", file=sys.stderr)
    sys.exit(1)
PY
}

assert_no_audio_summary() {
  local viewer_log="$1"
  local summary
  summary="$(grep 'audio summary:' "$viewer_log" | tail -1 || true)"
  if [[ -z "$summary" ]]; then
    echo "missing audio summary in $viewer_log" >&2
    return 1
  fi
  SUMMARY="$summary" python3 - <<'PY'
import os
import re
import sys

summary = os.environ["SUMMARY"]
values = {key: int(value) for key, value in re.findall(r"([a-z_]+)=([0-9]+)", summary)}
if values.get("decoded", -1) != 0 or values.get("played", -1) != 0 or values.get("samples", -1) != 0:
    print(f"audio flowed without consent: {summary}", file=sys.stderr)
    sys.exit(1)
PY
}

dump_logs() {
  local label="$1"
  local peer_log="$2"
  local viewer_log="$3"
  echo "audio e2e smoke failed: $label" >&2
  echo "--- peer log ---" >&2
  tail -80 "$peer_log" >&2 || true
  echo "--- viewer log ---" >&2
  tail -80 "$viewer_log" >&2 || true
}

run_smoke() {
  local transport="$1"
  local audio_codec="$2"
  local listen_port admin_port consent_port peer_log viewer_log connect_arg daemon_pid
  listen_port="$(pick_port)"
  admin_port="$(pick_port)"
  consent_port="$(pick_port)"
  peer_log="$LOG_DIR/${audio_codec}-${transport}-peer.log"
  viewer_log="$LOG_DIR/${audio_codec}-${transport}-viewer.log"
  rm -f "$peer_log" "$viewer_log"

  "$PEER_BIN" \
    --transport "$transport" \
    --listen "127.0.0.1:${listen_port}" \
    --admin-port "$admin_port" \
    --consent-port "$consent_port" \
    --frames 12 \
    --fps 30 \
    --audio sine \
    --audio-codec "$audio_codec" \
    --audio-interval-ms 10 \
    --telemetry-level off \
    --m1-preprod-auto-consent \
    --operator-key-path "$LOG_DIR/${audio_codec}-${transport}-operator.key" \
    >"$peer_log" 2>&1 &
  daemon_pid="$!"
  trap 'cleanup_pid "$daemon_pid"' RETURN
  sleep 2
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    dump_logs "$transport" "$peer_log" "$viewer_log"
    return 1
  fi

  case "$transport" in
    tcp)
      connect_arg="127.0.0.1:${listen_port}"
      ;;
    ws)
      connect_arg="ws://127.0.0.1:${listen_port}"
      ;;
    quic)
      wait_for_pattern 'iroh:' "$peer_log"
      connect_arg="$(grep -o 'iroh:[^[:space:]]*' "$peer_log" | tail -1)"
      ;;
    *)
      echo "unsupported transport: $transport" >&2
      return 1
      ;;
  esac

  if ! "$VIEWER_BIN" \
    --transport "$transport" \
    --connect "$connect_arg" \
    --frames 8 \
    --play-audio synthetic \
    --audio-codec "$audio_codec" \
    >"$viewer_log" 2>&1; then
    dump_logs "$transport" "$peer_log" "$viewer_log"
    return 1
  fi

  wait "$daemon_pid" 2>/dev/null || true
  daemon_pid=""
  trap - RETURN

  if ! assert_audio_summary "$viewer_log"; then
    dump_logs "$transport" "$peer_log" "$viewer_log"
    return 1
  fi
  echo "audio e2e smoke passed: $audio_codec/$transport"
}

run_negative_consent_smoke() {
  local listen_port admin_port consent_port peer_log viewer_log daemon_pid
  listen_port="$(pick_port)"
  admin_port="$(pick_port)"
  consent_port="$(pick_port)"
  peer_log="$LOG_DIR/no-consent-peer.log"
  viewer_log="$LOG_DIR/no-consent-viewer.log"
  rm -f "$peer_log" "$viewer_log"

  "$PEER_BIN" \
    --transport tcp \
    --listen "127.0.0.1:${listen_port}" \
    --admin-port "$admin_port" \
    --consent-port "$consent_port" \
    --frames 4 \
    --fps 30 \
    --audio sine \
    --audio-interval-ms 10 \
    --telemetry-level off \
    --operator-key-path "$LOG_DIR/no-consent-operator.key" \
    >"$peer_log" 2>&1 &
  daemon_pid="$!"
  trap 'cleanup_pid "$daemon_pid"' RETURN
  sleep 2
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    dump_logs "no-consent" "$peer_log" "$viewer_log"
    return 1
  fi

  if ! timeout 15 "$VIEWER_BIN" \
    --transport tcp \
    --connect "127.0.0.1:${listen_port}" \
    --frames 1 \
    --play-audio synthetic \
    >"$viewer_log" 2>&1; then
    dump_logs "no-consent" "$peer_log" "$viewer_log"
    return 1
  fi

  wait "$daemon_pid" 2>/dev/null || true
  daemon_pid=""
  trap - RETURN

  if ! assert_no_audio_summary "$viewer_log"; then
    dump_logs "no-consent" "$peer_log" "$viewer_log"
    return 1
  fi
  if ! grep -qE 'consent|frame flow|M1|preflight|Consent|PermissionDenied|StreamFrame' "$peer_log"; then
    dump_logs "no-consent" "$peer_log" "$viewer_log"
    echo "expected consent/preflight failure evidence in peer log" >&2
    return 1
  fi
  echo "audio negative consent smoke passed"
}

build_binaries

run_smoke tcp raw-pcm
run_smoke ws raw-pcm
run_smoke quic raw-pcm
run_negative_consent_smoke

if [[ "$WITH_OPUS" -eq 1 ]]; then
  run_smoke tcp opus
  run_smoke ws opus
  run_smoke quic opus
fi

echo "xenia audio e2e smoke passed"
