#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
EVIDENCE="${1:-$ROOT/qualification-evidence}"
mkdir -p "$EVIDENCE"
LOG="$EVIDENCE/production-crash-surface.txt"
BUILD_LOG="$EVIDENCE/logs-production-crash-probe-build.txt"
: > "$LOG"

refresh_manifest() {
  (
    cd "$EVIDENCE"
    find . -type f ! -name EVIDENCE.sha256 -print0 \
      | sort -z \
      | xargs -0 -r sha256sum \
      > EVIDENCE.sha256
  )
}
trap refresh_manifest EXIT

{
  echo 'PRODUCTION_CRASH_SURFACE_SCHEMA=xenia-sqlite-v2-production-crash-surface-v1'
  echo 'EXPECTED_DEFAULT_FEATURES=none'
  echo 'EXPECTED_CRASH_PROBE_REQUIRES_FEATURE=crash-injection'
} >> "$LOG"

# An explicitly requested crash probe must not be buildable under the production feature set.
# Require the diagnostic to identify the exact target and required feature so an unrelated
# compiler error cannot masquerade as successful feature-gate evidence.
set +e
cargo build --locked --no-default-features --bin store_crash_probe >"$BUILD_LOG" 2>&1
probe_rc=$?
set -e
printf 'NO_FEATURE_CRASH_PROBE_BUILD_RC=%s\n' "$probe_rc" >> "$LOG"
if [[ "$probe_rc" -eq 0 ]]; then
  echo 'FAIL: store_crash_probe built without crash-injection feature' >> "$LOG"
  exit 1
fi
grep -F 'store_crash_probe' "$BUILD_LOG" >/dev/null || {
  echo 'FAIL: no-feature build failure did not identify store_crash_probe' >> "$LOG"
  exit 1
}
grep -F 'crash-injection' "$BUILD_LOG" >/dev/null || {
  echo 'FAIL: no-feature build failure did not identify required crash-injection feature' >> "$LOG"
  exit 1
}

# Optimized ordinary binaries link the production library surface. The environment-variable
# controls must not survive cfg-elimination into those binaries.
cargo build --locked --release --no-default-features \
  --bin store_lock_probe --bin sqlite_profile_probe

for binary in target/release/store_lock_probe target/release/sqlite_profile_probe; do
  [[ -x "$binary" ]]
  if strings "$binary" | grep -F 'XENIA_SQLITE_V2_CRASH_AT' >/dev/null; then
    echo "FAIL: crash-point environment variable present in $binary" >> "$LOG"
    exit 1
  fi
  if strings "$binary" | grep -F 'XENIA_SQLITE_V2_COMMIT_WINDOW' >/dev/null; then
    echo "FAIL: commit-window environment variable present in $binary" >> "$LOG"
    exit 1
  fi
  sha256sum "$binary" >> "$LOG"
done

cat >> "$LOG" <<'EOF'
NO_FEATURE_CRASH_PROBE_BUILD=refused-for-required-feature
PRODUCTION_CRASH_ENVIRONMENT_CONTROLS=absent
PRODUCTION_CRASH_SURFACE=PASS
EOF

cat "$LOG"
