#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$TMP/$label.log" 2>&1; then
    echo "negative validation fixture unexpectedly passed: $label" >&2
    cat "$TMP/$label.log" >&2
    exit 1
  fi
}

# Python syntax validation must fail without leaving ignored bytecode state.
PY_FIXTURE="$TMP/python-syntax"
mkdir -p "$PY_FIXTURE/scripts"
cp "$ROOT/scripts/check-python-syntax.py" "$PY_FIXTURE/scripts/"
printf 'def broken(\n' >"$PY_FIXTURE/scripts/broken.py"
expect_failure python-syntax python3 -B "$PY_FIXTURE/scripts/check-python-syntax.py" "$PY_FIXTURE"
if find "$PY_FIXTURE" \( -type d -name __pycache__ -o -type f -name '*.pyc' \) -print -quit | grep -q .; then
  echo "Python syntax validation created bytecode state" >&2
  exit 1
fi

# Shell syntax validation must reject malformed automation.
SH_FIXTURE="$TMP/shell-syntax"
mkdir -p "$SH_FIXTURE/scripts"
cp "$ROOT/scripts/check-shell-syntax.py" "$SH_FIXTURE/scripts/"
printf '#!/usr/bin/env bash\nif true; then\n' >"$SH_FIXTURE/scripts/broken.sh"
expect_failure shell-syntax python3 -B "$SH_FIXTURE/scripts/check-shell-syntax.py" "$SH_FIXTURE"

# Timeout cleanup must terminate the whole child process group.
PID_FILE="$TMP/timed-child.pid"
set +e
python3 -B "$ROOT/scripts/run-validation-command.py" --timeout-secs 1 -- \
  bash -c 'sleep 30 & child=$!; echo "$child" >"$1"; wait "$child"' _ "$PID_FILE" \
  >"$TMP/timeout.log" 2>&1
status=$?
set -e
if [[ "$status" -ne 124 ]]; then
  echo "validation timeout returned $status instead of 124" >&2
  cat "$TMP/timeout.log" >&2
  exit 1
fi
if [[ ! -s "$PID_FILE" ]]; then
  echo "timeout fixture did not record its child PID" >&2
  exit 1
fi
child_pid="$(cat "$PID_FILE")"
child_state=""
for _ in 1 2 3 4 5; do
  child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d ' ' || true)"
  [[ -z "$child_state" || "$child_state" == Z* ]] && break
  sleep 0.1
done
if [[ -n "$child_state" && "$child_state" != Z* ]]; then
  echo "timed-out validation left a live child process running (state=$child_state)" >&2
  exit 1
fi

# Timeout configuration must reject zero and non-integer values before checks run.
expect_failure zero-timeout env XENIA_VALIDATION_CHECK_TIMEOUT_SECS=0 \
  "$ROOT/scripts/xenia-static-validate.sh" "$ROOT"
expect_failure fractional-timeout env XENIA_VALIDATION_CHECK_TIMEOUT_SECS=0.5 \
  "$ROOT/scripts/xenia-static-validate.sh" "$ROOT"

# Report generation is opt-in and the static wrapper must forward its options.
REPORT_FIXTURE="$TMP/report-mode"
mkdir -p "$REPORT_FIXTURE/scripts"
cp "$ROOT/scripts/xenia-validate.sh" \
  "$ROOT/scripts/xenia-static-validate.sh" \
  "$ROOT/scripts/check-python-syntax.py" \
  "$ROOT/scripts/check-shell-syntax.py" \
  "$ROOT/scripts/run-validation-command.py" \
  "$REPORT_FIXTURE/scripts/"
cat >"$REPORT_FIXTURE/scripts/generate-release-dashboard.py" <<'PY'
#!/usr/bin/env python3
from pathlib import Path
import os
Path(os.environ["XENIA_NEGATIVE_REPORT_MARKER"]).write_text("generated\n")
PY
chmod +x "$REPORT_FIXTURE/scripts/"*
REPORT_MARKER="$TMP/report-generated"
env XENIA_NEGATIVE_REPORT_MARKER="$REPORT_MARKER" \
  "$REPORT_FIXTURE/scripts/xenia-static-validate.sh" "$REPORT_FIXTURE" \
  >"$TMP/report-default.log" 2>&1
if [[ -e "$REPORT_MARKER" ]]; then
  echo "default validation unexpectedly generated advisory reports" >&2
  exit 1
fi
if ! grep -Fq 'release dashboard generation: skipped (use --with-reports)' "$TMP/report-default.log"; then
  echo "default validation did not disclose skipped report generation" >&2
  cat "$TMP/report-default.log" >&2
  exit 1
fi
env XENIA_NEGATIVE_REPORT_MARKER="$REPORT_MARKER" \
  "$REPORT_FIXTURE/scripts/xenia-static-validate.sh" --with-reports "$REPORT_FIXTURE" \
  >"$TMP/report-enabled.log" 2>&1
if [[ ! -f "$REPORT_MARKER" ]]; then
  echo "--with-reports was not forwarded by the static validation wrapper" >&2
  cat "$TMP/report-enabled.log" >&2
  exit 1
fi

echo "validation runtime negative tests: PASS"
