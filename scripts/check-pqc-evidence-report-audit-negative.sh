#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
checker="$root/scripts/check-pqc-evidence-report-audit.sh"

if [[ ! -x "$checker" ]]; then
  echo "missing executable PQC evidence report audit checker: $checker" >&2
  exit 1
fi

tmp="${TMPDIR:-/tmp}/xenia-pqc-report-audit-negative.$$"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

make_fixture() {
  local dst="$1"
  mkdir -p "$dst/apps/xenia-peer/src" "$dst/docs/crypto" "$dst/scripts"
  cp "$root/apps/xenia-peer/src/main.rs" "$dst/apps/xenia-peer/src/main.rs"
  cp "$root/apps/xenia-peer/src/m1_runtime.rs" "$dst/apps/xenia-peer/src/m1_runtime.rs"
  cp "$root/docs/crypto/PQC_EVIDENCE_REPORT_AUDIT.md" "$dst/docs/crypto/PQC_EVIDENCE_REPORT_AUDIT.md"
  cp "$checker" "$dst/scripts/check-pqc-evidence-report-audit.sh"
  chmod +x "$dst/scripts/check-pqc-evidence-report-audit.sh"
}

expect_fail() {
  local fixture="$1"
  local label="$2"
  if "$fixture/scripts/check-pqc-evidence-report-audit.sh" "$fixture" >"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "PQC evidence report audit checker accepted invalid fixture: $label" >&2
    exit 1
  fi
}

case1="$tmp/no-cli"
make_fixture "$case1"
python3 - "$case1/apps/xenia-peer/src/main.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('--audit-evidence-report', '--audit-report-removed'))
PY
expect_fail "$case1" "CLI audit flag removed"

case2="$tmp/no-runtime-audit"
make_fixture "$case2"
python3 - "$case2/apps/xenia-peer/src/m1_runtime.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('audit_evidence_verification_report_artifacts_dir', 'audit_removed'))
PY
expect_fail "$case2" "runtime audit function removed"

case3="$tmp/no-mismatch-refusal"
make_fixture "$case3"
python3 - "$case3/apps/xenia-peer/src/m1_runtime.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('verification_report artifact digests do not match', 'digest mismatch refusal removed'))
PY
expect_fail "$case3" "digest mismatch refusal removed"

case4="$tmp/no-doc-boundary"
make_fixture "$case4"
python3 - "$case4/docs/crypto/PQC_EVIDENCE_REPORT_AUDIT.md" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('does **not** replace signature verification', 'signature verification boundary removed'))
PY
expect_fail "$case4" "signature verification boundary removed"

printf 'PQC evidence report audit negative check passed (4 cases)\n'
