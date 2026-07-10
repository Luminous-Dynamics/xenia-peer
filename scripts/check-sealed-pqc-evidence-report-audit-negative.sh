#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
checker="$root/scripts/check-sealed-pqc-evidence-report-audit.sh"

if [[ ! -x "$checker" ]]; then
  echo "missing executable sealed PQC evidence report audit checker: $checker" >&2
  exit 1
fi

tmp="${TMPDIR:-/tmp}/xenia-sealed-pqc-report-audit-negative.$$"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

make_fixture() {
  local dst="$1"
  mkdir -p "$dst/apps/xenia-peer/src" "$dst/docs/crypto" "$dst/scripts"
  cp "$root/apps/xenia-peer/src/main.rs" "$dst/apps/xenia-peer/src/main.rs"
  cp "$root/apps/xenia-peer/src/m1_runtime.rs" "$dst/apps/xenia-peer/src/m1_runtime.rs"
  cp "$root/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md" "$dst/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md"
  cp "$root/docs/crypto/FULL_PQC_SEALED_EVIDENCE_ARTIFACTS.md" "$dst/docs/crypto/FULL_PQC_SEALED_EVIDENCE_ARTIFACTS.md"
  cp "$root/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md" "$dst/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md"
  cp "$checker" "$dst/scripts/check-sealed-pqc-evidence-report-audit.sh"
  chmod +x "$dst/scripts/check-sealed-pqc-evidence-report-audit.sh"
}

expect_fail() {
  local fixture="$1"
  local label="$2"
  if "$fixture/scripts/check-sealed-pqc-evidence-report-audit.sh" "$fixture" >"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "sealed PQC evidence report audit checker accepted invalid fixture: $label" >&2
    exit 1
  fi
}

case1="$tmp/no-write-cli"
make_fixture "$case1"
python3 - "$case1/apps/xenia-peer/src/main.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('--write-sealed-evidence-report', '--write-sealed-report-removed'))
PY
expect_fail "$case1" "sealed report write CLI flag removed"

case2="$tmp/no-audit-cli"
make_fixture "$case2"
python3 - "$case2/apps/xenia-peer/src/main.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('--audit-sealed-evidence-report', '--audit-sealed-report-removed'))
PY
expect_fail "$case2" "sealed report audit CLI flag removed"

case3="$tmp/no-runtime-audit"
make_fixture "$case3"
python3 - "$case3/apps/xenia-peer/src/m1_runtime.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('audit_sealed_evidence_verification_report_artifacts_dir', 'audit_sealed_removed'))
PY
expect_fail "$case3" "sealed runtime audit function removed"

case4="$tmp/no-mismatch-refusal"
make_fixture "$case4"
python3 - "$case4/apps/xenia-peer/src/m1_runtime.rs" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('sealed verification_report artifact digests do not match', 'sealed digest mismatch refusal removed'))
PY
expect_fail "$case4" "sealed digest mismatch refusal removed"

case5="$tmp/no-doc-boundary"
make_fixture "$case5"
python3 - "$case5/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md" <<'PY'
from pathlib import Path
path = Path(__import__('sys').argv[1])
text = path.read_text()
path.write_text(text.replace('does **not** replace signature verification', 'signature verification boundary removed'))
PY
expect_fail "$case5" "sealed report documentation boundary removed"

printf 'sealed PQC evidence report audit negative check passed (5 cases)\n'
