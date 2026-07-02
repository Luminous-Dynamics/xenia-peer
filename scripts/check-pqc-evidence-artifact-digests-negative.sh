#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
checker="$root/scripts/check-pqc-evidence-artifact-digests.sh"

if [[ ! -x "$checker" ]]; then
  echo "missing executable PQC evidence artifact digest checker: $checker" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local fixture="$1"
  mkdir -p \
    "$fixture/apps/xenia-peer/src" \
    "$fixture/apps/xenia-peer" \
    "$fixture/docs/crypto" \
    "$fixture/scripts"
  cp "$root/apps/xenia-peer/Cargo.toml" "$fixture/apps/xenia-peer/Cargo.toml"
  cp "$root/apps/xenia-peer/src/main.rs" "$fixture/apps/xenia-peer/src/main.rs"
  cp "$root/apps/xenia-peer/src/m1_runtime.rs" "$fixture/apps/xenia-peer/src/m1_runtime.rs"
  cp "$root/docs/crypto/PQC_EVIDENCE_ARTIFACT_DIGESTS.md" "$fixture/docs/crypto/PQC_EVIDENCE_ARTIFACT_DIGESTS.md"
  cp "$checker" "$fixture/scripts/check-pqc-evidence-artifact-digests.sh"
  chmod +x "$fixture/scripts/check-pqc-evidence-artifact-digests.sh"
}

expect_pass() {
  local fixture="$1"
  if ! "$fixture/scripts/check-pqc-evidence-artifact-digests.sh" "$fixture" >"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "PQC evidence artifact digest checker rejected valid fixture" >&2
    exit 1
  fi
}

expect_fail() {
  local fixture="$1"
  local label="$2"
  if "$fixture/scripts/check-pqc-evidence-artifact-digests.sh" "$fixture" >"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "PQC evidence artifact digest checker accepted invalid fixture: $label" >&2
    exit 1
  fi
}

valid="$tmp/valid"
make_fixture "$valid"
expect_pass "$valid"

case1="$tmp/no-blake3-dependency"
make_fixture "$case1"
python3 - "$case1/apps/xenia-peer/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('blake3 = "1.5"\n', ''))
PY
expect_fail "$case1" "missing blake3 dependency"

case2="$tmp/no-artifact-set"
make_fixture "$case2"
python3 - "$case2/apps/xenia-peer/src/m1_runtime.rs" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('EvidenceArtifactDigests', 'EvidenceArtifactDigestRemoved'))
PY
expect_fail "$case2" "artifact digest struct removed"

case3="$tmp/no-cli-print"
make_fixture "$case3"
python3 - "$case3/apps/xenia-peer/src/main.rs" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('artifact set blake3', 'artifact set digest removed'))
PY
expect_fail "$case3" "CLI artifact set print removed"

case4="$tmp/no-doc-boundary"
make_fixture "$case4"
python3 - "$case4/docs/crypto/PQC_EVIDENCE_ARTIFACT_DIGESTS.md" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('does not replace signature verification', 'replaces signature verification'))
PY
expect_fail "$case4" "digest documentation boundary removed"

printf 'PQC evidence artifact digest negative check passed (4 cases)\n'
