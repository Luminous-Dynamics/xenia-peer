#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
checker="$root/scripts/check-pqc-feature-gate.py"

if [[ ! -x "$checker" ]]; then
  echo "missing executable PQC feature-gate checker: $checker" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found; cannot run PQC feature-gate negative check" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local fixture="$1"
  mkdir -p \
    "$fixture/crates/xenia-ledger/src" \
    "$fixture/apps/xenia-peer/src" \
    "$fixture/.github/workflows" \
    "$fixture/scripts"
  cp "$root/crates/xenia-ledger/Cargo.toml" "$fixture/crates/xenia-ledger/Cargo.toml"
  # xenia-ledger/src was split from one lib.rs into focused modules on
  # 2026-07-19 -- copy every source file so the checker (which now
  # concatenates them all) sees the full crate, not just the re-export shell.
  cp "$root/crates/xenia-ledger/src/"*.rs "$fixture/crates/xenia-ledger/src/"
  cp "$root/apps/xenia-peer/Cargo.toml" "$fixture/apps/xenia-peer/Cargo.toml"
  cp "$root/apps/xenia-peer/src/main.rs" "$fixture/apps/xenia-peer/src/main.rs"
  # The evidence-verification surface now lives here (extracted 2026-07-12);
  # the checker reads both files concatenated, so both must be present.
  cp "$root/apps/xenia-peer/src/evidence_verifier.rs" "$fixture/apps/xenia-peer/src/evidence_verifier.rs"
  cp "$root/.github/workflows/xenia-validate.yml" "$fixture/.github/workflows/xenia-validate.yml"
  cp "$checker" "$fixture/scripts/check-pqc-feature-gate.py"
  chmod +x "$fixture/scripts/check-pqc-feature-gate.py"
}

expect_pass() {
  local fixture="$1"
  if ! python3 "$fixture/scripts/check-pqc-feature-gate.py" "$fixture" >/"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "PQC feature-gate checker rejected valid fixture" >&2
    exit 1
  fi
}

expect_fail() {
  local fixture="$1"
  local label="$2"
  if python3 "$fixture/scripts/check-pqc-feature-gate.py" "$fixture" >/"$fixture/check.log" 2>&1; then
    cat "$fixture/check.log" >&2
    echo "PQC feature-gate checker accepted invalid fixture: $label" >&2
    exit 1
  fi
  if ! grep -q "PQC feature gate check failed" "$fixture/check.log"; then
    cat "$fixture/check.log" >&2
    echo "PQC feature-gate checker failed without diagnostic: $label" >&2
    exit 1
  fi
}

valid="$tmp/valid"
make_fixture "$valid"
expect_pass "$valid"

case1="$tmp/ml-dsa-not-optional"
make_fixture "$case1"
python3 - "$case1/crates/xenia-ledger/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('optional = true', 'optional = false'))
PY
expect_fail "$case1" "ml-dsa dependency not optional"

case2="$tmp/feature-missing-dep-link"
make_fixture "$case2"
python3 - "$case2/crates/xenia-ledger/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('pqc-signatures = ["dep:ml-dsa"]', 'pqc-signatures = []'))
PY
expect_fail "$case2" "pqc-signatures feature not linked to dep:ml-dsa"

case3="$tmp/pqc-enabled-by-default"
make_fixture "$case3"
python3 - "$case3/crates/xenia-ledger/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('default = []', 'default = ["pqc-signatures"]'))
PY
expect_fail "$case3" "pqc-signatures enabled by default"

case4="$tmp/missing-ml-dsa-cfg"
make_fixture "$case4"
python3 - "$case4/crates/xenia-ledger/src/signature.rs" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('#[cfg(feature = "pqc-signatures")]\npub struct MlDsa65EvidenceSignatureBackend;', 'pub struct MlDsa65EvidenceSignatureBackend;')
path.write_text(text)
PY
expect_fail "$case4" "ML-DSA backend symbol not cfg-gated"

case5="$tmp/missing-ledger-ci-feature-test"
make_fixture "$case5"
python3 - "$case5/.github/workflows/xenia-validate.yml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('cargo test --locked -p xenia-ledger --features pqc-signatures --lib --no-fail-fast', 'cargo test --locked -p xenia-ledger --lib --no-fail-fast')
path.write_text(text)
PY
expect_fail "$case5" "CI does not test ledger pqc-signatures feature"

case6="$tmp/peer-feature-missing-ledger-link"
make_fixture "$case6"
python3 - "$case6/apps/xenia-peer/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('pqc-signatures = ["xenia-ledger/pqc-signatures"]', 'pqc-signatures = []')
path.write_text(text)
PY
expect_fail "$case6" "xenia-peer feature does not propagate to ledger"

case7="$tmp/peer-missing-suite-selector"
make_fixture "$case7"
python3 - "$case7/apps/xenia-peer/src/main.rs" "$case7/apps/xenia-peer/src/evidence_verifier.rs" <<'PY'
import pathlib, sys
for p in sys.argv[1:]:
    path = pathlib.Path(p)
    text = path.read_text()
    text = text.replace('EvidenceVerifierSuite', 'EvidenceVerifierSuiteRemoved')
    text = text.replace('evidence_signature_suite', 'evidence_signature_suite_removed')
    text = text.replace('verify_evidence_bundle_with_selected_suite', 'verify_evidence_bundle_without_suite_selector')
    path.write_text(text)
PY
expect_fail "$case7" "xenia-peer verifier suite selector removed"

case8="$tmp/peer-ml-dsa-import-not-cfg-gated"
make_fixture "$case8"
python3 - "$case8/apps/xenia-peer/src/main.rs" "$case8/apps/xenia-peer/src/evidence_verifier.rs" <<'PY'
import pathlib, sys
for p in sys.argv[1:]:
    path = pathlib.Path(p)
    text = path.read_text()
    text = text.replace(
        '#[cfg(feature = "pqc-signatures")]\n'
        'use xenia_ledger::{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend};',
        'use xenia_ledger::{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend};',
    )
    path.write_text(text)
PY
expect_fail "$case8" "xenia-peer ML-DSA backend import not cfg-gated"

case9="$tmp/missing-peer-ci-feature-test"
make_fixture "$case9"
python3 - "$case9/.github/workflows/xenia-validate.yml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('cargo test --locked -p xenia-peer --features pqc-signatures --no-fail-fast', 'cargo test --locked -p xenia-peer --no-fail-fast')
path.write_text(text)
PY
expect_fail "$case9" "CI does not test peer pqc-signatures feature"

case10="$tmp/peer-missing-profile-requirement"
make_fixture "$case10"
python3 - "$case10/apps/xenia-peer/src/main.rs" "$case10/apps/xenia-peer/src/evidence_verifier.rs" <<'PY'
import pathlib, sys
for p in sys.argv[1:]:
    path = pathlib.Path(p)
    text = path.read_text()
    text = text.replace('EvidenceProfileRequirement', 'EvidenceProfileRequirementRemoved')
    text = text.replace('require_evidence_profile', 'require_evidence_profile_removed')
    text = text.replace('preflight_evidence_verifier_selection', 'preflight_evidence_verifier_selection_removed')
    path.write_text(text)
PY
expect_fail "$case10" "xenia-peer verifier profile requirement removed"

printf 'PQC feature-gate negative check passed (10 cases)\n'
