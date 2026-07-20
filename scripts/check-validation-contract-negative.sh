#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

copy_contract_tree() {
  local dst="$1"
  mkdir -p "$dst/scripts" "$dst/.github/workflows" "$dst/apps" "$dst/crates"
  cp "$ROOT/Cargo.toml" "$ROOT/rust-toolchain.toml" "$ROOT/xenia.features.toml" "$dst/"
  cp "$ROOT/scripts/check-rust-toolchain-contract.py" "$dst/scripts/"
  cp "$ROOT/scripts/check-feature-matrix.py" "$dst/scripts/"
  cp "$ROOT/.github/workflows/"*.yml "$dst/.github/workflows/"
  while IFS= read -r -d '' manifest; do
    relative="${manifest#"$ROOT/"}"
    mkdir -p "$dst/$(dirname "$relative")"
    cp "$manifest" "$dst/$relative"
  done < <(find "$ROOT/apps" "$ROOT/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -print0)
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$TMP/$label.log" 2>&1; then
    echo "negative validation fixture unexpectedly passed: $label" >&2
    cat "$TMP/$label.log" >&2
    exit 1
  fi
}

# A floating channel must never satisfy the declared toolchain contract.
TOOLCHAIN_FIXTURE="$TMP/toolchain"
copy_contract_tree "$TOOLCHAIN_FIXTURE"
sed -i 's/channel = "1.94.0"/channel = "stable"/' "$TOOLCHAIN_FIXTURE/rust-toolchain.toml"
expect_failure toolchain-drift python3 "$TOOLCHAIN_FIXTURE/scripts/check-rust-toolchain-contract.py" "$TOOLCHAIN_FIXTURE"

# A newly introduced Cargo feature must be registered before validation passes.
FEATURE_FIXTURE="$TMP/feature"
copy_contract_tree "$FEATURE_FIXTURE"
cat >>"$FEATURE_FIXTURE/crates/xenia-video/Cargo.toml" <<'EOF_FEATURE'

# Negative validation fixture: intentionally absent from xenia.features.toml.
[package.metadata.xenia-validation-negative]
marker = true
EOF_FEATURE
# Insert into the real [features] table rather than inventing a second table.
python3 - "$FEATURE_FIXTURE/crates/xenia-video/Cargo.toml" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
needle = '[features]\n'
if needle not in text:
    raise SystemExit('xenia-video [features] table not found')
path.write_text(text.replace(needle, needle + 'validation-negative-fixture = []\n', 1))
PY
expect_failure feature-registration python3 "$FEATURE_FIXTURE/scripts/check-feature-matrix.py" "$FEATURE_FIXTURE"

# Registered CI evidence must point to a command that still exists.
EVIDENCE_FIXTURE="$TMP/evidence"
copy_contract_tree "$EVIDENCE_FIXTURE"
python3 - "$EVIDENCE_FIXTURE/.github/workflows/ci.yml" <<'PY_EVIDENCE'
from pathlib import Path
import sys
path = Path(sys.argv[1])
lines = path.read_text().splitlines()
filtered = [line for line in lines if "cargo check --locked -p xenia-peer   --features hdc" not in line]
if len(filtered) == len(lines):
    raise SystemExit("HDC evidence command not found")
path.write_text("\n".join(filtered) + "\n")
PY_EVIDENCE
expect_failure feature-evidence python3 "$EVIDENCE_FIXTURE/scripts/check-feature-matrix.py" "$EVIDENCE_FIXTURE"

# Full validation cannot claim success when the Rust executable path is absent;
# the explicitly named static mode must remain available for diagnostics.
RUST_FIXTURE="$TMP/missing-rust"
mkdir -p "$RUST_FIXTURE/scripts" "$RUST_FIXTURE/.github/workflows"
cp "$ROOT/Cargo.toml" "$ROOT/rust-toolchain.toml" "$RUST_FIXTURE/"
cp "$ROOT/scripts/xenia-validate.sh" "$ROOT/scripts/xenia-static-validate.sh" \
  "$ROOT/scripts/check-rust-toolchain-contract.py" \
  "$ROOT/scripts/check-python-syntax.py" \
  "$ROOT/scripts/check-shell-syntax.py" \
  "$ROOT/scripts/run-validation-command.py" \
  "$RUST_FIXTURE/scripts/"
cp "$ROOT/.github/workflows/ci.yml" "$RUST_FIXTURE/.github/workflows/"
expect_failure missing-rust env PATH=/usr/bin:/bin \
  "$RUST_FIXTURE/scripts/xenia-validate.sh" --require-rust "$RUST_FIXTURE"
env PATH=/usr/bin:/bin "$RUST_FIXTURE/scripts/xenia-static-validate.sh" "$RUST_FIXTURE" \
  >"$TMP/static-only.log" 2>&1
if ! grep -Fq 'Rust compilation and tests were NOT run' "$TMP/static-only.log"; then
  echo "static validation did not disclose its non-compiling scope" >&2
  cat "$TMP/static-only.log" >&2
  exit 1
fi

echo "validation contract negative tests: PASS"
