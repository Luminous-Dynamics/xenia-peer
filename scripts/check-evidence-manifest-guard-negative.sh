#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
checker="$root/scripts/check-evidence-manifests.py"
fixture_dir="$root/docs/crypto/fixtures"

if [[ ! -x "$checker" ]]; then
  echo "missing executable evidence manifest checker: $checker" >&2
  exit 1
fi
if [[ ! -d "$fixture_dir" ]]; then
  echo "missing evidence manifest fixture dir: $fixture_dir" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found; cannot run evidence manifest guard negative check" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
sandbox="$tmp/root"
mkdir -p "$sandbox/docs/crypto"
cp -R "$fixture_dir" "$sandbox/docs/crypto/fixtures"

# Baseline copy must still validate before we mutate it.
python3 "$checker" "$sandbox" >/dev/null

unknown_fixture="$sandbox/docs/crypto/fixtures/unregistered-full-pqc.manifest.json"
cp "$sandbox/docs/crypto/fixtures/full-pqc-v1.valid.manifest.json" "$unknown_fixture"
unknown_log="$tmp/unregistered.log"
if python3 "$checker" "$sandbox" >"$unknown_log" 2>&1; then
  cat "$unknown_log" >&2
  echo "evidence manifest checker accepted an unregistered fixture" >&2
  exit 1
fi
if ! grep -q "unexpected unregistered manifest fixtures" "$unknown_log"; then
  cat "$unknown_log" >&2
  echo "evidence manifest checker failed without reporting an unregistered fixture" >&2
  exit 1
fi
rm -f "$unknown_fixture"

missing_fixture="$sandbox/docs/crypto/fixtures/full-pqc-v1.valid.manifest.json"
rm -f "$missing_fixture"
missing_log="$tmp/missing-required.log"
if python3 "$checker" "$sandbox" >"$missing_log" 2>&1; then
  cat "$missing_log" >&2
  echo "evidence manifest checker accepted a missing required fixture" >&2
  exit 1
fi
if ! grep -q "missing required valid manifest fixtures" "$missing_log"; then
  cat "$missing_log" >&2
  echo "evidence manifest checker failed without reporting a missing required fixture" >&2
  exit 1
fi

printf 'evidence manifest guard negative check passed\n'
