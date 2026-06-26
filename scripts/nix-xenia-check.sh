#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
run() {
  echo "+ $*"
  if ! "$@"; then
    fail "command failed: $*"
  fi
}

if [[ ! -f flake.nix ]]; then
  echo "No flake.nix at $PWD; skipping Nix validation."
  exit 0
fi

if ! command -v nix >/dev/null 2>&1; then
  echo "nix not found; install Nix or run this inside a Nix-enabled environment." >&2
  exit 2
fi

run nix flake check --show-trace

if [[ -f scripts/xenia-validate.sh ]]; then
  run nix develop .#ci -c bash scripts/xenia-validate.sh .
fi

if ((failures)); then
  echo "Nix-backed Xenia validation failed with ${failures} failure(s)." >&2
  exit 1
fi

echo "Nix-backed Xenia validation completed."
