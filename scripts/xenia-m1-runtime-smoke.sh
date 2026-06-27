#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

output="$(cargo run -p xenia-peer -- --m1-runtime-smoke)"

printf '%s\n' "$output"

expected='M1 runtime smoke passed
entries: 3
consent.requested
consent.granted
consent.revoked'

if [[ "$output" != "$expected" ]]; then
  echo "unexpected M1 runtime smoke output" >&2
  exit 1
fi
