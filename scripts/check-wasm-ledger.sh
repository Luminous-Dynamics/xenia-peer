#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

cargo check -p xenia-ledger --target wasm32-unknown-unknown
