#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

cargo fmt --check
cargo test --locked -p xenia-peer-core
cargo test --locked -p xenia-transport-ws --test transport_conformance
cargo test --locked -p xenia-transport-quic --test transport_conformance
git diff --check
