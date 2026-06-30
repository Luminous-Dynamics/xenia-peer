#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

cargo fmt --check
cargo test -p xenia-peer-core
cargo test -p xenia-transport-ws --test transport_conformance
cargo test -p xenia-transport-quic --test transport_conformance
git diff --check
