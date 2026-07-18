#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

pkg-config --modversion alsa
pkg-config --modversion opus
cargo check --locked -p xenia-peer --features audio-capture
cargo check --locked -p xenia-viewer --features audio-output
cargo test --locked -p xenia-peer-core --features opus
cargo check --locked -p xenia-peer --features audio-opus
cargo check --locked -p xenia-viewer --features audio-opus
scripts/xenia-audio-e2e-smoke.sh . --with-opus
