#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

cargo fmt --check
cargo test --locked --workspace
nixpkgs-fmt --check flake.nix
git diff --check
nix flake check
