#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

scripts/xenia-fast-check.sh .
scripts/xenia-audio-check.sh .
nixpkgs-fmt --check flake.nix
git diff --check
nix flake check
