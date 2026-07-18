#!/usr/bin/env bash
set -euo pipefail

# Item 6 of docs/security/POST_DELEGATION_HARDENING_PLAN.md: the real
# browser-driven vertical slice. Builds the real xenia-peer daemon,
# xenia-operator-agent, xenia-viewer, and the compiled sovereign-admin
# console, then hands off to the Python driver
# (scripts/e2e/vertical_slice.py), which owns process orchestration
# (pexpect-driven agent PTY, subprocess-managed daemon/viewer/static
# server) and the Playwright browser automation. Run this inside
# `nix develop .#e2e` (or via `nix run .#e2e`), which provides Playwright's
# browser binaries + pexpect.
#
# Deliberately mirrors scripts/xenia-audio-e2e-smoke.sh's conventions
# (NO_COLOR for clean log greps, LOG_DIR override, build-then-run shape)
# rather than inventing new ones. NO_COLOR is NOT exported script-wide --
# scripts/e2e/vertical_slice.py sets it per-subprocess for the daemon/
# agent/viewer processes it spawns (where tracing_subscriber just checks
# for its presence), but `trunk` binds its own `--no-color` clap arg to
# the same env var and requires a literal "true"/"false" value, not "1" --
# exporting NO_COLOR=1 here breaks `trunk build` with "invalid value '1'
# for '--no-color'".

ROOT="${1:-.}"
cd "$ROOT"
ROOT="$(pwd)"

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
LOG_DIR="${XENIA_E2E_LOG_DIR:-/tmp/xenia-e2e-vertical-slice}"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

echo "=== building xenia-peer, xenia-operator-agent, xenia-viewer ===" >&2
cargo build --locked -p xenia-peer -p xenia-operator-agent -p xenia-viewer >&2

echo "=== building sovereign-admin console (trunk) ===" >&2
(cd apps/sovereign-admin && trunk build) >&2

export XENIA_E2E_ROOT="$ROOT"
export XENIA_E2E_TARGET_DIR="$TARGET_DIR"
export XENIA_E2E_LOG_DIR="$LOG_DIR"
export XENIA_E2E_DIST_DIR="$ROOT/apps/sovereign-admin/dist"

echo "=== running Playwright vertical-slice driver ===" >&2
exec python3 "$ROOT/scripts/e2e/vertical_slice.py"
