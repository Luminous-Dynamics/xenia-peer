#!/usr/bin/env bash
set -euo pipefail

# Keep validation/build artifacts outside the repository tree.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/xenia-peer-target}"


ROOT="${1:-.}"
MODE="${2:-full}"
case "$MODE" in
  full|--require-rust) MODE="full" ;;
  static|--static-only) MODE="static" ;;
  *)
    echo "usage: scripts/xenia-hygiene-audit.sh [ROOT] [--require-rust|--static-only]" >&2
    exit 2
    ;;
esac
cd "$ROOT"

failures=0

section() {
  printf '\n== %s ==\n' "$1"
}

fail_if_any() {
  local title="$1"
  shift

  section "$title"

  local tmp
  tmp="$(mktemp)"
  if "$@" > "$tmp"; then
    if [ -s "$tmp" ]; then
      cat "$tmp"
      failures=$((failures + 1))
    else
      echo "clean"
    fi
  else
    if [ -s "$tmp" ]; then
      cat "$tmp"
      failures=$((failures + 1))
    else
      echo "clean"
    fi
  fi
  rm -f "$tmp"
}

warn_if_any() {
  local title="$1"
  shift

  section "$title"

  local tmp
  tmp="$(mktemp)"
  if "$@" > "$tmp"; then
    if [ -s "$tmp" ]; then
      cat "$tmp"
    else
      echo "clean"
    fi
  else
    if [ -s "$tmp" ]; then
      cat "$tmp"
    else
      echo "clean"
    fi
  fi
  rm -f "$tmp"
}

# Hard failures: active generated/source-control artifacts.
fail_if_any "archive bundles in active paths" \
  find . \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    -type f \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' \) -print

fail_if_any "build output directories in active paths" \
  find . \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    -type d \( -name target -o -name dist -o -name build -o -name node_modules \) -print

fail_if_any "Python bytecode caches in active paths" \
  find . \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    \( -type d -name __pycache__ -o -type f \( -name '*.pyc' -o -name '*.pyo' \) \) -print

fail_if_any "migration scratch scripts in active paths" \
  find . \
    -maxdepth 2 \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    -type f \( -name 'fix_transport*.py' -o -name '*scratch*.py' \) -print

# Root .git is expected. Nested .git is not.
fail_if_any "nested git repositories in active paths" \
  find . \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    -type d -name .git -print

# Hard failure only for source/config machine-local paths.
fail_if_any "absolute local workspace references in source/config" \
  rg -n \
    --glob '!*.md' \
    --glob '!scripts/xenia-hygiene-audit.sh' \
    --glob '!_archive/**' \
    --glob '!target/**' \
    --glob '!**/target/**' \
    '/srv/luminous-dynamics|/home/|/mnt/data|tristan\.stoltz@|evolvingresonantcocreationism\.com' .

# Docs are warnings, because docs may intentionally describe forbidden examples.
warn_if_any "absolute local workspace references in docs" \
  rg -n \
    --glob '*.md' \
    --glob '!_archive/**' \
    --glob '!target/**' \
    --glob '!**/target/**' \
    '/srv/luminous-dynamics|/home/|/mnt/data|tristan\.stoltz@|evolvingresonantcocreationism\.com' .

warn_if_any "review markers for humans" \
  rg -n \
    --glob '!_archive/**' \
    --glob '!target/**' \
    --glob '!**/target/**' \
    'DO NOT USE IN PRODUCTION|placeholder|stub|TODO|FIXME' .

fail_if_any "local runtime secret/state files" \
  find . \
    -path './.git' -prune -o \
    -path './_archive' -prune -o \
    -type f \( -name '.env' -o -name '*.pem' -o -name '*.key' -o -name '*.sqlite' -o -name '*.db' \) -print

section "cargo metadata smoke check"
if [[ "$MODE" == "static" ]]; then
  echo "skipped by explicit --static-only mode"
elif command -v cargo >/dev/null 2>&1; then
  cargo metadata --format-version 1 --no-deps >/dev/null
  echo "cargo metadata: ok"
else
  echo "cargo metadata: cargo not found" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo
  echo "Xenia hygiene audit failed. Move historical/build artifacts to _archive and reconcile warnings."
  exit 1
fi

echo
echo "Xenia hygiene audit passed."
