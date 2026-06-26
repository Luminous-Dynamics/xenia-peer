#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/export-source-archive.sh [ROOT] [OUT]

Creates a source-only tarball while excluding build output, nested VCS state,
previous archives, local editor files, and generated web/pkg artifacts.

Examples:
  scripts/export-source-archive.sh . /tmp/xenia-source.tar.gz
  scripts/export-source-archive.sh xenia-wire /tmp/xenia-wire-source.tar.gz
USAGE
}

root="${1:-.}"
out="${2:-xenia-source-$(date +%F).tar.gz}"

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

if [[ ! -d "$root" ]]; then
  echo "error: root directory does not exist: $root" >&2
  exit 2
fi

mkdir -p "$(dirname "$out")"
root_name="$(basename "$(cd "$root" && pwd)")"
parent="$(dirname "$(cd "$root" && pwd)")"

# Use tar from the parent so the archive has a stable top-level directory.
tar -C "$parent" -czf "$out" \
  --exclude='.git' \
  --exclude='.github/workflows/*.log' \
  --exclude='target' \
  --exclude='*/target' \
  --exclude='dist' \
  --exclude='*/dist' \
  --exclude='pkg' \
  --exclude='*/pkg' \
  --exclude='node_modules' \
  --exclude='*/node_modules' \
  --exclude='_archive' \
  --exclude='*/_archive' \
  --exclude='*.tar.gz' \
  --exclude='*.tgz' \
  --exclude='*.zip' \
  --exclude='.claude' \
  --exclude='*/.claude' \
  --exclude='.DS_Store' \
  "$root_name"

echo "wrote: $out"
echo "archive size: $(du -h "$out" | awk '{print $1}')"

if [[ -x "$root/scripts/check-source-archive.sh" ]]; then
  "$root/scripts/check-source-archive.sh" "$out"
elif [[ -x "scripts/check-source-archive.sh" ]]; then
  scripts/check-source-archive.sh "$out"
else
  echo "warning: scripts/check-source-archive.sh not found; archive not post-validated" >&2
fi
