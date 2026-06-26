#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/export-source-archive.sh [ROOT] [OUT]

Creates a deterministic source-only tarball while excluding build output, nested
VCS state, previous archives, local editor files, generated web/pkg artifacts,
and generated archive-checksum evidence that would otherwise create a checksum
cycle.

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

if ! tar --version 2>/dev/null | grep -qi 'gnu tar'; then
  echo "error: reproducible source archives require GNU tar" >&2
  exit 2
fi

mkdir -p "$(dirname "$out")"
root_abs="$(cd "$root" && pwd)"
archive_root_name="${XENIA_ARCHIVE_ROOT_NAME:-xenia-peer}"

# Use deterministic tar metadata and gzip without embedded filename/timestamp.
# The stable top-level directory keeps archives reproducible across local clone
# paths as long as the source tree content is identical.
tar -C "$root_abs" \
  --sort=name \
  --format=gnu \
  --mtime='UTC 1970-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --transform "s#^\.\$#${archive_root_name}#" \
  --transform "s#^\./#${archive_root_name}/#" \
  -cf - \
  --exclude='./.git' \
  --exclude='./.github/workflows/*.log' \
  --exclude='./target' \
  --exclude='./*/target' \
  --exclude='./dist' \
  --exclude='./*/dist' \
  --exclude='./pkg' \
  --exclude='./*/pkg' \
  --exclude='./node_modules' \
  --exclude='./*/node_modules' \
  --exclude='./_archive' \
  --exclude='./*/_archive' \
  --exclude='./*.tar.gz' \
  --exclude='./*.tgz' \
  --exclude='./*.zip' \
  --exclude='./.claude' \
  --exclude='./*/.claude' \
  --exclude='./.DS_Store' \
  --exclude='./docs/release/evidence/RC1_SOURCE_ARCHIVE_CHECKSUMS.md' \
  --exclude='./docs/release/evidence/rc1-source-archive-checksums.json' \
  --exclude='./docs/release/evidence/*.sha256' \
  . | gzip -n > "$out"

echo "wrote: $out"
echo "archive size: $(du -h "$out" | awk '{print $1}')"

if [[ -x "$root/scripts/check-source-archive.sh" ]]; then
  "$root/scripts/check-source-archive.sh" "$out"
elif [[ -x "scripts/check-source-archive.sh" ]]; then
  scripts/check-source-archive.sh "$out"
else
  echo "warning: scripts/check-source-archive.sh not found; archive not post-validated" >&2
fi
