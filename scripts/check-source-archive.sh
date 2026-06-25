#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/check-source-archive.sh ARCHIVE.tar.gz

Validates that a source archive does not contain build output, nested VCS state,
previous archives, local runtime state, or absolute local workspace references in
source/config files.
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

archive="${1:-}"
if [[ -z "$archive" || ! -f "$archive" ]]; then
  echo "error: archive file required" >&2
  usage >&2
  exit 2
fi

fail=0
section() { printf '\n== %s ==\n' "$1"; }
fail_hit() { fail=1; sed 's/^/  /'; }

section 'archive inventory smoke check'
if ! tar -tzf "$archive" >/tmp/xenia-archive-list.$$; then
  echo "error: unable to read archive: $archive" >&2
  rm -f /tmp/xenia-archive-list.$$
  exit 2
fi
wc -l /tmp/xenia-archive-list.$$ | awk '{print "entries: " $1}'

section 'disallowed paths'
if grep -E '(^|/)(target|dist|pkg|node_modules|\.git)(/|$)' /tmp/xenia-archive-list.$$; then
  fail=1
else
  echo 'clean'
fi

section 'nested archive files'
if grep -E '\.(tar\.gz|tgz|zip)$' /tmp/xenia-archive-list.$$; then
  fail=1
else
  echo 'clean'
fi

section 'runtime secret/state files'
if grep -E '(^|/)(operator\.key|\.env|\.env\.[^/]+|[^/]+\.ledger)$' /tmp/xenia-archive-list.$$; then
  fail=1
else
  echo 'clean'
fi

section 'absolute local workspace references in source/config'
needle='/srv'"/luminous-dynamics"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir" /tmp/xenia-archive-list.$$' EXIT

tar -xzf "$archive" -C "$tmpdir"
if command -v rg >/dev/null 2>&1; then
  if rg -n --hidden -g '!**/*.md' -g '!**/target/**' -g '!**/dist/**' -g '!**/.git/**' "$needle" "$tmpdir"; then
    fail=1
  else
    echo 'clean'
  fi
else
  if grep -R --exclude='*.md' --exclude-dir='.git' --exclude-dir='target' --exclude-dir='dist' "$needle" "$tmpdir"; then
    fail=1
  else
    echo 'clean'
  fi
fi

if ((fail)); then
  printf '\nSource archive validation failed: %s\n' "$archive" >&2
  exit 1
fi

printf '\nSource archive validation passed: %s\n' "$archive"
