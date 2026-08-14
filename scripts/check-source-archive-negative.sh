#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"
CHECK="$ROOT/scripts/check-source-archive.sh"

if [[ ! -x "$CHECK" ]]; then
  echo "error: checker not executable: $CHECK" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_root() {
  rm -rf "$tmp/tree"
  mkdir -p "$tmp/tree/xenia-peer/src"
  printf 'fn main() {}\n' > "$tmp/tree/xenia-peer/src/main.rs"
}

archive_tree() {
  local out="$1"
  tar -C "$tmp/tree" -czf "$out" xenia-peer
}

expect_reject_path() {
  local rel="$1"
  make_root
  mkdir -p "$(dirname "$tmp/tree/xenia-peer/$rel")"
  printf 'fixture-secret-bytes\n' > "$tmp/tree/xenia-peer/$rel"
  local archive="$tmp/reject-$(echo "$rel" | tr '/.' '__').tar.gz"
  archive_tree "$archive"
  if "$CHECK" "$archive" >/dev/null 2>&1; then
    echo "FAIL: source archive checker accepted forbidden path: $rel" >&2
    exit 1
  fi
}

make_root
clean="$tmp/clean.tar.gz"
archive_tree "$clean"
"$CHECK" "$clean" >/dev/null

expect_reject_path 'xenia-peer-state/host-identity.key'
expect_reject_path 'xenia-peer-state/consent-ledger.key'
expect_reject_path 'xenia-operator-agent-state/operator-agent-token.key'
expect_reject_path 'nested/operator-http-ml-dsa.key'
expect_reject_path 'nested/identity.pem'
expect_reject_path 'nested/session.ledger'
expect_reject_path 'nested/.env.production'
expect_reject_path '.claude/worktrees/local/src/main.rs'

# The checker extracts source to inspect local path references, so prove member
# traversal is rejected before extraction. GNU tar's transform creates the
# malicious member name without writing outside this test's own temp tree.
make_root
traversal="$tmp/traversal.tar.gz"
tar -C "$tmp/tree" --transform='s#^xenia-peer#../xenia-peer#' -czf "$traversal" xenia-peer
if "$CHECK" "$traversal" >/dev/null 2>&1; then
  echo 'FAIL: source archive checker accepted a parent-traversal member' >&2
  exit 1
fi

# Links are unnecessary in the source release and can redirect extraction.
make_root
ln -s /tmp "$tmp/tree/xenia-peer/redirect"
link_archive="$tmp/link.tar.gz"
archive_tree "$link_archive"
if "$CHECK" "$link_archive" >/dev/null 2>&1; then
  echo 'FAIL: source archive checker accepted a symlink member' >&2
  exit 1
fi

echo 'source archive negative tests passed'
