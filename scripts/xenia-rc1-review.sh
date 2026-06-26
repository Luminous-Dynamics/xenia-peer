#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

echo "xenia rc1 review: evidence freshness"
python3 scripts/check-release-evidence-freshness.py .

echo "xenia rc1 review: validation"
scripts/xenia-validate.sh .

echo "xenia rc1 review: release readiness"
python3 scripts/check-release-readiness.py .
python3 scripts/check-release-readiness.py . --rc1

echo "xenia rc1 review: source archive export"
workdir="$(mktemp -d)"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

archive="$workdir/xenia-peer-source.tar.gz"
scripts/export-source-archive.sh . "$archive"

echo "xenia rc1 review: source archive check"
scripts/check-source-archive.sh "$archive"

echo "xenia rc1 review: git diff check"
git diff --check

echo "xenia rc1 review completed"
