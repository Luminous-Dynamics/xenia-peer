#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

python3 scripts/generate-rc1-candidate-review.py . --check
scripts/xenia-validate.sh .
python3 scripts/check-release-readiness.py .
python3 scripts/check-release-readiness.py . --rc1

workdir="$(mktemp -d)"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

archive="$workdir/xenia-peer-source.tar.gz"
scripts/export-source-archive.sh . "$archive"
scripts/check-source-archive.sh "$archive"

git diff --check

echo "xenia rc1 review completed"
