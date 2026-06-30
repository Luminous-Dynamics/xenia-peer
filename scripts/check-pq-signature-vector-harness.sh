#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

required=(
  "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
  "$root/docs/crypto/fixtures/pq-signatures/README.md"
)

for path in "${required[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing required PQ signature vector harness file: $path" >&2
    exit 1
  fi
done

grep -q "full-pqc-v1 must remain refused" "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
grep -q "Placeholder, stub, or unconditional-success verification is forbidden" "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
grep -q "No vectors are active yet" "$root/docs/crypto/fixtures/pq-signatures/README.md"

echo "PQ signature vector harness contract present"
