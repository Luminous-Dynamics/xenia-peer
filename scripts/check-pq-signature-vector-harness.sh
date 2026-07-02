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

grep -q "full-pqc-v1" "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
grep -q "must remain refused by default" "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
grep -q "Mocked or unconditional-success verification is forbidden" "$root/docs/crypto/PQ_SIGNATURE_VECTOR_HARNESS.md"
grep -q "Generated ML-DSA backend smoke tests are active" "$root/docs/crypto/fixtures/pq-signatures/README.md"
grep -q "External known-answer vectors are still required" "$root/docs/crypto/fixtures/pq-signatures/README.md"

echo "PQ signature vector harness contract present"
