#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

# Ban strong PQC claims outside documents whose purpose is to define the future
# migration target. This keeps README/compliance/product wording aligned with
# the actual crypto posture: ML-KEM key establishment today; Ed25519 signatures
# still present until the PQ signature lane lands.
patterns=(
  "entirely PQC"
  "entirely post-quantum"
  "fully PQC"
  "full-PQC"
  "full post-quantum"
  "PQC at every layer"
  "PQC-by-default at every layer"
)

allow_re='(^|/)(docs/crypto/FULL_PQC_MIGRATION_PLAN\.md|docs/crypto/EVIDENCE_CRYPTO_PROFILE\.md|scripts/check-pqc-claims\.sh|scripts/check-evidence-crypto-profile\.sh)$'
failures=0

for pattern in "${patterns[@]}"; do
  while IFS=: read -r file line text; do
    [[ -z "${file:-}" ]] && continue
    if [[ "$file" =~ $allow_re ]]; then
      continue
    fi
    printf 'PQC claim overreach: %s:%s: %s\n' "$file" "$line" "$text" >&2
    failures=$((failures + 1))
  done < <(grep -RIn --exclude-dir=.git --exclude-dir=target --exclude='*.patch' -- "$pattern" . || true)
done

if (( failures > 0 )); then
  cat >&2 <<'MSG'

Strong PQC wording found outside the migration plan.
Use precise wording instead: "ML-KEM key establishment with classical Ed25519
signatures today; full-PQC profile planned after ML-DSA/SLH-DSA integration."
MSG
  exit 1
fi

printf 'PQC claim check passed\n'
