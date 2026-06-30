#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

required_doc="docs/crypto/EVIDENCE_CRYPTO_PROFILE.md"
if [[ ! -f "$required_doc" ]]; then
  echo "missing $required_doc" >&2
  exit 1
fi

required_terms=(
  "hybrid-pre-pqc-v1"
  "full-pqc-v1"
  "ml-kem-768-fips203"
  "ed25519-rfc8032"
  "ml-dsa-65-fips204"
  "ledger_signature"
  "transcript_signature"
  "downgrade_policy"
  "xenia-evidence-crypto-manifest-v1"
  "reject-classical-signatures"
)

for term in "${required_terms[@]}"; do
  if ! grep -RIn --exclude-dir=.git --exclude-dir=target -- "$term" "$required_doc" >/dev/null; then
    echo "evidence crypto profile is missing required term: $term" >&2
    exit 1
  fi
done

printf 'evidence crypto profile check passed\n'
