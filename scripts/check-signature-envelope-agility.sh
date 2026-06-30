#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

required_terms=(
  "SignatureEnvelope"
  "LedgerEntryExport"
  "verify_exported_chain"
  "SIGNATURE_ENVELOPE_AGILITY.md"
  "ml-dsa-65-fips204"
  "unsupported signature suite"
)

for term in "${required_terms[@]}"; do
  if ! grep -R --exclude-dir=.git --exclude-dir=target -Fq "$term" \
    crates/xenia-ledger docs/crypto scripts; then
    echo "missing signature-envelope agility term: $term" >&2
    exit 1
  fi
done

echo "signature-envelope agility check passed"
