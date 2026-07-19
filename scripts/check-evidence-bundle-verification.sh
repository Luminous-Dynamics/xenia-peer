#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
# xenia-ledger/src was split from one lib.rs into focused modules on
# 2026-07-19 -- concatenate every source file so this guard still catches
# the logic silently disappearing, wherever it currently lives.
ledger_dir="$root/crates/xenia-ledger/src"
doc="$root/docs/crypto/EVIDENCE_BUNDLE_VERIFICATION.md"

if [[ ! -d "$ledger_dir" ]]; then
  echo "missing xenia-ledger source dir: $ledger_dir" >&2
  exit 1
fi
ledger="$(cat "$ledger_dir"/*.rs)"

if [[ ! -f "$doc" ]]; then
  echo "missing evidence bundle verification doc: $doc" >&2
  exit 1
fi

required_source=(
  "EvidenceBundleVerifyError"
  "verify_evidence_bundle"
  "LedgerSignatureSuiteMismatch"
  "entry_signature_suite"
)

for token in "${required_source[@]}"; do
  if ! grep -q "$token" <<< "$ledger"; then
    echo "missing evidence bundle verifier token in xenia-ledger: $token" >&2
    exit 1
  fi
done

required_doc=(
  "Verifier::verify_evidence_bundle"
  "manifest.ledger_signature"
  "entry signature envelope"
)

for token in "${required_doc[@]}"; do
  if ! grep -q "$token" "$doc"; then
    echo "missing evidence bundle verification documentation token: $token" >&2
    exit 1
  fi
done

echo "evidence bundle verification contract present"
