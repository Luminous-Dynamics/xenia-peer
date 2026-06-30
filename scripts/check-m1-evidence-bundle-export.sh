#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
main="$root/apps/xenia-peer/src/main.rs"
doc="$root/docs/crypto/M1_EVIDENCE_BUNDLE_EXPORT.md"

for file in "$runtime" "$main" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing M1 evidence export contract file: $file" >&2
    exit 1
  fi
done

required_runtime=(
  "EvidenceCryptoManifestExport"
  "EvidenceVerificationReport"
  "M1EvidenceBundlePaths"
  "write_transcript_bound_evidence_bundle"
  "evidence_manifest.json"
  "ledger_entries.json"
  "session_transcript_binding.json"
  "verification_report.json"
  "verify_transcript_bound_evidence_bundle"
)

for token in "${required_runtime[@]}"; do
  if ! grep -q -- "$token" "$runtime"; then
    echo "missing M1 evidence export runtime token: $token" >&2
    exit 1
  fi
done

required_main=(
  "m1_runtime_smoke_evidence_dir"
  "write_transcript_bound_evidence_bundle"
)

for token in "${required_main[@]}"; do
  if ! grep -q -- "$token" "$main"; then
    echo "missing M1 evidence export CLI token: $token" >&2
    exit 1
  fi
done

required_doc=(
  "evidence_manifest.json"
  "session_transcript_binding.json"
  "verification_report.json"
  "stable labels"
)

for token in "${required_doc[@]}"; do
  if ! grep -q -- "$token" "$doc"; then
    echo "missing M1 evidence export documentation token: $token" >&2
    exit 1
  fi
done

echo "M1 evidence bundle export contract present"
