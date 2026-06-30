#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
main="$root/apps/xenia-peer/src/main.rs"
doc="$root/docs/crypto/FULL_PQC_RUNTIME_REFUSAL_GATE.md"

for file in "$runtime" "$main" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing full-PQC runtime refusal file: $file" >&2
    exit 1
  fi
done

required_runtime=(
  "FullPqcRuntimeUnavailable"
  "UnsupportedEvidenceExportProfile"
  "ensure_runtime_can_emit_profile"
  "write_transcript_bound_evidence_bundle_for_profile"
  "full-pqc-v1"
  "ed25519-rfc8032"
)

for token in "${required_runtime[@]}"; do
  if ! grep -q -- "$token" "$runtime"; then
    echo "missing full-PQC runtime refusal token: $token" >&2
    exit 1
  fi
done

required_main=(
  "m1_runtime_smoke_evidence_profile"
  "hybrid-pre-pqc-v1"
  "write_transcript_bound_evidence_bundle_for_profile"
)

for token in "${required_main[@]}"; do
  if ! grep -q -- "$token" "$main"; then
    echo "missing full-PQC CLI refusal token: $token" >&2
    exit 1
  fi
done

required_doc=(
  "must refuse"
  "claim full PQC while carrying"
  "FullPqcRuntimeUnavailable"
)

for token in "${required_doc[@]}"; do
  if ! grep -q -- "$token" "$doc"; then
    echo "missing full-PQC runtime refusal doc token: $token" >&2
    exit 1
  fi
done

echo "full-PQC runtime refusal gate present"
