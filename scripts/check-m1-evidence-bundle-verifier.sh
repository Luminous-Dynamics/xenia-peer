#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
main="$root/apps/xenia-peer/src/main.rs"
# The evidence-verification surface (incl. its CLI flag parsing/dispatch)
# was extracted out of main.rs into its own module on 2026-07-12 -- see
# evidence_verifier.rs's module doc comment. The "$main" CLI-token check
# below concatenates both files so this guard still catches the logic
# silently disappearing, wherever it currently lives --
# verify_transcript_bound_evidence_bundle_dir was confirmed present only
# in evidence_verifier.rs, not genuinely missing.
evidence_verifier="$root/apps/xenia-peer/src/evidence_verifier.rs"
doc="$root/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md"

for file in "$runtime" "$main" "$evidence_verifier" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing M1 evidence verifier contract file: $file" >&2
    exit 1
  fi
done

required_runtime=(
  "verify_transcript_bound_evidence_bundle_dir"
  "to_manifest"
  "require_label"
  "evidence_manifest.json"
  "ledger_entries.json"
  "session_transcript_binding.json"
  "verify_transcript_bound_evidence_bundle"
)

for token in "${required_runtime[@]}"; do
  if ! grep -q -- "$token" "$runtime"; then
    echo "missing M1 evidence verifier runtime token: $token" >&2
    exit 1
  fi
done

required_main=(
  "verify_evidence_bundle"
  "evidence_public_key_hex"
  "parse_evidence_public_key_hex"
  "verify_transcript_bound_evidence_bundle_dir"
)

main_and_verifier="$(cat "$main" "$evidence_verifier")"
for token in "${required_main[@]}"; do
  if ! grep -q -- "$token" <<< "$main_and_verifier"; then
    echo "missing M1 evidence verifier CLI token: $token" >&2
    exit 1
  fi
done

required_doc=(
  "--verify-evidence-bundle"
  "--evidence-public-key-hex"
  "without trusting"
  "operator public key supplied out-of-band"
)

for token in "${required_doc[@]}"; do
  if ! grep -q -- "$token" "$doc"; then
    echo "missing M1 evidence verifier documentation token: $token" >&2
    exit 1
  fi
done

echo "M1 evidence bundle verifier contract present"
