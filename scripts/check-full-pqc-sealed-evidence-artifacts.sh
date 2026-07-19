#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
# xenia-ledger/src was split from one lib.rs into focused modules on
# 2026-07-19 -- concatenate every source file so this guard still catches
# the logic silently disappearing, wherever it currently lives.
ledger_dir="$root/crates/xenia-ledger/src"
sealed_doc="$root/docs/crypto/FULL_PQC_SEALED_EVIDENCE_ARTIFACTS.md"
verifier_doc="$root/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md"
main="$root/apps/xenia-peer/src/main.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
real_pqc_check="$root/scripts/check-real-pqc-signature-backend.sh"

if [[ ! -d "$ledger_dir" ]]; then
  echo "missing xenia-ledger source dir: $ledger_dir" >&2
  exit 1
fi
ledger="$(cat "$ledger_dir"/*.rs)"

for file in "$sealed_doc" "$verifier_doc" "$main" "$runtime" "$real_pqc_check"; do
  if [[ ! -f "$file" ]]; then
    echo "missing full-PQC sealed evidence artifact contract file: $file" >&2
    exit 1
  fi
done

required_ledger_tokens=(
  "EvidenceBundleSeal"
  "EVIDENCE_BUNDLE_SEAL_SCHEMA"
  "evidence_bundle_seal_message"
  "sign_evidence_bundle_seal_ml_dsa_65"
  "sign_evidence_bundle_seal_ml_dsa_87"
  "BundleSealSignatureBackend"
  "verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings"
  "full_pqc_sealed_bundle_can_verify_with_ml_dsa"
)

for token in "${required_ledger_tokens[@]}"; do
  if ! grep -q -- "$token" <<< "$ledger"; then
    echo "missing sealed full-PQC ledger/verifier token: $token" >&2
    exit 1
  fi
done

required_artifact_names=(
  "evidence_manifest.json"
  "session_transcript_binding.json"
  "session_transcript_signature.json"
  "transcript_public_key_binding.json"
  "ledger_public_key_binding.json"
  "ledger_entries.json"
  "evidence_bundle_seal.json"
)

for artifact in "${required_artifact_names[@]}"; do
  if ! grep -q -- "$artifact" "$sealed_doc"; then
    echo "sealed full-PQC artifact layout doc missing artifact: $artifact" >&2
    exit 1
  fi
done

required_doc_tokens=(
  "profile = full-pqc-v1"
  "downgrade_policy = reject-classical-signatures"
  "Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings"
  "must not be accepted by the older unsigned"
  "out-of-band trust anchor"
  "Do not treat the public-key binding files as self-authenticating identity claims"
  "--verify-sealed-evidence-bundle"
  "--trusted-transcript-key-fingerprint-hex"
  "--trusted-ledger-key-fingerprint-hex"
)

for token in "${required_doc_tokens[@]}"; do
  if ! grep -q -- "$token" "$sealed_doc"; then
    echo "sealed full-PQC artifact layout doc missing token: $token" >&2
    exit 1
  fi
done

required_verifier_doc_tokens=(
  "Full-PQC sealed evidence"
  "evidence_bundle_seal.json"
  "transcript_public_key_binding.json"
  "ledger_public_key_binding.json"
  "out-of-band trust anchor"
  "--verify-sealed-evidence-bundle"
  "--trusted-transcript-key-fingerprint-hex"
  "--trusted-ledger-key-fingerprint-hex"
)

for token in "${required_verifier_doc_tokens[@]}"; do
  if ! grep -q -- "$token" "$verifier_doc"; then
    echo "M1 evidence verifier doc missing sealed full-PQC token: $token" >&2
    exit 1
  fi
done

required_cli_tokens=(
  "verify_sealed_evidence_bundle"
  "sealed_evidence_signature_suite"
  "trusted_transcript_key_fingerprint_hex"
  "trusted_ledger_key_fingerprint_hex"
  "parse_evidence_key_fingerprint_hex"
  "validate_sealed_evidence_verifier_suite"
)

for token in "${required_cli_tokens[@]}"; do
  if ! grep -q -- "$token" "$main"; then
    echo "xenia-peer CLI missing sealed full-PQC verifier token: $token" >&2
    exit 1
  fi
done

required_runtime_tokens=(
  "verify_sealed_transcript_bound_evidence_bundle_dir_with_backend"
  "TrustedKeyFingerprintMismatch"
  "xenia-sealed-evidence-artifact-digests-v1"
  "xenia-sealed-evidence-verification-report-v1"
)

for token in "${required_runtime_tokens[@]}"; do
  if ! grep -q -- "$token" "$runtime"; then
    echo "M1 runtime missing sealed full-PQC verifier token: $token" >&2
    exit 1
  fi
done

if ! grep -q -- "verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings" "$real_pqc_check"; then
  echo "real-PQC backend check must require sealed bundle verification token" >&2
  exit 1
fi

printf 'full-PQC sealed evidence artifact contract present\n'
