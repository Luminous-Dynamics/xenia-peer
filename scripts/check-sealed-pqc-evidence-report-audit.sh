#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
doc="$root/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md"
sealed_doc="$root/docs/crypto/FULL_PQC_SEALED_EVIDENCE_ARTIFACTS.md"
verifier_doc="$root/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md"

for file in "$main" "$runtime" "$doc" "$sealed_doc" "$verifier_doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing sealed PQC evidence report audit file: $file" >&2
    exit 1
  fi
done

for token in \
  "write_sealed_evidence_report" \
  "--write-sealed-evidence-report" \
  "audit_sealed_evidence_report" \
  "--audit-sealed-evidence-report" \
  "write_sealed_evidence_verification_report_dir" \
  "sealed evidence verification report artifact audit passed"; do
  if ! grep -Fq -- "$token" "$main"; then
    echo "missing sealed evidence report audit CLI token: $token" >&2
    exit 1
  fi
done

for token in \
  "read_sealed_evidence_verification_report_dir" \
  "write_sealed_evidence_verification_report_dir" \
  "audit_sealed_evidence_verification_report_artifacts_dir" \
  "require_sealed_evidence_verification_report_schema" \
  "require_sealed_evidence_report_artifacts_match_current_bundle" \
  "xenia-sealed-evidence-verification-report-v1" \
  "xenia-sealed-evidence-artifact-digests-v1" \
  "xenia-sealed-evidence-trust-policy-receipt-v1" \
  "trust_policy" \
  "policy_blake3" \
  "policy_signature_blake3" \
  "policy_root_key_fingerprint_hex" \
  "require_sealed_evidence_trust_policy_receipt_schema" \
  "signed-enrolled-policy" \
  "policy_epoch" \
  "valid_from" \
  "valid_until" \
  "sealed verification_report artifact digests do not match" \
  "sealed report audit should reject a swapped sealed artifact"; do
  if ! grep -Fq -- "$token" "$runtime"; then
    echo "missing sealed evidence report audit runtime token: $token" >&2
    exit 1
  fi
done

for token in \
  "--write-sealed-evidence-report" \
  "--audit-sealed-evidence-report" \
  "xenia-sealed-evidence-verification-report-v1" \
  "xenia-sealed-evidence-artifact-digests-v1" \
  "xenia-sealed-evidence-trust-policy-receipt-v1" \
  "policy_blake3" \
  "policy_epoch" \
  "validity window" \
  "does **not** replace signature verification" \
  "scripts/check-sealed-pqc-evidence-report-audit.sh"; do
  if ! grep -Fq -- "$token" "$doc"; then
    echo "missing sealed evidence report audit documentation token: $token" >&2
    exit 1
  fi
done

for token in \
  "--write-sealed-evidence-report" \
  "--audit-sealed-evidence-report"; do
  if ! grep -Fq -- "$token" "$sealed_doc"; then
    echo "sealed artifact contract doc missing sealed report token: $token" >&2
    exit 1
  fi
  if ! grep -Fq -- "$token" "$verifier_doc"; then
    echo "M1 evidence verifier doc missing sealed report token: $token" >&2
    exit 1
  fi
done

printf 'sealed PQC evidence report audit surface present\n'
