#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
# The evidence-verification surface (incl. its CLI flag parsing/dispatch)
# was extracted out of main.rs into its own module on 2026-07-12 -- see
# evidence_verifier.rs's module doc comment. All the "$main" CLI-token
# checks below concatenate both files so this guard still catches the
# logic silently disappearing, wherever it currently lives. Every one of
# this script's tokens was confirmed present only in evidence_verifier.rs,
# not genuinely missing -- this was a stale checker, not a real gap.
evidence_verifier="$root/apps/xenia-peer/src/evidence_verifier.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
policy_doc="$root/docs/crypto/SEALED_PQC_TRUST_POLICY.md"
report_doc="$root/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md"

for file in "$main" "$evidence_verifier" "$runtime" "$policy_doc" "$report_doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing sealed PQC signed trust-policy file: $file" >&2
    exit 1
  fi
done
main_and_verifier="$(cat "$main" "$evidence_verifier")"

for token in \
  "sealed_evidence_trust_policy_signature" \
  "trusted_sealed_evidence_policy_root_fingerprint_hex" \
  "require_signed_sealed_evidence_trust_policy" \
  "verify_sealed_evidence_trust_policy_signature_with_selected_suite" \
  "verify_ml_dsa_65_sealed_evidence_trust_policy_signature" \
  "verify_ml_dsa_87_sealed_evidence_trust_policy_signature"; do
  if ! grep -Fq -- "$token" <<< "$main_and_verifier"; then
    echo "xenia-peer missing signed sealed trust-policy token: $token" >&2
    exit 1
  fi
done

for token in \
  "SealedEvidenceTrustPolicySignature" \
  "SealedEvidenceTrustPolicySignatureReceipt" \
  "read_sealed_evidence_trust_policy_signature_file" \
  "verify_sealed_evidence_trust_policy_signature_file_with_backend" \
  "attach_sealed_evidence_trust_policy_signature_receipt" \
  "xenia-sealed-evidence-trust-policy-signature-v1" \
  "sealed_evidence_trust_policy_signature_message" \
  "policy_signature_path" \
  "policy_signature_blake3" \
  "policy_root_key_fingerprint_hex" \
  "require_sealed_evidence_trust_policy_receipt_schema" \
  "trust-policy-root"; do
  if ! grep -Fq -- "$token" "$runtime"; then
    echo "M1 runtime missing signed sealed trust-policy token: $token" >&2
    exit 1
  fi
done

for token in \
  "xenia-sealed-evidence-trust-policy-signature-v1" \
  "--sealed-evidence-trust-policy-signature" \
  "--trusted-sealed-evidence-policy-root-fingerprint-hex" \
  "--require-signed-sealed-evidence-trust-policy" \
  "policy_signature_blake3" \
  "policy_root_key_fingerprint_hex" \
  "detached policy-root signature"; do
  if ! grep -Fq -- "$token" "$policy_doc" "$report_doc"; then
    echo "signed sealed trust-policy docs missing token: $token" >&2
    exit 1
  fi
done

printf 'sealed PQC signed trust-policy surface present\n'
