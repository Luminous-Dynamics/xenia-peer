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
sealed_doc="$root/docs/crypto/FULL_PQC_SEALED_EVIDENCE_ARTIFACTS.md"
verifier_doc="$root/docs/crypto/M1_EVIDENCE_BUNDLE_VERIFIER.md"

for file in "$main" "$evidence_verifier" "$runtime" "$policy_doc" "$sealed_doc" "$verifier_doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing sealed PQC trust policy file: $file" >&2
    exit 1
  fi
done
main_and_verifier="$(cat "$main" "$evidence_verifier")"

for token in \
  "sealed_evidence_trust_policy" \
  "--sealed-evidence-trust-policy" \
  "--sealed-evidence-trust-policy-signature" \
  "--trusted-sealed-evidence-policy-root-fingerprint-hex" \
  "--require-signed-sealed-evidence-trust-policy" \
  "--minimum-sealed-evidence-policy-epoch" \
  "resolve_sealed_evidence_trust_anchors" \
  "minimum_sealed_evidence_policy_epoch" \
  "conflicts_with_all"; do
  if ! grep -Fq -- "$token" <<< "$main_and_verifier"; then
    echo "xenia-peer CLI missing sealed PQC trust policy token: $token" >&2
    exit 1
  fi
done

for token in \
  "SealedEvidenceTrustPolicy" \
  "SealedEvidenceTrustPolicySignature" \
  "SealedEvidenceTrustPolicySignatureReceipt" \
  "SealedEvidenceTrustAnchors" \
  "SealedEvidenceTrustPolicyReceipt" \
  "read_sealed_evidence_trust_policy_file" \
  "read_sealed_evidence_trust_policy_signature_file" \
  "verify_sealed_evidence_trust_policy_signature_file_with_backend" \
  "sealed_evidence_trust_policy_anchors" \
  "sealed_evidence_trust_policy_receipt_file" \
  "attach_sealed_evidence_trust_policy_signature_receipt" \
  "xenia-sealed-evidence-trust-policy-receipt-v1" \
  "xenia-sealed-evidence-trust-policy-signature-v1" \
  "sealed_evidence_trust_policy_signature_message" \
  "require_sealed_evidence_trust_policy" \
  "parse_trust_policy_fingerprint_hex" \
  "parse_policy_rfc3339" \
  "require_sealed_evidence_trust_policy_at" \
  "require_sealed_evidence_trust_policy_minimum_epoch" \
  "xenia-sealed-evidence-trust-policy-v1" \
  "sealed_trust_policy_rejects_wrong_suite" \
  "sealed_trust_policy_rejects_expired_future_and_revoked_policy" \
  "sealed_trust_policy_minimum_epoch_fails_closed" \
  "sealed_trust_policy_receipt_records_policy_source"; do
  if ! grep -Fq -- "$token" "$runtime"; then
    echo "M1 runtime missing sealed PQC trust policy token: $token" >&2
    exit 1
  fi
done

for token in \
  "xenia-sealed-evidence-trust-policy-v1" \
  "--sealed-evidence-trust-policy" \
  "--sealed-evidence-trust-policy-signature" \
  "--trusted-sealed-evidence-policy-root-fingerprint-hex" \
  "--require-signed-sealed-evidence-trust-policy" \
  "signature_suite" \
  "xenia-sealed-evidence-trust-policy-signature-v1" \
  "policy_root_key_fingerprint_hex" \
  "policy_signature_blake3" \
  "trusted_transcript_key_fingerprint_hex" \
  "trusted_ledger_key_fingerprint_hex" \
  "xenia-sealed-evidence-trust-policy-receipt-v1" \
  "policy_blake3" \
  "policy_id" \
  "operator_id" \
  "policy_epoch" \
  "--minimum-sealed-evidence-policy-epoch" \
  "valid_from" \
  "valid_until" \
  "revoked_policy_ids" \
  "Do not combine" \
  "must not authorize"; do
  if ! grep -Fq -- "$token" "$policy_doc" "$sealed_doc" "$verifier_doc"; then
    echo "sealed PQC trust policy docs missing token: $token" >&2
    exit 1
  fi
done

printf 'sealed PQC trust policy surface present\n'
