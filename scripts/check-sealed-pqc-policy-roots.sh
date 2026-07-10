#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
policy_doc="$root/docs/crypto/SEALED_PQC_TRUST_POLICY.md"
report_doc="$root/docs/crypto/SEALED_PQC_EVIDENCE_REPORT_AUDIT.md"

for file in "$main" "$runtime" "$policy_doc" "$report_doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing sealed PQC policy-root file: $file" >&2
    exit 1
  fi
done

for token in \
  "sealed_evidence_policy_roots" \
  "required_sealed_evidence_policy_root_id" \
  "--sealed-evidence-policy-roots" \
  "--required-sealed-evidence-policy-root-id" \
  "use either --sealed-evidence-policy-roots"; do
  if ! grep -Fq -- "$token" "$main"; then
    echo "xenia-peer CLI missing sealed PQC policy-root token: $token" >&2
    exit 1
  fi
done

for token in \
  "SealedEvidencePolicyRoots" \
  "SealedEvidencePolicyRoot" \
  "SealedEvidencePolicyRootReceipt" \
  "read_sealed_evidence_policy_roots_file" \
  "sealed_evidence_policy_root_receipt_file_for_signature" \
  "attach_sealed_evidence_policy_root_receipt" \
  "require_sealed_evidence_policy_root_at" \
  "parse_policy_root_rfc3339" \
  "xenia-sealed-evidence-policy-roots-v1" \
  "policy_roots_blake3" \
  "policy_root_id" \
  "policy_root_supersedes_root_id" \
  "sealed_policy_roots_authorize_matching_current_root" \
  "sealed_policy_roots_reject_revoked_required_and_stale_roots"; do
  if ! grep -Fq -- "$token" "$runtime"; then
    echo "M1 runtime missing sealed PQC policy-root token: $token" >&2
    exit 1
  fi
done

for token in \
  "xenia-sealed-evidence-policy-roots-v1" \
  "--sealed-evidence-policy-roots" \
  "--required-sealed-evidence-policy-root-id" \
  "policy_roots_blake3" \
  "policy_root_id" \
  "supersedes_root_id" \
  "revoked_root_ids" \
  "policy-root registry"; do
  if ! grep -Fq -- "$token" "$policy_doc" "$report_doc"; then
    echo "sealed PQC policy-root docs missing token: $token" >&2
    exit 1
  fi
done

fingerprint_assignment_count=$(grep -F 'let transcript_fingerprint_hex = trusted_transcript_key_fingerprint_hex' "$main" | wc -l | tr -d ' ')
if [[ "$fingerprint_assignment_count" != "1" ]]; then
  echo "expected exactly one transcript fingerprint assignment, found $fingerprint_assignment_count" >&2
  exit 1
fi

printf 'sealed PQC policy-root surface present\n'
