#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
doc="$root/docs/crypto/PQC_EVIDENCE_REPORT_AUDIT.md"

for file in "$main" "$runtime" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing PQC evidence report audit file: $file" >&2
    exit 1
  fi
done

for token in \
  "audit_evidence_report" \
  "--audit-evidence-report" \
  "audit_evidence_verification_report_artifacts_dir" \
  "evidence verification report artifact audit passed"; do
  if ! grep -Fq -- "$token" "$main"; then
    echo "missing evidence report audit CLI token: $token" >&2
    exit 1
  fi
done

for token in \
  "read_evidence_verification_report_dir" \
  "audit_evidence_verification_report_artifacts_dir" \
  "require_evidence_verification_report_schema" \
  "require_evidence_report_artifacts_match_current_bundle" \
  "verification_report artifact digests do not match" \
  "report audit should reject a swapped artifact"; do
  if ! grep -Fq -- "$token" "$runtime"; then
    echo "missing evidence report audit runtime token: $token" >&2
    exit 1
  fi
done

for token in \
  "--audit-evidence-report" \
  "xenia-evidence-artifact-digests-v1" \
  "artifact_set_blake3" \
  "does **not** replace signature verification" \
  "scripts/check-pqc-evidence-report-audit.sh"; do
  if ! grep -Fq -- "$token" "$doc"; then
    echo "missing evidence report audit documentation token: $token" >&2
    exit 1
  fi
done

printf 'PQC evidence report audit surface present\n'
