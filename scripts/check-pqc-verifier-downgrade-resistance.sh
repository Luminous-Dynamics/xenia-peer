#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
# The evidence-verification surface (suite selection, profile/downgrade
# preflight, etc.) was extracted out of main.rs into its own module on
# 2026-07-12 -- see evidence_verifier.rs's module doc comment. Both files are
# checked so this guard still catches the logic silently disappearing,
# wherever it currently lives.
verifier="$root/apps/xenia-peer/src/evidence_verifier.rs"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
doc="$root/docs/crypto/PQC_PEER_VERIFIER_SURFACE.md"

for file in "$main" "$verifier" "$runtime" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing PQC verifier downgrade-resistance file: $file" >&2
    exit 1
  fi
done

for token in \
  "require_evidence_profile" \
  "EvidenceProfileRequirement" \
  "preflight_evidence_verifier_selection" \
  "validate_required_profile_suite" \
  "read_evidence_crypto_manifest_export_dir" \
  "expected_downgrade_policy_label" \
  "does not satisfy required evidence profile" \
  "requires a post-quantum verifier suite" \
  "evidence downgrade policy" \
  "evidence transcript signature" \
  "evidence ledger signature" \
  "does not match requested verifier suite"; do
  if ! grep -Fq "$token" "$main" "$verifier"; then
    echo "missing verifier downgrade-resistance token in xenia-peer main/evidence_verifier: $token" >&2
    exit 1
  fi
done

if ! grep -Fq "read_evidence_crypto_manifest_export_dir" "$runtime"; then
  echo "m1_runtime must expose a manifest reader for verifier preflight checks" >&2
  exit 1
fi

for token in \
  "--require-evidence-profile full-pqc-v1" \
  "--require-evidence-profile hybrid-pre-pqc-v1" \
  "downgrade-resistant" \
  "refuses before accepting" \
  "requested verifier suite" \
  "transcript_signature" \
  "ledger_signature" \
  "split-suite bundle" \
  "reject-classical-signatures"; do
  if ! grep -Fq -- "$token" "$doc"; then
    echo "missing verifier downgrade-resistance documentation token: $token" >&2
    exit 1
  fi
done

printf 'PQC verifier downgrade-resistance surface present\n'
