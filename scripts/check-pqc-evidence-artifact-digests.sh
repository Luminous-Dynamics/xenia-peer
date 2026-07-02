#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
main="$root/apps/xenia-peer/src/main.rs"
cargo="$root/apps/xenia-peer/Cargo.toml"
doc="$root/docs/crypto/PQC_EVIDENCE_ARTIFACT_DIGESTS.md"

for file in "$runtime" "$main" "$cargo" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing PQC evidence artifact digest file: $file" >&2
    exit 1
  fi
done

if ! grep -Eq '^blake3\s*=\s*"1\.5"' "$cargo"; then
  echo "xenia-peer must declare blake3 for verifier artifact digests" >&2
  exit 1
fi

for token in \
  "EvidenceArtifactDigests" \
  "xenia-evidence-artifact-digests-v1" \
  "evidence_manifest_blake3" \
  "ledger_entries_blake3" \
  "session_transcript_binding_blake3" \
  "artifact_set_blake3" \
  "evidence_artifact_digests" \
  "blake3_file_hex" \
  "evidence_artifact_set_digest" \
  "verification_report_carries_verified_artifact_digests"; do
  if ! grep -Fq "$token" "$runtime"; then
    echo "missing evidence artifact digest runtime token: $token" >&2
    exit 1
  fi
done

if ! grep -Fq "artifact set blake3" "$main"; then
  echo "xenia-peer verify CLI must print the artifact-set digest" >&2
  exit 1
fi

for token in \
  "xenia-evidence-artifact-digests-v1" \
  "BLAKE3-256" \
  "evidence_manifest.json" \
  "ledger_entries.json" \
  "session_transcript_binding.json" \
  "artifact_set_blake3" \
  "does not replace signature verification" \
  "post-verification audit"; do
  if ! grep -Fq "$token" "$doc"; then
    echo "missing evidence artifact digest documentation token: $token" >&2
    exit 1
  fi
done

printf 'PQC evidence artifact digest surface present\n'
