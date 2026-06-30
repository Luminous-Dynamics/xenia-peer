#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
ledger="$root/crates/xenia-ledger/src/lib.rs"
doc="$root/docs/crypto/TRANSCRIPT_BOUND_EVIDENCE.md"

if [[ ! -f "$ledger" ]]; then
  echo "missing xenia-ledger source: $ledger" >&2
  exit 1
fi

if [[ ! -f "$doc" ]]; then
  echo "missing transcript-bound evidence doc: $doc" >&2
  exit 1
fi

required_source=(
  "SessionTranscriptBinding"
  "SESSION_TRANSCRIPT_BINDING_SCHEMA"
  "compute_session_transcript_hash"
  "TranscriptBindingError"
  "verify_transcript_bound_evidence_bundle"
  "TranscriptSessionMismatch"
  "EmptyTranscriptBoundBundle"
)

for token in "${required_source[@]}"; do
  if ! grep -q "$token" "$ledger"; then
    echo "missing transcript-bound evidence token in xenia-ledger: $token" >&2
    exit 1
  fi
done

required_doc=(
  "xenia-session-transcript-binding-v1"
  "Verifier::verify_transcript_bound_evidence_bundle"
  "transcript_hash_algorithm = blake3-256"
  "wrong transcript"
)

for token in "${required_doc[@]}"; do
  if ! grep -q "$token" "$doc"; then
    echo "missing transcript-bound evidence documentation token: $token" >&2
    exit 1
  fi
done

echo "transcript-bound evidence contract present"
