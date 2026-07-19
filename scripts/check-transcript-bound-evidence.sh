#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
# xenia-ledger/src was split from one lib.rs into focused modules on
# 2026-07-19 -- concatenate every source file so this guard still catches
# the logic silently disappearing, wherever it currently lives.
ledger_dir="$root/crates/xenia-ledger/src"
doc="$root/docs/crypto/TRANSCRIPT_BOUND_EVIDENCE.md"

if [[ ! -d "$ledger_dir" ]]; then
  echo "missing xenia-ledger source dir: $ledger_dir" >&2
  exit 1
fi
ledger="$(cat "$ledger_dir"/*.rs)"

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
  if ! grep -q "$token" <<< "$ledger"; then
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
