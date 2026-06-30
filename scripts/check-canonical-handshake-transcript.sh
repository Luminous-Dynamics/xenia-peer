#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
handshake="$root/crates/xenia-handshake/src/lib.rs"
peer_core="$root/crates/xenia-peer-core/src/handshake.rs"
m1_runtime="$root/apps/xenia-peer/src/m1_runtime.rs"
daemon="$root/apps/xenia-peer/src/main.rs"
doc="$root/docs/crypto/CANONICAL_HANDSHAKE_TRANSCRIPT.md"

for file in "$handshake" "$peer_core" "$m1_runtime" "$daemon" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing canonical transcript file: $file" >&2
    exit 1
  fi
done

required_handshake=(
  "HandshakeTranscriptV1"
  "HANDSHAKE_TRANSCRIPT_SCHEMA"
  "xenia-handshake-transcript-v1"
  "canonical_session_transcript_bytes"
  "compute_session_transcript_hash"
  "compute_session_transcript_hash_from_bytes"
  "HANDSHAKE_TRANSCRIPT_HASH_ALGORITHM"
)

for token in "${required_handshake[@]}"; do
  if ! grep -q "$token" "$handshake"; then
    echo "missing canonical transcript token in xenia-handshake: $token" >&2
    exit 1
  fi
done

required_runtime=(
  "HandshakeOutcome"
  "perform_host_handshake_with_transcript"
  "perform_viewer_handshake_with_transcript"
  "transcript_hash"
)

for token in "${required_runtime[@]}"; do
  if ! grep -q "$token" "$peer_core"; then
    echo "missing handshake runtime token in xenia-peer-core: $token" >&2
    exit 1
  fi
done

required_m1=(
  "bind_session_transcript_hash"
  "session_transcript_binding"
  "verify_transcript_bound_export"
  "MissingTranscriptBinding"
)

for token in "${required_m1[@]}"; do
  if ! grep -q "$token" "$m1_runtime"; then
    echo "missing M1 transcript binding token: $token" >&2
    exit 1
  fi
done

if ! grep -q "perform_host_handshake_with_transcript" "$daemon"; then
  echo "daemon does not use transcript-returning host handshake" >&2
  exit 1
fi
if ! grep -q "bind_session_transcript_hash(handshake.transcript_hash)" "$daemon"; then
  echo "daemon does not bind handshake transcript hash into M1 runtime" >&2
  exit 1
fi

required_doc=(
  "xenia-handshake-transcript-v1"
  "perform_host_handshake_with_transcript"
  "M1RuntimeSession"
  "runtime-produced hash"
)

for token in "${required_doc[@]}"; do
  if ! grep -q "$token" "$doc"; then
    echo "missing canonical transcript documentation token: $token" >&2
    exit 1
  fi
done

echo "canonical handshake transcript contract present"
