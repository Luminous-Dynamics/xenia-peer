#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
ledger="$root/crates/xenia-ledger/src/lib.rs"
cargo="$root/crates/xenia-ledger/Cargo.toml"
doc="$root/docs/crypto/PQC_SIGNATURE_BACKEND_BOUNDARY.md"

for file in "$ledger" "$cargo" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing PQC signature backend boundary file: $file" >&2
    exit 1
  fi
done

required_ledger=(
  "EvidenceSignatureBackend"
  "Ed25519EvidenceSignatureBackend"
  "MlDsa65EvidenceSignatureBackend"
  "MlDsa87EvidenceSignatureBackend"
  "verify_evidence_bundle_with_backend"
  "EvidenceSignatureBackendError"
  "PQC_SIGNATURE_BACKEND_STATUS"
  "pqc-signatures"
  "SignatureBackendSuiteMismatch"
)

for token in "${required_ledger[@]}"; do
  if ! grep -q -- "$token" "$ledger"; then
    echo "missing PQC signature backend source token: $token" >&2
    exit 1
  fi
done

if ! grep -q -- "pqc-signatures" "$cargo"; then
  echo "missing pqc-signatures feature in xenia-ledger Cargo.toml" >&2
  exit 1
fi
if ! grep -q -- "ml-dsa" "$cargo"; then
  echo "missing optional ml-dsa dependency in xenia-ledger Cargo.toml" >&2
  exit 1
fi

required_doc=(
  "implementation boundary, not a production PQC claim"
  "must never make unsupported PQ envelopes"
  "Real-backend gate"
  "FIPS-compatible vectors"
)

for token in "${required_doc[@]}"; do
  if ! grep -q -- "$token" "$doc"; then
    echo "missing PQC signature backend doc token: $token" >&2
    exit 1
  fi
done

echo "PQC signature backend boundary present"
