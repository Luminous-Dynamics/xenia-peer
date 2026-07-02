#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
ledger="$root/crates/xenia-ledger/src/lib.rs"
cargo="$root/crates/xenia-ledger/Cargo.toml"

for file in "$ledger" "$cargo"; do
  if [[ ! -f "$file" ]]; then
    echo "missing real PQC signature backend file: $file" >&2
    exit 1
  fi
done

required_source=(
  "MlDsa65EvidenceSignatureBackend"
  "MlDsa87EvidenceSignatureBackend"
  "verify_ml_dsa"
  "verify_exported_chain_with_backend"
  "verify_evidence_bundle_with_backend"
  "verify_transcript_bound_evidence_bundle_with_backend"
  "BadSignatureEncoding"
)

for token in "${required_source[@]}"; do
  if ! grep -q -- "$token" "$ledger"; then
    echo "missing real PQC signature backend source token: $token" >&2
    exit 1
  fi
done

if ! grep -q -- 'ml-dsa = {' "$cargo"; then
  echo "missing ml-dsa dependency declaration" >&2
  exit 1
fi
if ! grep -q -- 'pqc-signatures = \["dep:ml-dsa"\]' "$cargo"; then
  echo "pqc-signatures feature must explicitly enable dep:ml-dsa" >&2
  exit 1
fi

if command -v cargo >/dev/null 2>&1; then
  (
    cd "$root"
    cargo test -p xenia-ledger --features pqc-signatures --lib --no-fail-fast
  )
else
  echo "cargo not found; static real-PQC backend checks passed, Rust feature tests skipped" >&2
fi

printf 'real PQC signature backend boundary present
'
