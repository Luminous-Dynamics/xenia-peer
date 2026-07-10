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
  "MlDsaEvidenceChain"
  "new_ml_dsa_65_evidence_chain"
  "ml_dsa_65_evidence_chain_exports_real_pq_signed_entries"
  "EvidencePublicKeyBinding"
  "verify_evidence_bundle_with_key_binding"
  "ml_dsa_65_evidence_bundle_can_verify_with_public_key_binding"
  "SessionTranscriptSignature"
  "session_transcript_signature_message"
  "verify_signed_transcript_bound_evidence_bundle_with_key_bindings"
  "full_pqc_signed_transcript_bound_bundle_can_verify_with_ml_dsa"
  "MissingTranscriptSignatureInFullPqc"
  "EvidenceBundleSeal"
  "sign_evidence_bundle_seal_ml_dsa_65"
  "verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings"
  "full_pqc_sealed_bundle_can_verify_with_ml_dsa"
)

for token in "${required_source[@]}"; do
  if ! grep -q -- "$token" "$ledger"; then
    echo "missing real PQC signature backend source token: $token" >&2
    exit 1
  fi
done

if python3 - "$ledger" <<'PY'
import pathlib
import sys
sys.exit(0 if b"\x00" in pathlib.Path(sys.argv[1]).read_bytes() else 1)
PY
then
  echo "ledger source must not contain raw NUL bytes" >&2
  exit 1
fi

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
