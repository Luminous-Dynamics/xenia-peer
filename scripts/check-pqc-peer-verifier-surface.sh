#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
main="$root/apps/xenia-peer/src/main.rs"
# The evidence-verification surface was extracted out of main.rs into its own
# module on 2026-07-12 -- see evidence_verifier.rs's module doc comment. Both
# files are checked so this guard still catches the logic silently
# disappearing, wherever it currently lives.
verifier="$root/apps/xenia-peer/src/evidence_verifier.rs"
cargo="$root/apps/xenia-peer/Cargo.toml"
ci="$root/.github/workflows/xenia-validate.yml"
doc="$root/docs/crypto/PQC_PEER_VERIFIER_SURFACE.md"

for file in "$main" "$verifier" "$cargo" "$ci" "$doc"; do
  if [[ ! -f "$file" ]]; then
    echo "missing PQC peer verifier surface file: $file" >&2
    exit 1
  fi
done

if ! grep -Fq 'pqc-signatures = ["xenia-ledger/pqc-signatures"]' "$cargo"; then
  echo "xenia-peer must propagate pqc-signatures to xenia-ledger/pqc-signatures" >&2
  exit 1
fi

for token in \
  "EvidenceVerifierSuite" \
  "evidence_signature_suite" \
  "verify_evidence_bundle_with_selected_suite" \
  "verify_transcript_bound_evidence_bundle_dir_with_backend" \
  "MlDsa65EvidenceSignatureBackend" \
  "MlDsa87EvidenceSignatureBackend"; do
  if ! grep -Fq "$token" "$main" "$verifier"; then
    echo "missing xenia-peer PQC verifier surface token: $token" >&2
    exit 1
  fi
done

if ! python3 - "$main" "$verifier" <<'PY'
import pathlib, re, sys
text = "\n".join(pathlib.Path(p).read_text() for p in sys.argv[1:])
pattern = re.compile(r'#\[cfg\(feature = "pqc-signatures"\)\]\s*use xenia_ledger::\{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend\};')
if not pattern.search(text):
    raise SystemExit(1)
PY
then
  echo "xenia-peer ML-DSA verifier imports must remain cfg(feature = \"pqc-signatures\") gated" >&2
  exit 1
fi

if ! grep -Fq 'cargo test -p xenia-peer --features pqc-signatures --no-fail-fast' "$ci"; then
  echo "CI must compile/test xenia-peer with pqc-signatures enabled" >&2
  exit 1
fi

for token in \
  "--evidence-signature-suite" \
  "ed25519-rfc8032" \
  "ml-dsa-65-fips204" \
  "ml-dsa-87-fips204" \
  "does not enable PQ runtime export"; do
  if ! grep -Fq -- "$token" "$doc"; then
    echo "missing PQC peer verifier documentation token: $token" >&2
    exit 1
  fi
done

printf 'PQC peer verifier surface present\n'
