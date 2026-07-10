#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
run_required() {
  local path="$1"
  shift
  if [[ ! -x "$path" ]]; then
    fail "missing executable PQC/evidence boundary check: $path"
    return
  fi
  echo "+ $path $*"
  if ! "$path" "$@"; then
    fail "command failed: $path $*"
  fi
}
run_python_required() {
  local path="$1"
  shift
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found; cannot run $path"
    return
  fi
  if [[ ! -x "$path" ]]; then
    fail "missing executable PQC/evidence boundary check: $path"
    return
  fi
  echo "+ python3 $path $*"
  if ! python3 "$path" "$@"; then
    fail "command failed: python3 $path $*"
  fi
}

run_required scripts/check-pqc-claims.sh .
run_required scripts/check-pqc-claim-guard-negative.sh .
run_python_required scripts/check-evidence-manifests.py .
run_required scripts/check-evidence-manifest-guard-negative.sh .
run_required scripts/check-evidence-crypto-profile.sh .
run_required scripts/check-signature-envelope-agility.sh .
run_required scripts/check-evidence-bundle-verification.sh .
run_required scripts/check-transcript-bound-evidence.sh .
run_required scripts/check-pqc-signature-backend-boundary.sh .
run_python_required scripts/check-pqc-feature-gate.py .
run_required scripts/check-pqc-peer-verifier-surface.sh .
run_required scripts/check-pqc-verifier-downgrade-resistance.sh .
run_required scripts/check-pqc-evidence-artifact-digests.sh .
run_required scripts/check-pqc-evidence-artifact-digests-negative.sh .
run_required scripts/check-pqc-evidence-report-audit.sh .
run_required scripts/check-pqc-evidence-report-audit-negative.sh .
run_required scripts/check-sealed-pqc-evidence-report-audit.sh .
run_required scripts/check-sealed-pqc-evidence-report-audit-negative.sh .
run_required scripts/check-sealed-pqc-trust-policy.sh .
run_required scripts/check-sealed-pqc-trust-policy-signature.sh .
run_required scripts/check-sealed-pqc-policy-roots.sh .
run_required scripts/check-pqc-feature-gate-negative.sh .
run_required scripts/check-real-pqc-signature-backend.sh .
run_required scripts/check-full-pqc-sealed-evidence-artifacts.sh .
run_required scripts/check-full-pqc-runtime-refusal.sh .
run_required scripts/check-pq-signature-vector-harness.sh .

if (( failures > 0 )); then
  echo "PQC evidence boundary check failed with $failures failure(s)" >&2
  exit 1
fi

printf 'PQC evidence boundary check passed\n'
