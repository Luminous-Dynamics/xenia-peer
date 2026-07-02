#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
repo_script="$root/scripts/check-pqc-claims.sh"

if [[ ! -x "$repo_script" ]]; then
  echo "missing executable PQC claim guard: $repo_script" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

allowed="$tmp/allowed"
mkdir -p "$allowed"
cat >"$allowed/README.md" <<'EOF'
# Allowed precise PQC wording fixture

Xenia currently uses ML-KEM key establishment with classical Ed25519
signatures. Future authentication changes require explicit evidence and policy
fixtures before stronger claims are allowed.
EOF

allowed_log="$tmp/allowed.log"
if ! "$repo_script" "$allowed" >"$allowed_log" 2>&1; then
  cat "$allowed_log" >&2
  echo "PQC claim guard rejected precise non-overclaim wording" >&2
  exit 1
fi

claims=(
  "ENTIRELY PQC"
  "entirely post-quantum"
  "fully PQC"
  "full PQC"
  "full post-quantum"
  "fully post-quantum"
  "PQC at every layer"
  "PQC-by-default at every layer"
  "quantum-safe remote"
  "quantum-secure remote"
  "quantum-safe evidence"
  "quantum-secure evidence"
)

for index in "${!claims[@]}"; do
  claim="${claims[$index]}"
  fixture="$tmp/negative-$index"
  mkdir -p "$fixture"
  cat >"$fixture/README.md" <<EOF
# Negative PQC claim fixture

This intentional overclaim must be rejected: Xenia provides ${claim} today.
EOF

  log="$fixture/claim-guard.log"
  if "$repo_script" "$fixture" >"$log" 2>&1; then
    cat "$log" >&2
    echo "PQC claim guard accepted intentional overclaim: $claim" >&2
    exit 1
  fi

  if ! grep -q "PQC claim overreach" "$log"; then
    cat "$log" >&2
    echo "PQC claim guard failed without reporting overclaim: $claim" >&2
    exit 1
  fi
done

printf 'PQC claim guard negative check passed (%s cases)\n' "${#claims[@]}"
