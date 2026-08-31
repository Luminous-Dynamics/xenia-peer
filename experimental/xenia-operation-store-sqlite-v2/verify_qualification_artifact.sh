#!/usr/bin/env bash
set -euo pipefail

EVIDENCE="${1:-.}"
cd "$EVIDENCE"

fail() {
  echo "evidence-verification: FAIL: $*" >&2
  exit 1
}

[[ -f EVIDENCE.sha256 ]] || fail 'missing EVIDENCE.sha256'
sha256sum -c EVIDENCE.sha256

[[ -f tested-source/SOURCE.sha256 ]] || fail 'missing tested-source/SOURCE.sha256'
(
  cd tested-source
  sha256sum -c SOURCE.sha256
)

grep -Fx 'QUALIFICATION_RESULT=PASS' result.txt >/dev/null
grep -Fx 'PRODUCTION_CRASH_SURFACE=PASS' production-crash-surface.txt >/dev/null
grep -Fx 'RECOVERY_HEALTH=RecoveryRequired' writer-ownership.txt >/dev/null
grep -Fx 'SQLITE_VERSION=3.53.4' sqlite-source.txt >/dev/null
grep -Fx 'SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc' sqlite-source.txt >/dev/null

lib_recorded=$(grep -E '^LIB_RS_SHA256=' source-state.txt | cut -d= -f2-)
manifest_recorded=$(grep -E '^CARGO_TOML_SHA256=' source-state.txt | cut -d= -f2-)
lib_actual=$(sha256sum tested-source/src/lib.rs | awk '{print $1}')
manifest_actual=$(sha256sum tested-source/Cargo.toml | awk '{print $1}')
[[ -n "$lib_recorded" && "$lib_recorded" == "$lib_actual" ]] || fail 'tested lib.rs hash mismatch'
[[ -n "$manifest_recorded" && "$manifest_recorded" == "$manifest_actual" ]] || fail 'tested Cargo.toml hash mismatch'

dirty=$(grep -E '^TRACKED_SOURCE_DIRTY=' source-state.txt | cut -d= -f2-)
case "$dirty" in
  0) promotion='PROMOTION_SOURCE_STATE=clean-second-pass-candidate' ;;
  1) promotion='PROMOTION_SOURCE_STATE=dirty-first-pass-only' ;;
  *) fail "invalid TRACKED_SOURCE_DIRTY value: $dirty" ;;
esac

c0_rows=$(($(wc -l < c0-c10.tsv) - 1))
race_rows=$(($(wc -l < commit-races.tsv) - 1))
[[ "$c0_rows" -eq 22 ]] || fail "expected 22 C0-C10 rows, got $c0_rows"
[[ "$race_rows" -eq 80 ]] || fail "expected 80 COMMIT-race rows, got $race_rows"

# Exactly one deterministic row for each transaction class / C-point, with the expected durable
# presence, corresponding observed outcome, RecoveryRequired health, and proof evidence for
# committed cases.
for kind in admission effect-armed; do
  for n in $(seq 0 10); do
    point="C${n}"
    count=$(awk -F '\t' -v k="$kind" -v p="$point" 'NR>1 && $1==k && $2==p {n++} END {print n+0}' c0-c10.tsv)
    [[ "$count" -eq 1 ]] || fail "expected exactly one deterministic row for ${kind}:${point}"
  done
done

awk -F '\t' '
  NR == 1 { next }
  {
    early = ($2 ~ /^C([0-8])$/)
    expected_presence = early ? "absent" : "present"
    expected_outcome = early ? "absent" : "committed"
    if ($3 != expected_presence) exit 10
    if ($4 != expected_outcome) exit 11
    if ($5 != "RecoveryRequired") exit 12
    if ($4 == "committed") {
      if ($6 == "") exit 13
      if ($1 == "effect-armed" && $7 == "") exit 14
    }
  }
' c0-c10.tsv || fail 'deterministic matrix semantics invalid'

# Every race must canonicalize to fully absent or fully committed state, remain RecoveryRequired,
# and carry the relevant reconstructed proof commitments when committed.
awk -F '\t' '
  NR == 1 { next }
  {
    if ($1 != "admission" && $1 != "effect-armed") exit 20
    if ($4 != "either") exit 21
    if ($5 != "absent" && $5 != "committed") exit 22
    if ($6 != "RecoveryRequired") exit 23
    if ($5 == "committed") {
      if ($7 == "") exit 24
      if ($1 == "effect-armed" && $8 == "") exit 25
    }
  }
' commit-races.tsv || fail 'COMMIT-race matrix semantics invalid'

admission_races=$(awk -F '\t' 'NR>1 && $1=="admission" {n++} END {print n+0}' commit-races.tsv)
effect_races=$(awk -F '\t' 'NR>1 && $1=="effect-armed" {n++} END {print n+0}' commit-races.tsv)
[[ "$admission_races" -eq 40 ]] || fail "expected 40 admission race rows, got $admission_races"
[[ "$effect_races" -eq 40 ]] || fail "expected 40 EffectArmed race rows, got $effect_races"

kill_targeted=$(awk -F '\t' 'NR>1 && $10=="1" {n++} END {print n+0}' commit-races.tsv)
[[ "$kill_targeted" -gt 0 ]] || fail 'no COMMIT-race child was live when SIGKILL was attempted'

# The summary must agree with the observed evidence cardinality.
grep -Fx "C0_C10_ROWS=${c0_rows}" summary.txt >/dev/null
grep -Fx "COMMIT_RACE_ROWS=${race_rows}" summary.txt >/dev/null

echo "$promotion"
echo 'sqlite-v2-qualification-evidence: VERIFIED'
