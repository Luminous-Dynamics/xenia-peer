#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

EVIDENCE="${1:-$ROOT/qualification-evidence}"
rm -rf "$EVIDENCE"
mkdir -p "$EVIDENCE/logs"

PROBE="$ROOT/target/debug/store_crash_probe"
LOCK_PROBE="$ROOT/target/debug/store_lock_probe"
PROFILE_PROBE="$ROOT/target/debug/sqlite_profile_probe"

QUALIFICATION_RESULT=FAIL
ACTIVE_CHILD=""
ACTIVE_TMP=""

finalize_evidence() {
  local rc=$?
  if [[ -n "$ACTIVE_CHILD" ]]; then
    kill -KILL "$ACTIVE_CHILD" 2>/dev/null || true
    wait "$ACTIVE_CHILD" 2>/dev/null || true
  fi
  if [[ -n "$ACTIVE_TMP" ]]; then
    rm -rf "$ACTIVE_TMP" 2>/dev/null || true
  fi
  printf 'QUALIFICATION_RESULT=%s\nSCRIPT_EXIT_CODE=%s\n' "$QUALIFICATION_RESULT" "$rc" \
    > "$EVIDENCE/result.txt"
  (
    cd "$EVIDENCE"
    find . -type f ! -name EVIDENCE.sha256 -print0 \
      | sort -z \
      | xargs -0 -r sha256sum \
      > EVIDENCE.sha256
  )
}
trap finalize_evidence EXIT

fail() {
  printf 'QUALIFICATION_FAILURE=%s\n' "$*" | tee -a "$EVIDENCE/failure.txt" >&2
  exit 1
}

field() {
  local key="$1"
  local file="$2"
  grep -E "^${key}=" "$file" | tail -n 1 | cut -d= -f2- || true
}

record_inspection() {
  local table="$1"
  local kind="$2"
  local point="$3"
  local expected="$4"
  local inspect_file="$5"
  local extra="$6"
  local outcome health admission_proof arm_proof counts
  outcome="$(field OUTCOME "$inspect_file")"
  health="$(field HEALTH "$inspect_file")"
  admission_proof="$(field ADMISSION_PROOF_DIGEST "$inspect_file")"
  arm_proof="$(field EFFECT_ARMED_PROOF_DIGEST "$inspect_file")"
  counts="$(grep -E '^ADMISSIONS=' "$inspect_file" | tail -n 1 || true)"
  counts="${counts//$'\t'/ }"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$point" "$expected" "$outcome" "$health" \
    "$admission_proof" "$arm_proof" "$counts" "$extra" >> "$table"
}

# Record the exact environment before destructive testing.
{
  echo "QUALIFICATION_SCHEMA=xenia-sqlite-v2-qualification-evidence-v1"
  echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "GITHUB_SHA=${GITHUB_SHA:-unknown}"
  echo "GITHUB_RUN_ID=${GITHUB_RUN_ID:-unknown}"
  echo "GITHUB_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-unknown}"
  echo "GITHUB_REF=${GITHUB_REF:-unknown}"
  echo "PWD=$ROOT"
  echo
  rustc -Vv
  cargo -V
  echo
  uname -a
  echo
  cat /etc/os-release 2>/dev/null || true
  echo
  stat -f -c 'FILESYSTEM_TYPE=%T BLOCK_SIZE=%S' "$ROOT" 2>/dev/null || true
  findmnt -T "$ROOT" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true
  df -T "$ROOT" 2>/dev/null || true
} > "$EVIDENCE/environment.txt"

if [[ -f Cargo.lock ]]; then
  cp Cargo.lock "$EVIDENCE/Cargo.lock"
  sha256sum Cargo.lock > "$EVIDENCE/Cargo.lock.sha256"
fi

cargo tree -p rusqlite > "$EVIDENCE/rusqlite-tree.txt"
cargo tree -p libsqlite3-sys > "$EVIDENCE/libsqlite3-sys-tree.txt"

cargo build --locked --bin sqlite_profile_probe
"$PROFILE_PROBE" | tee "$EVIDENCE/sqlite-source.txt"
grep -Fx 'SQLITE_VERSION=3.53.4' "$EVIDENCE/sqlite-source.txt" >/dev/null
grep -Fx 'SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc' \
  "$EVIDENCE/sqlite-source.txt" >/dev/null

cargo build --locked --bin store_lock_probe
cargo build --locked --features crash-injection --bin store_crash_probe

printf 'kind\tpoint\texpected\toutcome\thealth\tadmission_proof_digest\teffect_armed_proof_digest\tcounts\textra\n' \
  > "$EVIDENCE/c0-c10.tsv"
printf 'kind\tdelay_seconds\trepetition\texpected\toutcome\thealth\tadmission_proof_digest\teffect_armed_proof_digest\tcounts\tchild_alive_at_kill\tchild_exit_status\n' \
  > "$EVIDENCE/commit-races.tsv"

# Real two-process ownership / stale-writer recovery probe.
ACTIVE_TMP="$(mktemp -d)"
chmod 700 "$ACTIVE_TMP"
db="$ACTIVE_TMP/operations-v2.sqlite3"
marker="${db}.xenia-operation-store-open-v2"
"$LOCK_PROBE" hold "$db" >"$EVIDENCE/logs/writer-holder.log" 2>&1 &
ACTIVE_CHILD=$!

for _ in $(seq 1 100); do
  if [[ -e "$marker" ]] && kill -0 "$ACTIVE_CHILD" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
[[ -e "$marker" ]] || fail "writer marker not created"
kill -0 "$ACTIVE_CHILD" 2>/dev/null || fail "writer exited before competing-open probe"

set +e
"$LOCK_PROBE" probe "$db" >"$EVIDENCE/logs/writer-competitor.log" 2>&1
second_rc=$?
set -e
[[ "$second_rc" -ne 0 ]] || fail "second process opened live writer store"

kill -KILL "$ACTIVE_CHILD"
wait "$ACTIVE_CHILD" 2>/dev/null || true
ACTIVE_CHILD=""
"$LOCK_PROBE" probe "$db" >"$EVIDENCE/logs/writer-recovery.log" 2>&1
grep -F 'HEALTH=RecoveryRequired' "$EVIDENCE/logs/writer-recovery.log" >/dev/null
printf 'LIVE_WRITER_COMPETITOR_RC=%s\nRECOVERY_HEALTH=RecoveryRequired\n' "$second_rc" \
  > "$EVIDENCE/writer-ownership.txt"
rm -rf "$ACTIVE_TMP"
ACTIVE_TMP=""

run_deterministic_case() {
  local kind="$1"
  local point="$2"
  local expect="$3"
  local db crash_log inspect_log cmd inspect_cmd rc
  ACTIVE_TMP="$(mktemp -d)"
  chmod 700 "$ACTIVE_TMP"
  db="$ACTIVE_TMP/operations-v2.sqlite3"
  crash_log="$EVIDENCE/logs/${kind}-${point}.crash.log"
  inspect_log="$EVIDENCE/logs/${kind}-${point}.inspect.log"

  if [[ "$kind" == "admission" ]]; then
    "$PROBE" init-empty "$db"
    cmd=admission
    inspect_cmd=inspect-admission
  else
    "$PROBE" init-arm "$db"
    cmd=effect-armed
    inspect_cmd=inspect-arm
  fi

  set +e
  XENIA_SQLITE_V2_CRASH_AT="${kind}:${point}" \
    "$PROBE" "$cmd" "$db" "$point" >"$crash_log" 2>&1
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || fail "${kind} ${point} did not crash"

  "$PROBE" "$inspect_cmd" "$db" "$expect" | tee "$inspect_log"
  grep -F 'HEALTH=RecoveryRequired' "$inspect_log" >/dev/null
  record_inspection "$EVIDENCE/c0-c10.tsv" "$kind" "$point" "$expect" "$inspect_log" "crash_rc=${rc}"
  rm -rf "$ACTIVE_TMP"
  ACTIVE_TMP=""
}

for kind in admission effect-armed; do
  for n in $(seq 0 10); do
    if [[ "$n" -le 8 ]]; then
      expect=absent
    else
      expect=present
    fi
    run_deterministic_case "$kind" "C${n}" "$expect"
  done
done

run_commit_race() {
  local kind="$1"
  local delay="$2"
  local repetition="$3"
  local db ready go alive inspect_cmd cmd inspect_log child_log child_rc
  ACTIVE_TMP="$(mktemp -d)"
  chmod 700 "$ACTIVE_TMP"
  db="$ACTIVE_TMP/operations-v2.sqlite3"
  ready="$ACTIVE_TMP/ready"
  go="$ACTIVE_TMP/go"
  inspect_log="$EVIDENCE/logs/${kind}-race-${delay}-${repetition}.inspect.log"
  child_log="$EVIDENCE/logs/${kind}-race-${delay}-${repetition}.child.log"

  if [[ "$kind" == "admission" ]]; then
    "$PROBE" init-empty "$db"
    cmd=admission
    inspect_cmd=inspect-admission
  else
    "$PROBE" init-arm "$db"
    cmd=effect-armed
    inspect_cmd=inspect-arm
  fi

  XENIA_SQLITE_V2_COMMIT_WINDOW="$kind" \
  XENIA_SQLITE_V2_COMMIT_READY="$ready" \
  XENIA_SQLITE_V2_COMMIT_GO="$go" \
    "$PROBE" "$cmd" "$db" RACE >"$child_log" 2>&1 &
  ACTIVE_CHILD=$!

  for _ in $(seq 1 1000); do
    [[ -e "$ready" ]] && break
    if ! kill -0 "$ACTIVE_CHILD" 2>/dev/null; then
      set +e
      wait "$ACTIVE_CHILD"
      child_rc=$?
      set -e
      ACTIVE_CHILD=""
      cat "$child_log" >&2 || true
      fail "${kind} commit-race child exited before READY with rc=${child_rc}"
    fi
    sleep 0.001
  done
  [[ -e "$ready" ]] || fail "${kind} commit-race READY timeout"

  : > "$go"
  sleep "$delay"
  if kill -0 "$ACTIVE_CHILD" 2>/dev/null; then
    alive=1
    kill -KILL "$ACTIVE_CHILD" 2>/dev/null || true
  else
    alive=0
  fi

  set +e
  wait "$ACTIVE_CHILD"
  child_rc=$?
  set -e
  ACTIVE_CHILD=""

  if [[ "$alive" -eq 0 && "$child_rc" -ne 0 ]]; then
    cat "$child_log" >&2 || true
    fail "${kind} commit-race child failed before kill with rc=${child_rc}"
  fi

  "$PROBE" "$inspect_cmd" "$db" either | tee "$inspect_log"
  grep -E '^OUTCOME=(absent|committed)$' "$inspect_log" >/dev/null

  local outcome health admission_proof arm_proof counts
  outcome="$(field OUTCOME "$inspect_log")"
  health="$(field HEALTH "$inspect_log")"
  admission_proof="$(field ADMISSION_PROOF_DIGEST "$inspect_log")"
  arm_proof="$(field EFFECT_ARMED_PROOF_DIGEST "$inspect_log")"
  counts="$(grep -E '^ADMISSIONS=' "$inspect_log" | tail -n 1 || true)"
  counts="${counts//$'\t'/ }"
  printf '%s\t%s\t%s\teither\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$delay" "$repetition" "$outcome" "$health" \
    "$admission_proof" "$arm_proof" "$counts" "$alive" "$child_rc" \
    >> "$EVIDENCE/commit-races.tsv"
  rm -rf "$ACTIVE_TMP"
  ACTIVE_TMP=""
}

# Repetition matters more than forcing both outcomes: atomicity permits either side of COMMIT.
delays=(0 0.00025 0.0005 0.001 0.002 0.005 0.010 0.025)
for kind in admission effect-armed; do
  for delay in "${delays[@]}"; do
    for repetition in $(seq 1 5); do
      run_commit_race "$kind" "$delay" "$repetition"
    done
  done
done

{
  echo "C0_C10_ROWS=$(($(wc -l < "$EVIDENCE/c0-c10.tsv") - 1))"
  echo "COMMIT_RACE_ROWS=$(($(wc -l < "$EVIDENCE/commit-races.tsv") - 1))"
  echo "ADMISSION_COMMITTED=$(awk -F '\t' 'NR>1 && $1=="admission" && $5=="committed" {n++} END {print n+0}' "$EVIDENCE/commit-races.tsv")"
  echo "ADMISSION_ABSENT=$(awk -F '\t' 'NR>1 && $1=="admission" && $5=="absent" {n++} END {print n+0}' "$EVIDENCE/commit-races.tsv")"
  echo "EFFECT_ARMED_COMMITTED=$(awk -F '\t' 'NR>1 && $1=="effect-armed" && $5=="committed" {n++} END {print n+0}' "$EVIDENCE/commit-races.tsv")"
  echo "EFFECT_ARMED_ABSENT=$(awk -F '\t' 'NR>1 && $1=="effect-armed" && $5=="absent" {n++} END {print n+0}' "$EVIDENCE/commit-races.tsv")"
  echo "RACE_CHILDREN_KILL_TARGETED=$(awk -F '\t' 'NR>1 && $10=="1" {n++} END {print n+0}' "$EVIDENCE/commit-races.tsv")"
} > "$EVIDENCE/summary.txt"

[[ "$(($(wc -l < "$EVIDENCE/c0-c10.tsv") - 1))" -eq 22 ]] \
  || fail "expected 22 deterministic C0-C10 evidence rows"
[[ "$(($(wc -l < "$EVIDENCE/commit-races.tsv") - 1))" -eq 80 ]] \
  || fail "expected 80 commit-race evidence rows"

QUALIFICATION_RESULT=PASS
cat "$EVIDENCE/summary.txt"
echo "sqlite-v2-destructive-qualification: OK"
