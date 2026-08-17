#!/usr/bin/env bash
set -euo pipefail

# Keep validation build artifacts out of the repository tree.
# This prevents cargo check/test from recreating ./target and causing hygiene
# checks to fail immediately after successful validation.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/xenia-peer-target}"


root="${1:-.}"
cd "$root"

failures=0
warnings=0
checks=0
verbose="${XENIA_VERBOSE:-0}"
validation_dir="${XENIA_VALIDATION_DIR:-/tmp/xenia-validation-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$validation_dir"
chmod 700 "$validation_dir"
summary_file="$validation_dir/summary.tsv"
printf 'status\tcheck\tlog\n' > "$summary_file"
chmod 600 "$summary_file"

warn() {
  warnings=$((warnings + 1))
  echo "WARN: $*" >&2
  printf 'WARN\t%s\t-\n' "$*" >> "$summary_file"
}

surface_logged_warnings() {
  local label="$1" log="$2"
  [[ "$verbose" == "1" ]] && return 0
  if grep -Eiq '(^|[[:space:]])warn(ing)?([:[:space:]]|$)' "$log"; then
    warnings=$((warnings + 1))
    echo "WARN: ${label} emitted warning lines; showing up to 3 (full log: ${log})" >&2
    grep -Ei '(^|[[:space:]])warn(ing)?([:[:space:]]|$)' "$log" | head -n 3 >&2 || true
    printf 'WARN\t%s emitted warning lines\t%s\n' "$label" "$log" >> "$summary_file"
  fi
}

run_logged() {
  local kind="$1"
  shift
  checks=$((checks + 1))

  local label="$*" log rc
  printf -v log '%s/%03d.log' "$validation_dir" "$checks"
  : > "$log"
  chmod 600 "$log"
  {
    printf 'kind=%s\ncommand=' "$kind"
    printf ' %q' "$@"
    printf '\n\n'
  } > "$log"

  if [[ "$verbose" == "1" ]]; then
    echo "+ $*"
    if "$@" > >(tee -a "$log") 2> >(tee -a "$log" >&2); then
      rc=0
    else
      rc=$?
    fi
  else
    if "$@" >> "$log" 2>&1; then
      rc=0
    else
      rc=$?
    fi
  fi

  if [[ "$rc" -eq 0 ]]; then
    printf 'PASS\t%s\t%s\n' "$label" "$log" >> "$summary_file"
    surface_logged_warnings "$label" "$log"
    return 0
  fi

  if [[ "$kind" == "advisory" ]]; then
    warnings=$((warnings + 1))
    echo "WARN: advisory command failed (${rc}): ${label} (log: ${log})" >&2
    printf 'WARN\t%s\t%s\n' "$label" "$log" >> "$summary_file"
    return 0
  fi

  failures=$((failures + 1))
  echo "FAIL: command failed (${rc}): ${label}" >&2
  echo "--- last 40 log lines ---" >&2
  tail -n 40 "$log" >&2 || true
  echo "--- full log: ${log} ---" >&2
  printf 'FAIL\t%s\t%s\n' "$label" "$log" >> "$summary_file"
  return 0
}

run() {
  run_logged gate "$@"
}

run_advisory() {
  run_logged advisory "$@"
}

finish_validation() {
  echo
  if [[ "$failures" -ne 0 ]]; then
    echo "xenia validation failed with ${failures} failure(s)" >&2
    echo "RESULT: FAIL (${failures} gate(s); ${warnings} warning/advisory finding(s))" >&2
    echo "Evidence: ${validation_dir}" >&2
    return 1
  fi

  echo "xenia validation completed"
  echo "RESULT: PASS (${checks} checks; ${warnings} warning/advisory finding(s))"
  echo "Evidence: ${validation_dir}"
}

if [[ -x scripts/xenia-hygiene-audit.sh ]]; then
  run scripts/xenia-hygiene-audit.sh .
else
  warn "scripts/xenia-hygiene-audit.sh not found or not executable"
fi

# Shell/Python syntax check for project scripts.
while IFS= read -r -d '' script; do
  run bash -n "$script"
done < <(find scripts -type f -name '*.sh' -print0 2>/dev/null || true)
if command -v python3 >/dev/null 2>&1; then
  while IFS= read -r -d '' script; do
    run python3 -m py_compile "$script"
  done < <(find scripts -type f -name '*.py' -print0 2>/dev/null || true)
else
  warn "python3 not found; skipping Python script syntax checks"
fi

if [[ -d scripts/tests ]] && command -v python3 >/dev/null 2>&1; then
  run python3 -m unittest discover -s scripts/tests -p 'test_*.py'
fi

# Archive hygiene is security-sensitive enough to keep a negative regression
# suite in the normal validation path. It is pure shell/tar and does not need a
# Rust toolchain, so contaminated archive acceptance is caught even on light
# review hosts.
if [[ -x scripts/check-source-archive-negative.sh ]]; then
  run scripts/check-source-archive-negative.sh .
else
  warn "scripts/check-source-archive-negative.sh not found or not executable"
fi

if [[ -x scripts/check-xenia-policy.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-xenia-policy.py .
  else
    warn "python3 not found; skipping Xenia policy check"
  fi
fi

if [[ -x scripts/check-codeowners.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-codeowners.py .
  else
    warn "python3 not found; skipping CODEOWNERS check"
  fi
fi

if [[ -x scripts/check-secure-defaults.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-secure-defaults.py . --max-lines 120
  else
    warn "python3 not found; skipping secure-default scan"
  fi
fi

if [[ -x scripts/check-pqc-evidence-boundary.sh ]]; then
  run scripts/check-pqc-evidence-boundary.sh .
else
  if [[ -x scripts/check-pqc-claims.sh ]]; then
    run scripts/check-pqc-claims.sh .
  fi

  if [[ -x scripts/check-pqc-claim-guard-negative.sh ]]; then
    run scripts/check-pqc-claim-guard-negative.sh .
  fi

  if [[ -x scripts/check-evidence-crypto-profile.sh ]]; then
    run scripts/check-evidence-crypto-profile.sh .
  fi

  if [[ -x scripts/check-evidence-manifests.py ]]; then
    if command -v python3 >/dev/null 2>&1; then
      run python3 scripts/check-evidence-manifests.py .
    else
      echo "WARN: python3 not found; skipping evidence manifest check" >&2
    fi
  fi

  if [[ -x scripts/check-signature-envelope-agility.sh ]]; then
    run scripts/check-signature-envelope-agility.sh .
  fi

  if [[ -x scripts/check-evidence-bundle-verification.sh ]]; then
    run scripts/check-evidence-bundle-verification.sh .
  fi

  if [[ -x scripts/check-transcript-bound-evidence.sh ]]; then
    run scripts/check-transcript-bound-evidence.sh .
  fi

  if [[ -x scripts/check-pqc-signature-backend-boundary.sh ]]; then
    run scripts/check-pqc-signature-backend-boundary.sh .
  fi

  if [[ -x scripts/check-full-pqc-runtime-refusal.sh ]]; then
    run scripts/check-full-pqc-runtime-refusal.sh .
  fi

  if [[ -x scripts/check-pq-signature-vector-harness.sh ]]; then
    run scripts/check-pq-signature-vector-harness.sh .
  fi
fi

if [[ -x scripts/check-canonical-handshake-transcript.sh ]]; then
  run scripts/check-canonical-handshake-transcript.sh .
fi


if [[ -x scripts/check-m1-evidence-bundle-export.sh ]]; then
  run scripts/check-m1-evidence-bundle-export.sh .
fi

if [[ -x scripts/check-m1-evidence-bundle-verifier.sh ]]; then
  run scripts/check-m1-evidence-bundle-verifier.sh .
fi

if [[ -x scripts/check-release-readiness.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-release-readiness.py .
  else
    warn "python3 not found; skipping Xenia release-readiness check"
  fi
fi

if [[ -x scripts/check-normalization-plan.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-normalization-plan.py .
  else
    warn "python3 not found; skipping Xenia normalization-plan check"
  fi
fi

if [[ -x scripts/plan-normalization-execution.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/plan-normalization-execution.py . --output /tmp/xenia-normalization-execution-plan.json
  else
    warn "python3 not found; skipping normalization execution-plan generation"
  fi
fi

# This check is advisory before the actual layout move and becomes a gate after
# normalization-v0.2 has been applied. It still catches contradictory states.
if [[ -x scripts/check-post-normalization.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run_advisory python3 scripts/check-post-normalization.py .
  else
    warn "python3 not found; skipping post-normalization check"
  fi
fi

# Cargo path/boundary checks are cheap and catch the most common migration
# mistakes before cargo metadata tries to resolve the whole workspace.
if [[ -x scripts/check-zk-protocol-boundary.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-zk-protocol-boundary.py .
  else
    warn "python3 not found; skipping ZK protocol boundary check"
  fi
fi

if [[ -x scripts/check-cargo-boundaries.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run python3 scripts/check-cargo-boundaries.py .
  else
    warn "python3 not found; skipping Cargo boundary check"
  fi
fi

# Risk pattern checks are intentionally advisory in normal validation. Use
# `scripts/check-runtime-risk-patterns.py . --strict` for RC hardening.
if [[ -x scripts/check-runtime-risk-patterns.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run_advisory python3 scripts/check-runtime-risk-patterns.py . --max-lines 120
  else
    warn "python3 not found; skipping runtime risk pattern report"
  fi
fi

# Unsafe/FFI scans are advisory during stabilization and become review gates for RC work.
if [[ -x scripts/check-unsafe-surfaces.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run_advisory python3 scripts/check-unsafe-surfaces.py . --max-lines 120
  else
    warn "python3 not found; skipping unsafe/FFI surface report"
  fi
fi


if [[ -x scripts/generate-release-dashboard.py ]]; then
  if command -v python3 >/dev/null 2>&1; then
    run_advisory python3 scripts/generate-release-dashboard.py . --markdown /tmp/xenia-release-dashboard.md --json /tmp/xenia-release-dashboard.json
  else
    warn "python3 not found; skipping release dashboard generation"
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  warn "cargo not found; skipping Rust checks"
  exit "$failures"
fi

validate_cargo_dir() {
  local dir="$1"
  [[ -f "$dir/Cargo.toml" ]] || return 0
  (
    cd "$dir"
    # `--locked` when a Cargo.lock is actually present -- xenia-peer commits
    # one (application workspace: needs reproducible builds), but this
    # function also runs against xenia-wire, a library that deliberately
    # gitignores its lockfile (see xenia-wire/Cargo.toml's own convention).
    # Forcing --locked unconditionally would break that case with no
    # lockfile to lock against.
    local locked_flag=()
    [[ -f Cargo.lock ]] && locked_flag=(--locked)
    # xenia-launcher-windows is Windows-only: unconditional Win32 API usage
    # (won't even compile without the `windows` crate, which is
    # target-gated to cfg(windows)). xenia-launcher-shell/xenia-launcher-linux
    # need GTK3/libappindicator/libxdo system dev headers (tray-icon's Linux
    # backend) this runner doesn't have. xenia-launcher-macos is macOS-only
    # (unconditional Objective-C message-send usage, no Apple SDK/objc2 on
    # this runner). Exclude all four from a bare host `cargo check`/
    # `test --no-run` here, same reasoning as the MSRV job's explicit
    # --exclude (their own windows-latest / linux-launcher / macos-launcher
    # CI jobs cover them for real). Only applies when this workspace
    # actually has those members -- xenia-wire's own separate workspace
    # doesn't.
    local exclude_flags=()
    if [[ -f apps/xenia-launcher-windows/Cargo.toml ]]; then
      exclude_flags=(--exclude xenia-launcher-windows --exclude xenia-launcher-shell --exclude xenia-launcher-linux --exclude xenia-launcher-macos)
    fi
    cargo metadata --format-version 1 --no-deps >/dev/null || exit $?
    cargo fmt --all -- --check || exit $?
    cargo check "${locked_flag[@]}" --workspace --all-targets "${exclude_flags[@]}" || exit $?
    cargo test "${locked_flag[@]}" --workspace --all-targets --no-run "${exclude_flags[@]}" || exit $?
  )
}

check_cargo_dir() {
  local dir="$1"
  [[ -f "$dir/Cargo.toml" ]] || return 0
  run validate_cargo_dir "$dir"
}

# Support both the transitional flat extraction and the intended Xenia tree.
if [[ -f Cargo.toml ]]; then
  check_cargo_dir .
fi
if [[ -f xenia-wire/Cargo.toml ]]; then
  check_cargo_dir xenia-wire
fi
if [[ -f xenia-peer/Cargo.toml ]]; then
  check_cargo_dir xenia-peer
fi

# Supply-chain checks are advisory unless cargo-deny is installed in the active
# shell. The Nix CI shell includes cargo-deny so this becomes enforced there.
if [[ -f deny.toml ]]; then
  if command -v cargo-deny >/dev/null 2>&1; then
    run cargo deny check advisories bans licenses sources
  elif command -v cargo >/dev/null 2>&1; then
    if cargo deny --version >/dev/null 2>&1; then
      run cargo deny check advisories bans licenses sources
    else
      warn "cargo-deny not found; skipping supply-chain policy check"
    fi
  else
    warn "cargo-deny not found; skipping supply-chain policy check"
  fi
fi

# `cargo vet` (audit provenance -- has this specific dependency *version*
# actually been reviewed by someone, self or a trusted third party) is a
# real gate here, same as cargo-deny above. This used to be advisory-only
# because xenia-peer's Cargo.lock was gitignored, so the exact dependency
# versions CI resolved could drift from whatever was current when
# `supply-chain/` was last updated -- cargo-vet's exemptions are pinned to
# specific versions, so a routine upstream patch release (not a real
# supply-chain event) would otherwise fail this unpredictably on unrelated
# PRs. Now that Cargo.lock is committed (2026-07-19), dependency versions
# only change on a deliberate `cargo update`, so drift is no longer
# spontaneous -- bump the lockfile and run `cargo vet regenerate
# exemptions` (after actually reviewing what changed) in the same commit.
if [[ -f supply-chain/config.toml ]]; then
  if command -v cargo-vet >/dev/null 2>&1 || cargo vet --version >/dev/null 2>&1; then
    run cargo vet --locked
  else
    warn "cargo-vet not found; skipping supply-chain audit-provenance check"
  fi
fi

# If this is a flat directory of crate tarball extracts with workspace-inherited
# manifests, do not try to synthesize a workspace here. That normalization belongs
# in the active repo, not in this validator.

if ! finish_validation; then
  exit 1
fi
