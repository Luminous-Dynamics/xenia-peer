#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
out="${2:-xenia-preflight-report.md}"
cd "$root"

run_block() {
  local title="$1"
  shift
  {
    echo
    echo "## $title"
    echo
    echo '```text'
    "$@" 2>&1 || true
    echo '```'
  } >> "$out"
}

cat > "$out" <<EOF_REPORT
# Xenia Preflight Report

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Root: $(pwd)

This report is intentionally diagnostic. A command appearing here does not mean
it passed; inspect each block.
EOF_REPORT

run_block 'Git status' git status --short
run_block 'Top-level layout' find . -maxdepth 2 -mindepth 1 -type d -not -path './.git*' -not -path './target*' | sort
run_block 'Hygiene audit' bash scripts/xenia-hygiene-audit.sh .
if [[ -x scripts/check-codeowners.py ]]; then
  run_block 'CODEOWNERS check' python3 scripts/check-codeowners.py .
fi
if [[ -x scripts/check-secure-defaults.py ]]; then
  run_block 'Secure-default scan' python3 scripts/check-secure-defaults.py . --max-lines 120
fi
if [[ -x scripts/generate-release-dashboard.py ]]; then
  run_block 'Release dashboard' python3 scripts/generate-release-dashboard.py .
fi
if [[ -x scripts/check-xenia-policy.py ]]; then
  run_block 'Policy manifest check' python3 scripts/check-xenia-policy.py .
fi
if [[ -x scripts/check-release-readiness.py ]]; then
  run_block 'Release readiness check' python3 scripts/check-release-readiness.py .
fi
if [[ -x scripts/check-normalization-plan.py ]]; then
  run_block 'Normalization manifest check' python3 scripts/check-normalization-plan.py .
fi
if [[ -x scripts/emit-normalization-plan.py ]]; then
  run_block 'Normalization move plan' python3 scripts/emit-normalization-plan.py .
fi
if [[ -x scripts/plan-normalization-execution.py ]]; then
  run_block 'Normalization execution plan' python3 scripts/plan-normalization-execution.py .
fi
if [[ -x scripts/check-post-normalization.py ]]; then
  run_block 'Post-normalization acceptance check' python3 scripts/check-post-normalization.py .
fi
if [[ -x scripts/check-cargo-boundaries.py ]]; then
  run_block 'Cargo boundary check' python3 scripts/check-cargo-boundaries.py .
fi
if [[ -x scripts/check-runtime-risk-patterns.py ]]; then
  run_block 'Runtime risk pattern report' python3 scripts/check-runtime-risk-patterns.py . --max-lines 120
fi
if [[ -x scripts/check-unsafe-surfaces.py ]]; then
  run_block 'Unsafe/FFI surface report' python3 scripts/check-unsafe-surfaces.py . --max-lines 120
fi
if [[ -x scripts/collect-xenia-metrics.py ]]; then
  run_block 'Repository metrics' python3 scripts/collect-xenia-metrics.py .
fi
if command -v cargo >/dev/null 2>&1 && [[ -f Cargo.toml ]]; then
  run_block 'Cargo metadata' cargo metadata --format-version 1 --no-deps
fi
if command -v nix >/dev/null 2>&1 && [[ -f flake.nix ]]; then
  run_block 'Nix flake metadata' nix flake metadata
fi

cat <<EOF_DONE
wrote: $out
EOF_DONE
