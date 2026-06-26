#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
out="${2:-xenia-agent-handoff.md}"
cd "$root"

block() {
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
# Xenia Agent Handoff Report

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Root: $(pwd)

Use this file when handing Xenia to another human or agent. It captures current
state without asking the next actor to infer project truth from terminal history.
EOF_REPORT

block 'Git status' git status --short
block 'Current branch' git branch --show-current
block 'Recent commits' git log --oneline -n 12
block 'Top-level files' find . -maxdepth 2 -mindepth 1 -not -path './.git*' -not -path './target*' | sort

if [[ -x scripts/xenia-hygiene-audit.sh ]]; then
  block 'Hygiene audit' scripts/xenia-hygiene-audit.sh .
fi
if [[ -x scripts/check-codeowners.py ]]; then
  block 'CODEOWNERS check' python3 scripts/check-codeowners.py .
fi
if [[ -x scripts/check-secure-defaults.py ]]; then
  block 'Secure-default scan' python3 scripts/check-secure-defaults.py . --max-lines 120
fi
if [[ -x scripts/generate-release-dashboard.py ]]; then
  block 'Release dashboard' python3 scripts/generate-release-dashboard.py .
fi
if [[ -x scripts/check-xenia-policy.py ]]; then
  block 'Policy manifest check' python3 scripts/check-xenia-policy.py .
fi
if [[ -x scripts/check-release-readiness.py ]]; then
  block 'Release readiness check' python3 scripts/check-release-readiness.py .
fi
if [[ -x scripts/check-normalization-plan.py ]]; then
  block 'Normalization manifest check' python3 scripts/check-normalization-plan.py .
fi
if [[ -x scripts/emit-normalization-plan.py ]]; then
  block 'Normalization move plan' python3 scripts/emit-normalization-plan.py .
fi
if [[ -x scripts/plan-normalization-execution.py ]]; then
  block 'Normalization execution plan' python3 scripts/plan-normalization-execution.py .
fi
if [[ -x scripts/check-post-normalization.py ]]; then
  block 'Post-normalization acceptance check' python3 scripts/check-post-normalization.py .
fi
if [[ -x scripts/check-cargo-boundaries.py ]]; then
  block 'Cargo boundary check' python3 scripts/check-cargo-boundaries.py .
fi
if [[ -x scripts/check-runtime-risk-patterns.py ]]; then
  block 'Runtime risk pattern report' python3 scripts/check-runtime-risk-patterns.py . --max-lines 80
fi
if [[ -x scripts/check-unsafe-surfaces.py ]]; then
  block 'Unsafe/FFI surface report' python3 scripts/check-unsafe-surfaces.py . --max-lines 80
fi
if [[ -x scripts/collect-xenia-metrics.py ]]; then
  block 'Repository metrics' python3 scripts/collect-xenia-metrics.py .
fi

cat <<EOF_DONE
wrote: $out
EOF_DONE
