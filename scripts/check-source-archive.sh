#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/check-source-archive.sh ARCHIVE.tar.gz

Validates that a source archive does not contain build output, VCS/agent state,
previous archives, runtime secrets/state, unsafe archive members, or absolute
local workspace references in source/config files.
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

archive="${1:-}"
if [[ -z "$archive" || ! -f "$archive" ]]; then
  echo "error: archive file required" >&2
  usage >&2
  exit 2
fi

fail=0
section() { printf '\n== %s ==\n' "$1"; }

list_file="$(mktemp)"
verbose_list_file="$(mktemp)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir" "$list_file" "$verbose_list_file"' EXIT

section 'archive inventory smoke check'
if ! tar -tzf "$archive" >"$list_file" || ! tar -tvzf "$archive" >"$verbose_list_file"; then
  echo "error: unable to read archive: $archive" >&2
  exit 2
fi
wc -l "$list_file" | awk '{print "entries: " $1}'

# We extract below to scan source/config contents. Refuse member names and entry
# types that could escape or redirect that temporary extraction first. Xenia
# source archives currently contain regular files/directories only; links and
# device/FIFO entries have no legitimate release role.
section 'unsafe archive members'
if grep -E '(^/|(^|/)\.\.(/|$))' "$list_file"; then
  fail=1
fi
if awk '$1 ~ /^[lhbcp]/ { print }' "$verbose_list_file" | grep -q .; then
  awk '$1 ~ /^[lhbcp]/ { print }' "$verbose_list_file"
  fail=1
fi
if ((fail)); then
  echo 'unsafe member(s) found'
else
  echo 'clean'
fi

section 'disallowed paths'
if grep -E '(^|/)(target|dist|pkg|node_modules|\.git|\.claude|\.direnv)(/|$)' "$list_file"; then
  fail=1
else
  echo 'clean'
fi

section 'nested archive files'
if grep -Ei '\.(tar\.gz|tgz|zip)$' "$list_file"; then
  fail=1
else
  echo 'clean'
fi

section 'runtime secret/state files'
# Reject the complete known runtime-state directories, plus secret-bearing file
# classes anywhere in the archive. Checking only operator.key is insufficient:
# host identity, consent-ledger, ML-DSA, and operator-agent keys use different
# basenames but are equally sensitive.
secret_re='(^|/)(xenia-peer-state|xenia-operator-agent-state)(/|$)|(^|/)(\.env(\.[^/]+)?|[^/]+\.(key|pem|p12|pfx|sqlite|db|ledger))$'
if grep -Ei "$secret_re" "$list_file"; then
  fail=1
else
  echo 'clean'
fi

section 'absolute local workspace references in source/config'
needle='/srv'"/luminous-dynamics|/"'home/'"|/"'mnt/data|tristan'"\\.stoltz@|evolvingresonantcocreationism\\.com"

# Extraction is safe only after the member checks above. If an unsafe member was
# present, do not extract even into the temporary directory.
if ((fail)) && { grep -Eq '(^/|(^|/)\.\.(/|$))' "$list_file" || awk '$1 ~ /^[lhbcp]/ { found=1 } END { exit !found }' "$verbose_list_file"; }; then
  echo 'skipped because archive contains unsafe members'
else
  tar -xzf "$archive" -C "$tmpdir"
  if command -v rg >/dev/null 2>&1; then
    if rg -n --hidden -g '!**/*.md' -g '!**/target/**' -g '!**/dist/**' -g '!**/.git/**' -g '!**/.claude/**' -g '!**/scripts/check-source-archive.sh' -g '!**/scripts/xenia-hygiene-audit.sh' -g '!**/scripts/generate-source-archive-checksums.py' "$needle" "$tmpdir"; then
      fail=1
    else
      echo 'clean'
    fi
  else
    if grep -RE --exclude='*.md' --exclude='check-source-archive.sh' --exclude='xenia-hygiene-audit.sh' --exclude='generate-source-archive-checksums.py' --exclude-dir='.git' --exclude-dir='.claude' --exclude-dir='target' --exclude-dir='dist' "$needle" "$tmpdir"; then
      fail=1
    else
      echo 'clean'
    fi
  fi
fi

if ((fail)); then
  printf '\nSource archive validation failed: %s\n' "$archive" >&2
  exit 1
fi

printf '\nSource archive validation passed: %s\n' "$archive"
