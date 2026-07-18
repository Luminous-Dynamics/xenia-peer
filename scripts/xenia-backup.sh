#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/xenia-backup.sh [OPTIONS]

Back up xenia-peer's and/or xenia-operator-agent's state directories
(private keys, consent ledger, host-trust pins, audit log) into a single
timestamped archive. See docs/deploy/backup-and-restore.md for what's
included and why it matters.

Options:
  --state-dir PATH          Back up this state directory (repeatable).
                             Default: auto-detect both systemd-standard
                             locations
                             (~/.local/state/xenia-peer/xenia-peer-state and
                             ~/.local/state/xenia-operator-agent/xenia-operator-agent-state).
                             Pass explicitly for a manually-run, CWD-relative
                             layout.
  --operators-file PATH     Also include this --operators-file (not secret,
                             but operationally important; not auto-detected
                             since it has no default path).
  --revoked-operators-file PATH
                             Also include this --revoked-operators-file.
  --out DIR                 Directory to write the archive into. Default: ".".
  --encrypt-to RECIPIENT    Encrypt the archive to this age recipient (a
                             public-key string, or a file containing one or
                             more recipients) via `age -r`/`age -R`. Requires
                             `age` on PATH.
  --passphrase               Encrypt the archive with a passphrase via
                             `age -p` (interactive prompt). Requires `age`.
  -h, --help                 Show this help.

Without --encrypt-to/--passphrase, the archive is written PLAINTEXT and
contains raw private key material -- encrypt it yourself before storing
it anywhere off this host.
USAGE
}

state_dirs=()
operators_file=""
revoked_operators_file=""
out_dir="."
encrypt_to=""
use_passphrase=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-dir) state_dirs+=("$2"); shift 2 ;;
    --operators-file) operators_file="$2"; shift 2 ;;
    --revoked-operators-file) revoked_operators_file="$2"; shift 2 ;;
    --out) out_dir="$2"; shift 2 ;;
    --encrypt-to) encrypt_to="$2"; shift 2 ;;
    --passphrase) use_passphrase=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -n "$encrypt_to" && "$use_passphrase" -eq 1 ]]; then
  echo "error: --encrypt-to and --passphrase are mutually exclusive" >&2
  exit 1
fi

# Auto-detect only when the caller passed no --state-dir at all -- an
# explicit (even empty-after-filtering) list must never silently fall
# back to a different set of directories than what was asked for.
if [[ ${#state_dirs[@]} -eq 0 ]]; then
  for candidate in \
    "$HOME/.local/state/xenia-peer/xenia-peer-state" \
    "$HOME/.local/state/xenia-operator-agent/xenia-operator-agent-state"; do
    if [[ -d "$candidate" ]]; then
      state_dirs+=("$candidate")
    fi
  done
fi

if [[ ${#state_dirs[@]} -eq 0 ]]; then
  echo "error: no state directories found. Pass --state-dir explicitly (e.g." >&2
  echo "for a manually-run, CWD-relative layout), or check that xenia-peer /" >&2
  echo "xenia-operator-agent have been run at least once." >&2
  exit 1
fi

for d in "${state_dirs[@]}"; do
  if [[ ! -d "$d" ]]; then
    echo "error: state directory not found: $d" >&2
    exit 1
  fi
done

mkdir -p "$out_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive_path="${out_dir%/}/xenia-backup-${timestamp}.tar.gz"

# Interleaved -C/path pairs so the archive stores paths relative to each
# item's own parent directory, never the absolute host path.
tar_args=(--numeric-owner -p -czf "$archive_path")
for d in "${state_dirs[@]}"; do
  tar_args+=(-C "$(dirname "$d")" "$(basename "$d")")
done
if [[ -n "$operators_file" ]]; then
  if [[ ! -f "$operators_file" ]]; then
    echo "error: --operators-file not found: $operators_file" >&2
    exit 1
  fi
  tar_args+=(-C "$(dirname "$operators_file")" "$(basename "$operators_file")")
fi
if [[ -n "$revoked_operators_file" ]]; then
  if [[ ! -f "$revoked_operators_file" ]]; then
    echo "error: --revoked-operators-file not found: $revoked_operators_file" >&2
    exit 1
  fi
  tar_args+=(-C "$(dirname "$revoked_operators_file")" "$(basename "$revoked_operators_file")")
fi

echo "Backing up:"
for d in "${state_dirs[@]}"; do echo "  $d"; done
[[ -n "$operators_file" ]] && echo "  $operators_file"
[[ -n "$revoked_operators_file" ]] && echo "  $revoked_operators_file"

tar "${tar_args[@]}"

if [[ -n "$encrypt_to" || "$use_passphrase" -eq 1 ]]; then
  if ! command -v age >/dev/null 2>&1; then
    echo "error: age not found on PATH; cannot encrypt. Install age, or omit" >&2
    echo "--encrypt-to/--passphrase to produce a plaintext archive (not" >&2
    echo "recommended for off-host storage)." >&2
    exit 1
  fi
  encrypted_path="${archive_path}.age"
  if [[ -n "$encrypt_to" ]]; then
    if [[ -f "$encrypt_to" ]]; then
      age -R "$encrypt_to" -o "$encrypted_path" "$archive_path"
    else
      age -r "$encrypt_to" -o "$encrypted_path" "$archive_path"
    fi
  else
    age -p -o "$encrypted_path" "$archive_path"
  fi
  rm -f "$archive_path"
  chmod 600 "$encrypted_path"
  echo "Encrypted backup written to: $encrypted_path"
else
  chmod 600 "$archive_path"
  echo "WARNING: this archive is PLAINTEXT and contains raw private key material."
  echo "         Encrypt it yourself before copying it off this host, or re-run"
  echo "         with --encrypt-to/--passphrase. See docs/deploy/backup-and-restore.md."
  echo "Backup written to: $archive_path"
fi
