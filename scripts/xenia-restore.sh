#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/xenia-restore.sh ARCHIVE TARGET_DIR [OPTIONS]

Restore a backup produced by scripts/xenia-backup.sh into TARGET_DIR.
State directories land at TARGET_DIR/xenia-peer-state,
TARGET_DIR/xenia-operator-agent-state (matching the archive layout) --
point xenia-peer/xenia-operator-agent's --*-path flags there afterward,
or make TARGET_DIR the process's working directory to pick up the
binaries' own defaults directly.

Arguments:
  ARCHIVE                   Path to a .tar.gz (or .tar.gz.age) archive
                             from xenia-backup.sh.
  TARGET_DIR                Directory to restore into (created if absent).

Options:
  --force                    Overwrite an existing, non-empty
                              xenia-peer-state/ or xenia-operator-agent-state/
                              under TARGET_DIR. Without this, restoring on
                              top of live state is refused.
  --decrypt-with IDENTITY_FILE
                              Decrypt an age-encrypted archive using this
                              identity (private key) file. Omit for a
                              passphrase-encrypted archive -- `age` will
                              prompt interactively. Requires `age` on PATH
                              for any *.age archive.
  -h, --help                  Show this help.

This script does not cryptographically verify the restored consent
ledger or audit chain -- xenia-peer and xenia-operator-agent already
refuse to start on a corrupt/tampered one (fail closed), which is the
same trusted verification code path this would otherwise duplicate in
bash. If either binary refuses to start after a restore, that is the
signal to check the backup's integrity, not a bug in this script.
USAGE
}

if [[ $# -lt 2 ]]; then
  usage >&2
  exit 1
fi

archive="$1"
target_dir="$2"
shift 2

force=0
decrypt_with=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) force=1; shift ;;
    --decrypt-with) decrypt_with="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ ! -f "$archive" ]]; then
  echo "error: archive not found: $archive" >&2
  exit 1
fi

mkdir -p "$target_dir"

# Refuse to clobber live state unless --force -- checked BEFORE touching
# anything, so a refusal never leaves a half-extracted archive behind.
if [[ "$force" -ne 1 ]]; then
  for leaf in xenia-peer-state xenia-operator-agent-state; do
    existing="${target_dir%/}/${leaf}"
    if [[ -d "$existing" ]] && [[ -n "$(ls -A "$existing" 2>/dev/null)" ]]; then
      echo "error: ${existing} already exists and is non-empty. Pass --force to overwrite." >&2
      exit 1
    fi
  done
fi

plain_tar="$archive"
cleanup() {
  if [[ -n "${decrypted_tmp:-}" ]] && [[ -f "$decrypted_tmp" ]]; then
    rm -f "$decrypted_tmp"
  fi
}
trap cleanup EXIT

if [[ "$archive" == *.age ]]; then
  if ! command -v age >/dev/null 2>&1; then
    echo "error: age not found on PATH; cannot decrypt $archive" >&2
    exit 1
  fi
  decrypted_tmp="$(mktemp)"
  if [[ -n "$decrypt_with" ]]; then
    age -d -i "$decrypt_with" -o "$decrypted_tmp" "$archive"
  else
    # No identity given: age prompts interactively for a passphrase if
    # that's what the archive was encrypted with.
    age -d -o "$decrypted_tmp" "$archive"
  fi
  plain_tar="$decrypted_tmp"
fi

echo "Restoring into: $target_dir"
tar --numeric-owner -p -xzf "$plain_tar" -C "$target_dir"

# Defense in depth against a backup/transfer step that didn't preserve
# modes: re-assert owner-only permissions on the restored state dirs.
for leaf in xenia-peer-state xenia-operator-agent-state; do
  d="${target_dir%/}/${leaf}"
  if [[ -d "$d" ]]; then
    chmod 700 "$d"
    find "$d" -maxdepth 1 -type f -exec chmod 600 {} +
    echo "  restored: $d"
  fi
done

echo "Restore complete. Start xenia-peer/xenia-operator-agent pointed at"
echo "this directory (or with it as the working directory) to verify --"
echo "both fail closed at startup on a corrupt or tampered ledger/audit chain."
