#!/usr/bin/env bash
# Generate a GPG keypair for signing a future xenia-launcher APT repository's
# Release/InRelease files. See docs/packaging/apt-repo.md for the full
# picture -- this script only produces the keypair; it does not publish
# anything or decide where a repo would be hosted.
#
# This is deliberately NOT run against a real identity by default. A repo
# signing key's public half becomes a permanent, published part of the
# project's trust story (anyone who ever ran `apt-key add` or trusted the
# repo keeps trusting this key until it's explicitly revoked), so the
# name/email embedded in it should be a project decision, not a default this
# script silently picks. Override via env vars; the script refuses to run
# with the placeholder defaults still in place.
#
# Usage:
#   APT_REPO_KEY_NAME="Xenia Launcher APT Repository" \
#   APT_REPO_KEY_EMAIL="packaging@example.org" \
#   APT_REPO_KEY_EXPIRE="2y" \
#     ./scripts/generate-apt-signing-key.sh /path/to/output/dir
#
# Produces, in the given output dir:
#   - gnupg-home/          a throwaway GNUPGHOME containing the keypair
#   - xenia-launcher-apt-repo-public.asc   the exported public key (ASCII-armored)
#   - fingerprint.txt      the key's fingerprint, for docs/verification
#
# The private key stays only inside gnupg-home/ -- it is the caller's
# responsibility to move it somewhere durable (this project's convention is
# BWS, see CLAUDE.md's Credentials section) and then delete this directory.
# Nothing in this script uploads or transmits the private key anywhere.

set -euo pipefail

KEY_NAME="${APT_REPO_KEY_NAME:-CHANGE_ME}"
KEY_EMAIL="${APT_REPO_KEY_EMAIL:-CHANGE_ME}"
KEY_EXPIRE="${APT_REPO_KEY_EXPIRE:-2y}"
OUT_DIR="${1:?usage: $0 <output-dir>}"

if [[ "$KEY_NAME" == "CHANGE_ME" || "$KEY_EMAIL" == "CHANGE_ME" ]]; then
  echo "error: set APT_REPO_KEY_NAME and APT_REPO_KEY_EMAIL before running this" >&2
  echo "       (see the script's own header comment for why these aren't defaulted)" >&2
  exit 1
fi

if [[ -e "$OUT_DIR" ]]; then
  echo "error: $OUT_DIR already exists -- refusing to overwrite" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
GNUPGHOME="$OUT_DIR/gnupg-home"
mkdir -m 700 "$GNUPGHOME"
export GNUPGHOME

echo "Generating a fresh ed25519 signing-only keypair (no encryption subkey --"
echo "an APT repo key only ever signs Release files, it never needs to decrypt"
echo "anything)."

gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  "$KEY_NAME <$KEY_EMAIL>" ed25519 sign "$KEY_EXPIRE"

FPR=$(gpg --list-secret-keys --with-colons "$KEY_EMAIL" \
  | awk -F: '/^fpr:/ { print $10; exit }')

gpg --armor --export "$FPR" > "$OUT_DIR/xenia-launcher-apt-repo-public.asc"
echo "$FPR" > "$OUT_DIR/fingerprint.txt"

echo
echo "Done. Fingerprint: $FPR"
echo "Public key:  $OUT_DIR/xenia-launcher-apt-repo-public.asc"
echo "Private key: still only inside $GNUPGHOME (GNUPGHOME for this session)."
echo
echo "Next steps (not done by this script):"
echo "  1. Move the private key to durable storage (this project's convention"
echo "     is BWS -- see CLAUDE.md's Credentials section) via:"
echo "       GNUPGHOME=$GNUPGHOME gpg --armor --export-secret-keys $FPR"
echo "  2. Delete $GNUPGHOME once step 1 is done."
echo "  3. Commit xenia-launcher-apt-repo-public.asc somewhere users can find"
echo "     it (e.g. docs/packaging/, or a real repo hosting location once one"
echo "     is decided -- see docs/packaging/apt-repo.md)."
