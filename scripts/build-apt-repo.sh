#!/usr/bin/env bash
# Assemble a real, GPG-signed flat APT repository from a directory of .deb
# files. See docs/packaging/apt-repo.md for the full picture: this produces
# a correct repo layout on disk; it does not decide where (or whether) to
# host it publicly, and does not run automatically anywhere yet.
#
# Usage:
#   ./scripts/build-apt-repo.sh <deb-input-dir> <repo-output-dir> <gpg-key-id>
#
# <deb-input-dir>   directory containing one or more *.deb files (e.g. the
#                   xenia-launcher-linux-deb artifact downloaded from CI)
# <repo-output-dir> where to write the repo tree (created fresh; refuses to
#                   overwrite an existing dir so a stale repo can't get
#                   silently half-clobbered)
# <gpg-key-id>      fingerprint or key ID to sign with -- must already be
#                   importable by `gpg` in the environment this runs in
#                   (see scripts/generate-apt-signing-key.sh)
#
# Produces a standard Debian flat-repo layout:
#   <repo-output-dir>/
#     pool/main/*.deb
#     dists/stable/Release          (unsigned metadata)
#     dists/stable/Release.gpg      (detached signature over Release)
#     dists/stable/InRelease        (clearsigned Release -- what modern apt prefers)
#     dists/stable/main/binary-amd64/Packages
#     dists/stable/main/binary-amd64/Packages.gz
#
# Needs dpkg-scanpackages (from `dpkg`) and `gpg` on PATH -- on this NixOS
# dev machine, get both via:
#   nix-shell -p dpkg gnupg --run './scripts/build-apt-repo.sh ...'

set -euo pipefail

DEB_DIR="${1:?usage: $0 <deb-input-dir> <repo-output-dir> <gpg-key-id>}"
REPO_DIR="${2:?usage: $0 <deb-input-dir> <repo-output-dir> <gpg-key-id>}"
KEY_ID="${3:?usage: $0 <deb-input-dir> <repo-output-dir> <gpg-key-id>}"

CODENAME="${APT_REPO_CODENAME:-stable}"
COMPONENT="${APT_REPO_COMPONENT:-main}"
ARCH="${APT_REPO_ARCH:-amd64}"
ORIGIN="${APT_REPO_ORIGIN:-Xenia Launcher}"
LABEL="${APT_REPO_LABEL:-Xenia Launcher}"
DESCRIPTION="${APT_REPO_DESCRIPTION:-Xenia Launcher APT repository}"

for tool in dpkg-scanpackages gpg gzip; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool not found on PATH (see this script's header comment)" >&2
    exit 1
  }
done

if [[ ! -d "$DEB_DIR" ]] || ! compgen -G "$DEB_DIR"/*.deb >/dev/null; then
  echo "error: no *.deb files found in $DEB_DIR" >&2
  exit 1
fi

if [[ -e "$REPO_DIR" ]]; then
  echo "error: $REPO_DIR already exists -- refusing to overwrite" >&2
  exit 1
fi

POOL_DIR="$REPO_DIR/pool/$COMPONENT"
BINARY_DIR="$REPO_DIR/dists/$CODENAME/$COMPONENT/binary-$ARCH"
mkdir -p "$POOL_DIR" "$BINARY_DIR"

cp "$DEB_DIR"/*.deb "$POOL_DIR/"

# dpkg-scanpackages wants to be run from the repo root so the Filename:
# fields it emits are relative to it (what a real client resolves against
# the repo's base URL).
(
  cd "$REPO_DIR"
  dpkg-scanpackages --arch "$ARCH" "pool/$COMPONENT" > "dists/$CODENAME/$COMPONENT/binary-$ARCH/Packages"
)
gzip -9c "$BINARY_DIR/Packages" > "$BINARY_DIR/Packages.gz"

# Build the Release file by hand: apt-ftparchive isn't guaranteed present in
# this dev environment either, and the format is simple enough to be
# explicit about rather than depend on a third tool. Every listed file gets
# its size + MD5/SHA1/SHA256 -- apt checks all three where present, and this
# script writes all three so it works against picky client configs.
DIST_DIR="$REPO_DIR/dists/$CODENAME"
RELEASE_FILE="$DIST_DIR/Release"

hash_section() {
  local algo="$1" cmd="$2"
  echo "$algo:"
  ( cd "$DIST_DIR" && find "$COMPONENT/binary-$ARCH" -type f | sort | while read -r f; do
      sum=$("$cmd" "$f" | awk '{print $1}')
      size=$(stat -c%s "$f")
      printf ' %s %16d %s\n' "$sum" "$size" "$f"
    done )
}

{
  echo "Origin: $ORIGIN"
  echo "Label: $LABEL"
  echo "Suite: $CODENAME"
  echo "Codename: $CODENAME"
  echo "Architectures: $ARCH"
  echo "Components: $COMPONENT"
  echo "Description: $DESCRIPTION"
  echo "Date: $(date -Ru)"
  hash_section MD5Sum md5sum
  hash_section SHA1 sha1sum
  hash_section SHA256 sha256sum
} > "$RELEASE_FILE"

gpg --local-user "$KEY_ID" --detach-sign --armor -o "$DIST_DIR/Release.gpg" "$RELEASE_FILE"
gpg --local-user "$KEY_ID" --clearsign -o "$DIST_DIR/InRelease" "$RELEASE_FILE"

echo
echo "Built repo at $REPO_DIR"
echo "Test locally with:"
echo "  python3 -m http.server -d $REPO_DIR 8000"
echo "  echo 'deb [signed-by=/path/to/pubkey.asc] http://localhost:8000 $CODENAME $COMPONENT' | sudo tee /etc/apt/sources.list.d/xenia-test.list"
echo "  sudo apt-get update"
