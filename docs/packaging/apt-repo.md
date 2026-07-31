# Linux APT repository -- groundwork

Companion to `docs/packaging/README.md`'s bottom-line on Linux signing: a
directly-installed `.deb` (`sudo dpkg -i xenia-launcher_*.deb`) has no
Gatekeeper/SmartScreen-equivalent gate, so nothing here is required for that
path. This groundwork only matters if `apt install xenia-launcher` via a real
hosted repository is ever wanted.

**Status: tooling built and verified end-to-end against a real `apt` client
using a throwaway test key and a fake `.deb`. No production signing key has
been generated, and no repository is hosted anywhere.** Both of those are
real decisions, not implementation work -- see "What's still a decision"
below.

## What exists now

- `scripts/generate-apt-signing-key.sh` -- generates an ed25519,
  signing-only GPG keypair (no encryption subkey; a repo key only ever signs
  `Release` files). Refuses to run with placeholder name/email so a real
  identity has to be a deliberate choice, not a script default.
- `scripts/build-apt-repo.sh` -- takes a directory of `.deb` files (e.g. the
  `xenia-launcher-linux-deb` CI artifact) and a GPG key ID, and produces a
  standard flat Debian repo layout: `pool/main/*.deb`,
  `dists/stable/main/binary-amd64/Packages{,.gz}`, `dists/stable/Release`
  (with MD5/SHA1/SHA256 hash sections), `dists/stable/Release.gpg` (detached
  signature), and `dists/stable/InRelease` (clearsigned -- what modern `apt`
  prefers).

Both scripts need `dpkg-scanpackages` (from `dpkg`) and `gpg` on `PATH`; on
this dev machine that's `nix-shell -p dpkg gnupg --run '...'`.

## How this was verified (not just asserted)

Built with a throwaway test key (`APT_REPO_KEY_EMAIL=test-do-not-use@...`,
1-day expiry, deleted after the test) and a minimal fake `.deb`
(`dpkg-deb --build` on a hand-written control file, no real binary), then
proved the whole chain works with tools that have no stake in believing it
does:

1. `python3 -m http.server` served the built repo tree.
2. A real `apt-get update` (nixpkgs' `apt` package, pointed at an isolated
   `Dir::State`/`Dir::Cache`/sourcelist so it touched nothing on this
   machine) fetched `InRelease` over HTTP and verified its GPG signature
   against the test public key via `[signed-by=...]` -- no
   signature-verification error, which is the real proof this isn't just
   syntactically plausible output.
3. `apt-cache show xenia-launcher-fake-test` against that same isolated
   state resolved the package's full metadata (`Filename`, `Size`,
   `MD5sum`/`SHA1`/`SHA256`, `Description`) from the generated `Packages`
   file.

All three steps used the real Debian tooling a real user's machine would
use, not a hand-rolled parser -- this is what "real, not placeholder"
tooling means here, matching this project's usual bar (see the platform
launcher CI jobs and their own doc comments for the same discipline).

## What's still a decision, not implementation work

**No production signing key exists yet.** Generating one is one command
away (`scripts/generate-apt-signing-key.sh`), but the name/email embedded in
it becomes a permanent, published part of the project's trust story --
anyone who ever trusts the repo keeps trusting that key until it's
explicitly revoked. That's a project-identity choice, not something to
default silently. Once generated, the private key's durable home should be
BWS (this project's standard credential store per `CLAUDE.md`'s Credentials
section, matching how the crates.io token is stored) -- the generation
script deliberately stops short of that step and just prints the export
command.

**No repository is hosted anywhere.** This groundwork produces a correct
repo *tree on disk*; putting it somewhere `apt` can actually reach
(a subdomain, object storage plus a CDN, GitHub Pages, etc.) is a new
public-facing infrastructure decision, in the same category as the
subdomain/hosting choices tracked in `PORTS.md` / `WEBSITE_REGISTRY.md` in
the wider monorepo -- worth raising explicitly rather than assuming.

**Whether to stand this up at all, yet.** There's no released `.deb` in the
wild today (no GitHub Release, no version above `0.0.0-m0`) -- an APT repo
with nothing versioned to track is arguably premature. This groundwork
exists so the remaining work is "make two decisions" rather than "design and
build the tooling from scratch," not because publishing today is
recommended.

## Local testing recipe

For anyone picking this back up:

```bash
nix-shell -p dpkg gnupg -- run 'true'  # or just have dpkg-scanpackages + gpg on PATH

# 1. Generate a keypair (use a real name/email once that decision is made;
#    a short expiry + throwaway email is fine for another local test).
APT_REPO_KEY_NAME="..." APT_REPO_KEY_EMAIL="..." \
  ./scripts/generate-apt-signing-key.sh /tmp/apt-key

# 2. Build the repo from a directory of .deb files.
GNUPGHOME=/tmp/apt-key/gnupg-home \
  ./scripts/build-apt-repo.sh /path/to/debs /tmp/apt-repo <fingerprint>

# 3. Serve and point apt at it (signed-by avoids needing apt-key/system trust).
python3 -m http.server -d /tmp/apt-repo 8000
echo 'deb [signed-by=/tmp/apt-key/xenia-launcher-apt-repo-public.asc] http://localhost:8000 stable main' \
  | sudo tee /etc/apt/sources.list.d/xenia-test.list
sudo apt-get update
```
