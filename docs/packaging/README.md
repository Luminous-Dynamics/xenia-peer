# Xenia launcher packaging

Real, CI-built installer/package artifacts for the three native launcher
shells (`xenia-launcher-windows`, `xenia-launcher-linux`,
`xenia-launcher-macos`), so they can be handed to someone as a download
rather than requiring a `cargo build` from source.

## What exists today

| Platform | Format | Tool | CI job | Artifact |
|----------|--------|------|--------|----------|
| Windows | `.msi` | [cargo-wix](https://github.com/volks73/cargo-wix) (WiX Toolset v3) | `windows-launcher-windows` | `xenia-launcher-windows-msi` |
| Linux | `.deb` | [cargo-deb](https://github.com/kornelski/cargo-deb) | `linux-launcher` | `xenia-launcher-linux-deb` |
| macOS | `.app` (zipped) | hand-built bundle (no notarization tooling required) | `macos-launcher` | `xenia-launcher-macos-app` |

Every artifact is built and uploaded by the platform's own real CI job
(`windows-latest`/`ubuntu-latest`/`macos-latest`) -- not built or verified
locally, for the same reasons the launcher crates themselves couldn't be:
WiX Toolset, `dpkg-deb`, and macOS bundle conventions each need their real
platform (or, for `.deb`, at minimum a Debian-family userland) to build and
mean anything.

## What's deliberately NOT here yet: signing and notarization

**Windows**: the `.msi` is unsigned. There is no purchased Windows code-signing
certificate (Authenticode) in this project's infrastructure. An unsigned
installer will trigger a Microsoft SmartScreen "Windows protected your PC"
warning on a fresh machine -- the installer still works if the user clicks
"More info" -> "Run anyway," but this is a real, disclosed rough edge, not
something `cargo wix` or CI can paper over.

A real *free* path exists and was researched (not just assumed) 2026-07-31:
the [SignPath Foundation's open-source program](https://signpath.io/solutions/open-source-community)
signs qualifying OSS projects for free, holding the private key on its own
HSM rather than handing it to the project. Confirmed eligibility criteria
(via `signpath.org/terms.html`): an OSI-approved license without commercial
dual-licensing (AGPL-3.0-or-later qualifies), no malware, actively
maintained, functionality documented on a download page, and -- the one real
gap today -- **the project must already have released software in the form
that needs signing**; a from-source `cargo wix`/`cargo deb` build with no
GitHub Release or version above `0.0.0-m0` likely doesn't clear that bar
yet. Confirmed CI integration mechanics (via `docs.signpath.io/trusted-build-systems/github`):
a single `SIGNPATH_API_TOKEN` secret, the
`signpath/github-action-submit-signing-request` action submitting an
already-uploaded `actions/upload-artifact` artifact for signing and
downloading the signed result back -- no private key material ever touches
this project's own CI. Applying is a real, externally-visible action
(project name/description handed to a third party) and hasn't been done --
worth doing once there's an actual release to point the application at.
Azure Trusted Signing (~$10/month) remains a cheaper-than-a-cert fallback if
SignPath eligibility doesn't pan out.

**macOS**: the `.app` bundle is unsigned and unnotarized. Gatekeeper will
refuse to open it via a normal double-click on a fresh machine -- the user
has to right-click -> Open (accepting the one-time override) or run
`xattr -d com.apple.quarantine Xenia\ Launcher.app` after unzipping. Fixing
this needs an actual Apple Developer Program enrollment (a paid, identity-
verified account), a Developer ID Application certificate, and wiring
`codesign`/`xcrun notarytool` into the CI job. None of that exists in this
project's infrastructure either.

**Linux**: no signing gap here -- `.deb` packages aren't gated by an
OS-level Gatekeeper/SmartScreen equivalent for local installation (`sudo dpkg
-i` just works). A real APT repository would want GPG-signed
`Release`/`Packages` files, but that's a distribution-infrastructure concern
distinct from the package itself, and not required for someone to install
the `.deb` directly. Groundwork for that (key-generation and repo-build
tooling, verified end-to-end against a real `apt` client) exists in
`docs/packaging/apt-repo.md` -- not wired up or hosted anywhere yet, since
standing up a real repo is a separate hosting decision.

**Bottom line**: these are real, working, CI-verified installers -- not
placeholders -- but they are not yet suitable for wide, unsuspecting-user
distribution without the signing/notarization step above. Treat them as
"build artifacts for people who trust the source and are willing to click
through one OS warning," not "ready for a public download page," until that
infrastructure is funded and wired in.

## Windows (`.msi`)

- Config: `apps/xenia-launcher-windows/wix/main.wxs` (generated via `cargo
  wix init`, then hand-verified for well-formed XML -- see git history for
  the exact `cargo wix init` invocation used).
- Product name: "Xenia Launcher". Manufacturer: "Tristan Stoltz" (the
  `authors` field in the root `Cargo.toml` contains a literal
  `<maintainer-email>` placeholder that was never filled in, which
  `cargo wix`'s own parser mangled into a stray `>` -- worth fixing
  upstream in `Cargo.toml` at some point, unrelated to packaging itself).
- No EULA dialog: AGPL-3.0-or-later isn't one of the three licenses
  (`MIT`/`Apache-2.0`/`GPL-3.0`) `cargo wix init` auto-generates an RTF
  EULA for, and no EULA dialog is legally required for AGPL software at
  install time. Can be added later by hand-editing the `.wxs` file.
- Installs the `xenia-launcher.exe` binary plus an optional PATH-variable
  feature (unchecked by default in the installer's feature tree).

## Linux (`.deb`)

- Config: `[package.metadata.deb]` in `apps/xenia-launcher-linux/Cargo.toml`.
- Installs the `xenia-launcher` binary to `/usr/bin/` and a static
  application-menu entry (`apps/xenia-launcher-linux/packaging/
  xenia-launcher.desktop`) to `/usr/share/applications/` -- distinct from
  the autostart `.desktop` file the app itself writes to `~/.config/
  autostart/` at runtime when the user enables "start at login" (see
  `startup.rs`); this one is static, ships with the package, and gives the
  app a normal entry in the system application menu.
- No custom icon: no icon asset exists for this project yet, so the
  `.desktop` entry has no `Icon=` key and desktop environments will show
  their generic fallback icon. Can be added later once real product art
  exists.
- `depends = "$auto"`: runtime library dependencies (GTK3,
  libappindicator or libayatana-appindicator depending on distro, libxdo)
  are auto-detected from the actual built binary via `dpkg-shlibdeps`,
  rather than hand-listed -- verified locally that this comes back empty
  on this NixOS dev machine (Nix store libraries aren't tracked in
  dpkg's shlibs database, a local-environment artifact, not a real bug),
  so the real ubuntu-latest CI job (which apt-installs the actual `-dev`
  packages first) is the authoritative check that auto-detection resolves
  real Debian package names.
- **Confirmed on real CI**: `Depends: libc6 (>= 2.39), libgdk-pixbuf-2.0-0
  (>= 2.22.0), libglib2.0-0t64 (>= 2.54.0), libgtk-3-0t64 (>= 3.21.5),
  libxdo3 (>= 1:3.20130104.1)`. Notably absent: `libappindicator3-1` /
  `libayatana-appindicator3-1`, even though `tray-icon`'s Linux backend
  depends on `libappindicator` at the Cargo level. `dpkg-shlibdeps` only
  sees libraries the binary is actually link-time-linked against, so the
  most likely explanation is `libappindicator` (or `tray-icon`'s use of
  it) loads it via `dlopen` at runtime rather than linking it directly --
  plausible but not independently confirmed by reading `tray-icon`'s
  source in this pass. Worth keeping in mind if a machine without
  libappindicator installed shows degraded (or missing) tray icon
  behavior: the `.deb`'s dependency list won't have pulled it in.

## macOS (`.app`, zipped)

- Config: `apps/xenia-launcher-macos/packaging/Info.plist`, assembled into
  a real bundle directory structure by a shell script inline in the
  `macos-launcher` CI job (no `cargo-bundle`/`cargo-packager` dependency
  -- a `.app` bundle is just `Contents/{MacOS/<binary>,Info.plist}`, no
  tool is strictly required to build one).
- `LSUIElement = true`: makes this a background/accessory app -- no Dock
  icon, no menu bar, no Cmd-Tab entry. This is the bundled-app version of
  the `NSApplicationActivationPolicy::Accessory` call `main.rs` already
  makes at runtime; keeping both is deliberate, not redundant cruft (see
  the comment in `Info.plist`).
- `CFBundleIdentifier = net.mycelix.xenia.launcher`, matching the
  `LABEL` constant `startup.rs` already uses for the LaunchAgent -- one
  consistent identity across the app's macOS integration points, not two
  independently-chosen strings.
- **Worth testing on a real Mac, not just asserted**: `UNUserNotificationCenter`
  (this app's notification backend, see `notify.rs`) is generally
  understood to require the calling process to be part of a real app
  bundle with a valid `CFBundleIdentifier` -- a bare, unbundled binary
  (which is all that existed before this packaging work) may not be able
  to request notification authorization or post notifications at all.
  If true, this `.app` bundle isn't just a distribution nicety for macOS
  -- it may be a functional prerequisite for the notification feature to
  work at all. Not independently verified in this session (no real Mac
  available); flagged here so whoever does real hands-on testing on
  macOS checks notifications specifically, both from the raw binary and
  from the bundle, to confirm or correct this.
- No custom icon (`CFBundleIconFile` omitted) -- same "no real product art
  yet" reasoning as the Linux `.desktop` entry.
