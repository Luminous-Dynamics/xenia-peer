# Xenia Workspace Boundaries

Xenia is split into protocol, reusable runtime crates, runnable apps, and
migration archives. Keeping those boundaries explicit prevents future agents,
release scripts, and CI jobs from treating build output or historical bundles as
active source.

## Canonical ownership

| Area | Owns | Should not own |
|---|---|---|
| `xenia-wire/` | Byte-level sealed-envelope protocol, normative spec, test vectors, fuzz targets, cross-language validation material. | Product UIs, daemon state, build output, app-specific transport policy. |
| `xenia-peer/crates/*` or extracted crate dirs | Reusable libraries: peer core, capture, video, handshake, ledger, transports, injection. | Runnable UI apps, tarballs, migration scratch scripts, `target/`. |
| `xenia-peer/apps/*` or app crate dirs | Runnable binaries/UIs: daemon, native viewer, web viewer, sovereign admin. | Protocol test vectors, reusable core logic that belongs in crates. |
| `_archive/YYYY-MM-DD-*` | Historical tarballs, migration artifacts, superseded scripts, frozen audit snapshots. | Anything imported by the active Cargo workspace. |

## Source-of-truth rules

1. Active source directories must contain source, tests, docs, examples, and small fixtures only.
2. Never keep `*.tar.gz`, `*.tgz`, `target/`, `dist/`, or agent scratch scripts inside active crate/app paths.
3. Do not delete historical material during cleanup. Move it under `_archive/YYYY-MM-DD-*` with a short README.
4. `xenia-wire` should stay independently publishable and reviewable.
5. Product crates may depend on `xenia-wire`; `xenia-wire` should not depend on product crates.
6. Apps should depend on crates; crates should not depend on apps.

## Recommended normalized layout

```text
xenia/
  xenia-wire/                  # protocol crate/repo
  xenia-peer/                  # product workspace
    Cargo.toml
    crates/
      xenia-peer-core/
      xenia-capture/
      xenia-video/
      xenia-handshake/
      xenia-ledger/
      xenia-transport-ws/
      xenia-transport-quic/
      xenia-inject/
    apps/
      xenia-peer/
      xenia-viewer/
      xenia-viewer-web/
      sovereign-admin/
    docs/
    scripts/
    _archive/
```

The current tree may be in a transitional state. Normalize by moving files, not
by deleting them.
