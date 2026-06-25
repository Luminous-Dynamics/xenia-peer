# Xenia Workspace Normalization Plan

This plan turns the current transitional Xenia tree into a stable product
workspace without deleting historical material.

## Objective

Normalize Xenia into three clear layers:

1. `xenia-wire/` — protocol/spec/test-vector source of truth.
2. `xenia-peer/crates/` — reusable libraries.
3. `xenia-peer/apps/` — runnable products and UIs.

Historical bundles, build outputs, and agent scratch files must move under
`_archive/YYYY-MM-DD-*` and must not be imported by Cargo, Nix, CI, or release
scripts.

## Phase 0 — Freeze and snapshot

Before changing paths, capture the current state:

```bash
cd <xenia-root>
git status --short
mkdir -p _archive/$(date +%F)-pre-normalization
find . -maxdepth 3 -type f \( -name '*.tar.gz' -o -name '*.tgz' \) -print \
  > _archive/$(date +%F)-pre-normalization/archive-inventory.txt
```

Do not start feature work during this phase.

## Phase 1 — Move artifacts out of active paths

Run the artifact archiver in dry-run mode first:

```bash
scripts/archive-active-artifacts.sh .
```

Then apply only after reviewing the printed move list:

```bash
scripts/archive-active-artifacts.sh . --apply
```

Expected result: no active `*.tar.gz`, `*.tgz`, `target/`, `dist/`, nested
`.git`, or `fix_transport*.py` files outside `_archive/`.

## Phase 2 — Declare ownership before moving crates

Create or verify this mapping:

| Package | Target location | Reason |
|---|---|---|
| `xenia-peer-core` | `xenia-peer/crates/xenia-peer-core` | Shared runtime types/session logic. |
| `xenia-capture` | `xenia-peer/crates/xenia-capture` | Capture backend library. |
| `xenia-video` | `xenia-peer/crates/xenia-video` | Codec/frame pipeline library. |
| `xenia-handshake` | `xenia-peer/crates/xenia-handshake` | Session bootstrap/trust library. |
| `xenia-ledger` | `xenia-peer/crates/xenia-ledger` | Audit/provenance library. AGPL exception stays explicit. |
| `xenia-transport-ws` | `xenia-peer/crates/xenia-transport-ws` | WebSocket transport library. |
| `xenia-transport-quic` | `xenia-peer/crates/xenia-transport-quic` | QUIC/Iroh transport library. |
| `xenia-inject` | `xenia-peer/crates/xenia-inject` | Local input injection library. |
| `xenia-peer` | `xenia-peer/apps/xenia-peer` | Daemon/application. |
| `xenia-viewer` | `xenia-peer/apps/xenia-viewer` | Native viewer application. |
| `xenia-viewer-web` | `xenia-peer/apps/xenia-viewer-web` | Web viewer application/assets. |
| `sovereign-admin` | `xenia-peer/apps/sovereign-admin` | Governance/admin application. |

## Phase 3 — Move paths with Cargo updates

For each move, update all path dependencies in `Cargo.toml` files using relative
paths only. Never reintroduce `<workspace-root>/...` paths.

After each small batch:

```bash
cargo metadata --format-version 1 --no-deps
scripts/xenia-validate.sh .
```

## Phase 4 — Enforce boundaries

Once layout is normalized, turn these from advisory to required in CI:

```bash
scripts/check-cargo-boundaries.py .
scripts/xenia-hygiene-audit.sh .
scripts/check-source-archive.sh /tmp/xenia-source.tar.gz
cargo deny check advisories bans licenses sources
```

## Phase 5 — Source-only export

Export source archives only through the guarded script:

```bash
scripts/export-source-archive.sh . /tmp/xenia-source-$(date +%F).tar.gz
scripts/check-source-archive.sh /tmp/xenia-source-$(date +%F).tar.gz
```

A valid source archive must not contain build output, nested `.git`, previous
archives, local runtime state, or absolute local paths in source/config.

## Stop conditions

Pause and investigate if any of these occur:

- `cargo metadata` fails after a move.
- A moved app crate is imported by a library crate.
- `xenia-wire` gains dependencies on peer/product crates.
- Any active source/config file contains `<workspace-root>`.
- A generated archive exceeds expected source-only size by a large margin.
