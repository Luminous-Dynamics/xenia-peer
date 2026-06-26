# Xenia Workspace Normalization Runbook

This runbook turns the transitional Xenia layout into the canonical apps/crates
layout without deleting history.

## 0. Work on a branch

```bash
git switch -c normalize/xenia-workspace-v0.2
```

## 1. Generate evidence before moving anything

```bash
scripts/check-normalization-plan.py .
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json
scripts/emit-normalization-plan.py . > /tmp/xenia-normalization-plan.md
scripts/emit-normalization-plan.py . --format shell > /tmp/xenia-normalization-commands.sh
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-before-normalization.md
```

Review both generated files before executing commands.

## 2. Archive active artifacts

Dry run first:

```bash
scripts/archive-active-artifacts.sh .
```

Apply only after reviewing output:

```bash
scripts/archive-active-artifacts.sh . --apply
```

Expected archived classes:

- `*.tar.gz`
- `*.tgz`
- `target/`
- `dist/`
- nested `.git/`
- one-off migration scratch scripts

## 3. Move app surfaces

Prefer `git mv` so history remains readable. The manifest source of truth is
`xenia.normalization.toml`.

Current expected moves:

```text
xenia-peer/crates/xenia-peer          -> xenia-peer/apps/xenia-peer
xenia-peer/crates/xenia-viewer        -> xenia-peer/apps/xenia-viewer
xenia-peer/crates/xenia-viewer-web    -> xenia-peer/apps/xenia-viewer-web
xenia-peer/crates/sovereign-admin     -> xenia-peer/apps/sovereign-admin
```

Do not move `xenia-peer-core`, capture, video, handshake, ledger, transports, or
inject out of `crates/`; those are reusable library surfaces.

## 4. Update workspace paths

After moving apps, update `xenia-peer/Cargo.toml` workspace members and any local
path dependencies that referenced the old app paths.

Use ripgrep first:

```bash
rg 'crates/(xenia-peer|xenia-viewer|xenia-viewer-web|sovereign-admin)' .
```

## 5. Generate post-move evidence

```bash
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-after.json
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-after-normalization.md
scripts/xenia-validate.sh .
```

## 6. Validate a clean source archive

```bash
scripts/export-source-archive.sh . /tmp/xenia-source-normalized.tar.gz
scripts/check-source-archive.sh /tmp/xenia-source-normalized.tar.gz
```

## 7. Update manifests only after evidence exists

After validation, update:

- `xenia.normalization.toml`: `status = "applied"`
- `xenia.policy.toml`: layout mode to normalized, if present
- `xenia.release.toml`: remove the transitional-layout hard blocker only if the
  evidence above exists

## Rollback posture

Rollback means reverting the branch or using the before/after snapshots and Git
history to move paths back. It does not mean deleting archived evidence.
