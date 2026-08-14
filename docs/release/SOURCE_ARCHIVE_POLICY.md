# Xenia Source Archive Policy

The previous migration archives included build output and nested repository
state. Future public or review bundles must be source-only.

## Allowed in source archives

- Source code.
- Tests, examples, benches, fuzz targets, and small fixtures.
- Specs, docs, changelogs, plans, licenses, and policy files.
- Lockfiles when intentionally part of the workspace.

## Disallowed in source archives

- `target/`, `dist/`, `pkg/`, `node_modules/`.
- VCS/agent workspace state such as `.git/`, `.claude/`, and `.direnv/`.
- Prior `*.tar.gz`, `*.tgz`, or `*.zip` bundles.
- Runtime state directories such as `xenia-peer-state/` and `xenia-operator-agent-state/`.
- Secret-bearing files such as `.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.sqlite`, `*.db`, and `*.ledger`.
- Agent scratch files such as `fix_transport_final_v*.py`.
- Absolute local workspace paths in source/config.

## Required commands

```bash
scripts/export-source-archive.sh . /tmp/xenia-source.tar.gz
scripts/check-source-archive.sh /tmp/xenia-source.tar.gz
```

`export-source-archive.sh` also refuses to run when live runtime secret/state files are present in the active source tree (outside excluded agent/archive/build directories). This is intentional: a release export must not silently hide a contaminated working tree.

`check-source-archive.sh` rejects unsafe archive member names and link/device entries before extracting the archive for content checks.

If `check-source-archive.sh` fails, do not publish the archive.
