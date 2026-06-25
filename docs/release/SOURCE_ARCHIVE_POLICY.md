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
- Nested `.git/` directories.
- Prior `*.tar.gz`, `*.tgz`, or `*.zip` bundles.
- Runtime state such as `.env`, `.env.*`, `operator.key`, `*.ledger`.
- Agent scratch files such as `fix_transport_final_v*.py`.
- Absolute local workspace paths in source/config.

## Required commands

```bash
scripts/export-source-archive.sh . /tmp/xenia-source.tar.gz
scripts/check-source-archive.sh /tmp/xenia-source.tar.gz
```

If `check-source-archive.sh` fails, do not publish the archive.
