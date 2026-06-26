# Post-Normalization Acceptance Gate

The normalization pass is done only when the tree is easier to validate than it
was before. Moving files is not enough.

## Required evidence

| Evidence | Command | Required for |
| --- | --- | --- |
| Normalization manifest check | `scripts/check-normalization-plan.py .` | merge |
| Before snapshot | `scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json` | merge |
| After snapshot | `scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-after.json` | merge |
| Preflight report | `scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-after-normalization.md` | merge |
| Full validation | `scripts/xenia-validate.sh .` | merge |
| Source archive check | `scripts/check-source-archive.sh <archive>` | release |

## Layout acceptance

- `xenia-peer/apps/` exists.
- Runnable products live under `xenia-peer/apps/`.
- Reusable libraries live under `xenia-peer/crates/`.
- `xenia-wire/` is protocol-only and independently checkable.
- No active `target/`, `dist/`, nested `.git`, tarballs, or scratch scripts remain
  outside `_archive/`.

## Security acceptance

- Consent and revocation behavior remains fail-closed.
- Ledger/audit behavior is not weakened by path moves.
- Admin/control-plane surfaces remain visibly app-scoped.
- Runtime risk and unsafe-surface reports are regenerated after the move.

## Release note requirement

The merge commit or PR description should include:

```text
Normalization evidence:
- preflight report: <path or artifact>
- before snapshot: <path>
- after snapshot: <path>
- source archive check: pass/fail + notes
```
