# Normalization Agent Rules

Agents working on Xenia normalization must treat the repository as evidence.

## Required behavior

- Prefer `git mv` semantics when moving source directories.
- Never delete migration debris; move it under `_archive/`.
- Never overwrite a target path during normalization.
- Generate a plan before applying moves.
- Generate a ledger and rollback script when applying moves.
- Run post-normalization checks before reporting success.

## Forbidden behavior

- Do not silently rewrite unrelated manifests.
- Do not mix dependency upgrades with layout moves.
- Do not move `xenia-wire` into the product workspace.
- Do not move reusable libraries into `apps/`.
- Do not claim RC readiness while release hard blockers remain.

## Minimal handoff after work

```bash
scripts/xenia-agent-handoff-report.sh . _archive/normalization-v0.2/agent-handoff-after.md
```

The handoff should state what was planned, what was applied, what failed, and
which evidence files were produced.
