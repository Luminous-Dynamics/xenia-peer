# Xenia Normalization Execution Protocol

Xenia normalization is a reversible repository operation. It should be performed
on a dedicated branch and should leave an evidence trail under
`_archive/normalization-v0.2/`.

## Goals

- Move runnable products from `xenia-peer/crates/` to `xenia-peer/apps/`.
- Archive generated/build/migration artifacts out of active source paths.
- Rewrite Cargo workspace members only for the known app moves in
  `xenia.normalization.toml`.
- Produce a ledger and rollback script for every applied run.

## Non-goals

- Do not delete historical files.
- Do not rename crates or package names during the layout move.
- Do not upgrade dependencies during normalization.
- Do not productize remote-control behavior during normalization.

## Recommended flow

```bash
# 1. Start clean.
git status --short

# 2. Create a dedicated branch.
git switch -c xenia-normalization-v0.2

# 3. Generate evidence before moving anything.
scripts/xenia-preflight-report.sh . _archive/normalization-v0.2/preflight-before.md
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json
scripts/plan-normalization-execution.py . --output _archive/normalization-v0.2/execution-plan.json

# 4. Review the plan.
cat _archive/normalization-v0.2/execution-plan.json

# 5. Dry-run the executor.
scripts/apply-normalization-execution.py . --plan _archive/normalization-v0.2/execution-plan.json

# 6. Apply only after review.
scripts/apply-normalization-execution.py . \
  --apply \
  --plan _archive/normalization-v0.2/execution-plan.json \
  --ledger _archive/normalization-v0.2/execution-ledger.json \
  --rollback _archive/normalization-v0.2/rollback.sh

# 7. Capture after-state evidence.
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-after.json
scripts/check-post-normalization.py .
scripts/xenia-validate.sh .
```

## Rollback

The executor writes a rollback script for filesystem moves. Review it before
running it:

```bash
cat _archive/normalization-v0.2/rollback.sh
bash _archive/normalization-v0.2/rollback.sh
```

Cargo workspace-member rewrites are text changes. Roll them back with Git unless
you explicitly want to preserve the normalized paths.

## Acceptance rule

A normalization branch is not ready to merge until:

- `scripts/check-post-normalization.py .` passes;
- `scripts/xenia-validate.sh .` passes, except for documented toolchain absence;
- `cargo metadata --format-version 1 --no-deps` passes in `xenia-peer/`;
- source archives pass `scripts/check-source-archive.sh`;
- the before/after snapshots and execution ledger are committed or archived as
  release evidence.
