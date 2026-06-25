# First Real Xenia Branch Plan

The project now has enough guardrails. The next branch should be a concrete
normalization branch, not another planning branch.

## Branch name

```bash
git switch -c xenia/normalization-v0.2-execution
```

## Goal

Turn the current mixed migration workspace into the intended source layout while
preserving all historical material under `_archive/`.

## Required evidence

The branch should produce:

- `_archive/normalization-v0.2/snapshot-before.json`
- `_archive/normalization-v0.2/execution-plan.json`
- `_archive/normalization-v0.2/execution-ledger.json`
- `_archive/normalization-v0.2/rollback.sh`
- `_archive/normalization-v0.2/snapshot-after.json`
- `_archive/release-dashboard.md`
- `_archive/fix-tickets.md`

## Command sequence

```bash
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json
scripts/plan-normalization-execution.py . --output _archive/normalization-v0.2/execution-plan.json
scripts/apply-normalization-execution.py . \
  --apply \
  --plan _archive/normalization-v0.2/execution-plan.json \
  --ledger _archive/normalization-v0.2/execution-ledger.json \
  --rollback _archive/normalization-v0.2/rollback.sh
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-after.json
scripts/check-post-normalization.py .
scripts/ci-collect-artifacts.sh . _archive/ci-artifacts
scripts/generate-fix-tickets.py . --markdown _archive/fix-tickets.md --json _archive/fix-tickets.json
```

## Do not do in this branch

- Do not rewrite architecture for features.
- Do not delete historical material.
- Do not silently weaken consent/security defaults.
- Do not chase every code warning unless it blocks Cargo/Nix path repair.

## Merge condition

Merge only when the layout is normalized, Cargo/Nix path breakage is repaired or
explicitly ticketed, and the release dashboard clearly shows remaining blockers.
