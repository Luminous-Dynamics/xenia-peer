# Normalization Execution Acceptance

This checklist gates the merge of the `normalization-v0.2` branch.

## Required evidence

- [ ] `_archive/normalization-v0.2/preflight-before.md`
- [ ] `_archive/normalization-v0.2/snapshot-before.json`
- [ ] `_archive/normalization-v0.2/execution-plan.json`
- [ ] `_archive/normalization-v0.2/execution-ledger.json`
- [ ] `_archive/normalization-v0.2/rollback.sh`
- [ ] `_archive/normalization-v0.2/snapshot-after.json`
- [ ] `_archive/normalization-v0.2/preflight-after.md`

## Hard gates

- [ ] No active `target/`, `dist/`, `.tar.gz`, `.tgz`, or nested `.git` outside `_archive/`.
- [ ] App directories exist under `xenia-peer/apps/`.
- [ ] Reusable libraries remain under `xenia-peer/crates/`.
- [ ] `xenia-peer/Cargo.toml` no longer references moved app paths under `crates/`.
- [ ] `cargo metadata --format-version 1 --no-deps` passes in `xenia-peer/`.
- [ ] `scripts/check-post-normalization.py .` passes.
- [ ] `scripts/xenia-validate.sh .` passes, or missing host tools are explicitly noted.

## Review cautions

Normalization is not a feature branch. Reject any normalization PR that also:

- changes protocol semantics;
- changes consent defaults;
- enables remote control by default;
- upgrades dependencies without a separate review;
- removes historical files instead of archiving them.
