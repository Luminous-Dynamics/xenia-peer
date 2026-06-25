# Xenia Agent File-Touch Policy

This policy exists because Xenia is a multi-surface project where broad agent
edits can accidentally blur security, release, and workspace boundaries.

## Default rule

Make the smallest coherent change that advances the current milestone.

## Before editing

1. Read `WORKSPACE_BOUNDARIES.md`.
2. Run or inspect `scripts/xenia-agent-handoff-report.sh` output when available.
3. Check `xenia.policy.toml`, `xenia.release.toml`, and `xenia.normalization.toml`.
4. Use `rg` before changing paths, dependency names, or crate members.

## Do not casually touch

- `xenia-wire` protocol semantics
- consent, revocation, and input authority code
- ledger/audit behavior
- transport authentication/replay handling
- Cargo workspace membership
- Nix/CI gates

Touch these only with a clear validation plan and a note in the handoff report.

## Forbidden without explicit review

- Deleting source or historical material instead of archiving it.
- Introducing absolute `<workspace-root>` paths.
- Moving apps/crates without updating the normalization manifest or snapshots.
- Converting advisory security checks into ignored failures without documenting
  why.
- Treating RC1 as a production-security claim.

## Handoff requirement

Every substantial agent pass should end with:

```bash
scripts/xenia-agent-handoff-report.sh . /tmp/xenia-agent-handoff.md
```

Include what changed, what failed, and what should happen next.
