# Consent maintenance architecture

Status: implemented orchestration boundary; not a substitute for cryptographic or integration tests.

`xenia-peer` exposes normal daemon service and a large set of explicit one-shot
maintenance operations. Those operations verify, sign, advance, quarantine, or
otherwise transform security evidence. They deliberately remain available from
the daemon binary so deployments use the same schemas and trust policy as the
runtime, but they must not behave like loosely ordered boolean flags.

## Dispatch invariant

`consent_maintenance::OneShotOperation` is the canonical inventory of one-shot
commands. Each variant has exactly one public flag and one operation family.
`validate_one_shot_selection` runs immediately after argument parsing and before
any signing key is loaded.

An invocation may select:

- no one-shot operation, in which case normal daemon startup continues; or
- exactly one one-shot operation.

Selecting two operations is an error even when the operations belong to
different historical families. This prevents the source-order of early-return
branches in `main.rs` from silently deciding which requested command runs.

Adding a new one-shot flag therefore requires all of the following in the same
change:

1. Add a `OneShotOperation` variant.
2. Map it to one `OperationFamily`.
3. Map it to one CLI flag.
4. Add it once to `selected_one_shot_operations`.
5. Add positive and ambiguity tests when it introduces a new family or dispatch shape.

## Canonical path invariant

Every maintenance output is checked against canonicalized inputs, key files,
and protected evidence trees through `consent_artifact_paths` before an atomic
writer runs.

`ProtectedPathSet` rejects:

- an output that aliases an input;
- a symlink resolving to an input;
- an output equal to a protected evidence root; and
- an output below a protected evidence root.

Individual operations may impose stricter rules, but they must not reimplement
path normalization locally in `main.rs`.

## Verified retention context

Custody and final-destruction-readiness operations share
`VerifiedRetentionContext`. Construction performs the complete common
verification sequence once:

1. Read the retention certificate, retained anchor, witness bundle, purge
   approval bundle, and optional renewal chain.
2. Enforce witness-key separation.
3. Verify the anchor and configured witness quorum.
4. Verify the renewal chain and derive the current retention subject.
5. Retain the exact source paths as output-protection provenance.

Callers receive one validated value rather than a tuple plus repeated reads from
raw CLI arguments. The context also owns `protect_output`, so a later branch
cannot accidentally omit one of the prerequisite evidence files from its
alias checks.

This is a local typestate boundary, not proof that all evidence remains fresh
forever. Commands still verify time-sensitive evidence at execution time, and
normal cryptographic tests remain authoritative.

## CI regression guard

`scripts/check-consent-maintenance-boundary.py` enforces the source-level
architecture:

- every `OneShotOperation` has one selector entry, family, and flag;
- ambiguous selection is rejected before signing-key loading;
- ad hoc operation counters do not return to `main.rs`;
- canonical path helpers remain centralized;
- unchecked retention-context `.expect` lookups do not return; and
- the path guard retains canonicalization and symlink-alias coverage.

The guard is intentionally narrow. It does not parse Rust types, compile the
workspace, validate cryptographic behavior, or replace the repository's Cargo,
clippy, fuzzing, browser, mobile, and reproducibility lanes.

## Remaining decomposition work

`main.rs` still contains the concrete command handlers. The next safe reduction
is to move related handlers behind small command modules that accept verified
inputs and return typed outcomes, without changing schemas or adding another
evidence artifact. That extraction should happen incrementally and retain the
single typed selector described above.
