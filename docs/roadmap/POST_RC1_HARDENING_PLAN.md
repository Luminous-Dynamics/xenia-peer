# Post-RC1 Hardening Plan

Status: planning.

Xenia Peer has reached RC1 as a GitHub/source release candidate. The next phase should preserve the RC1 baseline while improving repeatability, packaging posture, CI resilience, and public API clarity.

## Current baseline

- Release status: `rc`
- Current milestone: `normalization-v0.2`
- Next candidate: `rc1`
- Hard blockers: `0`
- Soft blockers: `0`
- RC1 candidate review: passing
- Source archive validation: passing
- GitHub prerelease tag: `xenia-peer-v0.0.0-rc1`
- Crates.io publication: deferred

## Hardening principles

Post-RC1 work should follow these constraints:

- Do not weaken existing validation gates.
- Do not change RC1 evidence retroactively unless correcting deterministic/reproducibility issues.
- Do not publish crates.io packages until an explicit public API packaging milestone is complete.
- Prefer additive checks, evidence, and documentation.
- Keep release-train status changes in explicit promotion/release PRs.
- Archive or deprecate historical material rather than deleting it.

## Track 1: Evidence reproducibility

Goal: make release evidence easier to verify and harder to accidentally stale.

Candidate tasks:

- Add `--check` mode to all release evidence generators.
- Add a single evidence freshness checker.
- Ensure committed evidence avoids branch-specific or squash-merge-specific fields.
- Add golden-file or schema checks for release evidence JSON.
- Document which evidence is structural versus environment-derived.

Acceptance criteria:

- One command can verify all committed release evidence is current.
- Evidence freshness checks pass on clean `main`.
- Evidence does not include local paths, usernames, secrets, or transient workspace paths.

## Track 2: CI resilience

Goal: reduce runner/network flake without hiding real failures.

Candidate tasks:

- Document known transient dependency-fetch failure modes.
- Add retry wrappers only around network-dependent Cargo fetch/package steps.
- Consider setting `CARGO_HTTP_MULTIPLEXING=false` only if HTTP2 failures recur.
- Add a CI troubleshooting note for macOS/Linux/Windows runner-specific failures.
- Keep test failures distinct from infrastructure failures.

Acceptance criteria:

- CI logs clearly distinguish code failures from transient infrastructure failures.
- No retry logic masks test assertions, clippy failures, format failures, or validation failures.

## Track 3: Crates.io/public API readiness

Goal: prepare for future crates.io publication without prematurely publishing.

Candidate tasks:

- Decide which crates are public API versus internal implementation crates.
- Replace path-only inter-crate dependencies with versioned path dependencies for future publication candidates.
- Define first public version policy, likely not `0.0.0-m0`.
- Resolve or document git dependency strategy for `scap`.
- Add package archive hygiene checks for selected crates.
- Add `cargo publish --dry-run` evidence only after `publish = false` is intentionally lifted for selected crates.

Acceptance criteria:

- A publication matrix identifies each crate as `public`, `internal`, or `deferred`.
- Public crates have complete package metadata.
- Public crates pass `cargo package` and `cargo publish --dry-run`.
- Private crates remain protected with `publish = false`.

## Track 4: Security and protocol hardening

Goal: improve the security posture beyond RC1 minimum readiness.

Candidate tasks:

- Expand transport fault-injection coverage.
- Add malformed envelope fuzz or property tests where practical.
- Add compatibility tests for stable admin/operator audit event names.
- Document audit event naming compatibility policy.
- Review consent ledger verification surfaces.
- Add negative tests for tampered or reordered ledger events.

Acceptance criteria:

- Protocol fault tests cover malformed, truncated, oversized, and invalid-state inputs.
- Audit event names remain stable under tests.
- Ledger integrity failures are explicit and test-covered.

## Track 5: Release operations

Goal: make future release candidates boring and repeatable.

Candidate tasks:

- Add a release checklist for RC2/final release.
- Document tag naming policy.
- Document GitHub release creation steps.
- Document crates.io deferral/publication decision process.
- Add rollback/archive instructions for release evidence mistakes.

Acceptance criteria:

- Future release candidates can be cut using a documented checklist.
- Release tags, notes, evidence, and validation commands are all traceable.

## Recommended next milestone

Suggested milestone name:

`post-rc1-hardening-v0.1`

Suggested first implementation PRs:

1. Evidence generator `--check` modes
2. Unified evidence freshness checker
3. Crates/public API publication matrix
4. CI resilience notes
5. Audit event compatibility policy

## Non-goals

This plan does not:

- Publish crates to crates.io
- Promote RC1 to a final release
- Change the RC1 tag
- Change release status
- Add new product features
- Refactor core protocol code

## Decision

Post-RC1 work should begin with reproducibility and packaging discipline, not feature expansion. RC1 is valid as a source/GitHub release candidate; the next milestone should make future releases easier to verify, package, and explain.
