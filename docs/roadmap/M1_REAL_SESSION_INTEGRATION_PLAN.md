# M1 Real-Session Integration Plan

**Status:** next implementation lane after M1 runtime smoke evidence.
**Scope:** wire the deterministic M1 consent/accountability runtime into real session paths without claiming production remote desktop readiness.

## Goal

M1 should prove one local Xenia session can only move privileged frame/input flow through an explicit consent runtime, and that consent-boundary decisions are persisted as a verifiable ledger transcript.

## Non-goals

- No production screen-sharing claim.
- No silent input injection backend enablement.
- No networked multi-party consent ceremony.
- No replacement of the existing RC1 historical evidence.

## Patch sequence

### 1. Runtime transcript persistence

Add app-layer helpers for persisting and reloading M1 ledger entries. The CLI smoke path should verify both the in-memory transcript and the persisted/reloaded transcript.

Acceptance:

```sh
cargo test -p xenia-peer m1_runtime
scripts/xenia-m1-runtime-smoke.sh .
```

### 2. Explicit runtime gate helpers

Expose named frame/input guard methods on the daemon-local runtime bridge. These should call the deterministic M1 state machine before lower-level frame or input plumbing runs.

Acceptance:

```sh
cargo test -p xenia-peer revoked_session_blocks_privileged_flow
cargo test -p xenia-peer denied_session_records_denial_and_blocks_privileged_flow
```

### 3. Frame path gating

Thread the runtime gate into the daemon frame send path. The first implementation may use a deterministic local approval source; it must still be explicit in code and tests.

Acceptance:

- Frame seal/send is impossible before runtime approval.
- Frame seal/send stops after revocation.
- Ledger transcript contains consent boundaries, not per-frame noise.

### 4. Input path gating

Thread the runtime gate into the host-side input open/inject path before any backend consumes input events.

Acceptance:

- Input injection is impossible before runtime approval.
- Input injection stops after revocation.
- Operation events are audit events but not misrepresented as consent ledger entries.

### 5. Evidence update

Add a fresh M1 evidence note only after executable checks exist. Do not rewrite RC1 evidence.

Acceptance:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
scripts/xenia-m1-runtime-smoke.sh .
gh pr checks <PR>
```

## Risks

| Risk | Mitigation |
| --- | --- |
| Auto-approving consent in demo code becomes confused with production consent. | Name it as deterministic local approval only; document non-goal. |
| Per-frame events pollute consent ledger. | Keep frame/input operation events out of `xenia-ledger` until an operation-audit schema exists. |
| Persistence format becomes prematurely normative. | Label bincode transcript as app-local M1 evidence, not stable public interchange. |
| Runtime gate duplicates wire consent state. | Keep M1 as app-layer authority and wire consent as protocol-layer guard; tests must verify fail-closed behavior. |

## Definition of done for this lane

- M1 runtime smoke still prints the same stable output.
- Smoke additionally persists, reloads, and verifies the transcript internally.
- Revoked and denied sessions block frame/input guard methods.
- Main branch receives a small evidence update only after CI is green.
