# Local Effect-Commit Gate for Revocation Linearization

**Status:** Additive reference primitive v0.1 — pure local synchronization model.  
**Tracking:** [Xenia #504](https://github.com/Luminous-Dynamics/xenia-peer/issues/504).  
**Related:** [#510 operation-stage evidence](https://github.com/Luminous-Dynamics/xenia-peer/issues/510), [#508 delegated M1 authority](https://github.com/Luminous-Dynamics/xenia-peer/issues/508), [#512 route mediation](https://github.com/Luminous-Dynamics/xenia-peer/issues/512), [#529 preemptible writes](https://github.com/Luminous-Dynamics/xenia-peer/issues/529).

## 1. Required local ordering

A permission preflight is not enough to prevent a queued operation from committing after the effect owner has observed revocation. Xenia needs a local linearization boundary at each protected effect owner.

The required ordering is:

- If revocation linearizes first, the protected effect closure must not be invoked.
- If the effect commit closure linearizes first, it completes before revocation can linearize.
- A stale permit from an earlier authority epoch cannot commit after an epoch advance, revoke or regrant.
- Revocation, authority-epoch advance and UNKNOWN invalidate all other permits already prepared but not yet committed.
- A permit can be explicitly abandoned before invocation; its pending slot is released, but its operation ID stays consumed.
- If dispatch occurs and the result is ambiguous, the operation is UNKNOWN; no new protected mutation is admitted until reconciliation.

The primitive in `crates/xenia-peer-core/src/effect_commit_gate.rs` implements a local version of this ordering using one mutex shared by commit and revoke.

## 2. How it works

### Permit creation

After the caller has independently checked recipient consent, exact M1 lane, resource/purpose scope, semantic delegation, authority freshness and expiry, it calls `prepare_after_admission`.

The gate verifies:
- session fingerprint;
- current local authority epoch;
- gate active state;
- that this operation ID has not already been used;
- bounded per-session permit count.

It returns an opaque, non-cloneable, one-shot permit bound to this gate instance, exact lane/direction, context digest and authority epoch.

The gate does **not** validate the signatures/truth of the authority inputs. It is a synchronization primitive, not an authorization engine.

### Effect commit

`commit(permit, closure)` acquires the same mutex used by `revoke`, rechecks current gate state and epoch, then invokes the synchronous effect-owner closure while holding the lock.

The closure must return one of:
- `Committed`: effect owner crossed its defined local commit point;
- `NotCommitted`: effect owner was invoked and can prove its local commit point was not crossed;
- `Unknown`: invocation happened, but the commit result is ambiguous.

The returned receipt binds operation ID, session fingerprint, M1 lane, direction, context digest and authority epoch. The caller can append the receipt to the stage-accurate operation evidence ledger under #510.

### Revocation

`revoke(new_epoch, evidence_digest)` uses the same mutex. It must advance the authority epoch strictly. When it returns, the gate is revoked and all outstanding permits from the previous epoch fail.

A repeated identical revocation receipt is idempotent; a different receipt cannot overwrite a prior revocation. Re-activation requires a separately verified grant at a strictly newer epoch.

### Unknown outcome

If the effect closure returns UNKNOWN:
- the operation ID is consumed;
- the gate records the unresolved operation;
- no new permit or commit in this gate/session is admitted;
- the caller must independently reconcile by operation ID and provide a verified receipt;
- only after that receipt is recorded does the gate reopen admission (subject to the gate still being active).

The gate never converts UNKNOWN to success/failure itself and never retries an operation.

## 3. Critical scope limitation: synchronous local commit only

The mutex protects only the closure that executes while the gate lock is held. Therefore:

**Valid uses:** short, synchronous effect-owner commit points whose return value genuinely establishes the local commit outcome—for example, a bounded local state mutation or a synchronous platform API whose documented success is the defined commit point.

**Invalid uses:** holding the mutex across an async network send, remote acknowledgement, whole file transfer, large encode, long-running filesystem scan or unbounded OS operation. Holding a blocking standard mutex across an async await is also invalid.

For asynchronous operations, use this gate only around the actual synchronous effect-owner commit transition and use separate stable operation receipts for dispatch, commit and remote observation. If the true commit point occurs in another process or after an unbounded asynchronous wait, a local mutex cannot prove the remote effect was ordered before revocation. That needs an owner-side transaction/receipt and reconciliation protocol.

The gate is intentionally not a solution to transport head-of-line blocking or whole-frame preemption; see #529.

## 4. Failure behavior

- A stale authority epoch is rejected.
- A revoked gate rejects permits and commits.
- An operation ID cannot be issued twice within a gate/session.
- A foreign-gate permit is rejected.
- Any unresolved UNKNOWN blocks subsequent mutations session-wide.
- A prepared permit may be explicitly abandoned before invocation; abandoning releases the pending slot but never permits operation-ID reuse.
- A panic while the effect closure holds the mutex poisons the gate. All future operations fail closed with `LockPoisoned`; recovery requires an explicit process/session recovery and reconciliation, not clearing the poison and continuing.
- If an UNKNOWN exists, even permits created before that UNKNOWN cannot commit after its receipt is reconciled; a fresh permit is required.

A product integration must persist or independently recover the revocation/authority frontier across daemon restart. A freshly constructed in-memory gate is not a substitute for revalidating authoritative state after restart.

## 5. Synthetic test coverage

[effect-commit-gate-v0.1.json](../../benchmarks/effect-commit-gate-v0.1.json) defines 12 synthetic race/failure scenarios.

The current unit tests cover:
1. Normal commit after admission.
2. Revocation before commit denies without invoking the effect closure.
3. Commit closure holds the lock until completion; a later revoke obtains the lock after it returns.
4. One operation ID cannot receive two permits.
5. Permit minted by another gate instance is rejected.
6. Authority-epoch advancement invalidates existing permits.
7. Regrant requires a strictly newer epoch.
8. UNKNOWN blocks new mutations until reconciliation.
9. Session fingerprint mismatch is rejected before permit creation.
10. Revocation receipt idempotency and conflict handling.
11. A panic inside the effect closure poisons the gate and future calls fail closed.

## 6. Integration order

Do not integrate by simply placing a mutex around the existing M1 permission preflight. The correct sequence is:

1. Use #512 to identify every protected effect owner and alternate path.
2. Use #508 to obtain current, typed, exact-lane authority/consent inputs.
3. At each owner, call the gate only after admission has been independently established.
4. Put only that owner's synchronous commit point inside the closure.
5. Append Attempted/Committed/Unknown evidence under #510 from the actual return/receipt.
6. Reconcile UNKNOWN before any subsequent mutation, reconnect replay or retry.
7. Run deterministic and concurrent effect-vs-revoke tests for every route.

No generic global policy engine or parallel Mycelix authorization logic is introduced.

## 7. Claim boundary

This primitive does not provide global/distributed instant revocation, does not authorize actions, does not prove the authenticity of supplied receipts, does not serialize remote async effects, does not prove complete route mediation, and is not integrated into the live daemon.

**Current evidence state:** implementation and deterministic/concurrent unit tests authored; Rust tests, Clippy, formatting, CI and platform effect-owner qualification remain unexecuted.
