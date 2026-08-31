# ADR-020: SQLite V2 crash qualification boundaries

Status: draft candidate

## Context

ADR-007 requires crash injection at the privileged-operation persistence/effect boundaries. ADR-019 requires a C0-C10 crash qualification for the SQLite V2 backend, but the earlier ADRs did not freeze what those labels mean.

An undefined crash label is not reproducible evidence. Different implementations could call different moments "C5" and still claim the same gate.

The V2 store also has two different security-bearing transactions:

1. durable admission / finite-use reservation; and
2. write-ahead `EffectArmed` receipt persistence.

Both transactions must prove that a process death cannot produce a partially authoritative state or turn an unknown commit outcome into permission for blind retry.

## Decision

Freeze the following C0-C10 boundary map for `xenia-operation-store-sqlite-v2`.

The same labels apply independently to the **admission** and **EffectArmed** transactions. Where an operation has transaction-specific metadata, the definition below states the corresponding step.

### C0 - before mutable transaction begin

The store is open and its unclean-writer marker is durable, but the operation transaction has not begun.

Expected post-crash state:

- store reopens `RecoveryRequired`;
- target admission / `EffectArmed` event is absent;
- local integrity remains valid;
- no retry is authorized merely by the crash.

### C1 - after `BEGIN IMMEDIATE`

The transaction exists but no operation-specific mutation has occurred.

Expected post-crash state: same durable semantic state as C0.

### C2 - after uniqueness/CAS reads, before primary mutation

For admission this means operation-id and finite-use-slot conflict checks completed.

For `EffectArmed` this means existing-event / receipt-head compare-and-append checks completed.

Expected post-crash state: target mutation absent.

### C3 - after primary mutation row write

For admission, the immutable admission authority row has been inserted inside the uncommitted transaction.

For `EffectArmed`, the first receipt event has been inserted inside the uncommitted transaction.

Expected post-crash state: the primary row does not survive as authoritative state unless the complete transaction commits.

### C4 - after operation-local pre-frontier mutation, before frontier append

For admission, `next_admission_sequence` has been advanced inside the transaction.

For `EffectArmed`, the receipt row is present and the transaction is ready to advance the frontier; there is no independent admission-sequence update.

Expected post-crash state: no sequence-only / event-only partial authority survives.

### C5 - after frontier row insertion

The new frontier row exists inside the uncommitted transaction, but the store singleton has not yet been advanced to that frontier.

Expected post-crash state: no orphan authoritative frontier survives.

### C6 - after store frontier pointer advancement

`store_meta.current_frontier_digest` and `next_frontier_sequence` point at the new frontier inside the uncommitted transaction.

Expected post-crash state: the previous committed frontier remains authoritative after recovery unless the complete transaction committed.

### C7 - after mutation-to-frontier link write

The admission / receipt row now names its committing frontier inside the transaction.

Expected post-crash state: either the complete transaction is absent or, if SQLite completed commit despite an externally ambiguous failure, reread must recover the exact complete transaction. A partial row/frontier/link combination is forbidden.

### C8 - immediately before `COMMIT`

All intended transaction writes have been issued; SQLite commit has not been invoked.

Expected post-crash state: target mutation absent and previous committed frontier retained.

### C9 - immediately after `COMMIT` returns success, before store result return

SQLite reported commit success but the caller has not received the `AdmissionCommitV2` / `EffectArmedCommitV2` result.

Expected post-crash state:

- target mutation exists exactly;
- its committing frontier exists exactly;
- local integrity succeeds;
- store reopens `RecoveryRequired` because clean close did not occur;
- recovery reconstructs the exact persistence proof from durable facts;
- the lost acknowledgement does not authorize a second logical operation.

### C10 - immediately after the store result reaches the worker, before any subsequent security-bearing step

This is a caller-level crash boundary rather than an internal SQLite statement boundary.

For admission, the durable admission exists but no fresh `EffectArmAuthorityV2` should be assumed to exist merely because admission returned.

For `EffectArmed`, the durable write-ahead event exists but no external effect has started in this store tranche.

Expected post-crash state is the same durable transaction as C9. Recovery uses durable evidence and never assumes that the caller's next intended action occurred.

## Commit-in-flight kill race

C8 and C9 bracket SQLite `COMMIT`, but neither alone proves behavior when the process dies **while commit is in flight**.

Qualification therefore includes a separate commit-race probe for admission and `EffectArmed`:

1. create a clean baseline store;
2. child process executes one target transaction;
3. child signals immediately before invoking `COMMIT` and then proceeds without waiting for acknowledgement;
4. parent sends `SIGKILL` with varied scheduling/delay around that signal;
5. reopen the store as `RecoveryRequired`;
6. classify by durable reread.

Only two semantic outcomes are acceptable:

### Fully absent

- target mutation absent;
- previous frontier remains current;
- no finite-use slot is consumed by a partial row;
- local integrity succeeds.

### Fully committed

- exact target mutation present;
- exact use-slot / receipt CAS state present;
- exact committing frontier present and linked;
- store frontier pointer agrees;
- deterministic persistence proof reconstructs;
- local integrity succeeds.

The following are qualification failures:

- admission row without its frontier;
- frontier without exactly one corresponding mutation;
- use-slot reservation without the admission;
- receipt event without the matching frontier;
- advanced `store_meta` frontier pointer without the transaction state it commits;
- broken frontier replay;
- failure to resolve the durable state by reread;
- automatic retry because the original commit outcome was unknown.

The commit-race probe SHOULD run multiple iterations because scheduler timing is nondeterministic. It is evidence for atomic crash behavior, not a proof that every hardware/storage stack honors fsync correctly.

## Injection mechanism

Crash instrumentation is a **qualification-only build feature**.

The reference crate may provide a feature such as:

```text
crash-injection
```

that enables named abort/pause hooks. Normal builds must not consult an environment variable or expose a remote crash primitive.

The deterministic hook namespace is:

```text
admission:C0 ... admission:C9
effect-armed:C0 ... effect-armed:C9
```

C10 is injected by the probe process after the store method returns.

A crash hook must terminate the process abruptly enough that ordinary `Drop` and `close_clean()` do not run. `SIGKILL` remains the preferred cross-process qualification mechanism. A feature-gated `std::process::abort()` hook is acceptable for deterministic internal points, with the real SIGKILL lifecycle probe retained separately.

## Recovery assertions

Every crash case must assert all applicable invariants after reopening:

- unclean marker survives;
- store health is `RecoveryRequired`;
- recovery open is non-mutating;
- `PRAGMA integrity_check` succeeds when the crash produced a SQLite-valid state;
- authority-row integrity succeeds;
- receipt-chain integrity succeeds;
- complete frontier hash verification succeeds;
- semantic frontier replay succeeds;
- mutation-to-frontier cardinality is exact;
- no new privileged mutation is permitted while recovery is unresolved.

For C9/C10 and a commit-race that resolves as committed, the probe must additionally show that the exact durable proof can be reconstructed from the store facts. Serialized proof bytes are not treated as self-authenticating state.

## `EffectArmed` consequence

A recovered durable `EffectArmed` event does **not** prove that the external effect started.

The SQLite store in ADR-019 performs no external effect. A crash after durable `EffectArmed` therefore enters the governed recovery path from ADR-014/ADR-018. Future adapters may have a later invocation-start classification, but this store must never infer it.

## Anti-rollback boundary

Passing C0-C10 proves local transaction/crash semantics for the tested SQLite/VFS/filesystem profile. It does not prove resistance to restoring an older but internally valid database image.

External frontier anchoring remains a separate promotion gate.

## Promotion gate

SQLite V2 crash qualification is complete only when:

1. admission C0-C10 pass;
2. `EffectArmed` C0-C10 pass;
3. admission commit-in-flight race produces only fully-absent or fully-committed states;
4. `EffectArmed` commit-in-flight race produces only fully-absent or fully-committed states;
5. every surviving state passes local semantic integrity;
6. committed lost-ack cases reconstruct the exact persistence proof;
7. no crash case permits mutation while `RecoveryRequired`;
8. the results are captured as reproducible CI evidence.

## Non-goals

This ADR does not:

- create an external effect;
- implement automatic governed recovery;
- clear `RecoveryRequired`;
- prove hardware power-loss behavior beyond the qualified environment;
- provide external anti-rollback anchoring;
- claim generic exactly-once execution.
