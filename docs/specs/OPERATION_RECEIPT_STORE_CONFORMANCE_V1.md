# Operation Receipt Store Conformance V1

This document is the executable-test plan for an eventual durable implementation of ADR-007. It does not bless a particular database or filesystem.

## Required observable operations

A conforming store must expose behavior equivalent to:

- `open_and_verify()`
- `admit(OperationAdmissionV1)`
- `get_admission(operation_id)`
- `get_by_grant_use(grant_digest, use_index)`
- `append_receipt_event(operation_id, expected_head, event)`
- `get_receipt_chain(operation_id)`
- `scan_non_terminal()`
- `calculate_frontier()`
- `verify_against_anchor(frontier_anchor)`
- `health()`

The concrete Rust trait and error types may differ, but they must preserve the semantics below.

## Admission concurrency tests

### A1 — duplicate identical operation

Two concurrent callers submit byte-identical immutable admission records with the same `operation_id`.

Expected:

- exactly one physical admission row/record exists;
- both callers may resolve successfully, but at most one reports `AdmittedNew`;
- the other resolves as `AdmittedExisting` after comparing the complete admission commitment;
- one grant-use reservation exists;
- one admission sequence is consumed.

### A2 — operation-id collision

Two callers submit the same `operation_id` with any different immutable committed field.

Expected:

- at most one commits;
- the loser receives `OperationIdConflict`;
- the loser cannot arm an effect;
- the store remains `Healthy` if the collision was an ordinary rejected request.

### A3 — grant-use double spend

Two different operation ids attempt the same `(grant_digest, use_index)`.

Expected:

- exactly one can commit;
- the other receives `GrantUseAlreadyReserved`;
- no application-level timing or lock order can allow both.

### A4 — adjacent use slots

Concurrent operations reserve `(G, 7)` and `(G, 8)`.

Expected:

- both may commit if valid;
- each has a distinct admission sequence;
- sequence allocation remains gap-tolerant only if the backend contract explicitly allows rolled-back sequence reservations; a committed sequence must never be reused.

## Receipt compare-and-append tests

### R1 — first event race

Two workers race different first events for the same admission, for example `EffectArmed` and `CancelledBeforeEffect`.

Expected:

- at most one event index `0` commits;
- the loser receives `ReceiptHeadConflict` or the exact persisted event if byte-identical;
- the receipt chain never forks.

### R2 — duplicate exact event

The same event is submitted twice because acknowledgement was lost.

Expected:

- one event exists physically;
- replay resolves as `AppendedExisting` after exact digest comparison;
- no second event index is allocated.

### R3 — stale terminal writer

Worker A commits terminal `Completed`. Worker B, holding the old `EffectArmed` head, attempts `OutcomeUnknown`.

Expected:

- worker B fails with head conflict/terminal state;
- terminal state is never extended or replaced.

### R4 — previous digest mismatch

A syntactically valid event carries a previous-event digest other than the actual current head.

Expected:

- reject before commit;
- no mutation.

## Crash-point matrix

Every implementation must support deterministic fault injection at or immediately around the following points.

| ID | Crash point | Required restart interpretation |
|---|---|---|
| C0 | before admission transaction begins | no admission exists; no use slot consumed |
| C1 | after uniqueness checks but before durable admission commit | never infer admission from preflight checks; reread authoritative store |
| C2 | during admission commit/fsync | treat acknowledgement as unknown; reread `operation_id` and grant-use key before any next decision |
| C3 | after durable admission commit but before response | duplicate delivery resolves to exact existing admission; never allocates a second use slot |
| C4 | before `EffectArmed` append begins | admission exists with no events; recovery defaults to `CancelledBeforeEffect` |
| C5 | during `EffectArmed` commit/fsync | effect MUST NOT have started; recovery rereads whether `EffectArmed` exists before deciding state |
| C6 | after durable `EffectArmed` commit but before adapter invocation | treat effect as potentially having happened; `NonReplayable` recovery cannot blindly invoke it |
| C7 | during external effect | `NonReplayable` recovery is `OutcomeUnknown` unless positive outcome evidence exists |
| C8 | after external effect returns but before terminal receipt commit | outcome may have happened; recover by evidence/reconciliation, never by assuming no effect |
| C9 | during terminal receipt commit/fsync | reread receipt head; if exact terminal event exists, accept it; otherwise remain conservative |
| C10 | after terminal commit but before response | duplicate completion resolves to existing terminal event; never appends another lifecycle event |

For every crash point, restart testing must reconstruct state from durable bytes only. In-memory process state may not be used as oracle evidence.

## Durability-uncertainty tests

### D1 — simulated fsync failure

Expected:

- operation store transitions out of `Healthy` when durable state cannot be proven;
- no new `EffectArmed` acknowledgement is issued;
- read-only evidence may remain available.

### D2 — commit succeeded, response lost

Expected:

- caller rereads durable keys/head;
- exact existing object resolves idempotently;
- no independent retry transaction is allowed to create a second logical operation/effect.

### D3 — impossible invariant discovered

Inject two persisted admissions with the same grant-use reservation in a corrupted fixture.

Expected:

- `open_and_verify()` fails;
- health becomes `RecoveryRequired`;
- privileged effects remain disabled.

## Restart recovery tests

### S1 — clean terminal store

Expected:

- full integrity verification passes;
- no recovery actions required;
- store becomes `Healthy` after anti-rollback verification.

### S2 — admission without event

Expected:

- appears in `scan_non_terminal()`;
- default recovery path appends `CancelledBeforeEffect`;
- no adapter effect is invoked.

### S3 — non-replayable armed effect

Expected:

- appears in `scan_non_terminal()`;
- no new effect attempt starts;
- recovery appends `OutcomeUnknown` unless existing separately governed evidence proves `Completed` or `FailedKnown`.

### S4 — idempotency-key armed effect

Expected:

- recovery may invoke only the adapter's committed reconciliation/idempotency procedure;
- the stable target idempotency key must match the admission commitment;
- no new logical operation id or grant slot is substituted.

### S5 — transactional armed effect

Expected:

- recovery is restricted to the committed transaction scope;
- any target transaction identity mismatch fails closed.

## Backup/restore anti-rollback tests

### B1 — restore current snapshot

Restore a snapshot whose frontier equals the newest trusted external anchor.

Expected:

- complete integrity verification succeeds;
- privileged operation may resume after ordinary non-terminal recovery.

### B2 — restore older snapshot

Restore a valid older snapshot while retaining a newer external frontier anchor.

Expected:

- rollback is detected;
- store enters `RecoveryRequired`;
- no grant use slot from the missing suffix may be reused;
- no privileged effect may be armed.

### B3 — local store and anchor both rolled back

Expected:

- local-only anti-rollback cannot prove freshness;
- deployment must not claim restore-safe at-most-once semantics unless the chosen anchor domain is outside the rollback scope.

This test documents a claim boundary, not a solvable local-database problem.

### B4 — VM clone with same store id

Start two instances from one snapshot containing the same `store_id`.

Expected:

- deployment fencing/single-writer mechanism prevents both from acting as independent writers; or
- one clone receives a new store identity and cannot reuse the old grant/receipt authority domain.

A passing test cannot consist merely of "they usually do not write at the same time."

## Frontier tests

### F1 — deterministic frontier

Two independent readers of identical durable state calculate byte-identical frontier commitments.

### F2 — admission changes frontier

Any newly committed admission changes the frontier.

### F3 — receipt-head change changes frontier

Appending `EffectArmed` or a terminal receipt changes the frontier.

### F4 — reordered serialization cannot change meaning

Backend row iteration order must not affect the frontier. Canonical ordering is required.

### F5 — tampering

Changing any committed admission or receipt event causes integrity/frontier verification to fail.

## Migration tests

### M1 — clean migration

Expected:

- pre-state verifies completely;
- privileged effect arming is blocked during migration;
- post-state verifies completely;
- migration produces a new deterministic frontier and migration evidence;
- a new external anchor is required before effect arming resumes when the durable representation changes materially.

### M2 — crash during migration

Expected:

- startup cannot silently continue with a half-migrated store;
- state is either atomically old, atomically new, or `RecoveryRequired`;
- no privileged effects occur until resolved.

## Resource exhaustion tests

The implementation must bound adversarial growth and malformed input without weakening evidence invariants.

At minimum test:

- oversized canonical records rejected by protocol limits;
- maximum non-terminal scan is streamed/bounded rather than loading unbounded hostile state into memory;
- disk-full during admission;
- disk-full during `EffectArmed` append;
- disk-full during terminal append;
- read-only filesystem transition;
- interrupted checkpoint/frontier write.

Disk exhaustion must fail closed for new effects.

## Platform qualification

Durability behavior is platform/filesystem dependent. Qualification must name and test the supported combinations rather than assuming identical semantics.

At minimum, before production claims, record:

- operating system;
- filesystem/storage class;
- database/store engine and exact version;
- journal/WAL mode;
- synchronous/fsync settings;
- locking mode;
- backup mechanism;
- restore mechanism;
- external frontier-anchor mechanism;
- crash/power-loss test method.

## Exit gate for first native exec

Real one-shot native exec must remain disabled until a concrete store implementation passes this conformance suite for the deployment profile used by the daemon.

The minimum exit evidence is:

1. admission uniqueness race tests pass;
2. receipt CAS race tests pass;
3. C0-C10 crash injection passes;
4. non-terminal recovery passes;
5. durability-uncertainty fail-stop passes;
6. anti-rollback B1-B4 behavior is demonstrated or the deployment claim is explicitly narrowed to exclude restore/clone safety;
7. frontier determinism/tamper tests pass;
8. the exact platform/storage configuration is recorded in release evidence.
