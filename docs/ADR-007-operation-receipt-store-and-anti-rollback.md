# ADR-007: Durable Operation Receipt Store and Anti-Rollback Boundary

- Status: Proposed
- Date: 2026-08-30
- Depends on: ADR-005, ADR-006
- Scope: privileged-operation admission/receipt persistence only

## Context

ADR-005 defines session-bound capability grants and linear use budgets. ADR-006 defines immutable `OperationAdmissionV1` records, append-only receipt events, the write-ahead `EffectArmed` boundary, and the deliberately narrow claim of at-most-once local admission rather than generic exactly-once external effects.

Those protocol objects are not sufficient by themselves. Their security properties depend on a persistence domain that can atomically reserve grant-use slots, reject conflicting duplicate operations, serialize receipt heads, survive crashes, and detect rollback of previously durable state.

A naive implementation such as "check whether the operation exists, then insert it" is unsafe under concurrency. A mutable status row is unsafe under crash recovery. A database restored from an older backup can be even worse: it can forget that a grant slot was consumed and permit the same authority to be exercised again.

Therefore the operation receipt store is a privileged security boundary, not an interchangeable convenience repository.

## Decision

Xenia will define a durable operation receipt store with the following V1 invariants.

### 1. Admission is one atomic reservation transaction

A successful admission transaction MUST atomically establish all of the following before returning success:

1. the exact immutable `OperationAdmissionV1` record is durable;
2. `operation_id` is unique within the store identity domain;
3. `(grant_digest, use_index)` is unique within the store identity domain;
4. one monotonic `admission_sequence` has been allocated exactly once;
5. the store has advanced to a durable frontier that includes this admission.

No in-memory mutex, preflight lookup, or application-level "check then insert" may substitute for storage-enforced uniqueness.

The logical API result is one of:

- `AdmittedNew`: this call created the unique durable admission;
- `AdmittedExisting`: the same `operation_id` already exists with the exact same immutable admission commitment;
- `OperationIdConflict`: the `operation_id` exists but commits to different immutable bytes;
- `GrantUseAlreadyReserved`: the exact `(grant_digest, use_index)` is already bound to another operation;
- `DurabilityUnknown`: the storage implementation cannot prove whether the transaction committed;
- `StoreUnavailable`: no durable effect authorization may proceed.

`AdmittedExisting` is an idempotent lookup result, not permission to create a second external effect attempt.

### 2. Unknown commit outcome is resolved by reread, never by blind retry

Storage APIs may fail after the underlying transaction has committed but before the caller receives acknowledgement.

If admission returns an ambiguous commit result, the runtime MUST reopen or reread the durable store and resolve both uniqueness keys:

- `operation_id`; and
- `(grant_digest, use_index)`.

Only the exact persisted admission may be treated as admitted. A caller MUST NOT issue a second logically independent admission merely because the first acknowledgement was lost.

### 3. Receipt events use compare-and-append semantics

Receipt history is append-only.

Appending a receipt event MUST atomically compare the caller's expected receipt head and append exactly one successor. The expected head consists of:

- expected next `event_index`;
- expected previous-event digest, or the all-zero sentinel for the first event;
- expected current non-terminal state implied by the validated chain.

The store MUST reject stale writers. Two concurrent attempts to append different successors to the same receipt head cannot both commit.

The logical result is one of:

- `AppendedNew`;
- `AppendedExisting` for the exact already-committed event;
- `ReceiptHeadConflict`;
- `TerminalReceipt`;
- `DurabilityUnknown`;
- `StoreUnavailable`.

The protocol validator remains authoritative for legal state transitions; the store is authoritative for durable serialization of those transitions.

### 4. `EffectArmed` acknowledgement is a hard side-effect gate

The adapter MAY cross its external-effect boundary only after the exact `EffectArmed` event is durably committed and acknowledged by the store.

The sequence is:

```text
validate live session/grant/use
        |
        v
atomic admission + grant-use reservation
        |
        v
append EffectArmed with CAS
        |
        v
DURABLE COMMIT ACKNOWLEDGED
        |
        v
external effect may begin
```

A memory-visible event, queued write, asynchronous flush request, or successful serialization is insufficient.

If the storage layer cannot prove the `EffectArmed` commit, the adapter MUST NOT begin the effect until recovery rereads the durable store and proves the event exists exactly.

### 5. Store health is fail-stop for new privileged effects

The store exposes a security health state, conceptually:

- `Healthy`;
- `ReadOnlyDegraded`;
- `RecoveryRequired`.

Any of the following moves the privileged-operation runtime out of `Healthy` until explicitly recovered:

- integrity-check failure;
- receipt-chain validation failure;
- duplicate uniqueness keys that should be impossible;
- monotonic sequence regression;
- inability to determine commit outcome after reread;
- durability/fsync failure;
- anti-rollback frontier mismatch;
- unsupported schema migration state;
- storage corruption.

While not `Healthy`, Xenia may expose read-only evidence and recovery tooling, but it MUST refuse to arm new privileged effects.

### 6. Recovery defaults are conservative

On startup, every non-terminal operation is classified before new privileged effects are permitted.

#### Admission with no receipt event

The effect boundary was never durably armed.

Default recovery action: append `CancelledBeforeEffect`.

V1 MUST NOT resurrect an old admission merely because the original request once had authority. A new attempt requires a new operation id and current authorization.

#### `EffectArmed` with no terminal event

The effect may have happened.

- `NonReplayable`: resolve to `OutcomeUnknown` unless the adapter can positively prove a known terminal outcome without creating another effect.
- `TargetIdempotencyKey`: the adapter may perform a read/reconciliation operation allowed by its committed recovery contract; it may only repeat a target mutation when the target's idempotency semantics prove that repetition is the same logical operation.
- `Transactional`: the adapter may use the exact committed transaction recovery mechanism to query/finish/abort according to that protocol's semantics.

A transport timeout is never, by itself, retry authorization.

#### Terminal receipt

No further lifecycle event may be appended.

### 7. Backup/restore rollback is part of the threat model

A restored old database can forget consumed capability slots and previously armed effects. Therefore ordinary database durability is not enough to sustain the at-most-once claim across backup restore, filesystem snapshots, VM rollback, or disk-image rollback.

The store MUST have a stable random `store_id` and a monotonic externally comparable frontier.

The conceptual `OperationStoreFrontierV1` commits at least:

- store schema/version;
- `store_id`;
- store generation;
- highest committed admission sequence;
- count/commitment of admitted operations;
- commitment to current receipt heads;
- frontier timestamp or checkpoint sequence when available.

The exact accumulator format is deferred to the implementation tranche, but it MUST be deterministic and collision-resistant.

A frontier only detects rollback if a newer reference survives outside the rolled-back store. Therefore production deployments MUST anchor frontier checkpoints into at least one rollback-resistant domain before claiming restore-safe at-most-once semantics. Candidate anchors include:

- a checkpoint record in Xenia's existing append-only evidence ledger;
- TPM/secure-element monotonic state where available;
- a separately administered immutable object store;
- a remote witness/quorum for higher-assurance deployments.

On startup after restore, if the local frontier is older than the newest trusted external anchor, the store enters `RecoveryRequired` and privileged effects remain disabled.

### 8. Store identity prevents accidental clone equivalence

Cloning a VM or disk image clones the receipt database too. Two live clones must not silently act as one authority domain.

`store_id` is therefore part of the store security identity. Deployment tooling MUST either:

- ensure only one live writer exists for a `store_id`; or
- intentionally create a new store identity and require fresh authority/grants for the clone.

V1 does not support active-active multi-writer receipt stores across independent machines unless the backend provides a proven single-copy serialization/consensus contract strong enough to preserve all uniqueness and CAS invariants.

### 9. Monotonic ordering does not rely on wall-clock time

Wall-clock timestamps remain evidence metadata, but ordering authority comes from storage serialization:

- `admission_sequence` for admissions;
- `event_index` and previous-event digest for one operation's receipt chain;
- frontier/checkpoint sequence for anti-rollback comparison.

Clock rollback therefore cannot make an old operation "new" again.

### 10. Sensitive content remains outside the receipt store by default

The receipt store records commitments and lifecycle facts, not arbitrary privileged output.

It MUST NOT automatically persist:

- stdout/stderr bodies;
- terminal transcripts;
- credentials or tokens;
- clipboard contents;
- file payloads;
- database result rows;
- HTTP bodies;
- secret environment values.

If an adapter needs durable outcome evidence, it should store separately governed evidence and place only a digest/typed reference in the receipt event.

### 11. No V1 destructive compaction

V1 receipt-store implementations MUST NOT discard admissions or receipt events merely because an operation is terminal.

Future compaction may replace old material only after a cryptographically committed checkpoint/segment format and restore-verification procedure are defined. Until then, retention is append-only.

### 12. Migration is a privileged evidence operation

Schema migration can alter uniqueness, ordering, or replay behavior. Therefore migration MUST:

1. refuse to run while privileged effects are being armed;
2. verify the pre-migration store completely;
3. produce a deterministic migration receipt/checkpoint;
4. preserve `store_id` only when all security invariants are preserved exactly;
5. enter `RecoveryRequired` on partial/ambiguous migration;
6. require a new external frontier anchor before privileged operation resumes when the durable representation changes materially.

## Informative relational shape

A relational implementation may approximate the logical invariants with tables such as:

```text
operation_store_meta(
    store_id PRIMARY KEY,
    schema_version,
    generation,
    next_admission_sequence,
    health_state,
    ...
)

operation_admissions(
    operation_id PRIMARY KEY,
    admission_sequence UNIQUE NOT NULL,
    grant_digest NOT NULL,
    use_index NOT NULL,
    admission_digest UNIQUE NOT NULL,
    canonical_admission NOT NULL,
    UNIQUE(grant_digest, use_index)
)

operation_receipt_events(
    operation_id NOT NULL,
    event_index NOT NULL,
    previous_event_digest NOT NULL,
    event_digest UNIQUE NOT NULL,
    canonical_event NOT NULL,
    PRIMARY KEY(operation_id, event_index)
)
```

This schema is illustrative only. Correctness depends on transaction/durability behavior, not table names.

## Required implementation properties

The first concrete store implementation SHOULD be deliberately boring and local-first. It must support:

- one atomic admission transaction;
- storage-enforced uniqueness;
- CAS receipt append;
- durable commit acknowledgement;
- startup integrity verification;
- complete non-terminal recovery scan;
- deterministic frontier calculation;
- explicit health state;
- crash-injection tests at every persistence/effect boundary.

SQLite in WAL mode is a reasonable candidate only if its exact synchronous, fsync, checkpoint, locking, filesystem, and backup semantics are qualified for the supported platforms. This ADR does not bless a database merely by product name.

## Consequences

### Positive

- Duplicate network delivery cannot consume one grant slot twice.
- Concurrent runtime workers cannot race one use slot into two operations.
- Receipt heads cannot fork silently.
- Ambiguous database acknowledgements do not become duplicate effects.
- Backup/VM rollback is explicitly recognized as an authority-reuse hazard.
- A broken evidence store fails closed before privileged side effects.
- The runtime can remain adapter-agnostic while adapters declare exact recovery semantics.

### Costs

- Persistence becomes part of the trusted computing base.
- Backup/restore requires evidence-aware procedures rather than simple file replacement.
- High-assurance multi-machine operation requires an external witness or consensus-capable store.
- The implementation must test crash behavior, not merely happy-path unit logic.

## Non-goals

ADR-007 does not:

- implement SQLite or another database;
- provide distributed consensus;
- create an active-active cluster;
- spawn a process;
- retry an external effect;
- open a PTY or tunnel;
- store secrets;
- define receipt compaction;
- define cross-subject delegation;
- claim generic exactly-once execution.

## Security claim boundary

After ADR-007 is implemented and qualified, Xenia may claim at-most-once local admission and use-slot reservation **within a verified, non-rolled-back receipt-store identity domain**.

It may not extend that claim across arbitrary restored snapshots, cloned VMs, or independent writers unless anti-rollback/single-writer invariants are also proven for that deployment.
