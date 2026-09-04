# Xenia ledger persistence outcome V0.1

## Purpose

`Chain::append_transactional` and `Chain::append_transactional_chain` historically model persistence as `Result<(), E>`.

That shape is correct only when `Err` proves the candidate did **not** become durable. It is not sufficient for storage/service boundaries where a commit can succeed and the acknowledgement can be lost.

The unsafe interpretation is:

```text
append candidate N
    ↓
durable commit may happen
    ↓
acknowledgement lost
    ↓
callback Err
    ↓
pop N locally
    ↓
retry another event as N
```

If N actually became durable, local state has now forgotten an external effect and can produce a fork/duplicate sequence.

V0.1 adds an additive outcome-aware path without changing the legacy API's source compatibility.

## Persistence classifications

A storage callback must classify one exact candidate as:

```text
Persisted
ProvenNotPersisted(error)
OutcomeUnknown(error)
```

`OutcomeUnknown` is mandatory whenever the backend cannot prove whether the external durable effect occurred.

## Pre-dispatch latch

`Chain::append_transactional_outcome` performs:

```text
append signed candidate
        ↓
construct exact PendingPersistenceFrontier
        ↓
latch candidate as persistence-uncertain
        ↓
invoke persistence backend
```

The latch is installed **before** the callback executes.

This matters even for unwinding. If a persistence callback panics after crossing its effect boundary and a caller catches that unwind while retaining the `Chain`, the candidate remains latched and further append is blocked.

## Exact ambiguous frontier

`PendingPersistenceFrontier` commits in-memory identity sufficient to ensure reconciliation is still talking about the exact candidate:

- absolute candidate sequence;
- candidate entry hash;
- total chain entry count;
- current chain head hash.

While the latch exists:

```text
Chain::append(...)
    -> UncertainPersistencePending
```

and every transactional append that routes through `append` is blocked as well.

## Outcome semantics

### Persisted

The exact pending frontier is rechecked, the latch is cleared, and the candidate remains resident.

### ProvenNotPersisted

The exact pending frontier is rechecked, exactly the ambiguous last entry is removed, and only then is the latch cleared.

Sequence reuse after this state is safe because the backend explicitly proved the candidate did not become durable.

### OutcomeUnknown

The candidate remains resident and the latch stays set. No new append is permitted.

## Reconciliation

`Chain::reconcile_pending_persistence` invokes a separate reconciliation callback for the existing candidate; it never creates a new ledger entry.

The reconciliation can return the same three states:

- `Persisted`: keep candidate, clear latch;
- `ProvenNotPersisted`: remove exact candidate, clear latch;
- `OutcomeUnknown`: preserve candidate and latch.

There is no implicit retry of the original persistence effect.

## Legacy API boundary

The existing `append_transactional*` methods remain available for compatibility. Their callback `Err` is explicitly documented as a **proof of non-persistence** contract.

Backends with commit ambiguity must not use those methods.

The later Xenia witness-anchor integration will use only the outcome-aware API.

## Checkpoints

`Chain::sign_checkpoint` signs the current in-memory frontier. If persistence is uncertain, that frontier includes the ambiguous candidate and the checkpoint therefore does **not** prove durable persistence.

Concrete durability-sensitive integrations must check/reconcile `Chain::has_uncertain_persistence()` before treating a checkpoint as a durable-source checkpoint. A later small API hardening can make this a dedicated checked checkpoint constructor if qualification indicates value in enforcing that distinction structurally.

## Crash boundary

The latch is process-local and deliberately is not serialized by `from_entries` / `from_checkpoint_suffix`.

After process death, the storage layer becomes the source of truth and must reconstruct/verify whichever durable frontier exists before creating a new appendable `Chain`.

For the intended witness-anchor integration, a deterministic external operation ID plus fresh Xenia checkpoint/current-anchor lookup provides that cross-process reconciliation identity.

## Tests authored

The dedicated integration suite covers:

- ambiguous persistence keeps candidate resident and blocks subsequent append;
- reconciliation confirming persistence clears the latch and allows the next sequence;
- proven non-persistence rolls the exact candidate back and permits safe sequence reuse;
- unknown followed by proven absence removes only the exact ambiguous candidate;
- a caught panic inside the persistence callback leaves the chain fail-closed and append-blocked.

## Non-claims

V0.1 does not provide a storage engine, cross-process operation log, disk fsync policy, source-side CAS, or remote freshness mechanism.

It fixes the in-memory ledger semantics so those concrete layers can represent ambiguity without converting uncertainty into permission to retry.
