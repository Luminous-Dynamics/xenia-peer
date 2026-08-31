# ADR-024: Operation-frontier external retention reference model

Status: draft candidate

## Context

ADR-023 requires externally retained operation-frontier witness bundles to be append-only and durable before acknowledgement. Cloud/object-store/remote-witness APIs differ in conditional-write behavior and in how they report timeouts or ambiguous commit outcomes. Xenia should define the security semantics before selecting a backend.

## Decision

Introduce `xenia-operation-frontier-retention-model` as an executable behavioral oracle.

The model is not network code and does not itself provide rollback resistance. It defines the minimum state machine a real independent retention backend must realize.

## Sequence identity

The immutable retention identity is the signed witness sequence inside `RetainedOperationFrontierWitnessBundleV1`.

The model requires:

```text
first retained witness sequence == 0
next sequence == previous + 1
```

For any already-retained sequence:

```text
same sequence + exact same bundle bytes
    -> DuplicateSame

same sequence + any different bundle field
    -> SequenceConflict
```

A mutable latest pointer is never an authority source. Rehydration validates the complete retained bundle lineage.

## Persistence-before-ack

A new candidate is not inserted into the model and cannot return `Appended` until the external persistence boundary reports `Durable` for that exact candidate.

The persistence outcome vocabulary is:

- `Durable` — backend positively confirms durable append;
- `Rejected` — backend positively confirms candidate was not durably appended;
- `Unknown` — backend cannot prove whether append committed.

`Rejected` leaves the in-memory model healthy and unchanged.

`Unknown` changes health to `DurabilityUncertain` and fail-stops every subsequent mutation.

This deliberately rejects the unsafe interpretation:

```text
timeout / connection loss
    -> probably did not write
    -> retry same/new witness
```

## Recovery from uncertain persistence

There is no `clear_uncertain(true)` operation.

The only V1 recovery path is external readback of the immutable retained lineage followed by `from_retained_lineage(...)`, which revalidates:

- bundle-local signature/checkpoint binding;
- genesis sequence zero;
- exact successor sequence/digest rules;
- retention timestamp monotonicity.

The readback may establish that the ambiguous candidate is present or absent. Either result is acceptable when cryptographically/immutably proven by the external backend; guessing is not.

## Backend mapping

A real backend should implement an equivalent conditional append, for example:

```text
put immutable object keyed by
(store_id, generation, witness_sequence)
with create-if-absent / first-writer-wins

if object already exists:
    exact bytes/digest -> DuplicateSame
    different bytes   -> conflict

only after durable object confirmation:
    CAS latest pointer (optional optimization)
    acknowledge Appended
```

If the provider cannot distinguish rejected from ambiguous persistence, Xenia must use `Unknown` and fail-stop.

## External-domain requirement

Matching the model does not by itself satisfy ADR-023. The backend must also survive independently from the protected operation-store/ledger rollback domain and must provide sufficient immutable readback evidence for recovery verification.

## Non-goals

ADR-024 does not:

- choose S3, Azure, GCS, Holochain, TPM, or another provider;
- define network authentication;
- define multi-witness quorum consensus;
- clear ADR-014 recovery state;
- authorize a privileged operation;
- relax the complete-ledger proof boundary from ADR-023.

## Qualification gates

Before a concrete retention backend is accepted:

1. Rust 1.96 fmt/test/Clippy passes for the reference model;
2. Rust 1.94 MSRV passes;
3. exact duplicate replay returns `DuplicateSame` without a second persistence call;
4. same-sequence different bundle fails as conflict;
5. sequence gaps/regressions fail before persistence;
6. definite rejection leaves model healthy/unchanged;
7. unknown persistence outcome enters `DurabilityUncertain`;
8. uncertain health refuses all further writes;
9. only external lineage readback/revalidation restores a healthy model;
10. the concrete backend has destructive tests demonstrating equivalent semantics under timeout, process kill, connection loss, and duplicate concurrent writers.
