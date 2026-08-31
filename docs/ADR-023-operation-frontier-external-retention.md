# ADR-023: External retention for operation-frontier witnesses

Status: draft candidate

## Context

ADR-022 defines a signed operation-frontier witness and an AGPL verifier that composes it with a real Xenia ledger checkpoint, a retained trusted ledger key, the recovered signed ledger, and the retained operation-store frontier chain.

That composition only detects whole-store rollback when evidence survives outside the rollback domain. Retaining a witness without the exact signed `LedgerCheckpoint` it references is operationally fragile, and overwriting one mutable `latest` object would create a new rollback/fork surface in the retention layer itself.

## Decision

Introduce `RetainedOperationFrontierWitnessBundleV1` as the atomic external-retention object:

```text
OperationFrontierLedgerWitnessV1
              +
exact signed LedgerCheckpoint
              +
retained_at_unix_ms
              |
              v
RetainedOperationFrontierWitnessBundleV1
              |
              v
canonical bytes + bundle digest
```

Bundle-local validation proves:

- witness syntax/signature is valid;
- checkpoint self-signature/schema is valid;
- witness checkpoint binding equals the exact retained signed checkpoint fingerprint/count/head/key/timestamp;
- retention time does not predate either signed evidence object.

Bundle-local validation does **not** prove that the checkpoint key is the deployment's independently trusted ledger key or that the recovered ledger/store contains the witnessed history. Those checks remain in the ADR-022 authority adapter.

## External retention store semantics

A deployment claiming rollback detection must retain bundles in a rollback domain independent from the protected operation store and local consent-ledger state.

The first retention backend should expose append-only compare-and-append semantics rather than mutable object overwrite.

Conceptually, the key is:

```text
(store_id, generation, witness_sequence)
```

and the immutable value is the exact `bundle_digest` plus canonical bundle bytes.

Required behavior:

```text
same key + same digest
    -> DuplicateSame

same key + different digest
    -> CONFLICT / fork evidence

new exact next witness sequence
    -> durable append

sequence gap/regression
    -> reject

ack before durable retention
    -> forbidden
```

A separately maintained `latest` pointer may exist as an optimization only if it is CAS-bound to an already durable immutable bundle. Recovery must be able to enumerate/verify the retained lineage rather than trusting one mutable pointer.

## Retention succession

`RetainedOperationFrontierWitnessBundleV1::validate_successor(previous)` requires:

1. both bundles are locally self-consistent;
2. the contained signed witness is an exact ADR-022 successor;
3. retention time does not regress.

This keeps external storage semantics aligned with the signed witness lineage rather than inventing a second independent ordering system.

## Recovery verification

The retained bundle is passed to the ADR-022 authority adapter with:

- independently retained trusted ledger public key;
- recovered signed ledger entries;
- retained operation-store frontier history;
- current time/freshness policy.

Only that composition yields `VerifiedOperationFrontierWitnessV1`.

Successful verification is recovery evidence only. It does not clear `RecoveryRequired`, advance epochs, consume a grant, append a receipt, or authorize an external effect.

## Ledger compaction boundary

The first ADR-022 adapter deliberately uses `Verifier::verify_checkpoint_prefix(checkpoint, ledger_entries, trusted_key)` with a complete recovered signed ledger.

Therefore V1 makes a deliberately conservative promotion claim:

> A deployment may not destructively compact away the signed ledger history needed to prove the externally retained witness checkpoint as an exact prefix unless it also retains separately verifiable checkpoint-extension/compaction evidence and uses a verifier profile qualified for that evidence.

Until such a profile exists, rollback-resistant privileged-operation deployments must retain the complete signed ledger history required by the prefix verifier.

This is not a permanent rejection of Xenia ledger compaction. `xenia-ledger` already has checkpoint/compaction/archive primitives. A later adapter profile may accept an anchored suffix only when it can cryptographically prove that the compaction base itself extends the externally retained witness checkpoint and that the resident suffix extends that base.

The verifier must never infer this merely because a compacted checkpoint has a larger entry count.

## Independent trust domains

Examples of valid external retention include:

- separately administered immutable object storage with version/object-lock policy;
- another host or service identity with append-only retention;
- a remote witness service;
- offline retained evidence;
- later TPM/secure-element-backed witness state.

Keeping the bundle only in the same VM, filesystem snapshot, database backup, or administrator-controlled rollback domain as the protected state does not satisfy ADR-023.

## Non-goals

ADR-023 does not yet:

- choose a cloud/object-store vendor;
- implement network transport;
- define quorum consensus;
- support destructive ledger compaction in the V1 verifier;
- clear recovery state;
- authorize a privileged operation;
- replace ADR-014 governed recovery.

## Qualification gates

Before an external retention backend may satisfy the privileged-operation rollback-resistance claim:

1. retained bundle Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV passes;
3. mismatched signed checkpoint/witness cannot form a bundle;
4. bundle retention time cannot predate signed evidence;
5. exact duplicate retention is distinguishable from same-sequence fork;
6. retention sequence gaps/regressions fail closed;
7. durable append occurs before acknowledgement;
8. recovery verifies the exact retained bundle through the ADR-022 authority adapter;
9. old operation-store snapshot + newer retained bundle fails;
10. old/truncated ledger + newer retained bundle fails;
11. retention backend survives independently from the protected rollback domain;
12. any future compaction-aware verifier is separately qualified before complete-ledger retention is relaxed.
