# ADR-019: SQLite V2 authority and receipt store

Status: draft candidate

## Context

The earlier SQLite experiment proved only atomic admission/use-slot reservation. The recovery-safe authority stack now has stronger requirements: authority epochs, authenticated issuance, V2 admission/arm authority, durable persistence proofs, append-only receipts, local anti-rollback frontiers, governed recovery, and an invocation/revocation fence.

Retrofitting those semantics into the V1 experimental schema would create a large compatibility diff and blur which guarantees belong to which persistent format.

## Decision

Define a fresh experimental `xenia-operation-store-sqlite-v2` format. V2 remains incapable of causing an external privileged effect.

The reference profile is:

```text
sqlite-delete-extra-nofollow-v2
```

with:

- rollback journal mode `DELETE` for healthy writer lifecycles;
- `synchronous=EXTRA` for healthy writer lifecycles;
- foreign keys enabled for healthy writer lifecycles;
- exclusive healthy-writer process ownership;
- `SQLITE_OPEN_NOFOLLOW` on the database leaf;
- pre-provisioned Linux authority root from ADR-012;
- exact owner checks with no root exemption;
- `0700` authority directory;
- `0600`, regular, single-link persistent leaves;
- explicit unclean-writer marker;
- no automatic recovery-state clearing.

SQLite/VFS/filesystem/hardware durability remains part of the deployment claim. This ADR does not claim that SQLite can overcome storage hardware that lies about synchronization.

## Recovery-open rule

A pre-existing unclean-writer marker means **historical authority is being inspected**, not initialized.

Therefore the V2 open path must distinguish two modes before mutable SQLite configuration:

### Healthy/fresh lifecycle

```text
no historical marker
  -> open READ_WRITE | CREATE | NOFOLLOW
  -> verify/tighten newly created leaf
  -> acquire exclusive writer ownership
  -> re-check marker race
  -> durably create unclean-writer marker
  -> only then configure DELETE / synchronous=EXTRA / foreign_keys
  -> initialize or verify V2 metadata
```

### Recovery-required lifecycle

```text
historical marker exists
  -> database MUST already exist
  -> verify DB + marker ownership/type/mode
  -> open READ_ONLY | NOFOLLOW
  -> do not CREATE
  -> do not chmod persistent authority
  -> do not change journal/synchronous/schema state
  -> verify exact metadata
  -> expose only RecoveryRequired inspection
```

A marker with a missing database is an integrity failure (`RecoveryDatabaseMissing`), not permission to silently create an empty replacement authority store.

A healthy open re-checks marker existence after obtaining writer ownership. If marker state changed during that window, the open fails closed instead of deciding which lifecycle “probably” won.

Governed mutation of a recovery store is a later ADR-014 recovery transition, not ordinary `open()` behavior.

## Persistent authority metadata

The store singleton commits at least:

- schema version and schema digest;
- exact store id and generation;
- exact authority domain and authority epoch digest;
- exact `StoreAuthorityV2` digest;
- backend implementation/configuration digest;
- persistence profile digest;
- next admission sequence;
- next frontier sequence;
- current local frontier digest.

Opening with a different store/generation/epoch/authority profile fails closed.

## Admission authentication boundary

The SQLite store is itself an authority-spending boundary. It must not assume that an upstream caller already authenticated a V2 authority object.

`admit()` therefore requires:

- exact `GrantAuthorityV2`;
- exact `UseAuthorityV2`;
- exact `AdmissionAuthorityV2`;
- `AuthenticatedIssuanceContextV2` supplied by the configured issuance trust path;
- authenticated semantic use-slot facts;
- authenticated semantic admission facts.

Before beginning the durable mutation, the store reruns the complete:

```text
GrantAuthorityV2 authenticated issuance
  -> UseAuthorityV2 exact predecessor
  -> AdmissionAuthorityV2 exact predecessor/current epoch
  -> semantic slot/admission binding
```

validation.

A structurally valid serialized grant/use/admission chain is insufficient. Failed issuance authentication must leave the admission sequence, use-slot state, and frontier unchanged.

## Admission transaction

A successful admission atomically commits a **named 16-field authority record** containing:

- operation id;
- raw semantic admission commitment;
- exact serialized `AdmissionAuthorityV2` plus its digest;
- exact serialized `UseAuthorityV2` plus its digest;
- exact `GrantAuthorityV2` digest;
- exact serialized `GrantAuthorityV2` bytes;
- raw semantic use commitment;
- authenticated finite use index;
- exact use-slot reservation digest;
- gap-free admission sequence;
- semantic admission time;
- current authority epoch digest;
- the local frontier that committed the mutation;
- persistence time.

The insert names every column explicitly; it does not depend on table-position ordering.

Database constraints make both operation id and `(grant_authority_digest, use_index)` unique.

An exact lost-ack replay may return `DuplicateSame`. Reusing either identity with different immutable state is a conflict.

Persisting `GrantAuthorityV2` bytes preserves the exact issuance evidence object for audit/recovery. Those bytes do **not** authenticate themselves after restart: external issuance evidence still has to be validated by the configured trust domain whenever a recovery/governance decision depends on its authenticity.

## Persistence proofs are reconstructed

V2 does **not** store separately mutable serialized `AdmissionPersistenceProofV2` or `EffectArmedPersistenceProofV2` blobs.

The store persists the facts from which those proofs are deterministically reconstructed. The trusted backend returns the corresponding non-serialized `AuthenticatedPersistenceContextV2` only after the relevant durable transaction is known to have committed.

This avoids creating a second proof table whose fields could diverge from the durable authority/receipt rows they purport to prove.

Serialized proof bytes remain evidence objects, not self-authenticating credentials.

## Receipt compare-and-append

Receipt events are append-only and keyed by `(operation_id, event_index)`.

Each event persists:

- exact previous event digest;
- exact event digest;
- exact canonical event bytes;
- state code;
- event time;
- committing frontier digest;
- persistence time.

Before any ordinary receipt transaction, the store requires the caller's exact `AdmissionAuthorityV2` digest and raw admission commitment to match the immutable admission already persisted for that operation. Merely reusing the same operation id cannot bind a receipt to a different authority record.

The store revalidates the semantic receipt transition before append. A terminal event cannot be extended.

An exact event replay may return `DuplicateSame` only while it remains semantically appropriate. In particular, historical `EffectArmed` proof retrieval must not become permission to approach the external-effect boundary after a later receipt exists. A stale caller presenting the old first event after a successor exists fails closed.

## Write-ahead `EffectArmed`

`EffectArmed` is the only receipt append in this tranche that may return an `EffectArmedPersistenceProofV2` and authenticated persistence context.

Before that proof is issued, the same atomic mutation must commit:

1. exact V2 arm authority validation against the admission/store/current epoch;
2. exact first receipt event with the fresh arm authorization commitment;
3. the event as the current receipt head;
4. a new local frontier containing that head;
5. the event's committing frontier reference.

No external effect may occur in this crate.

## Local frontier

Every admitted mutation and receipt append advances a local hash-chained frontier.

Each frontier commits:

- exact frontier sequence;
- previous frontier digest;
- canonical root over all immutable admission-authority digests;
- canonical root over exactly one current receipt-event digest per admitted operation;
- creation time.

The roots intentionally exclude each row's own `committed_frontier_digest`, avoiding a circular hash/fixed-point construction.

The store verifies the complete retained frontier chain and recomputes the current admission/head roots during local integrity checks.

The local frontier is **not itself rollback resistant**. External anchoring from ADR-007/ADR-014 remains necessary for deployments claiming VM-snapshot/backup rollback resistance.

## Local integrity gate

`PRAGMA integrity_check` is necessary but insufficient.

Before a clean store may be considered locally healthy, V2 also verifies:

- metadata/store/epoch binding;
- serialized grant/use/admission authority records parse and structurally validate;
- stored raw admission/use commitments agree with the serialized authority records;
- stored grant/use/admission authority digests recompute exactly;
- operation and predecessor identities agree;
- use-slot reservation digests recompute from the durable authority/use-index facts;
- admission sequences are exactly gap-free and `next_admission_sequence` agrees;
- admission epoch commitments equal the current store epoch;
- persistence timestamps do not precede the semantic admission or current epoch;
- every receipt chain validates from its immutable admission;
- receipt auxiliary columns (`event_index`, previous digest, event digest, state code, recorded time) agree with the canonical serialized event bytes;
- receipt persistence time does not precede event time;
- the full local frontier chain is contiguous and hash-valid;
- the current frontier roots match current durable state;
- admission/event frontier references name retained frontiers.

Persisted grant bytes preserve evidence, but local structural verification does not substitute for an external authenticated-issuance check during governed recovery.

External anchor continuity is a separate recovery check.

## Unclean lifecycle

Store open creates and synchronizes an unclean-writer marker only after healthy exclusive database ownership is obtained and before mutable profile/schema work begins.

Ordinary `Drop`, panic, kill, or crash leaves the marker. A later owner opens the existing database read-only as `RecoveryRequired` and cannot mutate privileged authority until ADR-014 governed recovery succeeds.

Verified clean close closes the SQLite connection first and only then removes and directory-syncs the marker. Failure biases toward recovery rather than a false-clean lifecycle.

## Concurrency and process ownership

This profile is intentionally single-writer-process. CI exercises a real two-process probe:

1. process A opens and holds the V2 store;
2. process B must fail to obtain usable access while A is the live exclusive writer;
3. A is killed with `SIGKILL`;
4. the marker survives;
5. process C opens the existing database only as `RecoveryRequired`.

## Crash qualification

Before promotion, the implementation must fault/kill at the ADR-007 C0-C10 boundaries around admission and receipt/frontier commits.

Unexpected mutation/commit errors that make commit outcome ambiguous fail-stop the in-memory store as `DurabilityUncertain`. They never become proof of non-commit and never authorize blind retry.

## Relationship to the invocation fence

This store may produce the durable authority/persistence evidence consumed by ADR-018. It does not cross the invocation fence or perform its irreversible start primitive.

The intended ordering is:

```text
externally authenticated GrantAuthorityV2
  -> V2 admission commit
  -> AdmissionPersistenceProofV2
  -> fresh EffectArmAuthorityV2
  -> durable EffectArmed + frontier
  -> EffectArmedPersistenceProofV2
  -> required external rollback anchor
  -> invocation/revocation fence
  -> bounded adapter start
```

## Non-goals

This ADR does not implement or authorize:

- process creation;
- PTY or shell execution;
- service tunneling;
- credential use;
- Redfish/device operations;
- automatic recovery;
- distributed multi-writer consensus;
- generic exactly-once external effects;
- external anti-rollback anchoring by itself.

## Promotion gates

Before this backend may gate real privileged effects:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV check passes;
3. `SQLITE_OPEN_NOFOLLOW` is proven available in the pinned rusqlite dependency;
4. the explicit named 16-field admission mapping and serialized grant/use/admission chain are tested;
5. wrong authenticated issuance fails before durable mutation/frontier movement;
6. same-operation-id but different admission authority cannot append a receipt;
7. two-process writer/SIGKILL recovery passes;
8. stale marker + missing DB fails closed without replacement creation;
9. RecoveryRequired inspection does not mutate SQLite profile/schema state;
10. negative symlink/hard-link/type/owner/mode tests pass;
11. authority/receipt/frontier auxiliary-column corruption tests fail closed;
12. C0-C10 crash injection passes for admission and `EffectArmed`;
13. governed recovery, authenticated issuance evidence, and external-anchor verification integrate without a bypass;
14. only then may the native-exec adapter consume V2 persistence proofs.
