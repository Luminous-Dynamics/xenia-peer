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
- exact qualified SQLite source lineage for rollback-journal recovery;
- no automatic recovery-state clearing.

SQLite/VFS/filesystem/hardware durability remains part of the deployment claim. This ADR does not claim that SQLite can overcome storage hardware that lies about synchronization.

## Recovery-open rule

A pre-existing unclean-writer marker means **historical authority is being recovered/inspected, not initialized**.

Rollback-journal SQLite may require pager-level hot-journal rollback before a crashed database can be read. ADR-021 therefore owns the narrow engine-recovery boundary. SQLite pager recovery may canonicalize the database back to its last committed SQLite image, but it is not an Xenia authority transition and cannot make the store healthy.

The V2 open path distinguishes two modes before any ordinary Xenia mutation becomes possible.

### Healthy/fresh lifecycle

```text
no historical marker
  -> open READ_WRITE | CREATE | NOFOLLOW
  -> verify exact qualified SQLite source
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
  -> verify adjacent rollback-journal leaf if present
  -> ADR-021 engine-recovery bootstrap:
       existing DB only
       READ_WRITE | NOFOLLOW
       NO CREATE
       exact qualified SQLite source
       pager may roll back a hot journal only
  -> close bootstrap connection
  -> reverify DB / journal trust
  -> reopen READ_ONLY | NOFOLLOW
  -> verify exact metadata + local semantic integrity
  -> expose RecoveryRequired inspection only
```

During the ADR-021 bootstrap, Xenia does not admit operations, consume grant slots, append receipts, advance frontiers/epochs, clear the marker, or restore privileged runtime authority.

If no pager recovery is necessary, the recovery lifecycle must not perform unrelated Xenia authority mutation. If pager recovery is necessary, changed SQLite bytes are acceptable only insofar as the qualified SQLite engine canonicalizes an interrupted transaction to its last committed database image; post-recovery semantic verification remains mandatory.

A marker with a missing database is an integrity failure (`RecoveryDatabaseMissing`), not permission to silently create an empty replacement authority store.

A healthy open re-checks marker existence after obtaining writer ownership. If marker state changed during that window, the open fails closed instead of deciding which lifecycle “probably” won.

Governed mutation of Xenia recovery state is an ADR-014 recovery transition, not ordinary `open()` behavior and not ADR-021 pager rollback.

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

Hash-chain validity alone is insufficient. The V2 verifier also replays durable mutations in frontier order. Genesis commits the empty admission/head roots. Every later frontier must correspond to exactly one durable admission or receipt mutation, and replaying that mutation must reproduce that frontier's stored semantic roots.

This proves more than “all frontiers hash together”: it establishes that the retained frontier history is a deterministic checkpoint history of the retained mutation set.

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
- grant issuance, semantic admission, and persistence times obey the local consistency ordering required by the V2 contracts;
- every receipt chain validates from its immutable admission;
- receipt auxiliary columns (`event_index`, previous digest, event digest, state code, recorded time) agree with the canonical serialized event bytes;
- receipt persistence time does not precede event time;
- the full local frontier chain is contiguous and hash-valid;
- every non-genesis frontier corresponds to exactly one durable mutation;
- mutation replay reproduces the admission/head roots at every retained frontier;
- the current frontier roots match current durable state;
- admission/event frontier references name retained frontiers.

Persisted grant bytes preserve evidence, but local structural verification does not substitute for an external authenticated-issuance check during governed recovery.

External anchor continuity is a separate recovery check.

## Unclean lifecycle

Store open creates and synchronizes an unclean-writer marker only after healthy exclusive database ownership is obtained and before mutable profile/schema work begins.

Ordinary `Drop`, panic, kill, or crash leaves the marker. A later owner performs only the ADR-021 qualified pager-canonicalization bootstrap needed to establish a readable last-committed SQLite image, then reopens read-only as `RecoveryRequired`. Privileged Xenia authority remains fail-stopped until ADR-014 governed recovery succeeds.

Verified clean close is a security ceremony rather than merely a connection close:

1. health must still be `Healthy`;
2. the store reruns complete local semantic integrity;
3. SQLite connection close must succeed;
4. only then may the marker be removed and its parent directory synchronized.

If final integrity or connection close fails, the marker remains. The next lifecycle therefore enters recovery instead of inheriting a false-clean claim.

## Concurrency and process ownership

This profile is intentionally single-writer-process. CI exercises a real two-process probe:

1. process A opens and holds the V2 store;
2. process B must fail to obtain usable access while A is the live exclusive writer;
3. A is killed with `SIGKILL`;
4. the marker survives;
5. process C may use ADR-021 pager recovery only to canonicalize SQLite's interrupted transaction state;
6. process C then exposes the existing store as `RecoveryRequired`, never `Healthy`.

## Crash qualification

ADR-020 freezes the exact C0-C10 vocabulary for the admission and `EffectArmed` transactions.

Before promotion, the implementation must exercise every C0-C10 boundary for both transaction classes and must separately race `SIGKILL` across SQLite `COMMIT`. C8/C9 bracketing alone is not enough to qualify a commit-in-flight crash.

Each crash case starts from an independent baseline and is evaluated only after ADR-021 pager recovery plus full local semantic verification.

For a commit-in-flight race, reread may resolve only one of two semantic outcomes:

- the target transaction is fully absent and the previous frontier remains authoritative; or
- the exact complete target transaction, frontier, links, and proof-reconstruction facts are present.

Partial authority is a failure.

Unexpected mutation/commit errors that make commit outcome ambiguous fail-stop the in-memory store as `DurabilityUncertain`. They never become proof of non-commit and never authorize blind retry.

## Qualified SQLite source lineage

Rollback-journal pager recovery is part of the security boundary. The qualification lineage therefore pins the exact rusqlite revision and exact bundled SQLite source ID named by ADR-021 rather than accepting an arbitrary semver-compatible SQLite build.

A source-lineage change invalidates the existing crash/recovery evidence until the destructive matrix is rerun. Runtime qualification verifies both `sqlite_version()` and `sqlite_source_id()` before an unclean journal may be consumed.

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
- automatic Xenia authority recovery;
- distributed multi-writer consensus;
- generic exactly-once external effects;
- external anti-rollback anchoring by itself.

## Promotion gates

Before this backend may gate real privileged effects:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV check passes;
3. `SQLITE_OPEN_NOFOLLOW` is proven available in the pinned rusqlite dependency;
4. the exact ADR-021 SQLite version/source ID is verified at runtime before rollback-journal recovery;
5. the explicit named 16-field admission mapping and serialized grant/use/admission chain are tested;
6. wrong authenticated issuance fails before durable mutation/frontier movement;
7. same-operation-id but different admission authority cannot append a receipt;
8. two-process writer/SIGKILL recovery passes through ADR-021 and remains `RecoveryRequired`;
9. stale marker + missing DB fails closed without replacement creation;
10. recovery with no pager rollback need performs no unrelated Xenia authority mutation;
11. rollback-journal symlink/hard-link/type/owner/mode violations fail before pager recovery;
12. authority/receipt/frontier auxiliary-column corruption tests fail closed;
13. semantic frontier replay proves exactly one mutation per non-genesis frontier and exact roots at every checkpoint;
14. verified clean close reruns complete local integrity before removing the unclean marker;
15. ADR-020 admission and `EffectArmed` C0-C10 qualification passes after pager recovery;
16. ADR-020 commit-in-flight SIGKILL races resolve only to fully absent or fully committed state;
17. the qualification evidence records exact Rust, kernel/filesystem/storage, lockfile, rusqlite revision, SQLite version/source ID, C0-C10 outcomes, commit-race outcomes, and reconstructed proof commitments;
18. governed recovery, authenticated issuance evidence, and external-anchor verification integrate without a bypass;
19. only then may the native-exec adapter consume V2 persistence proofs.
