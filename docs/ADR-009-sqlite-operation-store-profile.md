# ADR-009: Conservative SQLite privileged-operation store profile

Status: Draft / experimental reference backend

## Context

ADR-007 requires a concrete receipt store to preserve atomic operation admission, unique grant-use reservation, receipt compare-and-append, fail-stop durability health, crash recovery, and anti-rollback frontier history before any privileged adapter is enabled.

SQLite is a strong candidate for the first local backend, but the security claim must be narrower than "SQLite is ACID". Durability depends on journal mode, synchronous mode, the SQLite VFS, filesystem, storage firmware, and whether backup/restore preserves every required file.

## Decision

The first experimental Xenia profile is `sqlite-delete-extra-v1`.

It uses:

- bundled SQLite through a pinned rusqlite dependency;
- `PRAGMA journal_mode=DELETE`;
- `PRAGMA synchronous=EXTRA`;
- `PRAGMA foreign_keys=ON`;
- one long-lived writer connection;
- exclusive SQLite locking for the authority-store process;
- immediate write transactions;
- strict tables and explicit unique constraints;
- an unclean-writer marker retained outside SQLite transaction state;
- no network filesystems in the qualified V1 deployment profile;
- no automatic recovery from a stale/unclean marker;
- no destructive frontier pruning.

The reference implementation is experimental until the ADR-007 crash matrix passes on a named platform/filesystem/storage profile.

## Why rollback journal + EXTRA first

SQLite documents that `synchronous=EXTRA` adds a directory sync after rollback-journal removal in `DELETE` mode and provides stronger power-loss durability than `FULL` rollback mode on filesystems where a just-committed transaction could otherwise disappear.

WAL with `synchronous=FULL` is also ACID, but WAL introduces additional persistent `-wal` and `-shm` state and requires backups/copies to preserve WAL state correctly. Xenia's first receipt store is low-write and security-critical, so the simpler rollback-journal persistence envelope is preferable even if it sacrifices write concurrency.

This is not a claim that rollback journal is universally safer than WAL. The profile is chosen to minimize the number of persistent files and backup semantics that the first Xenia qualification must reason about.

## SQLite profile verification

Open must verify rather than merely request:

- returned journal mode is `delete`;
- synchronous mode reports `EXTRA` (`3`);
- foreign keys are enabled;
- schema version is exact;
- store id and store schema digest are non-zero and match the expected authority domain.

If the runtime cannot establish the exact profile, privileged writes remain disabled.

## Atomic admission schema

The durable schema must enforce at least:

```text
PRIMARY KEY(operation_id)
UNIQUE(grant_digest, use_index)
UNIQUE(admission_sequence)
```

The same immediate transaction must:

1. classify exact lost-ack duplicate vs conflict;
2. verify the grant-use slot is unused;
3. verify `admission_sequence == next_admission_sequence`;
4. insert immutable admission;
5. reserve the grant-use slot through the unique constraint;
6. advance the metadata sequence;
7. commit.

A commit acknowledgement error is treated as durability uncertainty, not as permission to retry on another operation id.

## Receipt storage

Receipt history is append-only. The backend stores every canonical receipt event, not only a mutable status row.

The durable key is:

```text
PRIMARY KEY(operation_id, event_index)
```

Each event also stores its exact event digest and canonical serialized bytes.

A write transaction must classify an exact already-current event as `DuplicateSame`; otherwise it requires the caller's expected predecessor to equal the durable head, validates the semantic transition, inserts the next event, and commits.

## Unclean-writer marker

SQLite transaction recovery cannot by itself tell Xenia whether the previous process exited at a security-sensitive point or whether the application observed an ambiguous commit error.

The first backend therefore uses a sidecar marker as a fail-stop signal:

- marker is created before privileged writes are enabled;
- marker is synchronized to storage under the qualified platform profile;
- normal process drop does **not** erase it;
- only explicit verified clean shutdown may erase it;
- if the marker already exists when a new process has obtained exclusive database ownership, the store opens `RecoveryRequired` and privileged writes remain disabled.

A future implementation may replace this marker with stronger platform primitives, but may not weaken the fail-stop semantics.

## Commit-error policy

Unexpected errors during a mutating transaction, including commit errors, transition the in-memory store to `DurabilityUncertain`.

The runtime must not infer from an error that the transaction definitely failed. The operation/store must be reconciled from durable state before authority advances again.

## Recovery policy

A store opened after an unclean writer is inspection-only until an explicit recovery procedure verifies:

- SQLite integrity;
- schema identity;
- immutable admission/index consistency;
- receipt chain validity;
- frontier chain validity;
- externally anchored frontier lineage when the deployment claims rollback protection;
- any `EffectArmed` operation outcome conservatively.

No V1 API silently flips `RecoveryRequired` back to `Healthy`.

## Backup and restore

A backup, filesystem snapshot, VM snapshot, or copied database is not automatically authoritative.

A restored store may resume privileged operation only when its local retained frontier is proven to contain the exact externally trusted anchor and valid descendants, or when a separately governed migration creates a fresh store generation.

## Platform claim

The initial experimental backend must not claim power-loss durability on every platform merely because SQLite returns success from `fsync`/VFS sync operations. Qualification is named by at least:

- OS/kernel;
- filesystem;
- mount options relevant to durability;
- SQLite/rusqlite build identity;
- storage class;
- crash/fault test evidence.

Network filesystems are out of scope for V1 unless separately qualified.

## Dependency choice

The experiment begins with `rusqlite = 0.39.0` plus `bundled` SQLite and proves Rust 1.94 compatibility in CI. This is intentionally not upgraded to the newest rusqlite release without re-running the MSRV and crash/durability qualification.

## Non-goals

This ADR does not:

- enable native exec;
- claim generic exactly-once target effects;
- provide distributed consensus;
- provide multi-host HA;
- replace the external anti-rollback anchor;
- make ordinary SQLite backups rollback-safe;
- qualify cloud/network filesystems.

## Exit gate

The SQLite backend remains experimental until it demonstrates behavioral equivalence to `xenia-operation-store-model` and passes ADR-007 C0-C10 crash/fault qualification on a named platform profile.
