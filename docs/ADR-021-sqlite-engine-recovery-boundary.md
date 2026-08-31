# ADR-021: SQLite engine recovery boundary

Status: draft candidate

## Context

The SQLite V2 store uses rollback-journal mode (`journal_mode=DELETE`). ADR-019 originally required every unclean lifecycle to reopen the database strictly read-only before Xenia governed recovery.

That rule is too strong for a real mid-transaction crash.

SQLite calls a rollback journal **hot** when it contains the state required to undo an interrupted transaction. Before SQLite can safely read the database, it may need to obtain an exclusive lock, copy original pages from the hot journal back into the database, synchronize those writes, and remove/truncate the journal. A database opened read-only cannot perform that rollback and may fail with `SQLITE_READONLY_ROLLBACK`.

Therefore two different notions of recovery must remain separate:

1. **SQLite engine crash recovery**: pager-level rollback that restores the last SQLite-committed database image after an interrupted transaction; and
2. **Xenia governed authority recovery**: ADR-014 assessment/approval/epoch logic that may eventually decide whether privileged authority can resume.

Treating the first as if it were the second would make crash recovery impossible. Treating the second as automatic SQLite cleanup would be unsafe.

A second issue is security-critical. The V2 crate originally used `rusqlite 0.39.0` with its bundled SQLite 3.51.3. In June 2026 SQLite fixed a crafted rollback-journal issue in which a malicious journal could cause deletion of an arbitrary file through a forged super-journal pathname. The V2 recovery path intentionally consumes rollback journals, so the recovery profile must pin SQLite source that contains that fix.

## Decision

Define a two-phase unclean-lifecycle open for `sqlite-delete-extra-nofollow-v2`.

### Phase A: SQLite engine recovery

Phase A exists only to make the SQLite database represent one complete previously committed state.

It is not an Xenia authority mutation.

When the Xenia unclean-writer marker already exists:

1. the fixed authority root must pass the Linux profile checks;
2. the main database must already exist and pass the exact persistent-leaf checks;
3. any adjacent fixed rollback-journal leaf that exists must pass the journal trust checks below;
4. the runtime must prove it is using the exact qualified SQLite source profile;
5. if engine recovery may be required, open the **existing** main database with:
   - `SQLITE_OPEN_READ_WRITE`;
   - `SQLITE_OPEN_NO_MUTEX`;
   - `SQLITE_OPEN_NOFOLLOW`;
   - **no `SQLITE_OPEN_CREATE`**;
   - no URI/VFS override supplied by the caller;
6. set only a zero/finite busy timeout needed by the local single-owner profile;
7. execute a read that forces SQLite to establish a readable pager state, thereby allowing SQLite itself to detect and roll back a hot journal if one exists;
8. perform no Xenia schema write, admission, receipt append, migration, grant consumption, frontier append, pragma that changes journal/synchronous mode, marker change, or clean-close ceremony;
9. close the bootstrap connection;
10. re-verify the main database leaf and any surviving rollback-journal leaf.

If any step is ambiguous or fails, the store remains fail-stopped and no Xenia authority API is exposed.

### Phase B: Xenia recovery inspection

After Phase A succeeds, reopen the stabilized database:

```text
SQLITE_OPEN_READ_ONLY
| SQLITE_OPEN_NO_MUTEX
| SQLITE_OPEN_NOFOLLOW
```

and expose it only as `RecoveryRequired`.

Phase B then verifies:

- exact store metadata / epoch binding;
- SQLite integrity;
- durable authority records;
- receipt chains;
- complete frontier hashes;
- semantic frontier replay;
- mutation/frontier cardinality;
- any other local checks required by ADR-019.

Phase B does **not**:

- clear the unclean-writer marker;
- make the store `Healthy`;
- append a recovery receipt;
- consume or restore a grant slot;
- arm an effect;
- advance an authority epoch;
- claim external anti-rollback continuity.

Those decisions remain governed by ADR-014.

## Why pager rollback is not governed authority recovery

The security invariant is:

> SQLite engine recovery may remove an **uncommitted** transaction from the physical database. It must never create a new Xenia-authoritative transaction.

For rollback-journal mode, successful pager recovery canonicalizes the file to the last SQLite-committed state. The resulting state is then subjected to Xenia's independent semantic integrity checks.

This means a C0-C8 crash may legitimately cause the database/journal bytes to change during Phase A even though the target Xenia transaction remains semantically absent.

The claim is semantic, not byte-identical:

```text
interrupted physical SQLite state
        |
        v
SQLite pager rollback only
        |
        v
one complete prior committed DB image
        |
        v
READ_ONLY Xenia RecoveryRequired inspection
```

## Rollback-journal trust

The only rollback journal recognized by this profile is the exact sibling path:

```text
<fixed database path>-journal
```

No caller-supplied journal path is accepted.

If that leaf exists before or after Phase A, the local Linux profile requires it to be:

- a regular non-symlink file;
- owned by the expected service uid;
- owner-only under the qualified umask/profile;
- single-link (`nlink == 1`);
- located inside the already trusted `0700` authority root.

A leaf that violates those rules is not handed to SQLite recovery.

The first Linux claim already excludes compromise by another process running as the exact service uid. A future higher-assurance profile may replace pathname-based auxiliary-file handling with a descriptor-rooted custom VFS or a separate authority process.

### Journal presence does not imply hotness

The runtime must not implement its own partial parser and decide that `-journal` presence means “hot”. SQLite owns hot-journal classification.

A journal may exist but not be hot, depending on its header/state and the selected locking/journal behavior. The bootstrap connection lets the qualified SQLite pager make that determination.

## SQLite source security gate

Hot-journal recovery is disabled unless the SQLite source used by this V2 profile contains the 2026-06-24 crafted-journal fix.

For the first qualification lineage, pin the exact rusqlite Git revision:

```text
a8f0a07bf65b28c05fa54b260d39707368ad9ed3
```

whose bundled SQLite header identifies:

```text
SQLITE_VERSION   3.53.4
SQLITE_SOURCE_ID 2026-07-24 19:02:57
                 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc
```

This is intentionally an **exact source profile**, not merely `SQLite >= 3.53.3`.

The qualification workflow must record and assert both runtime:

- `sqlite_version()`; and
- `sqlite_source_id()`.

A dependency resolution that produces a different SQLite source is a new evidence lineage requiring explicit review/requalification.

## No `ATTACH` / super-journal requirement

The V2 operation store is a single-database authority store and does not use SQLite `ATTACH` for its security transaction.

Therefore Xenia has no legitimate need to create a multi-database super-journal in this profile. The bundled SQLite source is nevertheless required to include the upstream crafted-journal fix because recovery consumes potentially unclean journal bytes before Xenia can semantically inspect the database.

Future use of `ATTACH` would change the crash/recovery threat model and requires a new store profile.

## Recovery concurrency

Only one process may perform Phase A for a given authority store at a time.

The unclean marker is retained throughout. Competing recovery attempts must fail/busy rather than both treating themselves as authority restorers.

Phase A may take the locks SQLite requires for pager recovery. It must not use those locks as evidence that Xenia governed recovery has completed.

## Filesystem changes permitted during Phase A

The allowed mutation set is narrowly bounded to changes made by the qualified SQLite pager while restoring its own interrupted rollback-journal transaction:

- restoring database pages from the rollback journal;
- truncating the database back to its pre-transaction size when required;
- synchronizing the restored database;
- deleting/truncating/neutralizing the rollback journal according to the qualified journal mode.

No other persistent Xenia file is intentionally mutated.

The unclean-writer marker must survive unchanged.

## Crash qualification consequences

ADR-020 C0-C10 is interpreted **after Phase A canonicalization**.

For admission:

- C0-C8 deterministic abort points must recover to the fully absent target admission and the prior frontier;
- C9/C10 must recover the exact fully committed admission/frontier and reconstruct its proof;
- a commit-in-flight SIGKILL race may recover either fully absent or fully committed, never partial.

For `EffectArmed`:

- C0-C8 must preserve the already committed admission baseline while the target `EffectArmed` event/frontier is absent;
- C9/C10 must recover the exact committed event/frontier and reconstruct its proof;
- commit-in-flight may settle absent or committed, never partial.

Raw database byte equality is not required when a hot journal was rolled back. Semantic equality to a valid previously committed state is required.

## Recovery qualification tests

The V2 gate must include at least:

1. stale marker + no rollback journal -> no SQLite engine mutation is needed; Phase B opens read-only;
2. deterministic crash after primary transaction writes -> Phase A rolls back as needed and target mutation is absent;
3. deterministic crash after frontier/store-pointer writes but before commit -> Phase A restores the prior complete state;
4. C9/C10 lost-ack -> exact committed state/proof survives;
5. commit-in-flight SIGKILL -> only absent or committed outcomes;
6. untrusted/symlink/hard-linked rollback-journal leaf -> fail before bootstrap;
7. marker survives every Phase A outcome;
8. Phase B is read-only and cannot admit/arm;
9. exact SQLite version/source ID matches the qualified source;
10. full Xenia local semantic integrity passes after successful Phase A.

## Failure classification

New failures should remain distinguishable, for example:

- `RecoveryDatabaseMissing`;
- `RecoveryJournalNotTrusted`;
- `SQLiteSourceProfileMismatch`;
- `EngineRecoveryFailed`;
- `RecoveryJournalStateChanged` where a filesystem race is detected;
- existing `RecoveryRequired` health for successfully stabilized but not governed-resumed stores.

No engine-recovery error is proof that an interrupted Xenia transaction committed or did not commit. If durable state cannot be classified by reread after SQLite recovery, quarantine is the safe outcome.

## Anti-rollback boundary

Phase A only resolves an interrupted local SQLite transaction. It cannot detect restoration of an older but internally valid database image.

External frontier anchoring remains mandatory for the corresponding restore-safe authority claim.

## Non-goals

ADR-021 does not:

- clear `RecoveryRequired`;
- implement ADR-014 approval/recovery mutation;
- authorize a retry;
- infer that an external effect occurred;
- make persisted grant bytes self-authenticating;
- protect against root/kernel or same-service-uid compromise;
- qualify WAL mode;
- qualify SQLite `ATTACH`/multi-database transactions;
- implement a custom VFS.

## Promotion gate

The SQLite V2 store cannot gate real privileged effects until:

1. the exact post-fix SQLite source profile is pinned and asserted;
2. journal-leaf trust checks pass;
3. Phase A handles real hot journals without granting Xenia authority;
4. Phase B reopens only as read-only `RecoveryRequired`;
5. ADR-020 C0-C10 and commit-in-flight qualification pass through this two-phase recovery path;
6. governed recovery and external anti-rollback checks remain separate and fail closed.
