# ADR-010: Privileged-operation store filesystem trust boundary

Status: Draft / required before SQLite security qualification

## Context

ADR-009 defines SQLite transaction and durability behavior, but a correct transaction engine cannot protect Xenia authority if an untrusted local principal can replace, redirect, delete, truncate, or race the database, rollback journal, unclean-writer marker, or containing directory.

The first experimental SQLite implementation does not yet fully enforce this filesystem trust contract. Therefore passing its SQL/unit tests is **not** sufficient to claim a security-qualified privileged-operation store.

This ADR deliberately follows the same philosophy as `xenia-secure-file`: filesystem identity and ownership are part of the security boundary, not deployment trivia.

## Decision

Before a SQLite receipt-store profile may enable privileged effects, its storage root must be a dedicated Xenia authority directory satisfying an explicit platform-specific trust check.

For the first Unix profile, qualification requires at least:

1. the authority directory is an actual directory, not a symlink;
2. every ancestor that is included in the named trust profile is checked according to that profile;
3. the authority directory has the expected owner identity;
4. group/other write access is forbidden; the initial reference profile should prefer owner-only `0700`;
5. the database is a regular file, not a symlink, device, FIFO, or socket;
6. the database has the expected owner identity and should be owner-only `0600`;
7. the unclean-writer marker is a regular owner-controlled file and should be `0600`;
8. the rollback journal may only be created inside the already-trusted authority directory;
9. unexpected hard-link count, owner change, type change, or permission widening is a fail-stop event;
10. the store must re-check security-relevant path identity at defined lifecycle boundaries rather than relying forever on one startup pathname check.

ACLs, capabilities, mount namespaces, network filesystems, container bind mounts, and platform-specific ownership semantics must be included in the deployment claim where they can change effective access. A simple Unix mode-bit check is not automatically sufficient on every system.

## Path construction

V1 should prefer:

```text
<trusted-xenia-state-root>/operation-store/<store-id>/
    operations.sqlite3
    operations.sqlite3-journal       # transient SQLite rollback journal
    operations.sqlite3.xenia-operation-store-open-v1
```

The authority directory is created/verified before SQLite opens the database.

The runtime must not accept an arbitrary operator-provided database pathname for a production privileged-effect profile without applying the same trust validation to that path and directory.

## Creation semantics

When creating a new authority directory/database/marker:

- use create-new / no-follow semantics where the platform offers them;
- set restrictive permissions at creation time rather than creating permissively and tightening later;
- synchronize the created file and containing directory according to the named durability profile;
- verify the resulting object identity/type/permissions after creation;
- fail closed on an already-existing object whose identity does not match the expected role.

## Open semantics

Opening an existing store must reject or enter `RecoveryRequired` on:

- symlink substitution;
- wrong object type;
- owner mismatch;
- permission widening outside the allowed profile;
- unexpected hard links when the platform profile forbids them;
- authority directory trust failure;
- marker type/ownership mismatch;
- database/store identity mismatch.

The exact distinction between hard rejection and inspect-only recovery is implementation-specific, but neither path enables privileged mutations.

## SQLite auxiliary files

Rollback journal mode still creates an auxiliary `-journal` file. The security claim therefore includes the directory in which SQLite creates that file, not only `operations.sqlite3` itself.

The directory must be trusted strongly enough that an attacker cannot pre-place or replace the journal path, redirect it, or mutate it while SQLite believes it owns the store.

WAL is not used by ADR-009 V1, but a future WAL profile must explicitly add `-wal` and `-shm` to its persistent trust/backup model.

## Unclean-writer marker

The marker is a security object, not a convenience flag.

A pre-existing marker must be inspected under the same no-symlink/type/ownership/permission policy as the database. An attacker-controlled marker must never be opened, truncated, removed, or trusted merely because the pathname matches.

Marker removal during verified clean shutdown must verify that the object being removed is the marker object Xenia created/accepted, under the platform profile's available identity checks.

## Owner identity

The production Unix implementation should compare filesystem ownership to the effective process/service identity using a safe platform abstraction rather than shelling out or trusting environment variables.

Running as root does not exempt a file from ownership/type/permission checks. A root daemon still needs an explicit policy for which service identity owns the authority store.

## Runtime identity changes

If Xenia starts privileged and drops privileges, the authority-store ownership policy must define which identity opens, writes, and validates the store. Privilege transitions must not create a second ambient authority path around the receipt-store capability model.

## Recovery and restore

A restored database that passes SQL integrity but fails filesystem trust remains unusable for privileged effects.

Filesystem trust verification and anti-rollback frontier verification are independent gates:

```text
SQLite structural integrity
        AND
filesystem/path ownership trust
        AND
receipt/admission semantic integrity
        AND
frontier/anchor anti-rollback integrity
        -> eligible for governed recovery
```

None of these alone implies the others.

## Conformance tests

The first Unix backend must add negative tests for at least:

- database path is a symlink;
- authority directory is a symlink;
- database is world/group writable;
- authority directory is writable outside the allowed owner profile;
- marker is a symlink;
- marker has widened permissions;
- database/marker object type is wrong;
- store object is replaced between validation and use where the platform API can model the race;
- unexpected hard link where the profile forbids it.

Where a race cannot be eliminated with path-based APIs, the implementation should move toward directory/file-descriptor-relative operations (`openat`/`openat2`-style or equivalent safe abstractions) rather than papering over TOCTOU with repeated pathname checks.

## Claim boundary

Until this ADR is implemented and qualified, #185 is correctly described as an **experimental transaction/durability backend**, not a complete local-adversary-resistant privileged-operation store.

## Non-goals

This ADR does not define Windows ACL semantics, macOS sandbox semantics, container volume policy, TPM sealing, remote witnesses, or network filesystems. Each requires its own named profile before inclusion in the security claim.
