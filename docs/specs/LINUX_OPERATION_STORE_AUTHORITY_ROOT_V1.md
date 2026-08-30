# Linux Privileged-Operation Store Authority Root V1

Profile: `linux-systemd-state-root-v1`

This specification is the deployment/fault-test companion to ADR-012. It defines what must be demonstrated before the experimental SQLite operation store may be treated as a trusted local authority store on Linux.

It does **not** enable receipt persistence or native exec.

## Reference layout

```text
/var/lib/xenia/operation-store/
├── operations.sqlite3
├── operations.sqlite3-journal                    # transient, SQLite-managed
└── operations.sqlite3.xenia-operation-store-open-v1
```

The runtime accepts the exact authority root and fixed leaf names for this profile. Arbitrary caller-supplied nested paths, SQLite URIs, VFS names, database suffixes, and alternate journal locations are outside V1.

## Reference service identity

V1 assumes a statically provisioned dedicated service account:

```text
user  = xenia
group = xenia
```

The account name itself is deployment metadata; the security invariant is that the daemon's effective uid is the exact owner uid of the final authority directory and persistent leaves.

`root` receives no ownership-trust exemption.

## Reference systemd fragment

```ini
[Service]
User=xenia
Group=xenia
StateDirectory=xenia/operation-store
StateDirectoryMode=0700
UMask=0077
```

Recommended additive hardening, subject to qualification with the rest of the daemon:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

The additive sandbox controls are not part of SQLite's transaction correctness. If one is incompatible with another Xenia function, it may be omitted only with the deployment evidence recording that difference.

V1 does not treat a `DynamicUser=` deployment as equivalent to this profile.

## SQLite open contract

The first production candidate derived from #185 must include:

```text
SQLITE_OPEN_READ_WRITE
SQLITE_OPEN_CREATE
SQLITE_OPEN_NO_MUTEX
SQLITE_OPEN_NOFOLLOW
```

The no-follow flag is a leaf defense for the main database filename. It does not replace component-wise authority-root verification.

## Authority-root invariants

Before the store can enter `Healthy`, the deployment/runtime combination must establish all of these:

| ID | Invariant |
|---|---|
| AR-01 | Authority root equals the deployment-approved path. |
| AR-02 | `..` or caller-selected path traversal cannot reach the store. |
| AR-03 | No traversed authority-root component is accepted through a symlink. |
| AR-04 | Final authority root is a directory. |
| AR-05 | Final authority root owner uid equals the daemon effective uid. |
| AR-06 | No uid-0/root ownership exemption exists in the Xenia trust decision. |
| AR-07 | Final authority root mode is exactly `0700` or a separately documented stricter equivalent. |
| AR-08 | Other unprivileged local uids cannot create, unlink, or rename entries in the authority root. |
| AR-09 | Database and rollback journal live in the same qualified authority root. |
| AR-10 | Store startup accepts no caller-controlled SQLite URI or VFS override. |

## Persistent leaf invariants

For each persistent leaf that exists at startup:

| ID | Invariant |
|---|---|
| LF-01 | Leaf is not a symlink. |
| LF-02 | Leaf is a regular file. |
| LF-03 | Leaf owner uid equals daemon effective uid. |
| LF-04 | Effective permissions expose no group/other access for the V1 profile. |
| LF-05 | Unexpected hard-link multiplicity is rejected. |
| LF-06 | Marker and database path are fixed single-component names. |

The SQLite rollback journal is transient and managed by SQLite. The containing `0700` authority root is the primary defense against another unprivileged uid preplanting or replacing that transient name.

## Negative qualification matrix

Every named Linux filesystem/storage profile must run the following tests before privileged effects are allowed behind the store.

| Test | Mutation/attack | Required result |
|---|---|---|
| LAR-01 | Replace an intermediate authority-root component with a symlink to a same-uid directory. | Startup refuses the authority root. |
| LAR-02 | Make the final authority root a symlink. | Startup refuses it. |
| LAR-03 | Supply a path containing `..`. | Configuration/runtime rejects it before SQLite open. |
| LAR-04 | Make authority root owner differ from daemon uid. | Store cannot become `Healthy`. |
| LAR-05 | Widen authority root to group/other writable. | Store refuses or safely retightens only under the explicitly qualified policy; no silent broad trust. |
| LAR-06 | Replace existing database leaf with a symlink. | SQLite/Xenia open fails closed. |
| LAR-07 | Replace marker with a symlink. | Startup fails closed; marker is not followed. |
| LAR-08 | Replace marker/database with directory/FIFO/socket/device. | Startup fails closed. |
| LAR-09 | Create extra hard link to persistent DB/marker where the profile forbids it. | Startup fails closed. |
| LAR-10 | Attempt create/rename/unlink from a different unprivileged uid. | Kernel/filesystem denies mutation. |
| LAR-11 | Try a SQLite URI, alternate VFS, or alternate journal location through public configuration. | No such input surface exists in V1. |
| LAR-12 | Start two writers. | Second live writer cannot enter `Healthy` or `RecoveryRequired` as though the first were dead. |
| LAR-13 | SIGKILL current writer. | Later owner obtains DB lock but sees `RecoveryRequired`. |
| LAR-14 | Restore an older otherwise-valid store snapshot while a newer external frontier anchor exists. | Rollback is detected; mutation remains disabled. |

## C0-C10 crash matrix binding

Passing the authority-root tests does not replace ADR-007 crash qualification.

The final local profile evidence must identify, for every C0-C10 crash point:

- kernel/OS build;
- architecture;
- SQLite version/build flags;
- rusqlite version;
- filesystem type;
- mount options relevant to durability;
- underlying storage profile;
- journal mode;
- synchronous mode;
- process kill/power-loss injection method;
- post-restart SQLite integrity result;
- operation admission/use-slot result;
- receipt head result once receipts exist;
- frontier/anchor result once anchors exist.

The profile may not generalize from one filesystem/storage combination to all Linux systems.

## Recovery admission gate

An unclean lifecycle can only become eligible for governed recovery after all applicable checks succeed:

```text
SQLite structural integrity
        AND
filesystem authority-root integrity
        AND
operation/admission semantic integrity
        AND
receipt-chain integrity            # once implemented
        AND
frontier/anchor anti-rollback integrity
```

Even then, recovery is an explicit governed transition. The store must not automatically reinterpret `RecoveryRequired` as `Healthy` merely because `PRAGMA integrity_check` returned `ok`.

## Evidence record

A qualification run should emit a machine-readable record containing at least:

```text
profile_id
service_uid/service_gid
approved_authority_root
root owner/mode/device/inode metadata
SQLite version
rusqlite version
journal mode
synchronous mode
filesystem + mount profile
kernel + architecture
store_id + generation
store_schema_digest
latest local frontier digest/sequence
external anchor digest/sequence, when required
LAR-01..LAR-14 outcomes
C0..C10 outcomes
```

Sensitive file contents, credentials, SQL rows, command stdout/stderr, and terminal content are not part of this evidence by default.

## Exit gate for receipt persistence

SQLite receipt CAS/frontier persistence may be developed while this profile is still draft, but the backend must not be promoted as a security-qualified effect gate until:

1. #187-style component-wise path semantics are integrated or equivalently enforced;
2. the database main-file open uses `SQLITE_OPEN_NOFOLLOW`;
3. persistent-leaf checks are implemented;
4. LAR-01..LAR-14 pass on the named profile;
5. ADR-007 C0-C10 tests pass;
6. anti-rollback behavior is verified for the deployment claim.

## Exit gate for native exec

Native exec remains disabled until all receipt-store gates above pass **and** the live capability/consent/effect-arm chain is integrated. This document is not an authorization to spawn processes.
