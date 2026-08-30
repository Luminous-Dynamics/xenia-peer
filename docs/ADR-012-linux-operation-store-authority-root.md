# ADR-012: Linux authority-root profile for the privileged-operation SQLite store

Status: Draft

Profile: `linux-systemd-state-root-v1`

## Context

ADR-009 defines a conservative SQLite transaction/durability profile. ADR-010 and issue #186 identify a separate filesystem-trust problem: database correctness is insufficient if an untrusted actor can redirect or replace the pathname used for the database, rollback journal, or unclean-writer marker.

ADR-011 further sharpens the claim boundary. Component-wise descriptor traversal can verify and retain a trusted directory descriptor, but a stock SQLite VFS subsequently opens database and journal files by pathname. A one-time path verification therefore does not magically make SQLite descriptor-relative.

The first deployable Linux profile should avoid a custom SQLite VFS until the simpler operating-system ownership model has been qualified.

## Decision

### 1. Reference deployment root

The first Linux profile places the store below a system-manager-controlled state path:

```text
/var/lib/xenia/operation-store/
    operations.sqlite3
    operations.sqlite3-journal   [transient; SQLite-owned]
    operations.sqlite3.xenia-operation-store-open-v1
```

The exact database and marker names are fixed single path components. Callers may not supply arbitrary nested paths beneath the authority root.

### 2. Static dedicated service identity for V1

V1 uses a statically provisioned dedicated service user/group, for example `xenia:xenia`.

The reference systemd shape is:

```ini
[Service]
User=xenia
Group=xenia
StateDirectory=xenia/operation-store
StateDirectoryMode=0700
UMask=0077
```

For system services, `StateDirectory=` is created below `/var/lib`; systemd owns the directory lifecycle and makes the innermost configured state directory owned by the configured service identity. `StateDirectoryMode=0700` fixes the innermost mode, while `UMask=0077` makes newly created ordinary files owner-only by default.

V1 deliberately does **not** use `DynamicUser=`. Current systemd implementations may place dynamic-user state under `/var/lib/private` and expose another path using namespace/mount/symlink machinery. That can be a good security mechanism, but it changes the pathname/ownership model ADR-011 is trying to qualify. A dynamic-user deployment needs its own explicit profile rather than being silently treated as equivalent.

### 3. Authority-root ancestry requirement

Before privileged operation-store mutation can become healthy, startup must establish that:

- the configured authority root is the exact deployment-approved path;
- every pathname component is traversed without following symlinks;
- `..` is rejected;
- the final authority root is owned by the current service uid;
- the final authority root is mode `0700`;
- no untrusted uid can rename or create entries in the authority root;
- the parent path from the system-managed anchor to the authority root is not writable by an untrusted local uid.

The component-walk semantics defined by ADR-011 are the preferred reusable verifier for the no-symlink/final-owner portion. The deployment profile supplies the stronger ancestor-mutability argument that a descriptor-only preflight cannot supply to a later path-based SQLite reopen.

### 4. SQLite main-file no-follow

The SQLite connection must add `SQLITE_OPEN_NOFOLLOW` to the existing V1 open flags.

The intended main-file flags therefore include:

```text
SQLITE_OPEN_READ_WRITE
SQLITE_OPEN_CREATE
SQLITE_OPEN_NO_MUTEX
SQLITE_OPEN_NOFOLLOW
```

`SQLITE_OPEN_NOFOLLOW` protects the main database filename from being a symbolic link. It does not replace the authority-root ancestry requirement and should not be described as doing so.

### 5. Leaf-file policy

Before opening an existing authority store, the runtime should fail closed if the fixed database or marker leaf is an unexpected filesystem object.

For the V1 local-filesystem profile:

- database, when present: regular file, current uid, owner-only effective permissions, no unexpected hard-link multiplicity;
- unclean-writer marker, when present: regular file, current uid, owner-only effective permissions, no unexpected hard-link multiplicity;
- authority root: directory, current uid, `0700`;
- database and rollback journal remain in the same authority root;
- no caller-controlled SQLite URI parameters, VFS name, path suffix, or alternate journal location are accepted.

SQLite creates/removes the rollback journal as part of its own transaction protocol. Other local uids cannot preplant or swap the journal name when the containing authority directory is `0700`; compromise of another process running under the same service uid remains outside this V1 local-account boundary.

### 6. Local filesystem only

`linux-systemd-state-root-v1` is not valid on an arbitrary network or userspace filesystem.

Qualification must name the OS/kernel, SQLite build, filesystem, mount options, and storage profile used for the C0-C10 crash tests. NFS, CIFS/SMB, distributed filesystems, unusual FUSE filesystems, and removable/network-backed state require separate qualification.

### 7. Service hardening is additive, not part of SQLite correctness

Deployments should consider normal systemd sandboxing such as `NoNewPrivileges=yes`, `ProtectSystem=strict`, and limiting writable paths to managed state directories when compatible with the rest of the Xenia daemon.

Those controls reduce blast radius but do not substitute for database integrity, operation-receipt semantics, or anti-rollback anchoring.

### 8. Backup/restore remains governed by ADR-007

A perfectly protected `/var/lib/xenia/operation-store` can still be restored from an old snapshot. Filesystem ownership does not prevent authority rollback.

Therefore the at-most-once claim still requires either:

- verification against an externally retained newer `OperationStoreFrontierAnchorV1`, or
- a separately governed new store generation with old authority invalidated.

## Why not a custom SQLite VFS first?

SQLite's VFS interface can provide a stronger descriptor-rooted design because the VFS controls `xFullPathname`, `xOpen`, journal opens, access checks, deletes, and related file operations. It is also a substantially larger native-code/security surface and would need independent crash, locking, and cross-platform review.

For the first low-write local operation store, a system-manager-owned static service root plus SQLite's own no-follow flag is simpler to reason about and test. A custom descriptor-rooted VFS remains a possible higher-assurance future profile, not a prerequisite for proving the initial local deployment.

## High-assurance future split

A later profile may run the receipt store as a separate local authority process with exclusive filesystem ownership and expose only a typed Unix-domain operation-admission/receipt API to the Xenia daemon. That could reduce the executor's direct ability to mutate evidence state, but it introduces a new authenticated local IPC boundary and is intentionally deferred until the single-process semantics are qualified.

## Qualification gates

Before this deployment profile can gate real native exec, tests must demonstrate at least:

1. authority-root component symlink rejection;
2. final authority-root exact uid + `0700` enforcement;
3. database-leaf symlink rejection through `SQLITE_OPEN_NOFOLLOW`;
4. marker symlink/non-regular-file rejection;
5. owner/mode/hard-link mismatch rejection for persistent leaves;
6. another local uid cannot create/rename entries in the authority root;
7. live competing writer remains distinguishable from stale unclean lifecycle;
8. crash-recovery behavior under the ADR-007 C0-C10 matrix;
9. filesystem/storage profile is recorded with the evidence;
10. restored-old-store detection against the anti-rollback frontier/anchor.

## Claim boundary

When all of the above gates are satisfied, Xenia may claim that the named Linux deployment protects its local SQLite authority store against pathname substitution by other unprivileged local accounts within the qualified filesystem profile.

It still does not claim protection against:

- kernel/root compromise;
- compromise of another process running as the exact same service uid;
- malicious storage firmware;
- rollback without an external frontier anchor;
- arbitrary network filesystems;
- generic exactly-once external effects.
