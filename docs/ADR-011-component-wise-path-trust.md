# ADR-011: Component-wise path trust for sensitive local state

Status: Draft

## Context

`xenia-secure-file` already protects sensitive leaf files with descriptor-relative access, exact-owner checks, owner-only permissions, atomic publication, and `O_NOFOLLOW`. During the privileged-operation receipt-store review, we identified a narrower ancestor-path gap: a one-shot `openat(CWD, full_parent_path, O_NOFOLLOW, ...)` only refuses a symlink in the trailing component on POSIX-style systems. Earlier pathname components may still contain symlinks.

That means a claim such as “every parent path component is no-follow protected” requires component-wise traversal or a separately qualified platform primitive.

The same review also exposed a second boundary: a descriptor-safe validation step cannot make a later unrelated pathname reopen safe. This matters for path-based libraries such as the stock SQLite VFS.

## Decision

### 1. Portable Unix baseline: descriptor chain

For security-sensitive Xenia directories, V1 walks the path one component at a time:

1. start from `/` for an absolute path or the current-directory descriptor for a relative path;
2. reject `..`;
3. ignore `.` and the root marker;
4. open each normal component relative to the already-open directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`;
5. when an allowed component is missing, create it with `mkdirat(..., 0700)`, sync the parent directory, then reopen it through the same no-follow path;
6. refuse symlinks and non-directory components;
7. require the final private directory to be owned by the current uid, with no privilege/root exemption;
8. tighten the final private directory to `0700` through the verified descriptor;
9. retain the final descriptor as the authority anchor for subsequent sensitive leaf operations.

The reference implementation is the standalone `contracts/xenia-path-trust` crate while this rule is qualified independently of the production workspace.

### 2. Ownership scope

V1 does **not** require every ancestor such as `/`, `/home`, or `/tmp` to be owned by the process uid. That would reject valid platform layouts and would conflate no-symlink path binding with deployment policy.

Instead:

- every traversed component must be a real directory, not a symlink;
- the final private directory must have exact current-uid ownership;
- callers that need stronger ancestor mutability guarantees must additionally choose a deployment-controlled authority root.

### 3. Descriptor-relative continuation is part of the guarantee

The component-walk guarantee continues only while security-sensitive operations remain relative to the returned verified directory descriptor.

This is safe in shape:

```text
component walk
    -> verified directory fd
       -> openat/create/link/rename children relative to that fd
```

This is **not** made race-free merely by a prior validation:

```text
component walk(path)
    -> discard fd
       -> unrelated_library.open(path)
```

The second operation resolves the pathname again and needs its own trust argument.

### 4. SQLite consequence

The experimental privileged-operation SQLite store uses a conventional path-based SQLite VFS. Therefore `xenia-path-trust` alone is not sufficient to claim that SQLite database/journal opens are descriptor-bound.

Before the SQLite store may gate a real privileged effect, it must use one of these separately qualified strategies:

- a deployment-controlled authority root whose path ancestry cannot be replaced by an untrusted actor during the authority lifecycle;
- a platform-specific descriptor-rooted/VFS strategy whose database and transient journal files are proven to remain under the verified directory;
- another design with equivalent or stronger path-binding evidence.

A preflight call to `xenia-path-trust` followed by ordinary `Connection::open(path)` is not sufficient evidence by itself.

### 5. Linux specialization may come later

Linux `openat2` with `RESOLVE_NO_SYMLINKS` can reject symlink resolution in all path components and may become a qualified specialization. V1 retains the component-walk algorithm as the auditable portable Unix baseline rather than making Linux-specific behavior the protocol contract.

## Security properties

The V1 component walk is intended to establish:

- no symlink is followed in any traversed path component;
- no `..` traversal escapes the descriptor chain;
- creation of missing directories is descriptor-relative;
- the final directory descriptor refers to the directory actually verified;
- later rename/replacement of the pathname does not retarget operations that continue through that descriptor;
- the final sensitive directory is exact-current-uid owned and `0700`;
- uid 0 receives no ownership-trust exemption.

## Non-goals

ADR-011 does not claim:

- protection against a fully compromised same-uid process;
- protection after a consumer discards the descriptor and reopens an untrusted pathname;
- SQLite VFS security by itself;
- network-filesystem safety;
- mount-namespace or bind-mount immutability;
- anti-rollback protection;
- Windows reparse-point semantics (those remain governed by the Windows secure-file implementation and require separate qualification for any new shared primitive).

## Qualification requirements

At minimum, the component-walk implementation must test:

- ordinary nested creation;
- final mode tightening to `0700`;
- intermediate symlink rejection, including a symlink targeting a same-uid directory;
- final symlink rejection;
- `..` rejection;
- final exact-uid policy with no root exception;
- descriptor stability after the original pathname is renamed;
- descriptor-relative leaf `O_NOFOLLOW` behavior.

Before production promotion, retain the exact dependency lock and run the contract at Xenia's MSRV in addition to the pinned current toolchain.
