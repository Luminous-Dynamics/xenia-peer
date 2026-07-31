# ADR-003: Filesystem trust contract for `xenia-secure-file`

**Status**: accepted
**Date**: 2026-07-29
**Deciders**: tstoltz
**Related**: PR #114 (agent HTTP correctness), PR #115 (atomic first-writer-wins
publish) -- the first two PRs in the same security-hardening sequence this
ADR is item 3 of. Item 4 (correct Unix ownership semantics + CI fixture)
and item 5 (real Windows ACL/reparse-point backend) both implement the
decisions recorded here; they are deliberately separate PRs.

## Context

`crates/xenia-secure-file` is the TOCTOU-safe file layer both
`apps/xenia-peer` and `apps/xenia-operator-agent` use for identity keys,
pairing tokens, and host-trust pins. An external review of that crate (and
the two PRs above) surfaced two problems that are really one question asked
twice:

1. **The Unix backend exempts `uid 0` from its ownership check.**
   `owner_check_should_apply(current_uid) = current_uid != 0`. The doc
   comment ties this directly to `apps/xenia-peer`'s network-chaos CI smoke
   test (`scripts/xenia-network-chaos-smoke.sh`): that test's daemon runs
   as root inside a network namespace (`sudo ip netns exec`), while its
   state directory is `mkdir -p`'d by the unprivileged CI runner user
   beforehand -- an owner mismatch the check would otherwise reject. The
   exemption exists to unblock that specific CI topology, not because
   trusting *any* root process's ambient filesystem state is actually
   correct on the merits.
2. **The non-Unix backend has no ownership/ACL/reparse-point hardening at
   all** -- plain `std::fs`, no equivalent of the Unix backend's `O_NOFOLLOW`
   + owner-uid check + descriptor-relative access. It was never designed
   against a stated contract; it's simply whatever `std::fs::OpenOptions`
   does by default.

Both are instances of the same missing artifact: this crate has an implicit,
undocumented, per-platform notion of "trustworthy owner" and "trustworthy
storage object," inferred from whatever the Unix implementation happened to
do first, rather than a contract designed once and implemented per platform
against it. This ADR is that contract. It does not implement anything --
PR items 4 and 5 do that, against the decisions recorded below.

## Decision

### 1. Trustworthy owner: the running process's own account, by default. No implicit privilege exemption.

The check is: **the file/directory's owner must equal the identity the
current process is actually running as.** This applies uniformly regardless
of what that identity is -- including root/uid 0 on Unix and an elevated
token on Windows. `owner_check_should_apply` returning `false` for uid 0 is
**removed**. A privileged process gets no special trust for state it didn't
create; the whole point of the check is that *ambient* state shouldn't be
trusted just because this process happens to be running with the
permissions to read anything.

### 2. Explicitly provisioned state from another account: opt-in only, never implicit.

There is a real, legitimate use case the old root exemption was informally
serving: a separate provisioning step (an installer, a systemd
`ExecStartPre=`, a packaging postinst) creates state under one account
before the long-running process -- possibly under a different account --
starts and needs to read it. That's a real deployment shape and this crate
should support it, but as an **explicit, caller-declared exception**, not an
implicit "trust every root process" rule that silently also covers
processes for which no such provisioning relationship exists.

Concretely: `load_or_create_secure_file` / `read_secure_file_if_exists` /
`secure_overwrite` gain no *default* extra trust. A caller who genuinely
needs to accept state provisioned under a different, known account passes
that expectation in explicitly (an `expected_owner: Owner` parameter or
equivalent -- exact shape is item 4/5's to design, not this ADR's), and the
check becomes "owned by the running identity OR by the one specific
declared owner" instead of "owned by the running identity, unless running
as root, in which case skip the check entirely." Every such exception is
then visible at the call site, not hidden in a platform-generic default.

### 3. Symlink / reparse-point policy: refuse, don't follow. Same on every platform.

Unix already does this correctly (`O_NOFOLLOW` on both the parent-directory
open and the leaf-file open; `open_secure_existing` also gives a clear
"is a symlink" error rather than a raw errno). The Windows implementation
(item 5) must provide the equivalent: open with
`FILE_FLAG_OPEN_REPARSE_POINT` and explicitly reject if the resulting
handle is a reparse point (symlink, junction, or any other reparse tag) --
not attempt to enumerate "acceptable" reparse types, refuse all of them.
A directory junction or symlink swapped into the parent path is exactly as
dangerous on Windows as a symlinked parent on Unix and gets exactly the
same answer: refused, not resolved.

### 4. Permissions / ACLs: owner-only, set at creation, never loosened silently.

Unix: `0600` files / `0700` directories, set via the `Mode` passed to the
creating `openat` call (not a separate `chmod` after the fact), with a
defense-in-depth re-tighten on every subsequent open in case something
drifted. Windows must reach the equivalent end state -- a DACL granting
full control to the owner (the SID the process is running as) and nothing
to any broader principal (`Everyone`, `Authenticated Users`, `Users`,
`BUILTIN\Administrators` as a blanket grant) -- not merely "whatever the
parent directory's inherited ACL happens to be," which is what the current
plain-`std::fs` backend gets by default. Exact API (`SetNamedSecurityInfoW`
+ an explicit owner-only DACL, or `CreateFileW` with a `SECURITY_ATTRIBUTES`
carrying a pre-built descriptor) is item 5's implementation choice, not
this ADR's.

### 5. Atomic create and replace semantics: first-writer-wins, never silently clobbered.

Already decided and implemented for the Unix backend in PR #115: content is
written to a sibling temp file, `fsync`'d, then published via
link-then-unlink so a concurrent racer can never silently overwrite an
already-published value, and a losing racer reads back and returns the
winner's content. This ADR extends that as the standing contract for **any**
platform backend, present or future: `load_or_create_secure_file` must
never let the final path exist in a partially-written state, and must never
let two concurrent generators race to a silent clobber. Windows has an
equivalent non-replacing publish primitive (`CreateHardLinkW`, which -- like
POSIX `link()` -- fails if the destination already exists) that item 5
should use for the same purpose; `MoveFileEx` without
`MOVEFILE_REPLACE_EXISTING` is the nearest analogue to a plain `rename` and
should be avoided for the same reason `rename` was avoided on Unix.

### 6. Crash-durability: the data must be durable before the name that points to it exists.

`fsync` the temp file's data before publishing it (already true for both
backends' `overwrite`, now also true for the Unix `load_or_create` per
PR #115); `fsync`/flush the parent directory's own metadata after a
successful publish, so a crash immediately after the publish call can't
lose the directory entry even though the data it points to was already
durable. Windows lacks a direct analogue of "fsync a directory," so item 5
must document what durability guarantee (if any) it can actually make there
rather than silently omitting the step -- this is the one place platform
parity may not be fully achievable, and the honest answer is required, not
an unstated gap.

### 7. Behavior when running elevated: no special trust, full logging.

Per decision 1, elevation (root, or Windows "Run as Administrator" /
`LocalSystem`) grants no ownership-check exemption. It should, however,
be visible: when the crate is asked to trust a directory/file under an
explicitly-declared cross-account exception (decision 2) while running
elevated, that's a materially more consequential trust decision than the
same exception under a normal account, and should be logged (or otherwise
surfaced through whatever this project's structured logging already is)
rather than passing silently. Exact logging shape is an implementation
detail for item 4/5.

## Consequences

**Accepted:**

- `owner_check_should_apply`'s current test
  (`owner_check_is_skipped_only_for_root`) is now testing behavior this ADR
  removes; item 4 replaces it with a test of the *new*, uniform check plus
  a test of the explicit-exception path from decision 2.
- `scripts/xenia-network-chaos-smoke.sh` must stop relying on the removed
  exemption. Two options were on the table; item 4 should implement
  **dropping privileges before the daemon runs**, not chowning the fixture:
  `sudo ip netns exec "$DAEMON_NS"` is only needed to enter the network
  namespace (`setns()`, which requires `CAP_SYS_ADMIN`/root) -- the daemon
  process itself has no need to keep running as root afterward. Wrapping
  the daemon invocation in `setpriv --reuid="$(id -u)" --regid="$(id -g)"
  --clear-groups` drops to the invoking (unprivileged) user *before*
  `xenia-peer` execs, so its state directory is naturally owned by that
  same user with no chown step and no CI-specific carve-out in the crate
  itself. This is also the more correct fix on the merits, independent of
  this ADR: the daemon has no actual need for root privilege once it's
  inside the namespace, so it shouldn't have it.
- Any future caller that genuinely needs the cross-account provisioning
  case (decision 2) must say so explicitly at the call site. Today,
  neither `apps/xenia-peer` nor `apps/xenia-operator-agent` has such a
  case -- both create and read their own state under their own account --
  so in practice this ADR's decision 1 alone (no code depends on decision
  2's opt-in mechanism existing yet) closes the real gap; decision 2 exists
  so that if such a deployment shape shows up later, the crate has a
  principled place to put it instead of reaching for another blanket
  exemption.
- The non-Unix backend goes from "no contract, whatever `std::fs` does" to
  a stated target it currently fails to meet on decisions 3/4/5/6 -- this
  ADR makes that gap explicit and trackable (item 5) rather than implicit
  and easy to overlook.

**Deliberate non-consequences (out of scope for this ADR):**

- Exact Windows API choices (`SetNamedSecurityInfoW` vs. a
  `SECURITY_ATTRIBUTES`-at-creation approach; which `windows`/`windows-sys`
  crate surface to depend on) are item 5's implementation decision.
- The exact shape of the decision-2 "declared owner" parameter (a new
  public parameter on the existing functions vs. a new
  `load_or_create_secure_file_with_trusted_owner` variant vs. a builder) is
  item 4/5's implementation decision.
- This ADR does not change `secure_overwrite`'s or `read_secure_file_if_exists`'s
  existing atomicity properties (both already correct on Unix per the
  crate's original design) beyond the ownership-check and cross-platform
  parity changes above.

## References

- `crates/xenia-secure-file/src/lib.rs` -- the crate this ADR governs.
- PR #114 -- agent HTTP correctness (CORS-on-error, `Retry-After`, redacted
  secrets); PR #115 -- atomic first-writer-wins publish (decision 5 above).
- `scripts/xenia-network-chaos-smoke.sh` -- the CI topology that produced
  the original root exemption; `run_profile()`'s `state_dir` handling is
  what item 4 changes per the "Accepted" section above.
- `docs/security/XENIA_SECURITY_INVARIANTS.md` -- this repo's standing
  security-invariant catalogue; a future invariant covering "no implicit
  privilege-based trust exemption" would generalize decision 1 beyond this
  one crate, but is out of scope for this ADR.
