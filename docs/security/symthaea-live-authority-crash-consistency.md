# Symthaea Live Authority Crash-Consistency Model

Status: design and regression-test contract for the live D3A1 issuance path.

This document distinguishes durable facts from in-process coordination. A successful
signature alone is not a durable issuance outcome: the portable receipt is eligible
for delivery only after the issuance journal has retained the exact receipt bytes.

## State that must survive a crash

The live authority state is composed of:

- trusted operator policy and revocation source objects;
- the authority generation ledger and its effective-state commitment;
- the durable issuance journal, keyed by request nonce and binding digest;
- the process-wide authority owner lock.

The owner lock prevents a second cooperating daemon from admitting the same live
authority root while the first owner is active. It is not a substitute for filesystem
permissions or protection against a hostile process that can modify the trusted root.

## Required ordering

```text
authenticate request
    -> reserve nonce + binding digest durably
    -> acquire coherent live-authority snapshot barrier
    -> revalidate token, revocation, and key lineage
    -> construct and sign receipt from that snapshot
    -> retain exact receipt bytes as terminal Issued journal state
    -> release snapshot barrier
    -> deliver HTTP response
```

A receipt must not be returned to the caller before terminal journal retention succeeds.
The coherent snapshot barrier must remain held through receipt construction, signing,
and terminal journal retention. A copied snapshot retained after the barrier is released
is historical provenance, not a lease to issue against current authority state.

## Crash-cut matrix

| Cut point | Durable state on restart | Required behavior |
|---|---|---|
| Before nonce reservation | No journal entry for this attempt | A retry may begin as a new attempt, subject to normal authentication and current policy |
| After reservation, before snapshot | Nonterminal Reserved record | Recover as DeliveryUnknown; do not reuse the nonce to mint a second receipt |
| After snapshot, before signing | Nonterminal Reserved record | Recover as DeliveryUnknown; the snapshot is not independently reusable as a live issuance lease |
| After signing, before terminal journal write | Nonterminal Reserved record | Recover as DeliveryUnknown; do not assume a signature was delivered or mint again under that nonce |
| After durable Issued record, before HTTP response | Terminal Issued record with exact receipt bytes | Same nonce and binding returns the retained exact receipt; different binding is rejected |
| After durable Aborted record | Terminal Aborted record | Same nonce remains non-reusable; a later Issued transition is invalid |

A failure while writing a terminal journal record must not be treated as success.
If the journal cannot establish whether the terminal record reached durable storage,
the running process must fail closed; restart must parse the journal and resolve only
what the durable bytes prove.

## Authority-generation relationship

A receipt's signed generation and effective-policy commitment must come from one
coherent authority snapshot. A policy or revocation mutation must be serialized against
issuance, persisted before its new commitment is admitted, and followed by a durable
generation transition. A failure after in-memory semantic mutation must poison the
live authority process rather than allow issuance to continue from uncertain state.

The intended invariant is:

```text
receipt generation and commitment
    == the coherent authority version used for signing
```

This is a provenance statement, not a claim that a historically authentic receipt is
currently authorized. Consumers must separately define whether they require historical
signature validity, freshness, or current authorization, and enforce that policy at
their own acceptance boundary.

## Regression-test contract

The following behaviors should be tested at the narrowest deterministic seam available:

1. A request rejected before reservation leaves no nonce entry.
2. A reservation followed by simulated termination reopens as DeliveryUnknown.
3. A terminal Issued record replays byte-for-byte after reopen.
4. A terminal Aborted record cannot transition to Issued.
5. A nonce cannot be rebound to a different request digest.
6. Mutation cannot interleave between coherent snapshot acquisition and terminal
   receipt retention.
7. A generation/policy pair from one snapshot cannot be transplanted into another
   receipt.
8. A failure after semantic mutation poisons the live authority process.
9. A receipt is not exposed by the handler if terminal journal retention fails.
10. An authentic but stale receipt is distinguished from a currently authorized one
    by each downstream acceptance policy.

Existing crate-level tests cover journal restart/idempotency, unresolved reservations,
terminal transitions, nonce binding, and snapshot/provenance invariants. The daemon
package now also carries `apps/xenia-peer/tests/symthaea_crash_cuts.rs`, a cross-crate
regression matrix that reopens the real public journal boundary after Reserved, Issued,
and Aborted cuts. These tests do not by themselves prove every integrated HTTP-handler
crash cut. The integrated cases above remain explicit acceptance criteria until a
deterministic handler-level fault-injection seam exercises them.

## Filesystem assumptions and limits

The trusted-root design relies on a daemon-owned directory that is not group/world
writable, direct-child durable paths, no-follow opens for final path components,
stable identity checks on opened files, and (on Unix) a kernel lock held on the
trusted root directory inode itself. The root-directory lock avoids the
replaceable-child-lock-file problem: replacing a child pathname cannot transfer
ownership to another inode while the first owner remains alive. These checks reduce path substitution risk,
but final-component no-follow flags do not constrain every intermediate component.
A Linux-specific `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` implementation may
strengthen path resolution, but should be introduced only with platform-specific tests
and a clearly documented portability/fallback policy.

Atomic rename, file synchronization, and directory synchronization are distinct
properties. Durable replacement paths should preserve the ordering of writing and
syncing the temporary file, renaming it, and syncing the containing directory on
platforms where that operation is supported. Platform-specific behavior must not be
silently generalized to targets that have not been qualified.
