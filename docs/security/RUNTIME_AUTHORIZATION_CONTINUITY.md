# Runtime authorization continuity

Status: implemented by architecture hardening series eight.

## Invariant

An authenticated operator approval is not complete merely because the consent
service accepted a signature. The exact grant, its restrictive host-local
lifetime, and its eventual terminal reason must remain visible in the separate
M1 runtime evidence chain.

The continuity path is:

```text
ConsentOfferV2
  -> authenticated operator approval
  -> consent ledger action id + offer digest
  -> ConsentApprovalReceipt
  -> M1 authorization binding v2
  -> privileged runtime gates
  -> authority termination binding
```

## Lease continuity

`xenia-runtime-authorization-binding-v2` adds
`lease_deadline_unix_secs` to the signed runtime binding. Zero means no local
lease. A non-zero value is the absolute Unix second derived when approval was
durably committed.

Every authenticated privileged operation and transcript-bound evidence export
checks that deadline. Rehydration parses the same signed field, so restoring an
M1 ledger cannot silently turn a time-bounded grant into an unlimited one.
Historical v1 authorization bindings remain readable as unlimited because they
never committed to a deadline; operators requiring strict lease continuity
should begin a new session rather than restore one of those historical grants.

## Terminal-reason continuity

The consent authority publishes one of these terminal states:

- `denied`;
- `revoked`;
- `failed`;
- `offer_expired`;
- `authorization_lease_expired`.

The runtime first applies the corresponding fail-closed M1 transition and then
appends `consent.lifecycle_termination` using the
`xenia-runtime-authority-termination-v1` scope. The record commits to the stable
terminal state and the same immutable six-bit permission descriptor used by the
offer and grant.

Rehydration requires the terminal reason to agree with the immediately replayed
M1 state. Duplicate or contradictory authority-termination records are refused.
A closed lifecycle watch channel is treated as `failed`, never as continued
approval.

## Persistence boundaries

The live consent ledger and M1 runtime transcript use separate magic-tagged v1
persistence envelopes. Both include an entry count and chain head, impose hard
file and entry limits, reject oversized declared bincode vectors before
allocation, and migrate historical bare `Vec<LedgerEntry>` files on the next
successful write. Writes use owner-only same-directory temporary files, file
`fsync`, atomic rename, and directory `fsync` on Unix.

These envelopes detect corruption, torn generations, metadata inconsistency, and
unsupported local schemas. They do not by themselves detect replacement by a
complete older valid generation. Detecting valid-prefix rollback requires an
independently retained signed ledger checkpoint, as described by
`xenia_ledger::LedgerCheckpoint` and exposed at `/v1/audit/checkpoint`.

## Non-claims

- A host attacker controlling the signing keys can create new valid evidence.
- Restoring a complete older state directory can roll back the ledger and its
  local envelope together; external checkpoint retention is the rollback anchor.
- Historical authorization-binding v1 records cannot prove a lease that was
  never signed into them.
- A termination record proves what the daemon recorded, not that every external
  device immediately erased already received plaintext or media.
