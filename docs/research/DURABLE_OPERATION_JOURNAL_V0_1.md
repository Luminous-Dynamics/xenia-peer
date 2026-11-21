# Durable Operation Receipt Journal for Live M1 Effects v0.1

**Status:** Implementation contract and adversarial recovery plan; no persistent journal is implemented here.  
**Tracking:** [#545](https://github.com/Luminous-Dynamics/xenia-peer/issues/545).  
**Depends on:** [#510](https://github.com/Luminous-Dynamics/xenia-peer/issues/510), [PR #531](https://github.com/Luminous-Dynamics/xenia-peer/pull/531), [PR #532](https://github.com/Luminous-Dynamics/xenia-peer/pull/532), [PR #542](https://github.com/Luminous-Dynamics/xenia-peer/pull/542), and [#450](https://github.com/Luminous-Dynamics/xenia-peer/issues/450).

## 1. Why another layer is required

The current live M1 work now distinguishes permission admission from synchronous input and clipboard API outcomes. Those events are held in `M1SessionMachine::audit()`. The consent ledger deliberately excludes operation events, as it should. Therefore the consent journal does not become a high-volume operation log.

However, the live M1 operation events are still process-local and disappear at process exit. PR #531 adds a bounded in-memory BLAKE3-linked operation ledger; PR #532 adds a process-local synchronous commit/revoke gate. Neither is yet the durable, crash-recoverable operation journal required for protected asynchronous effects.

The gap is not solved by simply serializing the current audit vector at shutdown: a process may crash between an external effect and the next audit append. The journal must be written ahead of dispatch and must recover uncertainty conservatively.

## 2. Target invariant

For every protected operation, the journal must be able to establish exactly one of these statements:

- **Rejected:** authority/consent was not admitted; no effect owner was invoked.
- **Admitted:** authority was admitted, but the effect owner was not invoked.
- **Attempted:** the effect owner was invoked; no result is yet known.
- **Committed:** the local effect owner crossed its documented commit point.
- **Observed:** an independent layer-specific observer supplied a valid observation receipt.
- **Unknown:** the owner may have acted, but the result is ambiguous.
- **Reconciled:** a stable receipt later resolved an UNKNOWN operation as not committed, locally committed, or observed.

No record may claim a stronger state than its actual producer establishes. UNKNOWN is a first-class durable recovery state, not an error message that disappears after reconnect.

## 3. Write-ahead state machine

For short synchronous effects, the required order is:

1. Acquire the local M1/effect owner serialization lock.
2. Check exact M1 consent and applicable authority/freshness gates.
3. Append and durably sync `AuthorizationAdmitted`.
4. Append and durably sync `EffectAttempted`.
5. Invoke the local effect owner.
6. Append and durably sync one of `EffectCommitted`, `EffectNotCommitted`, or `Unknown`.
7. Release the local lock.

The durable append before step 5 is essential. On recovery:
- a terminal rejection remains rejected;
- admission without attempt can be safely classified as not invoked if the writer guarantees the attempt record was synced before invocation;
- an Attempted record without a terminal owner result is UNKNOWN. The process may have crashed immediately before the call or immediately after the external effect; recovery cannot infer which.

Do not hold a local blocking mutex across asynchronous network I/O, an entire file transfer, remote acknowledgement, video encoding, or an unbounded operation. For those, write durable admission/attempt records, release local locks, and let the effect owner return an authenticated receipt. The remote receiver must independently enforce session/authority epoch and idempotency.

## 4. Stable operation identity

The operation ID must be stable across retry, reconnect and process restart. Random UUIDs are acceptable only when the generated ID is durably persisted before dispatch and reused by every retry. Prefer protocol-native monotonic identity where it exists.

Candidate derivations, domain-separated and bound to session fingerprint and key epoch:

| Lane | Stable identity material | Privacy rule |
|---|---|---|
| Input | session fingerprint, key epoch, inbound frame/event sequence, lane | Never include key codes, pointer coordinates or raw payload |
| Clipboard read/write | session fingerprint, key epoch, clipboard sequence/frame identity, direction | Never include clipboard text or a hash of low-entropy content |
| File transfer | session fingerprint, key epoch, transfer ID, direction, chunk offset/index | Use transfer/chunk metadata; never include file bytes |
| Video frame | session fingerprint, key epoch, frame ID, codec/frame class | Never include frame pixels or media payload |
| Audio | session fingerprint, key epoch, stream ID and sequence | Never include samples or transcript |
| Telemetry | session fingerprint, key epoch, batch/sequence identity and telemetry scope | Do not include values that disclose sensitive measurements |

The same operation ID plus identical context/sequence is idempotent. Reuse with different lane, direction, resource identity, epoch or sequence is a conflict and fails closed.

## 5. Operation context and event chain

The bounded model in PR #531 already defines:
- operation ID and monotonically increasing operation sequence;
- authenticated session fingerprint;
- exact M1 permission lane and direction;
- privacy-preserving resource digest;
- consent reference digest and policy digest;
- optional authority commitment digest and epoch;
- stage kind, clock domain/tick, evidence digest, previous hash and event hash.

Reuse that model rather than creating a parallel data structure. The event hash chain provides tamper-evident ordering; it does not prove an external statement is truthful and is not a signature.

The operation journal remains separate from human consent entries. The signed export manifest should bind:
- consent ledger root and export digest;
- operation ledger root, event count and sequence high-water;
- authenticated session transcript hash;
- policy/authority profile digest;
- schema version, key epoch and clock-domain metadata.

The verifier must reject missing, reordered, duplicate-conflicting, altered or truncated stage events.

## 6. Commit gates and effect owners

PR #532's `EffectCommitGate` is deliberately synchronous and local. Use it, or an equivalent reviewed linearization primitive, only at the short local effect-owner commit point. It does not authorize the effect and it does not establish remote delivery.

### Input
- Permission admission -> write-ahead operation admission/attempt.
- Invoke OS injector under local revoke serialization.
- `Ok(())` -> locally committed/PlatformAccepted.
- Backend error after invocation -> UNKNOWN, because a batch may have partially applied.
- No-op fallback detected before invocation -> NotAttempted/Rejected; never report successful injection.
- Target application acceptance requires a distinct application-level observer (for example, a controlled test app echo); never infer it from injector return.

### Clipboard
- Check read/write direction permission before opening the OS API.
- Read `get_text` completion is a local read commit; peer disclosure is a later outbound transport operation.
- `set_text` returning success is local API acceptance; another process consuming the value is not observed.
- Do not persist or log clipboard contents, raw values, low-entropy content hashes or secret-bearing error strings.
- Oversized input or adapter setup failure before `set_text` is NotAttempted; error after invocation is UNKNOWN.

### File send
- Offer, each chunk dispatch, Complete, and receiver Verified are separate operations/stages.
- Stable chunk identity binds transfer ID, offset and chunk length/digest.
- Local QUIC stream write completion is only local transport acceptance; receiver full-file hash verification plus no-clobber publication is stronger observation.
- Partial send timeout/cancellation is UNKNOWN. Do not resend on the same broken framed stream or silently restart from offset zero.

### File receive
- Offer accepted, chunk staged, full digest verified, and final name published are distinct.
- The existing stager's atomic no-clobber publication is the local commit point.
- A `Verified` response should bind transfer ID, size and full digest commitment. Duplicate verified receipts are idempotent; conflicting receipts are rejected.
- Crash after all chunks but before final publication recovers from staging state; crash after publication but before response is UNKNOWN to the sender until the receiver replays a stable receipt.

### Video/audio/telemetry
- Sender admission, local transport write, peer receipt, decode, render/playout and display observation remain separate.
- The current protocol does not prove viewer presentation; do not manufacture `OutcomeObserved` from send success.
- Deadline expiry can become a defined drop before attempt or UNKNOWN after dispatch depending on the transport's actual receipt.

## 7. Durable storage and recovery protocol

### WAL record
Use a versioned, append-only binary journal (or equivalent format with unambiguous record framing), containing:
- magic and schema version;
- record length with strict cap;
- monotonic journal sequence;
- operation event bytes;
- checksum/hash-chain link;
- explicit commit marker if record framing requires one.

Each append must handle short writes, disk-full, I/O error and torn final record. Recovery may truncate only an incomplete final record whose preceding valid hash chain remains intact; interior corruption fails closed.

### Synchronization
- AuthorizationAdmitted and EffectAttempted must be durable before dispatch.
- The owner result must be durable before the local lock is released for synchronous effects.
- Do not use deferred/grouped sync for a record that authorizes an imminent external effect unless the group-commit barrier itself is awaited before dispatch.
- Measure journal sync latency and queue depth. On storage failure, no new protected effect may be dispatched.

### Restart
On process restart:
1. Verify journal schema, checksum chain and session binding.
2. Reconstruct each operation state and the monotonic sequence high-water.
3. Convert every nonterminal Attempted record to UNKNOWN.
4. Prevent duplicate dispatch for an unresolved operation ID.
5. Require a verified owner/receiver receipt to reconcile UNKNOWN.
6. Persist reconciliation before allowing a new attempt for that operation ID.
7. Require fresh consent/authority admission after revocation/epoch change.

No auto-retry after crash. No silent deletion/eviction of active or UNKNOWN operations.

### Capacity
Start with PR #531 limits (4,096 operations and 32,768 events per session). Capacity exhaustion is explicit and fail-closed. A later compaction design may archive only fully terminal records after a signed snapshot and continuity proof; UNKNOWN and in-flight records may not be compacted away.

## 8. Cryptographic integrity and trust

The BLAKE3 hash chain is tamper evidence, not authenticity. Durable export must use the existing evidence crypto policy/profile and a signer whose trust binding can be independently verified.

Do not store signing private keys in the journal. Sign an export root/manifest or append authenticated checkpoints through the configured signature backend. The verifier must check signature profile, key binding, session transcript binding, consent root, operation root, sequence high-water and all artifact hashes.

A signed receipt still proves only that a key signed a statement. Trust in the effect owner, its implementation and its observation method remains part of the assurance case.

## 9. Performance and safety targets (proposed)

- p99 durable pre-dispatch journal barrier <= 3 ms on the qualified local SSD profile; publish device/filesystem/write-cache/fsync semantics.
- p99 synchronous input/clipboard M1 lock hold (including journal writes and local API call) <= 20 ms on the qualified profile; report max and tail, not just average.
- Zero protected effects dispatched when the write-ahead admission/attempt record is not durable.
- Zero automatic retry after UNKNOWN.
- Zero conflicting duplicate operation IDs accepted.
- Zero protected payload bytes in journal/events/logs.
- 100% recovery classification for crash injection at every stage boundary.
- Journal recovery must be linear in record/event count and bounded by explicit file size limits.
- Capacity-full and disk-full must fail closed before another effect invocation.

These targets are not measured and may need adjustment after fsync measurements on Linux, macOS and Windows.

## 10. Adversarial test matrix

See [durable-operation-journal-v0.1.json](../../benchmarks/durable-operation-journal-v0.1.json). The corpus covers torn records, disk-full, crash between attempt/result, duplicate/reordered receipts, conflicting operation ID reuse, stale epochs, revoke race, file partial-send, file verify/publication split, clipboard privacy, process restart and signature/artifact tampering.

## 11. Implementation sequence

1. Integrate #531's operation ledger into the live M1 runtime, without changing consent journal semantics.
2. Define stable operation IDs for input and clipboard based on authenticated session/epoch/ingress sequence.
3. Wire #532 at synchronous input/clipboard commit points after M1 admission and before invoking the OS API.
4. Add a separate durable append-only journal with write-ahead barriers and crash recovery.
5. Add signed operation transcript export/verification alongside the consent transcript (#450).
6. Extend file transfer with per-chunk identity and receiver verification receipt.
7. Add frame/audio/telemetry receipt only where the protocol has an actual observer.
8. Run fault injection, restart tests and cross-platform fsync qualification.
9. Independently review the threat model and recovery rules before enabling persistence by default.

## 12. Claim boundary

This document is a target design. It does not claim a durable journal, crash recovery, authenticated remote receipts, signed operation export, distributed revocation, or performance result is already implemented. PR #542 currently provides in-memory local owner outcomes for input and clipboard only; PRs #531/#532 remain additive reference models until live integration is complete.
