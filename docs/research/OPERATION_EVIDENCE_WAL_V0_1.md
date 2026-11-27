# Durable Operation Evidence WAL v0.1

**Status:** Standalone durable storage primitive, stacked on the in-memory operation evidence model in PR #531. It is not yet connected to live M1 effect owners.
**Tracking:** [#545](https://github.com/Luminous-Dynamics/xenia-peer/issues/545).
**Base:** `research/xenia-operation-evidence-v0.1` (PR #531).

## 1. What is implemented

`xenia-peer-core::operation_evidence_wal::DurableOperationEvidenceJournal` wraps the existing `OperationEvidenceLedger`; it does not define a second operation-stage state machine.

- Versioned, length-framed Bincode WAL records.
- A domain-separated BLAKE3 chain over each record body, with sequence, previous hash, authenticated session fingerprint and clock-domain binding.
- Synchronous `sync_data` after each appended record.
- Unix file creation mode 0600 and parent-directory sync when the WAL and writer lock are created.
- Create-new single-writer lock file; two live writers cannot open the same path.
- Strict per-record, total-file, operation-count and event-count bounds. The WAL also reserves worst-case bytes for each still-required terminal/reconciliation event, so a full log cannot consume the space needed to recover an attempted effect to UNKNOWN.
- Full replay and hash/state verification on open.
- Only an incomplete final frame is truncated to the last verified offset; complete malformed or hash-invalid records fail closed.
- After recovery, any operation whose latest known stage is Attempted is durably advanced to Unknown before the journal is returned to the caller.
- The operation ID is stable across retries/restarts; identical admission is idempotent, conflicting context reuse is rejected.
- Invalid state transitions and clock regressions are rejected before a WAL record is appended.
- A failed append/sync poisons the in-process writer; callers must stop dispatch and reopen/reconcile.

## 2. Write-ahead caller contract

For a protected effect, the caller must use this ordering:

1. Check consent/authority independently.
2. Call `admit(...)` and wait for its durable result.
3. Call `mark_attempted(...)` and wait for its durable result.
4. Only after step 3 succeeds, invoke the actual effect owner.
5. Call `mark_committed`, `mark_not_committed`, or `mark_unknown` with the effect owner's result.
6. For a stronger remote/consumer observation, call `mark_observed` only when an actual observer supplies a receipt.

Do not infer authorization from the journal; the WAL is evidence, not a permission token. Do not call an effect owner when admission or attempt persistence fails. If an effect owner may have acted but its terminal receipt cannot be synced, stop new operations and recover the operation as UNKNOWN.

## 3. Recovery semantics

- A partial final four-byte length prefix or partial final record payload is treated as a torn tail and truncated to the previous fully verified record boundary.
- A complete frame with malformed Bincode, unsupported schema, invalid sequence, session/clock mismatch, broken previous-hash link, bad record hash, or invalid state transition fails closed. Interior corruption is never skipped.
- A complete Attempted record with no terminal owner result is recovered as UNKNOWN. The recovery receipt digest is domain-separated and binds operation ID, operation sequence and previous WAL hash. The journal reserves both event slots and worst-case WAL bytes for this terminal/reconciliation path before admitting new operations.
- UNKNOWN prevents `mark_attempted` from succeeding again. A verified reconciliation receipt must resolve the same operation ID first.
- Exact duplicate admission is idempotent. Reusing an ID with a different operation sequence or context is rejected.
- The journal uses a caller-supplied persistent `clock_domain` and logical monotonic `at_ticks`; these values must continue across restart. They are not wall-clock timestamps.

## 4. Bounds and filesystem behavior

| Bound | Value |
|---|---:|
| WAL schema | v1 |
| Maximum serialized record | 1 KiB |
| Maximum journal size | 32 MiB |
| Operations/session | 4,096 (from PR #531) |
| Stage events/session | 32,768 (from PR #531) |
| Unix file permissions | 0600 |

The lock file is created with `create_new` and removed on clean drop. A stale lock after process termination is deliberately not removed automatically: operators must verify that the old writer is gone before deleting the lock. This avoids two writers racing after recovery.

On Unix, parent-directory metadata is synced when the WAL/lock file is first created. On non-Unix targets, std does not provide a consistent directory-fsync interface here; file data is synced, but rename/directory-entry durability needs platform-specific qualification before production claims. Filesystem, device write cache, power-loss behavior and sync semantics must be measured on each target OS.

## 5. Tests authored

Eleven unit tests cover:

1. Write-ahead admit/attempt/commit survives close/reopen.
2. An interrupted Attempted operation recovers to UNKNOWN and cannot be retried.
3. A torn final frame is truncated to the last valid record boundary.
4. Complete record tampering fails closed.
5. Conflicting operation-ID reuse is rejected.
6. A second active writer is rejected.
7. Reconciliation receipt survives restart and exact duplicate reconciliation is idempotent.
8. Session fingerprint or clock-domain mismatch is rejected.
9. Invalid transition is rejected before WAL append.
10. Regressing tick is rejected before WAL append.
11. Identical admission is idempotent and adds no second WAL record.

These tests are authored but are not claimed to have passed until exact-head CI compiles and executes them.

## 6. What is not implemented

- No live wiring into `M1RuntimeSession`, `InputEffectExecution`, clipboard wrappers, file-transfer routes or the consent socket.
- No signed journal export, independent signer binding, cross-file artifact manifest, or evidence bundle verifier integration.

The public `head_candidate()` accessor exports the payload-free tuple `(session_fingerprint, clock_domain, journal_sequence, wal_chain_digest, last_operation_sequence)`. This is not itself an authenticated anchor. A caller must durably accept it in a separate trust domain and verify it during recovery before accepting later work. The operation sequence is used by the async dispatch gate to restore its high-water mark.

**Local integrity boundary:** the BLAKE3 chain is unkeyed and has no trusted external head by itself. It detects malformed records, interior mutation, reordering, and broken links in the retained prefix, but it cannot detect deletion of a complete valid suffix, restoration of an older valid journal, or a full rewrite by an actor who can modify the file and recompute the chain. Therefore this WAL alone is not tamper-proof or rollback-proof against a malicious local writer. A consumer that needs that property must independently persist/authenticate at least `(journal_sequence, wal_chain_digest)` in a separate trust domain and reject a journal whose recovered head does not match or advance that checkpoint. Such anchoring is not implemented by this PR.
- No cross-process distributed lock beyond one local create-new lock file.
- No remote receipt protocol, receiver deduplication store or operation replay response endpoint.
- No automatic retry; recovery deliberately leaves ambiguity as UNKNOWN.
- No cross-platform power-loss qualification or benchmark result.

PR #542 currently has in-memory input/clipboard outcomes. This WAL is the next substrate; live integration must separately bind stable ingress operation IDs and owner receipts. PR #531 remains the underlying stage ledger; PR #532 remains a local effect-commit/revocation gate reference model.

## 7. Proposed performance targets (not measured)

- p99 WAL `sync_data` barrier <=3 ms on a qualified local SSD profile.
- p99 local synchronous effect lock hold <=20 ms including WAL barrier and API call.
- Zero effect dispatch if either admission or attempt write-ahead barrier fails.
- Zero automatic retry after UNKNOWN.
- 100% deterministic recovery for every crash point in the fault corpus.
- Zero protected payload bytes in any WAL record.

No latency, crash-safety or production-readiness claim is made from these authored tests. Exact-head Rust compilation, formatting, Clippy, runtime tests, filesystem fault injection and cross-platform durability tests are required.