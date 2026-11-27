# Externally witnessed operation-WAL heads and sequence leases v0.1

## Status

This branch contains protocol/reference types and unit tests. It does not contain a production witness service, durable independent witness storage, or live integration with DurableOperationEvidenceJournal. Benchmarks are preregistered and unmeasured.

## Why this exists

A hash-linked WAL detects edits to records that remain available. It cannot detect replacement with an older, fully valid prefix when the local storage itself is rolled back. A latest-head commitment retained outside that storage failure domain is needed to detect this.

Xenia already has checkpoint and independent-witness concepts in xenia-ledger. That crate is AGPL-3.0-or-later, while xenia-peer-core is Apache-2.0 OR MIT. This branch does not add an xenia-ledger dependency or change licensing. It implements the minimal compatible protocol boundary natively using the peer-core crate's existing Ed25519, BLAKE3 and serde dependencies.

## Protocol

### 1. Checkpoint

An OperationWalCheckpoint binds:

- authenticated session fingerprint
- clock-domain identity
- durable WAL sequence
- exact WAL record-chain head hash
- monotonically increasing independent witness generation
- fingerprint of the previously retained checkpoint
- timestamp

The first checkpoint uses witness generation 1 and a zero previous-checkpoint fingerprint. Later checkpoints must be immediate successors. Same-sequence/different-head is a fork; lower WAL sequence is rollback.

### 2. Extension proof

A witness must not countersign a proposed head merely because it has a valid signature or is numerically newer. It must verify the path from its own previous checkpoint to the candidate. The current reference model carries sequence + previous-hash + record-hash tuples for every intervening record.

This is intentionally linear in the number of WAL records since the previous checkpoint. For production-scale retention, move to a Merkle Mountain Range or RFC 9162-style append-only consistency proof so the witness can verify O(log n) proof material rather than receiving every link. The local verifier must still validate every actual canonical record body and its hash.

### 3. Independent witness store

OperationWalWitnessStore defines the boundary to an independently operated monotonic authority. Implementations MUST durably and atomically:

1. compare the caller's expected previous checkpoint fingerprint with the store's current head;
2. verify session, clock-domain, witness-generation and checkpoint succession;
3. verify the supplied hash-link extension ends at the candidate head;
4. persist the new head before returning countersignatures.

The sequence-lease path must atomically reserve a non-overlapping range and persist its end before returning signatures. A timeout or unknown result must be reconciled by reading the store's retained state before retry. Never blindly retry with a new head or a new sequence range.

A sidecar file in the WAL directory is not an independent witness. Suitable production options include a separately administered quorum-backed service, an independently retained append-only log, or a hardware-backed monotonic store, depending on deployment and threat model.

### 4. Restore gate

After process restart:

- verify the witness bundle against a caller-pinned witness-key set and quorum;
- load and verify the local WAL hash chain;
- require local sequence and head to equal the latest witnessed checkpoint;
- reject older local state as rollback;
- reject a local suffix newer than the checkpoint as unanchored until it has been externally witnessed;
- reconcile unknown witness-store outcomes before permitting a new mutation.

The checkpoint protocol deliberately separates authenticity (witness quorum), continuity (extension proof), and local equality (restore gate). No one check substitutes for the others.

### 5. Process-bound operation-sequence leases

Witnessing every frame would add a remote round-trip to the hot path. Instead, a witness atomically reserves a bounded lease range. Each lease binds session, authority epoch, monotonic lease generation, start/end sequence, previous-lease fingerprint, process-boot fingerprint and validity interval.

The process verifies the quorum once and receives a non-deserializable VerifiedOperationSequenceLease token. Each frame then performs a constant-time range check. The token is process-local and must not survive restart. The next process uses a fresh boot fingerprint and reserves a range after the previous lease's entire end. Unused sequence numbers are burned. This prevents reuse when a process crashes after an effect may have occurred but before its local terminal record is durable.

The WAL remains the durable per-operation record. A lease is a reservation of identities, not evidence that every identity was used or that every effect succeeded.

## Industry comparison and opportunity

| System / pattern | Strong point | Xenia opportunity |
|---|---|---|
| Certificate Transparency 2.0 (RFC 9162) | Signed tree heads and consistency proofs for append-only logs | Replace linear WAL extension proofs with compact Merkle consistency proofs or an MMR |
| Sigstore Rekor | Public transparency checkpoints and independent monitoring | Use independent witness-store monitoring for privileged remote-control effects |
| TUF | Persisted version/freshness metadata and rollback/freeze resistance | Bind checkpoint generation and freshness policy to WAL restore |
| PostgreSQL WAL | Mature local durability and crash recovery | Add an independent history-retention layer outside local disk |
| Kafka transactions | Explicit producer/consumer transaction boundaries | Keep transport acceptance distinct from peer observation and downstream application |

Xenia should not claim that a BLAKE3 chain alone is stronger than a transparency log. Its differentiator should be the combination of stage-accurate effect evidence, external monotonic retention, explicit rollback refusal, and process-bound identity leases across the full remote-control lifecycle.

Primary references:
- RFC 9162, Certificate Transparency Version 2.0: https://www.rfc-editor.org/rfc/rfc9162
- Sigstore Rekor transparency log: https://docs.sigstore.dev/logging/overview/
- TUF specification: https://theupdateframework.github.io/specification/latest/
- PostgreSQL WAL configuration: https://www.postgresql.org/docs/18/runtime-config-wal.html
- Kafka design: https://kafka.apache.org/design/

## Deterministic reference-store qualification

The module's unit tests include a test-only in-memory witness store. It holds the checkpoint/lease state behind a mutex and performs expected-head comparison, extension/successor verification, signing, and state replacement under one critical section. This is a deterministic reference implementation of the compare-and-advance semantics, not an independent witness: its process memory can be lost or rolled back with the test process and is not a security boundary.

The tests cover a successful checkpoint sequence with readback, rejection of a broken extension without advancing state, two concurrent contenders using the same prior checkpoint where exactly one wins, and monotonic lease reservation with a readback path for a simulated lost response. The real deployment must repeat these tests against a durable store in a separate failure domain and test failures before commit, after commit, quorum partition, restart and storage rollback.

## Benchmark programme

See benchmarks/operation-wal-anchor-v0.1.json. Status is preregistered_unmeasured.

The benchmark compares local hash-chain-only restore, per-operation remote witness round-trips, witnessed sequence leases with local constant-time range checks, and transparency-log consistency-proof reference implementations. It tests 2-of-3 and 3-of-5 witness quorums, lease spans up to 1,048,576, concurrency through 512, and histories through 100 million operations.

Provisional targets (not results): cached range check p99 <= 1 us, stable ID derivation p99 <= 5 us, local sequence-admission >= 1 million operations/s, and same-region 2-of-3 lease acquisition p99 <= 100 ms. Absolute correctness goals are zero rollback accepts, zero overlapping sequence ranges, zero untrusted quorum accepts, and zero blind retries after unknown witness outcomes.

Report model verification, local witness-store measurements, and multi-region production-like results separately. Preserve raw samples, exact commit SHAs, witness failure-domain topology and injected fault schedules.

## Implementation boundaries

Implemented here: typed checkpoint/extension/lease model, witness quorum signature verification, local-head checks, immediate-successor validation, process-local verified lease token, and unit tests.

Not implemented here: durable independent witness store, hardware monotonic counters, MMR/RFC 9162 proof format, network protocol, operation-WAL API wiring, or crash/restart multi-process tests. These are explicit follow-on integration gates, not claimed capabilities.
