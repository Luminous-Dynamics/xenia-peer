# Independent Journal-Head Witness v0.1

## Status and scope

This PR adds a reference interface and local verification model for the rollback boundary left open by the durable operation WAL in PR #547.

Implemented in this branch:

- A bounded prefix-head index in the WAL, including the sequence-zero genesis head.
- Exact verification that a proposed external checkpoint matches the hash, session, clock domain, journal sequence, and operation-sequence high-water at that WAL prefix.
- A JournalHeadWitness interface with durable compare-and-swap generation semantics.
- Strict startup behavior: an empty journal may initialize a genesis checkpoint; a non-empty journal with no checkpoint fails closed.
- A recovered WAL older than the checkpoint is rejected as rollback.
- A local WAL newer than the checkpoint is an unanchored suffix. It is not automatically trusted or promoted.
- An explicit checkpoint-advance operation that requires the caller to have independently verified the new stage/owner receipts before requesting the CAS.
- Unit tests for genesis initialization, missing anchors, unanchored suffixes, explicit advance, valid-prefix truncation/rollback, stale generations, prefix reconstruction after restart, and forked digest/operation-sequence detection.

Not implemented:

- No remote Mycelix witness service, HSM/TPM provider, hardware monotonic counter, or production persistent witness backend.
- No signed owner receipt verifier or evidence-bundle signature scheme.
- No live M1/clipboard/input/file-transfer wiring.
- No adversarial multi-host test, process-kill test against a real witness, or measured latency result.

The included MemoryJournalHeadWitness exists only under tests. It is not a production trust anchor.

## The core distinction

Three different claims must remain separate:

1. **Local chain integrity:** the WAL's BLAKE3 chain detects malformed records, interior changes, reordering, and broken hash links in the retained prefix.
2. **Rollback resistance:** an independent witness remembers the last accepted head and refuses a local file that is older or diverges at that trusted sequence.
3. **Effect truth:** an authenticated effect owner or observer proves whether an external operation actually committed or was observed.

An unkeyed local hash chain cannot provide claim 2 by itself. A checkpoint also does not prove claim 3. It commits to bytes and order; it does not prove that a clipboard write, input injection, or peer-side effect happened.

## Head and prefix model

The WAL exports a payload-free head tuple:

| Field | Purpose |
|---|---|
| session fingerprint | Binds the checkpoint to the authenticated Xenia session |
| clock domain | Prevents cross-domain replay of logical ticks |
| journal sequence | Monotonic position in the durable WAL |
| WAL chain digest | Commits to the exact record prefix |
| last operation sequence | Monotonic operation-idempotency high-water |

The WAL retains a bounded prefix-head entry for each verified journal sequence, including genesis. The bound follows the existing 32,768-event WAL limit. This makes prefix verification indexed by sequence rather than requiring the whole WAL to be rehashed for every checkpoint check.

## Startup and advancement protocol

1. Open the WAL. It verifies the complete retained record chain and recovers interrupted Attempted operations to UNKNOWN before returning.
2. Read the checkpoint for the session from an independent witness.
3. If no checkpoint exists, initialize only an empty sequence-zero journal. A non-empty unanchored WAL requires a deliberate administrative bootstrap; never trust it just because its local hash chain verifies.
4. If the local sequence is below the witness sequence, reject as rollback.
5. Verify that the witness's complete head tuple is an exact prefix of the recovered WAL. A different digest or operation-sequence value at the same sequence is a fork/mix-and-match failure.
6. If the recovered head exactly equals the witness, the journal is anchored.
7. If the recovered WAL is newer, report an unanchored suffix. Do not silently fast-forward. The caller must independently validate all stage and effect-owner receipts in that suffix, then call the explicit checkpoint-advance API. The witness must authenticate that caller and durably CAS the new generation.

The explicit advance function verifies exact prefix continuity and monotonic operation sequence. It does **not** verify signatures or the truth of external effects. That verification belongs to the caller's independent evidence verifier and the witness's authorization policy.

For irreversible effects, the intended deployment protocol is to anchor the durable admission/attempt state before invoking the effect owner. A completion record written after the external operation is not sufficient by itself: its receipt must be validated by the external verifier before the witness accepts the new head. If the process dies after the effect but before a validated terminal checkpoint, recovery stays UNKNOWN and does not retry.

## Why an unanchored suffix is not auto-promoted

A local attacker who can rewrite the WAL can construct a new internally consistent hash chain for a suffix that was never witnessed. If startup automatically advanced the witness to any newer locally valid hash, it would convert that attacker-controlled suffix into trusted history.

This PR deliberately returns UnanchoredSuffix instead. The external verifier must decide whether the new records are justified by authenticated owner/observer receipts and only then ask the witness to persist the new head. A production witness should make the checkpoint update a durable compare-and-swap and bind the authenticated principal, session, previous generation, and new head.

## Risk-tiered checkpoint cadence (research direction)

A remote witness round trip on every 60 fps video frame or audio packet would likely dominate the media path. It is not a sensible universal design target. The checkpoint cadence should be selected by effect risk and receiver capabilities:

| Class | Examples | Candidate anchor policy | Required caveat |
|---|---|---|---|
| High-risk local mutation/disclosure | Input injection, host clipboard read/write, file publication, privilege changes | Anchor admission and attempt before invoking the effect owner; anchor a terminal stage only after owner-receipt verification | Witness availability blocks the new mutation |
| High-volume stream | Video frames, audio packets, routine telemetry | Short-lived, signed stream lease that commits a monotonic sequence range and a batch root before the first send; periodic witnessed range advancement | Receiver must enforce sequence/dedup, and crash inside the range leaves unresolved work UNKNOWN |
| Control/authority plane | M1 consent, rekey, revocation, scope changes | Per-transition checkpoint; invalidate prior leases and epochs | No stale lease may admit a new operation after the revocation linearization point |

The batch/lease approach is a research candidate, not implemented here. It is only safe if the remote receiver durably remembers the accepted sequence high-water (or a deduplication window), the lease is scoped to exact session/epoch/lane/direction/resource context, and the entire bounded range is committed before sending. A batch commitment cannot be used to pretend every frame was received or rendered. If receiver-side deduplication is unavailable, use the stricter per-operation path or retain the stream as at-least-once/UNKNOWN on recovery.

This creates a measurable optimization problem: minimize witness round trips while bounding the maximum unanchored effect window and preserving zero silent retries.

## Witness implementation requirements

A production JournalHeadWitness must:

- Live outside the WAL's threat and failure domain. A sibling file on the same writable disk is not independent.
- Authenticate the writer and bind every update to the session identity.
- Persist a monotonically increasing generation and reject stale CAS attempts.
- Reject a lower journal sequence, lower operation sequence, clock-domain change, or same-sequence conflicting digest.
- Provide a durable success receipt only after its own state is committed.
- Fail closed when unavailable; never fall back to trusting the local file.
- Support disaster recovery with an explicit, separately authorized re-bootstrap procedure.
- Retain audit history for witness updates, including old/new generation and head digests.

Potential implementations include a separately administered Mycelix witness service, HSM/TPM-backed monotonic state, or a threshold-signed transparency-log checkpoint. Those are implementation options, not claims that this PR already provides them.

## Industry comparison

- **TUF** persists trusted metadata versions and requires clients to reject lower versions; its timestamp metadata is threshold-signed, expires, and is persisted. It is a strong reference for rollback/freeze protection, not a ready-made effect journal.
- **Sigstore Rekor** stores signed metadata in an append-only transparency log and exposes inclusion/integrity proof mechanisms and signed checkpoints. Its log checkpoint model is a useful reference for externally witnessed roots.
- **Certificate Transparency / Merkle consistency proofs** provide the adjacent idea of proving that a newer tree extends a previously trusted tree without changing the old prefix. Xenia's WAL prefix index is a compact local equivalent for this single-session journal; a remote Merkle transparency service would be a later option.
- **PostgreSQL WAL** documents how durability depends on the configured write/sync boundary. Xenia must state which records have been locally synced and which heads have additionally been accepted by the independent witness. These are different durability tiers.
- **Kafka, RabbitMQ and NATS** make useful delivery-boundary comparisons, but they do not automatically provide external-effect truth for Xenia's host OS input/clipboard owners. Their confirms/acks or stream deduplication must not be conflated with a remote application's processing or presentation.

Primary references:

- TUF current specification: https://theupdateframework.github.io/specification/latest/
- Sigstore Rekor overview: https://docs.sigstore.dev/logging/overview/
- Rekor inclusion/consistency proof and signed checkpoint model: https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md
- PostgreSQL WAL durability settings: https://www.postgresql.org/docs/18/runtime-config-wal.html
- Kafka delivery semantics: https://kafka.apache.org/design/
- RabbitMQ publisher confirms and consumer acknowledgements: https://www.rabbitmq.com/docs/confirms
- NATS JetStream: https://docs.nats.io/concepts/jetstream

## Benchmark and qualification plan

See benchmarks/journal-head-anchor-v0.1.json. Status is preregistered_unmeasured.

Keep the three benchmark layers separate:

1. Local prefix lookup/verification (in-memory index, same process).
2. Durable witness CAS latency (remote/HSM/TPM backend, including network and durable-commit time).
3. End-to-end crash/rollback behavior with real processes, filesystem images and a separately controlled witness.

Compare against a no-witness baseline, a naive same-disk checkpoint (negative control; not a security solution), and the production candidate witness backend. Measure p50/p95/p99/p999 latency, throughput, bytes per checkpoint, CAS conflict rate, witness availability, memory overhead, and recovery time. Fault schedules include stale witness responses, duplicate update, concurrent updates, witness partition, power-loss after WAL sync but before witness CAS, rollback to older valid WAL prefixes, complete rewritten suffixes, and witness database restore.

Provisional local target: prefix verification p99 <= 50 us for a journal at the 32,768-event bound. This does not include a remote witness round trip. The security target is absolute: zero stale/rolled-back/forked WAL heads accepted after a checkpoint has been durably acknowledged. All performance values remain targets until measured with exact runner/hardware receipts.

## Open integration gates

1. Implement a production witness outside the local WAL's failure domain.
2. Define authenticated receipt schemas for admission, attempt, owner commit/not-committed, and observation.
3. Bind witness advances to the verified receipt set, not just a caller-supplied digest.
4. Integrate witness verification before any new effect admission after restart.
5. Define recovery for a WAL that has an unanchored terminal suffix; keep it UNKNOWN unless the owner receipt is independently validated.
6. Run multi-process crash, restore, partition and stale-witness tests.
7. Publish raw benchmark samples, exact commits, witness backend identity and durability configuration.
