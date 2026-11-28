# Xenia–Mycelix Operation-Journal Checkpoint Interop v1

## Status

This branch defines a versioned Xenia-to-Mycelix checkpoint payload and a shared 297-byte golden vector. It is a wire-contract/reference implementation, not a production connection to the Mycelix DeSci service.

Implemented:

- Payload-redacted Xenia checkpoint structure.
- Keyed, deployment-scoped journal identity commitment.
- Fixed canonical binary encoding with explicit field order and integer endianness.
- Domain-separated local BLAKE3 digest for content identity/idempotency.
- Lifecycle counters that keep admitted, attempted, committed, observed, unknown and reconciled outcomes distinct.
- Shared golden payload fixture and Rust test.
- Documentation and preregistered cross-language/interop benchmark matrix.

Not implemented:

- Mycelix API endpoint or governed event type that accepts this payload.
- RFC 9162 proof generation or verification in Xenia.
- Mycelix signed tree-head/witness verification in Xenia.
- An independent verifier that checks every external effect-owner receipt.
- Production witness service, remote transport, or organization-diverse deployment.
- Measured interop latency or a live multi-process integration result.

## Trust stages: do not collapse these claims

The integration must preserve these independent statements:

1. **Xenia local WAL integrity.** Xenia replays its framed WAL and operation-stage chain, verifies monotonic sequences and hash links, and constructs a checkpoint candidate. The BLAKE3 digests are unkeyed local integrity commitments, not signatures or external truth proofs.
2. **Canonical checkpoint identity.** The fixed versioned payload has a stable byte encoding. Its local BLAKE3 digest identifies those bytes for idempotency and content addressing.
3. **RFC 9162 proof validity.** The Mycelix primitive verifier can return inclusion-valid-relative-to-supplied-root or consistency-valid-relative-to-supplied-roots. This does not authenticate the supplied tree head, log identity, signer, witness quorum, source completeness, or payload truth.
4. **Governed root authentication.** The Mycelix DeSci trust layer must establish that the checkpoint is in governed published history and verify the witness key, actor, organization, receipt time, key epoch, revocation/compromise intervals, and organization-diverse witness/mirror thresholds.
5. **Effect-owner truth.** A source-journal checkpoint alone does not prove that an input injector applied an event, a clipboard changed, a transport peer received data, a file was published, or a remote application rendered/observed it. Where this claim is required, an independent verifier must validate scoped effect-owner/observer receipts before the checkpoint is promoted or a positive outcome is asserted.
6. **Unresolved lifecycle.** Admitted, attempted and unknown counts remain visible. A witnessed root must not turn an UNKNOWN operation into success or authorize silent retry. Local commit and stronger observation are distinct.

A caller should return a staged evidence object, not a single boolean called trusted.

## Canonical payload v1

The wire domain is:

    XENIA-MYCELIX-OPERATION-JOURNAL-CHECKPOINT-V1\0

Integers are unsigned big-endian. Fixed-size byte arrays are emitted as-is. The optional operation sequence is encoded as one byte followed by a u64 only when present.

Field order:

| Order | Field | Encoding | Purpose |
|---:|---|---|---|
| 1 | domain separator | fixed bytes | Prevent cross-protocol interpretation |
| 2 | schema version | u16 BE | Explicit versioning |
| 3 | journal scope commitment | 32 bytes | Opaque deployment-scoped journal/session identifier |
| 4 | clock domain | u64 BE | Bind monotonic ticks to one clock domain |
| 5 | authority epoch | u64 BE | Bind the checkpoint to current M1 authority/rekey epoch |
| 6 | policy digest | 32 bytes | Bind exact permission/consent policy |
| 7 | journal sequence | u64 BE | WAL record high-water |
| 8 | WAL chain digest | 32 bytes | BLAKE3 hash-chain head for framed WAL |
| 9 | operation chain digest | 32 bytes | BLAKE3 hash-chain head for semantic operation events |
| 10 | last operation sequence | tag u8, then optional u64 BE | Persisted idempotency high-water |
| 11 | operation event count | u64 BE | Number of semantic stage events represented |
| 12 | lifecycle counts | ten u64 BE values | Preserve the current stage distribution |

The ten lifecycle counters appear in this exact order:

1. admitted
2. attempted
3. committed
4. observed
5. rejected
6. not_committed
7. unknown
8. reconciled_not_committed
9. reconciled_committed
10. reconciled_observed

For a checkpoint with a Some operation sequence, the current golden vector is 297 bytes. The fixture is in fixtures/xenia-myclix-checkpoint-v1.kat. It defines the fixed sample values and complete expected payload hex; the Rust unit test compares every byte.

### Scope commitment and privacy

The raw 32-byte session fingerprint is not exported. Xenia derives journal_scope_commitment using keyed BLAKE3 over:

- a separate domain separator;
- the raw session fingerprint; and
- the monotonic clock-domain identifier.

The 32-byte scope key is not serialized. It must be high entropy, deployment-specific, stored outside the WAL, and rotated under an explicit migration procedure. Reusing a key across unrelated deployments enables cross-deployment correlation and is not recommended.

The checkpoint does not include raw operation IDs, resource labels, clipboard text, keystrokes, file content, media payloads, bearer tokens, or private signing material. Policy and owner context are represented by digests only.

The opaque commitment remains linkable within a deployment by design. It is not an anonymity guarantee.

## Mycelix trust handoff

The intended adapter is a service/wire boundary, not a Rust crate dependency:

1. Xenia replays the durable WAL and verifies its operation chain.
2. Xenia reads the current authenticated M1 epoch and exact permission policy digest.
3. Xenia constructs XeniaJournalCheckpointV1 and publishes canonical_bytes.
4. The Mycelix side hashes those bytes as an RFC 9162 leaf using the verifier's SHA-256 0x00-prefixed leaf hash. Xenia's local BLAKE3 checkpoint_digest is not substituted for the RFC 9162 leaf hash.
5. The checkpoint entry is committed into a governed transparency history. The integration must define the exact event/entry type and how the Xenia payload is bound into the existing governed checkpoint; this is not an API that this PR claims already exists.
6. The RFC 9162 verifier establishes inclusion relative to the supplied root and consistency from a prior supplied root.
7. The governed DeSci trust layer authenticates the root/checkpoint history and independently verifies witness signatures, authorization at witness time, organization identity/diversity, key epochs, compromise intervals and signed mirror observations.
8. If positive external-effect claims are required, an independent effect verifier validates the relevant owner/observer receipts. A checkpoint signature alone is not a receipt for an external operation.
9. The returned evidence package preserves every stage separately, including root-authentication status, local-chain verification status, witness/mirror quorum, effect-owner verification, unresolved counts and exact versions/sequence.

The current Mycelix public contract is described by issue #6810 (checkpoint trust bridge) and #6811 (RFC 9162 primitive gap), with primitive verifier work in PR #6812. Mycelix DeSci's own README labels the system experimental and undergoing architectural refoundation. Therefore this document describes a proposed interop contract and reuse path, not a claim that a production Mycelix witness endpoint is already available.

## Why reuse the Mycelix witness plane

Xenia needs to answer: “Does this external verifier accept this exact operation-journal checkpoint under a governed key and witness policy?”

It should not build a parallel global trust registry, witness enrollment system, compromise governance system, or Merkle transparency log. Mycelix DeSci already has reference interfaces for:

- signed canonical events and append receipts;
- governed credential/key/organization histories;
- threshold-governed checkpoint publication;
- signed checkpoint witness observations;
- organization-diverse witness and independent mirror readiness policies;
- key compromise intervals and retroactive witness-validity classification.

The Xenia-specific work should be limited to a versioned source checkpoint and an adapter. The service boundary also keeps the Xenia Rust build graph independent from Mycelix's application workspace and license/dependency policy.

## Failure and recovery semantics

- A WAL head below the previously accepted independent witness checkpoint is rollback, not a recoverable success.
- A local head ahead of the witness is an unanchored suffix. Do not auto-promote it simply because its local BLAKE3 chain verifies.
- A forked hash/sequence at the same journal prefix fails closed.
- Witness unavailability blocks new high-risk effect admissions if deployment policy requires anchoring.
- A stale authority epoch or policy digest invalidates the checkpoint for new effect admission.
- Any UNKNOWN operation stays UNKNOWN until an independently verified receipt resolves it.
- A checkpoint that reports one or more pending_effects or pending_observation is not eligible for a “fully resolved” assertion.
- A successful RFC 9162 inclusion proof relative to an untrusted root remains untrusted at the root layer.
- A Mycelix witness quorum is acknowledgement under a governed policy, not real-world effect truth or proof that a source universe is complete.

## Benchmark programme

See benchmarks/xenia-myclix-checkpoint-interop-v0.1.json. Status is preregistered_unmeasured.

Compare like with like:

- Xenia canonical serialization and local BLAKE3 digest.
- RFC 9162 SHA-256 leaf hashing, inclusion verification and consistency verification.
- Governed checkpoint publication.
- Independent witness/mirror round-trip.
- Full end-to-end source-journal-to-authenticated-root verification.

Measure each boundary separately, then report end-to-end p50/p95/p99/p999, bytes transferred, CPU/op, memory, witness availability, quorum completion, and recovery after process restart. Never compare the 297-byte local checkpoint encoding time with a remote multi-organization witness quorum as if they were the same operation.

Correctness targets are absolute: no raw sensitive fields in payload; no stale authority/policy checkpoints accepted for new work; no UNKNOWN operation silently classified as committed/observed; zero accepted rollback/forked WAL heads after a durable external checkpoint; zero untrusted roots mislabeled authenticated; zero duplicate or conflicting canonical bytes accepted as the same checkpoint identity.

## Next gates

1. Add the Xenia checkpoint event to the Mycelix governed log with an explicit versioned payload type.
2. Add a Go/Mycelix test that consumes the shared KAT and computes the RFC 9162 leaf hash over the exact canonical bytes.
3. Bind the checkpoint entry to an authenticated tree head and the existing DeSci governance/witness policy.
4. Verify independent effect-owner receipts separately from checkpoint inclusion.
5. Add cross-repository fixtures for unknown/reconciled/observed lifecycle states and policy/epoch substitution.
6. Add a live remote-witness adapter with durable CAS and separate failure-domain deployment.
7. Run crash, rollback, split-view, stale-witness, witness-compromise and process-restart drills.
8. Publish exact-head evidence bundles and measured latency results.
