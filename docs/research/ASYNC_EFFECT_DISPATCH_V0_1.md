# Xenia asynchronous effect-dispatch lifecycle v0.1

## Status and scope

This is an executable local state-machine model for issue #545. It is not yet wired into Xenia's live senders and does not claim durable persistence, authenticated evidence, or peer receipt. The preregistered benchmark is explicitly unmeasured.

The central contract is:

- The short local transition in begin_dispatch is the logical dispatch-admission linearization point.
- If that transition precedes revocation, the send is already admitted and may finish after revocation.
- If revocation precedes that transition, no send admission is issued.
- No gate mutex is held across the async transport future.
- Dropping/cancelling the in-flight guard records UNKNOWN. UNKNOWN blocks new mutations until an independently authenticated reconciliation receipt is supplied.
- A successful local transport call is only TransportAccepted. It is not PeerObserved, decoded, applied, rendered, played, or displayed.

This is a precise and implementable meaning of revocation. It is not a claim that a physical socket write cannot occur after the revocation call returns: a send logically admitted first may be polled or complete later. A stronger physical stop guarantee would require transport-owner serialization, cancellation guarantees from the concrete carrier, and a separate proof that the write had not crossed its irreversible boundary.

## Why a separate model is needed

The synchronous effect-commit gate (#532) intentionally serializes a short, bounded local effect closure under one lock. It explicitly must not be held over an async network operation. Conversely, a one-time allow_frame_flow() followed by an unlocked await leaves the ordering contract implicit.

The async dispatch gate makes that contract explicit without keeping a lock across I/O. It distinguishes:

1. Prepared: external authorization has been checked and the stable operation ID is reserved.
2. InFlight: begin_dispatch has won against local revocation; transport dispatch may now proceed.
3. AcceptedByTransport: the carrier API returned success for the complete envelope.
4. Unknown: transport was invoked but completion is ambiguous, or the in-flight guard was dropped.
5. CancelledBeforeDispatch: a prepared permit was dropped or invalidated before dispatch.
6. Reconciled: an external verifier has authenticated a receipt resolving the exact UNKNOWN operation.

Operation IDs remain consumed after cancellation and reconciliation. New operations are blocked while UNKNOWN remains.

## Adapter sequence for live Xenia senders

The intended adapter sequence for a host-to-viewer frame, audio, telemetry, clipboard disclosure, or file chunk is:

1. Independently check the exact M1 permission, current authority/rekey epoch, scope, freshness, and payload/resource policy.
2. Derive a stable operation ID from the protocol identity where possible: authenticated session fingerprint + authority epoch + lane + protocol frame/sequence/transfer identity. Do not use an ephemeral random ID without a durable mapping.
3. Call prepare_after_admission.
4. Append and durably sync the stage-accurate AuthorizationAdmitted and EffectAttempted WAL records before any transport dispatch.
5. Call begin_dispatch immediately before invoking the concrete transport future. If revoke won first, record a definitive NotDispatched terminal event; if begin_dispatch won first, the operation is logically admitted before revoke.
6. Invoke and await the carrier send without holding the gate mutex.
7. On complete transport API success, append TransportAccepted. Do not append PeerObserved unless the protocol carries an authenticated receipt from the receiver.
8. On write error, timeout, task abort, or future drop, append UNKNOWN. Do not automatically replay the logical operation.
9. Reconcile only against an independently authenticated receipt bound to the exact operation ID, session, epoch and context digest.

There is a deliberate conservative case: the WAL may contain EffectAttempted even if revocation wins between the durable append and begin_dispatch. In that case no transport send is admitted; the caller records NotDispatched. A crash before that terminal record recovers to UNKNOWN, which is safe but may require operator/observer reconciliation. The alternative ordering—begin_dispatch before durable EffectAttempted—would create a gap where a crash can lose evidence of an admitted send, and is therefore not acceptable for the durable integration.

## Layer-specific semantics

| Layer | Positive evidence | What it does not prove |
|---|---|---|
| Input injector | Local platform injector accepted the event batch | Target application consumed it |
| Host clipboard read | Local get_text returned | Clipboard text was sent to peer |
| Host clipboard write | Local set_text returned | Another application read the new value |
| Transport send | Local carrier accepted the complete envelope | Peer received or processed it |
| File receiver | Authenticated receiver verifies full digest and publishes | Sender knows this unless a receipt returns |
| Video/audio | Receiver-specific authenticated receipt, if added | Decode, render, playback, or photons without those observers |

Do not persist raw keystrokes, clipboard text, media payloads, file bytes, secrets, bearer tokens, or socket payloads in this journal. Use bounded labels and context digests.

## Relationship to industry systems

This work complements existing infrastructure rather than replacing it:

- Kafka documents at-most-once, at-least-once and exactly-once semantics while warning that guarantees depend on the producer/consumer and storage boundaries. Xenia must similarly name each evidence boundary rather than claim universal exactly-once behavior.
- RabbitMQ publisher confirms tell a publisher when the broker has accepted a message; consumer acknowledgements are a distinct processing boundary. Xenia should retain this distinction between TransportAccepted and PeerObserved.
- NATS JetStream adds persistence and replay to Core NATS delivery. Xenia's operation journal is not a message broker; it carries operation identity and effect-stage evidence across Xenia's authorization/revocation lifecycle.
- PostgreSQL WAL durability depends on write-ahead logging, fsync and synchronous_commit policy. Xenia must measure durable append/sync separately from in-memory admission latency and record the selected durability level.
- TUF requires persisted version/freshness metadata to detect rollback and freeze attacks. Xenia's hash chain likewise needs an independently protected head checkpoint to detect deletion of a complete valid suffix or restoration of an old valid journal.

Primary references:
- Kafka design and message-delivery semantics: https://kafka.apache.org/design/
- RabbitMQ publisher confirms and consumer acknowledgements: https://www.rabbitmq.com/docs/confirms
- NATS JetStream: https://docs.nats.io/concepts/jetstream
- PostgreSQL 18 WAL settings: https://www.postgresql.org/docs/18/runtime-config-wal.html
- TUF current specification: https://theupdateframework.github.io/specification/latest/
- NIST SP 800-193 resiliency principles: https://csrc.nist.gov/pubs/sp/800/193/final

## Benchmark programme

See benchmarks/async-effect-dispatch-v0.1.json. Its status is preregistered_unmeasured.

The primary comparisons must run on identical hardware, toolchain, OS, payload sizes and failure schedules:

- No-gate direct transport baseline.
- A deliberately naive Tokio mutex held over the entire send future (comparison only, not an acceptable implementation).
- prepare + begin + finish with the new state machine.

Measure p50/p95/p99/p999 admission latency, throughput, CPU cost per operation, memory per retained operation, and revoke-to-quiescence time. Exercise concurrency levels 1/8/32/128 and frame/audio/telemetry/file-chunk workloads. Run failure injection for revoke/begin races, send future drops, partial writes, task aborts, process kills between WAL stages, reconnect and duplicate operation IDs.

Provisional performance targets are not results: p50 gate transition <= 5 us, p99 <= 50 us, >= 100k in-memory transitions/s, and <= 1% of a 16.67 ms frame budget. Correctness targets are absolute: zero begin_dispatch admissions after revoke wins, zero automatic retries of UNKNOWN, zero duplicate operation admissions, and zero lost in-flight IDs in revocation receipts.

Report synthetic state-machine results separately from live carrier and crash/restart results. Never compare an in-memory model's latency against a broker's durable publisher-confirm latency as though they were equivalent workloads.

## Next integration gates

1. Add a durable operation-event writer with admission/attempt fsync before transport dispatch.
2. Bind the live Xenia senders to stable per-lane operation IDs and the new gate.
3. Add receiver-side authenticated observations only where the protocol actually provides them.
4. Persist and externally anchor the journal head; reject rollback and stale snapshots.
5. Add crash/restart integration tests around every WAL stage.
6. Run the preregistered baseline matrix and publish raw samples, exact commits and environment receipts.
