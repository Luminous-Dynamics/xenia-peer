# Deadline-Aware Session Scheduling with Age of Information

**Status:** Research preregistration v0.1 — proposal and synthetic workload corpus only.  
**Tracking:** [Xenia #525](https://github.com/Luminous-Dynamics/xenia-peer/issues/525).  
**Related:** [#458 endpoint-stage telemetry](https://github.com/Luminous-Dynamics/xenia-peer/issues/458), [#457 physical input-to-photon traces](https://github.com/Luminous-Dynamics/xenia-peer/issues/457), [#465 matched product benchmark](https://github.com/Luminous-Dynamics/xenia-peer/issues/465), [#482 logical-stream isolation](https://github.com/Luminous-Dynamics/xenia-peer/issues/482), [#495 QUIC stream/path research](https://github.com/Luminous-Dynamics/xenia-peer/issues/495).

This document defines a testable scheduling hypothesis. It does **not** implement a scheduler, report a performance measurement, qualify the runtime, or claim superiority over commercial products.

## 1. The shift: from throughput to useful freshness

A remote session is a closed-loop interactive system. The user's experience depends on how recently the viewer can act on the newest useful host state, while preserving the exact semantics of control and authority transitions.

A byte-oriented FIFO treats all bytes as equally useful. That is false for interactive sessions:

- A screen frame that waited 300 ms in a queue may be less useful than a newer frame that is smaller.
- A key-up or mouse-button-up transition cannot be discarded like a stale frame.
- An audio packet that misses its playout deadline may be less useful than a later packet.
- A telemetry sample is normally replaceable by a newer sample.
- A file chunk must not be silently superseded; its transfer identity, offset and digest must remain reconcilable.

The proposed objective is therefore **freshness subject to semantic correctness**, not maximum throughput in isolation.

## 2. Delivery contracts

The scheduler consumes typed work items. Each item carries a lane-local monotonic enqueue tick, a maximum age/deadline where meaningful, bounded resource accounting, and stable identity where replay or reconciliation matters.

| Delivery class | Examples | Queue policy | Correctness rule |
|---|---|---|---|
| Ordered control transition | Key/button down/up, consent, revoke, rekey | Bounded FIFO with reserved service | Never silently drop, reorder, or replay an ambiguous mutation |
| Fresh visual state | Screen frames | Keep the newest decodable state; supersede stale queued work safely | Respect codec reference dependencies; do not display undecodable deltas |
| Deadline media | Audio frames | Bounded playout queue; deadline-aware admission | Late/drop/PLC outcome is explicit; no unbounded jitter buffer |
| Latest-value state | Telemetry, pointer position samples | Coalesce to newest value | Coalescing is allowed only for explicitly replaceable samples, never button/key edges |
| Durable transfer | File chunks | Bounded backpressure and resumable ordering | Stable transfer ID, chunk identity, offset/digest and reconciliation |

A queue policy is not an authorization decision. Existing host-side consent, capability, delegation and effect-owner gates remain authoritative.

## 3. Candidate scheduler

The initial policy should be a pure Rust model with deterministic inputs and no clocks, sockets, codec state or OS effects hidden inside it.

### Admission

1. Validate the item's closed delivery class and lane.
2. Check queue capacity before accepting ownership of the work.
3. Attach a lane-local enqueue tick and deadline/age budget, where defined.
4. Return an explicit disposition: accepted, coalesced, superseded, rejected-full, rejected-expired, or unsupported.
5. Preserve a stable causal sequence/operation ID for non-replaceable state transitions.

### Selection

- Preserve FIFO order inside the ordered-control class.
- Give control a bounded reserved service budget so bulk/media saturation cannot indefinitely delay it.
- Schedule audio against playout slack, with a declared minimum service share and explicit late-packet policy.
- Select the newest **decodable** video state. If a dropped reference invalidates dependent deltas, suppress the dependent chain until a valid recovery point/keyframe; never forward an undecodable delta merely to preserve frame count.
- Coalesce telemetry rather than allowing stale samples to accumulate.
- Let file transfer use residual capacity with bounded backpressure and resumable offsets.
- Use weighted/deficit fairness across eligible classes so strict priority cannot starve audio or bulk indefinitely.

The policy must distinguish *queue selection* from *transport congestion control*. QUIC streams have independent stream flow control but still share connection-level flow control and a congestion controller. More streams remove cross-stream ordered-byte head-of-line blocking; they do not create independent capacity or independent congestion control.

### Adaptation

Use separate control timescales to avoid oscillation:

- **Fast path:** supersede stale visual work, enforce audio playout deadlines, and protect control service.
- **Medium path:** adjust frame rate, quantization/bitrate and capture cadence based on queue age, receiver pressure and measured path capacity.
- **Slow path:** consider codec/profile changes only when a sustained state change justifies the switch.

Every adaptive policy needs hysteresis, bounded step sizes, a minimum dwell time, and a deterministic replayable decision trace. Missing telemetry must not be interpreted as a healthy path.

## 4. Age of Information and clock discipline

For a source whose generation time and observation time share a valid timebase, Age of Information is:

\[
\Delta(t) = t - u(t)
\]

where \(u(t)\) is the generation time of the newest update observed by the receiver at time \(t\).

A cross-host AoI measurement is valid only when the clock relationship and its uncertainty are independently established. Host and viewer monotonic clocks must never be subtracted directly. Without qualified synchronization, report only endpoint-local stage durations, queue age, sequence gaps, frame cadence, and round-trip measurements.

A local compositor callback is a presentation-submission signal, not proof that photons reached the user's eyes. Physical input-to-photon remains a separate calibrated instrument result under #457. Software timing must not be promoted into an I2P claim.

## 5. Security and authority interactions

The scheduler must preserve the authority architecture:

- It cannot grant, widen, renew or infer permission.
- A revoke observed by the local effect owner closes the corresponding effect gate independently of scheduling priority.
- Queued but not yet attempted work is cancelled or rejected according to the effect-owner contract.
- If dispatch occurred and the commit/remote outcome is ambiguous, the operation remains **UNKNOWN** until reconciled by stable operation identity.
- Reconnect and rekey do not reset operation identity, authority epochs, budgets, or sequence continuity.
- No policy optimization may cause an operation admitted under stale authority to commit after the effect owner has observed revocation.

The scheduling layer is not a second revocation engine and must not duplicate Mycelix authorization semantics.

## 6. Measurement and comparison

Compare these policies on the same endpoints, codecs, captures, workload traces, and impairment profile:

1. Existing one-stream FIFO baseline.
2. Multi-stream with bounded per-lane queues and static item-weighted service.
3. Multi-stream with byte-weighted Deficit Round Robin (WDRR).
4. Multi-stream with deadline/AoI-aware selection and starvation protection.
5. Simulation-only clairvoyant/oracle schedule as an upper bound, never as a production comparison.

The first pure Rust model currently implements candidate 3 only. Its quantum weights are provisional and have not been tuned against live network traffic. Candidate 2 remains a matched baseline to implement in the simulator; candidate 4 remains future work.

Use the synthetic workload definitions in [aoi-session-workloads-v0.1.json](../../benchmarks/aoi-session-workloads-v0.1.json). Synthetic fixtures validate policy semantics; they are not performance measurements.

### Metrics

Report separate distributions and denominators:

- Control: delivery/queue p50, p95, p99, maximum; ordered transition loss/reconciliation.
- Video: AoI only when clock-qualified; otherwise frame sequence age, local frame age, pacing, stale decode/presentation count, recovery-point wait and time to first useful frame.
- Audio: playout delay, late/drop/underrun/concealment count.
- Bulk: goodput, completion time, retransmitted/reconciled chunk count.
- Runtime: per-class queue occupancy and age, supersession reasons, memory, CPU/GPU, energy per useful delivered frame.
- Quality: matched-bitrate quality plus separate text/UI legibility and motion quality.
- Safety: unauthorized commit count, lost control transitions, unknown outcomes, reconciliation completion and evidence completeness.

Publish raw traces, configuration and workload digests, source SHA, toolchain, host/device metadata, seeds, impairment settings and confidence intervals. Keep performance, usability, safety and cryptographic assurance as separate dimensions. Do not hide trade-offs in an aggregate score.

### External comparison

Recent AoI scheduling literature also warns against equating freshness with greedy newest-first service. Jien and Kuo (October 2026) show that, in their single-base-station/multiple-terminal model, packet management combined with fair scheduling has strong competitive properties, while unfair greedy newest-message-first strategies can perform poorly. That theoretical setting is not a direct Xenia remote-session result; it motivates comparing WDRR and AoI-aware policies rather than assuming newest-first is optimal ([DOI 10.1016/j.comnet.2026.112690](https://doi.org/10.1016/j.comnet.2026.112690)).

The primary external systems remain Parsec, RustDesk, Sunshine/Moonlight and RDP under the matched methodology in #465.

Vendor-published numbers are context only. Parsec reports 7 ms added LAN latency and 97% NAT traversal success for its own test setup, and describes its BUD peer-to-peer UDP stack and hardware codec path. Neither vendor figure is a matched independent result. Sunshine's current troubleshooting guidance emphasizes path stability/consistency (latency variance and packet loss), and documents burst-induced buffer overruns when host emission exceeds a bottleneck link's drain rate. These observations motivate measuring queue age and pacing; they do not establish that one product is faster than another.

RustDesk is an important sovereignty/connectivity comparator: its official self-host documentation describes an ID/rendezvous service (`hbbs`) that attempts direct hole punching and a relay (`hbbr`) used when direct connectivity fails. It also supports operator-managed relay infrastructure. Xenia therefore needs an explicit relay-policy and metadata-visibility advantage, not just the ability to self-host.

Microsoft RDP is an important channel-architecture comparator: Microsoft's protocol documentation describes multiple virtual channels for presentation, device communication and encrypted keyboard/mouse data. Consequently, separate media/control streams are not, by themselves, a novel Xenia contribution. The stronger differentiator must be the combination of explicit recipient-bound authority, effect-stage evidence, freshness scheduling and a transparent sovereign relay policy.

## 7. Proposed targets (not achieved)

The first control hypotheses reuse #482 so the programmes do not silently diverge:

- control-event p99 no more than 75 ms under 90% media saturation;
- at least 30% lower p99 control latency than the one-stream FIFO baseline under the same saturation;
- zero silently lost or reordered accepted control-state transitions;
- bounded queues with no starvation of control/audio under sustained bulk work.

New freshness hypothesis:

- on a stable LAN, video p95 AoI no more than two source-frame periods when a newer decodable frame is available, measured only with a qualified common timebase; without one, report local/sequence-based proxies and do not mark AoI as passed.

Efficiency guard:

- no more than 5% loss of matched-quality video goodput compared with the static multi-stream policy.

All are prospective targets. A failed or missing measurement is not a PASS. Do not transfer results between commits, codecs, hardware or transport profiles.

## 8. Negative controls

The workload corpus includes:
- video saturation concurrent with key/button release;
- delta-frame dependency break after a dropped reference;
- audio arrival after playout deadline;
- bulk transfer saturating connection and stream flow control;
- telemetry flood and missing trace events;
- alternating bandwidth designed to trigger controller oscillation;
- queue starvation and priority-inversion mutants;
- rekey/reconnect with transitions queued;
- revoke racing with dispatch/commit;
- timeout after dispatch with UNKNOWN outcome;
- unsynchronized cross-host clocks.

The evaluator must fail closed or report INDETERMINATE when required telemetry, event association, clock evidence, or causal history is missing.

## 9. Standards and references

- [RFC 8836 — Congestion Control Requirements for Interactive Real-Time Media](https://www.rfc-editor.org/rfc/rfc8836.html): real-time interactive media has low-delay, semi-reliable requirements distinct from bulk transfer and must remain fair under competing traffic.
- [RFC 8868 — Evaluating Congestion Control for Interactive Real-Time Media](https://www.rfc-editor.org/rfc/rfc8868.html): provides reproducible network and traffic test scenarios; it does not define application-specific QoE metrics.
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000.html): defines multiplexed streams plus stream- and connection-level flow control.
- [RFC 10069 — Managing Multiple Paths for a QUIC Connection](https://www.rfc-editor.org/rfc/rfc10069.html): published November 2026; defines multipath path management but leaves address discovery and application scheduling unspecified.
- [Parsec technology overview](https://support.parsec.app/hc/en-us/articles/32361354307348-Overview): vendor description and self-reported LAN latency.
- [Sunshine troubleshooting](https://docs.lizardbyte.dev/projects/sunshine/v2026.319.132152/md_docs_2troubleshooting.html): packet-burst and bottleneck-buffer failure discussion.
- [RustDesk self-host documentation](https://rustdesk.com/docs/en/self-host/): operator-managed rendezvous, direct hole punching and relay fallback.
- [Microsoft RDP protocol documentation](https://learn.microsoft.com/en-us/windows/desktop/termserv/remote-desktop-protocol): multiple virtual channels for presentation, device communication and encrypted input.


## 10. V0.1 Rust policy model

The draft branch now contains a pure policy model in `crates/xenia-peer-core/src/delivery_scheduler.rs`, exported from `xenia-peer-core`. It is deliberately not connected to a live transport, codec, authorization decision, or OS effect.

The model implements:

- five typed delivery classes with separate bounded item and byte capacities;
- byte-weighted Deficit Round Robin with explicit once-per-visit quantum state and provisional quanta of 64 KiB Control, 256 KiB Video, 64 KiB Audio, 16 KiB Telemetry and 32 KiB Bulk;
- explicit queue admission, coalescing, supersession and rejection outcomes;
- monotonic sequence admission for control, audio and video frame identities;
- deadline/age pruning for video, audio and telemetry, while control and bulk are never silently aged out;
- keyframe reset and delta-reference validation, including cascading invalidation of deltas that depend on an expired reference;
- installation of a new initial decoder reference clears queued frames from the old reference context and resets the Video lane's deficit/visit state;
- an explicit invalidation method for dependent video frames after the transport proves a selected frame was not sent; ambiguous send outcomes still require session reconciliation;
- same-key telemetry coalescing and bounded bulk backpressure;
- bounded descriptor counts (4,096 maximum per lane) as well as byte caps (64 MiB maximum);
- explicit local counters and queue snapshots.

Configuration rejects zero capacities, zero age budgets, lane capacities above 64 MiB, item capacities above 4,096, byte quanta below 8 KiB, and any quantum larger than its lane's byte capacity so the configured weights cannot be silently clipped and the selection loop has a bounded visit budget.
The scheduler snapshot exposes `selected_cost_bytes` per lane, quantum-visit counts and current deficit credit. These are based on caller-supplied item-cost estimates; they are **not measured wire bytes**. Under a continuously backlogged lane with no expiry, keyframe reset, supersession or queue-drain reset, the finite scheduler model maintains:

`selected_cost_bytes_i + deficit_bytes_i = lane_visits_i * quantum_bytes_i`

For a lane whose visit has yielded to the next class, remaining deficit is below the next head item's size and therefore below the maximum eligible item cost `L_i`. At completed-visit boundaries, this yields the candidate service-lag inequality:

`selected_cost_bytes_i >= lane_visits_i * quantum_bytes_i - L_i`

This is a candidate lemma for #530, not yet an independently reviewed proof or competitive ratio. The current unit test exercises 64 queued items per lane with heterogeneous 4/8/12/16 KiB costs and unequal quanta, then checks the exact accounting identity after 100 selections. These are scheduler-accounting properties, **not real network service guarantees**: they exclude expiry, supersession, empty queues, transport blocking, write buffering, congestion control and actual remote delivery. The default quanta are hypotheses, not optimized settings. They must be compared against static item-weighted service and the AoI-aware candidate before being treated as a good operating point.

**Important scheduling boundary:** this model selects whole work items. WDRR byte accounting does not preempt a large send after the caller starts writing it. A whole 4–16 MiB frame or file chunk can still create non-preemptible sender blocking, depending on the transport writer. A bounded, frame-safe fragmentation/preemption contract is tracked separately in [#529](https://github.com/Luminous-Dynamics/xenia-peer/issues/529). Do not infer an end-to-end control p99 guarantee from this queue model alone.

Unit tests are authored for control ordering/full-queue behavior, audio/video sequence monotonicity, telemetry coalescing, keyframe dependency resets, known-unsent dependency invalidation, stale reference chains, audio deadlines, bulk retention, byte-deficit service across classes, a sustained two-item-per-class quantum-yield regression, heterogeneous packet-cost service accounting, initial-reference queue/deficit reset, quantum-versus-capacity validation, queue bounds, and invalid configuration.

A source review found and corrected an initial WDRR visit-state bug: after a lane spent its quantum exactly, it could receive another quantum on the next call without yielding, starving other lanes. The scheduler now tracks whether the current visit has already received its quantum and advances when the remaining deficit cannot cover the next head item. The new fairness regression test checks two items per lane in the expected cyclic service order. This is authored test coverage, not an executed test result.

An integration-test simulator now compares three policies over a deterministic, heterogeneous, preloaded backlog: global FIFO, per-class item round robin, and the actual `DeliveryScheduler` WDRR implementation. It uses one byte of service work per synthetic tick and reports completion in byte-time units. Tests require every policy to complete the same total work and require WDRR to improve control-tail completion against both references on this exact workload. These are regression assertions, not real-time milliseconds or network-performance results. Static item-weighted service, deadline/AoI scheduling and an offline oracle remain additional future candidates. **They have not yet been executed**: this authoring environment has no Rust toolchain, and hosted CI is not treated as evidence while queued. The branch contains no runtime transport integration and claims no measured performance or safety qualification.

## 11. Delivery plan

1. Run the authored Rust unit tests and Clippy/format checks on the exact branch head when an available local or hosted toolchain permits.
2. Extend the deterministic FIFO/item-round-robin/WDRR simulator with static item-weighted service, deadlines, packet expiry, fairness bounds, queue pressure and policy ablations from the 12-case corpus.
3. Replay the resulting scheduler policies through the #458 endpoint-stage telemetry and #457 calibrated physical I2P adapters.
4. Qualify bounded fragment/preemption semantics under #529 before connecting WDRR to large live video/file writes.
5. Integrate behind a negotiated multi-stream profile only after baseline semantics and exact-head evidence are frozen.
6. Compare Parsec, RustDesk, Sunshine/Moonlight and RDP under #465's matched measurement methodology.

**Current evidence state:** pure Rust policy model, deterministic unit tests and a synthetic comparison harness are committed to the draft branch; no Rust test execution, CI pass, hardware result, external product comparison, live transport integration, or production qualification is claimed.
