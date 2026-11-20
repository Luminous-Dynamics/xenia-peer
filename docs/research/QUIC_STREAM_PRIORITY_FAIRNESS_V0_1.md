# QUIC Stream Priority and Application Fairness Experiment

**Status:** Preregistered policy comparison v0.1; no live multi-stream implementation.  
**Tracking:** [#539](https://github.com/Luminous-Dynamics/xenia-peer/issues/539).  
**Related:** #526 WDRR, #529 bounded fragments, #534 fragment sender/receiver model, #538 cancellation-safe QUIC framing, #465 matched product/network benchmark.

## 1. Research question

Does a small number of Iroh/QUIC stream-priority tiers improve interactive responsiveness when combined with application-level byte fairness and bounded writes, compared with the existing single bidirectional stream?

The null hypothesis is that transport priorities provide no material improvement once Xenia's application scheduler and fragment quantum are controlled. A competing hypothesis is that coarse priorities reduce the delay of control/interactive traffic when the transport has buffered writes on multiple streams. The result may depend on when priorities are set, the amount already buffered, congestion state, RTT and peer flow-control windows.

This is an experiment, not an assumption that multistreaming or priority automatically improves QoE.

## 2. Source facts and design constraints

The repository's root lockfile pins Iroh 1.0.2. The exact `iroh::endpoint::SendStream` API exposes `set_priority(i32)`:
- higher-priority streams' locally buffered data are transmitted before lower-priority streams' buffered data;
- changing priority while data is pending may take effect only after that data is transmitted;
- many distinct priority levels can hurt performance.

The same API's `write` method is cancellation-safe and returns the written prefix length; `write_all` is not cancellation-safe. See the companion correctness fix [#538](https://github.com/Luminous-Dynamics/xenia-peer/pull/538).

RFC 9000 §§2.2–2.3:
- each QUIC stream is an ordered byte stream;
- streams can be interleaved, but there is no cross-stream byte ordering;
- QUIC does not exchange a standardized priority scheme; the application provides priority information to the implementation;
- streams still share connection-level congestion control and obey flow-control limits.

Consequences:
1. Set coarse, negotiated lane priorities before a stream starts buffering data. Do not expect priority changes to preempt already-buffered bulk bytes.
2. Retain an application scheduler. Transport priority is a local stream scheduling hint, not a fairness or deadline proof.
3. Use bounded fragments/application records so a long write cannot occupy the sender's application task indefinitely.
4. Carry sequence IDs and operation/frame identities; never infer ordering across streams from arrival order.
5. Do not call separate QUIC streams independent congestion control, dedicated bandwidth, QoS reservation or guaranteed preemption.

## 3. Candidate policies

All candidates use the same logical five lanes: Control, Video, Audio, Telemetry and Bulk.

| ID | Candidate | Stream layout | Application scheduler | Transport priority |
|---|---|---|---|---|
| P0 | Current baseline | One bidirectional stream | Global FIFO | One stream |
| P1 | Single-stream WDRR | One bidirectional stream | Byte WDRR + bounded fragments | One stream |
| P2 | Equal-priority multistream | Five logical streams | Byte WDRR | Same priority for all |
| P3 | Coarse-tier multistream | Five logical streams | Byte WDRR | Three fixed tiers |
| P4 | Fine-tier multistream | Five logical streams | Byte WDRR | Five distinct priorities |
| P5 | Strict-priority mutant | Five logical streams | Strict priority, no WDRR | Five distinct priorities |

P5 is deliberately unsafe as a control experiment: it should reveal starvation or unfairness under a continuously backlogged high-priority lane. It is not a candidate production policy.

For P3, preregister three tiers:
- High: Control.
- Medium: Audio and Video.
- Low: Telemetry and Bulk.

A later sensitivity test can reverse or split Audio/Video based on measured playout deadlines. Do not change the mapping after examining the result of a test cell.

## 4. Experimental controls

Where testing the transport-priority effect, hold fixed:
- source frames and frame dependency chain;
- resolution, capture cadence, codec, encoder settings and matched visual quality;
- bitrate and fragment/write quantum;
- lane arrival trace, operation sizes and control event timings;
- endpoint hardware/software, stream limits and flow-control configuration;
- RTT, jitter, packet loss, reordering, rate-change and cross-traffic traces;
- warm-up, run length and repetition seeds.

Use a paired design: replay the same deterministic application arrival trace and network impairment trace for each policy. Randomize candidate order within a block to avoid thermal/load drift. Publish all seeds and all rejected/failed runs.

Where transport priority is isolated, P1/P2/P3/P4 must use the same application WDRR policy and same fragment size. Use a separate factorial ablation to compare WDRR on/off and priority on/off. Do not compare a fragmented WDRR candidate against a whole-frame FIFO candidate and attribute the entire difference to priority.

## 5. Workloads and network cells

### Application workloads
1. Static 1080p60 UI with sparse control input.
2. Text-heavy desktop/UI changes.
3. Rapid pointer/keyboard interaction.
4. High-motion 1080p60 video.
5. Concurrent large file transfer.
6. All five lanes continuously backlogged.
7. Sparse control bursts during sustained video + bulk saturation.
8. Bursty telemetry, coalescing enabled and disabled.
9. Rekey/reconnect while a frame or file chunk is partially transmitted.

### Network impairment
- RTT: 5, 15, 30, 60 and 100 ms.
- Jitter: 0, 5, 15 and 30 ms.
- Random loss and burst loss as separate cells.
- Packet reordering as a separate cell.
- Media-link utilization: 50%, 75%, 90% and 100%.
- Long-lived TCP cross-traffic and concurrent equal/unequal-RTT sessions.
- Sudden capacity drop and recovery.
- Congested/delayed reverse path for ACK/flow-control feedback.
- Path change, reconnect and rekey.

Use RFC 8867/8868-style reproducible network impairment methodology, adapted to Xenia's sealed remote-interaction traffic. These RFCs do not define a remote-desktop product score.

## 6. Metrics and denominators

Do not collapse these into one score. Report each lane and each candidate with denominators.

### Latency stages
- Application queue residence.
- Scheduler selection wait.
- Writer wait / flow-control wait.
- Time to write an application fragment.
- Peer envelope/fragment receipt.
- Complete frame assembly.
- Decode completion.
- Physical input-to-photon, only using calibrated external instrumentation from #457.

Report p50/p95/p99/max and sample count. Use one-way delays only if clock synchronization is qualified; otherwise use local stage durations and RTT.

### Service/fairness
- selected bytes (not called wire bytes unless captured);
- observed wire goodput and bytes per lane;
- per-lane service lag and maximum starvation interval;
- max non-preemptible write quantum in bytes and time;
- time spent buffered per stream and aggregate;
- connection-level congestion window/pacing where instrumented;
- per-stream and connection-level flow-control stalls.

### Media/reliability
- frames complete, expired, aborted, stale and decoder-rejected;
- partial frame ever made decoder-visible (must be zero);
- codec recovery time after missing fragment/reference;
- audio late/underrun and A/V sync;
- file goodput, offset/digest resume correctness and UNKNOWN outcome duration.

### Cost
- CPU/GPU, memory high-water, reassembly high-water;
- energy per useful interaction minute;
- connection and stream counts;
- retransmission/loss/queue behavior.

## 7. Targets (proposed, not measured)

- Control p99 <= 75 ms on the qualified LAN profile at 90% media saturation.
- At least 30% control-p99 improvement over P0 on the same trace, without claiming that this alone proves physical input-to-photon improvement.
- No more than 5% matched-quality video goodput loss against the best qualified multistream baseline.
- Zero starvation for continuously eligible lanes under the preregistered application WDRR assumptions.
- Zero silently lost accepted control transitions.
- Zero incomplete/stale-reference frames presented.
- Zero reassembly or sender-queue bound violations.
- No increase in unauthorized effect acceptance or stale permit use.

A target is achieved only after exact hardware/network matched runs and a published trace corpus. Synthetic simulations and application counters are not substitutes for wire measurements or external I2P.

## 8. Statistical plan

- At least 30 independent repetitions per principal test cell where practical.
- Preregister test seeds, warm-up interval, run duration, discard criteria and all denominators before collecting comparisons.
- Use paired candidate runs on the same impairment trace.
- Publish median, p95/p99, maximum, confidence interval and full raw traces; report failed runs and missing observations.
- Do not drop bad p99 samples or cherry-pick a favorable impairment seed.
- For the primary endpoint, use control input-to-peer-receipt p99 under 90% media saturation; keep input-to-photon as a separately instrumented primary/secondary measure after #457 calibration.

## 9. Threats to validity

- Iroh implementation behavior may change across versions; cite and pin the exact API/build.
- A change to stream priority may not reorder already-buffered data.
- Connection-level congestion/flow control can dominate differences between streams.
- The operating system and Iroh task scheduling can confound application scheduling.
- Cross-stream arrival order is not guaranteed.
- Frame fragmentation changes both scheduling opportunity and overhead; isolate it from priority.
- A testbed's MTU, NIC offloads and queue discipline can materially change results.
- Product comparisons require matching capability and quality objectives, not copying vendor marketing numbers.

## 10. Claim boundary and delivery sequence

No live multi-stream priority implementation or measured improvement is currently claimed.

1. Validate the existing #538 framed-I/O fail-closed patch.
2. Complete #534 lazy fragment sender/receiver and a versioned wire contract.
3. Implement a local sender experiment harness with fixed arrival traces and priority policy adapters.
4. Implement negotiated logical streams under a versioned transport profile; set priorities before writes begin.
5. Add independent per-lane counters and connection-level transport telemetry.
6. Run local loopback + deterministic impairment tests, then physical LAN tests.
7. Compare Parsec, Sunshine/Moonlight, RustDesk and RDP only under matched conditions.
8. Publish traces, scripts, SHA digests, device/network setup and full failure denominators before any SOTA claim.
