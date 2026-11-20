# Bounded Frame Fragmentation and Reassembly for Xenia

**Status:** Receiver-side pure Rust reference model v0.1; no wire-format or live transport change.  
**Tracking:** [Xenia #529](https://github.com/Luminous-Dynamics/xenia-peer/issues/529).  
**Related:** [#525 WDRR policy](https://github.com/Luminous-Dynamics/xenia-peer/issues/525), [PR #526 scheduler model](https://github.com/Luminous-Dynamics/xenia-peer/pull/526), [#482/#495 multistream work](https://github.com/Luminous-Dynamics/xenia-peer/issues/482), [#457 physical I2P](https://github.com/Luminous-Dynamics/xenia-peer/issues/457), [#458 endpoint telemetry](https://github.com/Luminous-Dynamics/xenia-peer/issues/458).

## 1. Why fragmentation is the next required layer

The WDRR policy in PR #526 schedules whole work items. It does not preempt an async writer after a large frame/chunk write begins. A large encoded frame or file chunk can therefore still create non-preemptible sender blocking.

The transport standard has a few details that shape the solution:

- QUIC streams are independent ordered byte streams. Data from different streams may be interleaved, but QUIC provides no ordering between streams. Stream prioritization is an application/implementation responsibility ([RFC 9000, §§2.2–2.3](https://www.rfc-editor.org/rfc/rfc9000.html)).
- QUIC DATAGRAM frames are not fragmented. The extension's frame size is bounded by the negotiated transport parameter and the path MTU; an application that needs larger payloads must fragment them itself. DATAGRAM frames use the connection congestion controller and may be dropped when the receiver cannot process/store them ([RFC 9221, §§3, 5](https://www.rfc-editor.org/rfc/rfc9221.html)).
- QUIC senders should pace in-flight packets based on congestion-controller feedback; unpaced bursts can cause queue build-up and loss ([RFC 9002, §7.7](https://www.rfc-editor.org/rfc/rfc9002.html)).
- Direct Quinn 0.11.12 API documentation says `SendStream::write` is cancellation-safe, while `write_all` is not: a cancelled whole-buffer write may already have written a prefix. Xenia must verify the same behavior against the actual pinned Iroh/Quinn adapter/version before implementation ([Quinn SendStream docs](https://docs.rs/quinn/latest/quinn/struct.SendStream.html)).

These facts rule out treating “smaller frame” or “more streams” as a sufficient design. We need a versioned application-fragment envelope, bounded reassembly, a sender that yields between fragments, and precise treatment of partial/ambiguous writes.

## 2. Candidate transport profiles to compare

### A. Ordered QUIC streams with bounded application fragments

Use separate logical streams for control, video, audio and bulk where the negotiated profile supports them. Video and bulk writes are split into explicit application records. The sender schedules one bounded write quantum, then yields to the other eligible lanes.

Advantages:
- per-stream reliability and ordering;
- control bytes do not wait behind video bytes in a different stream's ordered offset space;
- resumable/digest-verified file transfer stays on a reliable lane.

Limitations:
- streams share connection-level congestion control and pacing;
- a large `write_all` can still monopolize application scheduling and is not cancel-safe in Quinn 0.11.12;
- bytes within one stream remain ordered, so a lost video fragment may delay later bytes in that video stream.

### B. QUIC DATAGRAM application fragments for real-time media

Split video frames into individually authenticated datagrams, each below the negotiated path-dependent DATAGRAM payload limit after envelope overhead. Reassemble only while every fragment can still arrive within the frame's usefulness window. Drop incomplete/expired frames and dependent deltas until a decodable recovery point.

Advantages:
- no QUIC stream byte-offset head-of-line blocking within the datagram lane;
- receiver can discard stale partial frames rather than requiring reliable retransmission;
- independent fragments can arrive out of order.

Limitations:
- no QUIC-layer fragmentation or delivery guarantee;
- loss of any required fragment may discard the frame;
- still shares the connection congestion controller;
- application must bound buffers and use frame deadlines/codec dependency metadata.

### C. Hybrid

Use reliable streams for control and bulk, and compare ordered-stream fragments versus DATAGRAM fragments for video/audio. This is a candidate, not an assumed winner. It must be negotiated and must have a deterministic fallback when DATAGRAM support or a sufficiently large path payload is unavailable.

## 3. Receiver reference model

The pure Rust model is in `crates/xenia-peer-core/src/frame_reassembly.rs`, exported by `xenia-peer-core`. It does not change `RawFrame`, the current lane envelope, or any deployed wire format.

Every fragment descriptor binds:
- authenticated Xenia session fingerprint;
- key epoch and frame ID;
- timestamp, dimensions and pixel/codec format;
- zero-based fragment index and total fragment count;
- declared complete-frame length;
- BLAKE3 digest of the complete encoded payload;
- fragment payload bytes.

The outer negotiated sealed transport must authenticate the fragment envelope. The BLAKE3 frame digest establishes assembled-payload consistency; it is not a substitute for AEAD, sender signature or authorization. The reassembler accepts only video/pixel formats (RGBA8, BGRA8, H.264, VP9, Passthrough and HDC); audio, telemetry and session-control PixelFormat variants are explicitly rejected before reservation.

The receiver accepts out-of-order fragments and only exposes a frame after:
1. every fragment index is present exactly once;
2. immutable metadata agrees across fragments;
3. accumulated length exactly matches the declared full-frame size;
4. the assembled BLAKE3 digest matches.

Exact duplicate fragments are idempotent. Conflicting duplicate bytes or metadata invalidate that frame. A frame is never decoder-visible in partial form.

## 4. Strict resource and replay bounds

Hard maxima are enforced even if a caller supplies a larger configuration:

| Resource | V0.1 hard maximum |
|---|---:|
| In-flight incomplete frames | 8 |
| Reserved full-frame bytes | 64 MiB |
| One encoded frame | 16 MiB |
| One application fragment | 64 KiB |
| Total fragment descriptors | 4,096 |
| Fragments per frame | 1,024 |
| Recent completed/expired/aborted frame tombstones | 2,048 |

The receiver reserves the *declared total frame size* when the first fragment arrives, rather than only counting bytes received so far. This prevents several incomplete frames from overcommitting future reassembly memory.

Incomplete frames expire using receiver-local monotonic ticks. Source-host timestamps and cross-host clock comparisons are not used. Expiry, abort, conflict, completion and digest failure all release reservations. A bounded terminal cache rejects late fragments for completed/expired/aborted/invalid frames; downstream frame-ID/freshness checks remain necessary after old tombstones age out.

On rekey, all incomplete assemblies and terminal IDs from the previous epoch are cleared. The key epoch is part of the assembly identity because Xenia frame IDs may reset on rekey.

## 5. Sender contract still required

This receiver model does not prove sender preemption. The eventual sender must:

- use an explicit negotiated fragment size/quantum;
- yield the application scheduler after each bounded fragment write;
- avoid one whole-frame `write_all` path when cancellation or cross-lane fairness matters;
- track partial progress and operation ID per frame;
- never reinterpret an ambiguous write result as a known-not-sent frame;
- never present a partial frame;
- bind every fragment to session, key epoch, frame ID, index/count, total length, metadata and digest;
- discard partial frame state on deadline, stream reset, reconnect, rekey or explicit abort;
- preserve codec reference dependencies until a new recovery point;
- enforce both local receiver memory limits and negotiated transport frame limits.

For DATAGRAM, `max_fragment_bytes` must be computed from the negotiated `max_datagram_frame_size`, path/UDP payload ceiling and envelope overhead; it must not be set to the 64 KiB stream-fragment default. For streams, the application record framing is explicit because QUIC stream frame boundaries are not visible to the receiver.

## 6. Adversarial corpus and tests

[frame-fragment-reassembly-v0.1.json](../../benchmarks/frame-fragment-reassembly-v0.1.json) contains 16 deterministic cases:

- ordered and out-of-order completion;
- exact duplicate idempotency;
- conflicting duplicate and metadata attacks;
- frame digest corruption;
- wrong session and key epoch;
- rekey with an incomplete frame;
- frame, aggregate byte and aggregate descriptor exhaustion;
- hard config limit bypass attempt;
- local clock regression;
- expiry and late-fragment replay;
- abort and late-fragment replay;
- overlong fragment and declared-size overflow.

The source currently has 20 deterministic unit tests authored. No Rust test execution is claimed.

## 7. Benchmark programme

Compare:
1. one whole-frame write on a single ordered stream;
2. whole-frame writes on separate logical streams;
3. bounded stream-fragment writes scheduled across lanes;
4. DATAGRAM frame fragments with deadline/drop semantics;
5. hybrid stream/datagram profile.

Use identical endpoint hardware, capture/codec settings, resolution, bitrate/quality, transport, RTT, packet-loss and jitter traces. Include 90–100% media saturation and concurrent large file transfer.

Report separately:
- maximum non-preemptible application send quantum;
- control queue wait, send-buffer admission wait and peer delivery;
- p50/p95/p99/max control latency;
- frame completion/drop and stale-frame rate;
- reassembly memory high-water and descriptor high-water;
- decode recovery after partial-frame loss;
- video goodput/quality and audio late/underrun rates;
- file-transfer throughput/resume correctness;
- connection-level congestion/pacing and per-lane fairness;
- physical input-to-photon only from calibrated #457 instrumentation.

Proposed targets remain hypotheses: control p99 <=75 ms under 90% media saturation on the qualified LAN profile, >=30% p99 improvement over the matched one-stream whole-frame baseline, <=5% matched-quality video goodput loss versus multistream whole-frame writes, zero incomplete frames presented, zero reassembly-cap violations and zero silent control loss. These are not measured results.

## 8. Industry positioning and claim ceiling

Sunshine documents burst-induced packet loss when host emission exceeds the bottleneck path's drain rate, motivating a separate pacing/queueing measurement ([Sunshine troubleshooting](https://docs.lizardbyte.dev/projects/sunshine/v2026.214.224301/md_docs_2troubleshooting.html)). QUIC's stream and datagram mechanisms are primitives, not complete remote-session scheduling systems. Xenia's differentiator must be the measured combination of bounded non-preemptible work, codec-aware frame expiry, fairness, recipient-bound authority and effect-stage evidence—not fragmentation alone.

**Current evidence state:** receiver-side reference model, bounded config, replay tombstones, source tests and synthetic corpus are authored/read back. No compilation, CI, live transport/wire integration, network benchmark, hardware result, decoder presentation result, or SOTA superiority is claimed.
