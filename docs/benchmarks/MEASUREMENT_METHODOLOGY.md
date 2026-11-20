# Xenia Measurement Methodology v0.1

Status: proposed, pre-measurement protocol
Prepared: 2026-11-16
Scope: remote-session streaming, input responsiveness, transport congestion, codec quality and resource use.

This document defines what Xenia's benchmarks mean and how to collect them. It is written before publishing results so the method cannot be adjusted after seeing the numbers. No results are asserted here.

## 1. Measurement claims and vocabulary

Do not use one latency number to describe several different stages.

| Metric | Start | Stop | What it establishes |
|---|---|---|---|
| Input-to-photon (I2P) | Physical viewer-side input actuator closes | Photodiode detects the corresponding changed pixels on the viewer display | Actual end-to-end interaction latency including peripheral, software, network, rendering, scanout and pixel response |
| Input-to-host-injection | Viewer event is physically/programmatically generated | Host OS input backend confirms injection | Input path up to OS injection; not user-visible response |
| Input-to-first-correct-frame | A uniquely identified input is issued | Client first presents a frame containing the expected state change | Software-observed response; useful for regression, but not physical I2P |
| Capture-to-present age | Host capture timestamp | Client display/presentation timestamp | Frame freshness only when both clocks are demonstrably comparable |
| Capture-to-send | Host capture completion | Host transport handoff | Host-side pipeline queue/encode cost |
| Receive-to-present | Client last packet needed for a frame | Client submits or displays decoded frame | Client-side network/decode/presentation cost; a present callback is not a photon |
| Control delivery latency | Sender emits a control message | Receiver authenticates and accepts it | Control-plane transport and verification latency |
| First-authorized-frame time | Consent decision is committed | First authorized frame is physically or software-observed at viewer | Startup/consent experience; report human deliberation separately |

The phrase input-to-photon is reserved for physical measurement. Software timestamps, a host ACK, a decoder callback, a present() return, or a browser frame callback cannot independently establish photon time.

For multi-host one-way latency, do not subtract monotonic timestamps from unsynchronized clocks. Either use a validated shared clock (e.g. PTP with measured offset and drift) and report clock uncertainty, or report endpoint-local segments and round-trip measurements instead. Never silently assume wall clocks are synchronized.

## 2. Physical input-to-photon bench

### 2.1 Preferred method: hardware input trigger + photodiode

Use a small measurement controller (e.g. a USB-capable MCU) with:
- a USB HID interface that generates a deterministic click/key event to the viewer machine;
- a hardware timer/counter with at least 1 MHz resolution;
- a photodiode or fast phototransistor attached to the viewer display;
- a comparator/ADC path with a calibrated transition threshold;
- a serial or USB data channel to export raw trigger/detection ticks and calibration metadata.

The same MCU clock timestamps the actual HID electrical trigger and the detected luminance transition. This avoids cross-host software clock subtraction.

The remote test application should toggle a known patch between two luminance states only after receiving the intended remote input. Use an unpredictable per-trial marker (e.g. a randomized bright/dark pattern ID) so stale or unrelated frames cannot be counted as the response. The instrument event ID must bind the trigger, expected remote state transition and sensor edge.

NVIDIA LDAT is an established reference for luminance-sensor system-latency measurement. Xenia should support equivalent raw evidence even when using an open hardware implementation. Do not claim the open instrument is equivalent until its timing, linearity, trigger jitter and sensor response are calibrated against a trusted reference.

### 2.2 Secondary method: synchronized high-speed camera

A high-speed camera can record both an input-trigger LED and the target display patch in the same exposure sequence. Prefer at least 1,000 frames/s for approximately 1 ms temporal quantization; 240 frames/s has approximately 4.17 ms frame spacing and is too coarse for fine sub-frame comparisons. Report camera frame rate, exposure, rolling/global shutter, trigger synchronization and quantization.

A camera is a useful cross-check, not a reason to report precision finer than its temporal resolution. A photodiode is preferred for repeated high-resolution measurement.

### 2.3 Trial procedure

For each host/client/transport/codec/network condition:

1. Fix and record display resolution, refresh, VRR state, HDR, pixel overdrive, scaling, compositor, capture backend and sensor location.
2. Warm up the session and encoder/decoder for at least 30 seconds. Record the warm-up separately.
3. Calibrate the sensor threshold with known light/dark transitions before and after the run. Reject the run if calibration drift exceeds the pre-registered tolerance.
4. Generate at least 300 valid input trials per condition. Randomize inter-trial delay to avoid phase-locking all inputs to a refresh boundary.
5. Run separate top-, centre- and bottom-of-display sensor placements when scanout position matters. Never compare different sensor positions without labeling them.
6. Include a local-control baseline on the same viewer hardware/display and a remote-session result. Report both raw distributions and paired differences; do not subtract a baseline and present the remainder as an observed network delay.
7. Export every raw trigger timestamp, sensor timestamp, event ID, detected transition, rejected trial and calibration record.

For a formal performance claim, target at least 1,000 valid trials per condition after the initial 300-trial pilot. Report p50, p95, p99, maximum, sample count, confidence intervals and the full empirical CDF. Use a declared bootstrap seed/method for confidence intervals. Do not discard outliers without a pre-registered exclusion rule and a count.

### 2.4 Attribution and controls

Input-to-photon includes peripheral/USB input, viewer event handling, encryption, transport, host verification/injection, application response, capture, encode, network return, decode, presentation, scanout and pixel response. This is the user-facing metric.

Use software trace points to explain regressions, not replace the physical end-to-end measure. Instrument the same event/frame IDs through:
- viewer physical/programmatic event receipt;
- input serialization and sealed-envelope handoff;
- host authenticated receive and authorization decision;
- OS injection completion;
- application-visible state marker;
- capture timestamp and frame ID;
- encoder queue/complete;
- transport send/receive;
- decoder completion;
- compositor/present submission.

If an event cannot be causally associated with the displayed marker, mark the trial invalid or failed; never infer a match from the next arbitrary frame.

## 3. Frame freshness, pacing and startup

### 3.1 Frame age

A capture timestamp generated on the host and a display timestamp generated on the client are on different clock domains. Valid choices:

- PTP-synchronized clocks with offset and drift measured before/after the run, including uncertainty in the reported frame-age bound;
- a same-host loopback experiment where timestamps share the same monotonic clock;
- endpoint-local durations (capture-to-send and receive-to-present) reported separately, without inventing one-way network delay.

Record frame ID, capture event, encode completion, send, receive, decode and presentation. Report missing/duplicate/out-of-order frames, dropped frames and stale frames separately.

### 3.2 Frame pacing

Report inter-present intervals, not just average FPS. Include:
- displayed FPS and p50/p95/p99/max frame interval;
- frames dropped by capture, encoder, transport, decoder and compositor when observable;
- frame freezes and freeze duration;
- queue age/high-water/capacity for every bounded stage;
- keyframe and rekey-induced stalls;
- capture damage/no-damage behavior.

A low mean frame interval cannot hide periodic long stalls.

### 3.3 Startup and consent

Measure separately:
- process start to listener-ready;
- connection start to authenticated handshake completion;
- consent request shown to user;
- user decision time;
- approval commit to capability availability;
- capability availability to first authorized frame.

Do not include human deliberation time inside a transport startup score. Denial, timeout and revocation must be reported as explicit outcomes, not dropped from the denominator.

## 4. Transport and congestion experiments

Xenia should follow the evaluation discipline in RFC 8836 and RFC 8868. Interactive media is freshness-oriented: late frames may be useless. The sender must adapt quickly, minimize self-induced latency and remain fair to competing flows.

### 4.1 Reproducible network profiles

Use a dedicated isolated test network. Record qdisc/rule version, link capacity, RTT, jitter distribution, random seed, loss model (independent or burst), reordering, queue limit and whether each direction is shaped symmetrically. Do not apply tc netem or firewall changes to a user's production interface as part of routine benchmark preparation.

Run at least:
- clean LAN;
- regional RTT with low jitter;
- 80 ms RTT with 1% loss and TCP cross-traffic;
- 100 ms RTT, 2% loss and constrained bandwidth;
- capacity step-down and step-up;
- short and long outages;
- NAT/reconnect and relay fallback;
- simultaneous video, audio, input, clipboard/file operations where explicitly authorized.

### 4.2 Packet-derived metrics

Log per-packet send/receive information or endpoint-equivalent transport telemetry. Report:
- sending rate, receiving rate and goodput (200 ms intervals);
- packets/bytes sent and received;
- packet delay, jitter, loss and discarded packets;
- retransmission/FEC overhead and post-repair loss where used;
- stream self-fairness and fairness against TCP cross-traffic;
- convergence time after startup/capacity changes/new flows;
- send-rate oscillation and queue-delay buildup;
- link utilization where interpretable.

For fairness, report relative goodput over multiple intervals (e.g. 1, 5 and 20 seconds) and compare against a same-bottleneck fair-queue reference. Do not require a universal 50/50 split between real-time and bulk classes; report the priority policy and its tradeoffs. Xenia must not starve unrelated TCP traffic.

### 4.3 Lane isolation

Exercise video at >=90% of available bottleneck capacity, while measuring control and input p95/p99. Repeat with an independent long-lived TCP bulk flow. Verify:
- control and input queues remain bounded;
- a video backlog cannot block consent, authorization, rekey or revocation;
- stale video is discarded rather than delivered late;
- TCP gets a documented fair share;
- file transfer is throttled/scheduled as bulk traffic;
- audio preserves its bounded jitter/latency policy.

Run a network step-down from 30 Mbps to 5 Mbps. Measure time to stable rate/FPS, queue age, stale-media drops, control latency and recovery. A proposed target is adaptation convergence within 2 seconds, but record actual values and oscillation rather than only pass/fail.

## 5. Codec and visual quality

### 5.1 Matched-quality comparisons

Compare passthrough, H.264, HEVC, AV1 and HDC only where a real implementation and hardware/software path exists. For each run record:
- exact codec/profile/level, encoder/decoder and versions;
- hardware vs software encode/decode;
- chroma subsampling, bit depth, HDR/SDR and color space;
- bitrate target and measured send/receive bitrate;
- keyframe interval, rate-control mode, encoder settings;
- capture backend, resolution, refresh, GPU and driver;
- host/client CPU/GPU, RSS, power/energy where available.

Sweep 5, 10, 15, 20, 25 and 30 Mbps at equivalent visual-quality targets. A bitrate comparison is invalid if the compared outputs are not acceptably equivalent.

### 5.2 Desktop-specific visual quality

VMAF/PSNR/SSIM can be useful on suitable content, but a single video perceptual score is not a sufficient desktop-quality gate. Text, terminal glyphs, small UI edges, thin lines, gradients, cursor shape and color accuracy matter.

Use a deterministic screen corpus containing:
- terminal/editor text at multiple sizes and font weights;
- syntax highlighting and small glyph distinctions;
- scrolling and selection;
- thin edges, diagrams and high-contrast controls;
- dark gradients and color ramps;
- high-motion video/animation;
- mixed desktop workloads.

Report full-reference image metrics plus a task-based text legibility test (human transcription of seeded strings, character error rate and completion time). Treat human task performance and pixel metrics as separate outcomes.

### 5.3 Energy and resource efficiency

Record host and client CPU/GPU utilization, memory/RSS, allocation rates where available, encoder/decoder engine, and energy per minute/session where a calibrated power meter or trustworthy hardware telemetry is available. Distinguish system-wide power from process-attributable power. Do not infer energy efficiency from CPU percentage alone.

## 6. Statistical and provenance requirements

Each run records:
- exact repo commit(s), dirty-tree state, build flags and harness version;
- host/client models, OS/kernel/compositor, CPU/GPU/driver, display details;
- transport, direct/relay path, peer configuration and feature flags;
- exact corpus digest, network recipe/seed, warm-up and duration;
- clock source, timebase, offset/drift/uncertainty;
- sample count, rejected sample count and exclusion rules;
- p50/p95/p99/max, confidence interval method and raw data digest;
- all tool failures, missing metrics and environment errors.

Use enough trials for tail estimates; 300 physical I2P trials is the pilot floor, with 1,000 preferred. Repeated runs on separate sessions/days are needed to characterize between-run variance. Keep raw sample files and plots, not only summary numbers.

Use the status vocabulary PASS / FAIL / BLOCKED / ENVIRONMENT_FAILURE. Missing data is not zero. A tool failure or uncalibrated instrument cannot produce PASS. The benchmark runner currently prepares and validates evidence packets only; it does not yet provide the physical or transport measurement adapters described here.

## 7. Reference methods

- NVIDIA LDAT: https://developer.nvidia.com/nvidia-latency-display-analysis-tool
- NVIDIA PC latency measurement overview: https://developer.nvidia.com/blog/understanding-and-measuring-pc-latency/
- RFC 8836 — congestion-control requirements: https://www.rfc-editor.org/rfc/rfc8836.html
- RFC 8868 — interactive media congestion-control evaluation metrics: https://www.rfc-editor.org/rfc/rfc8868.html
- W3C WebRTC Stats: https://www.w3.org/TR/webrtc-stats/
- Open-source hardware latency tester (BLT): https://github.com/jtl06/BLT

The references describe measurement tools/protocols, not Xenia results. Validate instrument calibration independently before comparing products.
