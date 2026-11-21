# Matched External Interaction Benchmark v0.1

**Status:** Preregistered experiment; no comparative measurements have been run.  
**Tracking:** [#543](https://github.com/Luminous-Dynamics/xenia-peer/issues/543).  
**Purpose:** Independently compare interactive response, visual quality, reliability, resource cost and assurance properties across remote desktop/game-streaming products.

## 1. The competitive question

Xenia should not compete solely on RTT, average encode/decode, or vendor overlay numbers. The useful outcome is the time between a real client input and the corresponding visible response on the client's display, under equivalent hardware, visual quality and network conditions.

The central endpoint is **external client-input-to-client-photon latency**. The benchmark decomposes it into stages where instrumentation permits:
- physical/input-actuator event;
- client input capture and encode;
- host network receipt;
- host input-injector return;
- host application-visible response;
- host capture;
- encode;
- wire receive completion;
- client decode;
- render queue;
- display photon transition.

A stage is an observable boundary, not a stronger claim than the instrument proves. In particular, platform injector return does not prove the target application consumed an event. A local clipboard API return does not prove another process read the clipboard.

## 2. Industry reference points (not matched results)

### Parsec
- Parsec's [Overview](https://support.parsec.app/hc/en-us/articles/32361354307348-Overview) advertises approximately 7 ms of additional latency on its own wired LAN test setup.
- Its [Troubleshooting Lag, Latency and Quality](https://support.parsec.app/hc/en-us/articles/32381352822804-Troubleshooting-Lag-Latency-and-Quality-Issues) guide recommends keeping encode and decode below 15 ms per frame at 60 FPS and describes network latency as a separate overlay measure.
- Its [Connectivity Requirements](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements) documents UDP P2P, relay alternatives and recommended 1080p60 bandwidth.

These are Parsec-specific vendor statements and operational guidance. They are not a same-hardware, same-workload independent comparison against Xenia.

### Sunshine + Moonlight
- [Moonlight's FAQ](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions) distinguishes receive, decode, frame queue and render latency. It explicitly warns that similarly named metrics from different clients may not measure the same thing and recommends external testing hardware for accurate system latency.
- [Sunshine troubleshooting](https://github.com/LizardByte/Sunshine/blob/master/docs/troubleshooting.md) recommends independent packet-loss/jitter testing and explains burst/queue overrun risks when a sender emits each 60 FPS frame in a short burst.

This is a strong reference implementation for open remote game streaming, but its application telemetry is not a substitute for the external endpoint.

### Microsoft RDP
- [Microsoft Learn: Optimization of RDP Traffic](https://learn.microsoft.com/en-us/windows-365/enterprise/optimization-of-rdp) describes direct UDP and TURN-relayed UDP paths as well as TCP alternatives in Windows 365/AVD contexts.
- Measure the route actually negotiated. Do not assume RDP always uses a single transport, and do not collapse an enterprise productivity workload into an unfair gaming-streaming leaderboard.

### Transport standards
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html): QUIC streams are independently ordered; there is no cross-stream ordering guarantee.
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html): QUIC DATAGRAM frames are unreliable, can be dropped, and still use the connection congestion controller.

QUIC streams or DATAGRAM do not, by themselves, create bandwidth reservation, uncongested priority, or end-to-end deadlines.

## 3. Experimental arms

| ID | System | Role |
|---|---|---|
| X0 | Xenia current single-stream | Baseline |
| X1 | Xenia single-stream WDRR + bounded fragments | Application scheduling control |
| X2 | Xenia multistream equal priority + WDRR | Stream multiplexing ablation |
| X3 | Xenia multistream coarse priority tiers + WDRR | Candidate transport scheduler |
| X4 | Xenia multistream fine priority levels + WDRR | Priority granularity ablation |
| S0 | Sunshine host + Moonlight client | Open streaming comparison |
| P0 | Parsec host + client | Commercial low-latency comparison |
| R0 | Microsoft RDP | Separate enterprise/productivity comparison |

Use matched endpoint hardware and input/display instrumentation per comparison block. If a product requires a different OS, codec, or feature, record the incompatibility and create a separate comparison block. Never silently compare unmatched capabilities.

## 4. Primary endpoints

### Primary: external input-to-photon
A hardware input actuator or electrical trigger creates a known input edge. A photodiode or high-speed camera detects the corresponding pixel transition on the client display. A shared acquisition clock captures both. Report:
- p50, p95, p99, maximum;
- sample count and invalid/missed trigger count;
- trigger-to-display calibration uncertainty;
- display refresh interval and phase;
- test application response distribution.

Where practical, use a microcontroller USB HID actuator and a photodiode connected to the same logic analyzer/oscilloscope. A high-speed camera can be a cross-check, not the only measurement when photodiode timing is available.

### Stage latency
Report independently:
- client input capture;
- network one-way or RTT only if clock synchronization uncertainty is qualified;
- host receive-to-injector return;
- host app event-to-visible-host-frame;
- capture-to-encode;
- encode;
- receive assembly;
- decode;
- render queue;
- scanout/photon.

Never add stage medians to claim an end-to-end percentile. Never use round-trip ping as a substitute for input-to-photon.

### Visual and interaction fidelity
- Matched-quality and matched-bandwidth arms must both be run.
- For natural video, report VMAF plus SSIM/PSNR and source/version/encoder settings; publish raw clips.
- For UI/text, use deterministic reference scenes and report pixel-region difference, text legibility/recognition error, chroma-edge fidelity and stale/partial updates.
- Count lost, duplicated, reordered, stale and expired control events.
- A test application can echo a sequence number into its UI to distinguish host application response from the host injector returning.

## 5. Proposed targets (not results)

These are engineering targets for the first qualified profile, not current Xenia measurements and not a claim that any product already satisfies an equivalent condition.

### Wired 1080p60 LAN, same endpoints
- Input-to-photon: p50 <= 12 ms, p95 <= 20 ms, p99 <= 30 ms.
- Host hardware encode stage p95 <= 8 ms where the chosen hardware encoder and scene allow it.
- Client decode stage p95 <= 8 ms where the chosen decoder and scene allow it.
- Control-event loss: 0 accepted transitions silently lost.
- Incomplete/stale frame presentation: 0.
- Clean-LAN frame loss target: <0.1%.

### 90% bottleneck utilization, video + bulk + interactive control
- Input-to-photon: p95 <= 25 ms, p99 <= 40 ms.
- Control p99 at least 30% better than X0, without more than 5% matched-quality video goodput loss against the best qualified Xenia candidate.
- No continuously eligible WDRR lane starved under the preregistered scheduler assumptions.
- No unbounded sender queue, stream buffer or reassembly memory growth.
- Revoke-to-local-effect-quiescence p99 <= 20 ms for synchronous local effect owners, measured separately; do not generalize this to remote peers.

### Impaired path
- At the declared loss/jitter profile, target <1% frame loss with bounded stale-frame age and no incomplete frame presentation.
- Every accepted control transition is either applied at the local owner, explicitly rejected, or retained as UNKNOWN with a reconciliation path. No silent discard.
- A reconnect/rekey does not replay a stale input or clipboard operation.

### 120 Hz profile
Define its own 8.33 ms frame interval, instrumentation and quality envelope. Do not simply scale 60 Hz targets or claim a 120 Hz win based on average frame rate.

## 6. Test matrix

### Endpoint and content profiles
1. 1080p60 static UI, pointer echo.
2. 1080p60 text-heavy editor and scrolling.
3. 1080p60 typing and key transitions.
4. 1080p60 high-motion video/gameplay.
5. 1440p120 high-motion (where all products in the block support it).
6. Clipboard read/write under concurrent video and control.
7. Bulk file transfer under concurrent interaction.
8. Rekey/reconnect while data is queued.
9. Local revoke during input/clipboard operation.
10. NAT direct path and relay path when supported by the candidate.

### Network cells
- RTT: 1, 5, 15, 30, 60, 100 ms.
- Jitter: 0, 1, 5, 15, 30 ms.
- Random loss and burst loss as separate conditions.
- Packet reordering and reverse-path congestion.
- Bottleneck utilization: 50, 75, 90, 100%.
- Capacity step-down and recovery.
- Long-lived TCP cross-traffic.
- Equal-RTT and unequal-RTT competing sessions.
- Direct P2P, relay/TURN and enterprise proxy/bypass cells where comparable and permitted.

Run both symmetric and asymmetric capacity. Record path MTU, NIC offloads, queue discipline, Wi-Fi band/channel or wired link, and any VPN/SWG.

## 7. Controls and statistical plan

- Same host/client hardware, OS image/build, GPU driver, display model, refresh rate, input device/actuator and workload trace in each paired comparison block.
- Match visual quality first, then repeat with a fixed network bandwidth ceiling. Publish both.
- Randomize product order within a test block to reduce thermal and background-load bias.
- Pin product versions and all settings, and capture configuration files.
- At least 30 independent repetitions per principal cell where practical; each run contains a preregistered input sample count.
- Report percentiles, maximum, confidence intervals, calibration uncertainty and all denominators.
- Retain disconnects, failed setup, dropped sessions and missing measurements in a separate failure table; do not cherry-pick successful runs only.
- Publish raw trigger traces, photodiode/camera source, network impairment seed, packet captures where lawful, test content hashes, binaries/build IDs and scripts.
- Do not compare vendor overlay fields as if they had equivalent start/end definitions.
- Keep endpoint-local stage durations separate from one-way delay unless clock offset and drift are measured.

## 8. Security / sovereignty scorecard (not a latency score)

Compare each product on:
- authentication and session establishment;
- transport encryption and key lifecycle;
- direct P2P vs relay behavior and metadata exposure;
- permission granularity for screen, input, clipboard, file transfer, audio and telemetry;
- revoke semantics and local effect-owner ordering;
- clipboard content retention and direction controls;
- file transfer bounds, verification and no-clobber publication;
- evidence export, privacy, auditability and operator-controlled retention;
- self-hosting, relay sovereignty, offline behavior and update/supply-chain transparency.

Do not collapse these dimensions into a single security number without an explicit weighting and threat model. A product with more features is not automatically safer; a product with a tamper-evident log is not automatically truthful.

## 9. Xenia's proposed paradigm shift

Conventional remote desktop telemetry tends to expose separate averages: encode, decode, ping, queue, and packet loss. Xenia should build a **causal interaction receipt chain**:

`ClientInputID -> AuthorizationAdmitted -> HostInputOwnerInvoked -> PlatformAccepted/Unknown -> AppEchoObserved -> HostFrameID -> ClientFrameDecoded -> PhotonTransition`

Only attach a stage after the actual owning subsystem reports it. Each receipt includes operation/session identity, monotonic stage sequence, time domain, and privacy-preserving evidence digest. Never include raw input, clipboard text, file bytes, or screen/audio payloads.

The chain should make it possible to answer:
- Did we admit the operation?
- Was the local effect owner invoked?
- Did the local owner return a defined commit result?
- Did the receiver acknowledge it?
- Was an application-level echo observed?
- Did a corresponding frame reach the client display?

Missing proof remains missing; an asynchronous timeout becomes UNKNOWN, not a guessed failure or success. This is a stronger integrity/evidence model, not a substitute for low latency or a claim that all remote outcomes are observable.

## 10. Claim boundary and execution sequence

1. Use #457/#458 to qualify external timing and endpoint telemetry.
2. Publish X0 baseline traces before tuning X1-X4.
3. Validate test content and actuator repeatability on one open baseline (Sunshine/Moonlight) before adding commercial systems.
4. Add Parsec under matched endpoint hardware and its supported connection mode.
5. Add RDP in a separate productivity/enterprise block with direct and relayed path labels.
6. Compare Xenia scheduler and transport policies by controlled ablation.
7. Publish raw data, scripts, versions and all failed runs.
8. Seek independent replication before SOTA or superiority claims.

**Current status:** no comparative hardware runs, external input-to-photon measurements, or superiority results are claimed by this document.
