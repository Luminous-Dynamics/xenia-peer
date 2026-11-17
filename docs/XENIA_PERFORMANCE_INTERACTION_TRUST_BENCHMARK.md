# Xenia Performance, Interaction, and Trust Benchmark v0.1

**Status:** proposed qualification programme; thresholds below are targets, not achieved results.  
**Scope:** native and browser clients, capture/encode, transport, decode/presentation, session authority, privacy, evidence, and operator experience.  
**Related work:** [release qualification and benchmark method](RELEASE_QUALIFICATION_AND_BENCHMARKS.md), [measurement methodology](benchmarks/MEASUREMENT_METHODOLOGY.md), [physical input-to-photon trace importer #457](https://github.com/Luminous-Dynamics/xenia-peer/issues/457), [matched benchmark issue #465](https://github.com/Luminous-Dynamics/xenia-peer/issues/465).

## 1. Strategic thesis: remote access as a verifiable control system

A remote desktop product is often evaluated as a video stream plus remote input. That framing underweights the most consequential property: the human operator is exercising authority over another machine.

Xenia should qualify the complete chain:

`Intent → Consent → Capability grant → Input authority → Execution → Observation → Independent verification → Receipt`

The product should be able to answer, with evidence:

- Who requested access, which authenticated principal approved it, and for which exact session?
- What operations, directions, resources, and duration were granted?
- Which authority generation was active when a control event was accepted?
- What was transmitted, what was applied, what was denied, and what remains unknown?
- When was authority revoked or expired, and can the host prove that later actions were rejected?
- What quality did the operator actually experience, measured at the endpoints rather than inferred from a dashboard counter?

The differentiator is not a cryptographic badge beside a conventional remote desktop. It is **evidence-carrying remote control**: the permission, the action, the observed result, and the measurement provenance are connected and independently checkable.

## 2. Industry comparison (feature evidence, not a performance ranking)

| System | Publicly documented strengths | What Xenia should learn / where to differentiate |
|---|---|---|
| Parsec | Gaming/workstation streaming; hardware decode; color-accuracy options; Teams/Enterprise identity and audit capabilities; on-premises relay and API options | Treat low-latency media and enterprise administration as the baseline. Bind a cryptographically inspectable capability to each session and preserve event-level outcome evidence |
| RustDesk | Open-source client, self-hosted rendezvous/relay, P2P encrypted connections; Pro adds OIDC/LDAP/2FA, device management, access control, log management and multiple relays | Keep deployment sovereignty, self-hosting and cross-platform simplicity; make policy decisions and evidence independently verifiable in both direct and relayed paths |
| Sunshine + Moonlight | High-performance streaming, hardware encode/decode, low-buffering modes and user-visible performance statistics | Benchmark full input-to-photon and frame pacing; expose measurement definitions because application counters are not directly comparable |
| Microsoft RDP / Windows 365 | Adaptive graphics, multiple virtual channels, UDP Shortpath, and RDP Multipath with multiple monitored UDP paths plus redundant TCP standby paths | Match the mature channel and path-resilience baseline. Differentiate with independently verifiable, capability-bound authority and measurable per-lane isolation rather than claiming multipath is unique |
| TeamViewer Tensor | Central conditional access, expiring rules, account/group/device-level scope, permissions for sessions and file transfer | Make grants short-lived, scope-specific and tied to the exact requested action—not just a general user/device relationship |
| AnyDesk | Permission management, device whitelisting, 2FA, privacy mode and session recording | Treat privacy as an explicit bilateral session state; make recording/redaction visible and verifiable |

### Publicly stated reference points

- Parsec's September 2026 guidance recommends 1080p60, a 25+ Mbps bandwidth limit, 30 Mbps host upload and 30 Mbps client download, with a same-city ping below 15 ms in its recommended setup. These are vendor configuration recommendations, **not an independent latency result or universal requirement**.
- Moonlight explicitly cautions that its internal connection statistics cannot be used to compare directly with other clients because instrumentation and available measurements differ. It recommends external hardware for accurate end-to-end measurements.
- Microsoft documents adaptive RDP graphics, separate dynamic virtual channels, UDP Shortpath, and RDP Multipath. The current RDP Multipath documentation describes multiple monitored UDP routes discovered with ICE/STUN/TURN plus redundant TCP standby paths; when the active path degrades or fails, the product can switch to a backup path. This is an established industry capability, not an Xenia differentiator.
- The RDP architecture already separates data across virtual channels, including presentation and input-related data. Xenia's existing cryptographic lane keys are a good security foundation, but the current QUIC transport still exposes one ordered logical stream; key separation alone does not provide stream-level head-of-line isolation.
- RustDesk documents an OSS self-hosted rendezvous/relay model and a commercial layer with centralized identity, policy and device-management features.
- AnyDesk and TeamViewer demonstrate that permission controls, privacy features, recording, expiry, and centralized conditional access are already established product expectations.

Sources:
- [Parsec overview and enterprise features](https://support.parsec.app/hc/en-us/articles/32361354307348-Overview)
- [Parsec 1080p60 recommended configuration](https://support.parsec.app/hc/en-us/articles/32361373629972-Gaming-Playtesting-Build-Reviews-and-QA)
- [Parsec connectivity and bandwidth requirements](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements)
- [Moonlight performance-statistic caveats and external measurement](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions)
- [Moonlight frame pacing modes](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions)
- [RustDesk self-hosting](https://rustdesk.com/docs/en/self-host/)
- [RustDesk Server Pro capabilities](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/)
- [Microsoft RDP bandwidth requirements](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-bandwidth)
- [Microsoft RDP Shortpath](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-shortpath)
- [Microsoft RDP Multipath (Azure Virtual Desktop)](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-multipath)
- [Microsoft RDP Multipath (Windows 365)](https://learn.microsoft.com/en-us/windows-365/enterprise/rdp-multipath)
- [Microsoft RDP architecture and virtual channels](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)
- [IETF RFC 10069: Managing Multiple Paths for a QUIC Connection (November 2026)](https://www.rfc-editor.org/rfc/rfc10069.html)
- [Iroh 1.0.2 relay security maintenance release](https://www.iroh.computer/blog/iroh-1-0-2)
- [TeamViewer Tensor conditional access](https://www.teamviewer.com/en-us/products/tensor/features/conditional-access/)
- [AnyDesk feature overview](https://anydesk.com/en/features)

## 3. Paradigm shifts to pursue

### 3.1 Capability-native sessions, not role-only sessions

A broad role such as `operator` is a starting point, not a sufficient authorization contract. Each approval should resolve to a narrowly scoped capability grant containing at least:

- authenticated requester and approver references;
- session identifier and authority generation;
- target device or resource reference;
- operation set and direction (view, keyboard, pointer, audio, clipboard, file transfer, administration);
- purpose or ticket reference when supplied by the requester;
- start time, expiry, and revocation state;
- constraints and policy version.

The grant should be short-lived, generation-bound, replay resistant, and checked at the enforcement point. The UI should render only fields authenticated by the protocol. Missing data is **unknown**, not a value to infer.

### 3.2 A verifiable session lifecycle

Create a machine-readable event chain for request, approval/denial, capability issue, connection, rekey, input authority change, privacy/recording transitions, revocation, disconnect, and final outcome. Bind records to session identity and authorization generation. Provide a verifier that detects missing, reordered, replayed, or modified events.

A log is not a proof merely because it is signed. The verifier must validate identity, event ordering, lifecycle consistency, and the relationship between grant and accepted action.

### 3.3 Quality-of-control, not bitrate or FPS alone

Optimize a vector of operator outcomes:

- externally measured input-to-photon latency;
- time-to-first-usable-frame and frame-pacing variance;
- visual/text fidelity at a stated bitrate;
- audio/video synchronization;
- control-lane latency under saturated media traffic;
- recovery time after network changes;
- CPU/GPU/energy cost;
- authority and privacy correctness.

Do not hide these dimensions behind one composite score. Publish a Pareto frontier and workload-specific profiles (desktop text, high-motion, CAD/design, video, low-bandwidth field support).

### 3.4 Independent measurement as a product feature

Embed a repeatable test harness and a stable evidence packet format. External instrumentation should be a first-class measurement source, not a one-off lab exercise. Each claimed result must link to its exact source commit, binary digest, configuration, hardware, network profile, instrument calibration, raw trace, and analysis version.

Software-side timestamps are valuable for diagnosis, but they do not measure the entire sensor → encode → network → decode → display pipeline.

### 3.5 Separate control from media under failure

Preserve independent, bounded control and media paths. Video can drop stale frames to preserve freshness; state transitions (key/button releases, consent, authority changes, file-operation lifecycle) cannot be silently discarded. Under congestion, control must remain responsive and fair without creating unbounded queues.

### 3.6 Privacy and intelligibility by default

Make sharing, recording, host telemetry, identity display, clipboard, and file transfer explicit capabilities. Default exported diagnostics and screenshots to redacted identity/host details. Make privacy state visible and ensure the operator can distinguish connected, viewing-only, input-authorized, degraded, revoked, and unknown states.


### 3.7 Design for accessible, safe operation

The console should target WCAG 2.2 AA: text contrast, reflow, visible and unobscured focus, keyboard operation, programmatic names/states, and status communication that does not depend on color alone. A screenshot is not an accessibility audit; perform keyboard, screen-reader and zoom tests.

Reference: [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/).

### 3.8 Multiplexed session lanes and path-resilient authority

A subtle but important distinction in Xenia's current implementation: LaneSession already derives separate Control, Video, Audio and Telemetry keys, but TransportProfileV1 still declares logical_streams = 1, and the native QUIC transport opens one bidirectional stream. This separates cryptographic keys but does not isolate ordered-stream delivery. A large video or file-transfer envelope can still delay input/control envelopes behind it.

The next transport architecture should use independently flow-controlled logical streams inside one authenticated QUIC connection:

- **Control:** input/key/button transitions, consent/rekey coordination, and security-critical state. Reliable, ordered, bounded, never silently discarded.
- **Video:** freshness-first presentation; discard/coalesce stale frames rather than build latency debt.
- **Audio:** bounded jitter and a separately measurable playout deadline.
- **Telemetry:** coalesce to current state; no backlog.
- **Bulk transfer:** independently backpressured so file chunks do not stall keyboard and revocation/control traffic.

Do not call this independent congestion control: multiple QUIC streams on the same connection still share its congestion controller. The immediate objective is removal of per-stream ordered-delivery head-of-line blocking and independent stream flow control. Xenia's current LaneSession keys are a foundation, but a fifth bulk lane requires an explicit key/replay/rekey design; simply reusing one mutable control replay window across concurrent streams is not acceptable.

This also needs a backward-compatible transport profile: one-stream TCP/WebSocket and older QUIC peers remain on the current profile; the multi-stream profile is explicitly negotiated and bound into the authenticated session context. Rekey is a session-wide barrier across all streams. File-transfer commits whose acknowledgements are lost must remain UNKNOWN until host reconciliation by transfer ID, chunk digest and committed offset—never blindly replay a mutation after reconnect.

**Path resilience is a second, different layer.** RFC 10069 specifies simultaneous QUIC paths and path identifiers, but deliberately leaves address discovery/management and application traffic scheduling out of scope. Xenia must own those policies. Microsoft's RDP Multipath shows that the industry already combines path probing, STUN/TURN and redundant TCP standby paths; Xenia should benchmark direct-only, public/custom relay, multiple relay candidates, TCP fallback and recovery rather than treating relay enablement as multipath.

Work in progress:
- [#480 — sovereign NAT traversal, relay policy and path resilience](https://github.com/Luminous-Dynamics/xenia-peer/issues/480)
- [#482 — isolate control, media, telemetry and bulk-transfer streams](https://github.com/Luminous-Dynamics/xenia-peer/issues/482)

These are roadmap targets, not implemented or measured capabilities.

## 4. Proposed qualification tiers and target thresholds

These are **engineering targets for planning**. They are not current Xenia measurements, competitor scores, or acceptance claims. Before promoting any target into a release gate, run a baseline against the exact supported hardware and codec matrix.

### Important: separate the release gate from the aspirational frontier

The existing `xenia-benchmark-profile-v0.1.json` in the release-qualification branch is the current proposed baseline contract. It specifies, among other targets:

- LAN 1080p60: input-to-photon p95 ≤ 80 ms, frame-age p95 ≤ 60 ms, direct connect-to-first-authorized-frame p95 ≤ 5 s, and post-approval-to-first-authorized-frame p95 ≤ 1 s.
- Regional interactive (20–30 ms RTT): input-to-photon p95 ≤ 120 ms and control-message delivery p95 ≤ 150 ms.
- Degraded WAN: control-message delivery p95 ≤ 250 ms, with the separate bandwidth-step-down and fairness conditions.

The tighter Tier A and Tier B values below are **aspirational product-frontier goals**, not replacements for those existing v0.1 release-qualification thresholds. For example, Tier A's proposed p95 ≤ 45 ms is a stretch goal relative to the existing LAN p95 ≤ 80 ms target. The first-usable-frame ≤ 2 s goal is also an additional product target; it must not be confused with the existing approval-to-first-authorized-frame measurement. Keep the schemas and result reports explicit about which profile is being tested. Do not silently tighten or loosen a release gate after seeing results.


### Tier A — controlled LAN, interactive desktop

| Metric | Proposed target | Measurement rule |
|---|---:|---|
| Profile | 1920×1080, 60 Hz, 15 Mbps cap | Same codec, encoder mode, color format and display refresh across products |
| Input-to-photon p50 | ≤ 25 ms | External photodiode or ≥1,000 fps camera; at least 300 randomized trials |
| Input-to-photon p95 | ≤ 45 ms | Report p50/p95/p99 and confidence intervals, not average only |
| Input-to-photon p99 | ≤ 70 ms | Record instrument uncertainty and reject uncalibrated runs |
| Frame pacing | p95 presented-frame interval ≤ 20 ms | Distinguish host capture FPS from client presentation cadence |
| First usable frame | ≤ 2.0 s after authenticated session acceptance | Record both acceptance-to-first-frame and connect-to-first-frame |
| Control under video load | p99 control response ≤ 75 ms | Saturate media traffic and verify no priority inversion |

The 15 Mbps profile is a stretch efficiency target against Parsec's 25+ Mbps / 30 Mbps recommendations for its stated 1080p60 setup. Xenia only beats that reference if visual fidelity is matched and the measurement rig is equivalent.

### Tier B — WAN and constrained links

| Metric | Proposed target | Test profile |
|---|---:|---|
| Input-to-photon p95 | ≤ 75 ms | 30 ms baseline RTT, 5 ms jitter, no loss, 1080p60 |
| Bandwidth adaptation | Stable target rate within ≤ 2 s | Abrupt 30 → 5 Mbps change |
| Recovery after transient outage | ≤ 3 s to usable picture | 1 s outage followed by restored route |
| Control under cross-traffic | p99 ≤ 100 ms | Competing TCP flow and video near bottleneck saturation |
| Fairness | ≥ 0.8 of fair-queue reference throughput | Report per-flow goodput and control latency |
| Packet loss | No crash, unbounded queue, or authority downgrade | 0.1%, 1%, 3%, 5% random loss plus burst-loss fixtures |

The session should gracefully reduce resolution, frame rate or quality rather than silently accumulating latency. Report the actual adaptation path and every temporary degraded state.

### Tier C — authority, evidence, and security

| Metric | Proposed target | Qualification |
|---|---:|---|
| Out-of-scope capability accepted | 0 | Negative tests for wrong session, wrong target, operation, direction, expiry and generation |
| Replayed/stale challenge accepted | 0 | At least 1,000,000 generated replay/stale/wrong-generation attempts across deterministic and randomized fixtures |
| Input after revocation acknowledgment | 0 accepted host-side events | Verify at the enforcement point, not merely the client UI |
| Audit completeness | 100% of accepted consent and state-changing control transitions represented | Cross-check emitted events against host-observed actions |
| Evidence tamper detection | 100% of injected mutation cases detected | Modify, delete, reorder, duplicate, truncate and substitute artifacts |
| Authorization downgrade | 0 | Expired authenticated session, failed refresh, sealed-channel failure and reconnect tests |
| Unknown outcome | No automatic retry or new mutation until reconciliation | Timeout, lost response and connection-reset cases |

A zero-acceptance target means all negative cases must be rejected in the tested population; it does not prove the absence of vulnerabilities outside that population.

### Tier D — product quality and operations

| Metric | Proposed target | Qualification |
|---|---:|---|
| Long-session reliability | 8-hour soak without stuck remote keys/buttons or unbounded queue growth | Periodic input, audio, video, rekey, network and authority transitions |
| Concurrent-session scaling | Publish 1 / 10 / 50 / 100 session curves | CPU, GPU, memory, relay bandwidth, queue depth and p99 control latency |
| Resource profile | Report CPU/GPU/RAM and joules per active session | Same host/client hardware and workload |
| Privacy | No unapproved clipboard/file/recording/telemetry capability | Negative tests and exported-artifact redaction checks |
| Browser console | WCAG 2.2 AA target | Automated axe checks plus manual keyboard, screen reader, high zoom and reflow |
| Native viewer | Keyboard focus and pointer-boundary safety tests | UI controls never inject remote keystrokes; target loss releases held state |

## 5. Matched comparison protocol

A fair comparison requires a fixed lab, not screenshots or vendor marketing claims.

1. **Endpoints:** publish host/client CPU, GPU, memory, OS/kernel, driver, capture backend, display model, refresh rate, scale factor, encoder/decoder and power profile.
2. **Software:** pin product versions, source commit/build digest where available, settings, codec, color format, transport path, relay/direct mode and security mode.
3. **Network:** publish RTT, jitter, loss, bandwidth cap, queue discipline, competing flows, route, MTU and impairment seed. Run LAN, WAN and constrained profiles separately.
4. **Workloads:** include static text/IDE, scrolling, window movement, video, rapid pointer movement, drag-and-drop, high-motion scenes, dual-monitor and mixed-resolution displays.
5. **Latency:** use an external input trigger and photodiode/high-speed-camera observation. Collect at least 300 valid trials per profile; publish raw timestamps, instrument calibration and dropped/invalid trial reasons.
6. **Quality:** pair objective video metrics with screen-specific text/UI legibility and blinded human assessment. Do not use VMAF, PSNR or SSIM alone to rank text-heavy desktop content.
7. **Statistics:** publish sample count, median, p95, p99, bootstrap confidence interval, run-to-run spread and outlier policy. Do not discard inconvenient tails without a pre-registered rule.
8. **Evidence:** include source SHA, binary digest, run packet digest, raw trace digest, environment manifest, network fixture, calibration record, and analysis tool version.
9. **Competitors:** where supported, test Parsec, RustDesk, Sunshine/Moonlight and RDP on the same endpoints. When a product cannot support an identical codec, path or feature, mark the cell **not comparable** rather than inventing an equivalent.
10. **Publication:** release reproducible scripts, raw traces, normalized summaries and known limitations. Separate vendor-stated recommendations from measurements made in this lab.

### Minimum matrix

| Axis | Values |
|---|---|
| Resolution / refresh | 1280×720@60, 1920×1080@60, 2560×1440@60, 3840×2160@60 where endpoints support it |
| Bitrate | 5, 10, 15, 20, 25, 30 Mbps |
| Codec | H.264, HEVC, AV1, passthrough where supported; record 4:2:0 / 4:4:4 |
| Transport | Direct, relay, TCP fallback / UDP path where supported |
| Transport policy | Direct-only, public relay, one custom relay, multiple custom relays, relay unavailable |
| Route resilience | Direct→relay, relay→direct, active path degraded, active path lost, backup path failover, all paths lost/reconnect |
| Logical streams | Current one-stream profile vs negotiated multi-stream profile; control/video/audio/telemetry/bulk saturation independently and concurrently |
| Lane pressure | 90% media saturation, large file transfer, audio jitter, burst control transitions, rekey overlap, queue-bound stress |
| RTT | 1, 15, 30, 60, 100 ms |
| Jitter | 0, 5, 15, 30 ms |
| Loss | 0, 0.1%, 1%, 3%, 5%, including burst loss |
| Cross-traffic | none, one saturating TCP flow, multiple competing flows |
| Authority | view-only, pointer, keyboard, audio, clipboard/file transfer, expiry, revocation |
| Duration | short task, 30-minute workload, 8-hour soak |

The full Cartesian product is too expensive. Use a pre-registered covering array for broad interaction testing, then run full deep dives on the high-risk profiles and every release-critical path.

## 6. How to beat the state of the art

Do not claim to beat the whole industry with one number. Establish independent wins on a few measurable frontiers:

- **Efficiency:** match Parsec-level 1080p60 legibility at a materially lower bitrate (15 Mbps target vs vendor guidance of 25–30 Mbps) without worse tail latency or frame pacing.
- **Responsiveness:** demonstrate lower externally measured p95/p99 input-to-photon latency under the same endpoint and network conditions, not just lower codec or receive time.
- **Congestion behavior:** maintain control responsiveness and bounded queues while media and bulk transfer are saturated; compare a single ordered stream with a negotiated multi-stream profile. Prove this against both product defaults and a fair-queue network reference.
- **Path resilience:** keep the authenticated session usable through direct-path degradation, relay failover and redundant-path changes; compare connection success, failover time, interruption duration, reconnect probability and metadata exposure against current RDP Multipath capabilities.
- **Authority correctness:** show zero out-of-scope or post-revocation accepted actions in the published negative-control suite, with host-side observation.
- **Evidence quality:** let a third party verify the complete chain from request and grant through action and outcome using raw artifacts and public verification code.
- **Deployment sovereignty:** make self-hosted, auditable operation practical without forcing customers into a proprietary control plane.
- **Operator trust:** make scope, expiry, input permissions, privacy, degraded state and unknowns legible, accessible and hard to misinterpret.

This is the credible route to SOTA: matched baselines, externally measured improvements, reproducible raw data, and strong negative controls.

## 7. Evidence packet schema (proposed)

Every result should be represented as a versioned run packet with:

- `schema_version`, `run_id`, exact source `commit_sha`, binary digest(s), and benchmark profile digest;
- host/client hardware and software manifests;
- resolution, refresh rate, codec, encoder, decoder, transport and relay mode;
- network impairment parameters and deterministic seed;
- instrument identifier, calibration artifact digest, clock-domain declaration and uncertainty;
- raw samples and trace artifact paths plus SHA-256 digests;
- analysis tool version, sample count, invalid-trial reasons, p50/p95/p99 and confidence intervals;
- result state: `PASS`, `FAIL`, `BLOCKED`, `NOT_COMPARABLE`, or `NOT_MEASURED`.

A `PASS` must require actual measurement evidence. A planned run, skipped check, missing artifact, internal-only timestamp, or historical result cannot qualify.

## 8. Release / research decision rules

- Keep proposed targets separate from measured achievements.
- Keep benchmark profile changes versioned; do not quietly retune thresholds after seeing results.
- A missing or uncalibrated physical trace is `BLOCKED`, not a zero-latency result.
- A competitor feature list is not a benchmark result.
- A run without an exact source SHA and reproducible environment is diagnostic only.
- Preserve all raw trial data and failed runs; publish the reasons an attempt was invalidated.
- Any changed trust, privacy or authority behavior requires independent negative tests and lifecycle evidence, not only visual review.

---

## Sources and further reading

- [Parsec overview](https://support.parsec.app/hc/en-us/articles/32361354307348-Overview)
- [Parsec gaming/playtesting settings (September 29, 2026)](https://support.parsec.app/hc/en-us/articles/32361373629972-Gaming-Playtesting-Build-Reviews-and-QA)
- [Parsec connectivity requirements](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements)
- [Moonlight FAQ: latency counters and external measurement](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions)
- [Moonlight FAQ: frame pacing](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions)
- [RustDesk self-hosting](https://rustdesk.com/docs/en/self-host/)
- [RustDesk Pro](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/)
- [Microsoft RDP bandwidth requirements](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-bandwidth)
- [Microsoft RDP Shortpath](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-shortpath)
- [TeamViewer Tensor conditional access](https://www.teamviewer.com/en-us/products/tensor/features/conditional-access/)
- [AnyDesk features](https://anydesk.com/en/features)
- [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/)
