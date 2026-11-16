# Xenia Release Qualification and Benchmark Programme

Status: research/qualification proposal; not a release approval.
Prepared: 2026-11-16
Scope: `xenia-peer` application and its `xenia-wire` protocol dependency.

This document turns Xenia's release goal into a reproducible qualification programme. It separates protocol correctness, authority/consent, product operation, performance, and independent review. A result in one lane must not be used to imply a result in another.

## 1. Product thesis and release boundary

Xenia should compete as **consent-first, evidence-verifiable remote-session infrastructure**, not merely as another remote desktop. Granular permissions, live permission changes and audit logs already exist in mature products. Xenia's proposed differentiator must therefore be stronger: an independently verifiable cryptographic evidence chain binding requester identity, purpose, exact operation/lane, direction, scope, expiry, authorization generation, rekey and outcome—without making a central service the authority.

The product proposition is:

- local machine owner remains the root of session consent;
- encrypted peer communication can operate without a mandatory Xenia cloud control plane;
- rendezvous/relay infrastructure, if introduced, is optional and cannot silently become an authority;
- each privileged operation is constrained by an explicit session capability;
- revocation prevents future protected effects; it does not pretend to erase data already disclosed;
- receipts prove defined protocol facts, not human understanding, voluntariness, or legal validity.

### Proposed staged releases

| Stage | Intended audience | Permitted claims |
|---|---|---|
| Protocol developer preview | Protocol implementers and reviewers | Wire format, vectors, API behavior and explicitly qualified cryptographic properties |
| Desktop technical preview | Invited technical users on enumerated platforms | Demonstrated capture, viewing, input and consent flows on the exact tested platform profile |
| Public beta | Broader users after independent review and operational hardening | Supported-platform matrix, documented limitations, reliable update/recovery path |
| Production | Operational deployments | Only independently reviewed, deployment-tested claims supported by current evidence |

Do not call a stage “production-ready” because unit tests pass, a feature is present, or a hosted runner is queued. Keep the product's tested platform boundary narrow and explicit. The existing live evidence is strongest for KDE Wayland; GNOME's VM capture attempt, wlroots, macOS and Windows must not be represented as equivalent validation.

## 2. Qualification lanes and hard promotion gates

### Q0 — Cryptographic and protocol correctness

Required before any external technical preview that handles real input or sensitive screens:

- close the duplicate-key installation nonce reset in [xenia-wire #35](https://github.com/Luminous-Dynamics/xenia-wire/issues/35);
- close the host/viewer directional nonce-domain collision reported in [xenia-peer #274](https://github.com/Luminous-Dynamics/xenia-peer/issues/274), including review of [PR #432](https://github.com/Luminous-Dynamics/xenia-peer/pull/432);
- close exact-new-key / exact-remote-domain rekey acknowledgement checks in [xenia-peer #286](https://github.com/Luminous-Dynamics/xenia-peer/issues/286);
- establish one normative nonce and key-lifecycle model across wire, handshake, lane and application layers;
- validate malformed, duplicate, reordered, truncated, replayed, cross-direction, stale-epoch and interrupted-rekey inputs;
- run independent implementation conformance and the bounded-model qualification tracked by [xenia-wire #83](https://github.com/Luminous-Dynamics/xenia-wire/issues/83), [#82](https://github.com/Luminous-Dynamics/xenia-wire/issues/82), and the current Kani workstream.

**Non-negotiable invariant:** two distinct successful AEAD seals must never reuse the same (key, nonce) pair. Direction, payload class, epoch, key installation, retries and rekey transitions must all be included in the argument. A test that only compares sequence counters is insufficient.

### Q1 — Consent, authority and evidence

- complete [xenia-peer #449](https://github.com/Luminous-Dynamics/xenia-peer/issues/449): every privileged lane validates an explicit, immutable, direction- and purpose-bound session capability;
- complete [xenia-peer #455](https://github.com/Luminous-Dynamics/xenia-peer/issues/455): reviewable human-readable consent presentation and evidence binding;
- complete [xenia-peer #451](https://github.com/Luminous-Dynamics/xenia-peer/pull/451) or an equivalent exact-head change: authenticate persisted ledger state before restoring authority;
- preserve separate permissions for screen, input, clipboard, file transfer and remote workloads; broad consent must not silently authorize new capabilities;
- test denial, expiry, revocation, reconnect, restart, rekey, process crash and concurrent in-flight lane traffic;
- define what revocation can and cannot do: stop future authority/effects and invalidate unconsumed capabilities where supported, while representing already-disclosed data and downstream deletion as separate obligations.

**Non-negotiable invariant:** no frame, input, file, clipboard, workload or administrative effect is dispatched after its authority is denied, expired, revoked, stale or ambiguous. Unknown execution outcome is reconciled, not blindly retried.

A signed record establishes the authenticated bytes and signer context. It does not prove comprehension, absence of coercion, legal capacity, or that a recipient erased previously disclosed information.

### Q2 — Operational product readiness

- publish a supported OS/compositor/device matrix with exact exercised versions;
- close the current dependency advisory finding tracked by [xenia-peer #454](https://github.com/Luminous-Dynamics/xenia-peer/issues/454), without weakening Cargo Deny or RustSec policy;
- verify installers, first-run setup, identity enrollment, key backup/rotation, secure update, rollback, uninstall and recovery;
- test capture/input consent behavior on every claimed supported platform;
- bound queues, memory, file sizes, buffering and timeouts; exercise slow consumers and resource exhaustion;
- provide a privacy-conscious incident bundle and an intelligible session history;
- document direct connection, relay/fallback behavior, firewall requirements and the behavior when rendezvous or optional infrastructure is unavailable.

### Q3 — Independent assurance and release operations

- independent security review of protocol, handshake, authority, operator agent, browser console, persistence and platform adapters;
- independent wire implementation with a receipt binding exact protocol commit, specification, vectors, implementation commit, runtime, and each positive/negative result;
- reproducible Kani environment and explicit Pass / Fail / Blocked / EnvironmentFailure outcomes;
- signed release artifacts, SBOM, dependency/license/advisory reports, provenance and reproducible build notes;
- exact-head qualification and promotion records; a skipped, queued, cancelled, stale or environment-failed job is never PASS;
- published vulnerability-reporting process, remediation policy and limitations.

## 3. Benchmark programme

All targets below are **proposed engineering goals**, not measured current results or claims about competitor performance. First establish a baseline on the same hardware, display, content, codec, quality setting, network profile and test duration. Compare medians and tail latency (p50/p95/p99), not isolated best runs.

### 3.1 Competitive set and fair comparison

| Comparator | What it is good for | Xenia comparison focus |
|---|---|---|
| [RustDesk OSS / Pro](https://rustdesk.com/docs/en/self-host/) | Open-source/self-hosted remote access; direct connection with relay fallback; Pro adds web administration, OIDC, LDAP, 2FA, device management and access controls | Direct-vs-relay reliability, self-host deployment burden, supported platforms, permissions, and whether Xenia's consent evidence is materially more specific |
| [AnyDesk security](https://anydesk.com/en/security) | Mature remote access with TLS/AEAD security claims, configurable session permissions and on-premises options | Session permission granularity, operator controls, auditability, installation and recovery |
| [TeamViewer security](https://www.teamviewer.com/en/trust-center/) | Enterprise remote support and fleet workflows | Enterprise administration, identity integration, policy lifecycle, audit and support operations |
| [Parsec performance guidance](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements) | High-frame-rate remote interaction; published 1080p60 guidance recommends roughly 30 Mbps and low same-city ping | Glass-to-glass latency, frame pacing, quality at constrained bandwidth, hardware encode/decode |
| [MeshCentral](https://docs.meshcentral.com/) | Self-hosted agent/server remote management, desktop, terminal and file workflows | Fleet operations, browser usability, administrator workflows, offline behavior and self-hosting |
| [Sunshine + Moonlight](https://docs.lizardbyte.dev/projects/sunshine/latest/) | Self-hosted low-latency streaming with hardware encoder selection and HEVC/AV1 support | Codec/encoder performance, capture path, frame pacing, HDR and bitrate-quality curves |

No single competitor is a universal baseline. Parsec is a useful latency/streaming comparator; RustDesk and MeshCentral are useful open/self-hosted product comparators; AnyDesk and TeamViewer are useful enterprise-operational comparators. Run supported editions and disclose their configuration. Do not compare Xenia passthrough against a hardware H.265 competitor, or compare direct Xenia against a relayed competitor, without labeling the difference.

Current vendor documentation makes the bar clearer: RustDesk Pro documents OIDC, LDAP, 2FA, device management, access control and multi-relay administration; RustDesk client configuration lists codec choices including AV1/H.264/H.265 but warns support depends on the machine. AnyDesk documents permission profiles and changing permissions during an active session. TeamViewer Tensor documents event logs covering session and management-console actions. Parsec's July 8, 2026 connectivity guidance recommends 30 Mbps host upload for 1080p60, and its September 29, 2026 playtesting guidance recommends 25+ Mbps. Sunshine documents hardware-dependent HEVC Main/Main10 and AV1 Main encoding. These are vendor-published claims and configuration guidance, not independent comparative test results.

Consequently, the 15 Mbps Xenia LAN objective is a **stretch target**, not an established advantage. Every codec must be compared on the same corpus and host/client hardware at matched visual quality. Run bitrate sweeps at 5/10/15/20/25/30 Mbps and disclose whether encode/decode is hardware or software, color subsampling, bit depth, HDR state, direct/relay path and compositor/capture method.

### 3.2 Codec and congestion-control comparisons

For every codec/encoder path, sweep 5, 10, 15, 20, 25 and 30 Mbps at the same visual-quality threshold. Include H.264, HEVC, AV1, passthrough and HDC where supported. Record encoder/decoder vendor, hardware-vs-software path, chroma format, bit depth, HDR, CPU/GPU use, power and dropped frames. Use a reference capture corpus containing small text, terminal glyphs, scrolling, gradients and high-motion content; do not use a single perceptual score as the sole quality gate for text-heavy desktops.

Add two explicit congestion experiments:

1. **Media/control isolation:** saturate at least 90% of the shaped bottleneck with video, then measure control/input queue age and p95/p99 delivery latency. Repeat with an independent long-lived TCP bulk flow. Verify the TCP flow is not starved and compare its goodput with a fair-queue reference; do not assume equal bandwidth shares between real-time and bulk classes.
2. **Fast network step-down:** begin at 30 Mbps, step to 5 Mbps with 80–100 ms RTT, jitter and packet loss, then measure time to stable bitrate/FPS, maximum queue age, stale-frame drops, control latency and recovery. Target adaptation convergence within 2 seconds without an unbounded queue or control starvation.

These experiments operationalize RFC 8836's requirements for low-delay interactive traffic, fairness to TCP, minimizing self-induced latency and rapid adaptation. They are proposed qualification goals; no Xenia results exist yet.

### 3.3 Performance profiles

Use one published test corpus containing static text/UI, scrolling, rapid pointer motion, video playback, high-motion scenes, dark scenes and mixed desktop work. Include a fixed lossless reference capture so image quality can be evaluated rather than guessed.

| Profile | Network conditions | Proposed target |
|---|---|---|
| LAN interactive | RTT 1–5 ms, 0% loss, low jitter | 1080p60 H.264; >=57 displayed FPS; p95 frame age <=60 ms; p95 input-to-photon <=80 ms |
| Regional interactive | RTT 20–30 ms, <=5 ms jitter, 0% loss | 1080p60 target; p95 input-to-photon <=120 ms; no authority/control starvation under video load |
| Degraded WAN | RTT 80 ms, 20 ms jitter, 1% loss, 10 Mbps bottleneck | Graceful quality/FPS adaptation; p95 control-message delivery <=250 ms; no unbounded queues or stale-input replay |
| Constrained link | RTT 100 ms, 30 ms jitter, 2% loss, 5 Mbps bottleneck | Stable consent/control and usable reduced-rate viewing; explicit reporting of quality reduction and dropped stale frames |
| Long session | LAN plus periodic network impairment/recovery | 24-hour soak; no crash, memory growth beyond declared budget, nonce/replay violation or authority drift |

Additional proposed budgets:

- Direct LAN connection to first authorized frame: p95 <=5 seconds, excluding human deliberation time in the consent prompt.
- After explicit approval: first authorized frame within 1 second on the LAN profile.
- 1080p60 H.264 average bitrate target: <=15 Mbps on the fixed UI/mixed corpus at a quality level independently scored as acceptable; also report p95 bitrate and quality. This is a goal, not a reason to degrade legibility.
- Queueing: bounded at every producer/transport/decoder/injector boundary. Old video/audio may be dropped or coalesced according to policy; key/button transitions and authority/control messages may not be silently lost.
- Resource use: publish CPU, GPU, encoder/decoder engine, RSS, allocation rate and energy where measurable. Define per-platform budgets after collecting baseline data rather than inventing a universal ceiling.
- Recovery: measure connect success, time-to-recover, number of user actions, and behavior after NAT changes, sleep/resume, Wi-Fi roam, relay failure and peer restart.

### 3.4 Security, correctness and resilience benchmarks

| Benchmark | Required measurement / target |
|---|---|
| AEAD nonce uniqueness | Zero repeated (key, nonce) pairs across 10 million generated transitions plus symbolic/model-checked boundary cases; any collision is an immediate fail |
| Replay and ordering | 100% rejection of duplicate, stale, wrong-domain and malformed test vectors; no false acceptance across lane/direction/epoch |
| Rekey | 100,000 scripted rekeys including interruption, duplicate Ack, stale-key Ack, delayed messages and restart; zero acceptance outside exact epoch/domain |
| Consent lifecycle | Zero protected effects after deny, expiry or revocation in deterministic and randomized race tests |
| Fault injection | At least 10,000 seeded state-machine scenarios covering disconnects, timeouts, process termination, partial writes, corrupted persistence and backpressure |
| Ledger restore | Tamper, truncate, reorder, swap keys, roll back and replay artifacts; all invalid authority state rejected before use |
| Dependency/security hygiene | Zero known unapproved critical/high advisories; no yanked dependency silently accepted; license/SBOM checks remain fail-closed |
| Independent conformance | 100% required positive and negative vectors pass in at least two independently implemented paths; exact version and vector manifest recorded |
| Formal analysis | Required proofs are non-vacuous, exact production-kernel-bound, toolchain-pinned and replayable; environment failure remains Blocked, never Pass |

The 10-million nonce and 100,000 rekey tests are stress targets, not mathematical proofs. They complement, rather than replace, code review, formal analysis and external cryptographic review.

### 3.5 Consent and user-trust benchmarks

Measure consent as a human interface, not merely as a signature API:

- a user can identify the requester, recipient, purpose, data/effect, scope, duration and consequences before approving;
- deny and revoke are as discoverable as approve;
- a read-only grant cannot authorize input, clipboard, file transfer, or workload execution;
- the interface explains what revocation stops and what cannot be recalled;
- keyboard-only, screen-reader, zoom and localization checks are included;
- test at least 20 representative users in formative rounds; measure comprehension errors and task completion, not just approval speed;
- target at least 90% correct comprehension for actor, scope, duration and revocation in the pre-release usability cohort; revise the presentation if any critical misunderstanding is observed.

Do not optimize for maximum approval rate. The correct behavior may be a thoughtful decline.

## 4. Paradigm shifts worth pursuing

### A. Remote access becomes temporary, typed capability issuance

Replace the mental model of "log in to a remote computer" with "receive one limited capability for one declared purpose." Capabilities bind session, operator, host, direction, payload class, permissions, authority generation, expiry and consent reference. The daemon rechecks them at the protected effect boundary.

This makes least privilege a property of the runtime, not a paragraph in an admin policy.

### B. Consent becomes a reviewable protocol artifact

Bind a versioned, human-readable explanation to the exact signed request. Store the presentation digest and retain accessible content for the participant. Separate cryptographic facts from human/process facts. A receipt should be independently verifiable while redacting screen contents and unnecessary personal metadata.

### C. A session becomes evidence-carrying

Create a session evidence bundle linking:
- peer identities and authenticated handshake transcript;
- negotiated crypto/profile and direction domains;
- exact consent scope and capability generation;
- lifecycle events, revocation and rekey;
- protected-action receipts and outcome/reconciliation records;
- privacy-redaction policy and artifact digest.

The evidence bundle is not a packet capture and must not become a covert screen-recording system.

### D. Security boundaries become compositional and independently testable

Keep wire confidentiality/integrity, handshake identity, session authority, capture consent, OS input authorization, persistence integrity and workload correctness as separate proof obligations. Each emits a versioned receipt with its own verifier. A downstream application composes evidence; it does not inherit unearned trust from a neighboring component.

### E. Deadline-aware congestion control protects interactivity

Treat lanes according to their deadlines and reliability needs: consent, authorization, input and control are protected; video/audio are freshness-oriented; file transfer is bulk/reliable. Video saturation must not starve input or control, and Xenia must remain fair to competing TCP traffic. Measure control p95/p99 while media saturates the bottleneck, while a separate long-lived TCP flow competes, and immediately after a bandwidth step-down. Report queue age, time-to-adapt, dropped stale media, TCP goodput against a fair-queue reference and recovery time. RFC 8836 calls for low-delay interactive media while retaining useful bandwidth, minimizing self-induced latency, fairness to TCP and rapid adaptation to changing conditions.

### E.1 Adaptive streaming optimizes usefulness, not raw FPS

Use deadline-aware scheduling: preserve fresh control/input, drop stale video, prioritize text/edges when legibility matters, adapt resolution and bitrate based on measured conditions, and keep audio jitter within a declared budget. Explore HDC tile deltas as a selective/static-content path only after measured CPU cost and image-quality results demonstrate an advantage over hardware H.264/H.265/AV1. Do not promote HDC based on attractive synthetic keyframe/delta ratios alone.

### F. Optional infrastructure cannot become hidden authority

A rendezvous service may help peers find one another; a relay may forward ciphertext. Neither should silently gain permission to approve access, impersonate a host, downgrade crypto, or rewrite session scope. Test this with malicious/compromised rendezvous and relay models.

### G. Human and machine collaboration with an explicit effect boundary

Symthaea may diagnose, explain and propose actions. Xenia checks whether a human- or policy-issued capability authorizes the exact operation. The assistant's confidence, reputation or generated plan must never become permission by itself. Begin with isolated read-only workloads; add mutation only after separate authorization, execution and independent outcome verification.

## 5. Benchmark implementation and evidence format

A first local-first Rust evidence tool lives in [`apps/xenia-peer/src/bin/xenia-bench.rs`](../../apps/xenia-peer/src/bin/xenia-bench.rs). It validates the profile, captures a privacy-minimized host/source snapshot, prepares a run packet that remains BLOCKED until a real adapter supplies measurements, and checks claimed profile results against explicit thresholds. It does not yet measure capture-to-display or input-to-photon; its consistency checker is not an independent attestation.

Physical and clock-domain measurement rules are specified in [Measurement Methodology v0.1](benchmarks/MEASUREMENT_METHODOLOGY.md). In particular, the performance runner will not accept an input-to-photon PASS based solely on software timestamps.

A first local-first Rust evidence tool now lives in [`benchmarks/runner`](../benchmarks/runner/README.md). It validates the profile, captures a privacy-minimized host/source snapshot, prepares a run packet that remains `BLOCKED` until a real adapter supplies measurements, and checks claimed profile results against explicit thresholds. It does not yet measure capture-to-display or input-to-photon, and its consistency checker is not an independent attestation.

The machine-readable target profile is [`benchmarks/xenia-benchmark-profile-v0.1.json`](../benchmarks/xenia-benchmark-profile-v0.1.json). It records proposed scenarios and thresholds, not measured results. Keep this manifest and this document synchronized when changing the qualification contract.

Create a reproducible benchmark runner that emits machine-readable JSON plus a concise Markdown report. Each run must record:

- repository, exact commit, dirty-tree state and build profile;
- Rust/toolchain, OS/kernel/compositor, CPU/GPU/driver and encoder/decoder;
- display dimensions/refresh, codec/profile, bitrate target, quality corpus digest;
- transport and direct/relay status;
- network shaping configuration (RTT, jitter, loss, reordering, bandwidth);
- warmup, sample count, duration and clock source;
- p50/p95/p99/max for latency and frame age, FPS/frame drops, bitrate, CPU/GPU, RSS and queue occupancy;
- failure counts, reconnect/recovery time and user-visible degradation;
- benchmark harness version, seed, raw sample artifact digest and result status.

Every result must be one of:

- **PASS** — all required measurements and invariants completed and thresholds met;
- **FAIL** — a required invariant or threshold was violated;
- **BLOCKED** — required evidence was not produced;
- **ENVIRONMENT_FAILURE** — the environment/tool was unavailable or invalidated the run.

Do not collapse missing measurements into zero. Do not mix results across different commits, test corpora, hardware, codec quality or network profiles.

Use Criterion for Rust microbenchmarks; use separate end-to-end harnesses for capture-to-display, input-to-photon, network impairment, session soak and authority fault injection. A fast local smoke suite should be runnable without hosted CI. Hosted CI adds independent reproducibility and exact-head admission; it does not replace local, real-device qualification.

## 6. Immediate execution order

1. **P0 — Wire nonce lifecycle:** fix and qualify #35. Add duplicate-key installation tests and prove a genuinely different key still transitions correctly.
2. **P0 — Peer direction domains:** review #432 and #276 evidence, validate role tags across every lane and sender, then close #274 only after production-path integration and exact-head tests.
3. **P0 — Exact rekey Ack:** implement #286's strict new-key/current-domain/sequence-zero verification without globally disabling previous-key grace for ordinary in-flight traffic.
4. **P1 — Session capability:** implement #449 with a lane/direction/permission matrix and concurrency/revocation tests.
5. **P1 — Consent proof boundary:** implement #455 and connect it to the evidence bundle without overstating consent validity.
6. **P1 — Ledger and dependency hygiene:** qualify #451 and fix #454 without weakening security gates.
7. **P2 — Local benchmark harness:** capture baseline metrics on the known KDE Wayland machine; publish harness version, run manifest and raw result digests. This work can proceed before hosted runners are available.
8. **P2 — Competitor baseline:** run RustDesk OSS, Parsec and one enterprise comparator on the same hardware/network matrix. Record configurations and exact versions.
9. **P3 — Independent review:** commission/recruit independent protocol, application and usability reviewers; publish scope, findings and remediation status.
10. **P3 — Technical preview:** only after P0/P1 and scoped platform/operational gates pass.

## 7. Release decision rule

A release candidate is admitted only when every required gate has an exact-head evidence record, the corresponding negative controls fail as expected, and all blocked/environment-failed results are resolved or explicitly excluded from the claimed product scope.

There is no aggregate score that allows high FPS, many tests, or good documentation to compensate for a cryptographic or authority failure.

The first public technical preview should be deliberately narrow: one supported host platform profile, explicit peer identity enrollment, consent required for each privileged capability, conservative defaults, and a documented manual recovery route. Expand the platform or autonomy scope only when its own evidence is complete.

## 8. External references

- RustDesk self-host architecture and Pro feature boundary: https://rustdesk.com/docs/en/self-host/
- AnyDesk security feature overview: https://anydesk.com/en/security
- TeamViewer Trust Center: https://www.teamviewer.com/en/trust-center/
- Parsec connectivity and 1080p60 bandwidth guidance: https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements
- MeshCentral documentation: https://docs.meshcentral.com/
- Kani Rust Verifier: https://model-checking.github.io/kani/
- Criterion.rs benchmarking guide: https://criterion-rs.github.io/book/

Reference pages were consulted on 2026-11-16. Competitor claims are summaries of vendor documentation, not independent evaluations. Re-run comparisons against current releases before publication.
