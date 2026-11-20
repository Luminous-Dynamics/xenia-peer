# Version Age of Information for Privacy-Preserving Remote UI Regions

**Status:** Research implementation v0.1 — pure metadata model and synthetic fixtures.  
**Tracking:** [Xenia #527](https://github.com/Luminous-Dynamics/xenia-peer/issues/527).  
**Related:** [#525 scheduler model](https://github.com/Luminous-Dynamics/xenia-peer/issues/525), [#526 WDRR implementation](https://github.com/Luminous-Dynamics/xenia-peer/pull/526), [#457 physical I2P traces](https://github.com/Luminous-Dynamics/xenia-peer/issues/457), [#458 endpoint-stage telemetry](https://github.com/Luminous-Dynamics/xenia-peer/issues/458), [#465 matched benchmark](https://github.com/Luminous-Dynamics/xenia-peer/issues/465).

This contribution defines a conservative, privacy-preserving *region version freshness* contract. It does not inspect screen content, infer application semantics, change the wire format, modify scheduling priority, or claim measured user benefit.

## 1. Why frame AoI is insufficient

Ordinary Age of Information (AoI) measures the elapsed time since the generation of the most recently received update. This is useful for describing freshness, but an average frame-level value can hide a stale interaction-critical region among many recently updated regions.

Version Age of Information (VAoI) extends freshness analysis with update-version/informativeness information. IEEE INFOCOM 2026's *From Timestamps to Versions: Version AoI in Single- and Multi-Hop Networks* studies stationary VAoI distributions under randomized, uniform and threshold-based policies, rather than considering only average timestamp AoI. This work is a networking model; it does not establish a remote desktop result.

For Xenia, the proposed step is to retain a **freshness vector**: one independently qualified result per ephemeral region, with optional explicit task relevance. We should report average, p95/p99 and worst-region values—not collapse the user experience into one scalar.

## 2. Conservative v0.1 contract

The Rust model lives in `crates/xenia-peer-core/src/region_freshness.rs` and is exported by `xenia-peer-core`.

Each sample contains only:
- Xenia session generation;
- ephemeral region ID;
- region/capture generation;
- source version and viewer-observed version;
- caller-declared region class;
- optional explicit relevance in 0..=100;
- optional local stage-age ticks with explicit clock-domain IDs.

It does not contain screen pixels, OCR, text, window titles, application names, clipboard content, passwords, raw input coordinates or cross-session behavior history.

### Version lag

When source and observed versions refer to the same session generation, region ID and region generation:

`version_lag = source_version - observed_version`

This is meaningful as a missed-update count only when the source increments versions contiguously. Otherwise it is an ordering-distance indicator that must be labeled according to the producer's semantics.

The following are UNKNOWN, not zero-age:
- missing source or observation;
- source/viewer session-generation mismatch;
- region ID or capture-generation mismatch;
- viewer version ahead of source.

Region generation must change when a region/capture source is recreated. Session generation must change when the session identity is renewed. This prevents an old region ID/version from appearing current after restart or reuse.

### Local pipeline age

Local queue/pipeline age is computed only if enqueue and observation ticks use the same declared monotonic clock domain and the observation tick is not earlier than enqueue:

`local_age_ticks = observed_at_ticks - enqueued_at_ticks`

This is an endpoint-local software duration. It is not cross-host one-way delay, remote presentation, or physical input-to-photon time. A viewer presentation callback is not evidence that photons reached the display.

Version freshness and local age are independent: version lag may be known even when clock evidence is missing.

### Relevance and class

Region class and relevance are supplied by a documented source or an explicit user choice. The v0.1 type includes CriticalInteraction, ActiveInteraction, PointerOrCaretFeedback, Background and Unclassified. The module never infers these from pixels or content.

Declared relevance is optional and constrained to 0..=100. It is descriptive metadata, not authorization. It must not grant access, change a permission, suppress a revocation, or let one region starve control/audio/bulk.

## 3. How this should affect scheduling (not yet integrated)

Do not immediately feed relevance scores into the WDRR policy. First collect region freshness vectors and compare them with ordinary frame AoI and byte-fair scheduling.

After provenance and human comprehension are established, a later scheduler may use *bounded* region classes as an input to a freshness objective, while preserving:
- control transition service reservations;
- audio deadline service;
- minimum fair service for background regions;
- bulk transfer progress;
- bounded queues;
- codec dependency correctness;
- privacy and explicit user control.

A region's task relevance must never become a hidden trust score or an authorization capability.

## 4. Comparison programme

Compare the following on identical captures, codecs, transports, endpoints, network impairments and workload traces:

1. Frame timestamp AoI.
2. Version lag only.
3. Per-region Version AoI vector.
4. Per-region Version AoI plus explicitly declared, opt-in relevance.
5. The above with byte-weighted WDRR, maintaining the same control/audio/bulk minimum service.

Report separately:
- frame AoI distribution;
- version-lag distribution and version semantics;
- per-region p50/p95/p99 and worst-region lag;
- critical-region-only p95/p99, when a trusted explicit class exists;
- local stage-age distribution and clock domain;
- unknown/missing evidence rate;
- bytes consumed per useful decodable update;
- queue occupancy, starvation and class fairness;
- time to first useful decoded/presented state;
- physical input-to-photon only from calibrated #457 external instrumentation.

No aggregate score. Keep quality, responsiveness, fairness, privacy, authority correctness and energy as separate axes.

## 5. Synthetic workload corpus

[version-aoi-regions-v0.1.json](../../benchmarks/version-aoi-regions-v0.1.json) defines 12 synthetic scenarios:
- small active control region changes among large background updates;
- critical region stops updating while background remains current;
- cursor/caret rapid updates;
- region ID reuse after capture restart;
- version duplicates, gaps, reorder and replay;
- source/viewer session generation mismatch;
- clock-domain mismatch and clock regression;
- missing region/version metadata;
- forged or changed relevance metadata;
- high-relevance flood designed to starve other classes;
- reconnect with version reset;
- privacy-field leakage negative control.

Synthetic fixtures are protocol/semantics tests only. They never produce performance PASS or product qualification.

## 6. Research basis and limits

- Erfan Delfani et al., *From Timestamps to Versions: Version AoI in Single- and Multi-Hop Networks*, accepted at IEEE INFOCOM 2026; published in IEEE Xplore on 29 June 2026. The paper analyzes VAoI distributions and scheduling policies for single- and multi-hop network models.
- Chen-Rui Jien and Tung-Wei Kuo, *Online Age of Information Scheduling: The Power of Packet Management and Fairness*, Computer Networks 289, article 112690 (October 2026), DOI 10.1016/j.comnet.2026.112690. Their model shows packet management and fairness are jointly important; greedy newest-message-first can starve terminals. This motivates the Xenia evaluation but is not direct remote-desktop evidence.
- RFC 8836 and RFC 8868 define interactive real-time media congestion-control requirements and reproducible evaluation scenarios.

The papers' terminal/network models do not include Xenia's UI regions, codecs, recipient consent or operating-system effect boundaries. Those semantics must be independently defined and measured.

## 7. Acceptance and claim ceiling

- Region identity includes session and region generations.
- Missing, mismatched, future or regressed evidence is UNKNOWN/INDETERMINATE, never fresh.
- Version freshness and local pipeline age are independent results.
- No cross-host timestamp subtraction or photon claim is possible in this module.
- No content-bearing field is introduced.
- Region/task weights cannot grant authority or starve other delivery classes.
- Tests and synthetic corpus pass exact-head Rust checks before any runtime integration.
- A human study must test comprehension and control before users are asked to assign importance weights.
- A full matched benchmark must precede any claim of outperforming SOTA.

**Current evidence state:** source-level implementation and deterministic unit tests authored; test execution, CI, hardware measurement, user study, runtime integration and external product comparison are not claimed.
