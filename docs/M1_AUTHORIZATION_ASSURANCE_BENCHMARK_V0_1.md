# M1 authorization assurance benchmark profile v0.1

**Status:** preregistration proposal; no comparative measurements have been produced.
**Owner:** Xenia #505, composed with Mycelix LISE #6136, #6213, #6236, #6140, #6170, #6189 and #6193.
**Candidate implementation:** Xenia M1 lanes in PR #509. Current route manifest is explicitly incomplete; see `M1_ROUTE_MEDIATION_INVENTORY_V0_1.json`.

## 1. Research objective

Evaluate not only whether a policy engine returns the expected decision, but whether the **exact protected effect** is admitted by the correct authority, remains valid at the effect owner, traverses a complete set of known enforcement routes, and is accounted for afterwards.

The benchmark has two separate tracks. Never combine them into one latency or security score:

- **Track A — authorization decision:** subject/action/resource/context decision correctness and decision latency.
- **Track B — delegated remote-effect assurance:** whether an effect-capable action is correctly bound, mediated, revoked, committed, observed and reconciled across Xenia's actual M1 lanes.

The key separations are:

```
task completion != authorization correctness
policy decision != effect-owner admission
admission != dispatch
dispatch != local commit
local commit != receiver acknowledgement
acknowledgement != independent observation
unknown outcome != no effect
```

## 2. Track A — matched authorization decision

### Comparator arms

1. **OPA** policy evaluation using a pinned Rego bundle and equivalent input. OPA's `opa bench` measures query evaluation and reports samples, ns/op, memory bytes/op, allocations/op and quantiles; it excludes preparation such as loading, parsing and compilation. Benchmark startup/bundle load separately. See [OPA policy performance](https://www.openpolicyagent.org/docs/policy-performance) and the [OPA benchmark dashboard](https://open-policy-agent.github.io/opa/).
2. **Cedar** policy evaluation using a pinned schema, policy set and entity/context corpus. Record validation at policy-load/update time separately from per-request decision cost. Cedar documents a formally proved schema-validation soundness result using a Lean implementation and differential tests against the Rust implementation; that is a validation-assurance comparator, not proof that a policy expresses the intended user authority. See [Cedar validation](https://docs.cedarpolicy.com/validation.html).
3. **OpenFGA** relationship authorization using the same subject/object/relationship cases. Pin model revision, datastore, cache configuration and consistency option. When caching is enabled, `HIGHER_CONSISTENCY` bypasses the cache; `MINIMIZE_LATENCY` may use it. Do not compare different consistency or cache semantics as if they were equivalent. See [OpenFGA query consistency options](https://openfga.dev/blog/query-consistency-options-announcement).
4. **Zanzibar-style reference arm** for causal authorization-change semantics. This is a comparator design, not Google's production Zanzibar. The original Zanzibar paper reports trillions of ACLs, millions of authorization requests per second, p95 latency below 10 ms and availability above 99.999% over three years of production at Google. These are paper-reported deployment metrics, not a directly reproducible target for this prototype. See [USENIX ATC 2019](https://www.usenix.org/conference/atc19/presentation/pang).
5. **Xenia local M1 policy arm** with local consent and exact lane checks, measured both with and without the optional Mycelix adapter when that adapter exists.
6. **No-enforcement negative control** only in a disposable deterministic sandbox, to prove the oracle detects out-of-scope effects. Never expose this arm to a real host or production resource.

### Frozen workload

Every arm receives semantically equivalent cases and the same frozen subject, action, resource, purpose, audience, policy revision, relationship graph and expected decision.

Include at minimum:
- allow and deny positive controls;
- missing/unknown context;
- expired, revoked and stale-epoch authority;
- wrong principal/delegate and cross-resource requests;
- exact action and direction mismatch;
- child scope widening;
- required-scope AND versus independent-grant OR composition;
- duplicate/replay and changed operation fingerprint;
- cache warm/cold and policy/model update;
- long lineage and relationship fanout;
- partitioned or delayed revocation visibility.

Where an engine cannot express a dimension, mark it **UNSUPPORTED**. Do not silently omit it from the denominator or translate it into a weaker permit.

### Metrics

Report separately:
- false permit and false deny counts/rates;
- correct DENY and correct INDETERMINATE/HOLD classification;
- decision latency p50/p90/p95/p99/p99.9/max;
- throughput and queueing under concurrency;
- CPU, RSS, allocations/op and bytes/op;
- policy/model compilation and load time;
- cold/warm behavior and update/cache-invalidation cost;
- relationship/lineage depth and fanout;
- revocation visibility lag and worst stale-authority exposure.

Include raw samples, exact versions, machine profile, OS, compiler/runtime, policy/model digests and harness SHA.

## 3. Track B — delegated remote-effect assurance

### M1 route units

The first candidate routes are the eight Xenia action lanes:

| Lane | Action identity | Direction | Protected effect owner |
|---|---|---|---|
| StreamFrame | `xenia.screen.view` | host → viewer | screen capture and frame transport |
| StreamTelemetry | `xenia.host.telemetry` | host → viewer | host telemetry source and transport |
| StreamAudio | `xenia.audio.capture` | host → viewer | audio source and transport |
| ReadHostClipboard | `xenia.clipboard.read` | host → viewer | host clipboard read and transport |
| WriteHostClipboard | `xenia.clipboard.write` | viewer → host | operating-system clipboard |
| InjectInput | `xenia.input.inject` | viewer → host | platform input injector |
| SendFileToViewer | `xenia.file.send` | host → viewer | host file source and transfer transport |
| ReceiveFileFromViewer | `xenia.file.receive` | viewer → host | staging and final filesystem publication |

The consent socket, sealed operator channel, admin HTTP/WebSocket router, session/rekey paths and file-transfer dispatcher are separate control-plane/transport surfaces. They must not be collapsed into the eight data-lane permissions. The route inventory is not complete until all effect-capable alternatives are enumerated independently.

### Candidate assurance composition

For an eventual Mycelix-integrated candidate, a protected operation must satisfy all applicable layers conjunctively:

```
authenticated principal + delegate
AND current, content-bound ROS-005 delegation and parent lineage
AND exact action + resource + direction + purpose + audience + data class
AND exact operation/payload commitment where applicable
AND recipient consent for the M1 lane
AND current Xenia session/rekey state
AND owner-local final gate at the effect boundary
=> may attempt the named effect
```

A positive result from one layer never promotes another. A Holochain zome-call capability is not semantic delegation; ROS-005 is not recipient consent; consent is not host OS authorization; a policy decision is not an effect receipt.

Until ROS-005 exposes the missing effect-scope fields and authenticated currentness evidence, unsupported dimensions remain HOLD/INDETERMINATE. Do not create a second Xenia delegation service to make a benchmark row look supported.

### Trace model

For each operation, record distinct events:
1. request formed and canonical operation identity fixed;
2. recipient consent decision;
3. semantic delegation/currentness decision;
4. local lane preflight;
5. final effect-owner authorization;
6. effect attempted/dispatched;
7. local commit result;
8. receiver/provider acknowledgement (when available);
9. independent observation (when genuinely independent);
10. reconciliation of unknown or partial outcome.

Bind each event to operation ID, monotonic session sequence, lane/action, direction, resource/host, session fingerprint/rekey epoch, consent reference, delegation content commitment/authority epoch when available, policy/profile digest and event-time/knowledge-time data. Do not log clipboard contents, raw file bytes, input payloads, screen/audio samples, or bearer/CapSecret material.

### Adversarial scenario panel

Start with at least 64 deterministic known-answer scenarios, then expand to at least 128 development cases and a sealed, independently adjudicated holdout. Include:
- each lane granted alone; every unrelated lane remains denied;
- screen permission cannot read clipboard, inject input, or send/receive files;
- clipboard read/write and file send/receive are directionally independent;
- child action/resource/time/parent/epoch widening attempts;
- parent revoke with cached child and grandchild;
- DHT/currentness visibility delayed, missing or conflicting;
- stale session, reconnect, rekey, daemon restart and old-session replay;
- consent revoked after source preflight but before final effect gate;
- source read occurs before revoke but transport send is after revoke;
- incoming file staging succeeds but final publication is revoked;
- send dispatched but acknowledgement is lost;
- duplicate/reordered/replayed file chunks and acknowledgements;
- operator revoke during a live sealed channel;
- direct host API, alternate transport, background worker and ambient-credential bypass;
- incomplete route inventory;
- malformed/unknown mandatory AuthZEN obligation;
- ambiguous user intent requiring principal clarification before action;
- valid positive controls for unrelated independent grants after a scoped revoke.

Each case must freeze the exact action, lane, direction, resource, purpose, audience, expected consent, currentness evidence, parent chain, session epoch, effect boundary, fault schedule and expected effect state. Keep the oracle independent from the candidate route manifest and enforcement code.

### Metrics and non-compensatory gates

Hard gates (prospective targets, not achieved results):
- zero false permits on the high-severity holdout;
- zero unauthorized protected effects in the finite deterministic panel;
- 100% rejection of finite child-widening, wrong-direction and cross-resource controls;
- zero effects after an effect owner has observed effective revocation in the tested scope;
- zero duplicate effect-bearing dispatches for a one-shot capability under tested concurrency/failure histories;
- zero blind retries after UNKNOWN/PARTIAL effects before qualified reconciliation;
- 100% correct HOLD/INDETERMINATE classification for incomplete route/currentness evidence;
- no complete-mediation PASS when route inventory is incomplete.

Also report false-deny rate on positive controls, time-to-revocation per route, worst stale exposure duration, route-inventory recall, unknown/partial reconciliation latency, evidence independence, task completion and clarification burden. None of these can offset a false permit or unauthorized effect.

### Performance targets after correctness gates

The local warm decision target remains aspirational:
- p50 ≤ 1 ms;
- p95 ≤ 2 ms;
- p99 ≤ 5 ms;
- lineage depth ≤ 8;
- named reference host, compiler, OS and workload.

These are not measured results. For distributed/effect-boundary runs, report coordination round trips, durable consumption cost, revocation propagation and network/OS latency separately. A globally consistent one-shot capability necessarily pays the cost of its actual coordination protocol; do not claim partition availability and globally unique consumption without a concrete protocol and assumptions.

## 4. Recent agent-benchmark comparators

Two 2026 benchmark papers reinforce why authorization and side-effect safety must be separate from task success:

- **AuthorizationBench**: 286 tasks across ten application domains and 6,864 trajectories; reports 19.2% out-of-authorization trajectories in its evaluated models/harnesses, with configurations from 10.5% to 26.6%. It also reports lower out-of-authorization rates in runs that consulted the principal (14.0%) than runs that did not (21.6%). These are study-specific results, not Xenia baselines. [Paper](https://arxiv.org/abs/2610.27548).
- **SABench**: 201 email/calendar/ticket tasks and 2,211 model-task runs; reports 15.2% collateral-damage runs and 12.8% unauthorized writes among goal-satisfied runs. Its trace oracle scores task success and authorization compliance independently. [Paper](https://arxiv.org/abs/2610.34167).

Use these as design comparators: leave out-of-scope routes executable and observable in a deterministic sandbox, and score task success, authorized effect, unauthorized side effects and evidence confidence as separate axes. Do not compare their headline percentages directly with M1 runtime tests or with policy-engine microbenchmarks.

## 5. Interoperability and standards

Use OpenID AuthZEN Authorization API 1.0 as the PDP↔PEP interoperability boundary rather than inventing a competing policy query protocol. Treat the AuthZEN Obligations Profile 1.0 as a version-pinned Working Group Draft, not a final standard. If negotiated, a PEP that cannot execute a mandatory obligation must deny; transport/authority uncertainty remains a separate local HOLD/INDETERMINATE condition.

References:
- [OpenID AuthZEN specifications](https://openid.net/wg/authzen/specifications/)
- [AuthZEN Profile for Obligations 1.0 Draft 1](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html)
- [Holochain 0.7.1 upgrade guide](https://developer.holochain.org/resources/upgrade/upgrade-holochain-0.7/)

Holochain 0.7.1 remains a separate substrate qualification. The benchmark does not pass it by exercising the pure Rust ROS-005 model.

## 6. Reporting and reproducibility

Every run publishes:
- scenario and oracle digests;
- candidate, evaluator and policy/model exact SHAs;
- engine/runtime/OS/toolchain versions;
- host hardware and workload settings;
- raw trace, timings and resource samples;
- positive/negative/indeterminate/unsupported/not-run denominators;
- all minimized counterexamples;
- missing evidence and unsupported guarantees;
- independence and shared-dependency disclosure;
- confidence intervals for repeated/stochastic runs;
- claim ceiling and untested route inventory.

Do not aggregate into a universal “authorization assurance score.” Publish separate correctness, safety, performance, operational and evidence-coverage results. A finite benchmark supports only claims about its declared route universe, scenario corpus, effect owners and fault model.

## 7. Ownership boundaries

- Xenia #508/#509: local M1 lane permissions and runtime gate implementation.
- Xenia #504: effect-commit ordering, timeout and UNKNOWN reconciliation.
- Xenia #506: consume authenticated authority freshness/frontier evidence.
- Xenia #510: producer-side authorization/attempt/commit/observation evidence stages.
- Xenia #517: ROS-005 ↔ M1 adapter scope and missing dimensions.
- Xenia #518: source route inventory and alternate-path/bypass controls.
- Xenia #505: matched benchmark corpus and harness.
- Mycelix #3659/#3677/#3680: semantic delegation and parent/content identity.
- Mycelix #4903/#6236: DHT/currentness and trajectory-wide revocation.
- Mycelix #6136/#6213/#6140/#6170/#6189/#6193: exact effectuation, route completeness, evidence provenance, agent authorization, one-shot effect interposition and concurrency/failure semantics.

This profile composes those owners. It does not create a parallel authority, policy, route-inventory, event or revocation service.
