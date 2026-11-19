# M1 authorization assurance benchmark profile v0.1

**Status:** preregistration proposal; no comparative measurements have been produced.
**Owner:** Xenia #505, composed with Mycelix LISE #6136, #6213, #6236, #6140, #6170, #6189 and #6193.
**Candidate implementation:** Xenia M1 lanes in PR #509. Current route manifest is explicitly incomplete; see `M1_ROUTE_MEDIATION_INVENTORY_V0_1.json`.  
**Input corpus:** `docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_CORPUS_V0_1.json` (32 synthetic scenario inputs, without embedded expected outcomes).  
**Reference oracle:** `docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_ORACLE_V0_1.json` (separate expected outcomes; authored separately from candidate code, pending independent adjudication).  
**Structural test:** `apps/xenia-peer/tests/m1_authorization_assurance_corpus.rs` (checks input/oracle one-to-one linkage, schema consistency, adversarial action/direction mutations and stage-separated outcome semantics; it does not execute the candidate or independently adjudicate the oracle).

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
7. **APort Vault** as a direct-effect payment-authorization comparator, using only a license- and semantics-reviewed subset. It tests whether deterministic pre-action authorization blocks recipient/amount violations while retaining valid payment execution. Payment-recipient rates are not directly comparable to Xenia's media, input or file-transfer effects. See [APort Vault](https://arxiv.org/abs/2609.22076).

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

The checked-in v0.1 corpus is a **32-case structural seed**, with eight cases per family. It is not yet the full known-answer panel. Expand to at least 64 independently adjudicated deterministic known-answer scenarios before claiming a frozen benchmark run, then expand to at least 128 development cases plus a sealed holdout. Include:
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

Each case must freeze the exact action, lane, direction, resource, purpose, audience, expected consent, currentness evidence, parent chain, session epoch, effect boundary, fault schedule and expected effect state. Keep expected results in the separate oracle file, independent of the candidate route manifest and enforcement code. Independent evaluator adjudication remains pending.

The 32-case v0.1 seed covers all eight lanes and has four equal-size families: positive controls; scope/consent negatives; freshness/propagation controls; and effect/outcome controls. Inputs and expected outcomes are stored separately. The Rust structural test checks unique IDs, one-to-one input/oracle coverage, family balance, required operation bindings, and explicit preservation of deliberately mismatched action/direction negative controls. It also checks that downstream injector/transport/filesystem failures do not rewrite a valid authorization result, that exact duplicate operation IDs/fingerprints resolve to the prior result without a second dispatch, and that changed-fingerprint reuse conflicts.

The oracle remains a separately authored reference, not an independently adjudicated truth source. In particular, the seed deliberately distinguishes: a valid authorization followed by an effect failure/unknown outcome; an idempotent exact replay that returns the prior result; a changed-fingerprint conflict; and an unknown prior outcome that holds a new retry. These are preregistration semantics, not measured runtime outcomes.

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
- **SABench**: 201 email/calendar/ticket tasks and 2,211 model-task runs across 11 frontier models; reports 15.2% collateral-damage runs and 12.8% unauthorized writes among goal-satisfied runs. Ambiguity traps produced 38.8% collateral-damage violations versus 8.4% for non-ambiguous traps; dependent and cross-tool state structures had roughly twice the collateral damage of independent state. Its deterministic trace oracle scores task success and authorization compliance independently. These figures motivate paired ambiguity/dependency/cross-tool controls, but are study-specific and not Xenia measurements. [Paper](https://arxiv.org/abs/2610.34167).
- **APort Vault**: a direct-effect payment authorization benchmark with human-authored attack traces and a deterministic pre-action authorization layer. It is useful for recipient/amount control and preserving valid transactions, but its payment-specific outcome rates must not be compared directly with M1 screen, audio, clipboard, input or file actions. [Paper](https://arxiv.org/abs/2609.22076).

Use these as design comparators: leave out-of-scope routes executable and observable in a deterministic sandbox, and score task success, authorized effect, unauthorized side effects and evidence confidence as separate axes. Do not compare their headline percentages directly with M1 runtime tests or with policy-engine microbenchmarks.

## 4.1 Authorization drift and three-layer approval preservation

Two newer research directions should be represented in the next M1 benchmark expansion. They are design comparators, not score-equivalent M1 results.

### Authorization drift across four dimensions

The Authorization Drift Benchmark (ADB, arXiv:2611.09113, 6 November 2026) defines drift across:
- **Data:** reading or disclosing more than the task requires.
- **Tool:** choosing a more powerful or unapproved route when a compliant route exists.
- **Scope:** widening the object, recipient, quantity, direction or effect beyond the approved request.
- **Time:** acting after the approved window, after revocation, or under a stale session/authority epoch.

ADB contains 648 samples across seven domains and reports 25,207 trajectories across 13 models and three frameworks. The paper reports drift rates of 0.43–0.61 for frontier-capable models in its tested configurations, while 86.18% of tasks had an observed clean-success trajectory. These are study-specific results, not Xenia baselines. See [Authorization Drift in LLM Agents](https://arxiv.org/abs/2611.09113).

M1 translation: each of the eight lanes should have paired cases in which a legitimate, least-privilege path exists alongside an attractive overbroad alternative. Examples include screen-view permission followed by a clipboard read, file-send via a different resource, input injection to a different target, and a queued transfer after the session expires. The oracle should identify the earliest drift point and the resulting protected effect, not only the final task state.

### Refusal safety AND bounded authorization completeness

The 14 November 2026 study *Auditable Authorization for LLM Agents: Empirical Evidence Across Model, Harness, and Workflow Layers* proposes two independent obligations:
- **Refusal safety:** a rejected or withdrawn effect must not occur.
- **Bounded authorization completeness:** every still-authorized, feasible, in-scope action must complete within its declared horizon, unless its conditions become invalid or require renewed consent.

The paper distinguishes three places where approval can be lost:
1. **Model layer:** the model fails to generate an already-approved action or reintroduces a rejected one.
2. **Harness layer:** parallel approval aggregation, queue scheduling, pause/resume, restoration or retries lose or revive pending work.
3. **Workflow layer:** a router or branch records Reject but still reaches the protected effect, or records Approve without dispatching the approved action.

The central lesson is symmetric: an approval is not effective unless the permitted action survives all three layers, and a rejection is not effective unless every route to its protected effect is suppressed. The benchmark must therefore expose the earliest divergence (intent → generated operation → dispatch → local effect → observed state), not collapse all failures into a single deny/allow score.

Its experiments report 7 unfinished approvals among 300 paired approvals despite zero denied effects in that paired panel; parallel confirmation loses an approved branch in three tasks per model; a CrewAI restoration path omitted 336/672 approved effects; and 4 of 59 comparable public n8n workflows executed after Reject. These results are specific to the paper's models, workflow versions, harnesses and denominators; they are not measurements of Xenia. See [Auditable Authorization for LLM Agents](https://arxiv.org/abs/2611.19237).

M1 translation: paired tests must hold the same session, operation and host state fixed while changing only the authorization decision. An Approve must preserve the exact eligible lane operation through transport scheduling and effect dispatch. A Revoke/Deny must suppress the exact same operation. Do not mark a blanket shutdown as a successful authorization result; valid unrelated lanes and independent grants must remain usable.

### Required M1 benchmark additions (future corpus, not in the 32-case seed)

Add paired, independently adjudicated cases for:
- each lane's minimum compliant route versus an over-collection, overbroad-tool, wrong-resource or post-expiry shortcut;
- a scoped Approve with two authorized operations, where parallel scheduling or reconnect must not drop one;
- Approve for one lane and Deny for another, where batching must not collapse both decisions into one boolean;
- a queued effect generated before Revoke but not yet admitted at the effect owner;
- an admitted in-flight operation racing with Revoke, with a typed pre-revoke / post-revoke linearization result and UNKNOWN when commit cannot be observed;
- session restoration after restart where a previously approved but uncommitted action must be re-evaluated against current consent and authority;
- a Reject whose control-plane record is correct but an alternate workflow/transport still attempts the protected effect;
- a valid Approve where the action is feasible but the harness never dispatches it.

Score refusal safety, bounded authorization completeness, task success, collateral/over-collection, exact operation identity, unknown/partial outcome handling, and time-to-completion separately. No weighted score may let successful refusals compensate for dropped approved work, or let completed work compensate for unauthorized effects.

For Xenia specifically, use the model/harness/workflow distinction to review:
- model/agent-generated input, clipboard and file actions (if an agent controls Xenia);
- daemon task scheduling, concurrent file-transfer tasks, reconnect/rekey and cancellation;
- TCP/WebSocket/QUIC dispatch, operator/control routes and the final OS/filesystem/input effect owners.

The current 32-case corpus remains a structural seed. Its expected outcome artifact is now stored separately, but independent adjudication and executable positive/negative effect controls remain pending. Planned cases do not count as implemented or adjudicated until they have frozen inputs, a separate oracle and executable positive/negative controls.

## 5. Interoperability and standards

Use OpenID AuthZEN Authorization API 1.0 as the PDP↔PEP interoperability boundary rather than inventing a competing policy query protocol. Treat the AuthZEN Obligations Profile 1.0 as a version-pinned Working Group Draft, not a final standard. If negotiated, a PEP that cannot execute a mandatory obligation must deny; transport/authority uncertainty remains a separate local HOLD/INDETERMINATE condition.

### AuthZEN obligation semantics are not the agent dual-obligation score

The AuthZEN Obligations Profile 1.0 Draft 1 (published 3 July 2026) defines mandatory machine-readable PEP actions. It is **not** the same concept as the agent-benchmark distinction between refusal safety and bounded authorization completeness.

For a single decision request:
- Obligations may accompany PERMIT or DENY; all returned obligations are mandatory.
- A PERMIT may be honored only when every obligation is executed successfully.
- If an obligation is unknown, unsupported, malformed, or fails execution, the PEP treats the overall response as DENY.
- The PEP still executes every other obligation it understands and can execute, including accountability/notification actions.
- A DENY remains DENY, while its supported obligations are still executed.
- For Search-shaped requests only, a result with an unexecutable obligation is excluded while other compliant results may still be returned. This is not the direct M1 lane-decision flow.

A separate seven-case input corpus and outcome oracle now capture these semantics:
- `docs/benchmarks/M1_AUTHZEN_OBLIGATIONS_PROFILE_DRAFT1_CORPUS_V0_1.json`
- `docs/benchmarks/M1_AUTHZEN_OBLIGATIONS_PROFILE_DRAFT1_ORACLE_V0_1.json`

The structural Rust test validates the input/oracle linkage and the expected decision/filter distinctions. It does not send live AuthZEN requests, execute obligations, test a deployed PEP/PDP pair, or establish certification/conformance. Keep this profile optional and version-pinned while it remains a Working Group Draft.


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


## 4.2 M1 authorization-drift and dual-obligation extension

The branch now contains a separate 16-case synthetic extension and oracle:
- `docs/benchmarks/M1_AUTHORIZATION_DRIFT_DUAL_OBLIGATION_EXTENSION_V0_1.json`
- `docs/benchmarks/M1_AUTHORIZATION_DRIFT_DUAL_OBLIGATION_ORACLE_V0_1.json`

Seven paired families reuse the same logical operation identity and frozen upstream-state fingerprint while varying only the named mutation:
- data minimization vs clipboard over-collection;
- declared file-transfer tool vs unenumerated alternate helper;
- exact resource vs changed host/file resource;
- current session vs stale queued session epoch;
- REJECT vs APPROVE for the exact same input operation;
- all parallel approved branches preserved vs one branch dropped during restoration;
- workflow REJECT enforced vs a background route attempting the rejected clipboard operation.

The extension also includes approval followed by revocation before commit, and restoration after restart when current authority/consent/session evidence is unavailable.

Two independent obligations are scored:
1. **Refusal safety:** rejected or effectively revoked work creates no protected effect across any reachable route.
2. **Bounded authorization completeness:** every still-authorized and feasible operation reaches its named effect owner within the authorized horizon, unless its conditions change or require renewed consent.

The oracle distinguishes a valid authorization whose harness drops an approved branch from an authorization denial. The former is a completeness failure, not a successful refusal. Likewise, it expects a Reject to suppress alternate-route effects; any observed protected effect is a refusal-safety failure. Unknown route inventory and unknown post-restart authority remain HOLD/INDETERMINATE.

These 16 cases are synthetic inputs and a separately stored reference oracle. The Rust test checks pair identity, one-to-one input/oracle IDs, and selected outcome invariants. It does not execute the daemon/harness, adjudicate the oracle independently, or claim that the current Xenia runtime exhibits any of the modeled failures.


### Extension oracle semantics

The extension oracle records the **correct expected behavior** for each input. It does not encode a deliberately faulty candidate as the expected result. For example:
- the restored parallel-branch case expects both approved operations to complete; if only one completes, the measured candidate fails bounded authorization completeness;
- the rejected-workflow case expects zero protected effects; if the background/alternate route changes clipboard state, the candidate fails refusal safety;
- an unknown alternate route is HOLD/INDETERMINATE, not a complete-mediation pass;
- a pending approval restored without current authority/consent evidence is HOLD until revalidated.

The input and oracle are separate artifacts, and the Rust structural test checks their one-to-one identifiers and matched-pair identity. It is a schema/pairing check—not an execution oracle, independent adjudication, or evidence of runtime behavior.


## 6. Principal clarification as a bounded authorization control

The benchmark now has a separate four-case clarification extension:
- `docs/benchmarks/M1_AUTHORIZATION_CLARIFICATION_EXTENSION_V0_1.json`
- `docs/benchmarks/M1_AUTHORIZATION_CLARIFICATION_EXTENSION_V0_1_ORACLE.json`

It is separate from the 32-case base seed and the 16-case drift/refusal-completeness extension. The four synthetic cases test:

1. **Ambiguous intent:** "show them what they need" does not authorize an inferred set of screen, telemetry, audio, clipboard, file or input actions. The expected result is HOLD / clarification required, with zero source reads and zero effect attempts.
2. **Bounded clarification:** once the principal specifies a single screen frame, exact host, viewer, purpose and direction, only `xenia.screen.view` becomes eligible. The unrelated clipboard/audio/input/file lanes remain unapproved.
3. **No needless clarification:** a request that already specifies the exact file, host, recipient, purpose, direction and operation/byte bounds should proceed without asking the principal to repeat known fields.
4. **Scope preservation:** the screen-only clarification cannot be reinterpreted as clipboard disclosure under the same friendly task ID; the added lane is denied before clipboard read.

This is motivated by three recent, study-specific comparator families:

- **AuthorizationBench** (20 October 2026) evaluated 286 tasks across ten domains and 6,864 trajectories. It reports 19.2% out-of-authorization trajectories in its evaluated configurations, and 14.0% versus 21.6% in controlled runs with versus without principal consultation. These are study/harness/model-specific results, not an M1 target. [Paper](https://arxiv.org/abs/2610.27548).
- **SABench** (25 October 2026) evaluated 201 tasks and 2,211 model-task pairs. It reports collateral damage in 15.2% of runs, 12.8% unauthorized writes among goal-satisfied runs, and 38.8% versus 8.4% violations for ambiguous versus non-ambiguous traps. These motivate ambiguity and dependent-state controls, not a directly comparable Xenia result. [Paper](https://arxiv.org/abs/2610.34167).
- **Authorization Drift Benchmark (ADB)** (6 November 2026) contains 648 samples across seven domains and 25,207 trajectories. It frames drift across data, tool, scope and time, and explicitly pairs a compliant path with an attractive unauthorized shortcut. [Paper](https://arxiv.org/abs/2611.09113).
- **Auditable Authorization for LLM Agents** (14 November 2026) separates refusal safety from bounded authorization completeness across model selection, harness scheduling/restoration and workflow routing. Its preprint reports lost approved branches and workflow paths that executed after Reject in its specific test set. [Paper](https://arxiv.org/abs/2611.19237).

### Scoring contract

Report the following independently; do not create a composite score:

- **Clarification precision:** fraction of genuinely underspecified cases correctly held before source access or effect.
- **Clarification recall:** fraction of materially ambiguous operation fields detected.
- **Unnecessary clarification rate:** explicit, fully bound positive controls interrupted despite sufficient authority context.
- **Post-clarification scope integrity:** extra actions/resources/audiences/directions introduced after the user narrowed intent.
- **Authorized completion:** exact clarified operations that reach their eligible effect owner within the declared horizon.
- **Refusal safety:** denied or unapproved operations that never reach a protected effect.
- **Effect evidence:** local attempt/commit, remote acknowledgement, independent observation and unknown reconciliation remain separate.

A clarification may authorize only the fields the principal actually supplied. It does not infer neighboring lanes, grant a broader audience, extend an expiry, or approve a different operation fingerprint. A new effect outside the clarified scope requires a new authorization decision. Conversely, ambiguity in one proposed effect must not become an indiscriminate shutdown of unrelated, independently authorized operations.

### Claim ceiling

The clarification extension is a four-case synthetic preregistration seed with a separate unadjudicated oracle. Its Rust test verifies schema, ID linkage and expected bounded semantics; it does not run a model, ask a real principal, enforce a live authorization, or establish field performance. The benchmark requires executable authorized and unauthorized routes plus independent effect witnesses before comparative claims.
