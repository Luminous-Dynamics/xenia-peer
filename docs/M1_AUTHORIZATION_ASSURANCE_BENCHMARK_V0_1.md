# M1 Authorization Assurance Benchmark v0.1

**Status:** preregistration / development protocol, not benchmark results, certification, or production qualification.  
**Owner:** Xenia #505, composed with #508, #510, #512, #517 and #518.  
**Cross-project owners:** Mycelix #6136 (exact-operation effectuation), #6213 (route mediation), #6236 (revocation propagation), #6140 (observation provenance), #6170 (agent authorization), #6189 (one-shot effect interposition), #6193 (distributed consumption consistency).  
**Seed corpus:** `docs/benchmarks/M1_AUTHORIZATION_ASSURANCE_CORPUS_V0_1.json`.

## 1. Research question and contribution

Can a remote-session system keep every consequential host/viewer operation inside the principal's exact, current, recipient-consented authority—and can an evaluator distinguish a policy decision from the effect that actually occurred?

The benchmark is deliberately split into two tracks:

- **Track A — decision-engine equivalence.** Measure policy decision and relationship-resolution costs under identical semantics and state.
- **Track B — delegated remote-effect assurance.** Measure complete mediation, exact lane/direction/resource binding, consent and delegation composition, revocation observation, effect-boundary checks, and outcome accounting.

A fast policy decision is not evidence that the protected operation was authorized at its final boundary. Likewise, a successful remote-session task is not evidence that every realized side effect was within scope.

The Xenia-specific seed corpus uses the eight existing M1 lanes. It is a starting panel; it does not claim to enumerate all Xenia routes or generalize to every authorization domain.

## 2. Core separations

The evaluator MUST keep the following propositions distinct:

```
task success
  != authorization correctness
  != PEP invocation / route coverage
  != local effect attempt
  != local effect commit
  != transport acknowledgement
  != receiver verification
  != independent observation
```

The following authority layers are independently required where applicable:

1. authenticated principal, delegate and workload/session identity;
2. Mycelix ROS-005 semantic delegation (action, resource, mode, parent lineage, epoch and validity);
3. Mycelix ROS-004 consent for disclosure/read audience, purpose, data class and field scope;
4. Xenia session/rekey state and exact M1 lane/direction;
5. owner-local OS, filesystem, transport or receiver-side enforcement.

No layer promotes another. Reputation or trust scores are not authority. A Holochain zome-call capability is not semantic delegation. Recipient consent is not execution authority. A ROS-005 permit is not a host-effect commit.

## 3. Fixed M1 lane vocabulary

| Lane | Action ID | Direction | Protected effect |
|---|---|---|---|
| StreamFrame | `xenia.screen.view` | Host → viewer | Disclose screen frames |
| StreamTelemetry | `xenia.host.telemetry` | Host → viewer | Disclose configured host telemetry |
| StreamAudio | `xenia.audio.capture` | Host → viewer | Disclose host audio |
| InjectInput | `xenia.input.inject` | Viewer → host | Apply keyboard/pointer input |
| ReadHostClipboard | `xenia.clipboard.read` | Host → viewer | Disclose host clipboard |
| WriteHostClipboard | `xenia.clipboard.write` | Viewer → host | Apply viewer clipboard content |
| SendFileToViewer | `xenia.file.send` | Host → viewer | Read and disclose a host file |
| ReceiveFileFromViewer | `xenia.file.receive` | Viewer → host | Stage, verify and publish a received file |

The direction is security-relevant. Read and disclose are not the same as write and apply. No lane implies another. Host administration, process execution, reboot, configuration changes and helper-binary control are separate control-plane capabilities and are outside this eight-lane action set.

## 4. Track A — matched authorization decision engines

Compare OPA, Cedar and OpenFGA only on a frozen, semantically equivalent workload:

- same subject/principal, delegate, action, resource, context and entity/relationship graph;
- same positive, negative, stale and unknown distributions;
- same delegation depth, parent fanout, policy size and update/revocation churn;
- same cache state and explicit consistency requirement;
- pinned engine, policy/model, schema and adapter versions.

Report two boundaries separately:

**Engine-only:** parse/load/compile excluded; time the evaluation or relationship check itself.

**End-to-end decision:** include serialization, adapter, PDP request/response and required remote graph access. Do not compare embedded OPA/Cedar evaluation to OpenFGA client/server network latency as though they are the same operation.

For every run publish p50, p90, p95, p99, p99.9, maximum, throughput, CPU, RSS, allocations/op, bytes/op, warm/cold state, model/policy load time and cache invalidation cost. Preserve raw samples and runner metadata.

OPA's `opa bench` and policy-performance guidance are useful evaluation baselines; they do not include every end-to-end loading or transport cost by default. Cedar schema validation is a separate assurance dimension from policy evaluation latency. OpenFGA consistency modes must be matched: a higher-consistency request can bypass a configured cache, but must not be described as globally linearizable unless the deployed datastore and protocol actually establish that property.

AuthZEN Authorization API 1.0 is the preferred interoperability boundary for PDP↔PEP experiments rather than a competing Xenia-specific wire protocol. The AuthZEN Obligations Profile 1.0 is a July 2026 Working Group Draft, not a final specification. When negotiated, mandatory obligations must be supported and executed; unknown, unsupported, malformed or unexecutable mandatory obligations result in PEP denial under that draft. Transport or authority-state uncertainty remains a separate HOLD/INDETERMINATE case.

## 5. Track B — delegated remote-effect assurance

Use the M1 routes as a domain-specific effect-bearing candidate adapter. The evaluator must retain out-of-scope paths as executable sandbox controls; hiding every forbidden path measures task completion, not authorization alignment.

For each operation capture these stages independently:

1. intent and exact operation projection;
2. authenticated principal/delegate/session;
3. delegation and consent references, including parent chain and epoch;
4. policy decision and decision inputs;
5. PEP/lane admission and route identity;
6. source-work preflight (before sensitive source read or resource work);
7. sealed/immutable operation identity and exact payload digest;
8. final owner-side lane/currentness check;
9. effect attempt and local result;
10. transport/provider acknowledgement;
11. receiver-side verification or filesystem publication result;
12. independent observation, when available;
13. unresolved/partial/unknown reconciliation.

An operation identity should bind at least the session fingerprint, monotonic per-session sequence, lane/action ID, direction, exact resource, operation/payload digest, schema/profile version and applicable authority epoch. Use owner-native references; do not create a second identity, evidence or revocation service.

### 5.1 Required fault and mutation families

The seed corpus begins with 32 scenarios across four families:

- **Positive controls:** one exact, fully authorized operation per M1 lane.
- **Scope/consent negatives:** lane substitution, direction confusion, resource mismatch, missing consent, wrong purpose/audience, expiry and revocation.
- **Freshness/propagation controls:** parent revocation, stale epoch, unknown parent/currentness snapshot, incomplete route inventory and stale rekey/session state.
- **Effect/outcome controls:** injector failure, transport uncertainty after dispatch, receiver verification failure, staging/publication failure, partial operation, duplicate/replay, changed operation under a reused ID and blind retry after UNKNOWN.

Each case freezes its inputs, route, authority/consent state, cutoff, expected decision, expected local effect state and expected reconciliation state. The oracle must be separately authored from the candidate enforcement implementation.

### 5.2 Non-compensatory gates

Prospective targets—not achieved results:

- zero false permits and zero unauthorized high-severity effects in the frozen held-out panel;
- 100% rejection of finite action, direction, resource, purpose, audience, parent-widening and stale-epoch negative controls;
- zero risk-increasing effects after the local PEP has observed effective revocation in the tested scope;
- zero duplicate effect-bearing dispatches for a one-shot operation under the declared consistency/failure model;
- zero blind mutation retries after UNKNOWN/PARTIAL unless a provider-qualified idempotency/reconciliation contract proves the retry safe;
- incomplete authority, route or revocation inventories remain HOLD/INDETERMINATE;
- unrelated independent grants remain usable after a scoped revoke;
- zero promotion of a sender/transport acknowledgement into receiver verification or human observation.

False denies, legitimate task completion and clarification burden are measured separately. No weighted score may allow latency, throughput or task success to compensate for a false permit or unauthorized effect.

## 6. External benchmark comparators

Use the following as protocol/design references, not as directly comparable headline rates:

- **AuthorizationBench** (286 tasks, 10 domains, 6,864 trajectories) reports out-of-authorization behavior in its evaluated agent/sandbox configurations. Its principal-consultation comparison motivates measuring clarification as an authorization control. These rates are specific to its tasks, models and harness.
- **SABench** (201 tasks, 47 templates, approximately 2,211 model-task runs) uses deterministic trace evaluation to score task success and authorization compliance separately; it highlights collateral effects and unauthorized writes even when the requested task succeeds.
- **APort Vault** studies agent payment authorization with a deterministic pre-action layer, human-authored attacks and recipient/amount constraints. Reuse only a license- and semantics-reviewed subset; payment-recipient results do not directly compare to screen, input or file-transfer operations.
- **Zanzibar** is a large-scale consistent relationship-authorization comparator. Its production scale and latency are contextual reference points, not a target for this small prototype.
- **OPA/Cedar/OpenFGA** are Track A decision-engine arms. Their native guarantees must be reported accurately; do not attribute downstream effect atomicity or independent observation to a policy engine.

No raw success or violation percentage is compared across different task populations. Build a common adapter subset and independently adjudicate each candidate's effect trace.

## 7. Performance targets and reporting

The current local warm objective—p50 ≤1 ms, p95 ≤2 ms, p99 ≤5 ms at lineage depth ≤8—is aspirational, not measured. It is valid only after naming the reference host, compiler/toolchain, policy/model, cache state, concurrency and matched semantics.

Report stage-level latency, not only one combined number:

- delegation proof/lineage verification;
- authority currentness/frontier check;
- consent evaluation;
- local lane preflight;
- final effect-owner check;
- local operation/transport;
- receiver verification/observation;
- revocation propagation and reconciliation.

For Track B, also report worst-surface stale exposure, route recall, duplicate dispatches, false denies, unknown age and reconciliation latency. An average revocation lag must not hide a single stale route.

## 8. Reproducibility and claim ceiling

Every run must bind:

- candidate commit SHA and clean/dirty state;
- benchmark schema, corpus and oracle digests;
- engine/policy/model/profile versions;
- OS, CPU, memory, runtime/toolchain and enabled features;
- workload seed, warm/cold/cache state, concurrency and fault schedule;
- all positive, negative, indeterminate, unsupported, timeout and not-run denominators;
- raw samples, minimized counterexamples and exact replay instructions.

The current source manifests under `docs/security/M1_ROUTE_INVENTORY_V0_1.toml` and `docs/M1_ROUTE_MEDIATION_INVENTORY_V0_1.json` are **partial source censuses**. Their route completeness is INDETERMINATE. They do not establish all OS, helper, plugin, alternate transport, reconnect/rekey or ambient-credential paths. A passing source-drift test is not a complete-mediation proof.

A benchmark pass qualifies only the disclosed corpus, versions, routes, assumptions and tested environment. It does not establish global revocation, arbitrary-provider exactly-once effects, Holochain 0.7.1 qualification, production security, legal compliance or universal SOTA superiority.

## 9. References

- OPA policy performance: https://www.openpolicyagent.org/docs/policy-performance
- OPA benchmark dashboard: https://open-policy-agent.github.io/opa/
- Cedar validation: https://docs.cedarpolicy.com/validation.html
- OpenFGA consistency options: https://openfga.dev/blog/query-consistency-options-announcement
- OpenID AuthZEN Authorization API 1.0 Final: https://openid.net/specs/authorization-api-1_0-final.html
- AuthZEN Obligations Profile 1.0 Working Group Draft: https://openid.github.io/authzen/authzen-obligations-profile-1_0.html
- Zanzibar / USENIX ATC 2019: https://www.usenix.org/conference/atc19/presentation/pang
- AuthorizationBench: https://arxiv.org/abs/2610.27548
- SABench: https://arxiv.org/abs/2610.34167
- APort Vault: https://arxiv.org/abs/2609.22076
