# Mycelix ↔ Xenia Revocable Delegated Access Profile v0.1

Status: architecture and qualification specification; no runtime integration or qualification claimed.
Tracking: Xenia #499; Mycelix #3659, #3677, #3680, #4903, #5719, #5775, #6230, #6236.

## 1. Product thesis

People should be able to delegate access without surrendering control. Mycelix owns the semantic authority and delegation lineage. Xenia owns the authenticated remote session, accessible recipient consent, and enforcement of session/lane capabilities. The target operating system and effect-owning service remain authoritative for privileged effects.

The product should support narrow grants such as view-only, input-only, one-way clipboard, upload to a named destination, or propose-only service administration. A single broad 'remote access' grant must not silently imply these distinct powers.

## 2. Authority layers and ownership

| Layer | Owner | What it establishes | What it does not establish |
|---|---|---|---|
| Identity/authentication | Mycelix identity + Xenia handshake | Which enrolled principal/delegate/host key participated | Authority to perform every action |
| Human consent | Xenia #455/#460 | Recipient reviewed a versioned request/explanation and recorded a decision | Institutional authority, comprehension guarantee, or coercion-free choice |
| Semantic delegation | Mycelix ROS-005 #3659 | Principal delegated bounded action/resource authority to delegate | Zome-call reachability or successful execution |
| Parent lineage/currentness | Mycelix #3677/#3680 and domain owner | Exact parent chain, scope containment, epoch and revocation status | Global instantaneous DHT convergence |
| Holochain call capability | Mycelix/Pulse on Holochain 0.7.1 | Caller can invoke the exact granted zome functions under host enforcement | Xenia screen/input/file capabilities |
| Xenia session capability | Xenia #449 | Exact session, lane, direction, scope, epoch and expiry are admitted | Host OS or Nixward privileged mutation authority |
| Effect authorization | Effect-owning daemon/service, e.g. Nixward | The requested effect is independently authorized at its commit boundary | That the effect actually succeeded |
| Effect observation | Independent observer/evidence owner | What was observed after execution | Authorization or intent by itself |

Do not merge these layers into one universal permission token or trust score.

## 3. Canonical delegation contract

A versioned canonical delegation must bind:

- delegation ID and canonical content commitment;
- principal/issuer and delegate identities;
- target resource and sovereignty/isolation domain;
- exact action/capability set, data classes and direction;
- purpose and policy/profile digest;
- proposal-only versus execution-authorized mode;
- validity interval and bounded lease;
- authority epoch and revocation namespace;
- parent delegation reference, depth and explicit subdelegation permission;
- audience/relying-party and target host constraints;
- canonical request digest, schema version and issuer authority evidence.

IDs must be content-bound: the same address must not identify materially different principal, delegate, scope, mode, validity, epoch or parent data. Revocation must be checked against the active authority epoch; stale-epoch revocation attempts fail without mutating state.

## 4. Composability and attenuation

Subdelegation is disabled by default. When explicitly enabled, a child is a strict subset of its parent:

- actions are a subset;
- resources and targets are narrower or equal only where the parent explicitly permits equality;
- data direction cannot widen;
- audience and purpose cannot widen;
- expiry cannot exceed the parent's effective expiry;
- execution mode cannot become stronger (propose-only cannot yield execute);
- delegation depth decreases and cannot exceed the parent's remaining depth;
- policy and assurance requirements are at least as strict as the parent.

Parent references are addressable and validated. A caller-supplied boolean such as parent_active is never evidence. Reject cycles, self-delegation, ambiguous parent paths and privilege amplification through role unions.

Distinguish two composition operators:

- Independent grants: either grant may authorize its own disjoint scope; revoking one leaves the other intact.
- Required bundle: all named parents are required; effective scope is their intersection and revoking any required parent invalidates the bundle.

Do not silently treat a bundle as a union. Deny/unknown precedence and conflict semantics must be deterministic. Trust/reputation scores are not authorization.

## 5. Holochain 0.7.1 boundary

Holochain's native private CapGrant/CapClaim mechanism is the low-level gate for remote zome calls. Use the 0.7.1 grant structure, a narrow listed function set and Assigned constraints where appropriate. Keep the claimant's CapClaim private. Never persist raw CapSecret in public DHT entries, Xenia artifacts, logs or UI telemetry.

A Holochain grant only authorizes its granted capability/function set. It is not the ROS-005 semantic delegation, not a Xenia SessionCapability and not permission to control a remote computer. The semantic contract must be checked before issuance and at the relevant application/effect boundary.

Revoking the actual host grant must cause the same remote zome call to become Unauthorized at the owning conductor. A stale application projection that says Active must not override that result. Delayed DHT visibility is an explicit unknown/incomplete state, not evidence of current authority.

Mycelix 0.7.1 remains unqualified until #5719's exact dependency/runtime matrix and fresh two-agent tests pass. Grant migration from earlier versions requires explicit re-issuance; do not reuse old secrets or claim compatibility.

## 6. Xenia session derivation

Xenia derives an immutable SessionCapability only after:

1. authenticating operator, delegate, host and target identities;
2. validating the canonical Mycelix delegation and every addressable parent;
3. checking current authority epoch, validity and revocation evidence from the owner;
4. presenting an accessible request bound to the exact action, target, purpose, scope and explanation digest;
5. recording recipient consent where the policy requires it;
6. binding the admitted session to the intended host and peer fingerprints.

The SessionCapability binds session fingerprint, operator, host, delegation commitment, parent lineage, action/resource scope, lane, direction, purpose, authority epoch, expiry, consent ID and revocation namespace.

Every privileged lane validates the capability before dispatch. The actual effect-owning service independently validates its own authorization at commit. Revalidate after reconnect, rekey, daemon restart, epoch change and immediately before a long-running operation commits.

## 7. Revocation semantics

Revocation is prospective. It blocks future use; it does not erase information already disclosed or undo completed effects.

On root revocation:

- stop new child delegation and session-capability issuance;
- invalidate all dependent descendants and sessions by parent lineage/epoch;
- block new lane dispatch at each enforcement point after that point observes effective revocation;
- block effect commits after the effect owner observes revocation;
- stop or safely abort in-flight transfers/operations according to explicit per-operation commit semantics;
- disable remote input and release forwarded keys/buttons exactly once;
- close or downgrade only affected sessions; unrelated independent scopes remain available;
- retain the historical record of prior disclosure/execution;
- record effective time, observed/knowledge time, epoch, enforcement point and acknowledgement.

A disconnected viewer or stale enforcement point has not necessarily observed revocation. Do not claim revoked everywhere until the relevant enforcement inventory is complete and acknowledgements are independently reconciled. For protected effects, unknown/incomplete propagation is HOLD/INDETERMINATE. Do not claim global instantaneous revocation over an eventually consistent DHT.

## 8. In-flight operation rules

Each lane defines a commit point:

| Lane | Revocation behavior |
|---|---|
| Screen view | Stop future frames at local enforcement observation; preserve only prior authorized disclosure history |
| Keyboard/pointer | Reject new events; release forwarded state exactly once; reject stale queued events |
| Clipboard | Reject new reads/writes; define whether an already completed copy is irreversible; never claim remote deletion without evidence |
| File transfer | Stop new chunks; recheck authority before final commit/rename; quarantine partial data under an explicit recovery policy |
| Audio | Stop future capture/playback frames; distinguish already transmitted audio |
| Shell/PTY | Stop new commands; define process termination and child-process handling; require separate host authorization |
| Reboot/configuration | Recheck at the effect-owning commit boundary; session access alone never authorizes privileged mutation |

## 9. Revocation propagation and evidence

Compose Mycelix #6236 rather than invent another propagation engine. Track each enforcement point: session, lane, worker, connector, token and effect owner. Record authority event, effective time, observed time, epoch, cache state, acknowledgement and route inventory completeness.

Report p50/p95/max propagation latency per surface and worst stale-capability exposure. Averages must not hide a single route that remains usable. If route/session inventory is incomplete, the global revocation claim is indeterminate.

Portable .xenia-session evidence must contain commitments and verifiable lineage, never capability secrets. It should distinguish grant issuance, consent, session admission, each enforcement acknowledgement, effect attempt, independent observation and unresolved propagation.

## 10. Adversarial qualification corpus

Include wrong principal/delegate/host/resource; action/direction escalation; proposal-to-execution escalation; expired/revoked/stale epoch; content substitution under same delegation ID; stale or missing parent; child surviving parent revoke; subdelegation without permission; cycles; independent-grant versus required-bundle confusion; duplicate issuance/retry; lost response; stale DHT projection; duplicate/replayed revoke; disconnected viewer; reconnect/rekey; queued input after revoke; clipboard/file transfer during revoke; effect started before revoke but committed after; alternate lane bypass; incomplete route inventory; unrelated scope remains valid; explicit regrant creates a new lineage.

## 11. Metrics and gates

- 100% exact results on the frozen finite positive/negative/indeterminate corpus.
- Zero scope amplification across parent/child/grandchild cases.
- Zero protected effects after the relevant enforcement point has observed effective revocation.
- Unknown/incomplete propagation is never shown as globally revoked.
- 100% correct lane denial after local enforcement observes revocation.
- Unrelated independent grants remain usable.
- Exact binding of principal, delegate, resource, action, direction, purpose, parent, epoch and consent is independently verified.
- Two-agent Holochain 0.7.1 runtime demonstrates successful call before grant deletion and Unauthorized after deletion despite stale application projection.
- Xenia runtime demonstrates every lane and effect-commit boundary rejects after local revoke observation, including reconnect/rekey and in-flight operations.
- Independent .xenia-session verification reconstructs delegation → consent → session capability → revocation lineage without secrets.

Report denominators, confidence intervals, per-surface latency and worst-case stale exposure. Synthetic fixtures qualify only the declared finite contract, not production-wide revocation.

## 12. Integration sequence

1. Crosswalk ROS-005 and Holochain 0.7.1 owners to Xenia #392/#449/#450/#455.
2. Freeze canonical contract, parent-chain rules and attenuation semantics; consume #3677/#3680.
3. Build deterministic Rust fixtures and an independent oracle, including mutation tests.
4. Qualify idempotent Holochain 0.7.1 issuance and two-agent revocation using #5719/#5775/#4903.
5. Integrate Xenia SessionCapability into every lane and effect boundary under #449.
6. Add trajectory-wide propagation receipts and delayed/disconnected-path tests under #6236.
7. Integrate accessible consent and recipient-side revocation controls under #455/#460/#471.
8. Run human comprehension, recovery and accessibility studies under #496/#497.

## 13. Claim ceiling

This document is an architecture/qualification specification. It does not establish that Mycelix 0.7.1 is qualified, that Xenia currently consumes Mycelix delegations, that revocation is globally instantaneous, that previously disclosed data is erased, or that a UI consent record proves comprehension or voluntariness.

## 14. Standards interoperability and industry positioning

Do not replace established authorization interfaces. Map this profile to the industry ecosystem while retaining stronger local enforcement semantics:

| Ecosystem | Reuse | Mycelix/Xenia extension |
|---|---|---|
| OpenID AuthZEN Authorization API 1.0 | PDP↔PEP evaluation contract and SARC (subject/action/resource/context) request model | Carry delegation commitment, parent lineage, authority epoch, consent reference and effect-boundary identity as versioned context/obligations; local PEP remains responsible for enforcement |
| AuthZEN Obligations Profile 1.0 (Working Group Draft, 3 July 2026) / Access Request and Approval drafts | Mandatory machine-readable PEP actions, supported-obligation discovery/negotiation, and structured request/approval/re-evaluation | Version-pin the optional profile. For a single-effect request, any mandatory obligation the PEP cannot satisfy turns the overall response into DENY; on Search-shaped requests, exclude only the affected result. Execute other obligations that remain feasible. Consent and approvals are inputs to fresh evaluation, never a bypass or cached grant |
| Zanzibar-style relationship authorization / OpenFGA | Relationship graph and consistency-aware authorization patterns | Add explicit principal-issued delegation contracts, attenuating child grants, expiry/epoch and revocation receipts; benchmark on equivalent tuple/relationship workloads |
| OPA / Cedar | Policy evaluation and policy-as-code; use as optional PDP adapters | Keep policy decision separate from session capability issuance and OS/effect enforcement; never treat a PDP response as proof that the effect occurred |
| SPIFFE/SPIRE | Workload identity and short-lived workload credentials | Authentication is not authorization; bind workload identity to the semantic delegation and the exact Xenia session/effect scope |
| Holochain 0.7.1 CapGrant/CapClaim | Host-enforced reachability to specifically granted zome functions | Keep native call capability below the semantic delegation and Xenia lane/effect capability; revocation must be tested at the owning conductor |

The differentiator is not another policy language or another central PDP. It is an interoperable, sovereignty-aware authority lineage whose narrowing rules and revocation consequences are checked at the place where each effect is committed. External PDPs may contribute a decision; they do not mint host authority, override local revocation, or attest that an operation succeeded.



### Comparative interpretation

- **AuthZEN** is the interoperability boundary, not the delegation store. Its Authorization API 1.0 is a final OpenID specification approved 12 January 2026; map Xenia operations into its subject/action/resource/context request and keep the local enforcement point responsible for the effect. The AuthZEN Obligations Profile 1.0 is a 3 July 2026 Working Group Draft, not a final specification. It defines mandatory PEP actions plus discovery/negotiation of supported obligation types. For a single-effect request, if the PEP cannot execute one or more obligations, it MUST treat the overall response as DENY and MUST still execute every other obligation it can. For Search-shaped requests, it MUST exclude only the result whose obligation cannot be satisfied, while retaining other eligible results. Obligations attached to a DENY are also mandatory and additive to the denial. Keep the obligations adapter optional and version-pinned until the profile is finalized; never silently ignore an unsupported mandatory obligation.
- **OPA** provides `opa bench`, profiling, percentiles, bytes/op and allocations/op. Its documentation's illustrative simple RBAC benchmark reports about 45 μs/op and a p95 around 51 μs on that sample. This is not a general OPA guarantee and is not directly comparable to our recursive lineage plus freshness workload; reproduce equivalent semantics before drawing conclusions.
- **Cedar** provides schema-based policy validation and describes validation soundness, backed by a Lean validator and differential testing. We should reuse Cedar for policy validation or as an adapter where useful, rather than inventing a policy language. Our reference model's job is to qualify delegation lineage and effect semantics that sit around the PDP.
- **SPIFFE/SPIRE** solves portable workload identity, not authorization policy. Keep identity issuance and authorization separate; do not mistake a valid workload identity for a valid delegation.
- **OpenFGA** is a strong relationship-based baseline. Its query consistency options distinguish `MINIMIZE_LATENCY` (which may use a configured cache) from `HIGHER_CONSISTENCY` (which bypasses that cache and reads the database). OpenFGA documents that caching is disabled by default, but when enabled it applies to all requests unless a higher-consistency option is specified. An eventually consistent multi-region database can still have replication lag. Pin engine/model version, datastore, cache configuration and consistency setting; high-consistency mode is not automatically a global linearizability guarantee.

The model's current microbenchmark measures local lineage evaluation only. It does not yet measure allocations, memory, network propagation, or concurrency. Those must be added before any broad performance comparison. Its current benchmark harness is a starting measurement instrument, not a completed SOTA bake-off.

## 15. Benchmark protocol and aspirational targets

All targets below are proposed engineering goals, not measured results or industry-leading claims. Publish the harness, frozen fixtures, environment, raw samples, denominators, and exact tested commit for every run.

### Correctness and safety

- 100% expected outcomes across positive, negative and indeterminate fixtures; zero false permits in the frozen corpus.
- Zero privilege amplification across root/child/grandchild depth 0–16, including purpose, resource, action, direction, expiry, mode and epoch mutations.
- Zero protected effect commits after the local effect owner has observed effective revocation.
- Zero alternate-lane bypasses; zero stale queued input accepted after local revocation observation.
- 100% of incomplete authority states return non-permit outcomes; never render them as globally revoked or globally current.
- Independent grants preserve unrelated scope; required bundles fail when any required parent is invalid.

### Performance and scale

Measure local evaluation separately from network propagation. Initial acceptance targets for an optimized local evaluator on a declared reference host: p50 ≤ 1 ms, p95 ≤ 2 ms, p99 ≤ 5 ms for a warm cache and lineage depth ≤ 8; report cold-cache and depth-16 results separately. OPA's own guidance identifies an order-of-1-ms decision budget for some microservice authorization use cases and provides profiling/benchmark tooling; simple-policy examples are not directly comparable to this lineage workload. These are targets to test, not measured results.

Run 1, 10, 100 and 1,000 concurrent sessions; 1, 8 and 32 lanes/session; 1, 10, 100 and 1,000 grants/principal; lineage depths 0, 1, 4, 8 and 16. Measure CPU, memory, allocation count, throughput, and p50/p95/p99/max latency. Test bursty grant/revoke churn and concurrent authorization/effect commits.

### Revocation behavior

- Local linearization: once the effect owner has observed a revocation, no later protected commit may succeed. Test revoke-vs-commit races with deterministic barriers and record the winner/linearization point.
- Connected propagation goal: p95 ≤ 1 s and p99 ≤ 5 s from authoritative revoke to acknowledgement by every enumerated connected enforcement point. This is a target, not a global guarantee.
- Disconnected enforcement points must be visibly unconfirmed and must fail closed for high-risk effects when their bounded authority lease expires. Measure worst stale-capability exposure, not only average propagation latency.
- Report route inventory completeness. Missing acknowledgements or unknown routes make the global status Indeterminate.

### Comparative baseline

Compare equivalent policy semantics against at least one Zanzibar-style relationship engine (e.g. OpenFGA), OPA, Cedar, and an AuthZEN-compatible PDP/PEP pair. Keep identity, policy graph, resource count, cache state, consistency mode, hardware, concurrency, and query mix matched. Report raw latency distributions and correctness separately. Do not claim “better than SOTA” from unlike workloads or from a single median.

The likely advantage to pursue is not raw PDP latency alone: it is a stronger end-to-end safety envelope—strict delegation attenuation, no confused OR/AND composition, per-lane enforcement, explicit in-flight commit semantics, and independently verifiable revocation receipts—with acceptable measured overhead.

## 16. Deterministic reference model

A standalone, dependency-light Rust policy oracle, adversarial unit tests and a paired lineage/frontier microbenchmark live in `research/revocable-access-model/` and are tracked by Xenia #501. The benchmark reports per-depth p50/p95/p99/max latency for lineage-only and frontier-plus-lineage paths; it is a measurement harness, not a result or proof of comparative superiority. It models exact resource equality, parent attenuation, local revocation, epochs, three-valued decisions and OR/AND composition. It is deliberately not a production authorization service and does not qualify cryptography, Holochain, DHT convergence, or OS enforcement. CI/test results must be attached to the exact tested commit before any qualification claim.


## 17. AuthZEN adapter contract (proposed)

Implementation tracker: Xenia #502.

AuthZEN Authorization API 1.0 exposes a boolean decision (`true` or `false`) between a PDP and PEP. The local Mycelix/Xenia decision type remains three-valued. The adapter MUST map a valid `false` to Denied and a valid `true` to a *PDP permit input only*. Timeout, transport failure, malformed response, invalid metadata/signature or incomplete request context maps to Indeterminate; Indeterminate is never converted to Permit.

When the optional AuthZEN Obligations Profile 1.0 (Working Group Draft, 3 July 2026) is negotiated, obligations are mandatory even when attached to a DENY. For a single-effect Authorization API request, if the PEP cannot comply with one or more obligations (unknown or unsupported type, malformed instance, unsupported resource/action, or execution failure), it MUST treat the overall response as DENY, regardless of the returned boolean, and MUST still execute every other obligation it can. For Search-shaped requests with per-result obligations, the PEP MUST exclude only the result whose obligation it cannot satisfy and MUST return other results whose obligations are absent or successfully executed. Keep these obligation-compliance outcomes distinct from timeout/transport failure or unverifiable authority state, which remain local Indeterminate/HOLD. The obligations profile is a draft and must be version-pinned; do not assume its types or discovery rules are part of the Authorization API core. AuthZEN does not replace local delegation-lineage, consent, revocation-currentness or effect-boundary checks.

Example request mapping (illustrative profile values, not a registered AuthZEN vocabulary):

```json
{
  "subject": {
    "type": "xenia-delegate",
    "id": "did:example:delegate-bob",
    "properties": {
      "principal_id": "did:example:principal-alice",
      "delegation_id": "delegation:sha256:...",
      "authority_epoch": 42
    }
  },
  "action": {
    "name": "xenia.remote.input",
    "properties": {
      "lane": "input",
      "direction": "viewer-to-host",
      "mode": "execute"
    }
  },
  "resource": {
    "type": "xenia-host",
    "id": "host-key-fingerprint:...",
    "properties": {
      "sovereignty_domain": "home-network-a",
      "resource_id": "device-123"
    }
  },
  "context": {
    "purpose": "consented-support-session",
    "session_fingerprint": "sha256:...",
    "parent_lineage_commitment": "sha256:...",
    "consent_record_id": "consent:...",
    "authority_epoch": 42,
    "policy_profile_digest": "sha256:..."
  }
}
```

Mapping rules:

1. Subject is the authenticated delegate/workload acting now; principal and delegation lineage are bound as context/properties, not collapsed into one identity.
2. Action is a stable operation name plus exact lane, direction and proposal/execute mode. Do not map generic `remoteAccess` to every lane.
3. Resource identifies the exact host and sovereignty domain. Avoid ambiguous display names or wildcard resource IDs.
4. Context carries purpose, consent reference, session fingerprint, authority epoch and immutable policy/delegation commitments. Never include CapSecret, private CapClaim material or other bearer secrets.
5. A PDP `true` does not mint a capability. Mycelix lineage validation, Xenia session/lane admission and host effect authorization still run locally.
6. A response context may contain obligations. For a single-effect request, the PEP must satisfy every obligation; inability to satisfy one makes the overall response DENY, while the PEP still executes other obligations it can. For Search-shaped requests, the PEP filters only results whose individual obligations cannot be satisfied. Obligations on DENY responses are also executed where feasible. Profile-specific obligation names must be namespaced and versioned rather than pretending to be registered AuthZEN core fields.
7. Cache keys bind the complete request and policy/delegation digests. Cache lifetime cannot exceed the shortest underlying delegation/session lease; revocation or epoch change invalidates the entry.
8. Evaluate again at the protected effect commit boundary. A PDP permit obtained at session start is not a standing execution token.

This adapter lets deployments use AuthZEN-compatible PDPs without making Mycelix a proprietary PDP protocol or delegating the host's final authority to a remote service.


## 21. Causal freshness and authority watermarks

Implementation tracker: Xenia #506.

A grant can be unexpired and not locally marked revoked while still being evaluated against an authority snapshot older than a revocation. Time-to-live alone does not solve this stale-read problem.

Introduce an authenticated, monotonic AuthorityFrontier per sovereignty/authority namespace:

- namespace identifier;
- monotonic revision or epoch;
- authenticated issuer/source and signature or equivalent source proof;
- causal dependencies on relevant delegation, consent, policy and resource updates;
- issue time and bounded validity/lease;
- optional predecessor/frontier commitment for audit continuity.

Every session admission and effect request carries a minimum acceptable frontier. The effect owner must establish that its observed frontier is at least as new as the requested minimum and belongs to the exact resource authority namespace. A mismatched namespace or stale frontier is INDETERMINATE, never a permit. The standalone Rust model now includes a small freshness-frontier predicate; it does not authenticate frontiers, prove that a frontier commits to the exact in-memory authority snapshot being evaluated, or establish distributed convergence. An integrating caller must verify all three bindings before using the predicate.

Define explicit consistency profiles:

| Profile | Semantics | Allowed use |
|---|---|---|
| Strong | Online authoritative/quorum check satisfying the required causal frontier | High-risk effects |
| BoundedStaleness | Explicit maximum lag and short lease; observed frontier and exposure are reported | Risk-limited, reversible actions |
| OfflineLease | Pre-authorized narrow action, hard expiry, no scope expansion or high-risk effect | Limited continuity during disconnection |
| Unknown | Freshness cannot be established | HOLD/INDETERMINATE |

A reconnect must advance the local frontier monotonically; it must not roll back to an older cached snapshot. Cross-object causal dependencies must be included so a new resource state cannot be authorized using an older permission state.

### Industry comparison

Zanzibar's 2019 paper describes externally consistent authorization checks, causal ordering of ACL changes and a consistency token ("zookie") that lets clients require checks no older than a relevant update. The paper reports more than 2 trillion ACLs, millions of authorization checks per second, p95 below 10 ms and availability above 99.999% over a three-year production period. These are Google-reported deployment results, not an independently reproduced benchmark for this project. It reports more than 2 trillion ACLs, millions of checks per second, p95 below 10 ms and availability above 99.999% over a three-year production period. Those are Google-reported system results, not a benchmark directly comparable to this prototype.

OpenFGA exposes MINIMIZE_LATENCY and HIGHER_CONSISTENCY query preferences. HIGHER_CONSISTENCY bypasses its cache and reads from the database, but OpenFGA documents that custom eventually consistent multi-region databases may still exhibit replication lag. This is a useful operational control, not a universal linearizability guarantee.

Our target should not be to claim Zanzibar scale. It should be to make freshness semantics explicit and portable across a sovereign, multi-domain system: each operation states which authority frontier it requires, each effect owner proves what it observed, and disconnected/unknown states have defined behavior.

### Qualification corpus

Test:
- stale frontier immediately after revoke;
- current frontier at and above the required revision;
- namespace substitution and cross-domain replay;
- reordered, duplicated and missing frontier events;
- epoch reset and monotonicity violations;
- clock skew and lease expiry;
- partition, reconnect and stale-cache replay;
- new resource state combined with old authority state;
- missing causal dependency or untrusted frontier issuer.

Acceptance: zero permits below the requested freshness frontier; monotonic watermark advancement; explicit HOLD/INDETERMINATE for missing or mismatched evidence; measured propagation lag and maximum lease exposure. Do not infer freshness from wall-clock time alone.


## 22. Quantitative capability budgets

Implementation tracker: Xenia #507.

Least privilege should bound not only *which* operation is allowed, but *how much* authority may be consumed:

- maximum session duration and renewal count;
- operation/command count and rate;
- clipboard and file-transfer byte limits;
- maximum individual file size and total transfer volume;
- concurrent sessions/workers and target count;
- screen-view duration or other metered disclosure budgets.

Each child grant must have budgets less than or equal to its parent for every dimension. A reconnect, rekey, process restart or duplicated request must not reset consumption. Consumption uses stable operation IDs and monotonic authority epochs. Reserve/commit/reconcile semantics must treat a timeout after dispatch as UNKNOWN; do not refund or reuse quota until the effect outcome is reconciled. Parallel workers must share a serialized or otherwise overspend-safe budget ledger.

Independent grants retain independent budgets. Required bundles apply the strictest compatible constraints. If budget state or consumption is unknown, high-risk effects are HOLD/INDETERMINATE. Budget accounting must be independently auditable and must not depend on reputation scores.


## 23. Performance architecture without weakening authorization

The target is not to send every mouse event or video frame to a remote PDP. That would add avoidable latency and make availability depend on a network round trip. Instead:

1. Verify canonicalization, signatures and immutable parent-chain commitments once per content-addressed delegation version; cache the *verification result* by exact content digest.
2. Compile an immutable session/lane capability matrix from the verified delegation and consent, with exact resource, direction, purpose, epoch, expiry and budget constraints.
3. Cache lineage/attenuation proofs separately from current authorization. A cached proof that a child is narrower does not prove the parent remains current.
4. Keep a small local effect gate at each effect owner. It checks current local revocation watermark, session epoch, lane, expiry, operation sequence and budget reservation at the commit boundary.
5. Use short-lived lane leases and monotonic sequence numbers for high-frequency input paths. A lease may reduce repeated remote decision calls; it must never outlive the authority freshness bound or bypass the local effect gate.
6. Batch only operations whose semantics permit batching. Each protected operation still has a stable identity, ordered commit semantics and replay protection.
7. If the local frontier is below the required minimum, the session is partitioned beyond its lease, or the revocation state is unknown, stop high-risk effects rather than falling back to a stale cached allow.

This is the intended performance advantage: move expensive immutable proof work out of the hot path, while keeping freshness and effect authorization local and current. Benchmark the complete path, not just the compiled policy decision.


## 24. Institutional authorization assurance and trajectory-level evaluation

Cross-project alignment: Mycelix `docs/research/INSTITUTIONAL_AUTHORIZATION_ASSURANCE_PROFILE.md`
(14 November 2026). That profile is a research note and synthetic conformance
extension, not a standard, certification or production security claim. Xenia
should implement its remote-session-specific evidence under the shared
Claim–Obligation–Enforcement–Evidence–Effect vocabulary rather than inventing
another system-wide assurance score.

Map the integration as follows:

| IAAP property | Mycelix/Xenia application |
|---|---|
| IAAP-1 Complete mediation | Enumerate every effect-capable Xenia route: viewer session, media/input/clipboard/file lane, reconnect/rekey path, daemon/admin route, background worker, and host-side effect owner. A known reachable bypass fails; incomplete inventory is Indeterminate. |
| IAAP-2 Trajectory-wide least privilege | Compute the union of all active M1 lanes, Mycelix delegations, Holochain grants, ambient credentials and forwarded/session credentials available during the trajectory. Unused but available authority still counts. |
| IAAP-3 Revocation propagation | Bind the authority owner's effective epoch and each Xenia enforcement point's observed epoch/time; report stale-capability exposure and disconnected surfaces individually. A local Xenia revoke is not proof of cross-system revocation. |
| IAAP-4 Delegation containment | Check every edge for action, resource, purpose, data class/field, audience, direction, mode, validity, amount/operation/rate/concurrency budget and subject binding. Unknown subset semantics fail closed. |
| IAAP-5 Effect-level accounting | Keep authorization admission, attempt, dispatch, local commit, peer acknowledgement, independently observed result and reconciliation as distinct events. |

The IAAP profile's descriptive evidence maturity levels are E0 asserted,
E1 specified, E2 structurally checked, E3 adversarially exercised,
E4 independently observed and E5 externally replicated. These are not a
certification or a single assurance grade. Report the level separately for
each claim and protected-effect scope. In particular, this reference model is
not E4/E5 evidence and does not prove a production Xenia path.

### Current agent authorization benchmarks

Use these new external benchmarks as design inputs, not as direct scores for
Xenia or Mycelix:

- **AuthorizationBench** (Zhang et al., 20 October 2026):
  286 tasks across ten application domains and 6,864 trajectories; 19.2% of
  trajectories contained an out-of-authorization action. The authors report
  lower out-of-authorization behavior in paired runs where agents consulted
  the principal before completing the task (14.0% versus 21.6%). The result is
  benchmark-specific, not a universal estimate.
  https://arxiv.org/abs/2610.27548
- **SABench** (Huang et al., 25 October 2026):
  201 tasks, 47 templates and 2,211 model-task runs; 15.2% of runs incurred
  collateral damage, and 12.8% of goal-satisfied runs still contained
  unauthorized writes. The benchmark uses deterministic traces to evaluate
  task success and authorization compliance independently.
  https://arxiv.org/abs/2610.34167

The important transferable design is to keep out-of-scope paths executable and
observable during evaluation. Hiding every prohibited route makes an
authorization benchmark vacuous. Also include an ambiguity/clarification
family: when recipient, resource, action, quantity or destination changes the
protected effect and is not specified by the principal, the correct behavior
is clarification and zero dispatch—not a guessed authorization.

### Updated benchmark composition

Keep three scorecards rather than one weighted metric:

1. **Matched PDP decisions:** OPA, Cedar and OpenFGA on equivalent policy graphs,
   semantics, versions, cache and consistency modes; report engine-only and
   client/server latency separately.
2. **Delegated remote-effect assurance:** lineage containment, causal
   freshness, exact M1 lane enforcement, effect-commit ordering, revocation
   exposure and independently verified receipts.
3. **Trajectory-level alignment:** complete mediation, ambient/forwarded
   privilege union, clarification, unauthorized effects and side effects,
   using executable positive and negative controls.

Unauthorized protected effects, false permits, delegation amplification,
known bypass acceptance, duplicate side effects and unknown-to-permit
conversion are hard failures. They must not be averaged away by high task
completion or low median latency. Publish denominators, positive-control
false-deny rates, raw samples, route-inventory coverage, pinned comparator
versions, hardware and confidence intervals.


## 25. Current ROS-005 Rust implementation boundary (17 November 2026)

The Mycelix ROS-005 implementation is being developed in a stacked public PR
sequence:
- [#3660 — base delegated-authority types](https://github.com/Luminous-Dynamics/mycelix/pull/3660),
  branch `feat/ros-005-delegated-authority`.
- [#3679 — addressable parent chain and content binding](https://github.com/Luminous-Dynamics/mycelix/pull/3679),
  branch `feat/ros-005-parent-chain-hardening`, stacked on #3660.

The current #3679 source branch head reviewed on 17 November is
`ce5ad5b903d4ecf2a3c89e7b85273e7bf195875f`. Both implementation PRs remain
open and unmerged. On that exact head, pinned formatting and the 470-test
all-target suite passed. The original full-package Clippy gate failed because
the wider core-types package contains existing `wisdom_engine` diagnostics
(including `inherent_to_string_shadow_display`, `absurd_extreme_comparisons`
and an `overly_complex_bool_expr` in legacy tests). The two newly introduced
warnings in `delegation.rs` were corrected in this head.

The current qualification PR is [#6307](https://github.com/Luminous-Dynamics/mycelix/pull/6307).
Its earlier run found the Clippy path filter was matching repository-root
paths although rustc emits crate-relative `src/delegation.rs` paths. The
workflow now binds diagnostics to the `mycelix-core-types` package ID and
crate-relative source suffixes, while retaining the complete package JSON
artifact. Exact head `cc623a37a19a4e0bca85c01c449ec0a3333fceef` passed the
format gate, 470 tests, and the strict ROS-005 touched-file Clippy gate.
Full-package Clippy still returned 101 due to diagnostics outside the touched
ROS-005 files; the workflow explicitly records that as a non-pass rather than
suppressing it. Artifact:
https://github.com/Luminous-Dynamics/mycelix/actions/runs/44143989265/artifacts/14355083222.

### Existing Rust contract to consume

The public core-types implementation exposes:
- `Delegation`, `DelegationId`, `PrincipalRef`, `ActionScope`,
  `ResourceScope`, `DelegationMode`;
- `ExecutionRequest` and `ExecutionDecision`;
- `DelegationContext::from_slice` for explicit parent dependencies;
- `Delegation::authorize(request, context)`;
- `Delegation::validate_identity()` and
  `DelegationId::derive_content_bound()`.

The caller-supplied `parent_active` boolean has been removed. Parent records
are resolved by ID from the explicit context, duplicate IDs are rejected, and
each retrieved parent is now checked against its own content-bound identity
before its status or scope is trusted. The context is still only a set of
records supplied to the pure Rust validator: it does **not** authenticate
their Holochain/DHT provenance or establish that they are current. An Xenia
adapter must receive a source-authenticated authority snapshot and prove its
freshness/currentness under Mycelix #4903 before using it.

### Explicit subdelegation and strict attenuation

On the current #3679 branch:
- `Delegation::grant` defaults `subdelegation_allowed` to false.
- The principal must explicitly choose
  `grant_with_subdelegation(..., true)` for a delegate to issue children.
- Every parent edge in a multi-hop chain must have opted in.
- The subdelegation flag is part of the versioned canonical content encoding
  `mycelix.delegation-content.v2`.
- A child must narrow at least one currently modeled dimension: proposal-only
  mode, a later start time, or an earlier/finite expiry. A child with the same
  mode and validity interval is rejected.

Important limitation: current `ActionScope::Named` and
`ResourceScope::Named` containment is exact equality. These are not
hierarchical resource paths or set-valued action collections. The current
strict-attenuation rule therefore does not yet support a child selecting a
proper subset of multiple actions or nested resources. Mycelix #6302 tracks
versioned typed scopes and quantitative budgets. Until that work is complete,
an Xenia M1 grant should bind one exact delegated action ID and one exact host
resource identity. Multiple lanes need separate exact grants, or a separately
qualified typed-scope extension; do not infer wildcard or prefix semantics.

Purpose/audience/data-class binding and quantitative operation/byte/rate/
concurrency budgets must also remain explicit. Reuse the ROS-004 consent
contract for disclosure purpose and bind its consent record/digest into the
Xenia session capability; do not treat consent as delegated execution
authority or duplicate ROS-004 semantics inside a stringly typed action name.

### Adapter rule

Do not serialize a bare `DelegationContext` from an untrusted client and
treat it as authoritative. The future bridge must:
1. resolve the exact delegation and complete parent chain from the authority
   owner;
2. verify canonical IDs and any issuer/record authenticity required by the
   source;
3. bind the records to a verified authority epoch/frontier and currentness
   receipt;
4. construct the exact `ExecutionRequest` from the authenticated delegate,
   stable M1 action ID, exact host resource, proposal/execute mode and request
   time;
5. evaluate the pure ROS-005 contract;
6. compose the result with recipient consent and the local M1 lane gate;
7. repeat currentness and final authorization at the effect owner.

A pure `AuthorizedExecution` result is a semantic decision only. It does not
prove that the Zome call, Xenia lane, host OS effect or remote observation
occurred.

## 26. Exact Xenia M1 mapping onto ROS-004 and ROS-005

Xenia's current M1 crosswalk assigns eight stable action identifiers and
explicit data/control directions. The identifiers are intentionally exact
strings because the current ROS-005 `ActionScope::Named` containment rule is
equality-only. They are not wildcard families or hierarchical scopes.

| M1 lane | ROS-005 `ActionScope::Named` | Direction | Protected operation mode |
|---|---|---|---|
| `StreamFrame` | `xenia.screen.view` | Host → viewer | Execute/disclose |
| `StreamTelemetry` | `xenia.host.telemetry` | Host → viewer | Execute/disclose |
| `StreamAudio` | `xenia.audio.capture` | Host → viewer | Execute/disclose |
| `InjectInput` | `xenia.input.inject` | Viewer → host | Execute |
| `ReadHostClipboard` | `xenia.clipboard.read` | Host → viewer | Execute/disclose |
| `WriteHostClipboard` | `xenia.clipboard.write` | Viewer → host | Execute |
| `SendFileToViewer` | `xenia.file.send` | Host → viewer | Execute/disclose |
| `ReceiveFileFromViewer` | `xenia.file.receive` | Viewer → host | Execute |

The direction is a separate Xenia crosswalk invariant; it is not currently a
field in ROS-005's `ExecutionRequest`. The action IDs must remain direction-
specific so a send action cannot be reinterpreted as receive, and vice versa.
A proposal to request a session or change configuration may use proposal
semantics in a separate action profile, but `DelegationMode::Propose` does not
authorize any of the eight protected M1 effects.

For each M1 lane, an adapter constructs one exact ROS-005 request:

- authenticated principal and delegate references from the owner-validated
  source records;
- the exact stable M1 action ID above;
- one exact, canonical host/resource identity in `ResourceScope::Named`;
- `DelegationMode::Execute` for a protected lane effect;
- the source-defined request timestamp and current authority epoch.

Do not encode direction, purpose, audience, data class, session ID or operation
digest by appending ad-hoc strings to `ActionScope` or `ResourceScope`. The
current ROS-005 API has no explicit fields for those dimensions. Xenia must
bind direction, session fingerprint/rekey epoch, lane, consent reference,
resource identity and operation identity in its own local session/effect
capability, and combine the resulting decision with ROS-004 consent where
there is disclosure.

### ROS-004 composition

For host-to-viewer media, telemetry, clipboard and file disclosure, recipient
consent remains a separate required gate. Compose the source-owned ROS-004
`Consent::authorize(&ConsentRequest)` result with ROS-005 semantic action
authority and the existing M1 local lane gate. ROS-004 already carries the
requester/audience, named purpose, read-vs-disclose mode, data classes, exact
fields, explicit request time and authority epoch. Do not treat a valid
consent as execution authority. For viewer-to-host operations, the exact M1
operator/recipient gate remains required; do not invent an ROS-004 disclosure
record as a substitute for action authority.

### Important unresolved API semantics

- `ExecutionRequest::requested_at`, `Delegation::granted_at` and expiry are
  represented as `i64`; the reviewed API does not specify the epoch or unit.
  Xenia's runtime uses millisecond timestamps in other paths. Do not convert
  or compare these values until Mycelix standardizes the wire unit/epoch.
- `ResourceScope::Named` is also exact equality. Do not use string prefixes,
  wildcards or path ancestry to express host/resource containment.
- `DelegationContext::from_slice` checks duplicate identifiers and provides
  addressable parent records to the pure validator; it does not authenticate
  Holochain records, prove complete DHT visibility, or establish currentness.
- The type crate is not yet a released/pinned dependency for Xenia. Do not add
  an unpinned Git dependency or fork these Rust types into Xenia. Pin a reviewed
  source revision or published artifact only after the owner API and
  compatibility contract are stable.
- Current strict child attenuation is limited to proposal-mode narrowing,
  later start time or earlier/finite expiry. A child cannot yet select a proper
  subset of multi-action sets or nested resource sets. Mycelix #6302 owns the
  separately versioned typed-scope and quantitative-budget extension. Until
  it is implemented and qualified, Xenia should issue separate exact grants
  per lane/resource rather than infer set semantics.
- Mycelix #4903 owns Holochain/DHT capability currentness under delayed
  visibility; #6236 owns trajectory-wide revocation propagation. Xenia #506
  must consume their authenticated currentness evidence rather than treat a
  local revision or a complete-looking caller slice as proof of global
  currency. Holochain 0.7.1 qualification remains incomplete under Mycelix
  #5719.

### Adapter non-permit rules

A verified ROS-005 `AuthorizedExecution` is a semantic permit input only.
Missing parent records, an invalid content-bound ID, revoked/expired parent,
stale epoch, unknown action/resource semantics, unresolved timestamp profile,
incomplete authority frontier, or unavailable currentness evidence must not
be converted into a permit. Valid semantic denial maps to DENIED; unavailable
or unverifiable authority/currentness maps to HOLD/INDETERMINATE. The M1
source preflight remains a resource-minimization check, and the final effect
owner must revalidate before send/apply/publish. Neither stage alone closes
the asynchronous race tracked by Xenia #504.

This mapping is a contract only. Xenia PR #509 still consumes local M1 consent
and does not yet call ROS-005 or ROS-004 at runtime.
