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