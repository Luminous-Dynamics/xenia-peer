# ADR-005: Privileged operation grants are session-bound, attenuating leases

Status: Proposed

## Context

Xenia already separates authenticated session establishment, human consent, operator authorization, and application capabilities. Native execution now adds a new class of privilege: an authenticated operator may be allowed to perform one exact structured action without being granted unrestricted machine access.

That same shape will recur for service access, credential use, device management, recovery actions, and agent-initiated operations. Encoding each future adapter as an independent authorization model would create inconsistent privilege semantics and make revocation, evidence, delegation, and continual reevaluation harder to reason about.

Industry systems provide useful precedent without defining Xenia's boundary for us:

- NIST zero-trust guidance recommends just-enough / just-in-time access and ongoing reevaluation during a session.
- SPIFFE separates workload identity from application authorization and demonstrates the value of attesting a concrete running workload rather than trusting only network location.
- Privileged-access systems such as Teleport and Boundary demonstrate JIT approval, credential injection, and session evidence.
- Capability systems such as Macaroons and Biscuit demonstrate monotonic attenuation: delegated authority can be narrowed without allowing a holder to widen it.

Xenia should adopt the useful invariants while remaining compatible with its existing consent, transcript binding, and revocation architecture.

## Decision

Xenia will define a small, runtime-free privileged-operation grant contract between governance/authorization and protocol-specific execution adapters.

A V1 grant is **not a portable bearer credential**. It is an authorization record bound to:

1. one authenticated Xenia session context;
2. one authenticated subject identity fingerprint;
3. an exact, finite set of resource/action rules;
4. the policy revision that produced the decision;
5. the human/organizational approval commitment;
6. the stated purpose commitment;
7. a short validity interval;
8. a finite maximum use count; and
9. mandatory authorization reevaluation before each use.

Possession of serialized grant bytes is therefore insufficient to exercise authority in another session or as another subject.

## Layer boundary

```text
Mycelix / organization policy / external PDP
                 |
                 | may decide who should receive authority
                 v
Xenia operator + consent control plane
                 |
                 | produces approval/policy commitments
                 v
xenia-operation-proto
session-bound finite grant + exact scope + attenuation rules
                 |
                 | adapter must revalidate before each use
                 v
+----------------+----------------+----------------+
|                |                |                |
exec          service          credential       device/
request       access           injection        recovery
|                |                |                |
+----------------+----------------+----------------+
                 |
                 v
local enforcement / Nixward / OS / legacy bridge
```

The operation grant is an enforcement lease, not Xenia's global organizational authorization database. Relationship graphs, HR roles, business policy, approval workflows, and long-lived delegation policy may live in Mycelix or another policy decision point. Xenia consumes their decision as a bounded commitment it can enforce locally.

## V1 resource/action model

Each rule names:

- a resource kind;
- a resource namespace;
- an exact resource identifier;
- an operation class;
- an exact action label; and
- a parameter commitment.

Examples:

- host / `xenia-host` / host fingerprint / Execute / `exec.v1` / exact `ExecRequestV1` digest
- service / `tcp-service` / `db.internal:5432` / ConnectService / `connect` / target-policy digest
- workload / `spiffe` / `spiffe://example.org/ops/collector` / Observe / `read.logs` / query digest
- device / `redfish` / canonical Redfish resource URI / Recover / `computer-system.reset` / reset-parameter digest

Namespaces are explicit so Xenia does not pretend that a hostname, SPIFFE ID, Nix store path, Redfish URI, and database identifier have interchangeable identity semantics.

## Exact scope, not role implication

A grant contains a sorted, unique set of exact operation rules. It does not say "administrator", "shell", or "full access".

High-level role systems may decide that a person is eligible for a grant, but the grant itself records only the concrete authority Xenia can enforce.

This keeps the enforcement boundary stable even if an upstream RBAC/ReBAC/ABAC model changes.

## Per-use reevaluation

V1 requires authorization reevaluation before every privileged operation use.

Reevaluation is conceptually separate from signature verification. At minimum the runtime must confirm:

- the session is still authenticated and active;
- consent has not been revoked;
- the subject still matches;
- the policy revision is still accepted;
- the requested rule is in scope;
- the grant is inside its validity window;
- its use budget has not been exhausted; and
- any adapter-specific posture/attestation requirements still hold.

A later optimization may cache safe decisions for bounded intervals, but that requires a new explicit policy/version. V1 does not silently convert session admission into permanent authorization.

## Attenuation

A child grant may be derived only if it is strictly no broader than its parent.

V1 attenuation requires:

- identical session context;
- identical subject;
- identical policy, approval, and purpose commitments;
- child rules are a subset of parent rules;
- child `not_before` is no earlier;
- child expiry is no later;
- child maximum use count is no larger; and
- child names the exact parent grant digest.

This makes attenuation useful for handing an internal component a one-operation subset of a broader approved session without minting new authority.

## Cross-subject delegation is intentionally not V1 attenuation

Changing the subject is delegation, not attenuation.

Cross-subject delegation (for example human -> AI agent or operator -> specialist) requires an explicit later protocol with its own signed delegation statement, approval semantics, revocation behavior, and evidence chain. V1 rejects a child whose subject differs from its parent.

This prevents a generic `derive_child()` helper from accidentally becoming an ambient impersonation mechanism.

## Credential handling

A future credential adapter should prefer **credential use/injection** over credential disclosure. A grant may authorize "authenticate to service X using credential handle Y" without authorizing "reveal credential Y to the operator".

Credential disclosure, if ever supported, must be a separate action class and permission.

## Device and out-of-band management

Xenia should bridge established management protocols rather than replace them. Redfish is the preferred future adapter for standards-based out-of-band server management where available. Xenia's contribution is the session-bound authority, consent, evidence, and constrained operation semantics around that adapter.

## Evidence

The eventual runtime should distinguish at least:

- grant issued;
- grant attenuated;
- operation admitted;
- operation refused;
- operation started;
- operation completed/failed;
- grant expired/exhausted/revoked.

Sensitive output is not automatically evidence. Evidence should record commitments, identities, action/result metadata, and byte counts unless a separately consented recording policy requests content capture.

## Consequences

### Positive

- one authorization substrate can support exec, service access, secretless authentication, Redfish, recovery, and agent actions;
- AI and automation can receive exact actions rather than machine-wide access;
- upstream policy engines remain replaceable;
- attenuation is mechanically testable;
- grant theft does not create a portable bearer credential;
- continual reevaluation is a protocol invariant rather than an optional product feature.

### Cost

- adapters must identify resources/actions canonically;
- use-count replay prevention requires runtime state;
- clock validity needs a trusted-enough local time source;
- cross-subject delegation needs a separate later design;
- richer policy/posture inputs will need their own authenticated evidence contracts.

## Non-goals

This ADR does not implement:

- a global IAM or relationship database;
- a general policy language;
- cross-subject delegation;
- process spawning;
- PTY;
- SSH;
- arbitrary TCP forwarding;
- a VPN;
- secret storage;
- Redfish client behavior;
- SPIFFE issuance;
- unattended permanent access.

Those capabilities may consume or extend this boundary without being owned by it.
