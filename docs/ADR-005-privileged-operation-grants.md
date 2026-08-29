# ADR-005: Privileged operation grants are session-bound, attenuating leases

Status: Proposed

## Context

Xenia already separates authenticated session establishment, human consent, operator authorization, and application capabilities. Native execution adds a new class of privilege: an authenticated operator may be allowed to perform one exact structured action without being granted unrestricted machine access.

That same shape will recur for service access, credential use, device management, recovery actions, and agent-initiated operations. Encoding each adapter as an independent authorization model would create inconsistent privilege semantics and make revocation, evidence, delegation, use accounting, and continual reevaluation harder to reason about.

Industry systems provide useful precedent without defining Xenia's boundary for us:

- NIST zero-trust guidance recommends just-enough / just-in-time access and ongoing reevaluation during a session.
- SPIFFE separates workload identity from application authorization and demonstrates the value of attesting a concrete running workload rather than trusting only network location.
- Privileged-access systems such as Teleport and Boundary demonstrate JIT approval, credential injection, and session evidence.
- Capability systems such as Macaroons and Biscuit demonstrate monotonic attenuation: derived authority can be narrowed without allowing a holder to widen it.

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

Possession of serialized grant bytes is insufficient to exercise authority. Every use must additionally present live runtime facts for the current authenticated session, subject, time, and already-consumed use count, and those facts must match the grant before side effects are admitted.

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
- an optional exact parameter commitment.

Examples:

- host / `xenia-host` / host fingerprint / Execute / `exec.v1` / exact `ExecRequestV1` digest
- service / `tcp-service` / `db.internal:5432` / ConnectService / `connect` / target-policy digest
- workload / `spiffe` / `spiffe://example.org/ops/collector` / Observe / `read.logs` / query digest
- device / `redfish` / canonical Redfish resource URI / Recover / `computer-system.reset` / reset-parameter digest

Namespaces are explicit so Xenia does not pretend that a hostname, SPIFFE ID, Nix store path, Redfish URI, and database identifier have interchangeable identity semantics.

A parameterless operation uses a canonical zero request digest. An operation with committed parameters must present exactly the committed digest on every use. This prevents a grant for one structured request from being paired with a different request at exercise time.

## Exact scope, not role implication

A grant contains a sorted, unique set of exact operation rules. It does not say `administrator`, `shell`, or `full access`.

High-level role systems may decide that a person is eligible for a grant, but the grant itself records only the concrete authority Xenia can enforce.

This keeps the enforcement boundary stable even if an upstream RBAC/ReBAC/ABAC model changes.

## Per-use live binding and reevaluation

V1 requires authorization reevaluation before every privileged operation use.

The contract requires a live exercise context containing:

- the current authenticated session-context hash;
- the current authenticated subject fingerprint;
- the current trusted-enough local time; and
- the number of uses already atomically consumed by the grant.

A use is structurally admissible only when:

- current session equals the grant's bound session;
- current subject equals the grant's bound subject;
- the grant is inside its validity window;
- the grant still has remaining use budget;
- the use index is exactly the next consumed-use slot;
- the selected rule exists in the grant scope; and
- the request commitment exactly matches the rule's committed parameters.

The runtime must additionally confirm current consent, policy and posture state before side effects. It must atomically reserve/increment the use counter so concurrent requests cannot spend the same slot.

A later optimization may cache safe decisions for bounded intervals, but that requires a new explicit policy/version. V1 does not silently convert session admission into permanent authorization.

## Attenuation is linear in V1

A child grant may be derived only if it is no broader than its parent.

V1 attenuation requires:

- identical session context;
- identical subject;
- identical policy, approval, and purpose commitments;
- child rules are a subset of parent rules;
- child `not_before` is no earlier;
- child expiry is no later;
- child maximum use count is no larger than the parent's **remaining** use budget; and
- child names the exact parent grant digest.

Successful child issuance must atomically mark the parent grant **superseded** before the child becomes usable. V1 therefore forms a linear attenuation chain rather than a branching capability tree.

This prevents a parent and multiple children from independently spending the same remaining use budget. Branching allocation may be added later only with an explicit partitioned-budget protocol and replay-safe state model.

## Cross-subject delegation is intentionally not V1 attenuation

Changing the subject is delegation, not attenuation.

Cross-subject delegation (for example human -> AI agent or operator -> specialist) requires an explicit later protocol with its own signed delegation statement, approval semantics, revocation behavior, resource/action attenuation, and evidence chain. V1 rejects a child whose subject differs from its parent.

This prevents a generic `derive_child()` helper from accidentally becoming an ambient impersonation mechanism.

## Credential handling

A future credential adapter should prefer **credential use/injection** over credential disclosure. A grant may authorize `authenticate to service X using credential handle Y` without authorizing `reveal credential Y to the operator`.

Credential disclosure, if ever supported, must be a separate action class and permission.

## Workload and device identity

Xenia should be able to bind a resource to externally established identity semantics instead of inventing one universal identifier.

Examples include:

- a Xenia host identity fingerprint;
- a SPIFFE workload identity/attestation result;
- an immutable Nix store-path/closure identity;
- a TPM/device-attestation identity; and
- a canonical Redfish resource URI.

The grant commits the exact resource reference. The subsystem that proves that reference is genuine remains a separate attestation/adapter boundary.

## Device and out-of-band management

Xenia should bridge established management protocols rather than replace them. Redfish is the preferred future adapter for standards-based out-of-band server management where available. Xenia's contribution is the session-bound authority, consent, evidence, and constrained operation semantics around that adapter.

## Evidence

The eventual runtime should distinguish at least:

- grant issued;
- grant attenuated;
- parent grant superseded;
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
- live session/subject binding is mechanically required by the use validator;
- attenuation is mechanically testable and cannot double-spend parent/child use budgets if runtime supersession is enforced;
- grant theft does not create a portable bearer credential;
- continual reevaluation is a protocol invariant rather than an optional product feature.

### Cost

- adapters must identify resources/actions canonically;
- use-count replay prevention and attenuation supersession require atomic runtime state;
- clock validity needs a trusted-enough local time source;
- cross-subject delegation needs a separate later design;
- branching attenuation needs explicit budget partitioning rather than implicit copies;
- richer policy/posture inputs will need their own authenticated evidence contracts.

## Non-goals

This ADR does not implement:

- a global IAM or relationship database;
- a general policy language;
- cross-subject delegation;
- branching capability allocation;
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
