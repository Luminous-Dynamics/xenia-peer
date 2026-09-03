# Xenia Authority Invariants v1

Status: proposed convergence contract. This document does not itself authorize any runtime behavior.

## Purpose

Xenia is evolving from a remote-session system into a general authority layer for consequential interaction with machines. This document freezes the cross-cutting invariants that future handshake, consent, privileged-operation, credential, target-adapter, recovery, retention, and automation work must preserve.

These rules are intentionally stricter than any single product surface. Remote desktop, native execution, SSH, RDP, Kubernetes, Redfish, credential injection, Nix operations, and future agent-initiated actions are adapters over the same authority substrate.

## Core invariants

1. **Identity is not authority.** Authentication proves who or what is present. It does not by itself authorize a consequential action.
2. **Context is not authority.** Tickets, incidents, change windows, posture signals, role membership, policy decisions, and workflow state may constrain an authorization decision but may not independently manufacture Xenia authority.
3. **Serialized evidence is not live authority.** A signed grant, consent object, receipt, or retained record may prove historical authorization facts. Exercising live authority additionally requires the current authenticated Xenia session/subject and every applicable live gate.
4. **Authority must be causally bound.** Consequential effects must bind the exact target, capability/action, request or parameter commitment, authority lineage, and applicable expiry/use policy. Generic session approval must not be reinterpreted as permission for an arbitrary external operation.
5. **Authority narrows monotonically.** Attenuation may reduce scope, lifetime, use budget, or parameters. It may not widen rights, silently change subject, or escape the authenticated authority lineage.
6. **Credentials are not authority roots.** Possessing or retrieving a credential does not establish permission to use it. Credential providers are adapters. Credential use/injection and credential disclosure are distinct capabilities.
7. **Adapters do not manufacture or widen authority.** Target, identity, context, credential, evidence, discovery, and retention adapters consume or translate already-verified inputs. They may reject or narrow. They may never create additional Xenia authority.
8. **Durable admission precedes consequential effects.** A privileged effect must not begin until operation identity and use-slot authority are durably reserved according to the qualified store profile.
9. **Effect arming requires fresh authority.** Durable admission does not preserve permission indefinitely. Current session, subject, consent, policy, posture, store, epoch, and other required gates must be re-evaluated immediately before effect arming.
10. **Effect start and revocation have a defined order.** Every privileged adapter must expose a bounded irreversible-start boundary that can be linearized against authority-epoch transition or revocation. A vague “final check just before execution” is insufficient.
11. **Ambiguous outcomes remain ambiguous.** If Xenia cannot prove whether an external effect began or completed, it records `OutcomeUnknown` or an equivalent fail-closed state. It must not infer failure and blindly retry.
12. **Recovery never resurrects stale authority.** Store replacement, generation rollover, global revocation, or any other authority-epoch change invalidates prior live grants. Fresh authenticated issuance is required in the new epoch.
13. **Key transitions preserve authority only through authenticated lineage.** Arbitrary key replacement, detached session import, or unverified rekey tears down authority capability. Authority-preserving rekey must be an owned, authenticated, failure-atomic state transition.
14. **AEAD nonce uniqueness is global to a key domain.** Xenia must maintain `(key, nonce)` uniqueness across local key lifecycle transitions and every sealing role sharing that key. Per-session monotonic counters alone are not sufficient evidence of safety.
15. **Evidence and execution are separate trust domains.** Logs, receipts, session recordings, ledger entries, immutable-retention records, and SIEM exports are evidence. Their existence does not authorize an effect unless a specific authority protocol explicitly consumes authenticated evidence for that purpose.
16. **Claim strength is profile-bound.** A result may be described only at the level actually qualified: implemented, tested, platform-qualified, interoperability-qualified, rollback-resistant, externally reviewed, or production-supported must remain distinct claims.
17. **AI and automation may request authority but may not self-create authority.** Automated systems may discover, recommend, plan, or request bounded actions. Consequential authority still comes from an authenticated Xenia authority path and the configured governance policy.

## Canonical authority progression

The intended V2 privileged-operation progression is:

```text
authenticated negotiated session
        -> verified causal consent / issuance evidence
        -> GrantAuthority
        -> UseAuthority
        -> durable AdmissionAuthority + persistence proof
        -> fresh EffectArmAuthority
        -> durable EffectArmed + persistence proof
        -> invocation/revocation linearization
        -> adapter irreversible-start boundary
        -> Started | NotStartedKnown | OutcomeUnknown
        -> terminal receipt / recovery state
```

Safe production APIs should make skipped stages structurally difficult and should avoid caller-constructible “proof-like” objects that can be confused with authenticated authority.

## Adapter rule

The architectural rule for all future integrations is:

> **Adapters may translate authority. They may never manufacture or widen authority.**

A ServiceNow ticket is context. An OIDC token is identity evidence. A Vault secret is a credential. An SSH connection is an effect channel. OpenTelemetry is evidence export. None of them individually establishes permission to perform a consequential action.

## First qualified execution target

The first privileged-effect pilot should remain intentionally narrow:

- one-shot native execution only;
- no shell;
- no PTY or stdin;
- no elevation;
- no detached execution;
- exact executable + argv + cwd + environment commitments;
- bounded runtime/output/concurrency;
- durable admission and `EffectArmed` before process creation;
- revocation/invocation linearization;
- explicit crash ambiguity handling;
- no generic exactly-once claim.

A local-durable pilot profile may proceed before external anti-rollback retention is qualified, but it must explicitly exclude backup/VM-snapshot rollback resistance from its claims.

## Relationship to existing work

This convergence contract is intended to absorb the strongest invariants already developed across the causal-authority, negotiated-handshake, privileged-operation, recovery, invocation-fence, ledger-frontier, and external-retention draft lineages. It does not retroactively qualify those drafts or make their evidence interchangeable.
