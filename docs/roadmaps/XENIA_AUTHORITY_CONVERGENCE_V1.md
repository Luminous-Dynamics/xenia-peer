# Xenia Authority Convergence v1

Status: proposed implementation roadmap. This document does not promote any draft PR or claim qualification beyond its recorded evidence.

## Objective

Converge Xenia's negotiated-authority, rekey, privileged-operation, receipt-store, recovery, invocation-fence, and external-retention research into one reviewable production path before adding a broad integration catalog.

The target product boundary is:

```text
Identity -> Context -> Authority -> Credential -> Target -> Evidence
```

Xenia owns the authority invariant linking these planes. External systems remain adapters.

## Tranche X0 — cryptographic session safety

### X0.1 duplicate-key nonce repair

Promotion candidate: `xenia-wire#37`.

Required gate:

- preserve the evidence-only before-state from `xenia-wire#36`;
- duplicate installation of the current key is a true state no-op;
- next seal remains monotonic under the same key;
- genuine different-key rekey behavior remains intact;
- exact-head CI passes before promotion.

### X0.2 directional nonce-domain contract

Promotion candidate: `xenia-wire#34`, rebased/requalified after X0.1.

Freeze the rule that sender/sealing roles with overlapping sequence spaces may not share the same AEAD nonce domain under one key. Keep direction-specific TX/RX keys as a separately versioned future strengthening rather than hiding a key-schedule change in draft-03 errata.

### X0.3 wire security release and peer adoption

Cut the next `xenia-wire` alpha only after X0.1/X0.2 are qualified. Update `xenia-peer` in a dependency-only PR and rerun locked workspace qualification.

### X0.4 peer rekey containment

Promotion candidate: `xenia-peer#198`, rebased onto the nonce-safe wire baseline. Preserve `xenia-peer#196` as evidence-only and never merge it.

### X0.5 failure-atomic authority rekey

Implement `xenia-wire#32` after its authority/CI parent lineage is clean. One owned authority-session API must consume the sealed proposal, authenticate it, derive the new key internally, preseal sequence-0 Ack, commit key/nonce/lineage exactly once, and return durable transition evidence. No caller-supplied replacement key and no externally decoded “already authenticated” proposal input.

## Tranche X1 — authenticated negotiated authority

### X1.1 production V2 capability negotiation

Converge the staged negotiation/codec/V2 contract work rather than merging every research ancestor as a production unit.

Required properties:

- canonical host and viewer offers;
- hostile-byte bounded decoder;
- deterministic mutual selection;
- V4 + negotiation-binding -> V5 composition;
- Ed25519 + ML-DSA transcript binding;
- strict downgrade refusal;
- native/Wire interoperability;
- independent non-Rust reproduction;
- browser shadow alignment before browser acceptance.

Output only a non-constructible `AuthenticatedNegotiatedHandshake` after finalize verification.

### X1.2 causal consent integration

Consume the strongest semantics from `xenia-wire#21` / issue #20. Exact external-action authority must bind target, capability/action, parameter/request commitments, session lineage, expiry, and use policy. The response must bind the complete signed request.

Online use should require a session-borrowed non-serializable authority token. Historical evidence alone must not exercise authority.

### X1.3 ledger activation/rekey evidence

Persist V4/V5, peer offer hashes, selected-context hash, host identity, lineage id, activation id, authority profile, and rekey profile. Verified rekeys advance lineage; arbitrary key replacement terminates authority capability.

## Tranche X2 — operation authority V2 convergence

### X2.1 canonical semantic crate

Converge stable semantic types into `xenia-operation-proto`:

- resource identity/kind;
- operation class;
- exact rules and requests;
- semantic grant/use;
- replay/recovery classification.

Keep this crate runtime-free and permissively licensed. It must not claim live authority or persistence.

### X2.2 canonical authority crate

Use `xenia-peer#197` as the primary V2 authority baseline and incorporate the persistence-proof and invocation-fence semantics from `#199` and `#201`.

Target progression:

```text
VerifiedConsentAuthority
 -> GrantAuthorityV2
 -> UseAuthorityV2
 -> AdmissionAuthorityV2
 -> AdmissionPersistenceProofV2
 -> EffectArmAuthorityV2
 -> EffectArmedPersistenceProofV2
 -> InvocationStartLease
```

Fresh authenticated issuance is mandatory after an authority-epoch change. Old serialized grant bytes cannot be rewrapped into live authority.

### X2.3 adapter contract

Add a versioned target-adapter contract before enabling any privileged runtime. Every adapter must publish its request schema, supported operations, credential semantics, cancellation/recovery behavior, replay class, output sensitivity, and exact bounded irreversible-start definition.

No network round trip, DNS, credential fetch, user callback, or unbounded async operation may occur while holding the invocation/revocation linearization fence.

## Tranche X3 — first real privileged effect

### X3.1 complete local receipt persistence

Promote the SQLite experiment only after it persists:

- operation/use-slot admission;
- append-only receipt events;
- operation receipt head/CAS;
- authority epoch/store identity;
- frontiers/checkpoints required by the named local profile;
- recovery health state.

Crash ambiguity must fail closed. Unknown commit/effect outcome is not proof of non-execution.

### X3.2 local-durable pilot profile

Permit the first runtime under an explicitly narrower profile that does not claim rollback resistance against restored VM snapshots/backups. External frontier retention remains a stronger later assurance profile rather than a prerequisite for the first harmless real effect.

### X3.3 one-shot native execution

First target adapter:

- no shell;
- no PTY/stdin/elevation/detach;
- exact executable, argv, cwd, environment commitments;
- bounded runtime, output, concurrency;
- fresh reauthorization before arm;
- durable `EffectArmed` before process creation;
- invocation/revocation linearization;
- bounded teardown;
- terminal receipt or explicit `OutcomeUnknown`.

Initial demonstration target should be a harmless deterministic command such as `/usr/bin/id` or an equivalent test fixture.

Required adversarial scenarios include revocation at each authority phase, duplicate delivery, daemon restart, crash after admission, crash after arm, invocation-vs-revocation race in both legal orders, output overflow, and timeout.

### X3.4 Nix executable identity profile

Add an optional stronger identity for immutable Nix store executables/closures after the generic content identity is stable. Do not make Nix a prerequisite for Xenia operation semantics.

## Tranche X4 — rollback-resistant external authority retention

Continue the `#202-#213` lineage as a stronger assurance profile without blocking X3.

Complete:

- independent namespace trust;
- canonical provider profile;
- exact create/read/list semantics;
- authoritative readback after conflict/unknown outcome;
- full retained-lineage revalidation;
- real destructive GCS qualification with isolated project/bucket, separate principals, Bucket Lock, generation-zero writes, fault injection, process crash, gap/fork, and rollback recovery tests.

Do not claim real GCS/IAM/Bucket-Lock qualification from mock-only SDK tests.

## Tranche X5 — integration kernel and enterprise golden path

Create `xenia-integration-core` with provider-neutral boundaries such as:

```text
IdentityProvider
ApprovalContextProvider
CredentialProvider
ResourceDiscoveryProvider
TargetAdapter
EvidenceSink
RetentionBackend
```

Adapters may reject or narrow authority; they may not manufacture or widen it.

Initial integration sequence:

1. generic OIDC identity;
2. SSH target adapter;
3. Vault credential provider with use/injection distinct from disclosure;
4. ServiceNow approval/change context;
5. OpenTelemetry evidence export;
6. Kubernetes target/resource integration.

Golden-path demonstration:

```text
OIDC login
 -> authenticated Xenia session
 -> ServiceNow change/incident context
 -> exact causally bound approval
 -> session-bound Xenia grant/use
 -> Vault ephemeral credential
 -> credential injection without disclosure
 -> SSH adapter effect
 -> operation/session receipt
 -> immutable Xenia evidence
 -> OpenTelemetry/SIEM export
 -> ServiceNow result reference
```

OIDC, ServiceNow, Vault, SSH, and SIEM/OTel are integrations. None of them individually establishes Xenia authority.

## Existing PR classification

Treat existing branches as evidence and design ancestry rather than assuming every ancestor must merge.

### Merge/promotion candidates after their gates

- `xenia-wire#37` — duplicate-key nonce repair;
- `xenia-wire#34` — directional nonce-domain contract, after rebase/requalification;
- `xenia-peer#198` — peer Ack-domain containment, after safe wire adoption.

### Evidence only

- `xenia-wire#36`;
- `xenia-peer#196`;
- disposable qualification harness PRs whose stated purpose is execution of evidence lanes only.

### Convergence inputs

- negotiated authority/V2 handshake lineage including `xenia-peer#149` and descendants;
- causal authority `xenia-wire#21` and related authority-session drafts;
- `xenia-peer#175` semantic grants;
- `xenia-peer#197` consolidated V2 authority;
- `xenia-peer#199` persistence proofs;
- `xenia-peer#201` invocation/revocation linearization.

### Stronger-assurance lineage

- `xenia-peer#202-#213` external frontier/retention/GCS stack.

## Promotion discipline

A draft may advance only from evidence at its exact candidate head. Queued, pending, `action_required`, missing, stale, parent-head, or synthetic-merge results are not a pass for a source-head claim unless the relevant qualification contract explicitly says otherwise.

Convergence must preserve prior evidence rather than rewriting history. Superseded drafts can remain available as design/evidence ancestry while production integration moves onto a smaller canonical branch set.
