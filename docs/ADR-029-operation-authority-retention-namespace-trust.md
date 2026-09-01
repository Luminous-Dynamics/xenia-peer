# ADR-029: Operation Authority Retention Namespace Trust Gate V1

Status: **Draft / qualification required**

## Context

ADR-028 defines a provider-neutral immutable backend and a canonical `AuthorityRetentionNamespaceV1`. That namespace is deliberately only syntax. If a rollbackable host can choose the namespace it trusts, restoring an old machine snapshot can also restore an old `retention_lineage_id`/policy configuration and redirect recovery toward a different older-but-internally-valid external lineage.

The external store cannot decide which external lineage is authoritative for Xenia. That decision must come from a trust domain outside the protected machine's rollback scope.

## Decision

Introduce `xenia-operation-authority-retention-namespace-gate` as the authority-owned composition layer between recovery code and ADR-028's raw backend contract.

Production callers should depend on this gate rather than directly on the raw provider crate.

## Trust-source interface

`AuthorityRetentionNamespaceTrustSourceV1` is asked for the currently expected namespace of one exact `authority_domain_id`.

It returns one of:

- `Authenticated { authority_domain_id, expected_namespace_digest, trust_evidence_digest, valid_until_unix_ms }`;
- `Rejected`;
- `Unknown`.

`Unknown` is fail-closed. Network errors, unavailable registries, ambiguous policy state, or any other inability to authenticate the current namespace MUST NOT be converted into `Rejected` or local fallback configuration.

The authenticated response is accepted only when:

1. the returned authority domain exactly equals the requested domain;
2. expected namespace digest is non-zero;
3. trust-evidence digest is non-zero;
4. exact expected namespace digest equals the candidate namespace's canonical digest;
5. the trust result is live at operation start.

## What qualifies as a trust source

The Rust trait is a composition boundary, not automatic security.

A deployment satisfying ADR-029 must implement the trust source using evidence outside the protected host's rollback scope, for example:

- a separately administered remote namespace registry;
- TPM/secure-element/firmware-backed configuration whose anti-rollback properties are separately qualified;
- another independent witness/control-plane service;
- an offline/operator-held authenticated namespace commitment supplied through a governed recovery ceremony.

A plain file, environment variable, local database row, Nix configuration, or VM image stored inside the same rollback domain is **not** independently authenticated merely because it implements the trait.

## Verified namespace token

A successful composition produces `VerifiedAuthorityRetentionNamespaceV1`.

The type:

- has private fields;
- is non-serializable;
- is neither `Clone` nor `Copy`;
- is consumed by append/readback wrappers;
- has a maximum in-process lifetime of 60 seconds;
- rejects local clock regression after verification.

The short lifetime is only an application-time stale-token bound. It is not a Byzantine trusted-time claim.

Every append or complete readback therefore requires a fresh trust-source decision.

## Operation ordering

The production ordering is:

1. validate candidate namespace syntax;
2. authenticate expected namespace through the external trust source;
3. compare exact namespace digest/domain and trust evidence;
4. issue one private short-lived verified token;
5. validate token liveness;
6. only then call ADR-028 provider operations;
7. consume the token regardless of provider outcome.

Namespace-trust failure occurs before provider I/O. Authority evidence is never sent to a provider keyspace that failed the namespace gate.

## Trust-evidence digest

`trust_evidence_digest` is an audit commitment identifying the trust-source evidence/profile behind one successful namespace decision. V1 requires it to be non-zero but does not prescribe its schema.

A concrete trust-source profile must freeze what this digest commits—for example registry record/version/signature, TPM NV index/policy state, or recovery-ceremony evidence—and must provide its own qualification evidence.

The digest does not self-authenticate; authenticity comes from the configured trust-source implementation.

## Readback semantics

ADR-029 authenticates which namespace may be read. ADR-028 then proves whether that namespace contains a complete, canonical ADR-027 persistence lineage.

Neither gate alone authenticates ADR-025 recovery approval or ADR-026 global-revocation approval. Recovery must still run the corresponding authority verifiers over retained transition records.

An authenticated but empty namespace remains insufficient anti-rollback evidence.

## Security properties

V1 intends to establish:

- rollbackable host configuration cannot by itself select the authoritative external retention lineage;
- namespace selection fails closed when the external trust source is unavailable/ambiguous;
- wrong-domain and wrong-lineage responses fail before provider I/O;
- a verified namespace decision cannot be serialized into a bearer token;
- verified decisions cannot be indefinitely cached in-process;
- append/readback remain delegated to the already-frozen ADR-028 durability semantics.

## Non-goals / claim boundary

ADR-029 does **not**:

- define or qualify the first concrete namespace registry/TPM/witness provider;
- make the local wall clock a trusted timestamp authority;
- prove external object-store durability by itself;
- authenticate recovery/emergency approvals stored inside ADR-027 records;
- rotate the external namespace automatically;
- clear `RecoveryRequired`;
- mutate SQLite authority state;
- apply an authority epoch;
- arm or execute an external effect.

No process spawn, shell, PTY, SSH, or unattended privileged operation is enabled.

## Promotion gate

The gate is contract-qualified only after:

- Rust 1.96 format/test/strict-Clippy pass;
- Rust 1.94 build/test pass;
- real signed authority-state append/readback succeeds through a matching trust source;
- wrong namespace/domain, `Unknown`, expired trust, and expired-token cases prove zero provider I/O;
- exact dependency topology through ADR-028/#208 and ADR-027/#207 is retained as evidence;
- a concrete production trust-source profile is separately qualified before deployment makes an independent namespace-authentication claim.
