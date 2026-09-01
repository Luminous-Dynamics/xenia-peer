# ADR-028: Operation Authority Retention Backend Contract V1

Status: **Draft / qualification required**

## Context

ADR-027 defines one append-only external retention lineage for operation-authority evidence. That lineage is intentionally provider-neutral. A deployable anti-rollback profile still needs a concrete persistence boundary whose network/storage behavior maps conservatively onto ADR-027's `Durable`, `Rejected`, and `Unknown` semantics.

Cloud/object-store SDK status codes are not themselves Xenia authority semantics. In particular, a timeout can occur after the provider committed an object, list operations may be eventual rather than authoritative, and an object key may already contain conflicting immutable bytes.

## Decision

Introduce `xenia-operation-authority-retention-backend` as a small synchronous provider contract and canonical external object format. Concrete async/network SDK adapters remain outside this contract and must translate provider behavior into the exact outcomes defined here.

### Canonical namespace

`AuthorityRetentionNamespaceV1` commits:

- `authority_domain_id`;
- random `retention_lineage_id`;
- `retention_policy_digest`.

`retention_policy_digest` MUST commit the qualified provider profile, immutability controls, administrative/credential trust domain, region/location policy, and any other deployment choice whose weakening would invalidate the external-retention claim.

The full namespace is embedded inside every retained object. Provider path naming alone is not an authority binding.

### Namespace trust boundary

`AuthorityRetentionNamespaceV1` is syntax, not authentication.

The raw backend contract MUST NOT be used by production recovery as the source of which namespace is trusted. A rollback-resistant deployment must obtain the expected namespace digest from an independently authenticated configuration or registry outside the protected machine's rollback scope.

A later authority-owned adapter MUST compare the complete namespace to that independently trusted commitment before exposing append/readback to recovery code. Until that adapter is qualified, this crate remains below the recovery authority boundary.

This prevents a restored local configuration from silently selecting a different older-but-internally-valid external retention lineage and calling it current.

### Canonical retained object

`AuthorityRetentionObjectV1` contains:

1. exact object schema;
2. complete `AuthorityRetentionNamespaceV1`;
3. exact ADR-027 `OperationAuthorityRetentionRecordV2`.

Before any provider method is called, the adapter validates that every initial/terminal authority state carried by the record belongs to the namespace's `authority_domain_id`.

The provider-independent locator is:

`(namespace_digest, retention_sequence)`.

The provider must treat this locator as immutable first-writer-wins state.

## Required provider operations

A conforming provider exposes only the semantic operations Xenia needs:

- atomic `create_if_absent(locator, exact_bytes)`;
- authoritative `read_exact(locator)`;
- complete authoritative `enumerate_complete(namespace_digest)` for a quiescent namespace or an equivalently strong provider snapshot.

An eventual/best-effort list MUST return `Unknown`, never `Complete`.

### Create outcomes

A provider adapter may report:

- `DurableCreated`: provider positively confirms the exact supplied bytes are durably retained;
- `AlreadyExists`: immutable locator already exists;
- `Rejected`: provider positively proves this attempt did not commit;
- `Unknown`: commit outcome cannot be proved.

Errors that may have happened after commit MUST map to `Unknown`, not `Rejected`.

## Lost-ack rule

`AlreadyExists` and `Unknown` are never accepted by themselves.

The adapter performs an authoritative exact read:

- identical canonical bytes -> resolve as durable;
- different bytes -> fork/conflict evidence and fail-stop;
- absent/rejected/unknown read -> unresolved durability and fail-stop.

There is no "retry and hope" path.

## Persistence-before-ack

ADR-027 state advances only after the backend is resolved as `DurableExact`.

A definite provider rejection leaves the in-memory model healthy and unchanged. A conflicting object or unresolved potentially committed write drives the model to `DurabilityUncertain`; no later append is permitted until immutable external readback reconstructs and validates the lineage.

## Complete readback

Recovery readback MUST:

1. use the caller-selected namespace (which production will later require to be independently authenticated);
2. obtain a complete authoritative enumeration;
3. require exact contiguous sequences `0..N` in ascending order;
4. read every exact object;
5. deserialize and validate the embedded namespace and record;
6. require the object's canonical reserialization to equal the exact retained bytes;
7. require the object-derived locator to equal the requested locator;
8. rebuild ADR-027's model from the complete retained record sequence.

An empty namespace is structurally valid but supplies no anti-rollback evidence and MUST NOT satisfy ADR-014 recovery policy by itself.

## Provider qualification requirements

A concrete provider profile is not accepted because its documentation appears compatible. It requires destructive conformance tests for at least:

- durable create;
- exact duplicate;
- commit followed by lost acknowledgement;
- timeout without proven commit;
- existing conflicting immutable bytes;
- positive rejection;
- concurrent first-writer races;
- complete readback;
- missing/gapped/duplicated/out-of-order enumeration;
- read/list ambiguity;
- credential/admin-domain separation;
- immutability/retention policy enforcement;
- provider-region/profile binding.

The provider adapter must record the exact SDK/API/profile lineage used for qualification.

## Security properties

V1 intends to establish:

- provider errors cannot redefine Xenia's durable/unknown distinction;
- lost acknowledgements resolve only through exact authoritative readback;
- conflicting immutable bytes are fork evidence, not retry conditions;
- provider namespace mistakes fail before authority evidence is sent;
- complete readback reconstructs the same ADR-027 lineage semantics;
- storage durability does not authenticate transition approvals.

## Non-goals / claim boundary

This ADR does **not**:

- authenticate which namespace a recovery operator should trust;
- select or qualify S3, GCS, Azure Blob, Holochain, TPM, TSA, or another concrete provider;
- turn object-store credentials into recovery authority;
- authenticate ADR-025 recovery approval or ADR-026 emergency approval;
- provide a Byzantine trusted timestamp;
- clear `RecoveryRequired`;
- mutate SQLite authority state;
- apply an authority epoch;
- arm or execute an external effect.

No process spawn, shell, PTY, SSH, or unattended privileged operation is enabled by this tranche.

## Promotion gate

ADR-028 may be considered contract-qualified only after:

- Rust 1.96 format/test/strict-Clippy pass;
- Rust 1.94 build/test pass;
- fault-injecting backend conformance tests pass;
- the exact dependency tree through ADR-027/#207 is retained as evidence;
- a second clean run verifies the committed source rather than an ephemeral rewrite.

A concrete provider requires its own subsequent qualification profile and evidence lineage.
