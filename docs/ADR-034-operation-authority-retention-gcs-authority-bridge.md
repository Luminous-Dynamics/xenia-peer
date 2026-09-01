# ADR-034 — Authority-gated asynchronous GCS retention composition

Status: Proposed / qualification target

## Context

ADR-027 defines the append-only semantic operation-authority retention model. ADR-028 defines the provider-neutral immutable backend contract and the only accepted durability/fail-stop transitions. ADR-029 authenticates the expected external-retention namespace through a separately administered trust source. ADR-030 binds that namespace to one exact Google Cloud Storage profile. ADR-031 classifies final Google SDK errors conservatively. ADR-032 and ADR-033 provide narrow async create and exact read/list primitives.

Those layers intentionally do not by themselves provide a safe application-facing cloud API. An application must not be able to skip namespace authentication, substitute a different GCS profile, invent provider locators, persist a semantically invalid retention record, or reinterpret ambiguous provider results as success.

## Decision

Introduce `xenia-operation-authority-retention-gcs-authority-bridge` as the first GCS retention layer intended for application orchestration.

The bridge is an **authority composition layer**, not a new authority model and not a new durability state machine.

### 1. Verified namespace is consumed, not inspected or cached

Every append or complete readback requires a fresh `VerifiedAuthorityRetentionNamespaceV1` issued by ADR-029.

The namespace-gate crate exposes only a consuming operation:

`consume_verified_namespace_v1(token, now_unix_ms)`

It re-runs ADR-029's private liveness/clock checks and consumes the non-Clone token before releasing the authenticated namespace for immediate composition. No reusable raw-namespace getter is introduced.

Expired, clock-regressed, rejected, or otherwise invalid tokens fail before GCS provider I/O.

### 2. Exact ADR-030 profile binding is mandatory before provider I/O

After token consumption, the bridge calls `GcsAuthorityRetentionProfileV1::validate_namespace()`.

The authenticated namespace's `retention_policy_digest` must equal the exact canonical profile digest used to construct both the create and readback transports. The create and readback clients therefore cannot silently target different provider-policy profiles.

A profile mismatch fails before any create/read/list provider call.

### 3. Semantic ADR-027 preflight happens before provider I/O

The bridge must reject a malformed, conflicting, gapped, non-successor, or already fail-stopped semantic candidate before cloud mutation.

V1 performs this preflight by cloning `OperationAuthorityRetentionModelV2` and invoking the existing real `append()` implementation on the disposable clone with a synthetic `PersistenceOutcomeV2::Durable` result.

This deliberately avoids a second semantic validator.

- `Appended` means the candidate is a valid new next semantic record and provider I/O may begin.
- `DuplicateSame` returns immediately and performs no provider write.
- every existing ADR-027 typed error fails before provider I/O.

The live model is not mutated by preflight.

### 4. Applications never provide GCS object names or raw canonical bytes

For a new candidate, the bridge itself constructs `AuthorityRetentionObjectV1` from the consumed authenticated namespace and semantic ADR-027 record.

ADR-028 owns:

- namespace/authority-domain binding;
- canonical object serialization;
- provider-independent locator derivation;
- exact external bytes.

ADR-030 maps that locator to the deterministic GCS object name. Application callers do not supply bucket paths, object names, sequence strings, or canonical provider payloads.

### 5. Async provider observations may be materialized, never reinterpreted

The bridge may perform ADR-032/033 async SDK calls and hold their exact observed outcomes in memory. It must not make an independent durability decision from those outcomes.

Observed create/read outcomes are replayed through an in-memory implementation of `ImmutableAuthorityRetentionBackendV1`, and the live model is mutated only by ADR-028's existing `append_via_backend_v1()` path.

Therefore:

- `DurableCreated` may become durable through ADR-028;
- `AlreadyExists` is not success without exact authoritative byte equality;
- `Unknown` is not success without exact authoritative byte equality;
- conflicting bytes become external-object conflict / fail-stop;
- unresolved provider state becomes `DurabilityUncertain`;
- a positive provider rejection does not become a durable append.

The replay backend checks that ADR-028 rebuilds the exact locator and bytes previously observed by the async operation. A mismatch is a bridge error rather than an implicit success.

### 6. A readback-transport error after a possibly committed create must still fail-stop

If a create outcome requires exact readback and the ADR-033 transport itself fails local validation before returning an authoritative outcome, the bridge must not simply return that transport error while leaving the live model healthy.

Before returning the readback-transport error, it replays `Unknown create + Unknown read` through ADR-028. The expected result is `BackendStateUnknown`, which moves ADR-027 to `DurabilityUncertain`.

If that fail-stop replay cannot be established, the bridge reports a dedicated composition error.

### 7. Complete recovery is materialization followed by ADR-028 verification

For `readback_verified()` the bridge:

1. consumes/rechecks the ADR-029 token;
2. proves the ADR-030 profile binding;
3. obtains an ADR-033 complete sequence enumeration;
4. requires the sequence to be exactly contiguous `0..N` before object reads;
5. exact-reads every enumerated object;
6. materializes those bytes only in memory;
7. supplies them to ADR-028's existing `readback_complete_lineage_v1()` implementation.

ADR-028 remains responsible for decoding, canonical reserialization, full embedded namespace equality, locator equality, and ADR-027 lineage reconstruction.

The bridge does not define a cloud-specific second interpretation of retained evidence.

## Required qualification tests

The V1 qualification lane must prove at least:

- expired verified namespace -> zero provider calls;
- valid namespace committed to another GCS profile -> zero provider calls;
- semantically invalid ADR-027 candidate -> zero provider calls;
- exact duplicate replay -> no second provider write;
- successful create -> live ADR-027 append;
- create commits but returns timeout -> exact readback required before append succeeds;
- immutable locator contains different bytes -> `DurabilityUncertain` and conflict error;
- possibly committed create followed by readback local-validation failure -> live model is still `DurabilityUncertain`;
- complete append/readback round trip reconstructs the same ADR-027 records;
- source contract contains token consumption, profile validation, disposable-model preflight, and ADR-028 replay calls;
- exact Google Storage/GAX versions remain pinned for this qualification lineage.

## Non-goals / claim boundary

ADR-034 does **not** qualify:

- a real Google project, bucket, credentials, IAM policy, Bucket Lock configuration, VPC Service Controls, or network path;
- a concrete ADR-029 deployment trust source;
- concurrent live recovery without a provider snapshot/quiescence guarantee;
- automatic clearing of `DurabilityUncertain`;
- SQLite/local authority mutation outside ADR-027;
- arming or executing a privileged operation;
- process spawning, shell execution, PTY, SSH, forwarding, elevation, or credential delegation.

A later destructive disposable-cloud qualification must test the actual provisioned bucket/IAM/retention environment before this bridge can support a production cloud-authority claim.

## Consequences

The provider is deliberately reduced to an observed persistence mechanism beneath Xenia authority semantics. Google SDK success/failure behavior cannot directly grant authority or mutate the live retention model. The cost is an additional composition layer and, for ambiguous creates, an authoritative readback round trip. That cost is accepted because it preserves a single fail-closed authority/durability interpretation across local tests and real provider transports.
