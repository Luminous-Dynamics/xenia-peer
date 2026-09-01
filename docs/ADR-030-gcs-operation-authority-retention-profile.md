# ADR-030: Google Cloud Storage Operation Authority Retention Profile V1

Status: **Draft / provider qualification required**

## Context

ADR-028 defines the provider-neutral immutable backend semantics required by Xenia operation-authority retention, and ADR-029 authenticates which external namespace is trusted. A concrete provider must map its own consistency, conditional-write, retention, IAM, and SDK behavior into those frozen semantics without weakening them.

Google Cloud Storage (GCS) is the first provider candidate because its documented model maps closely to ADR-028:

- object reads are strongly globally consistent;
- object listings are strongly globally consistent;
- a generation-match precondition of `0` performs a write only when there is no live object with that name;
- Bucket Lock can make a bucket retention policy irreversible;
- uniform bucket-level access removes object ACLs as a parallel authorization path;
- public access prevention can be explicitly enforced;
- Google now publishes and supports an official Rust `google-cloud-storage` client.

This ADR freezes a provider requirements profile before any network SDK adapter is allowed to claim conformance.

## Selected SDK/API lineage

The first qualification target is:

- Rust crate: `google-cloud-storage`;
- exact version: `1.18.0`;
- service API profile: `google.storage.v2`;
- crate publisher/implementation lineage: Google Cloud Client Libraries for Rust.

Changing the SDK version or API profile creates a new provider evidence lineage. Compatible future upgrades may reuse the semantic ADR only after destructive provider conformance is rerun.

The selected crate declares Rust 1.90 minimum, below Xenia's Rust 1.94 qualification floor.

## Canonical object naming

Provider object names are derived solely from ADR-028's namespace digest and ADR-027 retention sequence:

`xenia-authority-retention/v1/<64-lowercase-hex-namespace-digest>/<20-digit-zero-padded-sequence>.bin`

No user/session/operation string is accepted as an object-path fragment.

Fixed-width sequence names make lexicographic GCS listing order equal retention-sequence order.

## First-writer primitive

Every object-data write MUST use the GCS generation-match precondition `ifGenerationMatch = 0` through the official Rust SDK/API equivalent.

GCS documents that this request succeeds only when no live object exists at that object name and otherwise fails with precondition failure.

### Object Versioning is forbidden in V1

GCS also documents that generation-match `0` may succeed when only noncurrent versions exist. Bucket Lock permits a live object in a versioned bucket to become noncurrent while preserving that version under retention.

That behavior is too subtle for Xenia's V1 locator invariant: one retention sequence should correspond to one immutable live object, not a provider version-selection problem.

Therefore V1 requires Object Versioning to be disabled. A future version-aware profile would require a new schema and explicit generation retention/readback rules.

## Consistency requirements

V1 relies on GCS's documented strong global consistency for:

- object read-after-write;
- object read-after-update/delete semantics relevant to authoritative absence/conflict classification;
- object listing.

ADR-028 complete readback MUST consume every page returned for the exact namespace prefix. A partial page, failed continuation, timeout, or otherwise incomplete pagination maps to `Unknown`, never `Complete`.

Public caching is irrelevant to the authority path and MUST NOT be used as the read source. Reads use authenticated Cloud Storage APIs.

## Bucket Lock and retention horizon

The dedicated bucket MUST have a Bucket Lock retention policy and that policy MUST be irreversibly locked before the provider profile is promoted.

Observed retention period MUST be at least both:

- `minimum_bucket_retention_seconds` in the profile; and
- the deployment's `required_recovery_horizon_seconds`.

The profile contract rejects a minimum above Google's documented 100-year maximum (3,155,760,000 seconds).

Bucket Lock is a time-bounded WORM guarantee. Once an object's retention expires, sufficiently privileged administration can delete or replace it. Xenia's contiguous external lineage will detect missing/conflicting historical records, but availability and long-horizon rollback resistance still depend on choosing an appropriate retention horizon and preserving ADR-029 namespace authority.

Deployments that want effectively lifetime retention should strongly consider the 100-year maximum for this small evidence stream, subject to privacy/legal/cost requirements.

No Object Lifecycle Management rule is allowed in the dedicated V1 bucket.

## Access-control profile

### Uniform bucket-level access

Uniform bucket-level access MUST be enabled so ACLs cannot act as a second object authorization system.

### Public access prevention

The bucket's own public access prevention setting MUST be explicitly `enforced`, rather than merely relying on inherited organization state.

An organization-level public-access-prevention constraint is additionally recommended, but the bucket must remain safe if ancestor policy changes later.

### Runtime data-plane principal

The Xenia runtime identity is restricted to the exact object permissions:

- `storage.objects.create`;
- `storage.objects.get`;
- `storage.objects.list`.

The V1 profile rejects any wider object permission list.

In particular the runtime identity MUST NOT have object delete/update/move/restore/retention permissions, bucket update/delete/IAM permissions, or retention-policy administration.

A custom IAM role is preferred over a broad predefined role so the provider profile can prove this exact allowlist.

### Retention administrator

The identity permitted to provision/lock the bucket retention policy MUST be a different trust identity from the runtime writer. Their exact principal commitments are part of the provider profile.

The runtime credential therefore cannot weaken the retention configuration even if compromised.

IAM grants/revocations are not treated as instantaneous revocation primitives; GCS documents that access-control changes can propagate asynchronously. Xenia's authorization/revocation security continues to come from its own authority epochs and invocation fence, not from emergency cloud-IAM changes.

## Bucket feature restrictions

V1 requires:

- Object Versioning disabled;
- hierarchical namespace disabled;
- no lifecycle rules;
- uniform bucket-level access enabled;
- public access prevention explicitly enforced;
- locked retention at or above the profile minimum.

The restrictions intentionally reduce provider feature interactions during first qualification.

## Object metadata

Bucket Lock protects object data from deletion/replacement during retention but does not freeze editable object metadata.

Xenia therefore trusts only the exact canonical object **bytes** read through ADR-028. Provider metadata, ETags, custom metadata, contexts, content type, cache controls, and labels may be used for diagnostics but do not establish record identity or authority.

The runtime principal does not receive object-update permission.

## Encryption profile

`encryption_profile_digest` commits the selected encryption/key-management configuration.

The first provider qualification SHOULD use Google-managed encryption to avoid adding a separate customer-managed key availability/administration dependency to the anti-rollback witness path. A CMEK profile is permitted only as a separately qualified profile whose KMS project, key identity, key-admin separation, availability, and anti-destruction rules are committed and destructively tested.

Loss of decryption ability is treated as unavailable/unknown external evidence, never as proof that a record does not exist.

## IAM/profile commitment

`iam_policy_profile_digest` commits controls not represented by the exact runtime object-permission list, including relevant organization constraints, workload identity/service-account configuration, bucket IAM bindings, administrative separation, and any network/perimeter policy on which the provider claim depends.

Both the IAM and encryption commitments are evidence descriptors; their bytes do not self-authenticate. ADR-029's external trust source authenticates the complete namespace/profile commitment.

## Provider error mapping

The later GCS SDK adapter MUST conservatively map provider outcomes into ADR-028:

- successful generation-0 write with final success response -> `DurableCreated`;
- generation precondition failure for an already-live object -> `AlreadyExists`;
- failures known to occur before a write could be accepted/committed -> `Rejected` only when the adapter can positively prove non-commit;
- transport cancellation, timeout, retry exhaustion, server failure, or another state where commit may have happened -> `Unknown`.

After `AlreadyExists` or `Unknown`, ADR-028's exact authoritative read/byte comparison remains mandatory.

The adapter MUST NOT blindly retry a create after an ambiguous result. Exact readback resolves the ambiguity first.

## Readback listing

The GCS adapter lists only the deterministic namespace prefix and MUST:

1. consume all pages;
2. reject object names outside the canonical record grammar;
3. reject duplicate/ambiguous sequence mappings;
4. return only the exact sequence set to ADR-028;
5. treat any page/read failure as `Unknown`;
6. rely on ADR-028 to read and byte-validate every object before constructing ADR-027's lineage.

Soft-deleted/noncurrent versions are not part of the V1 live-object lineage.

## Provisioning verification

`GcsObservedBucketStateV1` captures the provider state that must be observed before qualification/use:

- project number;
- bucket name and location;
- effective locked retention period;
- uniform bucket-level access state;
- explicit public access prevention state;
- Object Versioning state;
- hierarchical namespace state;
- lifecycle-rule count.

`verify_observed_bucket_state_v1` fail-closes if any required property is weaker than the frozen profile.

A production SDK adapter must obtain these facts through authenticated control-plane APIs. Local configuration claiming that the bucket is locked is not sufficient.

## Destructive qualification requirements

Before GCS can satisfy the deployed ADR-028 claim, a dedicated real test bucket/profile must prove at least:

1. two concurrent `ifGenerationMatch=0` writers cannot both create different live bytes at the same object name;
2. a precondition failure is resolved through exact point read;
3. simulated lost acknowledgement after a potentially committed write resolves only through exact point read;
4. ambiguous write plus unavailable/ambiguous read fail-stops;
5. strongly consistent prefix listing sees every successfully created test record after success;
6. pagination over more than one page yields the exact contiguous set;
7. conflicting externally pre-created bytes are detected as fork evidence;
8. runtime credentials cannot delete, overwrite, update metadata, move/restore objects, change retention, change bucket IAM, or unlock/change the retention policy;
9. retention administrator is distinct from runtime principal;
10. Bucket Lock is locked and cannot be reduced/unlocked;
11. Object Versioning is disabled;
12. no lifecycle rule exists;
13. uniform bucket-level access and explicit public access prevention are active;
14. complete readback reconstructs the exact ADR-027 lineage;
15. exact SDK version/API/profile and test environment are retained as evidence.

Provider qualification must use disposable test authority data, not production authority evidence.

## Security boundary

ADR-030 does not make GCS the authority root.

The composition remains:

`ADR-029 independently authenticated namespace -> ADR-030 qualified GCS profile -> ADR-028 provider semantics -> ADR-027 external evidence lineage -> ADR-025/026 authority re-verification -> ADR-014 governed recovery`.

A GCS success response can prove storage behavior; it cannot approve recovery or execute an operation.

## Non-goals

This profile does not:

- yet implement the network SDK adapter;
- provision or irreversibly lock a real bucket;
- qualify a real Google Cloud project/service account;
- define a concrete ADR-029 remote namespace registry;
- claim trusted wall-clock time;
- clear `RecoveryRequired`;
- mutate SQLite authority state;
- apply authority epochs;
- arm or execute effects.

No process spawn, shell, PTY, SSH, or unattended privileged operation is enabled.

## Evidence basis for the candidate

The initial profile was selected from current Google Cloud documentation confirming strong object read/list consistency, generation-match `0` create preconditions, Bucket Lock behavior including its 100-year maximum and interaction with Object Versioning, uniform bucket-level access, public access prevention, and the official Google Cloud Rust Storage client.

These provider facts are external dependencies. Qualification must record and periodically re-evaluate them when changing SDK/API/provider profile versions.
