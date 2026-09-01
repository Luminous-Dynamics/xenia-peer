# ADR-036: Manual destructive GCS authority-retention qualification harness

Status: Draft / experimental / no live provider evidence yet

## Context

ADR-035 deliberately stops before any cloud-mutating API. ADR-030 through ADR-034 define the provider profile, SDK outcome semantics, create/read transports and authority-gated composition, but mocks cannot establish that a real bucket/IAM configuration enforces those assumptions.

The live harness must therefore be capable of destructive provider actions while remaining difficult to invoke accidentally and easy to review as a separate surface.

Current provider facts relevant to this tranche:

- new Cloud Storage buckets have soft delete enabled by default unless an explicit policy disables it;
- soft delete duration `0` disables the feature;
- Bucket Lock is irreversible: after locking, retention cannot be removed or shortened;
- Bucket Lock should use the bucket metageneration as a precondition;
- bucket metadata writes are strongly readable after write, although configuration propagation may still take time;
- the official Rust `StorageControl` client exposes bucket creation/update/delete, IAM, permission testing and retention-policy locking.

## Decision

### 1. Separate executable phases

The harness has four separate binaries:

1. `xenia_gcs_admin_provision_v1`
2. `xenia_gcs_runtime_permissions_v1`
3. `xenia_gcs_admin_lock_v1`
4. `xenia_gcs_admin_teardown_v1`

There is intentionally no `run_everything` binary. Reversible qualification cannot fall through into Bucket Lock.

### 2. No network-capable target in the default feature set

Provider code exists only under the Cargo feature `live-gcs-network`. All four binaries declare that feature as `required-features`.

Ordinary CI may compile and lint the feature, but MUST NOT execute these binaries. The compile-only workflow has no cloud credential setup, no GitHub OIDC `id-token: write`, and no protected cloud environment.

A later manual workflow must be a separate diff and protected environment.

### 3. ADR-035 remains the primary destructive gate

Every binary reparses `GcsLiveQualificationConfigV1::from_current_environment()`.

The bucket remains derived from dedicated project number + fresh run nonce. No caller-supplied arbitrary bucket name is accepted.

`admin-provision` accepts only `reversible` mode.

`admin-lock` accepts only `irreversible-bucket-lock` mode and therefore requires ADR-035's second exact bucket/retention acknowledgement.

### 4. Bind exact IAM members to ADR-035 principal commitments

The harness additionally requires:

- `XENIA_GCS_LIVE_RUNTIME_MEMBER`
- `XENIA_GCS_LIVE_ADMIN_MEMBER`

Each exact IAM member string is domain-separated with BLAKE3 under `xenia-gcs-live-principal-v1` and MUST equal the corresponding ADR-035 principal digest.

The runtime/admin member strings MUST differ. `allUsers` and `allAuthenticatedUsers` are forbidden.

Accepted V1 member forms are explicit service-account/user/group or Workload Identity principal/principalSet member strings.

This binding proves configuration identity. It does not by itself prove which credential Google authenticated for one invocation; that remains an execution-environment responsibility in V1.

### 5. Runtime least privilege is tested from the runtime credential itself

The runtime probe invokes `testIamPermissions` using the credential executing that binary.

It MUST positively observe:

- `storage.objects.create`
- `storage.objects.get`
- `storage.objects.list`

It MUST positively observe absence of dangerous capabilities including:

- object delete/update/restore/retention mutation;
- bucket update/delete/IAM administration.

The provisioning IAM policy grants the configured runtime member only:

- `roles/storage.objectCreator`
- `roles/storage.objectViewer`

The protected live workflow must run provisioning/lock/teardown and runtime probing under distinct credential contexts.

### 6. Fresh bucket creation is hardened at creation time

The admin provision phase creates only the ADR-035-derived bucket and requests:

- dedicated project;
- exact configured location;
- Standard storage class;
- Uniform Bucket-Level Access enabled;
- public access prevention `enforced`;
- soft delete policy explicitly set to duration zero;
- Object Versioning disabled;
- hierarchical namespace disabled;
- no lifecycle rules.

The resulting bucket is re-read and these properties are positively checked.

Provider-normalized identifiers are handled narrowly:

- `Bucket.project` is verified against the configured project **number**, because GCS returns project-number resource identity;
- `bucket_id` must equal the ADR-035 derived bucket exactly;
- returned resource name must identify that exact bucket;
- location may differ only in provider-documented case normalization.

No feature mismatch is treated as benign normalization.

### 7. Every mutable bucket transition is conditional

Bucket policy updates use the immediately observed `metageneration` as `if_metageneration_match`.

The Bucket Lock request likewise uses the metageneration returned after setting the test retention policy.

A metadata race therefore fails instead of becoming last-writer-wins.

### 8. Bucket Lock is a separate irreversible transaction

`admin-lock` first verifies the existing disposable bucket state and confirms it is not already locked.

It then:

1. writes the exact ADR-035 short retention interval with a metageneration precondition;
2. verifies the policy is present and still unlocked;
3. calls `lock_bucket_retention_policy` with the new metageneration;
4. verifies the returned policy is locked with the exact interval.

Future live qualification should additionally attempt a prohibited decrease/removal and re-read the bucket before claiming irreversible enforcement evidence.

### 9. Teardown is explicit and may legitimately fail until expiry

Teardown completely enumerates live objects, deletes them using generation-qualified deletes, then deletes the bucket with a metageneration precondition.

For a locked qualification bucket this MUST naturally fail while objects remain under retention. The operator reruns the explicit teardown after expiry.

There is no background cleanup daemon and no promise that an irreversibly locked bucket is immediately disposable.

### 10. Live cloud evidence is separate from compile qualification

A compile-green ADR-036 PR proves only that the destructive harness builds against the pinned Google client and that its cloud-free safety tests pass.

It does NOT prove real GCS behavior.

A later protected-environment live run must retain at least:

- exact Git commit and Cargo.lock hash;
- Rust and Google SDK versions;
- ADR-035 config digest excluding secret credential material;
- bucket/project/location identifiers;
- bucket metadata before/after each transition;
- IAM policy and `testIamPermissions` results;
- object create/read/list conflict tests through ADR-034;
- provider request/error outcomes;
- Bucket Lock response and negative mutation checks when Phase B is armed;
- teardown outcome and any residual-resource/retention-expiry receipt.

## Explicit non-goals

ADR-036 does not:

- run from normal CI;
- select production credentials;
- claim principal identity is hardware-attested;
- alter ADR-030 V1's canonical provider-profile digest;
- make soft-delete disablement a production-policy requirement;
- clear Xenia `RecoveryRequired`;
- authorize an operation effect;
- spawn a process, shell, PTY or SSH session.

## Promotion gate

Before live-provider qualification can count toward the Xenia anti-rollback claim:

1. ADR-036 compile/test/clippy/MSRV qualification is green;
2. #217 authority bridge qualification is green;
3. the manual cloud workflow is reviewed separately;
4. the workflow uses a dedicated qualification project and protected environments;
5. admin/runtime credentials are distinct;
6. reversible Phase A passes first;
7. irreversible Phase B requires a separately approved run with the exact ADR-035 lock acknowledgement;
8. the live evidence artifact is retained independently of the disposable qualification bucket.
