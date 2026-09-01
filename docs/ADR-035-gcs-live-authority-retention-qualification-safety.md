# ADR-035 — Disposable live GCS authority-retention qualification safety

Status: Proposed / safety prerequisite

## Context

ADR-030 through ADR-034 qualify an exact Google Cloud Storage authority-retention design without credentials or network access. The next evidence step eventually needs a real disposable Google Cloud environment to test provider behavior that mocks cannot establish: IAM separation, actual bucket metadata, conditional-write races, read/list behavior, retention enforcement, and Bucket Lock.

A live qualification harness is itself dangerous. Google Cloud Storage Bucket Lock is irreversible once applied: the retention policy cannot be removed or reduced, and a locked bucket cannot be deleted until every retained object has aged past the policy. New buckets also receive provider defaults that are unsuitable to inherit silently in a deterministic disposable test environment, including a default soft-delete retention period unless explicitly changed.

Normal CI must therefore be incapable of turning a generic live-test switch into destructive or irreversible cloud actions.

## Decision

Introduce `xenia-operation-authority-retention-gcs-live-qualification` as a cloud-free safety/arming contract that must be satisfied before any later live Google SDK harness may mutate resources.

The safety crate has no Google Cloud SDK dependency and performs no network calls.

### 1. Live qualification is always disposable-purpose scoped

The primary arm must exactly equal:

`XENIA_GCS_LIVE_QUALIFICATION=DISPOSABLE_QUALIFICATION_ONLY`

This switch alone is insufficient to create or lock a bucket.

The harness additionally requires an exact project/bucket-specific acknowledgement derived from the qualification project ID and the fresh bucket name.

### 2. The harness cannot accept an arbitrary existing bucket

Callers supply no bucket name.

A bucket name is derived only from:

- fixed prefix `xenia-ar-qual-`;
- the dedicated qualification project number;
- an exact non-zero 8-byte run nonce supplied as 16 lowercase hexadecimal characters.

This makes the target explicit, fresh and reviewable while preventing a typo or reused configuration from redirecting the harness to a named development/production bucket.

The disposable acknowledgement is bound to the derived bucket:

`I_ACCEPT_DISPOSABLE_GCS_QUALIFICATION:<project-id>:<derived-bucket>`

Changing the run nonce invalidates an old acknowledgement.

### 3. Reversible and irreversible qualification are separate modes

V1 supports:

- `reversible`
- `irreversible-bucket-lock`

Reversible mode never authorizes Bucket Lock.

Irreversible mode requires a second exact acknowledgement:

`I_ACCEPT_IRREVERSIBLE_BUCKET_LOCK:<derived-bucket>:<retention-seconds>`

The second acknowledgement is bound to both the exact derived bucket and exact short qualification retention interval. An acknowledgement for another bucket or interval is invalid.

A later cloud runner must not derive irreversible authority merely from the primary live-test arm.

### 4. Disposable retention is deliberately short and cannot represent production policy

The safety contract accepts only a non-zero interval no greater than 300 seconds.

This ceiling exists to constrain accidental long-lived irreversible test resources. Passing this test proves provider retention mechanics only; it does not qualify a production recovery horizon.

Production retention duration remains committed separately by ADR-030.

### 5. Runtime and administration identities must remain distinct

Configuration carries non-zero 32-byte commitments for:

- the least-privilege runtime principal under test;
- the separate provisioning / retention-administration principal.

The digests must differ.

A future live harness may not qualify ADR-030 using one all-powerful credential for both roles and then infer that the runtime `create/get/list` permission boundary was tested.

The actual principal identities/credentials remain outside this crate; only their exact commitments are carried here.

### 6. Disposable bucket hardening state is explicit

Before authority-retention provider tests may run, the future live harness must positively verify the qualification bucket has:

- uniform bucket-level access enabled;
- public access prevention explicitly enforced;
- soft delete disabled for deterministic disposable cleanup;
- Object Versioning disabled;
- hierarchical namespace disabled;
- no Object Lifecycle Management rules.

The soft-delete requirement is a **qualification-environment cleanup rule**, not a silent modification of ADR-030 V1.

ADR-030 V1's canonical profile schema/digest must not be changed in place merely because this provider default was discovered later. If production authority identity needs to commit soft-delete policy, that must be introduced under a new provider-profile schema/version and migrated explicitly.

### 7. A future live runner must accept a validated config object

Cloud-mutating code should receive `GcsLiveQualificationConfigV1`, whose fields are private and whose constructors enforce this ADR.

It should not independently read loosely named environment variables and recreate weaker gating logic.

### 8. Normal CI remains cloud-free

The ordinary ADR-035 qualification workflow must:

- compile/test the safety contract only;
- contain no GCP credentials;
- contain no Google Cloud SDK dependency in this safety crate;
- perform no bucket/project/IAM mutation;
- retain source/lock/ADR/toolchain evidence.

A later Google-mutating workflow must be `workflow_dispatch`/protected-environment only and is a separate qualification tranche.

## Required safety tests

The safety crate must prove at least:

- reversible mode succeeds without any irreversible acknowledgement;
- changing the nonce/bucket invalidates an old disposable acknowledgement;
- irreversible mode without the second acknowledgement fails closed;
- irreversible acknowledgement for another retention interval fails closed;
- exact bucket+retention acknowledgement arms the irreversible mode;
- runtime/admin principal commitments cannot be equal or zero;
- retention above the disposable ceiling is rejected;
- run nonce must be exact canonical lowercase hex and non-zero;
- derived bucket name remains within the GCS name-length bound;
- required bucket state explicitly includes soft-delete disablement and the ADR-030 hardening controls.

## Planned live qualification phases

A later manual cloud harness should separate evidence into at least:

### Phase A — reversible provider qualification

- create only the derived fresh bucket in the dedicated qualification project;
- explicitly configure/verify required bucket state;
- verify runtime identity has exact create/get/list behavior and lacks update/delete/admin paths;
- run generation-zero concurrent-writer race tests;
- run exact read/list round trips and negative IAM tests;
- collect provider metadata, principal commitments, request/result evidence and audit identifiers;
- remove the unlocked retention policy if needed and fully tear down the bucket.

### Phase B — separately armed irreversible Bucket Lock qualification

- require the second bucket-specific acknowledgement;
- positively verify the bucket is still the fresh qualification bucket and contains no foreign objects;
- configure the short qualification retention period;
- lock it irreversibly;
- prove the policy cannot be removed/reduced;
- prove protected objects cannot be deleted or replaced before expiry;
- after the qualification interval, clean up only resources created by this run;
- retain evidence that cleanup succeeded or record any residual locked resources explicitly.

Phase B is never an implicit continuation of Phase A.

## Claim boundary

ADR-035 does not qualify any real GCS provider behavior. It qualifies only the arming/safety contract for a future live test.

It does not create buckets, grant IAM, lock retention, disable soft delete, write objects, execute Xenia authority effects, clear recovery state, spawn processes, or enable shell/PTY/SSH behavior.

## Consequences

Live provider testing becomes more verbose and requires deliberate per-run acknowledgements. That friction is intentional: reversible experimentation and irreversible retention locking have materially different operational risk and must not share one generic switch.
