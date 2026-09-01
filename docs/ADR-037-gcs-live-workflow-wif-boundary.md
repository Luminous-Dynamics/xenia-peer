# ADR-037: GitHub Actions / Google WIF boundary for live GCS qualification

Status: Draft / inert workflow contract / no cloud authentication activated

## Context

ADR-035 defines the fail-closed disposable qualification inputs. ADR-036 defines the cloud-mutating binaries but intentionally provides no credentials or active cloud workflow.

The next boundary is the identity of the automation that invokes those binaries. Long-lived service-account keys, repository-wide OIDC trust, floating third-party Actions references, or an automatic push/PR trigger would undermine the separation established by ADR-035/036.

Current platform facts used by this ADR:

- GitHub Actions jobs require `id-token: write` to request an OIDC token.
- GitHub recommends environment protection rules when environments participate in OIDC deployment trust.
- GitHub OIDC tokens expose immutable `repository_id` and `repository_owner_id` claims.
- Repositories created before 2026-07-15 do not automatically receive the new immutable default `sub` format unless opted in; therefore this ADR does not depend on the default `sub` format.
- Google recommends Workload Identity Federation instead of service-account keys for deployment pipelines.
- Google recommends attribute conditions for GitHub's multi-tenant issuer and immutable/non-reusable mapped attributes.
- Google recommends dedicated service accounts for distinct pipeline applications.

Repository identity frozen for this contract:

- repository: `Luminous-Dynamics/xenia-peer`
- GitHub repository ID: `1214159052`
- GitHub owner ID: `216969177`
- eventual active workflow path: `.github/workflows/operation-authority-retention-gcs-live-manual-v1.yml`

## Decision

### 1. The first workflow is inert by construction

The reviewed candidate lives at:

`.github/workflow-contracts/operation-authority-retention-gcs-live-manual-v1.yml`

GitHub does not execute workflow files from that directory.

Activation requires a separate PR that moves/copies the reviewed bytes into `.github/workflows/`. The contract verifier fails if the active path appears in this tranche.

### 2. Manual dispatch only

The activated V1 workflow may have only `workflow_dispatch` as an event trigger.

It MUST NOT include:

- `push`;
- `pull_request`;
- `schedule`;
- `repository_dispatch`;
- workflow chaining from an ordinary CI workflow.

One dispatch selects exactly one phase:

- `provision`;
- `runtime`;
- `lock`;
- `teardown`.

There is no all-phases job and no dependency edge from reversible testing to the irreversible lock phase.

### 3. Main branch and exact-SHA binding

Every cloud job requires:

`github.ref == 'refs/heads/main'`

and the dispatcher supplies `expected_sha`, which must equal `github.sha` before authentication or cloud mutation.

The GitHub protected environments MUST also restrict deployment branches/tags to the intended main-branch policy.

The intent is that an operator reviews one exact merged commit, dispatches that commit, and the job refuses to qualify a different revision.

### 4. Short-lived OIDC only

Each cloud job has job-scoped permissions:

- `contents: read`;
- `id-token: write`.

There is no workflow-wide `id-token: write` permission.

Service-account JSON, `credentials_json`, static Google keys and GitHub secret-backed cloud credential blobs are forbidden.

The workflow authenticates through Google Workload Identity Federation using environment-scoped non-secret variables:

- `GCP_WORKLOAD_IDENTITY_PROVIDER`;
- `GCP_SERVICE_ACCOUNT`.

The eventual provider/action lineage is pinned by full commit SHA in the inert workflow contract.

### 5. Third-party Actions are full-SHA pinned

The initial reviewed pins are:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` (resolved from v4 during ADR-037 preparation);
- `google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093` (resolved from v3 during ADR-037 preparation);
- `dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c` with explicit toolchain `1.96.0`.

Changing any action revision is a new qualification input and requires review/evidence.

### 6. Google WIF provider is repository-ID bound

Use one GitHub OIDC provider in a dedicated workload identity pool/project unless a later threat model requires stronger isolation.

Recommended attribute mapping includes at least:

- `google.subject=assertion.sub`;
- `attribute.repository_id=assertion.repository_id`;
- `attribute.repository_owner_id=assertion.repository_owner_id`;
- `attribute.environment=assertion.environment`;
- `attribute.event_name=assertion.event_name`;
- `attribute.ref=assertion.ref`;
- `attribute.workflow_ref=assertion.workflow_ref`.

The provider attribute condition MUST require at least:

- `assertion.repository_id == '1214159052'`;
- `assertion.repository_owner_id == '216969177'`;
- `assertion.event_name == 'workflow_dispatch'`;
- `assertion.ref == 'refs/heads/main'`;
- `assertion.workflow_ref` identifies the exact activated Xenia live-qualification workflow on main.

Do not authorize GitHub merely by issuer URL, organization name, or repository name.

If the repository is explicitly migrated to GitHub immutable default subject claims, that is useful defense in depth but does not remove the explicit repository/owner-ID conditions above.

### 7. Environment-specific service-account impersonation

V1 environments are distinct:

- `xenia-gcs-qual-admin-reversible`;
- `xenia-gcs-qual-runtime`;
- `xenia-gcs-qual-admin-lock`;
- `xenia-gcs-qual-admin-cleanup`.

The irreversible lock environment should have the strongest reviewer/approval policy.

The Google service-account `roles/iam.workloadIdentityUser` grants MUST be scoped to external principals/attribute sets that match the intended environment, not all identities in the pool.

At minimum:

- the runtime environment may impersonate only the runtime service account;
- admin environments may impersonate only the explicitly approved qualification administration service account;
- the runtime identity must remain distinct from administration, as required by ADR-035/036.

V1 may use the same qualification-admin service account for reversible provisioning, lock and cleanup while GitHub environments impose different human approval boundaries. If future policy requires separate cloud identities for irreversible lock, introduce a new ADR-035 configuration schema instead of silently changing the meaning of the existing admin principal commitment.

### 8. Workflow environment verifies intended service-account identity

Before the auth action, each job compares:

`serviceAccount:${{ vars.GCP_SERVICE_ACCOUNT }}`

against the exact ADR-035 IAM member input appropriate to that job.

This is configuration binding, not a cryptographic attestation of the eventual access token. Runtime `testIamPermissions` and Google audit logs remain separate provider-side evidence.

### 9. Irreversible lock cannot be implied by ordinary live access

The lock job requires all of:

- `phase == 'lock'`;
- `mode == 'irreversible-bucket-lock'`;
- environment `xenia-gcs-qual-admin-lock`;
- ADR-035's exact non-empty lock acknowledgement;
- main branch;
- exact expected SHA;
- successful WIF authentication for that environment.

No successful provision/runtime job automatically starts it.

### 10. Evidence and workflow activation

A later active workflow MUST preserve evidence independently of the disposable bucket. At minimum capture:

- `github.sha`, run ID/attempt, actor/actor ID;
- selected phase/mode and non-secret ADR-035 parameters;
- environment name;
- WIF provider/service-account identifiers;
- harness output;
- Google audit/effective-permission evidence where available;
- teardown/residual-resource state.

Activation is separate from this ADR because the active workflow is itself a cloud-capable control-plane artifact.

## Inert-contract verifier

`scripts/verify_gcs_live_workflow_contract_v1.py` fails closed on the important textual invariants, including:

- automatic triggers;
- active workflow appearing prematurely;
- floating Action versions;
- static credential/key inputs;
- wrong protected-environment set;
- missing job-scoped OIDC;
- missing main/SHA gates;
- missing environment service-account/member comparison;
- weakened lock condition;
- duplicate/hidden destructive binary invocation;
- `continue-on-error`.

This does not replace GitHub's workflow parser. It makes security-sensitive workflow structure an explicit reviewed contract before activation.

## Explicit non-goals

ADR-037 does not:

- configure GitHub environments;
- configure Google's WIF pool/provider;
- grant `roles/iam.workloadIdentityUser`;
- create service accounts;
- activate a cloud workflow;
- obtain an OIDC token;
- call Google Cloud;
- qualify real provider behavior;
- clear Xenia recovery state;
- enable any privileged machine effect.

## Promotion gate

Before an active live workflow is created:

1. ADR-035 safety qualification is green;
2. ADR-036 destructive harness compile qualification is green on committed bytes;
3. #217 authority-bridge qualification is green;
4. ADR-037 linter is green;
5. the WIF provider configuration is reviewed against repository/owner IDs and exact workflow path;
6. all four GitHub environments exist with explicit deployment protection rules;
7. runtime/admin service-account IAM is reviewed for least privilege;
8. the active workflow is introduced by a separate reviewable PR;
9. Phase A reversible qualification must succeed before any separately dispatched Phase B lock run.
