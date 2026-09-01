# ADR-038: Live GCS workflow activation readiness

Status: Draft / runtime-free readiness contract / no workflow activation / no cloud access

## Context

ADR-035 makes disposable live GCS qualification explicitly armable. ADR-036 isolates the cloud-mutating provider harness. ADR-037 defines an inert, reviewed GitHub Actions + Google WIF workflow contract and explicitly requires activation to happen in a later PR.

A simple file copy from `.github/workflow-contracts/` to `.github/workflows/` is still too weak as an activation ceremony. The external control plane may have drifted after workflow review: protected-environment reviewers can change, WIF conditions can broaden, service-account impersonation can change, or prerequisite qualification evidence can be superseded.

The activation step therefore needs a short-lived, independently authenticated readiness object that commits the exact reviewed code and external trust configuration.

## Decision

### 1. Activation manifest is evidence syntax, not authority

`GcsLiveActivationManifestV1` commits:

- authority domain;
- immutable GitHub repository ID `1214159052`;
- immutable GitHub owner ID `216969177`;
- exact reviewed main commit;
- SHA-256 of the exact inert workflow bytes;
- exact eventual active workflow path;
- qualification-evidence digests for ADR-034/#217, ADR-035/#218, ADR-036 and ADR-037;
- exact qualified ADR-030 GCS profile digest;
- WIF provider/configuration digest;
- WIF attribute-mapping/condition digest;
- all four protected-environment policy digests;
- all four environment service-account/member identity digests;
- a fresh activation nonce;
- bounded observation/application times.

Serialized manifest bytes cannot authenticate themselves.

### 2. Exact current checkout is measured independently

The verifier receives the actual current main Git SHA and actual SHA-256 of the inert workflow from outside the serialized manifest and requires exact equality.

A manifest for commit A cannot activate commit B. A manifest for workflow bytes X cannot activate workflow bytes Y.

The readiness ceremony also requires the active workflow path to still be absent. The ceremony is therefore preparation for a later narrow activation change, not post-hoc approval of an already-active workflow.

### 3. Runtime and administration remain distinct

The runtime service-account/member digest must differ from the service-account/member digest for every admin environment.

ADR-037 V1 still permits the reversible-provision, irreversible-lock and cleanup environments to use the same qualification-admin service account while GitHub environment policy supplies separate human approval boundaries. Requiring three different admin service accounts would change ADR-035/037 semantics and therefore needs a new version rather than an implicit strengthening in this layer.

### 4. Environment policy is part of activation identity

The required environment names remain exactly:

- `xenia-gcs-qual-admin-reversible`;
- `xenia-gcs-qual-runtime`;
- `xenia-gcs-qual-admin-lock`;
- `xenia-gcs-qual-admin-cleanup`.

Each manifest carries a separate digest of the reviewed protection configuration for that environment. Changing reviewers, branch restrictions, wait timers or other security-relevant environment policy invalidates the manifest rather than inheriting the change silently.

The contract does not prescribe one serialization of GitHub's environment API response. The authority-owned adapter that creates these digests must define a canonical external observation format and preserve the raw evidence used to derive it.

### 5. WIF trust is committed explicitly

The manifest separately commits:

- the exact WIF provider resource/configuration; and
- the exact attribute mapping + condition.

The expected ADR-037 condition continues to require immutable repository/owner IDs, manual dispatch, main ref and the exact activated workflow path. A provider/resource with the same human-readable name but broader policy is a different activation input.

### 6. Qualification evidence is freshness-bound

Activation is blocked unless non-zero evidence digests are supplied for:

- authority-gated GCS composition (ADR-034/#217);
- disposable qualification safety (ADR-035/#218);
- destructive-harness compile qualification on committed bytes (ADR-036);
- inert workflow/WIF contract qualification (ADR-037).

The manifest does not decide whether an arbitrary digest is genuine qualification evidence. The independent readiness authority is responsible for authenticating the complete manifest against the evidence registry/review process it governs.

### 7. Two time windows

A manifest may be prepared for at most 24 hours from observation to expiry.

The final independent readiness attestation may be valid for at most 15 minutes.

This separates a useful review/preparation window from a short actual activation-authority window. An old pre-approved activation manifest is not a permanent capability.

### 8. Independent trust source

`GcsLiveActivationTrustSourceV1` returns one of:

- `Authenticated`;
- `Rejected`;
- `Unknown`.

The authenticated result commits the exact manifest digest and a non-zero authority identity, and has its own bounded lifetime.

A trait implementation that simply echoes the caller's manifest is structurally possible Rust but is not an ADR-038-conforming security profile. The production authority source must be outside the machine/configuration rollback domain whose workflow is being activated—for example a governed evidence registry, independently administered release authority, or equivalent signed operator/reviewer ceremony.

`Rejected` and `Unknown` both prevent activation.

### 9. Successful result is non-serializable

`VerifiedGcsLiveActivationReadinessV1` has private fields and no Serde representation. It exists only as the result of running the live verifier against:

1. a structurally valid manifest;
2. exact observed main/workflow bytes;
3. absence of the active workflow;
4. a live independently authenticated manifest digest.

Storing old serialized JSON/YAML cannot recreate this result.

### 10. Activation remains a separate PR

ADR-038 does not create `.github/workflows/operation-authority-retention-gcs-live-manual-v1.yml`.

After all prerequisite evidence is green, the activation PR should be mechanically narrow:

- base from the exact reviewed main commit;
- copy the exact inert workflow bytes to the active path;
- attach/reference the live readiness evidence;
- do not change harness source, provider profile, WIF contract or security policy in the same activation diff.

If any of those inputs change, issue a new manifest and live attestation.

## Failure cases

Activation fails closed for at least:

- wrong repository/owner ID;
- wrong main commit;
- changed inert workflow bytes;
- active workflow already present;
- missing prerequisite evidence digest;
- wrong protected-environment name;
- zero or changed environment-policy digest;
- zero or changed WIF commitment;
- runtime/admin identity collision;
- stale manifest;
- rejected/unknown readiness source;
- attestation for another manifest;
- zero attesting authority;
- stale/future/overlong live attestation.

## Explicit non-goals

ADR-038 does not:

- activate a GitHub workflow;
- configure GitHub environments;
- inspect GitHub environment state itself;
- configure or query Google WIF;
- create/modify service accounts or IAM;
- obtain an OIDC token;
- call GCS;
- perform a live provider qualification;
- grant Xenia operation authority;
- clear recovery state;
- execute any machine effect.

## Promotion gate

An activation PR is ineligible until all of the following are true:

1. ADR-034/#217 qualification is green on the merged dependency lineage;
2. ADR-035/#218 qualification is green;
3. ADR-036 destructive harness has passed its clean second compile-qualification pass on committed bytes;
4. ADR-037 workflow/WIF contract is green;
5. the exact ADR-030 GCS profile is qualified;
6. WIF provider configuration/condition has been independently reviewed and committed into the manifest;
7. all four GitHub environment policies have been independently observed and committed into the manifest;
8. runtime/admin service-account bindings have been independently reviewed and committed into the manifest;
9. exact current main SHA and inert workflow SHA-256 match the manifest;
10. the active workflow is still absent;
11. a conforming independent authority authenticates the exact manifest digest inside the 15-minute application window.

Even after activation, only explicitly dispatched, protected-environment live qualification is enabled. No Xenia privileged operation or automatic recovery authority follows from workflow activation.
