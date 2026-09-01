# ADR-032: GCS authority-retention single-shot create transport

Status: **Experimental / draft qualification**

## Context

ADR-028 freezes provider-neutral immutable retention semantics. ADR-029 authenticates which external namespace is current. ADR-030 selects a qualified Google Cloud Storage bucket profile. ADR-031 freezes conservative Google SDK/GAX error classification.

The next mutating boundary must prove that Xenia constructs the exact Google write for which ADR-031's classifier is valid. A generic GCS uploader is too broad: retries, resumable sessions, additional preconditions, mutable metadata, or caller-selected object names would change the failure model.

## Decision

Add `xenia-operation-authority-retention-gcs-create-transport` as the only V1 Google create primitive below the future async ADR-028/029 bridge.

### Exact mutation profile

For every accepted canonical ADR-028 object the transport MUST:

1. validate the frozen ADR-030 provider profile before provider I/O;
2. reject empty canonical bytes;
3. reject canonical objects larger than 1 MiB before provider I/O;
4. derive the bucket resource solely as `projects/_/buckets/<qualified-profile-bucket>`;
5. derive the object name solely through ADR-030's deterministic namespace-digest + fixed-width retention-sequence mapping;
6. use Google Storage `WriteObject` with exactly `if_generation_match = 0` and no other generation/metageneration precondition;
7. set per-request retry policy to `google_cloud_gax::retry_policy::NeverRetry`;
8. set resumable-upload threshold to `usize::MAX` and keep the V1 payload <= 1 MiB;
9. use the exact canonical ADR-028 object bytes as payload;
10. map the final SDK result only through ADR-031.

A successful Google response maps to `DurableCreated`. `FailedPrecondition` / HTTP 412 maps to `AlreadyExists`, which is **not** durability: ADR-028 must exact-read and byte-compare. Ambiguous failures remain `Unknown` and therefore require the same readback/fail-stop path.

### Why no create retry

A lost response after a committed mutation is security-relevant state. Automatic retry can turn that state into a later precondition failure and obscure which provider attempt actually created the object. V1 therefore preserves one Xenia mutation attempt -> one Google mutation attempt -> one explicit ADR-028 ambiguity-resolution path.

### Why no resumable upload

Authority-retention records are deliberately small. Resumable upload adds session state, additional requests, restart semantics, and more lost-ack boundaries without useful benefit. V1 bounds canonical bytes at 1 MiB and forces the Google resumable threshold to `usize::MAX`.

### Google public-stub qualification

Google Storage 1.18.0 exposes `Storage<S>::from_stub(...)` and a public Storage stub whose unrelated methods have defaults. The test double therefore captures the real `WriteObjectRequest` produced by Google's public high-level builder rather than a Xenia shadow representation.

The mock qualification MUST verify:

- exact bucket resource;
- exact deterministic object name;
- `if_generation_match == Some(0)`;
- all other generation/metageneration preconditions absent;
- exact canonical payload bytes;
- resumable threshold equals `usize::MAX`;
- oversize input causes zero stub/provider calls;
- Google `FailedPrecondition` remains `AlreadyExists`;
- an ambiguous service status remains `Unknown`.

Google's `RequestOptions` intentionally does not expose retry policy to external mocks. Qualification therefore additionally inspects the production source and requires the exact `.with_retry_policy(NeverRetry)` builder call and `.with_resumable_upload_threshold(usize::MAX)` call to remain present. Dependency resolution is pinned to `google-cloud-storage = 1.18.0` and `google-cloud-gax = 1.14.0`.

## Authority boundary

This transport is a provider primitive, **not** an authority API.

Production code MUST NOT call it with a caller-invented locator. The future async composition layer must first authenticate the ADR-029 namespace, validate that ADR-030 is the exact `retention_policy_digest` profile committed by that namespace, construct/validate ADR-028 canonical object bytes, and only then invoke this transport with the corresponding locator.

The transport does not clear recovery state, mutate SQLite, authenticate recovery/emergency approvals, apply an authority epoch, or arm/execute an external effect.

## Qualification boundary

The first ADR-032 lane is credential-free and network-free. It proves compilation against the exact Google SDK lineage and request construction through Google's public mock surface. It does **not** yet prove real IAM, Bucket Lock, network behavior, one-attempt behavior on the wire, or destructive lost-ack recovery against a real GCS bucket.

Those require a separate disposable-bucket qualification tranche after read/list transport and the async ADR-028/029 bridge exist.
