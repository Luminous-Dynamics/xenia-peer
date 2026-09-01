# ADR-031: Google Cloud Storage Operation Authority Retention SDK Adapter V1

Status: **Draft / classification qualification required; network transport not yet qualified**

## Context

ADR-030 freezes the Google Cloud Storage provider profile for Xenia operation-authority evidence. ADR-028 already defines the provider-neutral durability oracle. The remaining risk is the SDK boundary: retries, upload mode, generated status codes, timeouts, and transport errors must not silently change ADR-028 semantics.

The selected first lineage is exactly:

- `google-cloud-storage = 1.18.0`;
- `google-cloud-gax = 1.14.0`;
- Rust floor supported by the Storage SDK: 1.90;
- Xenia qualification floor: Rust 1.94.

`google-cloud-storage 1.18.0` directly depends on `google-cloud-gax 1.14.0`. Any SDK/GAX change creates a new adapter evidence lineage and requires this classification/conformance suite to be rerun.

## Decision

Split provider integration into two independently reviewable layers:

1. **pure SDK outcome classification** — no credentials/network/runtime required;
2. **async GCS transport** — later child tranche that constructs the exact frozen requests and returns ADR-028 outcome enums.

The async Google SDK MUST NOT be hidden behind `block_on()` inside ADR-028's synchronous/runtime-free trait. A later orchestration bridge or dedicated I/O worker may compose the two layers only under its own qualification.

## Create request profile

A V1 retained authority object create is valid for this classifier only when the transport proves all of the following:

1. exact provider profile is ADR-030;
2. exact canonical ADR-028 object bytes are at most **1 MiB**;
3. object name is the deterministic ADR-030 name;
4. write has exactly `ifGenerationMatch = 0` as its mutable provider precondition;
5. no object ACL/custom authorization path is added;
6. write retry policy is `google_cloud_gax::retry_policy::NeverRetry`;
7. resumable-upload threshold is forced to `usize::MAX`, and the 1 MiB size cap therefore keeps V1 on the single-shot upload path;
8. the request is sent exactly once by the Xenia transport layer.

The high-level Google Rust writer exposes both `set_if_generation_match(0)` and per-request `with_retry_policy(...)`, so these are explicit code-level invariants rather than inferred generated-proto fields.

### Why single-shot only

The Storage SDK can switch from single-shot to resumable uploads according to a configurable payload threshold. Resumable uploads introduce upload-session state and multiple mutating requests. That is unnecessary for tiny authority evidence and complicates lost-ack analysis.

V1 therefore rejects an external object larger than 1 MiB before provider I/O and forces the resumable threshold to `usize::MAX`. A future large-evidence/resumable profile requires a new ADR/schema and its own crash/network ambiguity analysis.

## Create error classification

The classifier receives the final `google_cloud_gax::error::Error` from an exact V1 create request and returns an ADR-028 create outcome.

### `AlreadyExists`

Only the frozen generation-precondition conflict class maps to `AlreadyExists`:

- structured `Code::FailedPrecondition`; or
- HTTP 412 when no structured status is available.

This is not accepted as durable by itself. ADR-028 must immediately perform an authoritative exact read and byte-compare the object. If the service ever uses this status for another precondition, the follow-up read remains fail-safe: absence/uncertainty cannot become durability.

`Code::AlreadyExists` / HTTP 409 is **not** treated as generation-zero precondition evidence in V1; it is either a definite rejection (`Code::AlreadyExists`) or ambiguous HTTP conflict (`409`) according to the classifier.

### `Rejected`

Only failures with a positive non-commit interpretation may be classified as rejected, including:

- GAX serialization failure, which Google documents as occurring before the request is made;
- structured invalid argument, unauthenticated, permission denied, not found parent/resource, already exists, unimplemented, and out-of-range request rejection;
- selected HTTP 4xx/501 responses whose semantics positively reject the exact request.

A concrete transport may narrow this set further; it may never broaden `Rejected` without a new qualification.

### `Unknown`

The default is `Unknown`.

It includes at least:

- GAX timeout;
- deserialization failure;
- retry-policy exhaustion;
- `Cancelled`;
- `Unknown`;
- `DeadlineExceeded`;
- `ResourceExhausted`;
- `Aborted`;
- `Internal`;
- `Unavailable`;
- `DataLoss`;
- HTTP 408/409/425/429;
- every HTTP 5xx;
- any unrecognized HTTP response;
- any future `#[non_exhaustive]` GAX status code.

Google explicitly documents that `DeadlineExceeded` on state-changing operations may be returned even when the operation completed successfully. It also documents timeout/deserialization as cases where a mutating request may or may not have completed. These can never become `Rejected` in Xenia V1.

## Future Google status codes

`google_cloud_gax::error::rpc::Code` is non-exhaustive. All classifier matches include a catch-all that maps future codes to `Unknown`.

A future SDK adding a new status therefore fails closed without requiring an emergency Xenia release.

## Read classification

Exact point reads are non-mutating and may use qualified SDK retries/resume in the later transport.

The final error classification is:

- structured `NotFound` / HTTP 404 -> authoritative `NotFound`;
- positive request/auth rejection -> `Rejected`;
- timeout/deserialization/exhaustion/transient/server/future/unknown -> `Unknown`.

ADR-028 treats an unknown read after an ambiguous create as unresolved durability and fail-stops the lineage.

Read content integrity checking provided by the Storage SDK is retained. A checksum/integrity failure is never converted into `NotFound` or exact bytes; it is an unknown/unusable read result.

## Listing classification

Complete recovery enumeration is non-mutating but must be complete.

A later transport may retry individual list pages, but it returns ADR-028 `Complete` only after every page for the exact namespace prefix has succeeded and every object name has passed ADR-030 grammar checks.

Any page timeout, transient/server error, deserialization failure, retry exhaustion, continuation failure, future status, or other ambiguity means the entire enumeration is `Unknown`.

Partial page results are discarded for authority purposes.

## Retry policy

### Create

Create uses `NeverRetry` at the request level even though generation-zero writes are logically idempotent under exact readback.

This is an evidence-discipline choice: one Xenia create attempt maps to one provider mutation attempt and one eventual ADR-028 ambiguity-resolution decision. The SDK must not hide a sequence such as:

`request committed -> response lost -> SDK retried -> 412`.

Even that sequence is theoretically recoverable through exact readback, but disabling automatic create retries yields a clearer destructive qualification and smaller state machine.

### Read/list

Read and list are non-mutating and may use a separately frozen bounded retry profile. Final unresolved failure still maps to `Unknown`.

## Success semantics

A successful create response from the exact single-shot generation-zero request maps to `DurableCreated` only after the SDK reports successful completion and its upload-integrity checks pass.

The actual network transport must additionally verify that the returned object identity/name/bucket is the expected target before returning success to ADR-028.

## Async boundary

The official Storage SDK is asynchronous. V1 forbids:

- constructing or nesting an implicit Tokio runtime inside ADR-028's synchronous trait;
- calling `block_on` from the provider trait implementation;
- holding Xenia authority/invocation locks while waiting on network I/O.

The later async transport exposes async operations whose results are provider-neutral ADR-028 enums. A production actor/service/orchestrator may call these and feed their results into the pure ADR-028 model under a separately qualified sequencing contract.

## Tests required for this classification tranche

Before the classifier PR is promoted:

- exact Storage 1.18.0 + GAX 1.14.0 resolve in `Cargo.lock`;
- Rust 1.96 fmt/test/strict-Clippy pass;
- Rust 1.94 check/test pass;
- `FailedPrecondition` maps to `AlreadyExists`;
- `AlreadyExists` does not masquerade as the generation-zero conflict class;
- deadline exceeded/transient/server codes map to `Unknown` for create;
- GAX timeout maps to `Unknown` for create/read/list;
- GAX exhausted policy maps to `Unknown` for create;
- read `NotFound` remains distinct from unknown;
- future/non-exhaustive status fallback is present in source review/Clippy-qualified code;
- exact dependency tree and source/lock hashes are retained.

## Additional gates for the later network transport

The network adapter is not provider-qualified until it proves:

- max 1 MiB preflight before network;
- deterministic ADR-030 object name;
- exact generation-match-zero request;
- `NeverRetry` create policy;
- forced single-shot upload profile;
- exact successful response identity validation;
- full read collection with SDK integrity validation;
- complete all-page listing and strict canonical object-name parser;
- no provider call occurs when ADR-029 namespace trust fails;
- destructive real-bucket lost-ACK/concurrent-writer tests from ADR-030 pass.

## Claim boundary

This ADR/classifier does **not**:

- access Google credentials;
- send network traffic;
- provision or verify a real bucket;
- implement the ADR-029 namespace trust source;
- claim that a Google status code authenticates recovery authority;
- clear `RecoveryRequired`;
- mutate SQLite authority state;
- apply authority epochs;
- arm or execute effects.

No process spawn, shell, PTY, SSH, or unattended privileged operation is enabled.
