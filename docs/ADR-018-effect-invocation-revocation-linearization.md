# ADR-018: Privileged-effect invocation / revocation linearization

Status: draft candidate

## Context

The privileged-operation stack already requires fresh effect-arm authorization, durable `EffectArmed` evidence, store/epoch authority, persistence proofs, rollback assurance, and a final live gate. A residual race remains if an authority-epoch revocation can commit after the final check but immediately before the adapter crosses its irreversible external-effect start boundary.

A phrase such as “check immediately before spawn” is not a synchronization guarantee.

## Decision

Define one in-process **invocation fence** shared by effect-start admission and authority-epoch transition/revocation.

The reference contract is `contracts/xenia-effect-invocation-fence-v2`.

Production runtime state must place the equivalent of `InvocationFenceStateV2` behind the same synchronization guard used to inhibit new starts and commit authority-epoch transitions.

## Linearization rule

Exactly one side obtains the fence first.

### Revocation first

```text
acquire fence
  -> inhibit new starts
  -> commit authority epoch transition
  -> release/resume under new policy
```

Any operation carrying old epoch/store/admission/arm/persistence evidence then fails the start gate.

### Invocation first

```text
acquire fence
  -> revalidate exact authority + persistence + rollback evidence
  -> reserve invocation linearization evidence
  -> cross exact adapter start boundary
  -> classify Started / NotStartedKnown / OutcomeUnknown
  -> release fence
```

A later revocation is ordered after that effect start. It may still cancel/terminate an already-started operation according to adapter policy, but it cannot truthfully claim the start was prevented.

This gives a total order for **effect start vs epoch transition**, not generic transactional ordering of the complete external operation.

## RAII lease

`InvocationStartLeaseV2` holds a mutable borrow of the reference fence. Production code must retain the actual synchronization guard for the same lifetime.

The lease is:

- not serializable;
- not cloneable;
- operation-specific;
- bound to exact arm/admission/store/persistence proof commitments and current epoch;
- resolved exactly once as started, positively not started, or unknown.

Dropping an unresolved lease conservatively records `OutcomeUnknown` in the reference model.

## Critical-section discipline

The invocation fence is **not** an adapter-work lock.

All reversible or potentially slow preparation must occur before the fence is acquired, including where applicable:

- parsing/validating requests;
- resolving immutable executable identity;
- allocating bounded buffers;
- preparing IPC descriptors;
- target discovery;
- network DNS/discovery;
- fetching credentials or external approvals;
- waiting for external anti-rollback anchors.

Inside the fence, the runtime may perform only:

1. final authority/persistence/rollback validation;
2. linearization reservation;
3. one bounded adapter-specific irreversible-start primitive;
4. immediate start classification.

The fence critical section MUST NOT contain an async `.await`, unbounded retry, interactive prompt, DNS lookup, remote network round trip, secret-provider fetch, external anchor write, or arbitrary user/plugin callback.

If an adapter cannot expose a bounded start primitive, it is not eligible for privileged-effect V2 until a safer adapter boundary is designed.

## Adapter start boundary

Every adapter must document its precise irreversible start point.

Examples:

- native exec: the OS process-creation/start primitive that makes target code schedulable;
- service request: the transport/application commit that can make the remote request observable/effective;
- Redfish: the request-send boundary chosen by that adapter profile;
- credential injection: the first target interaction that can consume the delegated credential.

Adapters must not claim `NotStartedKnown` after crossing their documented start boundary.

## Start classification

### `Started`

Positive evidence establishes that the adapter crossed the documented start boundary.

### `NotStartedKnown`

Positive evidence establishes that the boundary was not crossed. The same operation id remains non-retryable; a retry requires a new operation/admission under fresh authority.

### `OutcomeUnknown`

The runtime cannot prove whether the boundary was crossed. This is the conservative state for panic/crash/drop/ambiguous adapter errors after reservation.

Unknown never authorizes an automatic retry.

## Crash boundary

The in-memory fence does not survive process death. Durable `EffectArmed` and persistence-proof evidence already exists before the fence is entered. Therefore a daemon crash after write-ahead arming but before durable terminal classification is recovered conservatively under ADR-014 as an armed uncertain operation.

A future adapter may add target-specific reconciliation or durable start evidence, but absence of such evidence does not become permission to retry.

## Ongoing-operation revocation

This ADR orders **start** against revocation. It does not imply that already-started operations ignore later revocation.

Each adapter must separately define whether revocation:

- terminates the operation/process tree;
- cancels a request when cancellation is meaningful;
- prevents follow-up reads/writes;
- merely records that an irreversible one-shot effect already began.

For native exec V1, the intended policy remains process-tree termination on revoke/session teardown after a started process exists.

## Concurrency

The fence does not globally serialize complete operations. It serializes only short start/revocation critical sections. Multiple operations may execute concurrently after each has independently crossed its start boundary.

## Evidence

`InvocationLinearizationEvidenceV2` commits at least:

- operation id;
- current authority epoch digest;
- fence revision;
- exact effect-arm authority;
- admission and `EffectArmed` persistence proofs;
- store authority;
- semantic final-gate evidence;
- rollback/anchor assurance evidence;
- reservation time.

Resolution evidence commits the exact linearization digest plus adapter-specific start/no-start/uncertainty evidence.

## Non-goals

This ADR does not provide:

- distributed consensus between independent Xenia daemons;
- generic exactly-once external effects;
- synchronous cancellation of every possible target;
- permission to hold the fence while performing slow preparation;
- process execution, PTY, forwarding, credential use, or device control by itself.

## Promotion gate

Before native exec is enabled, its adapter must document and test its exact bounded start primitive, demonstrate that the same synchronization domain orders epoch revocation and `begin_start`, and inject races showing both legal outcomes:

1. inhibit/revocation wins -> no process start;
2. invocation lease wins -> start is recorded before later revocation.

Unresolved/crash paths must remain `OutcomeUnknown`, never blind retry.
