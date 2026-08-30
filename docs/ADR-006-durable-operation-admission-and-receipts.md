# ADR-006: Privileged operations use durable at-most-once admission and explicit outcome uncertainty

Status: Proposed

## Context

ADR-005 defines session-bound, finite privileged-operation grants. A grant proves that one authenticated subject may attempt one exact operation under a bounded policy, approval, purpose, lifetime, and use budget. It does not answer the distributed-systems question that begins immediately before the first external side effect:

> What happens if the daemon, transport, storage layer, or target fails after an operation was admitted but before the caller learns its outcome?

This distinction is security-critical for actions such as process execution, reboot, credential rotation, service restart, database mutation, firmware management, and recovery operations. Blindly repeating an operation after a timeout can duplicate a non-idempotent effect. Claiming generic "exactly once" execution is also incorrect: Xenia cannot atomically commit its local evidence record and an arbitrary external system's state unless that adapter exposes a transaction or idempotency primitive strong enough to provide that property.

`xenia-ledger` already has a useful primitive: `Chain::append_transactional` appends an in-memory evidence entry and rolls it back if caller-supplied durable persistence fails. That gives Xenia a sound **persist-before-effect** building block. The operation layer must preserve the same discipline while keeping operation evidence semantically separate from consent evidence.

## Decision

Xenia V1 privileged operations use **durable at-most-once admission**, not a generic exactly-once-effect claim.

Before an adapter may begin an external side effect, the runtime MUST atomically establish durable local admission state for the exact operation. If that durable admission cannot be established, the effect MUST NOT begin.

Once an operation has reached the durable admitted state, its operation id and grant use slot are consumed even if the process later crashes or the target outcome becomes unknowable.

A reconnecting or retrying caller MUST query the existing operation receipt by operation id. It MUST NOT create a second attempt merely because the original response was lost.

## Terminology

### Admission

Admission is Xenia's local security decision and durable reservation that an exact operation is permitted to begin.

Admission includes at least:

- operation id;
- exact grant digest;
- exact capability-use digest;
- exact request digest;
- reserved grant use index;
- authenticated session-context commitment;
- authenticated subject commitment;
- adapter identity and protocol version;
- replay semantics;
- monotonic admission sequence;
- admission timestamp.

Admission does **not** mean the external effect happened.

### Effect attempt

The effect-attempt boundary is the earliest instant at which the adapter can cause externally visible target state or disclose/use a protected resource.

Examples:

- calling `spawn` for native exec;
- writing bytes to a target service connection after authentication;
- submitting a Redfish reset action;
- asking a secret provider to mint or inject a credential;
- issuing a state-changing database request.

Adapters MUST define this boundary explicitly.

### Receipt

An operation receipt is the durable, monotonic record of what Xenia knows about one operation's lifecycle. It is metadata/evidence, not a transcript of sensitive operation content.

## Receipt lifecycle

V1 uses a monotonic state machine. Implementations may persist more internal detail, but externally visible state may never move backward.

```text
Requested
   |
   +----> Refused
   |
   v
Authorized
   |
   v
Admitted        <-- durable before-effect boundary
   |
   +----> CancelledBeforeEffect
   |
   v
EffectAttempted
   |
   +----> Completed
   +----> FailedKnown
   +----> OutcomeUnknown
```

`Requested` and `Authorized` may be transient runtime states. `Admitted` and every later transition MUST be durably recoverable before the runtime reports the transition as committed.

## Terminal states

### Refused

Authorization failed before admission. No grant use slot is consumed unless a separate policy deliberately accounts refused attempts.

### CancelledBeforeEffect

The operation was durably admitted and its use slot consumed, but Xenia has durable evidence that the adapter did not cross the effect-attempt boundary.

V1 still does not recycle the consumed use slot. This deliberately favors conservative accounting over reclaiming authority after a crash/recovery ambiguity.

### Completed

The adapter has positive evidence that the requested operation reached its defined successful completion condition.

`Completed` does not imply the effect remains true forever. For example, "service restarted successfully" is a historical outcome, not a perpetual health assertion.

### FailedKnown

The adapter crossed the effect-attempt boundary and positively knows the operation failed according to adapter-specific semantics.

The effect may still have produced partial state. Adapters MUST NOT use `FailedKnown` to imply rollback unless rollback is itself part of the adapter contract and is proven complete.

### OutcomeUnknown

The adapter crossed, or may have crossed, the effect-attempt boundary but Xenia cannot prove the target outcome.

Examples include:

- daemon crash after process spawn but before durable completion evidence;
- connection loss after sending a state-changing request whose target response was not received;
- target reboot that intentionally destroys the management connection;
- external service timeout after accepting an idempotency key but before returning status.

`OutcomeUnknown` is a first-class security state, not an error to hide behind automatic retry.

## No blind retry

A duplicated request with an existing `operation_id` MUST resolve to the existing receipt or a stable duplicate-operation response. It MUST NOT consume another grant use slot and MUST NOT start a second effect.

A caller wishing to perform a genuinely new attempt after `FailedKnown` or `OutcomeUnknown` must request a new operation id and pass policy/consent evaluation again. Policy may require stronger approval for retrying an uncertain destructive operation.

## Replay semantics

Every adapter MUST declare one V1 replay class before admission:

### NonReplayable

Safe default. Xenia never automatically creates another effect attempt after durable admission.

Use for arbitrary native exec, reboot, credential rotation, firmware actions, and any adapter without a target-supported idempotency guarantee.

### TargetIdempotencyKey

The target protocol accepts a stable idempotency key whose semantics are strong enough for the adapter to query/retry the same logical operation without duplicating the target effect.

The idempotency key MUST be deterministically bound to the Xenia operation id and request commitment. A random replacement key on retry would create a new operation and is forbidden.

This class permits adapter-specific recovery of the **same logical operation**; it does not authorize a new grant use.

### Transactional

The adapter can place the target effect in a transaction whose commit/abort outcome can be recovered unambiguously under the target protocol.

This is the strongest class but MUST only be claimed when the target protocol actually provides the required semantics. A TCP connection, process spawn, shell command, or ordinary HTTP request is not transactional merely because Xenia has a local transaction.

## Exactly-once claim boundary

Xenia may claim:

- at-most-once **local admission** for an operation id;
- at-most-once grant-use reservation;
- durable persist-before-effect evidence;
- duplicate-operation detection;
- adapter-specific recovery where a target exposes sufficient idempotency/transaction semantics.

Xenia MUST NOT make a generic "exactly-once privileged operation" claim across arbitrary external systems.

For a `NonReplayable` adapter, a crash can leave the honest answer as `OutcomeUnknown`. Preserving that uncertainty is more secure than manufacturing a false success/failure state.

## Grant-use reservation

Admission and grant-use accounting form one logical atomic boundary.

For `CapabilityUseV1 { operation_id, use_index, ... }`, the runtime MUST ensure that before effect:

1. the operation id has not been admitted previously;
2. the live grant exercise context still matches the authenticated session and subject;
3. the current consumed-use counter equals `use_index`;
4. policy/consent/posture reevaluation succeeds;
5. the exact use/request commitments validate;
6. the use slot and operation admission are durably reserved together.

If persistence of this combined reservation fails, the effect MUST NOT begin.

If persistence succeeds and the process crashes immediately afterward, the use slot remains consumed and the recovered receipt is `Admitted`, not absent.

## Crash recovery

On startup, the operation runtime MUST reconcile non-terminal receipts before accepting conflicting privileged work.

### Recovered `Admitted`

If durable evidence proves the effect-attempt boundary was never crossed, the runtime may transition to `CancelledBeforeEffect`. It MUST NOT automatically start the effect after restart merely because authorization existed before the crash.

This avoids delayed execution after the original human/session context has disappeared.

### Recovered `EffectAttempted`

The adapter may query a target-supported idempotency/transaction mechanism when its replay class permits it.

If the adapter cannot prove a terminal result, the receipt transitions to `OutcomeUnknown`.

### Recovered terminal receipt

Terminal state is immutable except for append-only supplemental evidence that does not rewrite the historical result.

## Session teardown and revocation

Revocation or authenticated-session teardown prevents **new admission** immediately.

For an already `Admitted` but not-yet-attempted operation, the runtime MUST cancel before effect and durably record `CancelledBeforeEffect`.

For an operation already past `EffectAttempted`, the adapter follows its explicitly defined cancellation semantics. Native process execution, for example, should terminate the process tree when possible. The receipt records what is known; revocation must not rewrite an already-attempted effect as though it never happened.

## Monotonic persistence

Receipt persistence MUST reject:

- operation-id reuse with different commitments;
- grant-use-slot reuse;
- state regression;
- terminal-state replacement;
- request-digest changes;
- grant/use digest changes;
- adapter/replay-class changes after admission;
- sequence rollback.

Storage implementations should use compare-and-swap, uniqueness constraints, transactions, verified atomic files, or another mechanism that makes these invariants durable under concurrent requests and crashes.

The runtime-free protocol contract does not mandate SQLite, RocksDB, Holochain, a filesystem layout, or any other specific backend.

## Evidence and privacy

Receipts commit to operation content rather than storing sensitive content by default.

V1 receipts SHOULD contain hashes/identifiers for:

- grant;
- capability use;
- request;
- adapter;
- outcome metadata.

They SHOULD NOT automatically contain:

- stdout/stderr;
- terminal transcript;
- clipboard contents;
- transferred file contents;
- passwords/tokens/private keys;
- database result rows;
- full request payloads that contain secrets.

An adapter may produce separately governed evidence artifacts whose digests are referenced by the receipt.

## Separation from the consent ledger

`xenia-ledger` remains the consent/evidence chain. Operation receipts have a different cardinality and lifecycle: one consent ceremony can authorize many bounded operations, and one operation can produce several lifecycle transitions.

Therefore V1 does not overload `ConsentKind` with operation runtime events.

A later bridge may anchor batches/checkpoints of operation-receipt state into the cryptographic evidence ledger. That bridge should commit to receipt digests/checkpoints rather than force potentially high-volume operation transitions into the human-consent event vocabulary.

## Adapter requirements

Before a privileged adapter becomes live, it MUST define:

1. canonical request commitment;
2. exact effect-attempt boundary;
3. success condition;
4. known-failure condition;
5. cancellation behavior before and after effect attempt;
6. replay class;
7. recovery/query behavior after crash;
8. sensitive-output/evidence policy;
9. resource identity semantics;
10. maximum operation lifetime.

## Native exec implications

The first one-shot exec adapter should use `NonReplayable`.

The durable order is:

```text
authenticate session
  -> validate exact exec request
  -> validate CapabilityUseV1
  -> reevaluate consent/policy/posture
  -> atomically reserve use slot + persist Admitted receipt
  -> spawn directly (no shell)
  -> durably mark EffectAttempted
  -> stream bounded stdout/stderr
  -> durably record terminal outcome
```

The implementation SHOULD order the `EffectAttempted` persistence as close as possible to the process-creation boundary, but no ordinary userspace design can make persistence and OS process creation one atomic transaction. Recovery therefore treats ambiguity conservatively.

A child process tree must remain bound to session/revocation/cancellation lifetime rules even if response delivery fails.

## Service access implications

Opening a constrained service connection is not automatically a state-changing effect. However credential minting/injection, authentication attempts, and protocol requests may each have separate evidence boundaries.

A future service-access adapter should avoid treating an entire long-lived connection as one opaque operation when security-relevant sub-actions require their own grants or receipts.

## Redfish/recovery implications

Reset/power/firmware operations are particularly important examples of `OutcomeUnknown`, because a successful operation may intentionally terminate the management path used to observe it.

The adapter should use target operation/task resources when Redfish exposes them, but absence of a final response must not be interpreted as failure and retried automatically.

## Agent implications

Autonomous agents must use the same receipt path as human operators.

An agent planner may decide that retry is desirable, but a retry after a terminal/uncertain receipt is a **new privileged operation** requiring a new operation id and fresh authorization. Planning logic cannot override receipt replay semantics.

## Non-goals

ADR-006 does not:

- implement a process runtime;
- implement a database;
- guarantee exactly-once external effects;
- provide distributed consensus between Xenia peers;
- implement cross-subject delegation;
- record arbitrary session content;
- define a universal rollback protocol;
- make non-idempotent external systems idempotent;
- permit automatic retries of uncertain privileged effects.

## Security invariants

1. No privileged external effect begins before durable admission.
2. One operation id maps to one immutable operation commitment.
3. One grant use slot cannot admit two operations.
4. Duplicate delivery resolves to the existing receipt, not a second effect.
5. State transitions are monotonic.
6. Terminal outcomes are immutable.
7. `OutcomeUnknown` is preserved when outcome cannot be proven.
8. No generic exactly-once-effect claim is made.
9. Replay/recovery behavior is adapter-declared and committed before effect.
10. Session revocation blocks new admission immediately.
11. A crash after admission does not resurrect delayed authority on restart.
12. Sensitive output remains separate from receipt metadata by default.

## Consequences

This design intentionally spends some availability to gain safety. An operation can consume a use slot without producing an external effect, and an uncertain effect can require human/operator reconciliation rather than an automatic retry.

That is the correct default for privileged infrastructure operations. Higher availability is introduced only where an adapter can prove stronger target-side idempotency or transaction semantics.
