# ADR-008: Effect-Arm Reauthorization and External-Anchor Gates

- Status: Proposed
- Date: 2026-08-30
- Depends on: ADR-005, ADR-006, ADR-007
- Scope: privileged-operation transition from durable admission to actual external effect

## Context

ADR-005 defines session-bound grants and live reevaluation. ADR-006 defines durable operation admission and the write-ahead `EffectArmed` transition. ADR-007 defines the store and anti-rollback boundary.

One gap remains before any real privileged adapter may execute: durable admission can outlive the authority state that justified it.

An operation might be admitted, queued, and then encounter any of the following before its adapter is invoked:

- user revocation;
- session teardown;
- subject reauthentication to a different identity;
- grant expiry or supersession;
- policy change;
- posture degradation;
- approval withdrawal;
- emergency stop;
- a delayed external anti-rollback anchor.

Admission therefore reserves and spends authority, but it must not become an indefinitely reusable right to start an external effect later.

A second subtlety appears in high-assurance rollback-safe mode. If `EffectArmed` must be included in a rollback-resistant external frontier anchor before the effect starts, time can pass between the local arm record and the external anchor acknowledgement. Authority must still be current after that delay.

## Decision

Xenia will separate **admission authorization** from **effect-arm authorization**.

### 1. Admission permanently spends the grant-use slot

Successful `OperationAdmissionV1` remains a permanent use-slot reservation even if the operation is later cancelled before effect.

V1 does not refund a consumed grant slot. Refunding would reopen replay/double-spend complexity and make crash recovery ambiguous.

The operational meaning is:

```text
admission accepted
    => grant use slot permanently consumed
    != external effect indefinitely authorized
```

### 2. Fresh effect-arm authorization is mandatory

Immediately before an operation may become `EffectArmed`, the runtime MUST perform a fresh reevaluation using current authority state.

The reevaluation must prove at least:

- the same authenticated operation/admission;
- the same live subject expected by the admission/grant;
- a currently authenticated live session acceptable to policy;
- the grant has not expired, been superseded, or been revoked;
- current consent/approval still permits this exact operation class;
- current policy still permits the exact resource/action/request;
- current security/posture requirements still pass;
- any emergency-stop or global privileged-operation inhibit is clear.

A historical admission receipt is not sufficient evidence for this step.

### 3. Positive arm decisions are short-lived

A successful effect-arm reevaluation produces a typed `EffectArmAuthorizationV1` commitment.

V1 arm authorization has a short absolute validity window. The standalone contract currently caps that window at 60 seconds; deployments may choose a smaller policy value.

The record commits to:

- operation id;
- exact admission digest;
- exact grant and use commitments;
- live session-context commitment;
- live subject commitment;
- current consent-state commitment;
- current policy-state commitment;
- current posture-state commitment;
- current effect-anchor policy commitment;
- monotonic authorization epoch;
- evaluation and expiry times.

Only positive permit decisions produce this record. Denials do not become reusable authorization artifacts.

### 4. Effect-arm authorization is evidence, not a bearer credential

Possession of serialized `EffectArmAuthorizationV1` bytes does not authorize an effect by itself.

The runtime must still possess and validate the current authenticated session/subject context and confirm the durable operation store is in the expected non-terminal state.

The record exists so the eventual `EffectArmed` receipt can commit exactly which live reevaluation justified crossing toward the effect boundary.

### 5. `EffectArmed` must commit the arm-authorization digest

Before the receipt protocol is integrated into production, the draft receipt schema from ADR-006 must be amended so an `EffectArmed` event commits the exact `EffectArmAuthorizationV1` digest.

Conceptually:

```text
OperationReceiptEventV1::EffectArmed
    admission_digest
    operation_id
    arm_authorization_digest   <-- required, non-zero
    recorded_at
```

This prevents a durable arm event from being detached from the current consent/policy/posture decision that justified it.

A future schema may model this field differently, but the binding is mandatory.

### 6. `EffectArmed` is necessary but not always sufficient

ADR-006 described durable `EffectArmed` as the hard side-effect gate. ADR-008 refines that statement:

- `EffectArmed` is always a necessary local gate;
- deployment policy may impose additional mandatory gates before actual effect invocation.

In particular, rollback-safe high-assurance mode requires an externally anchored frontier that includes the exact `EffectArmed` event.

### 7. Two anchor assurance modes are explicit

V1 recognizes two broad deployment claims.

#### Local durable mode

```text
fresh arm authorization
    -> durable EffectArmed
    -> final live gate check
    -> effect
```

This mode can support at-most-once semantics inside the local non-rolled-back store domain, but it does not claim safety after rollback past the local frontier.

#### External-anchor-before-effect mode

```text
fresh arm authorization
    -> durable EffectArmed committing authorization digest
    -> calculate frontier containing EffectArmed
    -> write/verify rollback-resistant external anchor
    -> final live gate check
    -> effect
```

Only after the external anchor is durably acknowledged may the effect begin.

The anchor must live outside the rollback scope relevant to the claim. Anchoring into another file on the same rolled-back disk does not provide rollback resistance.

### 8. A second final live gate check occurs after external anchoring

External anchoring can take time. Therefore `ExternalAnchorBeforeEffect` mode MUST repeat the non-persistent live allow/deny check after anchor acknowledgement and immediately before adapter invocation.

At minimum this final gate verifies:

- current session still valid;
- current subject still matches;
- no revocation/emergency stop has occurred;
- the arm authorization has not expired;
- durable receipt head remains the exact expected `EffectArmed` event;
- external anchor still names the expected store frontier.

This final check does not create a new portable permission token.

### 9. Add `CancelledAfterArmBeforeEffect`

ADR-006 currently transitions from `EffectArmed` only to `Completed`, `FailedKnown`, or `OutcomeUnknown`.

That loses useful information when Xenia positively knows the adapter invocation boundary was never crossed after arming—for example, authority is revoked while waiting for an external anchor or at the final live gate.

Before receipt V1 is frozen, add a terminal state conceptually named:

`CancelledAfterArmBeforeEffect`

Allowed transition:

```text
EffectArmed
   -> CancelledAfterArmBeforeEffect
```

This terminal state is valid only when the runtime can positively prove the adapter's external-effect boundary was not crossed.

If that proof is unavailable after a crash or ambiguous failure, recovery MUST use `OutcomeUnknown` instead.

The state should carry a non-zero outcome/recovery evidence digest committing the reason and proof boundary.

### 10. Cancellation before arm remains distinct

The lifecycle becomes:

```text
OperationAdmissionV1
    |
    +--> CancelledBeforeEffect
    |
    v
fresh EffectArmAuthorizationV1
    |
    v
EffectArmed
    |
    +--> CancelledAfterArmBeforeEffect
    +--> Completed
    +--> FailedKnown
    +--> OutcomeUnknown
```

The distinction matters for recovery:

- `CancelledBeforeEffect`: effect was never armed;
- `CancelledAfterArmBeforeEffect`: effect was armed but Xenia positively knows invocation never began;
- `OutcomeUnknown`: effect was armed and Xenia cannot prove whether invocation/effect occurred.

### 11. Authority loss after effect invocation is cancellation, not history erasure

Once the adapter has crossed its defined external-effect boundary, subsequent revocation cannot make the effect "not have happened."

For managed effects such as native processes, tunnels, or sessions, revocation should trigger the adapter's bounded cancellation/teardown path.

The eventual receipt then records the known outcome honestly:

- `Completed` if the defined success condition was already reached;
- `FailedKnown` when termination/cancellation outcome is known and separately evidenced;
- `OutcomeUnknown` if the post-revocation outcome cannot be proven.

A later revocation never rewrites the original `EffectArmed` event.

### 12. First native-exec policy

The initial one-shot native-exec runtime should use the strongest simple semantics available:

- fresh arm authorization immediately before `EffectArmed`;
- a very short authorization lifetime;
- no queued/background start after arm;
- current daemon user only;
- no shell;
- no stdin;
- no PTY;
- no elevation;
- no forwarding;
- process-tree cancellation on revocation/session teardown;
- `NonReplayable` external-effect semantics;
- `CancelledAfterArmBeforeEffect` only when process creation definitely never started;
- otherwise `OutcomeUnknown` on crash ambiguity.

High-assurance deployments may additionally require external frontier anchoring before spawn.

## Security consequences

### Positive

- A queued admission cannot silently become a stale privileged effect hours later.
- Revocation between admission and effect arming fails closed.
- External-anchor latency cannot bypass current authority checks.
- Durable `EffectArmed` evidence becomes cryptographically attributable to an exact live policy/consent/posture decision.
- The receipt model distinguishes positive no-effect cancellation from genuine uncertainty.
- Restore-safe mode can externally remember that an effect was armed before the effect happens.

### Costs

- Every privileged effect requires another live authority evaluation.
- High-assurance external anchoring increases latency.
- Receipt V1 needs one more pre-freeze schema/state amendment.
- Admitted-but-cancelled operations still consume use budget.

## Non-goals

ADR-008 does not:

- define cross-subject delegation;
- create unattended permanent authority;
- guarantee revocation can undo an already completed external effect;
- define long-lived continuation leases for tunnels/PTY sessions;
- implement the receipt-store database;
- implement an external anchor backend;
- spawn a process.

## Claim boundary

A durable admission proves that one grant-use slot was consumed for one exact operation.

Only a fresh, live, short-lived effect-arm authorization plus all deployment-required durable gates may justify beginning the external effect.
