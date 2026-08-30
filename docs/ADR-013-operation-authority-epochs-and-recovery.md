# ADR-013: Operation authority epochs, recovery, and grant invalidation

Status: Draft

## Context

Xenia's privileged-operation stack now has finite session-bound grants, durable admission/use-slot reservation, fail-stop recovery state, receipt-store generations, and anti-rollback frontiers.

A remaining recovery hazard is subtle but serious:

```text
old grant is still inside its session/time window
        +
store is rolled to a new generation or replaced
        +
new store no longer contains old grant-use reservations
        =
potential authority reuse
```

A store `generation` by itself is not enough unless the operation authorization objects are also bound to that generation/authority epoch.

The `authorization_epoch` already present in the draft effect-arm contract is a reevaluation-authority counter. It is not currently a cryptographic binding shared by capability grants, admissions, and receipt-store recovery, so it does not solve this problem.

## Decision

Introduce a monotonic `OperationAuthorityEpochV1` above the receipt-store generation.

The current authority epoch is part of the live admission/effect authorization context. A grant issued under an older epoch is invalid for new admissions immediately after the epoch advances.

### 1. Epoch record

An authority epoch commits:

```text
authority_domain_id
epoch_id
epoch_sequence
previous_epoch_digest
store_id
store_generation
transition reason/evidence
established_at
```

The standalone reference contract lives at `contracts/xenia-operation-authority-epoch` while semantics are reviewed independently of the production workspace.

### 2. Supported V1 transitions

#### Genesis

```text
epoch sequence = 0
previous digest = zero
store generation = configured initial generation
```

#### Recovery generation rollover

Same receipt store identity, exact next store generation:

```text
store_id          unchanged
store_generation  old + 1
epoch_sequence    old + 1
recovery decision committed
```

#### Store replacement

A governed recovery may replace an unusable/corrupt store entirely:

```text
store_id          new non-zero identity
store_generation  0
epoch_sequence    old + 1
recovery decision committed
```

The old store is never silently treated as the new store.

#### Global revocation

Emergency/policy action may invalidate every outstanding operation grant without changing persisted receipt state:

```text
store_id          unchanged
store_generation  unchanged
epoch_sequence    old + 1
revocation decision committed
```

This gives Xenia a clean local kill-switch for all privileged-operation leases without inventing a fake store recovery event.

### 3. Pre-freeze grant amendment

Before `CapabilityGrantV1` is frozen, it must bind the exact current operation-authority epoch, preferably through an explicit compact field such as:

```text
authority_domain_id
authority_epoch_digest
```

A grant may only be exercised when that binding matches the live current epoch.

This validation is in addition to session, subject, time, policy, approval, purpose, scope, and use-budget checks.

### 4. Admission amendment

`OperationAdmissionV1` must commit the same exact authority-epoch binding.

Atomic admission therefore verifies, in one logical authority decision:

```text
grant epoch == current authority epoch
admission epoch == grant epoch
store metadata current epoch == admission epoch
operation id unused
grant/use slot unused
sequence exact next
```

An epoch mismatch is a policy/authority refusal, not a recoverable duplicate.

### 5. Receipt-store metadata amendment

The persistent store metadata must include the exact current authority epoch commitment, or a binding that can be proven against the externally governed epoch record.

The metadata cannot simply be edited from epoch A to epoch B as an ordinary SQLite migration. Epoch transition is itself a governed evidence event.

### 6. Effect-arm amendment

The fresh effect-arm authorization and final live gate must also bind/recheck the exact current authority epoch.

The existing numeric `authorization_epoch` remains a separate monotonic reevaluation-authority field unless deliberately renamed in a future schema. It must not be treated as interchangeable with `authority_epoch_digest`.

If the operation-authority epoch advances after admission but before effect invocation:

```text
fresh arm/final gate => deny
```

The consumed grant use is not refunded.

If the epoch advances after adapter invocation began, the runtime follows adapter-specific bounded cancellation/teardown semantics and records the actual/uncertain outcome; history is not rewritten.

### 7. Same-epoch recovery is narrow

A store that enters `RecoveryRequired` may resume the **same** authority epoch only if governed recovery proves that the authority state was not rolled back or replaced.

At minimum this requires the applicable combination of:

- SQLite structural integrity;
- filesystem authority-root integrity;
- immutable admission/use-slot integrity;
- receipt-chain integrity once receipts exist;
- anti-rollback frontier/anchor verification;
- store id/generation equality;
- current authority-epoch equality.

A stale-marker event alone does not force a new epoch if the complete state is proven intact.

### 8. New generation means old grants die

Any governed operation that advances receipt-store generation must advance the operation-authority epoch in the same recovery ceremony.

There is no V1 transition:

```text
new store generation + old authority epoch
```

Likewise, store replacement always creates a new authority epoch.

All outstanding pre-transition grants become unusable for new admissions, even if:

- their Xenia session is still connected;
- they have remaining use budget;
- their expiry has not been reached;
- their policy/approval digests still match old state.

Fresh privileged authority must be issued under the new epoch.

### 9. Epoch history and external evidence

Epoch records form an append-only digest chain. High-assurance deployments should authenticate the current epoch outside the rollback scope of the receipt store, potentially alongside operation-store frontier anchors.

An old local database must not be able to declare itself authoritative merely by storing an older epoch record internally.

### 10. Attenuation cannot cross epochs

A child/attenuated grant inherits the exact same authority-epoch binding as its parent.

Attenuation may reduce scope, lifetime, and remaining-use authority. It may not update a stale grant into a new epoch.

After an epoch transition, authority must be reissued from a current upstream approval/consent decision rather than transformed from an old grant.

## Recovery dispositions

A future recovery API should expose explicit dispositions rather than a boolean `clear_recovery`:

```text
Quarantine
ResumeSameEpoch
AdvanceStoreGenerationAndEpoch
ReplaceStoreAndAdvanceEpoch
```

`ResumeSameEpoch` requires full proof that no security-relevant durable state was lost or rolled back.

The two advancing dispositions require committed recovery evidence and invalidate all old grants.

## Required pre-freeze amendments

Before privileged-operation V1 is treated as stable:

1. `CapabilityGrantV1` — add authority-epoch binding;
2. `CapabilityUseV1` — ensure use commitment transitively/exactly binds the grant epoch;
3. `OperationAdmissionV1` — add authority-epoch binding;
4. receipt-store metadata — add current authority-epoch binding;
5. `EffectArmAuthorizationV1` — add current authority-epoch digest distinct from its reevaluation counter;
6. final live gate — compare current epoch;
7. attenuation — require identical epoch binding;
8. recovery/new-generation flow — make epoch transition atomic/governed at the logical security boundary;
9. external evidence — retain/authenticate current epoch outside the store rollback scope for high-assurance claims.

## Non-goals

ADR-013 does not:

- define organization-wide IAM epochs;
- replace session revocation or consent revocation;
- make grants bearer credentials;
- define a distributed consensus service;
- make rollback safe without external evidence;
- authorize automatic recovery;
- refund consumed uses after cancellation;
- enable native exec.

## Security result

The intended invariant is:

> A privileged-operation grant is authority for one exact Xenia session, one subject, one finite scope, and one exact current operation-authority epoch. Recovery can preserve that epoch only by proving durable continuity; any recovery that creates a new authority world invalidates every old grant by construction.
