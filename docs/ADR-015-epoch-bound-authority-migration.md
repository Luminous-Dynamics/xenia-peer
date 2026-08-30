# ADR-015: Epoch-bound privileged-operation authority migration

Status: draft

## Context

The first privileged-operation grant/use, admission/receipt, and effect-arm contracts were developed in ordered draft tranches before ADR-013 introduced a monotonic operation-authority epoch. Mutating every earlier serialized draft record in place would create a large, hard-to-review compatibility delta while the workspace qualification queue is already backlogged.

At the same time, recovery-capable operation stores cannot safely admit raw pre-epoch grant/use commitments: a store generation rollover, replacement, or global revocation must make all prior authority stale even when a grant's session/time/use budget would otherwise remain live.

## Decision

Introduce an explicit epoch-bound authority migration layer rather than silently changing earlier raw record bytes.

The chain is:

```text
validated raw CapabilityGrantV1 digest
        |
        v
EpochBoundGrantV1
  + exact AuthorityEpochBindingV1
        |
validated raw CapabilityUseV1 digest
        |
        v
EpochBoundUseV1
        |
validated raw OperationAdmissionV1 digest
        |
        v
EpochBoundAdmissionV1
        |
validated raw EffectArmAuthorizationV1 digest
        |
        v
EpochBoundArmV1
```

Persistent operation-store metadata additionally records `StoreAuthorityBindingV1`, binding the exact receipt-store id/generation to the exact current authority epoch.

## Raw records remain evidence, not sufficient authority

The migration does not invalidate the semantic work in the earlier contracts. Their exact commitments remain the inputs to the wrappers and remain useful audit/evidence identifiers.

However, once a deployment enables governed recovery/authority epochs, these raw commitments are insufficient on their own for:

- durable privileged-operation admission;
- fresh effect arming;
- recovery continuation;
- final live effect invocation.

The runtime must validate the raw predecessor under its original protocol **and** validate the epoch-bound wrapper chain against the current authority epoch.

## Security properties

### Global revocation

Advancing the authority epoch with `GlobalRevocation` makes every old bound grant/use/admission/arm fail current-epoch validation even though the receipt-store id/generation is unchanged.

### Recovery generation rollover

When the store advances generation, the new authority epoch commits the new generation. Old `StoreAuthorityBindingV1` and all old operation authority wrappers become stale.

### Store replacement

A replacement begins with a new store id and generation zero under a new authority epoch. Old operation authority cannot become usable merely because the replacement database has empty use counters.

### Attenuation

An attenuated raw grant may only receive an epoch envelope for the same current authority epoch as its parent. Epoch migration is never implemented as attenuation; after an epoch change, fresh upstream authority is required.

### Final live gate

The final effect gate must validate the `EpochBoundArmV1` and persistent `StoreAuthorityBindingV1` against the same current `OperationAuthorityEpochV1` after any external-anchor latency and immediately before adapter invocation.

## Compatibility strategy

V1 migration wrappers are intentionally explicit. A future consolidated `CapabilityGrantV2` / admission V2 / arm V2 may embed the epoch binding directly after qualification evidence shows the migration semantics are stable.

Until then, production code should avoid silently deserializing a raw V1 record into an epoch-aware shape with default/optional fields. Missing epoch binding must fail closed in recovery-capable mode.

## Persistence requirements

A recovery-capable store must persist enough information to prove:

- the current authority epoch commitment;
- exact store id/generation;
- the epoch-bound grant/use commitment admitted for each operation;
- the epoch-bound admission commitment used by effect arm;
- the epoch-bound arm commitment used by the final live gate.

The current experimental SQLite backend has not yet added these columns/records and therefore remains admission-only and non-effect-bearing.

## Claim boundary

These wrappers do not validate the underlying raw contracts by themselves. Callers must first validate the raw grant/use/admission/arm record under the protocol that produced its digest. The wrappers add authority-epoch continuity/invalidation; they do not replace session, subject, consent, scope, replay, receipt, or effect-arm semantics.

## Promotion gate

Before native exec is enabled, qualification must prove the complete sequence:

1. raw grant validates;
2. epoch-bound grant matches current epoch;
3. raw use validates against raw grant/live session;
4. epoch-bound use matches bound grant/current epoch;
5. durable admission atomically reserves the use and commits the epoch-bound use;
6. epoch-bound admission matches current epoch;
7. fresh arm authorization validates;
8. epoch-bound arm matches bound admission/current epoch;
9. persistent store-authority binding matches current store/epoch;
10. final live gate repeats current epoch validation immediately before effect.
