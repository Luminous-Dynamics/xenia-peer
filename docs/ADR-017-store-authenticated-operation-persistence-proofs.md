# ADR-017: Store-authenticated operation persistence proofs

Status: draft candidate

## Context

Authority V2 distinguishes semantic authority from recovery-safe epoch binding, but a further boundary remains: computing an admission or arm digest in memory does not prove that the trusted operation store durably committed the corresponding write-ahead state.

Native exec and other privileged adapters must never cross an effect boundary based solely on caller-provided serialized admission/arm objects.

## Decision

Introduce two store-authenticated persistence proofs.

### `AdmissionPersistenceProofV2`

Issued only after the trusted store has durably and atomically committed the exact operation admission/use-slot reservation. It commits:

- exact `AdmissionAuthorityV2` digest;
- exact `StoreAuthorityV2` digest;
- admission sequence;
- exact use-slot reservation commitment;
- exact committed store frontier/checkpoint;
- current authority epoch;
- persistence backend identity/configuration;
- named durability profile;
- exact backend commit/evidence commitment;
- persistence timestamp.

### `EffectArmedPersistenceProofV2`

Issued only after the trusted store has durably appended the exact write-ahead `EffectArmed` receipt. It commits:

- exact `EffectArmAuthorityV2` digest;
- exact admission persistence proof digest;
- exact durable `EffectArmed` receipt-event digest;
- exact current store authority;
- exact frontier/checkpoint containing the arm event;
- current authority epoch;
- backend/profile/commit evidence;
- persistence timestamp.

## Serialized proofs are not self-authenticating

Both proof types require an `AuthenticatedPersistenceContextV2` supplied by the trusted persistence path. A caller cannot make a fabricated proof authoritative merely by choosing plausible non-zero digests.

The authenticated context commits:

- backend authority identity/configuration;
- persistence/durability profile;
- exact commit evidence for that mutation.

A future concrete SQLite implementation must derive these values from the store/runtime evidence boundary and must not accept them from remote operation input.

## Final effect gating

Before external effect invocation, the runtime must establish all of the following:

1. semantic arm authorization remains live under its original contract;
2. `EffectArmAuthorityV2` validates against exact admission/store authority and current epoch;
3. `AdmissionPersistenceProofV2` validates against the exact persisted admission and authenticated admission-commit context;
4. `EffectArmedPersistenceProofV2` validates against the exact arm/admission proof/store/current epoch and authenticated arm-commit context;
5. applicable anti-rollback/external-anchor evidence remains valid;
6. the invocation linearization fence defined by the next runtime tranche is acquired before the adapter crosses the effect boundary.

## Frontier requirement

V2 persistence proofs require a non-zero committed frontier/checkpoint digest. The current experimental SQLite admission-only backend does not yet persist frontier state, so it cannot issue these proofs yet.

This is intentional: proof issuance must follow durable receipt/frontier integration rather than inventing a placeholder frontier value.

## Failure semantics

An unexpected persistence error does not produce a negative proof that a mutation did not occur. The store enters durability-uncertain/recovery-required behavior according to ADR-007/ADR-014.

A missing or unauthenticated persistence proof fails closed.

## Non-goals

This ADR does not provide:

- a digital signature format for local store proofs;
- generic proof portability between machines;
- exactly-once external effects;
- automatic recovery;
- an invocation/revocation synchronization primitive;
- process execution, PTY, forwarding, credential use, or device control.
