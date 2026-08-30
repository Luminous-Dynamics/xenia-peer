# ADR-016: Consolidated privileged-operation authority V2

Status: draft candidate

## Context

ADR-013 introduced operation-authority epochs. ADR-015 introduced explicit epoch-bound wrappers as a low-risk migration path for the earlier draft V1 grant/use/admission/arm commitments.

A review of that migration exposed an additional rule: wrapping an old raw grant digest in the current epoch is **not itself grant issuance**. Global revocation would be meaningless if arbitrary code could simply create a new wrapper around a still-live raw grant.

## Decision

Define a consolidated authority V2 candidate that treats authenticated issuance as a first-class input and chains every later authority stage by digest.

V2 remains a thin authority layer over the exact semantic commitments produced by the earlier contracts:

```text
validated raw grant digest
 + current authority epoch
 + authenticated issuer identity
 + authenticated issuance evidence
        |
        v
GrantAuthorityV2
        |
validated raw use digest
        v
UseAuthorityV2
        |
durable semantic admission digest
        v
AdmissionAuthorityV2
        |
exact StoreAuthorityV2
 + fresh raw arm authorization digest
        v
EffectArmAuthorityV2
        |
final live epoch/store gate
```

## Authenticated issuance

`GrantAuthorityV2` contains:

- raw semantic grant digest;
- exact `AuthorityEpochBindingV1`;
- issuer-authority commitment;
- issuance-evidence commitment;
- issuance evidence timestamp.

Validation requires an `AuthenticatedIssuanceContextV2` obtained from a configured trusted issuance path. The serialized V2 grant-authority bytes do not authenticate themselves.

Examples of suitable upstream authentication domains include a signed operator/consent transcript, a durable authority ledger, or another explicitly configured issuer proof. The V2 contract deliberately does not choose one cryptographic transport.

### Reissue after revocation

A global authority-epoch advance makes all prior V2 authority records stale. Reusing the same underlying raw grant digest in the new epoch requires **fresh authenticated issuance evidence**. This is a new authorization event and produces a different V2 grant-authority digest.

A runtime MUST NOT create a new V2 grant authority merely because it possesses old raw grant bytes.

## Store authority

`StoreAuthorityV2` binds the exact receipt-store identity/generation to the exact authority epoch. Effect arming and final invocation require this binding to remain current.

A generation rollover, replacement, or global revocation therefore invalidates old store authority and old operation authority together.

## Final live gate

`EffectArmAuthorityV2::validate_final_gate` repeats current store/epoch checks immediately before an adapter may cross the external-effect boundary. This is in addition to the fresh semantic arm authorization and any deployment-required external frontier anchor.

## Durable-admission proof remains separate

`AdmissionAuthorityV2` commits an existing semantic admission digest, but computing such a digest is not by itself proof that the store durably committed it.

Before effect arming is enabled, a separate store-issued admission persistence proof must bind:

- exact `AdmissionAuthorityV2` digest;
- exact `StoreAuthorityV2` digest;
- committed admission sequence/use-slot evidence;
- a durable store frontier/checkpoint as applicable.

The effect-arm authority should consume that proof rather than trusting an arbitrary in-memory admission object.

## Compatibility

V2 does not require rewriting historical V1 bytes. The exact V1 commitments remain evidence inputs. A future semantic-protocol V2 may inline the same fields after this authority shape is qualified.

## Non-goals

This ADR does not claim:

- self-authenticating serialized authority objects;
- generic bearer-token semantics;
- exactly-once external effects;
- proof of durable admission without a store persistence receipt;
- automatic recovery;
- process execution, PTY, forwarding, credential use, or device control.

## Promotion gate

Before native exec is enabled, qualification must prove authenticated issuance, exact authority-epoch binding, atomic durable admission, store-issued persistence proof, fresh effect-arm authorization, anti-rollback policy, and the final live store/epoch gate as one end-to-end path.
