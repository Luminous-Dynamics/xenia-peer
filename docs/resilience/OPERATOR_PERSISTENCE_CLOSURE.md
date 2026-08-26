# Xenia Compromised-Operator Persistence Closure v1

**Status:** Companion design contract to the qualified-target `xenia-resilience-evidence` schema v3. This document does not change the current v3 baseline evaluator.

## Purpose

Revoking a compromised operator proves only that the original authority is contained.

A capable attacker may use valid pre-revocation authority to create durable persistence before defenders notice, for example by:

- replacing or adding trusted operator keys;
- changing operator/revocation state;
- creating or altering consent/authorization state;
- minting still-valid delegated/bearer authority;
- changing trust relationships or enrolled peers;
- creating another identity through a path attributable to the compromised operator.

The stronger containment question is therefore:

> After the original operator is revoked, what authority derived from actions attributable to that compromised operator can still act?

## Separation from schema v3

The existing v3 operator-containment evaluator should first qualify unchanged.

It proves post-revocation refusal across baseline authority surfaces for the original operator.

Persistence closure is a later layer around that result. Do not expand the v3 crate until its focused format/test/clippy/MSRV lane is green.

## Compromise window

The exercise freezes:

```text
compromise_window_started_at
revocation_effective_at
post_containment_observation_ended_at
```

The compromise window begins when the synthetic exercise declares the operator credential/control context compromised, not when defenders first detect it.

This prevents activity performed before detection from being excluded merely because it happened before the revocation request.

## Audit-derived action set

Xenia's authoritative audit/consent/authorization surfaces remain the source of truth for actions performed by the test operator.

The exercise derives a set of security-relevant actions attributable to the compromised operator during the compromise window.

Conceptually:

```text
CompromisedOperatorAction
  action_id
  operator_id
  action_class
  target_id
  observed_at
  outcome
  source_revision
  evidence_ref
```

The persistence evaluator does not infer actions from filenames or human notes when authoritative ledger evidence exists.

## Persistence-relevant action classes

At minimum the design should classify actions equivalent to:

### KEY_OR_TRUST_REPLACEMENT

Changes an enrolled/trusted key or trust-root-adjacent operator key material.

### OPERATOR_ENROLLMENT_OR_ROLE_CHANGE

Creates a new operator or changes another principal's privileged role/scope.

### OPERATOR_REVOCATION_OR_LOCKOUT

Revokes/disables a legitimate operator in a way that may impede response/recovery.

### CONSENT_OR_AUTHORIZATION_MUTATION

Creates or changes durable consent/authorization state that could continue to authorize sensitive actions.

### DELEGATED_CREDENTIAL_CREATION

Creates a token/session/delegation/credential whose validity may outlive the original operator's revocation.

### SEALED_TRUST_MUTATION

Changes persistent peer/channel trust state that could permit later sealed-channel establishment through another identity.

### OTHER_AUTHORITY_CREATING_ACTION

Versioned extension point. Unknown state-changing action classes remain visible and cannot silently be assumed non-persistent.

## Derived authority graph

Persistence is modeled as a graph rather than a flat token list.

```text
compromised operator A
    |
    +-- key replacement ------> trusted key K2
    |
    +-- role/enrollment ------> operator B
    |
    +-- delegation -----------> credential C
    |
    +-- consent mutation -----> authorization D
```

Each edge carries source evidence.

A derived node is not assumed dangerous merely because it exists; the exercise must establish whether it grants continuing authority after A is revoked.

## Derived authority identity

Derived authority references must be opaque/non-secret and contain enough information to prevent substitution:

```text
derived_authority_id
origin_action_id
origin_operator_id
exercise_id
authority_class
issued_or_effective_at
valid_until_if_applicable
source_revision
evidence_locator
evidence_digest
```

Bearer tokens, private keys, seeds, passwords, or reusable secret bytes are never serialized into resilience evidence.

## Post-revocation closure tests

For every derived authority that could materially persist, the exercise must establish one of:

```text
REVOKED_OR_INVALIDATED
EXPIRED_BEFORE_CONTAINMENT_TEST
NEVER_BECAME_ACTIVE
EXPLICITLY_RETAINED_BY_POLICY
STILL_ACTIVE
UNPROVEN
```

`EXPIRED_BEFORE_CONTAINMENT_TEST` does not prove revocation cleanup; it only establishes that the artifact no longer confers live authority.

`EXPLICITLY_RETAINED_BY_POLICY` requires a governance/evidence record and remains visible as accepted residual authority.

`STILL_ACTIVE` is a material persistence finding when the authority is not intentionally retained.

## Live behavioral verification

Where a derived authority can safely be exercised in the disposable test environment, closure should use the same discipline as schema v3:

- authority existed before the containment checkpoint;
- authority would otherwise still be valid;
- post-containment attempt targets a meaningful protected surface;
- authoritative Xenia boundary returns the decision;
- evidence is claim/run/authority/time bound.

A derived credential that is already expired when tested cannot prove active cleanup.

## Key replacement persistence

Key replacement is particularly important because changing an operator key can outlive revocation of the credential/key originally compromised.

The exercise should distinguish:

```text
operator A revoked
    AND
old key refused
```

from the stronger:

```text
operator A revoked
    AND
all unauthorized replacement/trust mutations attributable to A
    are rolled back, revoked, or explicitly accepted
```

If A successfully replaced a trusted key with attacker-controlled K2 before revocation and K2 remains accepted afterward, revoking A's old key is not complete containment.

## Operator lockout resilience

The compromised operator may also try to revoke legitimate operators.

Persistence closure should therefore detect when pre-revocation actions can leave defenders without an independent administrative path.

A campaign should eventually prove at least one independently protected operator/recovery authority remains usable after the test compromise, rather than only proving the attacker was rejected.

## Consent/authorization persistence

Durable consent or authorization changes attributable to the compromised operator should be enumerated and evaluated after revocation.

The key question is whether revoking the operator automatically removes, leaves, or requires explicit cleanup of authorization state created while the operator was valid.

The evidence must preserve whichever semantic Xenia actually implements; the resilience layer must not invent revocation propagation behavior.

## Token/session persistence

If Xenia supports credentials whose validity is independent of the originating operator's current revocation state, those credentials become explicit derived-authority nodes.

If Xenia already checks live revocation on every protected boundary, the exercise can positively establish that retained credentials are neutralized by those boundary checks.

This is exactly why schema v3 tests retained live bearer authority rather than relying on token expiry.

## Derived authority discovery completeness

The exercise cannot claim closure merely because it tested one known persistence artifact.

It needs an evidence-bearing discovery/enumeration statement describing:

- which action/ledger surfaces were searched;
- time window;
- source revision;
- classes recognized;
- unsupported/unknown action types;
- discovered derived-authority nodes.

Unknown action classes remain limitations.

## No audit-ledger self-proof

The ledger proves that an action record exists and is attributable according to Xenia's ledger semantics.

It does not by itself prove that the resulting authority is inactive.

Closure requires both:

```text
origin/action evidence
    +
post-containment authority-state or behavioral evidence
```

## Closure outcome

A conservative future evaluator can use:

### VERIFIED

When:

- schema-v3 containment of the original operator is verified;
- persistence-relevant action discovery is complete for the declared surfaces/window;
- every non-excluded derived authority is proven inactive/invalidated or never active;
- at least one intended independent administrative/recovery path remains usable where required by the scenario.

### FAILED

When foundational applicability is proven and at least one non-excluded derived authority remains positively evidenced as active after containment, or compromised-operator actions positively establish unacceptable defender lockout.

### UNPROVEN

For incomplete discovery, unknown action class, missing origin evidence, stale/foreign evidence, untested still-valid derived authority, or ambiguous cleanup state.

## R8 integration

R8 should freeze:

- compromised operator id;
- compromise start;
- revocation checkpoint;
- expected Xenia revision;
- persistence-discovery policy revision.

The append-only R8 evidence ledger preserves both the original malicious test actions and subsequent cleanup/closure evidence.

A cleanup success must never erase the fact that durable persistence was successfully created before containment.

## Campaign integration

The campaign should distinguish:

```text
ORIGINAL_OPERATOR_REVOCATION_CONTAINMENT
DERIVED_AUTHORITY_PERSISTENCE_CLOSURE
INDEPENDENT_DEFENDER_AUTHORITY_SURVIVAL
```

A campaign may qualify the first while the second remains failed/unproven. That distinction is preferable to a broad statement that “identity containment passed.”

## Initial implementation tests

Before persistence closure can become a qualifying result, tests should establish:

1. a replacement key created by the compromised operator is discovered as derived authority;
2. revoking only the original operator cannot produce `VERIFIED` while an unauthorized replacement authority remains active;
3. a derived credential that merely expired is distinguished from explicit cleanup;
4. pre-revocation malicious actions remain in evidence after successful cleanup;
5. consent/authorization mutations are not inferred to disappear unless Xenia evidence proves that behavior;
6. operator-revocation actions that lock out defenders remain visible as a material finding;
7. unknown persistence-relevant action classes force `UNPROVEN` rather than being ignored;
8. audit evidence cannot substitute for post-containment behavioral/state evidence;
9. raw bearer/key material never appears in the evidence bundle;
10. schema-v3 original-operator containment remains independently evaluable.

## Exit gate

Persistence closure v1 exits when one disposable Xenia operator can:

1. act during a declared compromise window;
2. attempt/create representative persistence using real existing Xenia state-changing surfaces;
3. be revoked;
4. be refused by the existing schema-v3 boundary tests;
5. have all derived authority discovered from authoritative Xenia evidence;
6. prove each unauthorized derived authority inactive or expose it as `FAILED`;
7. preserve an independent legitimate recovery/admin path;
8. produce a claim-bound evidence set consumable by R8 without exposing reusable secrets.
