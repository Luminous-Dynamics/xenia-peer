# ADR-026: Authenticated global operation-authority revocation

Status: draft candidate

## Context

`OperationAuthorityEpochV1` already defines `AuthorityEpochReasonV1::GlobalRevocation`: a successor epoch that preserves the operation-store id/generation while making every older epoch-bound grant/use/admission/arm object stale.

ADR-025 intentionally rejects that transition because its governed-discontinuity profile is limited to ledger-key rotation and store recovery/replacement. A same-store epoch change must not become valid merely because the epoch sequence increased.

Global revocation is also semantically different from recovery. It is an emergency/policy action that invalidates outstanding authority while keeping the durable store lineage intact.

## Decision

Introduce a dedicated V1 global-revocation profile with two phases:

```text
APPLICATION TIME

GlobalRevocationIntentV1
        |
        v
external policy/emergency approval
        |
        v
GlobalRevocationDecisionV1
        |
        + exact previous authority epoch
        + ordinary retained witness successor
        + same ledger key
        + same store id/generation
        |
        v
candidate GlobalRevocation epoch
        |
        v
VerifiedGlobalRevocationTransitionV1
        |
 ledger-key signed receipt
        v
GlobalRevocationTransitionReceiptV1


HISTORICAL RECOVERY

retained signed receipt
        +
external approval re-authentication
        +
previous/candidate retained authority states
        +
ledger/frontier lineage
        |
        v
historically verified revocation
```

No recovery plan is used for this transition.

## Intent versus approval

The approval-independent `GlobalRevocationIntentV1` commits:

- unique decision id;
- authority domain;
- exact previous authority-epoch digest;
- global V1 scope;
- revocation-policy digest;
- privacy-preserving rationale/evidence digest;
- application window.

Its `intent_digest` is the exact object the external emergency/policy authority approves.

`GlobalRevocationDecisionV1` then contains:

```text
exact intent
+
approval_digest
```

The external approval verifier receives both the exact `intent_digest` and `approval_digest`. A callback that authenticates only the approval bytes but not the intent violates this contract.

This separation avoids circular hashing and makes it explicit what human/organizational authority approved.

## Scope

V1 has one scope only:

`AllOutstandingPrivilegedOperationAuthority`.

A global revocation changes the entire operation-authority epoch. V1 does not pretend to provide selective session/grant revocation through this mechanism; selective revocation remains a different policy/protocol concern.

## Short application window

A prepared decision may be applied for at most 15 minutes.

The live application verifier requires:

```text
authorized_at <= now < expires_at
```

This prevents a long-lived pre-authorized kill-switch artifact from being silently exercised much later.

Once the successor epoch is established, the revocation itself is permanent for that lineage: old authority remains stale because it commits the previous epoch digest.

## Ordinary anti-rollback succession is preserved

Global revocation is not a store/key discontinuity. Therefore the verifier deliberately reuses ordinary ADR-022/023 retained-bundle successor verification.

The previous/candidate retained witnesses must still prove:

- same operation-store id;
- same store generation;
- same ledger key;
- exact witness sequence + 1;
- exact previous-witness digest;
- non-regressing frontier/checkpoint lineage;
- exact real signed ledger/checkpoint ancestry;
- exact local frontier ancestry.

A global revocation cannot be used as a disguised key rotation or store replacement.

## Authority-epoch transition

The candidate epoch must pass:

```text
candidate.validate_successor(previous)
```

and its reason must be exactly:

```text
GlobalRevocation {
    revocation_decision_digest:
        digest(exact approved GlobalRevocationDecisionV1)
}
```

The candidate epoch must be established inside the decision's application window and may not exceed the deployment's accepted future clock skew.

Thus the approval is bound to the exact previous authority epoch and the candidate epoch is bound to the exact approved decision.

## Live application verification versus historical verification

The short decision lifetime is an **application-time** safety invariant.

Requiring the decision to remain live during later disaster recovery would make valid historical revocations unverifiable minutes after they occurred. V1 therefore separates the two paths.

### Live path

`verify_global_revocation_transition_v1(...)`:

1. requires the decision to be live now;
2. authenticates the exact intent/approval pair;
3. verifies ordinary retained witness succession;
4. verifies exact authority-epoch succession and decision binding;
5. returns non-serializable `VerifiedGlobalRevocationTransitionV1`.

### Historical path

`GlobalRevocationTransitionReceiptV1::sign_after_verification(...)` can be called only with that verified token and the exact candidate ledger signing key.

The receipt commits:

- complete approved decision;
- previous retained-state digest;
- candidate retained-state digest;
- candidate epoch digest;
- candidate witness digest;
- live-verification time;
- ledger public key;
- Ed25519 signature.

`verify_retained_global_revocation_transition_v1(...)` later:

- verifies receipt signature/local window statement;
- re-authenticates the exact intent/approval pair;
- re-verifies the previous/candidate retained states and complete ordinary witness lineage;
- re-verifies authority-epoch succession and exact decision digest;
- requires receipt commitments to equal the independently recomputed state/epoch/witness commitments;
- does **not** require the original short-lived decision to still be live now.

Historical checkpoint maximum age is disabled for this historical transition proof, while future-skew checks remain. Current/latest retention freshness remains a separate deployment gate.

## Clock / non-repudiation boundary

V1 uses Xenia's existing trusted-enough wall-clock model. The live application path enforces the decision window using the current runtime clock.

The signed historical receipt proves the ledger authority attested that the live verifier succeeded at the recorded time. External append-only retention makes replacement/reordering detectable.

V1 does **not** claim an independent Byzantine/trusted timestamp against a later compromise of every local signing/time source. A future remote witness, trusted timestamp authority, TPM monotonic counter, or provider-authenticated immutable-object creation time can strengthen this claim under a new profile.

Do not describe the V1 receipt as a universal cryptographic proof of wall-clock time.

## Receipt signing key

The receipt is signed by the exact ledger key verified for the candidate retained state. A different key cannot create the receipt through the V1 API.

This does not replace external policy approval: the ledger signature proves the Xenia authority recorded the successful live transition; the separately authenticated approval proves the emergency/policy authority approved the exact intent.

## External retention

A historical receipt only contributes to rollback resistance when retained outside the protected rollback domain, alongside the retained authority-state/witness lineage.

A subsequent tranche should extend the ADR-023/024 retention object/model so transition receipts are immutable append-only members of the same external evidence history rather than loose local files.

Until that integration is qualified, ADR-026 is a transition/evidence contract, not a complete independently retained deployment profile.

## Recovery semantics

Successful global-revocation verification does not:

- clear `RecoveryRequired`;
- mutate the operation store;
- create/apply an epoch by itself;
- resurrect or transform old grants;
- authorize a privileged external effect;
- replace ADR-014 recovery for actual store damage.

The practical effect of a successfully established successor epoch is that all authority objects bound to the predecessor epoch fail their current-epoch checks.

## Qualification gates

Before ADR-026 may contribute to privileged-operation recovery/security claims:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV passes;
3. approval authentication binds exact `intent_digest` + `approval_digest`;
4. live application rejects expired/not-yet-live decisions;
5. decision must bind the exact previous authority epoch;
6. ordinary retained witness succession must remain valid;
7. ledger key must remain unchanged;
8. store id/generation must remain unchanged;
9. candidate epoch must be the exact authority successor;
10. candidate reason must be `GlobalRevocation` with exact complete decision digest;
11. candidate epoch establishment must fall inside the decision window;
12. receipt cannot be signed with a different ledger key;
13. receipt tampering fails signature verification;
14. historical verification succeeds after decision expiry without weakening lineage/approval checks;
15. receipt/state/epoch/witness commitment mismatch fails;
16. receipt is independently retained before rollback-resistant historical recovery is claimed;
17. no V1 claim is made for independent trusted wall-clock timestamping.
