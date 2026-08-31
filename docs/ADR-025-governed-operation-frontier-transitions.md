# ADR-025: Governed transitions between retained operation-authority states

Status: draft candidate

## Context

ADR-022 deliberately makes ordinary operation-frontier witness succession fail closed when the ledger key changes or when the protected operation store changes identity/generation. ADR-023/024 then retain those witnesses outside the rollback domain using append-only durability semantics.

That strict default is correct, but Xenia also has legitimate discontinuities:

- a dual-signed ledger-key rotation;
- an ADR-014 same-store generation rollover after governed recovery;
- an ADR-014 store replacement after governed recovery;
- combinations where a recovery transition and ledger-key rotation occur in the same ceremony.

A larger key, generation, epoch sequence, or timestamp must never authenticate such a transition by itself.

Xenia already has the needed authority objects:

- `xenia-ledger::LedgerKeyTransition`, dual-signed by the previous and successor ledger keys and bound to the final previous checkpoint;
- `OperationStoreRecoveryAssessmentV1` and `OperationStoreRecoveryPlanV1` from ADR-014;
- `OperationStoreRecoveryPlanV1::validate_next_epoch(...)`, which binds the live recovery plan to the exact current and candidate `OperationAuthorityEpochV1`;
- `OperationAuthorityEpochV1`, whose successor rules distinguish recovery rollover, store replacement, and global revocation.

ADR-025 composes those objects rather than defining a second recovery/key-rotation protocol.

## Integration lineage

The first implementation branch is intentionally a two-lineage integration commit. It joins the retained-witness/retention-model lineage with the governed-recovery/authority-epoch lineage and imports the exact existing contract trees.

The integration must not reinterpret opaque recovery hashes when the original typed objects are available.

## Retained operation-authority state

Introduce `RetainedOperationAuthorityStateV1`:

```text
RetainedOperationFrontierWitnessBundleV1
              +
exact OperationAuthorityEpochV1
              |
              v
state-attestation message
              |
    Ed25519 signature by
 exact retained checkpoint key
              |
              v
RetainedOperationAuthorityStateV1
```

The authority epoch's `store_id` and `store_generation` must exactly equal the retained frontier anchor.

The retained witness must not predate establishment of the authority epoch it claims to represent.

The state signature commits the complete canonical retained bundle and complete canonical authority epoch. A newer witness therefore cannot be paired with an old epoch merely by storing both objects beside each other.

This signed state is still evidence, not permission to resume operations or clear `RecoveryRequired`.

## Ordinary versus governed succession

Ordinary ADR-022/023 succession remains the preferred path when key/store authority has not changed.

ADR-025 is only for an exceptional discontinuity. A transition with neither a ledger-key change nor a store identity/generation change is rejected as `NoGovernedDiscontinuity`.

Global revocation is deliberately not accepted by ADR-025 V1 merely because it advances the authority epoch while preserving the same store. It requires its own authenticated decision path.

## Global witness lineage remains continuous

Even across a governed discontinuity, the signed frontier-witness lineage must remain exact:

```text
candidate.witness_sequence == previous.witness_sequence + 1
candidate.previous_witness_digest == digest(previous signed witness)
```

Witness and external-retention timestamps may not regress.

The governed transition is an explicit bridge in one retained evidence lineage; it is not permission to begin an unrelated witness chain at sequence zero.

## Ledger-key rotation

If the retained checkpoint key changes, `LedgerKeyTransition` is mandatory.

Verification requires:

1. the previous retained state verifies under the independently retained previous ledger key;
2. the key-transition artifact is validly dual-signed;
3. its `previous_checkpoint` exactly equals the checkpoint retained in the previous authority state;
4. `Verifier::verify_ledger_key_successor(...)` proves the candidate checkpoint and candidate signed ledger are the successor epoch under the authorized new key;
5. the candidate retained frontier bundle verifies under that exact successor key.

A key-transition object from a different old checkpoint is rejected even when both of its signatures are valid.

If the ledger key did not change, supplying `LedgerKeyTransition` evidence is rejected rather than silently ignored.

## Governed store transition

If the frontier anchor changes `store_id` or `generation`, ADR-014 recovery evidence is mandatory.

The deployment must independently authenticate the recovery plan's approval. The serialized `approval_digest` does not authenticate itself.

After approval authentication, the verifier invokes:

```text
recovery.plan.validate_next_epoch(
    assessment,
    previous.authority_epoch,
    candidate.authority_epoch,
    now
)
```

Therefore the exact authority epoch signed into the candidate retained state must be the exact successor authorized by the still-live recovery plan.

This preserves ADR-014's required checks, assessment binding, store binding, policy/approval commitment, expiry, and recovery-plan digest commitment.

If the store did not change, supplying governed store-recovery evidence is rejected rather than silently ignored.

## Combined ledger-key rotation and store rollover

Both authority proofs are independently required when both discontinuities happen in one step:

```text
previous retained authority state
              |
       +------+------+
       |             |
       v             v
LedgerKeyTransition  ADR-014 recovery
 old+new signatures  authenticated approval
       |             |
       +------+------+
              v
candidate ledger/store/authority epoch
              |
              v
candidate retained authority state
```

A valid ledger handover cannot substitute for missing governed recovery evidence, and a valid recovery plan cannot substitute for a missing ledger-key handover.

## Same-key store rollover

When the ledger key is unchanged, both previous and candidate checkpoints must still be compatible with the same signed ledger history and trusted key. The candidate retained bundle then receives the current freshness policy.

A new store generation does not reset the ledger trust lineage.

## Same-store key rotation

When only the ledger key changes, the operation authority epoch must remain byte-for-byte the same in V1. Key rotation alone is not permission to advance operation authority.

## Transition record authority boundary

`GovernedOperationAuthorityTransitionV1` carries the exact previous/candidate signed states plus the optional typed transition evidence and an audit timestamp.

Its timestamp and `transition_digest` are audit/evidence commitments only. They do not authorize the discontinuity.

Authority comes from the underlying independently verified mechanisms:

- signed retained previous/candidate authority states;
- retained trusted previous ledger key and real signed ledger history;
- dual-signed `LedgerKeyTransition` when required;
- authenticated recovery approval when required;
- ADR-014 `validate_next_epoch()` when required.

## Recovery semantics

Successful ADR-025 verification does not:

- clear `RecoveryRequired`;
- create or apply an authority epoch;
- mutate SQLite or external retention state;
- import old grants into the candidate epoch;
- restore old privileged sessions;
- authorize `EffectArmed` or an external effect.

It produces evidence that one otherwise-disallowed retained-state discontinuity was cryptographically/governedly justified. ADR-014 policy remains responsible for the actual recovery ceremony.

## Global revocation boundary

`AuthorityEpochReasonV1::GlobalRevocation` intentionally preserves store identity/generation while changing authority epoch.

ADR-025 V1 rejects that same-store epoch change as `UnprovenAuthorityEpochChange`.

A later tranche must authenticate the exact emergency/policy revocation decision and bind it to the successor epoch before external retention may accept the epoch change. Do not generalize ADR-025 recovery logic to accept arbitrary epoch advancement.

## Qualification gates

Before ADR-025 may be used as governed recovery evidence:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV passes;
3. retained authority state signature binds the exact retained bundle and authority epoch;
4. epoch store id/generation must equal retained frontier anchor;
5. witness sequence/predecessor lineage remains exact across discontinuity;
6. ledger-key change without `LedgerKeyTransition` fails;
7. a key-transition object referencing a different previous checkpoint fails;
8. unchanged ledger key plus unexpected key-transition evidence fails;
9. store transition without ADR-014 recovery evidence fails;
10. unauthenticated recovery approval fails;
11. recovery plan cannot authorize a candidate epoch different from the epoch signed into the candidate retained state;
12. unchanged store plus unexpected recovery evidence fails;
13. combined key rotation + store-generation rollover succeeds only when both proof paths succeed;
14. removing either proof from that combined transition fails;
15. same-store unsupported authority-epoch change, including global revocation before its dedicated profile exists, fails;
16. transition verification never clears recovery or authorizes an external effect.
