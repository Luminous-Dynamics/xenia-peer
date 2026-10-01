# Symthaea Live Authority Three-Way Ordering Matrix

Status: qualification contract for the live D3A1 issuance path.

Implementation status: the integrated six-permutation matrix is now encoded in `apps/xenia-peer/src/operator_http.rs` as `integrated_issuance_three_way_ordering_matrix`. The test uses fresh durable fixtures per permutation, real HTTP mutation endpoints, post-authentication rendezvous for mutation-first cases, and a second authorized mutation principal. GitHub currently has no workflow/status result for the latest head, so this document does not treat the matrix as green until an actual test run is observed.

This document freezes the next concurrency boundary after the paired revocation and key-replacement races. The three mutable authority operations are:
- **I** — issuance of a Symthaea authorization receipt;
- **R** — operator revocation;
- **K** — operator-key replacement.

## Linearization model

Every successful semantic mutation advances the live authority generation exactly once. Issuance does not mutate the authority generation; it records the generation and effective policy commitment from the coherent snapshot that authorized the receipt.

```text
receipt provenance
    = coherent authority generation + effective-policy commitment
      observed while the issuance read barrier is held
```

For any mutation M:

```text
I completes before M commits
    -> receipt is valid provenance for generation N

M commits before I reaches its coherent snapshot
    -> I observes generation N+1 and either issues from it or rejects

I cannot straddle M
    -> no receipt combines pre-M provenance with post-M authority
```

Authentication is not itself a linearization point. A successfully authenticated request remains provisional until its token, revocation state, and key lineage are revalidated against the coherent live snapshot.

## Six permutations

| Order | Required observation |
|---|---|
| I -> R -> K | issuance is generation 1; revocation is generation 2; key replacement is generation 3 |
| I -> K -> R | issuance is generation 1; key replacement is generation 2; revocation is generation 3 |
| R -> I -> K | issuance observes revoked authority and returns no receipt; K becomes the next semantic generation |
| R -> K -> I | issuance observes both post-mutation facts and returns no receipt |
| K -> I -> R | issuance cannot use the replaced authenticated lineage; R remains a later generation |
| K -> R -> I | issuance observes replacement + revocation and returns no receipt |

The exact operation-specific outcome may vary with the target operator used by a test, but the provenance rule must not. For permutations beginning with a mutation, the test must use an issuance request whose authenticated authority is invalidated by that mutation.

## Mutation target versus mutation author

The matrix must keep **the identity being changed** separate from **the identity authorizing the change**.

A mutation-first case must not accidentally turn into an authorization test in which the first mutation revokes or replaces the credentials of the same principal needed to perform the second mutation. For example, if R targets the issuance principal, a later K operation must be authorized by a separate still-authorized actor. Likewise, the fixture must make the intended mutation target explicit rather than relying on whichever operator happens to be the test harness identity.

For every permutation:

1. Define the **issuance principal** whose authenticated request is under test.
2. Define the **mutation target** for R and K independently.
3. Define the **mutation author** independently for every mutation.
4. Ensure each mutation reaches the real guarded mutation boundary before the test asserts its ordering.
5. Ensure a rejection caused by stale lineage or revocation is distinguishable from a rejection caused merely by insufficient mutation authorization.

This separation matters because the theorem being qualified is:

```text
authority state transition ordering
    + coherent issuance observation
    + durable provenance

not merely:

```text
revoked/replaced principal cannot authorize another mutation
```

The fixture should therefore use a second authorized admin actor where necessary, while keeping the issuance principal's credentials as the object whose freshness is being tested.

## Generation accounting

For an initial authority generation N:

```text
one semantic mutation -> exactly N+1
two semantic mutations -> exactly N+2
```

No-op mutations do not advance the generation.

Persistence failure is not a committed generation transition:

```text
semantic mutation
    |
    +-- durable persistence succeeds -> generation advances
    |
    +-- durable persistence uncertain -> GuardPoisoned
                                          |
                                          +-- subsequent issuance refused
```

The matrix must assert the generation after every operation, not only the final state.

## Journal semantics

For every permutation, the issuance nonce must have exactly one terminal interpretation:
- **Issued** when the receipt was durably retained before a later mutation;
- **Aborted** when issuance is rejected after observing a mutation or poisoned guard;
- **DeliveryUnknown** only for an injected crash before terminal journal retention;
- never a second receipt for the same nonce and binding;
- never a receipt for a conflicting binding.

For an **Issued** result, the exact response bytes must equal the bytes retained by the journal. For an **Aborted** result, no receipt bytes may be exposed.

## Deterministic race construction

The matrix must not use sleeps, wall-clock timing, or scheduler luck.

Use the existing application-level rendezvous points:
1. `IssuanceAuthenticationPause` for races in which a mutation occurs after successful authentication but before coherent snapshot construction.
2. `IssuanceSnapshotPause` for races in which a mutation attempts to commit after the issuance snapshot has been acquired.
3. `SymthaeaAuthorityState::mutation_probe` to prove that a real HTTP mutation reached its guarded mutation boundary before the ordering assertion.

The intended authentication-side construction is:

```text
authenticated issuance
        |
        +--> authentication pause
        |       |
        |       +--> real mutation endpoint
        |              |
        |              +--> commit / block at authority barrier
        |
        +--> resume
                |
                +--> coherent snapshot
                +--> revalidate
                +--> sign
                +--> durable journal terminal record
```

The snapshot-side construction is the dual:

```text
coherent issuance snapshot
        |
        +--> snapshot pause
                |
                +--> real mutation reaches mutation boundary
                +--> mutation cannot commit through read barrier
                |
                +--> release issuance
                        |
                        +--> terminal journal retention
                        +--> mutation commits as later generation
```

## Required assertions per permutation

Every case should assert all of the following where applicable:
1. **HTTP result** — exact status class for issuance and each mutation.
2. **Generation** — one increment per successful semantic mutation.
3. **Live policy** — current key enrollment/revocation state.
4. **Durable policy** — a fresh reload agrees with live committed state.
5. **Receipt provenance** — generation and effective-policy commitment correspond to the coherent snapshot that authorized the receipt.
6. **Journal terminal state** — exact `Issued` / `Aborted` interpretation.
7. **No mixed provenance** — no receipt contains pre-mutation lineage after the mutation has linearized.
8. **Post-mutation authentication** — a retained token cannot bypass a revocation or key-lineage change.
9. **Persistence failure** — uncertainty poisons the authority and blocks subsequent issuance.
10. **Restart interpretation** — durable journal/policy state is sufficient to reconstruct the same security decision after reopening.

## Adversarial variants

After the six nominal orders qualify, replay the matrix with:
- mutation persistence failure;
- durable source removal immediately before mutation;
- stale authenticated token;
- same nonce with a conflicting request digest;
- repeated identical mutation;
- concurrent duplicate mutation attempts;
- restart between mutation persistence and the next issuance;
- journal path identity replacement;
- trusted-root replacement;
- owner-lock contention from a second cooperating daemon.

The filesystem variants remain a separate theorem from the in-memory ordering theorem. Rust's current filesystem guidance warns that metadata checks can race later use and recommends atomic operations and keeping files open for the duration of an operation. Linux `openat2(2)` additionally provides `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` to constrain complete pathname resolution; that is a future platform-specific hardening seam rather than an assumption of this matrix.

## Acceptance boundary

A green six-permutation matrix proves a stronger property than any single race test:

```text
ISSUE + REVOKE + REPLACE-KEY
        |
        v
one observable linearization order
        |
        +--> generation monotonicity
        +--> durable-state agreement
        +--> no stale-authentication bypass
        +--> no mixed receipt provenance
        +--> journal terminal-state agreement
```

It does not by itself prove physical power-loss durability beyond the journal's existing synchronization contract, protection from an uncooperative privileged process that ignores advisory locks, whole-path filesystem confinement on Linux, downstream freshness policy for historically valid receipts, or cross-repository cryptographic interoperability.

Those remain separate qualification contracts.
