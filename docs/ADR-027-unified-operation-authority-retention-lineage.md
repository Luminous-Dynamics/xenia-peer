# ADR-027: Unified external operation-authority retention lineage V2

Status: draft candidate

## Context

ADR-022/023 introduced externally retainable operation-frontier witness/checkpoint bundles. ADR-024 defined append-only persistence-before-ack semantics for those bundles.

The authority model has since grown richer:

- ADR-025 signs retained frontier/checkpoint evidence together with the exact `OperationAuthorityEpochV1` and defines governed key/store discontinuities;
- ADR-026 defines same-store global revocation and a ledger-signed historical transition receipt.

Persisting only bare frontier witness bundles is therefore no longer enough to reconstruct the complete operation-authority history after disaster recovery.

At the same time, the frontier `witness_sequence` should not become the storage key for every future evidence object. External persistence needs its own stable ordering domain.

## Decision

Introduce `OperationAuthorityRetentionRecordV2`, with an independent contiguous `retention_sequence` and exact previous-record digest.

```text
record 0
  explicit lineage origin
  AuthorityState
       |
       | digest(record 0)
       v
record 1
  AuthorityState | GovernedTransition | GlobalRevocationTransition
       |
       | digest(record 1)
       v
record 2
       ...
```

The retention sequence is independent from the embedded frontier-witness sequence. The semantic payload still preserves and verifies the witness lineage appropriate to its transition type.

## Payload vocabulary

V2 has three typed payloads.

### `AuthorityState`

Carries one exact signed `RetainedOperationAuthorityStateV1`.

As an ordinary successor it must:

- preserve the exact operation-authority epoch byte-for-byte;
- contain a retained witness bundle that is an exact ordinary successor of the previous terminal state's bundle.

An ordinary state record cannot silently perform a global revocation, key rotation, store rollover, or store replacement.

### `GovernedTransition`

Carries one exact `GovernedOperationAuthorityTransitionV1`, including its previous and candidate signed authority states plus typed ledger-key/recovery evidence.

The transition's explicit previous retained-state digest must equal the terminal state of the immediately previous retention record.

Local retention validation preserves and stores the evidence but does not authenticate the deployment's recovery approval. Before a recovery policy treats the transition as authority-valid, it must run the ADR-025 authority verifier against the real ledger/frontier histories and configured recovery-approval trust path.

### `GlobalRevocationTransition`

Carries atomically:

- exact previous retained authority state;
- exact candidate retained authority state;
- exact signed `GlobalRevocationTransitionReceiptV1`.

Local validation requires the receipt's previous-state, candidate-state, candidate-epoch, candidate-witness, and approved-decision commitments to equal the carried states exactly, and requires ordinary same-store retained-witness succession plus exact global-revocation epoch succession.

The historical ADR-026 verifier must still re-authenticate the external revocation approval and real ledger/frontier lineage before the transition is accepted as authority-valid recovery evidence.

## Explicit lineage origin

Record zero must declare one of two claims.

### `FullWitnessLineageGenesis`

The embedded authority state's witness must actually be witness sequence zero with an all-zero predecessor-witness digest.

This claim means the external V2 retention lineage begins at the witnessed operation-authority history's real external-witness genesis.

### `AdoptedAnchor`

An existing deployment may begin V2 external retention at a later already-running authority state.

This is deliberately allowed so systems can adopt stronger anti-rollback protection without fabricating history they never retained.

An adopted anchor means only:

> rollback protection begins at this exact externally retained state.

It makes **no claim** that earlier operation/witness history was independently protected.

The adoption ceremony must separately verify the anchor through the relevant ADR-022/025 authority path before a deployment treats it as a trusted starting point.

## Two distinct validity layers

This distinction is fundamental.

### Retention-lineage validity

`OperationAuthorityRetentionModelV2` and `validate_retained_lineage_v2(...)` prove local/immutable-storage properties such as:

- record schema and signatures that are self-verifiable;
- exact record sequence and previous-record digest chain;
- explicit origin semantics;
- ordinary witness succession;
- transition payload begins at the immediately previous terminal state;
- global-revocation receipt is internally bound to its carried states;
- no sequence gap/fork;
- persistence-before-ack;
- fail-stop handling of uncertain durability.

A model in `Healthy` state means the retained bytes form a coherent append-only persistence lineage under V2 semantics.

It does **not** mean every human/organizational approval embedded or referenced by those records has been independently authenticated.

### Authority-transition validity

Before retained transition evidence contributes to recovery authorization, callers must run the corresponding authority verifier:

- ordinary witness/state -> ADR-022 real-ledger/frontier verifier as applicable;
- governed transition -> ADR-025 verifier with retained trusted ledger key, signed ledger/frontier histories, and authenticated recovery approval;
- global revocation -> ADR-026 historical verifier with exact external approval authentication.

External persistence cannot manufacture authority merely by accepting well-formed bytes.

## Terminal-state semantics

Every payload has one terminal retained authority state.

Transition payloads also carry an explicit initial state.

For every transition record:

```text
payload.initial_state digest
    ==
previous_record.payload.terminal_state digest
```

This prevents a cryptographically valid transition from being inserted beside an unrelated retained predecessor.

The next record always continues from the prior record's terminal state.

## Independent retention sequence

The external key is conceptually:

```text
(retention_lineage_id/deployment binding, retention_sequence)
```

V2's current contract models the sequence/digest semantics; a concrete backend must additionally bind records to the correct configured deployment/authority domain when defining its provider keyspace.

A future backend must not key solely by witness sequence because:

- adopted anchors may begin at nonzero witness sequence;
- transition evidence has richer payload semantics than a bare witness bundle;
- future evidence profiles may need records that do not map one-to-one to a frontier witness.

## Persistence-before-ack

The V2 reference model retains ADR-024 semantics.

For an existing retention sequence:

```text
same exact canonical record
    -> DuplicateSame
    -> do not persist again

different bytes
    -> RetentionSequenceConflict
```

For a new record:

```text
exact next sequence + valid predecessor
        |
        v
backend persist exact immutable record
        |
        +-- Durable  -> Appended
        +-- Rejected -> healthy / unchanged
        +-- Unknown  -> DurabilityUncertain
```

No subsequent mutation is permitted in `DurabilityUncertain` state.

There is no in-memory `clear_uncertain` operation. Recovery requires external immutable readback and construction of a new model with `from_retained_lineage(...)`.

## Empty lineage

An empty model is structurally healthy before initial enrollment but provides **zero anti-rollback evidence**.

Recovery policy requiring external rollback protection must require at least one authenticated retained anchor; `Healthy + zero records` is not equivalent to `FrontierAnchorContinuity = Passed`.

## Timestamps

`retained_at_unix_ms` is audit/ordering metadata and is committed by the retained-record digest. It may not regress and may not predate the evidence the record contains.

Retention ordering authority is the exact `retention_sequence` + previous-record digest chain, not wall-clock time.

V2 does not claim a Byzantine trusted timestamp. Provider-authenticated immutable-object creation time, remote witnesses, TPM counters, or a trusted timestamp authority may strengthen future profiles.

## External backend requirement

The reference model does not itself create rollback resistance. A concrete backend must live outside the protected rollback domain and implement equivalent immutable first-writer-wins/readback semantics.

The first backend should provide:

- create-if-absent immutable object keyed by deployment/lineage + retention sequence;
- exact-byte/digest readback;
- enumeration sufficient to reconstruct the complete retained lineage from record zero;
- durable acknowledgement semantics;
- conflict visibility;
- no silent object overwrite;
- independent administration/credentials/failure domain from the protected operation store.

A mutable `latest` pointer may be an optimization only when CAS-bound to an already durable immutable record. It is never the recovery authority source.

## Recovery composition

A recovery flow using V2 should conceptually perform:

```text
external immutable readback
        |
        v
V2 retention-lineage validation
        |
        v
identify explicit origin + latest terminal state
        |
        v
re-authenticate every authority transition needed by policy
        |
        v
compare latest retained terminal state/frontier
against recovered local store + ledger
        |
        v
ADR-014 recovery assessment
```

Successful V2 readback does not clear `RecoveryRequired`.

## Non-goals

ADR-027 does not:

- choose S3/GCS/Azure/Holochain/TPM/remote-witness transport;
- claim authority validity from local structural validation alone;
- provide trusted wall-clock timestamps;
- clear governed recovery;
- apply authority epochs;
- revive old grants;
- authorize `EffectArmed` or external effects;
- permit shell, PTY, SSH, or process execution.

## Qualification gates

Before V2 external retention may satisfy privileged-operation rollback-resistance claims:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV passes;
3. direct witness-digest failures are fail-closed and surfaced explicitly;
4. true full-witness genesis is accepted;
5. a false full-genesis claim fails;
6. explicit adopted-anchor enrollment at a later witness is accepted without retroactive-history claims;
7. ordinary authority-state progression preserves exact authority epoch and witness succession;
8. an ordinary record cannot silently change authority epoch;
9. transition initial state must equal the immediately previous terminal state;
10. global-revocation record atomically binds exact previous/candidate state + signed receipt;
11. exact duplicate append performs no second persistence call;
12. same-sequence different bytes is fork/conflict evidence;
13. sequence gaps fail before persistence;
14. definite backend rejection leaves the model healthy and unchanged;
15. unknown persistence outcome enters `DurabilityUncertain` and blocks all later writes;
16. only immutable lineage readback/revalidation establishes a new healthy model after uncertainty;
17. an empty healthy model is never accepted as external anti-rollback evidence;
18. governed/global transition approvals are re-authenticated through ADR-025/026 before recovery acceptance;
19. a concrete external backend passes destructive timeout/process-kill/concurrent-writer tests before replacing the reference model in a security claim.
