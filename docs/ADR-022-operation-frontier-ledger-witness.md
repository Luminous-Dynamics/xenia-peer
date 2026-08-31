# ADR-022: Operation-store frontier ledger witness

Status: draft candidate

## Context

ADR-007 requires an operation-store frontier to survive outside the rollback scope before Xenia can claim detection of VM/disk/backup rollback. The standalone `xenia-operation-store-frontier` contract therefore defines `OperationStoreFrontierAnchorV1` but deliberately leaves signature, transport, and external retention to another trust domain.

Xenia already has an append-only signed consent ledger and signed `LedgerCheckpoint` objects. However, a ledger entry is semantically a `ConsentEventRecord`; inserting an operation-store checkpoint as a fake `ConsentKind` would corrupt the consent vocabulary. `EvidenceBundleSeal` is likewise session/evidence-bundle specific and should not become a global machine-authority checkpoint by accident.

The correct composition is a separate signed witness object that binds:

1. the exact operation-store frontier anchor;
2. one already-authenticated Xenia ledger checkpoint;
3. a monotonic witness lineage;
4. the same Ed25519 authority key that authenticates that ledger checkpoint.

An independently retained witness can then detect operation-store rollback without changing the stable consent-ledger entry schema.

## Decision

Introduce standalone `xenia-operation-frontier-ledger-witness` V1.

The core shape is:

```text
OperationStoreFrontierAnchorV1
              +
already-verified LedgerCheckpoint facts
              +
witness_sequence / previous_witness_digest
              +
witnessed_at
              |
              v
OperationFrontierLedgerWitnessPayloadV1
              |
       Ed25519 signature
   by the exact ledger key
              |
              v
OperationFrontierLedgerWitnessV1
              |
       externally retained
```

The witness contract performs no operation-store mutation, no ledger append, no recovery transition, and no privileged effect.

## Checkpoint authentication boundary

Serialized checkpoint fields inside a witness are evidence, not self-authenticating authority.

`AuthenticatedLedgerCheckpointV1` is intentionally non-serializable. Production callers must obtain it from the actual ledger checkpoint trust path, including:

- checkpoint signature verification;
- trusted ledger-key continuity/identity;
- any required checkpoint freshness policy;
- checkpoint fingerprint calculation over the exact signed object.

`LedgerCheckpointBindingV1::validate_against(...)` then requires exact equality with those independently authenticated facts.

A witness with a valid ledger-key signature but a fabricated checkpoint fingerprint does not pass this gate unless the caller independently authenticates the same checkpoint.

## Same-key signature

The witness is signed by Ed25519 V1 using the exact public key committed by the bound ledger checkpoint.

`sign_ed25519(...)` refuses a signing key whose verifying key differs from the checkpoint binding.

This creates one clear identity statement:

```text
ledger checkpoint authority K
        ==
frontier witness signer K
```

V1 does not introduce a second hidden witness key.

A later PQC/composite witness profile may be added under a new schema after the ledger's algorithm-tagged signature path is ready for this long-lived artifact. It must not silently change V1 verification semantics.

## Witness lineage

Every witness carries:

- `witness_sequence`;
- `previous_witness_digest` committing the exact previous signed witness;
- one frontier anchor;
- one ledger checkpoint binding;
- witness time.

Witness zero uses the all-zero previous digest. Every later witness must use exact previous + 1 and the exact previous signed-witness digest.

V1 successors require:

- identical operation-store `store_id`;
- identical operation-store generation;
- non-regressing frontier checkpoint sequence;
- no different frontier digest at the same frontier sequence;
- non-regressing frontier-anchor timestamp;
- identical ledger public key;
- non-regressing ledger entry count;
- no different checkpoint/head at the same ledger height;
- non-regressing ledger-checkpoint timestamp;
- non-regressing witness timestamp.

The same ledger checkpoint may witness a later operation frontier. The same operation frontier may be re-witnessed by a later ledger checkpoint. This supports independent cadence for the two logs.

Store-generation changes are deliberately rejected inside ordinary V1 witness succession. A recovery generation rollover or store replacement must first pass the governed recovery/authority-epoch transition. A future transition-witness type may explicitly bind that recovery evidence; V1 does not infer it from a larger generation number.

## Restart anti-rollback gate

`verify_latest_witness_against_local(...)` requires three things simultaneously:

1. the witness signature is valid under the embedded ledger key;
2. the witness checkpoint binding exactly matches independently authenticated checkpoint facts;
3. the exact externally witnessed operation-store anchor remains in the valid retained local frontier ancestry.

Therefore an older restored operation database fails when it cannot prove the witnessed frontier in its local lineage.

This verification does **not** clear `RecoveryRequired`. It produces one anti-rollback evidence result consumed by ADR-014 recovery policy.

## External retention requirement

A witness only detects rollback if at least one copy survives outside the rollback scope of the operation store and ledger state being protected.

Valid V1 deployment patterns include:

- separately administered immutable object storage;
- another host/service account with independent retention;
- remote witness service;
- offline retained checkpoints;
- later TPM/secure-element-backed retention.

Storing the only witness in the same VM/disk snapshot does not create anti-rollback security.

## Ledger checkpoint continuity remains independently important

This witness binds an operation frontier to a ledger checkpoint; it does not replace Xenia ledger checkpoint continuity verification.

A verifier retaining prior ledger checkpoints/witnesses should continue to detect:

- ledger-key substitution;
- ledger entry-count regression;
- same-height ledger forks;
- checkpoint freshness failures where policy requires freshness;
- failure to extend a retained checkpoint when stronger suffix evidence is available.

The witness contract's successor rules add another compact cross-domain lineage but do not weaken the ledger's own verification rules.

## Evidence privacy

The witness commits only compact continuity facts:

- operation-store identity/generation/frontier digest/sequence;
- ledger checkpoint fingerprint/count/head/key/timestamp;
- witness lineage metadata.

It contains no stdout/stderr, operation arguments, consent scope string, credentials, terminal transcript, or operation result payload.

## Non-goals

ADR-022 does not:

- change `ConsentKind`;
- append a fake consent event;
- mutate `LedgerCheckpoint` V1;
- modify the operation store;
- clear recovery state;
- perform governed recovery;
- provide remote storage/transport;
- provide distributed consensus;
- authorize a privileged effect;
- claim rollback protection when witness retention shares the same rollback domain.

## Qualification gates

Before this witness can satisfy the anti-rollback check in a privileged-operation recovery policy:

1. Rust 1.96 fmt/test/Clippy passes;
2. Rust 1.94 MSRV check passes;
3. witness signing with a key different from the ledger checkpoint key fails;
4. signature tampering fails;
5. serialized checkpoint facts cannot substitute for independently authenticated checkpoint context;
6. a local frontier chain behind the externally witnessed anchor fails;
7. same-height frontier and ledger forks fail;
8. ledger-key substitution fails;
9. previous-witness digest/sequence forks fail;
10. ordinary V1 succession refuses a store-generation change;
11. a production adapter constructs `AuthenticatedLedgerCheckpointV1` only after the actual `xenia-ledger` checkpoint verifier/trusted-key path succeeds;
12. the witness is retained in an independently administered rollback domain before restore-safe operation is claimed.
