# ADR-022: Operation-store frontier ledger witness

Status: draft candidate

## Context

ADR-007 requires an operation-store frontier to survive outside the rollback scope before Xenia can claim detection of VM/disk/backup rollback. `xenia-operation-store-frontier` therefore defines `OperationStoreFrontierAnchorV1` but deliberately leaves signature, transport, and external retention to another trust domain.

Xenia already has an append-only signed consent ledger and signed `LedgerCheckpoint` objects. A ledger entry is semantically a `ConsentEventRecord`; inserting an operation-store checkpoint as a fake `ConsentKind` would corrupt the consent vocabulary. `EvidenceBundleSeal` is session/evidence-bundle specific and should likewise not become a global machine-authority checkpoint.

## Decision

Use two deliberately different layers.

### 1. Permissive witness contract

`xenia-operation-frontier-ledger-witness` defines only signed evidence syntax and witness-lineage rules:

```text
OperationStoreFrontierAnchorV1
              +
LedgerCheckpointBindingV1
  (evidence syntax only)
              +
witness_sequence / previous_witness_digest
              +
witnessed_at
              |
              v
OperationFrontierLedgerWitnessPayloadV1
              |
       Ed25519 signature
  under key named by binding
              |
              v
OperationFrontierLedgerWitnessV1
```

The permissive crate intentionally exposes **no type named or treated as an authenticated checkpoint**. A valid witness signature proves possession of the private key corresponding to the public key named by the payload. It does not prove that the payload corresponds to a real Xenia ledger checkpoint or to the ledger history being recovered.

### 2. Authority-owning AGPL adapter

`xenia-operation-frontier-ledger-adapter` owns the actual anti-rollback trust decision. Its verification gate requires simultaneously:

1. the real signed `xenia_ledger::LedgerCheckpoint`;
2. a caller-retained trusted ledger public key;
3. the signed ledger entries being recovered;
4. the externally retained frontier witness;
5. the retained operation-store frontier chain;
6. checkpoint freshness policy and current time.

The adapter then requires:

```text
Verifier::verify_checkpoint_freshness(real checkpoint)
                 AND
Verifier::verify_checkpoint_prefix(
    checkpoint,
    recovered signed ledger,
    retained trusted key
)
                 AND
witness signature/shape valid
                 AND
witness checkpoint binding == exact real checkpoint facts/fingerprint
                 AND
verify_anchor_lineage(
    witnessed frontier anchor,
    retained local frontiers
)
```

Only this composition produces a non-serializable `VerifiedOperationFrontierWitnessV1`. Serialized witness/checkpoint bytes are evidence, not authorization tokens.

## Ledger identity

V1 witness signing uses Ed25519 and requires the signing key to match the public key named in `LedgerCheckpointBindingV1`.

The production adapter goes further: that binding must exactly equal a real `LedgerCheckpoint`, and the real checkpoint must match the independently retained trusted ledger key and an exact prefix of the signed ledger being recovered.

Therefore these are insufficient on their own:

- a self-consistent fabricated checkpoint binding;
- a valid witness signed by an attacker-controlled ledger key;
- a validly signed checkpoint from a different ledger fork;
- a signed checkpoint whose key is not the retained trusted key.

## Witness lineage

Every witness carries:

- `witness_sequence`;
- `previous_witness_digest` committing the exact previous signed witness;
- one frontier anchor;
- one checkpoint binding;
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
- no different ledger head at the same height;
- non-regressing ledger-checkpoint timestamp;
- non-regressing witness timestamp.

A checkpoint may be re-signed at the same ledger height when the ledger key/head are unchanged; its fingerprint may therefore legitimately change with its signed timestamp. The authority adapter still verifies the exact referenced real checkpoint.

The same ledger checkpoint may witness a later operation frontier, and the same operation frontier may be re-witnessed by a later ledger checkpoint.

Store-generation changes remain forbidden inside ordinary V1 witness succession. Recovery generation rollover/store replacement belongs to ADR-014 plus the authority-epoch transition; a larger generation number does not authenticate its own legitimacy.

## Successor verification

For a successor pair, the AGPL adapter verifies both referenced checkpoints as prefixes of the same currently recovered signed ledger. The prior checkpoint is historical evidence and is not rejected merely for exceeding a candidate freshness maximum-age SLA; future-skew and signature/key/prefix checks still apply. The candidate checkpoint receives the full freshness policy.

After both checkpoint/frontier compositions succeed, the candidate witness must also pass `validate_successor(previous)`.

This means a higher-height ledger fork cannot pass simply because the trusted key signed it: both retained checkpoint claims must be compatible with one recovered append-only signed ledger history.

## Recovery semantics

Successful witness verification does **not** clear `RecoveryRequired`, advance an authority epoch, consume a grant, append a receipt, or authorize an effect.

It produces one anti-rollback evidence result consumed by ADR-014 governed recovery.

A recovered operation store older than the externally retained witness fails because the exact witnessed frontier cannot be proved in retained local frontier ancestry.

A recovered ledger that does not contain the witnessed checkpoint as an exact prefix fails independently.

## External retention requirement

A witness only detects rollback if at least one copy survives outside the rollback scope of the operation store and ledger being protected.

Valid deployment patterns include separately administered immutable object storage, another host/service account with independent retention, a remote witness service, offline retained evidence, or later TPM/secure-element-backed retention.

Keeping the only witness in the same VM/disk snapshot creates no anti-rollback security.

## Privacy

The witness commits only compact continuity facts:

- operation-store identity/generation/frontier sequence/digest;
- ledger checkpoint fingerprint/count/head/key/timestamp;
- witness lineage metadata.

It contains no stdout/stderr, operation arguments, consent scope, credentials, terminal transcript, or result payload.

## Non-goals

ADR-022 does not:

- change `ConsentKind`;
- append a fake consent event;
- mutate `LedgerCheckpoint` V1;
- mutate the operation store or ledger;
- clear recovery state;
- perform governed recovery;
- provide remote storage/transport;
- provide distributed consensus;
- authorize a privileged effect;
- claim rollback protection when witness retention shares the protected rollback domain.

## Qualification gates

Before this witness can satisfy the anti-rollback check in privileged-operation recovery:

1. witness contract Rust 1.96 fmt/test/Clippy passes;
2. witness contract Rust 1.94 MSRV passes;
3. AGPL adapter Rust 1.96 fmt/test/Clippy passes;
4. AGPL adapter Rust 1.94 MSRV passes;
5. witness signing with a key different from the checkpoint binding fails;
6. witness signature tampering fails;
7. a fabricated checkpoint binding can be signed but fails the AGPL real-checkpoint comparison;
8. retained trusted-ledger-key substitution fails;
9. a validly signed ledger fork that is not a prefix of the recovered ledger fails;
10. a local operation-store frontier chain behind the witnessed anchor fails;
11. same-height frontier and ledger forks fail;
12. previous-witness digest/sequence forks fail;
13. ordinary V1 succession refuses store-generation changes;
14. successor verification proves both checkpoints against one recovered signed ledger;
15. the witness is retained in an independently administered rollback domain before restore-safe operation is claimed.
