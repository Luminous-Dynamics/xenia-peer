# Xenia witness-frontier anchor V0.1

## Purpose

This profile gives Symthaea qualification-witness chronology a typed Xenia anchor without overloading the human-consent ledger.

It is composed on a real two-parent merge of:

- bounded-agent authority provenance from Xenia PR #232; and
- outcome-unknown-safe persistence semantics from Xenia PR #287.

Witness chronology remains evidence. It does not create execution authority.

## Cross-repository operation identity

`WitnessFrontierAnchorTargetV1` independently reproduces Symthaea #457's exact operation commitment.

Normative operation transcript:

```text
"symthaea.qualification-witness.anchor-operation.v1\0"
u16_be(schema = 1)
source_id[16]
u64_be(source_epoch)
anchor_policy_digest[32]
witness_id[16]
u64_be(high_watermark)
reservation_head[32]
frontier_statement_digest[32]
```

The operation id is BLAKE3 of those exact bytes.

The frontier statement is also independently reproduced using:

```text
"symthaea.qualification-witness.sequence-frontier.v1\0"
u16_be(schema = 1)
witness_id[16]
u64_be(high_watermark)
reservation_head[32]
```

Therefore a caller cannot supply an arbitrary operation id or frontier commitment and ask Xenia to sign it.

## Source identity

The Xenia source id is not a free caller label.

V1 derives its 16-byte source namespace from:

```text
BLAKE3(
    "xenia.witness-frontier-source-id.v1\0"
    || ledger_public_key
    || anchor_policy_digest
)[0..16]
```

The source epoch remains an explicit monotonic policy/recovery generation.

A durable anchor verifies this source derivation again using its embedded Xenia public key. A signed record cannot therefore be relabelled to an unrelated source namespace without failing verification.

## Separate consent and witness chronology

V1 deliberately does **not** encode anchors as a `ConsentEventRecord`, `ConsentKind`, or `scope` string.

The consent ledger answers questions about human/operator authorization history. The witness-anchor store answers questions about externally retained qualification chronology. Mixing the two would create future confused-authority risks.

Both use the Xenia ledger authority key so a verifier can anchor trust in one already-reviewed public key.

## Durable anchor record

`SignedWitnessFrontierAnchorV1` signs:

- the exact Symthaea target;
- source sequence (`anchor_sequence`);
- previous signed-anchor fingerprint;
- Xenia consent-ledger count/head at signing time;
- the exact Xenia ledger public key;
- issue timestamp.

The consent-ledger count/head is **context only**. It is not a claim that the consent ledger was durably persisted. #287's `has_uncertain_persistence()` only proves that no outcome-aware append is currently unresolved. It does not prove that every historical plain `Chain::append` call was durable.

The separate #232 persistence-ordering gap therefore remains real and must be closed with a durable ledger-frontier witness rather than by reinterpreting these contextual fields.

## Durable store CAS contract

`WitnessFrontierAnchorStore` exposes three reviewed operations:

```text
lookup_operation(operation_id)
current_for_witness(source, epoch, witness)
compare_and_swap(expected_previous, candidate)
```

A successful `None` lookup is contractually authoritative for that source store.

`compare_and_swap` must be atomic/linearizable. The expected predecessor is the fingerprint of the exact currently verified signed anchor. For the first anchor it is `None`.

Xenia derives the next anchor sequence and predecessor itself. The caller does not choose them.

The new witness high watermark must strictly advance the currently anchored high watermark. Ancestry of the local witness history itself is intentionally proven on the Symthaea side by #452/#456 before the Xenia request exists.

## Idempotency

The Symthaea operation id is the source idempotency key.

Before CAS, Xenia performs an authoritative operation lookup:

```text
existing exact operation + exact target + exact signer
    -> return same signed anchor
    -> no second CAS

existing operation + different target/signer
    -> fail closed before effect
```

This makes an exact retry after a lost response idempotent.

## Outcome-unknown semantics

The anchor store reuses #287's closed-world persistence classification:

```text
Persisted
ProvenNotPersisted
OutcomeUnknown
```

After `compare_and_swap` is invoked:

- `Persisted` returns the exact signed candidate;
- `ProvenNotPersisted` is retry-safe for the exact deterministic operation;
- `OutcomeUnknown` returns the exact candidate and requires reconciliation.

A zero diagnostic on either failure path is converted to a nonzero internal diagnostic commitment. It never silently becomes success.

`reconcile_witness_frontier_anchor_v1` performs only authoritative operation lookup. It never creates another anchor.

## Consent-ledger uncertainty gate

Before signing an anchor or freshness observation, Xenia requires:

```text
Chain::has_uncertain_persistence() == false
```

Thus a #287 ambiguous consent-ledger append blocks new witness-source statements until reconciliation.

This is intentionally a conservative cross-domain dependency. It is not a durable-ledger certificate.

## Freshness is a separate signed object

A durable anchor is history, not freshness.

V1 adds `SignedWitnessFrontierObservationV1`, produced only after an authoritative `current_for_witness` query and signed under a verifier-provided nonzero 32-byte challenge.

The observation binds:

- source id;
- source epoch;
- anchor-policy digest;
- witness id;
- anti-replay challenge;
- observed timestamp;
- exact current anchor sequence/fingerprint/operation/frontier, if one exists;
- current Xenia ledger context;
- exact Xenia ledger public key.

Verification requires the exact expected challenge, trusted key, source namespace, source epoch, policy, witness, and freshness window.

`verify_current_anchor(anchor)` additionally requires the observation's current summary to equal the exact supplied signed anchor record, including its signed fingerprint.

Therefore:

```text
old signed anchor alone
    != currentness proof

exact signed anchor
+ fresh challenge-bound observation
+ exact anchor fingerprint match
    = authenticated current-source evidence
```

Network suppression can still deny a fresh observation. It cannot turn an old challenge into a new one. Availability failure therefore fails closed rather than manufacturing freshness.

## Time boundary

V1 accepts the issue/observation timestamp from its integration boundary. The source file does not itself prove wall-clock integrity.

Production composition should supply the same trusted-time discipline used by the Agency Kernel. A compromised local clock remains outside this source-only claim until that integration is wired.

## Cross-language qualification

The Xenia source independently fixes:

- Symthaea operation domain;
- Symthaea frontier-statement domain;
- both V1 schema numbers;
- field order;
- fixed widths;
- big-endian integer encoding.

Tests require operation-message length to equal the sum of the normative fields and reject operation/frontier commitment drift.

A frozen expected BLAKE3 digest vector should be added once the first exact-head Rust qualification executes; until then this is authored/static-reviewed interoperability, not a qualified cross-language vector.

## Tests authored

The source tests cover:

- exact persisted first anchor;
- exact operation idempotency with no second CAS;
- fresh challenge-bound current observation;
- observation-to-exact-anchor fingerprint binding;
- challenge substitution rejection;
- successor predecessor fingerprint chaining;
- non-monotonic witness frontier rejection;
- store `OutcomeUnknown` requiring explicit reconciliation;
- unresolved #287 consent persistence blocking anchor dispatch;
- cross-repository operation-id/frontier-digest drift rejection;
- signed anchor source relabelling rejection.

## Non-claims

V0.1 does not provide:

- a concrete production CAS database/service implementation;
- Byzantine/root-resistant anchor-store rollback prevention;
- a durable consent-ledger-frontier witness for #232;
- trusted wall-clock acquisition inside Xenia;
- transparency/SCITT publication;
- post-quantum witness-anchor issuance;
- a Symthaea #457 adapter yet;
- execution authority of any kind.

The next source-side tranche should be a concrete durable CAS store with crash/fault qualification. The next cross-repository tranche should independently verify the Xenia signed anchor + fresh observation and translate them into #452's `VerifiedExternalWitnessFrontierV1`.