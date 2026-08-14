# Xenia ZK Protocol V3

## Purpose

V3 is the clean extraction boundary between generic proof infrastructure and
application semantics. It is a new protocol generation, not a source-code rename
of Mycelix v2.

## Non-negotiable invariants

1. **No silent downgrade.** V3 verification never falls back to a legacy parser.
2. **Statement identity is explicit.** `{ecosystem}:{application}:{purpose}:vN`
   is display syntax; signed bytes length-frame each component independently.
3. **Backend identity is insufficient.** Every proof binds an exact `VerifierId`
   derived from the AIR/program/image bytes.
4. **Parameters are protocol data.** `ParameterSetId` prevents a verifier from
   accepting a proof under unintended security/proving parameters.
5. **Public inputs are bound.** The canonical body includes `public_inputs_hash`.
6. **Proof bytes are bound by digest.** Authentication signs a digest that includes
   `SHA-256(proof)` rather than trusting an outer serializer.
7. **Authentication metadata is bound.** Suite and signer-key ID are part of each
   authentication digest, so signatures cannot be relabeled across algorithms or
   signers.
8. **Application claims are extensions.** Energy, HDC metadata, governance data,
   and similar concepts do not become permanent fields in the generic envelope;
   V3 binds an extension digest instead.
9. **Structural validation is not proof verification.** Policy checks happen before
   backend verification and never claim cryptographic validity.
10. **Circuit admission is evidence-driven.** No primitive is promoted into Xenia
    until malicious-trace/adversarial tests exercise every claimed relation.

## Migration from Mycelix v2

The legacy signing domain remains byte-for-byte:

`MYCELIX:AuthenticatedProof:SignedEnvelope:v2`

A future compatibility crate may expose an explicit API such as
`verify_legacy_mycelix_v2(...)`. It must be opt-in at the call site. Parsing a V3
failure as V2 is forbidden.

New proof generation uses:

`XENIA:ProofEnvelope:Body:v3`

Legacy domain tags such as `ZTML:Governance:AnonVote:v1` remain historical
protocol identifiers. They are not renamed in place. New statements use the
backend-neutral `StatementId` structure.

## Intended crate boundaries

```text
xenia-zk-protocol        statement IDs, verifier IDs, parameter IDs, V3 envelope
xenia-zk-auth            adapters to Xenia signature/PQC implementations
xenia-zk-backend-*       Winterfell / Miden / RISC0 verification adapters
xenia-zk-primitives      only audited reusable proof statements
xenia-zk-legacy-mycelix  explicit V2 compatibility verifier

mycelix-*                governance, supply, identity, health, jurisdiction semantics
symthaea-*               HDC/computation-specific proof statements
nixward-*                build/policy-compliance statements
```

The dependency direction is one-way: application domains may depend on Xenia ZK
crates; Xenia ZK crates must not depend on Mycelix/Holochain/domain semantics.
