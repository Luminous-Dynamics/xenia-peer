# Full-PQC Migration Plan

Status: post-RC1 hardening plan.

Xenia is in a **mixed migration state**, not one global crypto profile. The current live handshake uses ML-KEM-768 plus mandatory Ed25519 AND ML-DSA-65 transcript authentication under `hybrid-pq-transcript-v1`. The stable consent-ledger/evidence append path remains Ed25519 by default under `hybrid-pre-pqc-v1`, with optional ML-DSA evidence capabilities behind an explicit feature. Aggregate `full-pqc` remains false.

`CURRENT_CRYPTO_SURFACE_V1.md` and `current_crypto_surface_v1.json` are the source-bound current-state census for these distinctions.

## Claim boundary

Use these terms consistently:

| Term | Meaning in Xenia | Current status |
|---|---|---|
| Classical | Classical-only signature/key-exchange surface. | Historical/compatibility only for new privileged handshake auth; still present on default ledger append. |
| PQ key establishment | Session key material derives from ML-KEM. | Current live handshake. |
| Hybrid PQ/T | Classical and PQ algorithms are both present in an authenticated construction. | Current live handshake. |
| Full-PQC | PQ key establishment plus PQ-only authority/signature surfaces under the full profile. | Future target; not current aggregate status. |

Do not claim `full-pqc-v1`, “entirely PQC,” or “PQC at every layer” until every required authority-bearing surface and downgrade rule has qualified evidence.

## Required algorithm baseline

- Key establishment: ML-KEM-768 baseline; stronger profiles may be evaluated separately.
- Online signatures: ML-DSA-65 baseline; ML-DSA-87 for higher-sensitivity profiles where justified.
- Offline/root signatures: SLH-DSA may be evaluated for conservative roots/release signing.
- Symmetric sealing: ChaCha20-Poly1305 remains acceptable for the current transport profile; alternative compliance profiles are separate work.
- Hashing: BLAKE3 remains the current internal transcript/hash-chain choice unless a compliance profile explicitly requires another hash.

## Migration stages

### Stage 0 — honest scoped status

Goal: prevent crypto-claim drift.

Current state:

- the live handshake is no longer Ed25519-only;
- the stable default ledger/evidence path is still Ed25519 by default;
- aggregate Xenia is not full-PQC.

A single global “current profile” must not collapse those surfaces.

### Stage 1 — signature agility types

Goal: version signature artifacts before changing authority policy.

Implemented foundations include algorithm-tagged `SignatureEnvelope` support and stable signature-suite labels. Historical Ed25519 evidence must remain verifiable under its original semantics.

### Stage 2 — PQ transcript authentication

Goal: prevent acceptance of the live handshake when only one side of the hybrid authentication policy verifies.

**Current status:** native dual signing is implemented. The live native handshake requires both Ed25519 and ML-DSA-65 transcript signatures (AND composition, no classical-only fallback) under `hybrid-pq-transcript-v1`.

A WASM-capable viewer-side handshake implementation also exists in `Luminous-Dynamics/xenia-wire` and targets the same ML-KEM-768 + Ed25519 AND ML-DSA-65 semantics. That is an external cross-repository implementation boundary: existence and cross-compatibility evidence do not by themselves prove every browser/operator deployment qualified. XEN-CRYPTO-FV-004 / issue #399 owns the stronger native↔WASM conformance lane.

Remaining Stage-2 proof work includes exact transcript refinement, protocol proofs under compromise, and explicit downgrade/composition theorems.

### Stage 3 — PQ ledger/evidence signatures

Goal: make long-lived consent evidence quantum-resistant without rewriting history.

Current status:

- the stable `Chain::append` path remains Ed25519 by default;
- ML-DSA-65/87 evidence verification/building support exists behind the optional `pqc-signatures` feature;
- optional PQ evidence capability does not make the default ledger append path PQ;
- historical Ed25519 chains remain first-class historical evidence.

Future production migration should define explicit chain/evidence policy at creation time and bind it into exported evidence.

### Stage 4 — PQ identity and admin authority

Goal: remove Ed25519 as a required authority root in deployments that claim full-PQC.

Still incomplete. Required work includes PQ identity material, key rotation/transition evidence, admin/policy authority, release artifacts, operator enrollment, and bridge records for historical identities.

### Stage 5 — full-PQC profile gate

Goal: make `full-pqc-v1` an enforceable profile rather than a label.

A qualified full-PQC profile must require at least:

- ML-KEM session establishment;
- PQ-only accepted transcript authentication under the declared full profile;
- PQ consent/ledger signatures;
- PQ-signed policy/admin authority where in scope;
- no silent Ed25519 fallback on authority-bearing surfaces;
- evidence export that binds negotiated algorithms/profile identities;
- negative controls proving downgrade rejection.

## Evidence-model evolution

The current live handshake acceptance rule is composite:

```text
Ed25519 valid AND ML-DSA-65 valid
```

The long-lived evidence v1 transcript-signature artifact currently models one `SignatureSuite`. Those are different boundaries. XEN-CRYPTO-FV-008 tracks a versioned composite-authentication evidence shape so future proof receipts can represent `AllOf(Ed25519, ML-DSA-65)` without silently changing v1 evidence semantics.

## Acceptance tests

A full-PQC claim is not qualified until tests/receipts establish, at minimum:

1. classical-only handshake authentication is rejected under the full profile;
2. classical-only ledger/evidence authority is rejected under the full profile;
3. every authority-bearing signature artifact reports its algorithm/policy identity;
4. tampered ML-DSA evidence fails closed;
5. historical Ed25519 evidence remains verifiable but cannot be relabeled as full-PQC;
6. algorithm/profile changes alter the bound evidence identity;
7. missing one member of an `AllOf` authentication policy fails verification;
8. admin/root/policy surfaces meet the same declared full-profile boundary.

## Product wording

Safe now:

> Xenia's live handshake uses ML-KEM-768 with mandatory Ed25519 + ML-DSA-65 transcript authentication, while the stable ledger/evidence append path remains Ed25519 by default. Xenia is still migrating other authority surfaces toward a future full-PQC profile.

Safe only after Stage 5 qualification:

> Xenia supports a full-PQC profile with post-quantum key establishment, authentication, consent-ledger signatures, and policy/admin authority under the qualified profile.

## Formal-verification path

The formal lane should preserve these proof classes separately:

- provider/primitive assurance;
- exact transcript and KDF refinement;
- symbolic protocol security;
- native/WASM conformance;
- replay/epoch state-machine proofs;
- computational construction proofs;
- compiled/constant-time and erasure evidence.

No one result should be relabeled as repository-wide “formally verified cryptography.”
