# Xenia Formal Cryptography Verification Architecture v1

Status: architecture contract only. No cryptographic theorem is established by this document.

Tracker: XEN-CRYPTO-FV-000 / #395.

## 1. Purpose

Xenia's cryptography is a composition of primitives, protocol state, concrete byte encodings, key schedules, replay/nonce state, transport policy, and runtime provider implementations. A proof about one layer must never silently become a claim about another.

The governing rule is:

```text
primitive proof
!= protocol proof
!= transcript/serialization proof
!= implementation refinement
!= side-channel proof
!= compiled-binary proof
!= runtime authorization
```

Formal crypto assurance is therefore evidence composition across explicit planes, not one `verified=true` bit.

This architecture reuses the cross-project SYM-FV evidence vocabulary where possible. The crypto-specific planes below are facets/subjects; they are not a competing evidence-class taxonomy.

## 2. Current production subject

The native `xenia-handshake` path currently composes:

- ML-KEM-768 key establishment;
- mandatory Ed25519 AND ML-DSA-65 transcript authentication;
- HKDF-SHA256 root/session/lane derivation;
- BLAKE3 identity/transcript/context hashing;
- fresh per-handshake ML-KEM decapsulation keys retained only while a handshake is pending;
- transcript-bound lane labels;
- negotiated session-context binding;
- typed rekey epoch/context binding.

`xenia-wire` supplies ChaCha20-Poly1305 session sealing, sequence/nonces, replay protection and key-epoch state. It also contains an independent browser/WASM handshake implementation under the `handshake` feature.

Those two handshake implementations are a useful diversity boundary, but also a drift boundary that requires independent conformance evidence.

## 3. Five primary verification planes

### Plane P1 — primitive provider assurance

Subjects include ML-KEM, ML-DSA, Ed25519, HKDF/SHA-256, BLAKE3 and ChaCha20-Poly1305.

A provider record must bind the exact implementation/version/checksum, standard revision/errata, tests, known advisories, formal-proof scope, audit status, secret-independence/constant-time evidence and platform-specific code paths.

Provider assurance may be imported from an external project only at the exact scope that project establishes.

Examples:

```text
verified field arithmetic
!= verified top-level API

source secret independence
!= compiler-preserved constant time

verified ML-KEM provider
!= verified Xenia handshake
```

The initial policy is to compare current RustCrypto providers against independent high-assurance/reference implementations before considering a provider migration. A stronger proof badge does not automatically justify adding FFI, unsafe code, a new compiler/toolchain or a less mature provider.

### Plane P2 — symbolic protocol security

Tamarin is the initial canonical symbolic protocol prover for the Xenia handshake/rekey protocol.

The model must include the actual protocol concepts:

- host/viewer roles;
- ephemeral ML-KEM exchange;
- Ed25519 and ML-DSA transcript signatures with AND acceptance;
- suite/profile/domain labels;
- transcript hash and negotiated context;
- TOFU identity pinning;
- lane/session key derivation;
- capability admission;
- rekey epochs;
- compromise events;
- replay/downgrade/adversarial network control.

Initial target properties:

- session-key secrecy under stated compromise assumptions;
- mutual authentication/injective agreement;
- agreement on peer identity, transcript and negotiated context;
- unknown-key-share resistance;
- replay resistance;
- suite/profile downgrade resistance;
- lane-domain separation in the symbolic KDF model;
- rekey anti-rollback/anti-replay;
- compromise behavior for each signing-key family and ephemeral KEM state;
- TOFU first-contact limitation;
- forward-secrecy result or counterexample matching actual ephemeral-key lifetime.

The model MUST retain expected negative results. In particular, a first-contact TOFU active MITM is not repaired by weakening the adversary.

A symbolic theorem treats primitives according to its equations/assumptions. It does not establish FIPS 203/204 implementation correctness.

### Plane P3 — transcript, encoding and key-schedule refinement

The implementation must be tied to the symbolic/model subject at the byte level.

High-value pure production kernels include:

- handshake signature-transcript construction;
- canonical handshake transcript construction;
- host identity fingerprint construction;
- negotiated context hashing;
- root-key derivation;
- transcript-bound lane-key derivation;
- rekey context/hash/key derivation.

Prefer Aeneas->Lean or hax/F* for exact safe-Rust source where tractable. A verification seam may be introduced only when it is the implementation used by production code; a copied verification-only encoder or KDF wrapper is forbidden.

Required relationships include:

- every security-relevant field is bound exactly once in the intended position/domain;
- role, schema, suite and policy labels are represented;
- host/viewer field order is unambiguous;
- lane labels are distinct and bound to derivation info;
- the canonical transcript hash is bound to installed lane keys;
- rekey state binds the base transcript, predecessor context/epoch, new epoch and reason;
- the identity fingerprint commits to both Ed25519 and ML-DSA verifying keys.

#### Canonical serialization decision

`HandshakeTranscriptV1` currently uses bincode-v1 canonical serialization. XEN-CRYPTO-FV-002 must either qualify the exact bincode-v1 shape used by the security subject or introduce a versioned explicit canonical encoding with migration and cross-vector evidence.

A serializer change is a semantic cryptographic change when transcript hashes/signatures depend on it.

### Plane P4 — executable state-machine proofs

Use Verus, Kani, Aeneas/Lean or another admitted tool according to the subject.

Initial subjects:

- replay-window bitmap semantics;
- nonce/sequence monotonicity and non-reuse conditions;
- key-epoch isolation;
- one-shot ephemeral decapsulation-key consumption;
- rekey transition ordering;
- lane/session state isolation;
- failure atomicity where cryptographic authority/state changes occur.

These are implementation theorems, not primitive-security proofs.

### Plane P5 — compiled/side-channel/runtime boundary

Constant-time and runtime properties remain separate.

Evidence may include:

- provider source-level secret-independence proofs;
- architecture-specific object-code proofs;
- compiler/assembly inspection;
- dudect-style statistical testing;
- zeroization/secret-lifetime evidence;
- exact target/toolchain profile.

Required distinctions:

```text
functional correctness != constant time
source constant time != compiled constant time
constant-time model != power/EM/fault resistance
no dudect signal != proof
zeroize API use != guaranteed physical erasure
```

## 4. Current provider baseline

The exact current dependency manifest/lockfile must be the source of truth. At architecture-freeze time the native handshake directly declares RustCrypto `ml-kem 0.3.0-rc.2`, `ml-dsa 0.1.1`, `ed25519-dalek 2`, HKDF/SHA-256, BLAKE3 and OS randomness. The lockfile binds concrete versions/checksums.

`xenia-wire` pins the same ML-KEM/ML-DSA versions for its independent browser/WASM handshake path and uses `chacha20poly1305 0.10` for session sealing.

The provider inventory must not infer assurance from version recency. Provider upgrades invalidate provider-specific evidence until requalified.

## 5. External high-assurance implementation policy

External proof artifacts are valuable as independent evidence/oracles, not as inherited marketing claims.

Candidate references include:

- `mlkem-native` for strongly verified native ML-KEM implementation/object-code evidence;
- libcrux ML-KEM/ML-DSA for Rust/hax/F* evidence where the exact current proof scope supports it;
- HACL*/EverCrypt for verified Ed25519, HKDF/SHA-2 and ChaCha20-Poly1305 reference implementations.

Every imported claim must include its exact version/revision and proof boundary. Published security advisories or verification-boundary findings are retained as part of provider provenance rather than hidden because a project is described as verified.

No provider migration occurs solely because another provider has more formal proofs. Compare the entire new trust boundary, including FFI/unsafe code, platform coverage, maturity, WASM support, side-channel evidence and operational maintenance.

## 6. Primitive-proof strategy

Xenia SHOULD NOT begin by re-proving complete FIPS 203 and FIPS 204 implementations from first principles.

The initial order is:

1. freeze exact primitive-provider evidence;
2. add authoritative standard vectors and independent cross-provider vectors;
3. prove the Xenia-owned composition/transcript/key-schedule/state code;
4. prove the protocol composition symbolically;
5. identify remaining primitive-provider gaps;
6. only then choose whether to verify a current provider directly, switch providers, or retain multiple independent providers/oracles.

Direct primitive proof is admitted when it closes a concrete assurance gap that imported evidence cannot economically close.

## 7. Cryptographic assumptions ledger

Every positive theorem/receipt must list relevant assumptions.

Initial assumption classes:

- ML-KEM security and correctness assumptions;
- ML-DSA/Ed25519 unforgeability assumptions;
- hash collision/preimage assumptions;
- HKDF PRF/extractor assumptions;
- AEAD confidentiality/integrity assumptions;
- OS/browser cryptographic RNG quality;
- private-key/ephemeral-key erasure assumptions;
- host storage integrity for TOFU pins;
- compiler/CPU assumptions for timing/zeroization claims;
- trust in formal translator/prover/solver boundaries.

A protocol theorem under assumptions does not establish that the runtime environment satisfies those assumptions.

## 8. TOFU theorem boundary

The identity fingerprint binds both classical and PQ signing identities, but TOFU has a structural first-contact limitation.

The target claim is intentionally shaped as:

```text
first contact:
  no pre-existing external authenticity guarantee

subsequent pinned contact:
  substituted signing identity -> pin mismatch
```

A future external trust root, QR ceremony, operator enrollment, DID binding or transparency mechanism may strengthen first contact, but must be modeled as an additional trust assumption/protocol step.

## 9. Forward-secrecy theorem boundary

The native handshake generates a fresh ML-KEM keypair per handshake and consumes/discards the decapsulation key after use. That architecture is intended to support secrecy of past sessions after later compromise of long-term signing state.

A positive formal claim requires all of:

- exact model of per-handshake ephemeral KEM generation;
- no retained recoverable decapsulation key after completion;
- explicit compromise timing;
- implementation/refinement evidence showing the production lifecycle matches the model;
- a clearly stated memory/zeroization limitation.

Do not abbreviate that result to generic `perfect forward secrecy` without the exact compromise model.

## 10. Native/WASM diversity boundary

The independent native and browser/WASM handshakes must be treated as two implementations of one protocol.

Cross-implementation evidence should compare deterministic vectors at every security boundary:

- messages;
- signature transcripts;
- transcript hashes;
- identity fingerprints;
- root/lane keys;
- context hashes;
- rekey derivations;
- malformed/downgrade rejection behavior.

Where possible, both implementations should refine the same abstract specification.

## 11. Documentation/evidence profile drift

Current-state documentation, exported evidence labels and implementation constants are part of the crypto evidence boundary.

A profile drift gate should compare at least:

- runtime suite/profile constants;
- dependency/provider manifest;
- transcript schema/profile labels;
- evidence/export labels;
- authoritative current-state documentation claims.

A mismatch is a review failure. Neither code nor prose silently wins.

This is motivated by an observed current drift: native code requires Ed25519+ML-DSA transcript signatures while some existing current-state documentation still describes the handshake as Ed25519-only/pre-PQC.

## 12. Negative controls

Formal qualification must demonstrate semantic sensitivity.

Initial mutation classes:

- replace AND signature policy with OR;
- omit ML-DSA or Ed25519 public key from identity/transcript binding;
- omit/rename/reorder suite/profile/domain labels;
- omit transcript hash from lane-key derivation;
- collide/reuse a lane label;
- reuse an ephemeral KEM decapsulation key;
- permit replayed handshake/rekey state;
- skip an epoch/predecessor binding;
- remove a mandatory input-validation/rejection rule;
- reuse evidence after provider/source/model drift.

Each mutant must have an expected detection point. Generic tool failure or parser failure is not semantic mutant detection.

## 13. Evidence composition

A high-assurance Xenia session may eventually compose evidence similar to:

```text
PrimitiveProviderEvidence
+ ProtocolSymbolicSecurity
+ EncodingTranscriptRefinement
+ StateMachineDeductiveProof
+ CrossImplementationConformance
+ SideChannelProfileEvidence
+ RuntimeQualification
```

Even that composition must preserve nonclaims about compiler correctness, hardware faults, physical side channels and assumptions not modeled.

## 14. Immediate PR sequence

```text
XEN-CRYPTO-FV-000  architecture / claim boundaries
XEN-CRYPTO-FV-001  exact primitive-provider assurance inventory
XEN-CRYPTO-FV-002  transcript + key-schedule refinement
XEN-CRYPTO-FV-003  Tamarin handshake/TOFU/rekey model
XEN-CRYPTO-FV-004  native <-> WASM semantic conformance
XEN-CRYPTO-FV-005  side-channel / compiled-boundary profile
XEN-CRYPTO-FV-006  crypto profile/documentation drift gate
```

Xenia-wire replay/nonce deductive proof work remains a parallel prerequisite for stronger end-to-end session claims.

## 15. Prohibited claim promotion

The following must remain explicit:

```text
formal model exists != property proved
property proved != model matches Rust
model matches Rust != primitive implementation proved
primitive implementation proved != protocol composition proved
source proof != binary proof
source secret independence != hardware side-channel resistance
hybrid PQ transcript auth != full-PQC system
PQC handshake != PQ-signed ledger/admin/identity root
verified dependency != verified application
```
