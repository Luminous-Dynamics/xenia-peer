# Xenia Crypto Provider External Evidence v1

Status: dated external-evidence snapshot; semantic child of Provider Assurance v1.

This contract attaches mutable outside evidence to the exact dependency identities frozen in `provider_assurance_v1.json`.

The snapshot date is `2026-09-25`. Every record in the machine-readable snapshot inherits that top-level observation date unless a future schema adds a per-record override. CI deliberately performs **no live network fetch**: historical qualification must remain reproducible, and changing web pages must not silently change an old receipt.

## Two roots, two jobs

`provider_assurance_v1.json` is the immutable local identity root:

```text
name + version + registry source + checksum
```

`provider_external_evidence_v1.json` is a dated research snapshot:

```text
identity reference
+ evidence class
+ source URL
+ scoped observed claim
+ applicability
+ disposition
+ claim ceiling
```

Never copy a mutable external assurance verdict back into the identity root.

## Standards are versioned evidence too

FIPS publication names are not sufficient provenance. The snapshot records the observed NIST publication date plus current errata/planning-note state for FIPS 203 and FIPS 204.

A theorem or vector suite that says only “against FIPS 203” without identifying the interpretation/errata state can become ambiguous as the standard evolves.

## Current RustCrypto posture

The exact locked RustCrypto ML-KEM and ML-DSA identities are referenced by their 001A checksum tuples.

The observed upstream documentation for both provider families says they have not been independently audited. This is recorded as an assurance gap, not as a vulnerability claim.

For ML-DSA, published 2026 advisory ranges are recorded conservatively. The locked `0.1.1` identity is outside the affected ranges published for the three captured January advisories. The permitted conclusion is only:

```text
locked version outside published affected range
```

not:

```text
safe
constant-time
FIPS-correct
free of other defects
```

## ML-KEM upgrade question

The locked Xenia identity remains `ml-kem 0.3.0-rc.2`. Current observed stable is newer, and the final 0.3.0 changelog records additional validation fixes and Wycheproof coverage.

The snapshot intentionally classifies exact rc.2 applicability as unresolved. We must determine source ancestry and/or run executable differential vectors rather than inferring that all final-release changes were or were not present in the release candidate.

An upgrade therefore needs a delta receipt, not a version-number argument.

## Oracle candidates

### mlkem-native

The project reports a strong but bounded verification story: CBMC for C memory/type safety and HOL Light proofs for selected architecture-specific functional correctness, memory safety, and secret-independent timing. Its own scope notes matter.

Use first as an independent ML-KEM oracle. A production migration would add a C/FFI/compiler/integration boundary that must be qualified independently.

### rust-libcrux / libcrux

The project reports hax/F* verification across documented portable/AVX2 ML-KEM components. This is promising for an independent Rust oracle.

The snapshot also records a 2026 libcrux ML-DSA AVX2 advisory as a structural warning: “formally verified project” is not a sufficient scope statement. Exact release, code path, assumptions, and proof coverage are required.

### HACL*/EverCrypt

The supported-algorithms documentation identifies completed verification for several classical primitives relevant to Xenia, including Ed25519, SHA-2, HKDF, and ChaCha20-Poly1305. These are useful independent reference/oracle candidates; they do not make Xenia’s Rust implementations verified.

## Executable successor

The next 001B tranche should turn the research snapshot into deterministic differential evidence.

Priority ML-KEM cases:

- known-answer key generation / encapsulation / decapsulation;
- invalid encapsulation-key rejection;
- serialized/expanded key validation where exposed;
- modified ciphertext / implicit rejection;
- exact provider/version identity in every receipt.

Priority ML-DSA cases:

- valid/invalid standard vectors;
- repeated hint indices;
- `UseHint` r0=0 edge behavior;
- tampered public key, signature, and message;
- cross-provider sign/verify interoperability where semantics permit it.

Functional vectors and target-specific timing evidence remain separate result classes.

## CI invariants

The snapshot validator must fail if:

- a provider reference does not exactly match 001A name/version/checksum;
- a provider-bound record silently points to another version;
- an advisory range assessment is strengthened to a general “safe” verdict;
- an oracle candidate is marked as the selected production provider;
- live-network checking is enabled in the reproducible CI contract;
- assurance scope is promoted into protocol/formal-security language.

## Governing non-equivalences

```text
published advisory range says not affected != independently audited
formal proof of provider component != proof of provider integration != proof of Xenia protocol
cross-provider vector agreement != computational security proof
newer provider version != stronger assurance until requalified
external evidence snapshot != permanently current truth
```

## Claim ceiling

A PASS establishes that this dated evidence snapshot is structurally conservative and correctly bound to the exact local provider identities. It does not independently validate the external sources, prove a primitive, prove the Xenia handshake, or establish production suitability.
