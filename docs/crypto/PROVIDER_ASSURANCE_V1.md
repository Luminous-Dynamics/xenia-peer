# Xenia Crypto Provider Assurance v1

Status: exact local dependency-identity contract.

This contract answers one narrow question: **which exact cryptographic provider artifacts does this Xenia source tree resolve?**

The machine-readable source is `provider_assurance_v1.json`. The companion validator checks it against `Cargo.lock`, the direct `xenia-handshake` and `xenia-ledger` requirements, and the workspace `xenia-wire` requirement.

## Assurance class

This tranche is deliberately `identity-only`.

A successful check establishes that the recorded package names, resolved versions, crates.io source identities, checksums, selected direct requirements, and selected feature relationships agree with the repository subject.

It does not establish that a package is:

- independently audited;
- formally verified;
- free of known or unknown vulnerabilities;
- constant-time on a given target;
- side-channel resistant;
- correctly compiled;
- preferable to another provider;
- sufficient to make the Xenia protocol secure.

Those changing external claims belong in XEN-CRYPTO-FV-001B and must be bound back to the exact identities frozen here.

## Provider roles

The registry classifies dependencies by role rather than treating all crypto crates as equivalent:

- ML-KEM: key encapsulation provider;
- ML-DSA: post-quantum signature provider;
- Ed25519-dalek: classical signature provider;
- HKDF/SHA-2: key-derivation/hash substrate;
- BLAKE3: transcript/fingerprint/hash-chain substrate;
- rand/rand_core/getrandom: native randomness/OS entropy path;
- zeroize: secret-erasure support;
- ChaCha20-Poly1305: AEAD provider through the wire layer;
- xenia-wire: transport/crypto-wrapper boundary whose resolved artifact is itself part of the assurance subject.

A role label is descriptive. It is not an assurance score.

## Requirement versus resolution

Cargo dependency requirements and locked artifacts are recorded separately.

For example:

```text
ml-kem requirement = 0.3.0-rc.2
resolved artifact  = 0.3.0-rc.2 + exact crates.io checksum

ed25519-dalek requirement = 2
resolved artifact          = 2.2.0 + exact crates.io checksum
```

The distinction is contractual:

```text
Cargo requirement != resolved package
```

Changing a version range without changing the selected lock artifact is still reviewable dependency drift. Changing a lock artifact without updating the assurance manifest is also drift.

## Entropy boundary

The current native handshake uses `rand::rngs::OsRng`. The frozen graph therefore includes the relevant `rand`, `rand_core`, and `getrandom` identities. This contract records that dependency path only; it does not prove OS entropy quality, VM entropy quality, browser entropy behavior, or runtime availability.

## xenia-wire boundary

The workspace currently consumes a crates.io `xenia-wire` release. Its exact locked artifact and expected crypto-dependency subset are therefore recorded here.

This is not equivalent to proving the separate xenia-wire repository source tree is identical to, or semantically equivalent to, the locked crate artifact. Native/WASM and cross-repository conformance remain separate evidence lanes.

## Negative controls

The validator must reject semantic in-memory mutations for at least:

1. the ML-KEM checksum;
2. the ML-DSA resolved version;
3. the xenia-wire checksum;
4. an `assurance_scope` stronger than `identity-only`.

A syntax/parser failure does not satisfy these controls: each mutant must remain structurally valid and fail an assurance invariant.

## Successor evidence

XEN-CRYPTO-FV-001B should add dated, source-cited evidence for:

- standards and errata;
- independent audits;
- test vectors/interoperability vectors;
- known advisories and exact-version applicability;
- formal-verification boundaries;
- constant-time/side-channel evidence;
- alternative/oracle providers;
- native versus WASM differences.

Those records should reference the provider identity they apply to rather than replacing this manifest.

## Governing non-equivalences

```text
Cargo requirement != resolved package
resolved package != audited package
resolved package != formally verified package
provider identity != protocol security
provider upgrade != stronger assurance until requalified
```

## Claim ceiling

A PASS establishes local dependency-identity consistency on the exact checkout only. It is not a cryptographic proof or a provider-quality verdict.
