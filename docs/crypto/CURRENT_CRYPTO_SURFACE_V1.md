# Xenia Current Crypto Surface v1

Status: source-bound current-state contract.

This document defines **which cryptographic migration stage applies to which Xenia surface**. It exists because one global label is no longer accurate: the live handshake has advanced to mandatory hybrid post-quantum transcript authentication, while the stable consent-ledger/evidence append path remains Ed25519 by default.

The machine-readable source of this contract is `current_crypto_surface_v1.json`. `scripts/validate_current_crypto_surface_v1.py` checks that registry against exact production-source constants and runs controlled negative mutations.

## Current surfaces

### Native handshake runtime

The production `xenia-handshake` subject is currently:

```text
profile             = hybrid-pq-transcript-v1
KEM                 = ml-kem-768-fips203
transcript auth     = ALL-OF(
                        ed25519-rfc8032,
                        ml-dsa-65-fips204
                      )
combined suite      = ed25519-rfc8032+ml-dsa-65-fips204
KDF                 = hkdf-sha256
transcript schema   = xenia-handshake-transcript-v1
transcript hash     = blake3-256
```

Both signature algorithms are required by the current handshake. This is stronger than the historical `hybrid-pre-pqc-v1` handshake profile, but it is still **not** the repository-wide `full-pqc-v1` target because Ed25519 remains part of the live authentication identity and other authority surfaces have not all migrated.

### Browser/WASM-capable viewer handshake

`Luminous-Dynamics/xenia-wire` contains a separate viewer-side handshake implementation intended to match the native handshake with the same hybrid-PQ transcript profile. Because that implementation lives in another repository, this registry records it as an **external conformance dependency**, not as locally proved source state.

`XEN-CRYPTO-FV-004` / xenia-peer issue #399 owns the stronger native↔WASM semantic-conformance evidence.

### Stable ledger and long-lived evidence path

The default `xenia-ledger` append/evidence path is currently:

```text
policy profile                = hybrid-pre-pqc-v1
current ledger signature      = ed25519-rfc8032
default evidence transcript
signature artifact            = ed25519-rfc8032
hash chain                    = blake3-256
```

`xenia-ledger` also contains optional ML-DSA evidence-signature verification/building support behind the `pqc-signatures` feature. That capability does **not** silently change the default `Chain::append` signature suite or make the default evidence path post-quantum.

The evidence-layer `SessionTranscriptSignature` must not be confused with the live handshake's internal dual signatures. They are different artifacts at different boundaries.

## Aggregate current state

The aggregate current status is deliberately described as:

```text
mixed-migration-v1
full_pqc = false
```

This is a descriptive census label, **not another runtime crypto policy profile**.

The current state can therefore be summarized as:

```text
live handshake
  = PQ key establishment
  + mandatory classical+PQ transcript authentication

stable ledger/evidence append
  = classical Ed25519 by default
  + optional PQ evidence backend capability

aggregate
  != full-PQC
```

## Invariants

The validator freezes these distinctions:

```text
handshake profile != ledger/evidence profile

hybrid PQ transcript authentication
!= full-PQC authority

optional ML-DSA evidence backend
!= PQ default ledger append

external xenia-wire implementation claim
!= local xenia-peer source proof

source/profile consistency
!= cryptographic security theorem
```

## Negative controls

The validator mutates an in-memory copy of the canonical registry and requires rejection when:

1. the native handshake combined transcript suite is weakened to Ed25519-only;
2. the default ledger signature is relabeled ML-DSA while production still says Ed25519;
3. the ledger/evidence profile is collapsed into the live handshake profile;
4. aggregate `full_pqc` is changed to `true`.

A generic parser failure does not satisfy these controls; each mutant must reach the semantic registry checks and be rejected there.

## Successor

`XEN-CRYPTO-FV-006B` should repair stale current-state prose and package/module descriptions against this registry, including:

- `CANONICAL_HANDSHAKE_TRANSCRIPT.md`;
- `FULL_PQC_MIGRATION_PLAN.md`;
- `xenia-handshake` package description;
- stale `xenia-handshake` module/error wording.

That documentation repair must preserve the scope distinction above rather than replacing one stale global label with another.

## Claim ceiling

A PASS of this contract means only that the declared current crypto surfaces agree with the selected production-source identities under this validator. It does not establish primitive security, protocol secrecy/authentication, source refinement, constant-time behavior, compiler correctness, or deployment qualification.
