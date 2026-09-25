# Handshake Transcript Encoding V1

This document freezes the exact current serialization boundary behind `HandshakeTranscriptV1::canonical_bytes()` for XEN-CRYPTO-FV-002B.

## Qualified subject

The current production path is:

```text
HandshakeTranscriptV1
  -> bincode::serialize(transcript)
  -> canonical bytes
  -> BLAKE3-256
  -> transcript hash
```

The schema label is `xenia-handshake-transcript-v1` and the hash algorithm label is `blake3-256`.

## Resolved serializer identity

For this tranche the exact Cargo.lock identities are:

- bincode `1.3.3`
  - source: `registry+https://github.com/rust-lang/crates.io-index`
  - checksum: `b1f45e9417d87227c7a56d22e471c6206462cba514c7590c09aff4cf6d1ddcad`
- serde `1.0.228`
  - source: `registry+https://github.com/rust-lang/crates.io-index`
  - checksum: `9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e`
- serde_core `1.0.228`
  - checksum: `41d385c7d4ca58e59fc732af25c3983b67ac852c1a25000afe1175de458b67ad`
- serde_derive `1.0.228`
  - checksum: `d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79`

The dependency declaration `bincode = "1.3"` is therefore not the cryptographic identity. The lockfile resolution above is.

## Bincode helper-function semantics

This code uses the root `bincode::serialize` helper, not `DefaultOptions::new()` directly.

For bincode 1.3.x helper-function compatibility, the relevant legacy format is fixed-width integer encoding with architecture-independent byte ordering. Struct fields are serialized in declaration order and strings/Vec lengths are represented as fixed-width lengths. This tranche freezes that exact helper path rather than replacing it with a new explicit configuration.

Changing to a different bincode API/configuration is a transcript-format change unless byte identity is mechanically demonstrated.

## Exact field order

The canonical struct order is:

1. `schema: String`
2. `kem: String`
3. `transcript_signature: String`
4. `kdf: String`
5. `negotiated_context_hash: Option<[u8; 32]>`
6. `host_ed25519_pk: [u8; 32]`
7. `viewer_ed25519_pk: [u8; 32]`
8. `host_ml_dsa_pk: Vec<u8>`
9. `viewer_ml_dsa_pk: Vec<u8>`
10. `host_kem_pk: Vec<u8>`
11. `kem_ciphertext: Vec<u8>`
12. `host_nonce: [u8; 32]`
13. `viewer_nonce: [u8; 32]`
14. `viewer_signature: Vec<u8>`
15. `host_signature: Vec<u8>`
16. `viewer_ml_dsa_signature: Vec<u8>`
17. `host_ml_dsa_signature: Vec<u8>`

Any reorder, insertion, removal, type change, Option-layout change, length-encoding change, endian change, or serializer change is security-relevant transcript drift.

## Current claim

This tranche establishes an exact implementation/serializer census and fail-closed drift gate. It does not yet claim universal byte-level refinement of bincode, and it does not replace the current format.

The successor should add full golden byte streams and hashes for deterministic fixtures on native and wasm32. Only after those vectors exist should the project choose between formally refining the current bincode-v1 format or introducing a future explicitly specified encoding under a new transcript schema.

## Non-equivalences

```text
same Rust field values
!= same canonical bytes under an arbitrary serializer

bincode 1.3.3 lock identity
!= proof of every serialized byte

golden fixture agreement
!= universal serializer refinement

exact transcript bytes
!= BLAKE3 collision-resistance proof
!= signature security
!= handshake authentication theorem
```
