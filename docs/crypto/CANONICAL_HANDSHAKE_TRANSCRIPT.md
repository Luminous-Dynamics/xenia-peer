# Xenia Canonical Handshake Transcript

Status: pre-production evidence contract.

This note closes the gap between transcript-bound ledger evidence and the real
handshake runtime. `xenia-ledger` can verify a `SessionTranscriptBinding`, but
the binding is only trustworthy when the hash comes from a canonical transcript
emitted by the handshake/session layer.

## Canonical shape

`xenia-handshake` now defines `HandshakeTranscriptV1` with:

- `schema = xenia-handshake-transcript-v1`
- `kem = ml-kem-768-fips203`
- `transcript_signature = ed25519-rfc8032` for the current hybrid/pre-PQC build
- `kdf = hkdf-sha256`
- host and viewer Ed25519 public keys
- host ML-KEM-768 public key
- viewer ML-KEM-768 ciphertext
- host and viewer nonces
- viewer transcript signature
- host finalize signature

The canonical bytes are `bincode` v1 serialization of that structure. The
canonical hash is `blake3-256(canonical_bytes)`.

## Runtime rule

`xenia-peer-core` exposes:

```rust
perform_host_handshake_with_transcript(...)
perform_viewer_handshake_with_transcript(...)
```

Both return a `HandshakeOutcome` containing the session key and the canonical
`transcript_hash`. The legacy `perform_*_handshake(...) -> [u8; 32]` helpers are
kept as compatibility wrappers.

The daemon path now binds the returned transcript hash into `M1RuntimeSession`
before recording the first M1 consent event. The M1 runtime can then export a
`SessionTranscriptBinding` and verify the manifest, binding, and exported ledger
entries as one transcript-bound evidence bundle.

## What this improves

Before this contract, a caller could provide arbitrary bytes to the ledger
binding helper. After this patch, the ordinary daemon handshake path has a real
canonical transcript hash from the actual exchanged handshake artifacts.

This still does not move the signature layer to the final PQ profile. The current transcript
signature suite remains `ed25519-rfc8032` until ML-DSA/SLH-DSA signing and
verification land. The important improvement is that evidence now has a stable
runtime-produced hash that can later be authenticated by a PQ signature suite
without another schema break.

## Reviewer checklist

A reviewer should confirm:

1. host and viewer compute the same transcript hash in loopback tests;
2. the M1 runtime stores the real handshake hash before `offer()`;
3. transcript-bound evidence verification rejects missing bindings;
4. `full-pqc-v1` still rejects classical transcript signatures.
