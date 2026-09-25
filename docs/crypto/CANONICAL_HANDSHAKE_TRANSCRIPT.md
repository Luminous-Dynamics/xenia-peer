# Xenia Canonical Handshake Transcript

Status: pre-production evidence contract.

This note binds Xenia's canonical handshake transcript to the **current live handshake surface**. It must be read together with `CURRENT_CRYPTO_SURFACE_V1.md`: the live handshake is currently `hybrid-pq-transcript-v1`, while the stable long-lived ledger/evidence path remains a separate `hybrid-pre-pqc-v1` surface.

## Canonical shape

`xenia-handshake` defines `HandshakeTranscriptV1` with:

- `schema = xenia-handshake-transcript-v1`
- `kem = ml-kem-768-fips203`
- `transcript_signature = ed25519-rfc8032+ml-dsa-65-fips204`
- `kdf = hkdf-sha256`
- optional negotiated session context hash
- host and viewer Ed25519 public keys
- host and viewer ML-DSA-65 public keys
- host ML-KEM-768 public key
- viewer ML-KEM-768 ciphertext
- host and viewer nonces
- viewer Ed25519 and ML-DSA-65 transcript signatures
- host Ed25519 and ML-DSA-65 finalize signatures

The canonical bytes are `bincode` v1 serialization of that structure. The canonical hash is `blake3-256(canonical_bytes)`.

## Authentication rule

The current live handshake accepts transcript authentication only when both signature systems verify:

```text
Ed25519 valid
AND
ML-DSA-65 valid
```

There is no classical-only fallback in the current live `hybrid-pq-transcript-v1` handshake path. This AND composition is a handshake-runtime property; it must not be confused with the separate singular `SessionTranscriptSignature` artifact currently used by the long-lived evidence/ledger v1 boundary.

Handshake signatures use a length-prefixed domain-separated prefix containing:

- `xenia-handshake-signature-v1`
- `xenia-handshake-transcript-v1`
- `hybrid-pq-transcript-v1`
- `ml-kem-768-fips203`
- `ed25519-rfc8032+ml-dsa-65-fips204`
- `hkdf-sha256`

Changing the profile, suite label, transcript shape, key material, ciphertext, nonce, role, or negotiated context changes the signed bytes and/or canonical transcript hash.

## Runtime key schedule

`xenia-peer-core` exposes transcript-returning handshake entry points. The live handshake derives a root key from the nonces and ML-KEM shared secret, then derives transcript-bound lane keys with:

```text
salt = xenia-session-key-schedule-v1
ikm  = root_key
info = lane_label || ":" || canonical_transcript_hash
```

The current lane labels separate at least default AEAD, control, video, audio, telemetry, rekey, and negotiated-context purposes. Distinct lane labels are intended to prevent a key derived for one lane from being reused as another lane's traffic key.

## Negotiated session context

The selected runtime context is computed before `HostHello` is finalized. Its hash is carried in the handshake, covered by both transcript-signature systems, and serialized into `HandshakeTranscriptV1`.

The current flow therefore binds the canonical transcript to the selected transport/capability context rather than only to the KEM exchange.

## Rekey epochs

Post-handshake rekey state is separately bound to the base transcript and previous epoch state. The rekey path must preserve ordering, previous-epoch continuity, and transcript identity; proving those properties is a separate state-machine/formal-verification subject rather than a consequence of this document.

## Evidence-boundary distinction

The live handshake and long-lived evidence layer intentionally remain separate current crypto surfaces:

```text
live handshake
  profile = hybrid-pq-transcript-v1
  transcript auth = ALL-OF(Ed25519, ML-DSA-65)

stable ledger/evidence default
  profile = hybrid-pre-pqc-v1
  ledger signature = Ed25519
  default evidence transcript-signature artifact = Ed25519
```

The evidence layer's `SessionTranscriptBinding` can carry the canonical handshake hash, but its current v1 transcript-signature artifact does not by itself encode the handshake's dual-signature acceptance policy. XEN-CRYPTO-FV-008 tracks a versioned composite-authentication evidence shape for that stronger statement.

## Full-PQC boundary

The live handshake having mandatory ML-DSA alongside Ed25519 does **not** make Xenia `full-pqc-v1`.

Full-PQC remains false because, among other separately gated surfaces:

- Ed25519 remains part of the live handshake identity/authentication composition;
- the stable default ledger append path remains Ed25519;
- admin/root/policy authority migration remains incomplete;
- optional PQ evidence backends do not silently change the default append authority.

## Reviewer checklist

A reviewer should confirm:

1. the current handshake profile is `hybrid-pq-transcript-v1`;
2. the canonical transcript suite is `ed25519-rfc8032+ml-dsa-65-fips204`;
3. both host and viewer ML-DSA public keys are represented in the canonical transcript;
4. both Ed25519 and ML-DSA transcript/finalize signatures are required by the live handshake;
5. the canonical transcript hash remains `blake3-256` over the versioned canonical bytes;
6. installed lane keys remain transcript-bound and domain separated;
7. negotiated session context remains covered by the authenticated transcript;
8. `full-pqc-v1` remains unavailable under the current aggregate crypto surface;
9. evidence/ledger v1 is not relabeled as dual-signature merely because the live handshake is;
10. any future claim of native/WASM equivalence is tied to the separate cross-repository conformance evidence lane.

## Claim ceiling

This document specifies the current handshake transcript contract. It does not prove primitive security, protocol secrecy/authentication, native/WASM refinement, constant-time behavior, compiler correctness, or deployment qualification.
