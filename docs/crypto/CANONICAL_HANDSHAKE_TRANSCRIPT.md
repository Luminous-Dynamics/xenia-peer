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
- optional negotiated session context hash
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

The installed traffic keys are no longer the raw hybrid KEM/HKDF output. The
handshake first derives a 32-byte root key from `host_nonce || viewer_nonce` and
the ML-KEM shared secret, then derives the default AEAD key with:

- `salt = xenia-session-key-schedule-v1`
- `ikm = root_key`
- `info = xenia/session/aead || ":" || canonical_transcript_hash`

The same schedule derives distinct transcript-bound keys for control, video,
audio, telemetry, rekey, and negotiated-context lanes. The daemon and viewer now
use `LaneSession`, which composes one `xenia-wire::Session` per forward-path
lane. Capabilities and rekey messages are sealed with the control key, display
frames with the video key, audio frames with the audio key, and telemetry frames
with the telemetry key. This keeps the sealed-envelope transport unchanged while
preventing one lane key from opening another lane's traffic.

`LaneSession` wraps each sealed `xenia-wire` envelope in a small cleartext lane
header:

- magic: `XLN1`
- lane tag: `0 = control`, `1 = video`, `2 = audio`, `3 = telemetry`
- body: the sealed `xenia-wire` envelope for that lane

The lane envelope version and magic are advertised in `RawCapabilities`, so
they are included in the negotiated session context hash carried by `HostHello`
and signed into the handshake transcript. The viewer rejects unsupported lane
envelope versions after validating that the sealed capabilities match the
transcript-bound context hash.

The lane tag is dispatch metadata, not trusted plaintext. After decryption, the
receiver verifies that the decoded `RawFrame::pixel_format` belongs to the
declared lane, so changing an audio tag to video fails instead of falling back
to another key. Unwrapped envelopes are accepted only as a local compatibility
path for pre-lane tests and older peers.

Handshake signatures also use a length-prefixed domain-separated transcript
prefix containing:

- `xenia-handshake-signature-v1`
- `xenia-handshake-transcript-v1`
- `hybrid-pre-pqc-v1`
- `ml-kem-768-fips203`
- `ed25519-rfc8032`
- `hkdf-sha256`

This binds the live signature transcript to the suite/profile context and makes
suite downgrade or transcript-shape confusion visible as signature failure or a
different canonical transcript hash.

## Negotiated Session Context

The daemon computes the selected runtime context before sending `HostHello`.
That context hash is included in `HostHello`, signed by both sides through the
ordinary handshake signature transcript, and serialized into
`HandshakeTranscriptV1`. Therefore the final canonical transcript hash and the
installed traffic key both change when selected transport or capabilities
change.

The negotiated context flow is:

- the daemon builds the exact `RawCapabilities` payload it will send first;
- the daemon computes `blake3-256(bincode(NegotiatedSessionContextV2))`;
- the context includes `schema = xenia-negotiated-session-context-v2`, selected
  transport, and the typed capabilities payload;
- the capabilities payload commits to the exact telemetry disclosure, audio
  source category, input authority, clipboard direction, file-transfer
  direction, video format, audio advertisement, and lane-envelope contract;
- the context hash is carried in `HostHello`;
- both sides include that value in the signed transcript and canonical
  transcript;
- the daemon sends sealed `RawCapabilities` as the first control frame after
  handshake;
- the viewer recomputes the context hash from the sealed capabilities and
  rejects a mismatch;
- the viewer rejects media before sealed capabilities are accepted.

This keeps capability negotiation explicit without adding another round trip.
Future protocol versions can replace the optional field with a required context
hash once all compatibility wrappers are removed.

## Rekey Epochs

After capabilities are accepted, the daemon performs sealed rekey control
exchanges through `SessionEpochState`:

- host sends `RawRekey::Proposal` under epoch 0;
- proposal includes `key_epoch`, base transcript hash, previous epoch hash,
  typed reason, and canonical rekey epoch hash;
- both sides derive per-lane epoch keys from the transcript-bound
  `xenia/session/rekey` lane and `RekeyEpochContextV1`;
- viewer validates next-epoch ordering, base transcript hash, previous epoch
  hash, and epoch hash before installing the new lane key set;
- viewer sends `RawRekey::Ack` under the new control-lane key;
- host validates the ack under the new control-lane key before sending or
  continuing media.

Epoch 0 is the initial transcript-bound traffic key. Epoch 1 is triggered before
the first media frames. The smoke policy then triggers epoch 2 after four video
frames, proving media survives repeated epoch rotation across TCP, WebSocket,
and QUIC. `SessionEpochState` tracks current epoch, base transcript hash,
previous epoch hash, per-epoch video/audio/byte counters, and rejected rekey
count.

Future work should add production frame-count/byte-count/time thresholds,
admin-triggered manual rekey, telemetry export for epoch counters, and a small
old-key overlap window only if a measured transport requires it.

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
5. tampering host hello, KEM ciphertext, or viewer signature fails signature
   verification;
6. installed lane keys are derived from the root key plus canonical transcript
   hash, not directly from the KEM/HKDF root key.
7. selected transport and sealed capabilities are represented by the negotiated
   context hash inside `HostHello` and `HandshakeTranscriptV1`;
8. viewer rejects media before capabilities and rejects capabilities whose
   recomputed context hash differs from the transcript-bound value.
9. rekey epoch lane keys are deterministic, distinct from epoch 0, and bound to
   transcript hash, previous epoch hash, epoch number, and reason.
10. live TCP, WebSocket, and QUIC smokes pass after epoch 1 and epoch 2
    proposal/ack rekey exchanges.
