# Xenia Authenticated Peer Application Channel v1

Status: additive AEAD/replay ownership boundary stacked on `AuthenticatedPeerTransportV1`.

## Problem

The preceding boundaries establish increasingly strong facts:

```text
AuthenticatedPeerHandshakeV1
    = exact hybrid peer identity passed one real Xenia handshake

AuthenticatedPeerTransportV1<T>
    = that handshake is structurally attached to the exact owned carrier

PeerBoundInboundEnvelopeV1
    = opaque bytes were received on that same carrier under stable carrier semantics
```

But carrier receipt is not application-message authentication.

A downstream integration must not pair a `PeerBoundInboundEnvelopeV1` with an arbitrary or mismatched `xenia_wire::Session` by convention. Doing so would recreate the same state-substitution problem one layer deeper.

## Boundary

`AuthenticatedPeerApplicationChannelV1<T>` consumes one `AuthenticatedPeerTransportV1<T>` and one validated application payload type.

It privately creates and owns a fresh `xenia_wire::Session`, then installs the exact `HandshakeOutcome::session_key` from the owned authenticated handshake.

Xenia's current host and viewer handshake implementations define:

```text
key_schedule = derive_session_key_schedule(root_key, transcript_hash)
session_key  = key_schedule.aead
```

so this is the existing transcript-bound Xenia AEAD traffic key, not a new Content Fabric-specific KDF or parallel protocol.

The application channel exposes no:

- raw `xenia_wire::Session`;
- raw `AuthenticatedPeerTransportV1<T>`;
- `install_key`;
- arbitrary-payload open/seal;
- carrier split; or
- transport extraction.

Dropping the application channel drops both owned state machines.

## Payload-domain pinning

Xenia reserves payload types:

```text
0x00..=0x0f  mesh compatibility
0x10..=0x1f  Xenia core
0x20..=0x2f  Xenia extensions
0x30..=0xff  applications
```

`ApplicationPayloadTypeV1` accepts only `0x30..=0xff`.

One `AuthenticatedPeerApplicationChannelV1` is pinned to exactly one such type for its lifetime. Callers cannot select a different type per message.

This is important because xenia-wire's generic `open<T>` authenticates/replay-checks the envelope before typed deserialization. A caller must therefore never guess multiple application types by repeatedly attempting opens.

The channel instead performs:

```text
PeerBoundInboundEnvelopeV1
        |
        +-- inspect cleartext nonce payload_type
        |
        +-- require exact configured ApplicationPayloadTypeV1
        |       x mismatch: terminate before replay state changes
        |
        v
private WireSession::open
        |
        +-- AEAD verify current/previous key
        +-- replay-window accept exactly once
        |
        v
OpenedPeerApplicationPayloadV1
```

A wrong-domain envelope is rejected before `WireSession::open`, so it cannot consume replay state in this channel.

## xenia-wire open semantics relied upon

The current `xenia-wire 0.2.0-alpha.9` open path performs:

1. minimum envelope-length validation;
2. ChaCha20-Poly1305 verification against the current key, then still-valid previous keys;
3. identification of the exact key epoch that authenticated the envelope;
4. replay-window acceptance keyed by source, payload type, key epoch, and sequence;
5. applicable consent gating; and
6. plaintext release.

Replay state advances only after AEAD authentication succeeds. Replaying a previously accepted envelope fails before plaintext is returned.

The application channel relies on these semantics and owns the `WireSession` so another caller cannot mutate that replay state independently.

## Opened payload evidence

`OpenedPeerApplicationPayloadV1` is privately constructed and intentionally not `Clone`, `Copy`, serializable, `Default`, or constructible through `From`.

A successful value binds together:

- AEAD-authenticated/replay-accepted plaintext;
- exact application payload type;
- carrier receive sequence;
- hybrid handshake transcript generation;
- negotiated context hash when present;
- exact Ed25519 peer key authenticated by that handshake;
- exact ML-DSA-65 peer key authenticated by that handshake; and
- exact stable transport profile observed for carrier receipt.

The token is request evidence, not a reusable credential.

### Logging/privacy rule

Authenticated plaintext is potentially sensitive. The opened token must not provide an auto-derived `Debug` implementation that dumps plaintext. Callers receive bytes deliberately through `plaintext()`.

## What successful open proves

A successful opened token establishes, in one owned composition:

```text
real Xenia hybrid peer authentication
        +
same exact owned carrier
        +
stable carrier profile during receipt
        +
exact configured application payload domain
        +
ChaCha20-Poly1305 authentication
        +
replay-window acceptance
```

This is materially stronger than any detached combination of a transcript hash, public keys, raw plaintext, and an arbitrary transport/session object.

## What successful open does NOT prove

It does not establish:

- that the plaintext decodes as a valid application request;
- that application invariants/schema validation pass;
- a Mycelix `PartyIdV1`;
- Mycelix group membership;
- permission to disclose a Content Fabric object;
- Nix trust/signature authorization;
- remote persistence/liveness after this receive; or
- permission to replay the same semantic operation at the application layer.

The next adapter must validate one expected application schema and then perform an explicit enrollment lookup over the exact authenticated hybrid key pair.

It must not respond to a schema-decode failure by trying another authority-bearing payload domain after replay state was accepted.

## Failure policy

This is a dedicated authority-bearing channel, so v1 fails closed and terminalizes on:

- underlying authenticated-transport failure;
- carrier/profile failure inherited from `AuthenticatedPeerTransportV1`;
- impossible carrier-binding mismatch;
- wrong/missing payload-type domain;
- AEAD open failure;
- replay rejection;
- wire/consent failure; or
- seal/send failure.

After terminalization later send/receive operations return `Terminal`.

A fresh connection + handshake is required instead of attempting to recover potentially ambiguous authority state.

## Rekey boundary

v1 intentionally exposes no public `install_key` or rekey mutator.

The private wire session is initialized with the handshake's current transcript-bound `schedule.aead` key and retains that key for this application-channel lifetime.

This means v1 is appropriate only for the short-lived/pre-production authority channel being qualified here. It does **not** claim long-lived forward-secure application-channel rekeying.

A future rekey tranche must bind:

- rekey generation/evidence;
- exact authenticated connection generation;
- both endpoints' key transition;
- replay-window epoch transition; and
- failure/rollback behavior

before a public rekey API is added.

## Content Fabric composition

The intended later Mycelix bridge becomes:

```text
AuthenticatedPeerApplicationChannelV1<T>
        |
        v
OpenedPeerApplicationPayloadV1
        |
        +-- validate exact Content Fabric request schema
        |
        +-- exact authenticated Ed25519 + ML-DSA-65 pair
        |
        v
CF-07C1 ReaderEnrollmentRegistryV1
        |
        v
explicit PartyIdV1 + groups
        |
        v
request-scoped RemoteReaderV1
        |
        v
CF-07A RemoteServingSnapshotV1
        |
        v
CF-03 cryptographically verified bytes
```

Nix signing/trusted-key authorization remains independent of every layer above.

## Tests required for v1

The executable unit model pins:

- Xenia-reserved payload types are rejected;
- full application range endpoints are accepted;
- wrong payload domain is rejected before replay mutation;
- the same wrong-domain envelope can still be opened by the correct domain afterward;
- successful AEAD/replay open succeeds once;
- replaying the exact accepted envelope fails;
- ciphertext/tag tampering fails; and
- too-short envelopes fail at the domain gate before wire open.

The full `xenia-peer-core` build also type-checks the ownership composition against `AuthenticatedPeerTransportV1<T>` and `AuthenticatedPeerHandshakeV1`.
