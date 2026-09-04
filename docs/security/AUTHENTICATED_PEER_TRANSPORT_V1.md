# Xenia Authenticated Peer Transport v1

Status: additive same-transport ownership boundary stacked on `AuthenticatedPeerHandshakeV1`.

## Problem

`AuthenticatedPeerHandshakeV1` proves which hybrid peer identity Xenia authenticated during one completed host handshake. It intentionally does not prove that later bytes came from the same carrier instance.

Keeping these values side by side is not enough:

```text
AuthenticatedPeerHandshakeV1 from transport A
        +
mutable transport B
        x
same authenticated connection
```

A downstream authority adapter must not depend on callers to preserve that pairing by convention.

## Ownership boundary

`perform_host_handshake_authenticated_transport_v1(...)` takes the transport **by value**.

It captures the exact:

- `TransportProfileV1`;
- `TransportPreSessionProfileV1`; and
- `TransportAvailabilityProfileV1`

before running the real hybrid host handshake.

After the handshake succeeds, all three profiles must still equal their pre-handshake values. Any drift drops the transport and returns no authenticated wrapper.

On success the result is:

```text
AuthenticatedPeerTransportV1<T> {
    exact owned T,
    AuthenticatedPeerHandshakeV1,
    bound transport profiles,
    private wrapper binding nonce,
    receive evidence sequence,
    terminal state
}
```

There is no public raw `&mut T`, split method, or `into_transport()` escape hatch. Dropping the wrapper drops the carrier.

## Not a perpetual liveness claim

Owning a transport object is not proof that the remote peer remains connected forever.

Therefore the wrapper itself is not named a live-session token and its mere existence must not authorize a request.

Same-carrier receipt evidence is minted only after:

```text
profile checks
      |
      v
successful Transport::recv_envelope()
      |
      v
profile checks again
      |
      v
PeerBoundInboundEnvelopeV1
```

A transport error is session-fatal and terminalizes the wrapper.

## Carrier receipt is not AEAD authentication

`Transport::recv_envelope()` returns opaque Xenia carrier-envelope bytes. This layer does **not** run xenia-wire AEAD open, replay-window mutation, payload-domain verification, or semantic decoding.

Therefore:

```text
PeerBoundInboundEnvelopeV1
        = same owned peer-bound carrier received these opaque bytes

PeerBoundInboundEnvelopeV1
        != application message cryptographically authenticated
```

A downstream adapter MUST still open the bytes through the correct xenia-wire session/replay state and validate the expected payload domain/schema before any application semantic or Content Fabric authorization decision trusts their contents.

This distinction is reflected in the type name: the token is **peer-bound**, not `AuthenticatedInboundEnvelope`.

## Profile stability around I/O

Every send and receive checks the exact bound transport/pre-session/availability profiles before I/O and again after successful I/O.

For receive, if any profile changes while the operation is in flight, the received bytes are discarded and no peer-bound inbound token is released.

This makes the admitted carrier semantics:

```text
same owned transport object
        +
same exact profile contract before/after I/O
```

rather than merely the same coarse TCP/WebSocket/QUIC kind.

## One-wrapper inbound evidence

`PeerBoundInboundEnvelopeV1` is:

- privately constructed;
- non-`Clone`;
- non-`Copy`;
- non-serializable;
- bound to the handshake transcript hash;
- bound to a private random nonce unique to the wrapper instance; and
- assigned a local monotonic successful-receive sequence.

`AuthenticatedPeerTransportV1::owns_inbound_envelope(...)` requires both the private wrapper nonce and transcript generation to match.

Therefore two independent wrapper instances with the same transcript value still cannot exchange inbound evidence tokens.

The token is historical evidence of one carrier receive. It is not permission to replay the represented application operation multiple times; xenia-wire and the application protocol still own cryptographic replay and semantic idempotency rules.

## Terminal behavior

The wrapper becomes terminal on:

- transport send failure;
- transport receive failure;
- transport profile drift;
- pre-session profile drift;
- availability profile drift; or
- receive-evidence sequence exhaustion.

After terminalization every later I/O call returns `Terminal` without attempting carrier reuse.

This follows the existing `Transport` contract that timeout/error may leave partial framing and is session-fatal.

## Relationship to application identity

This layer still does not know a Mycelix PartyId or group.

The eventual Content Fabric composition must include the missing cryptographic-open boundary:

```text
AuthenticatedPeerTransportV1<T>
        |
        v
PeerBoundInboundEnvelopeV1
        |
        v
xenia-wire AEAD + replay + payload-domain validation
        |
        v
validated request semantic
        +
exact hybrid enrollment lookup from the same handshake identity
        |
        v
PartyIdV1 + groups
        |
        v
request-scoped reader authority
```

The exact key-pair-to-PartyId mapping belongs to Mycelix CF-07C1, not Xenia.

## Non-claims

This PR does not:

- authenticate application-envelope bytes after carrier receipt;
- define Mycelix identity;
- authorize Content Fabric objects;
- define HTTP-over-Xenia;
- make stock Nix speak Xenia;
- add a listener;
- add TLS/DNS policy;
- make an idle carrier provably connected;
- prove remote application receipt after a local send completes;
- change handshake bytes, transcript bytes, crypto suites, or key schedules; or
- replace xenia-wire/application anti-replay semantics.

It establishes only the structural transport-ownership and same-carrier receipt primitive needed so later adapters do not pair authenticated identity evidence with an unrelated carrier by convention.
