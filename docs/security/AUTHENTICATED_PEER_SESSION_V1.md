# Xenia Authenticated Peer Session v1

Status: additive security boundary for downstream integrations.

## Problem

Xenia's host handshake already authenticates the viewer's Ed25519 **and** ML-DSA-65 signatures and can return the verified peer public keys.

The legacy `VerifiedPeerIdentity` is intentionally an ordinary data object with public key fields. That is convenient for policy lookup, but external Rust code can also construct the struct directly. Therefore this shape is unsafe as a type-level proof:

```text
VerifiedPeerIdentity value
        x
proof that a Xenia handshake authenticated it
```

Security-sensitive integrations such as Content Fabric remote-reader authorization need a non-forgeable-by-external-code session surface instead.

## Boundary

`AuthenticatedPeerSessionV1` owns:

- the exact `HandshakeOutcome`; and
- the exact `VerifiedPeerIdentity`

returned by **one invocation** of Xenia's real host-side hybrid handshake.

Its fields are private and it has no public constructor, `Default`, deserializer, or `From` implementation.

The only public creation path is:

```text
perform_host_handshake_authenticated_peer_session(...)
        |
        v
perform_host_handshake_authenticating_peer(...)
        |
        +-- verifies Ed25519 peer signature
        +-- verifies ML-DSA-65 peer signature
        +-- derives exact HandshakeOutcome
        |
        v
AuthenticatedPeerSessionV1
```

The legacy tuple-returning API remains available for compatibility. New authority-bearing integrations should require the sealed wrapper when they rely on the Rust type as authentication evidence.

## What the wrapper proves

Possession of an `AuthenticatedPeerSessionV1` from an external crate means the value originated from Xenia's host-handshake authentication path and binds the returned outcome to the peer key pair from the same call.

It exposes read-only facts:

- handshake outcome;
- transcript hash;
- negotiated context hash;
- peer Ed25519 public key; and
- peer ML-DSA-65 public key.

## What the wrapper does not prove

The wrapper does **not** establish an application/user principal.

In particular:

```text
transcript hash       != application principal
endpoint identity     != application principal
Ed25519 key alone     != hybrid enrolled principal
raw key fingerprint   != Mycelix PartyId
```

A downstream identity adapter must match the **exact authenticated Ed25519 + ML-DSA-65 pair** against an explicit enrollment/policy record before assigning an application identity.

This matches Xenia's existing operator-policy rule: hybrid authentication is meaningful only when both verified keys match the same enrollment record.

## Generation binding

The wrapper keeps the authenticated peer identity attached to the `HandshakeOutcome` that produced it. Downstream code may inspect the transcript hash as the exact connection generation, but must not reinterpret that generation as a durable user identity.

This complements the receiver-authority generation work: session/context identity, handshake generation, and application principal remain distinct concepts.

## Compatibility

This change is additive:

- `VerifiedPeerIdentity` remains available;
- `perform_host_handshake_authenticating_peer` remains available;
- no handshake wire bytes change;
- no transcript bytes change;
- no key schedule changes;
- no transport profile changes; and
- no operator enrollment format changes.

## Intended Content Fabric use

The next Content Fabric identity bridge should consume `&AuthenticatedPeerSessionV1`, then perform an explicit enrollment lookup over both peer keys before constructing any authenticated `RemoteReaderV1`.

It should **not** accept:

- `VerifiedPeerIdentity` by itself;
- a transcript hash;
- an endpoint ID;
- an HTTP header asserting a PartyId; or
- a caller-provided key fingerprint as already-authenticated identity.
