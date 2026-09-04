# Xenia Authenticated Peer Handshake v1

Status: additive security boundary for downstream integrations.

## Problem

Xenia's host handshake already authenticates the viewer's Ed25519 **and** ML-DSA-65 signatures and can return the verified peer public keys.

The legacy `VerifiedPeerIdentity` is intentionally an ordinary data object with public key fields. That is convenient for policy lookup, but external Rust code can also construct the struct directly. Therefore this shape is unsafe as a type-level proof:

```text
VerifiedPeerIdentity value
        x
proof that a Xenia handshake authenticated it
```

Security-sensitive integrations such as Content Fabric remote-reader authorization need a non-forgeable-by-external-code handshake evidence surface instead.

## Boundary

`AuthenticatedPeerHandshakeV1` owns:

- the exact `HandshakeOutcome`; and
- the exact `VerifiedPeerIdentity`

returned by **one invocation** of Xenia's real host-side hybrid handshake.

Its fields are private and it has no public constructor, `Default`, deserializer, or `From` implementation.

The only public creation path is:

```text
perform_host_handshake_authenticated_peer_v1(...)
        |
        v
perform_host_handshake_authenticating_peer(...)
        |
        +-- verifies Ed25519 peer signature
        +-- verifies ML-DSA-65 peer signature
        +-- derives exact HandshakeOutcome
        |
        v
AuthenticatedPeerHandshakeV1
```

The legacy tuple-returning API remains available for compatibility. New authority-bearing integrations should require the sealed wrapper when they rely on the Rust type as evidence that a peer identity passed the Xenia handshake.

## What the wrapper proves

Possession of an `AuthenticatedPeerHandshakeV1` from an external crate means the value originated from Xenia's host-handshake authentication path and binds the returned outcome to the peer key pair from the same call.

It exposes read-only facts:

- handshake outcome;
- transcript hash;
- negotiated context hash;
- peer Ed25519 public key; and
- peer ML-DSA-65 public key.

The transcript hash is connection-generation evidence. It is not an application identity.

## What the wrapper does not prove

The wrapper does **not** establish:

- that the underlying transport is still connected;
- that the holder still owns the transport that produced the handshake;
- a Mycelix application/user principal;
- a Mycelix group membership;
- authorization to a specific resource; or
- permission to replay this evidence as a bearer credential on another connection.

In particular:

```text
transcript hash       != application principal
endpoint identity     != application principal
Ed25519 key alone     != hybrid enrolled principal
raw key fingerprint   != Mycelix PartyId
handshake evidence    != live transport ownership
```

A downstream identity adapter must match the **exact authenticated Ed25519 + ML-DSA-65 pair** against an explicit enrollment/policy record before assigning an application identity.

This matches Xenia's existing operator-policy rule: hybrid authentication is meaningful only when both verified keys match the same enrollment record.

## Liveness is a separate authority

`AuthenticatedPeerHandshakeV1` is intentionally historical authentication evidence. It may outlive the socket and therefore must never be treated as a connection lease.

A downstream live server must separately prove that each request belongs to the currently authenticated transport generation. A safe future composition is:

```text
AuthenticatedPeerHandshakeV1
        +
exact enrolled application identity
        +
live transport ownership bound to the same handshake generation
        |
        v
request-scoped authenticated reader
```

A stale or copied handshake wrapper alone must not authorize a new network request.

## Generation binding

The wrapper keeps the authenticated peer identity attached to the `HandshakeOutcome` that produced it. Downstream code may inspect the transcript hash as the exact connection generation, but must not reinterpret that generation as a durable user identity.

This complements the receiver-authority generation work: negotiated session context, handshake generation, application principal, and live transport ownership remain distinct concepts.

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

The next Content Fabric identity bridge may inspect `&AuthenticatedPeerHandshakeV1`, then perform an explicit enrollment lookup over both peer keys before constructing application identity facts.

That alone is still insufficient to authorize a remote HTTP request. The request adapter must additionally bind the live connection to the same Xenia handshake generation before projecting any authenticated `RemoteReaderV1`.

It should **not** accept any of the following as sufficient authentication evidence:

- `VerifiedPeerIdentity` by itself;
- a transcript hash by itself;
- an endpoint ID;
- an HTTP header asserting a PartyId;
- a caller-provided key fingerprint;
- a Mycelix PartyId without key enrollment evidence; or
- an `AuthenticatedPeerHandshakeV1` detached from live transport-generation ownership.
