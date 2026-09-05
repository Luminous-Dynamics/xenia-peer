# Xenia Authenticated Peer Deadline Receive v0.1

Status: executable draft stacked on Content Fabric authenticated peer deadline send / PR #300.

## Purpose

This tranche adds a cancellation-safe ownership boundary for waiting on one opened application payload with an external monotonic deadline.

The relevant chain is:

```text
AuthenticatedPeerApplicationChannelV1<T>
        |
        +-- exact authenticated peer transport ownership
        +-- exact handshake generation
        +-- one application payload domain
        +-- private xenia-wire AEAD/replay state
        |
        v
recv_opened_payload_before_deadline_v1(channel, deadline)
        |
        +-- channel consumed by value
        +-- deadline checked before receive
        +-- receive future bounded by timeout_at(deadline)
        +-- deadline checked after successful open
        |
        +-- success --> (same channel, OpenedPeerApplicationPayloadV1)
        |
        `-- any failure/timeout --> error only; channel dropped
```

## Why ownership matters

Applying an external timeout directly to:

```rust
channel.recv_opened_payload()
```

can cancel the future while an underlying stream transport has already consumed part of a length-prefixed envelope. Returning that channel for ordinary reuse would risk treating partially advanced carrier framing as healthy state.

The v0.1 API therefore consumes the entire authenticated application channel by value.

On success, the same channel is returned with exactly one opened payload.

On any deadline, carrier, domain, AEAD, replay, or wire failure, the error type contains no channel and no recovery path. The owned channel is dropped when the function returns.

The same property holds if the caller cancels or drops the outer async operation itself: because the channel has been moved into that future, cancelling the future drops the owned channel rather than returning potentially advanced carrier state to the caller.

This makes potentially desynchronized carrier/replay state structurally unavailable after either an internal deadline timeout or caller-side task cancellation.

## Deadline semantics

The caller supplies one `std::time::Instant` monotonic deadline.

The implementation:

1. refuses an already-expired deadline before polling the receive future;
2. wraps the in-flight receive in `tokio::time::timeout_at` using that same deadline;
3. refuses a receive that completed but is observed at or beyond the deadline before returning the opened payload/channel pair.

The API does not accept a wall-clock timestamp, application identity, resource identifier, or policy object. Higher layers remain responsible for deriving a conservative monotonic deadline from their own authority horizon.

## Success evidence

A successful returned `OpenedPeerApplicationPayloadV1` retains the existing Xenia semantics:

- same authenticated peer carrier;
- exact application payload-domain match checked before wire open;
- AEAD authentication;
- replay acceptance;
- handshake transcript/context lineage; and
- authenticated Ed25519 + ML-DSA-65 peer key facts.

It still does **not** validate application plaintext schema or grant application authorization.

## Failure semantics

The only public outcomes are:

```text
Ok((channel, opened_payload))
```

or:

```text
Err(...)
```

There is no `Err((channel, ...))`, retry token, raw transport extraction, or recovery constructor.

This tranche deliberately chooses availability loss over reuse ambiguity after a cancelled or failed receive.

## Precise non-claims

This API does **not** claim that:

- cancellation reverses bytes already consumed inside a carrier implementation;
- a peer cannot have sent bytes before the deadline that arrive later;
- successful opened plaintext is a valid Content Fabric request;
- the channel remains live indefinitely after a successful receive;
- application authorization time equals the Xenia monotonic deadline; or
- long-lived rekey state is solved by this boundary.

Its narrow guarantee is that a receive which fails to complete safely inside the deadline cannot hand the possibly advanced authenticated channel back to the caller for reuse.

## Compatibility

The existing borrowing API:

```rust
recv_opened_payload(&mut self)
```

remains unchanged for callers whose lifetime/deadline is already owned by another fail-closed session abstraction.

The new consuming function is the preferred path when an external authorization deadline controls whether the channel may remain reusable.

## Qualification expectations

The focused lane must run:

- Rust 1.96 rustfmt/check/strict Clippy/tests/rustdoc;
- Rust 1.94 MSRV check/tests;
- focused deadline-receive helper tests;
- authenticated application-channel tests; and
- full `xenia-peer-core` tests on the primary toolchain.

Keep this tranche draft until exact-head GitHub Actions execute successfully.
