# Authenticated Peer Deadline Send v1

Status: executable draft stacked on `AuthenticatedPeerApplicationChannelV1` / PR #281.

## Purpose

This contract closes the application-seal → carrier-send timing gap for callers that must preserve an external serving/authorization deadline through the actual authenticated Xenia send path.

The boundary is:

```text
caller authority deadline (monotonic Instant)
        ↓
AuthenticatedPeerApplicationChannelV1
        ↓
pre-seal deadline check
        ↓
xenia-wire AEAD seal
        ↓
post-seal / pre-carrier deadline check
        ↓
deadline-bounded same-peer carrier send
        ↓
post-send deadline check
```

The new API is:

```rust
send_payload_before_deadline(
    plaintext: &[u8],
    deadline: std::time::Instant,
)
```

It does not replace the existing unbounded `send_payload(...)`; it is an additive stricter path for authority-bearing integrations.

## Deadline semantics

The caller supplies a local monotonic `Instant`. Xenia does not interpret this as user identity, remote policy, or wall-clock time.

The channel checks the deadline at four points:

1. before AEAD sealing;
2. immediately after sealing and before any carrier I/O;
3. around the carrier-send future using `tokio::time::timeout_at`; and
4. immediately after the carrier send reports success.

If any deadline check fails, the method returns `SendDeadlineExpired` and the application channel becomes terminal.

## Why post-seal expiry is terminal

AEAD sealing advances private wire-send state. If authority expires after sealing but before a safe carrier send completes, the method does not hand the channel back as ordinary reusable state.

This is deliberately conservative. It prevents higher layers from treating a partially advanced authority-bearing channel as if nothing happened.

## Carrier failures remain terminal

The owned `AuthenticatedPeerTransportV1` already enforces exact transport/pre-session/availability profile stability and terminalizes on carrier errors or profile drift.

`send_payload_before_deadline` preserves that behavior. A deadline timeout or post-send late completion additionally terminalizes the application channel.

## Precise non-claim

The API cannot recall bytes already accepted by an operating-system, kernel, NIC, proxy, or remote transport buffer before the deadline.

It guarantees instead that:

- a carrier send is never intentionally entered after the post-seal deadline check has observed expiry;
- the carrier-send future is bounded by the same monotonic deadline;
- a send that finishes only after the deadline is treated as failed; and
- a failed/late channel is not returned as healthy reusable application-channel state.

This is an application/carrier admission guarantee, not proof of remote receipt time.

## No new authority

The deadline API does not:

- authenticate a peer;
- assign a Mycelix principal;
- mint Content Fabric exposure authority;
- decide application semantics;
- change the configured Xenia payload domain;
- expose the raw transport or `WireSession`;
- add a rekey API; or
- weaken AEAD/replay behavior.

It operates only on an already sealed `AuthenticatedPeerApplicationChannelV1<T>`.

## Compatibility

The existing `send_payload(...)` API remains unchanged for integrations that do not have an external authorization deadline.

Security-sensitive integrations that must preserve a deadline through carrier admission should prefer `send_payload_before_deadline(...)`.

## Qualification expectations

The focused qualification lane must run:

- Rust 1.96 rustfmt/check/strict Clippy/tests/rustdoc;
- Rust 1.94 MSRV check/tests;
- the authenticated-peer application-channel test set; and
- the full `xenia-peer-core` test suite on the primary toolchain.

Keep the tranche draft until exact-head GitHub Actions execute successfully.
