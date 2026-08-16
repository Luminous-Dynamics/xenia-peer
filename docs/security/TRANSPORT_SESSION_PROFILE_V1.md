# Xenia Transport / Session Profile V1

Status: V10 security contract

`TransportProfileV1` is the authenticated contract between Xenia's transport
adapters and its session/handshake layer. It is intentionally stricter than a
carrier label such as `Quic`.

## Current exact profiles

| Carrier | Protocol ID | Framing | Session ceiling | Handshake parser ceiling | Logical streams |
|---|---|---|---:|---:|---:|
| TCP | `xenia/transport/tcp/0` | u32 big-endian length prefix | 16 MiB | 16 KiB | 1 |
| WebSocket | `xenia/transport/websocket/0` | one binary WS message per envelope | 16 MiB | 16 KiB | 1 |
| Iroh QUIC | `xenia/transport/quic/0` | u32 big-endian length prefix inside one bidirectional stream | 16 MiB | 16 KiB | 1 |

All current profiles require reliable, ordered delivery on the logical Xenia
envelope stream.

For QUIC, `XENIA_QUIC_ALPN` is derived directly from `QUIC_PROTOCOL_ID`, so the
runtime protocol selector and transcript-bound profile cannot drift as two
independent literals.

## Session-context binding

`NegotiatedSessionContextV2` commits:

- `TransportProfileV1`;
- `xenia-wire-sealed-envelope-v1`;
- `hybrid-pq-transcript-v1`;
- `xenia-handshake-transcript-v1`;
- `xenia-session-key-schedule-v1`;
- immutable `RawCapabilities`.

The daemon computes this context from `transport.transport_profile()` before it
sends `HostHello`. The resulting hash is included in the signed hybrid
handshake transcript. The viewer obtains the profile from its concrete
transport object and recomputes the context when the first sealed capabilities
frame arrives. A mismatch fails closed.

## Compatibility and downgrade policy

The V1 rule is exact-match, not field-by-field negotiation. If a field changes,
create a new explicitly reviewed profile. This prevents "compatible" local
choices from weakening a peer's assumptions without altering the authenticated
transcript.

The Python source gate `scripts/check_transport_session_profile_v10.py` checks
that the profile remains structurally connected to all concrete transports and
application paths even on review runners without Rust. The independent reduced
model `scripts/model_check_transport_session_profile_v1.py` mutates every
security-relevant profile field and verifies that each mutation changes the
committed context.

These checks do **not** replace Rust compilation, runtime transport conformance,
or network fuzzing.
