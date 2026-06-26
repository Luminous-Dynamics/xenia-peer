# Xenia Crate Ownership Map

This map defines which package owns each responsibility. Use it during reviews,
refactors, and agent handoffs to prevent product logic from leaking into the
protocol layer or app glue from leaking into reusable crates.

## Dependency direction

```text
apps/*
  -> crates/*
    -> xenia-wire
```

`xenia-wire` is the bottom of the stack. It must not depend on product crates,
transport implementations, capture backends, admin UI code, or deployment
policy.

## Packages

| Package | Kind | Owns | Must not own |
|---|---|---|---|
| `xenia-wire` | Protocol crate | Envelope format, nonce/epoch rules, replay window, payload IDs, consent payload encoding, test vectors, fuzz targets, normative spec. | Peer identity registry, UI consent flow, transport selection, capture, codecs, admin policy. |
| `xenia-peer-core` | Reusable runtime crate | Session state, common frame/control/audio/telemetry types, transport trait, loopback tests. | Platform capture APIs, WebSocket/QUIC implementation details, GUI, admin API. |
| `xenia-handshake` | Reusable security crate | Peer handshake state machine, key schedule, identity-binding material, test fixtures. | Wire envelope serialization, viewer UI, policy decisions. |
| `xenia-ledger` | Reusable accountability crate | Append-only consent/audit ledger, signatures, verification, import/export format. | Real-time UI, daemon HTTP handlers, transport state. |
| `xenia-capture` | Reusable platform crate | Capture abstraction, fake/test capture, optional platform backends, telemetry capture. | Encoding, network send, consent policy. |
| `xenia-video` | Reusable codec crate | Codec abstraction, passthrough, optional H.264, optional HDC. | Capture devices, transport, auth, admin UI. |
| `xenia-transport-ws` | Reusable transport crate | Binary WebSocket sealed-envelope transport and conformance tests. | Wire crypto, capture, policy, admin UI. |
| `xenia-transport-quic` | Reusable transport crate | QUIC/Iroh sealed-envelope transport and conformance tests. | Wire crypto, capture, policy, admin UI. |
| `xenia-inject` | Reusable platform crate | Input event abstraction and optional platform injection backends. | Viewer GUI decisions, transport sessions, consent ceremony. |
| `xenia-peer` | App/daemon | Host runtime, CLI, transport selection, capture/encode/send loop, admin bridge, session lifecycle. | Normative protocol rules that belong in `xenia-wire`. |
| `xenia-viewer` | App | Native viewer CLI/GUI, connect/open/decode/render loop. | Host capture, ledger authority, protocol internals. |
| `xenia-viewer-web` | App/demo | Browser demo/viewer surface, WASM protocol exercise, consent pages. | Product security claims, daemon policy, protocol source of truth. |
| `sovereign-admin` | App/admin UI | Operator console, policy visualization, ledger inspection, governance workflow. | Cryptographic protocol definitions, capture/codec internals. |

## Review rules

1. A protocol rule belongs in `xenia-wire` and must have a test vector or
   integration test.
2. A product policy belongs in `xenia-peer`, `sovereign-admin`, or docs; do not
   bake deployment assumptions into `xenia-wire`.
3. Platform-specific code must be behind features and stay in capture/inject/video
   crates unless it is purely app wiring.
4. New cross-crate types should start in the crate that owns their invariants.
5. Apps may aggregate; crates should stay narrow.

## License boundary

The protocol and reusable infrastructure crates can remain `Apache-2.0 OR MIT`
where appropriate. Product/operator surfaces that encode governance or networked
service behavior can remain `AGPL-3.0-or-later`. Do not accidentally copy AGPL
implementation code into dual-licensed crates without an explicit licensing
review.
