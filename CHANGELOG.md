# Changelog

All notable changes to `xenia-peer` and its sub-crates are documented
here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- V15 carries V14's pointer-motion/button distinction through the host injection
  backend interface, adds session-scoped tracking and teardown release/cancel of
  successfully injected key/button/touch state, and fixes uinput touch Cancel to
  release `BTN_TOUCH` fail-closed. Mobile outbound clipboard now coalesces to one
  latest-value slot, while file-transfer command queue saturation is surfaced
  explicitly through Rust/C/JNI/Kotlin instead of being silently ignored.
- V13 adds `TransportPreSessionProfileV1` and advances the current authenticated
  session context to V4. TCP connect, WebSocket connect/upgrade, QUIC connection
  establishment, and QUIC logical-stream establishment now have explicit
  fail-closed pre-authentication deadlines whose exact policy is committed after
  the handshake.
- Desktop GUI input no longer uses an unbounded Tokio channel. The queue is
  capped at 256 events: pointer motion is explicitly lossy under saturation,
  while keyboard/button state transitions use bounded backpressure rather than
  silently dropping a release event.
- WebSocket transport profile `/1` now requires the exact RFC 6455 subprotocol
  `xenia.transport.websocket.v1` and configures tungstenite message/frame
  ceilings at the carrier boundary before Xenia envelope parsing.
- Session applications now prefer a consuming `PendingSessionSurface` →
  `AuthenticatedSessionSurface` transition; the legacy boolean capability guard is removed. Desktop/mobile input, clipboard,
  file-transfer, media, telemetry, and rekey handling cannot cross the preferred
  application surface until the sealed capabilities contract is authenticated.
- Frame-0 synthetic viewer input is deferred until the authenticated session
  surface exists; duplicate capability advertisements remain fail-closed.
- QUIC conformance tests now pin fail-closed behavior for an altered ALPN and
  an altered Xenia stream preface, preventing future profile migration from
  silently reusing `/0` semantics.

- `xenia-zk-protocol` now provides `decode_bounded_envelope_with`, a format-neutral
  decode entry point that enforces the raw proof-envelope size ceiling before an
  application-owned parser is invoked. Oversized or empty frames never reach the
  decoder closure, and decoder errors remain distinct from frame-policy failures.

## [0.0.0-m0] — 2026-04-18

Initial milestone. Workspace scaffold + `xenia-peer-core` crate with
the minimum necessary to exchange sealed-RGBA-over-TCP on localhost.
**Not published to crates.io** — the crate is `publish = false` until
at least M1 makes it useful.

### Added

- `xenia-peer-core` crate:
  - `RawFrame` + `RawInput` framing types (raw RGBA only; encoded
    formats reserved).
  - `Session` thin wrapper around `xenia_wire::Session` with
    server/viewer role tracking and monotonic frame/input counters.
  - `Transport` trait + `TcpTransport` implementation
    (length-prefixed envelopes over `tokio::net::TcpStream`).
  - Integration test `hundred_frames_plus_inputs_roundtrip_over_tcp`
    exchanging 100 frames + 10 inputs end-to-end through real
    tokio TCP sockets.
  - Tests for replay protection across the real transport and for
    oversize-envelope safety (16 MiB cap).

### Design decisions locked in

- Codec: H.264 primary / VP9 fallback / HEVC bonus.
- Codec wrapper: `ffmpeg-next`.
- Capture: per-platform behind `xenia-capture` trait.
- Input: per-platform behind `xenia-inject` trait.
- Transports: Iroh QUIC primary + `tokio-tungstenite` WebSocket
  fallback.
- Browser viewer: WebCodecs + WebGL2.
- Native viewer: egui → Tauri progression.

### Deviations from plan

- `plans/VIEWER_PLAN.md` §3 M0 originally framed as an 11-file
  extraction from Symthaea's `rdp_*.rs`. Actual execution: fresh
  code on top of `xenia-wire`, with Symthaea's rdp_* as reference
  material. Result: smaller + cleaner than the extraction path
  would have produced.

### Known limitations

- No screen capture.
- No video encoding.
- No input injection.
- No QUIC transport (TCP-only for M0).
- No WebSocket transport.
- No browser client beyond what `xenia-viewer-web` in the
  `xenia-wire` repo already provides (demo-quality).

[Unreleased]: https://github.com/Luminous-Dynamics/xenia-peer/compare/v0.0.0-m0...HEAD
[0.0.0-m0]: https://github.com/Luminous-Dynamics/xenia-peer/releases/tag/v0.0.0-m0
