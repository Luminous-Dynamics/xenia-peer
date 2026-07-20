# Changelog

All notable changes to `xenia-peer` and its sub-crates are documented
here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Added ledger-signed purge rollback-retention certificates, independent witness
  bundles, externally retainable anchors, and exact protected-file inventory
  checks before any future final-destruction ceremony.

- A separate aged-quarantine purge ceremony with one-hour ledger-signed plans,
  purge-witness keys distinct from retirement witnesses, a complete owner-only
  rollback package persisted before the first unlink, per-file deletion
  journals, signed completion receipts, and public-key-only crash recovery.
- Short-lived ledger-signed consent-artifact retirement plans that bind exact
  candidate roles, canonical paths, lengths, digests, active compacted state,
  retained pin, GC-readiness certificate, and quarantine root.
- Independent retirement-witness approval bundles with configurable distinct
  trusted-key quorum; approval, recovery, and receipt verification require only
  the ledger public key rather than access to its private key.
- Owner-only reversible quarantine transactions with immediate candidate
  rehashing, per-rename crash journals, directory synchronization, signed
  completion receipts, and filesystem-reconciled rollback after stale journal
  writes. No artifact is unlinked.
- Dual-signed consent-ledger key succession artifacts for explicit epoch
  rotation without silently changing the signer inside one hash chain.
- Independent checkpoint countersignature bundles with configurable trusted
  witness quorums and retained-checkpoint freshness policy.
- Bounded, atomically exported ledger archive segments with exact checkpoint
  and signed-entry continuity verification.
- Bounded archive-sequence commitments, deterministic consent replay/recovery
  summaries, and ledger-signed non-destructive compaction preflight bundles.

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

### Compacted consent cutover assurance

- Advanced compacted active-state persistence to schema v2 and added
  ledger-signed cutover receipts that bind activation to the exact
  complete-ledger head and signing-key epoch. Historical v1 envelopes must be
  reactivated from their verified snapshot and cold archive.
- Added generation-linked active states and independently retainable signed
  compacted-state pins for rollback detection before listener startup.
- Added signed, non-destructive GC-readiness certificates that join the cold
  archive, recovery summary, cutover receipt, active state, and retained pin.
- Added bounded atomic CLI workflows for pin advancement and GC-certificate
  export/verification. No automatic deletion or cross-epoch compaction is
  enabled.
