# xenia-peer roadmap + status

Single source of truth for what's shipped, what's next, and what's
deferred. Updated by humans, not by commits. Last refresh:
2026-07-02 (B2/B3 real-capture + consent-ceremony wiring and first
live validation — see B2/B3/M1.2c/M2 below).

If this file disagrees with reality, the file is wrong.

---

## What's shipped

### Repository state

| Item | Status | Notes |
|---|---|---|
| 10-crate workspace | ✅ | `xenia-peer-core`, `xenia-peer`, `xenia-viewer`, `xenia-capture`, `xenia-video`, `xenia-transport-ws`, `xenia-transport-quic`, `xenia-inject`, `xenia-handshake`, `xenia-ledger` + workspace root |
| `flake.nix` | ✅ | H.264 + Wayland/DBus/PipeWire + libGL/libxkbcommon on LD_LIBRARY_PATH |
| CI (GitHub Actions) | ✅ | fmt + clippy + test (ubuntu/macos/windows) + MSRV 1.94 + docs + h264 matrix |
| ADR-001 architecture decisions | ✅ | `docs/ADR-001-m0-architecture.md` — monorepo, Wayland-exclusive, AGPL split |
| ADR-002 library licensing | ✅ | `docs/ADR-002-library-licensing.md` — all library crates Apache/MIT; binaries AGPL. Extends ADR-001. |

### Codecs (3)

| Codec | Feature | Status | Typical bandwidth (320×200 TestCapture @ 30 fps) |
|---|---|---|---|
| Passthrough | (default) | ✅ live | 256 KB / frame always |
| H.264 (libx264) | `h264` | ✅ live | 11.8 KB keyframe + ~2.7 KB P-frame |
| HDC hybrid tile-delta | `hdc` | ✅ live | 64.5 KB keyframe + 37 B per static delta frame |

### Transports (3)

| Transport | Crate | Status |
|---|---|---|
| TCP length-prefix | `xenia-peer-core::transport::TcpTransport` | ✅ daemon/viewer baseline; conformance-tested; explicit fallback |
| WebSocket (binary frames) | `xenia-transport-ws` | ✅ daemon/viewer baseline; conformance-tested; selected by `auto` for `ws://...` |
| Iroh QUIC | `xenia-transport-quic` | ✅ daemon/viewer CLI wired; conformance-tested; auto-discovered from `host:port` when daemon advertises it |

### Transport improvement plan

1. Keep TCP + WebSocket as the stable daemon/viewer baseline.
2. Maintain the shared transport conformance tests for envelope boundaries, ordering, and oversize rejection before expanding transport behavior.
3. Keep `--transport auto` as the normal CLI path: daemon accepts TCP/WS, advertises QUIC over an initial TCP probe, and accepts QUIC directly.
4. Next: harden fallback policy with timeouts, user-visible selected-transport reporting, and browser-compatible advertisement over WebSocket.

### Viewers (3)

| Viewer | Lives in | Status |
|---|---|---|
| CLI (`xenia-viewer`) | this repo | ✅ live, used by `--verify` smoke tests |
| egui GUI (`--gui` flag) | this repo | ✅ live, renders decoded RGBA at 1:1 |
| Browser (`xenia-viewer-web/daemon.html`) | `xenia-wire` repo | ✅ live (passthrough codec only so far) |

### Test matrix that works today

| Daemon | Viewer | Transport | Codec | Status |
|---|---|---|---|---|
| `xenia-peer` on desktop | CLI | tcp / ws / quic | all three | ✅ loopback + LAN; QUIC smoke verified with passthrough |
| `xenia-peer` on desktop | egui `--gui` | tcp / ws / quic | all three | ✅ visually verifiable; QUIC path uses same receive loop |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | passthrough | ✅ |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | h264 | ❌ needs WebCodecs wiring |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | hdc | ❌ needs bincode+grayscale decoder in WASM (~50 LOC) |
| **Phone → desktop** (phone as daemon) | desktop viewer | any | any | ❌ needs phone-side daemon port |

---

## Hard blockers for real deployment

These MUST land before anyone uses xenia-peer on anything that
handles real traffic. Native daemon/viewer handshakes now derive a
session key, but the capture and consent surfaces are still not
deployment-grade.

| # | Item | Status | Estimate | Why it blocks |
|---|---|---|---|---|
| B1 | **PQC handshake** (ML-KEM-768 + Ed25519 + HKDF-SHA256) | ✅ browser handshake landed 2026-07-02 in `xenia-wire`'s `xenia-viewer-web` crate (`src/handshake.rs`, `WasmHandshake`) — a from-scratch reimplementation (can't cross-repo-depend on `xenia-handshake` at runtime), proven byte-identical to the native host via a dev-dependency cross-compat test AND a live end-to-end run against a real `xenia-peer --transport ws` daemon (real `HostHello`→`ViewerResponse`→`HostFinalize` exchange, daemon accepted the derived key). 🟡 **new scope discovered, not yet done:** decoding real frames additionally requires `LaneSession`'s lane-envelope wire format (4 separately-keyed sub-sessions — control/video/audio/telemetry, each `xenia_wire::Session` with its own `SessionKeySchedule`-derived key, wrapped in a 5-byte lane tag) plus rekey-epoch key derivation (the daemon always does one mandatory rekey immediately post-handshake, regardless of `--rekey-disabled`, which only affects *later* automatic rekeys) — `xenia-viewer-web` implements neither today, so `openDaemonFrame` still fails on real daemon traffic once past the handshake. This is new information: the original "0.5 day" estimate covered only the handshake as scoped when this row was written, before `LaneSession` existed. | Handshake: done. Lane-envelope + rekey support: unscoped, likely 1-2 days | Fresh-impl against RustCrypto `ml-kem` 0.3.0-rc.2 + `ed25519-dalek` 2 + `hkdf` 0.12, exact-pinned to match `xenia-handshake`'s resolved versions (a plain semver range silently resolved a newer, API-incompatible `ml-kem`/`kem` in testing). Not a Symthaea carry — symthaea's version depended on `mycelix-crypto`. |
| B2 | **Universal host ingestion** | ✅ display backend (ScapCapture) wired into the daemon and validated on KDE-Wayland 2026-07-02: real 1920×1080 frames, zero decode errors, **16.76 effective fps — clears the 15fps bar** (`VERDICT: PASS`). Earlier same-day runs measured 0.33–8.70fps against a static desktop; root-caused to PipeWire's damage-driven ScreenCast (only pushes frames on visible screen changes), not a code defect — see `mycelix-sovereign/docs/capture-validation-runbook.md`. A separate real integration bug (encoder built from `--width`/`--height` CLI defaults, silently dropping every real-resolution frame) was also found and fixed the same day. GNOME/wlroots/macOS/Windows still unmeasured; audio/input real backends still pending. | Done for display on KDE-Wayland; 3–7 days per remaining audio/input backend; unknown for other display OSes/compositors | Capture is no longer synthetic-only and meets its own performance bar on the one platform measured so far. `xenia-capture` exposes host-agnostic display, audio, input, and telemetry traits; native daemon/viewer stream sealed `sysinfo` telemetry with explicit `basic`/`system`/`off` policy, plus synthetic RawAudio frames for jitter/timing validation. |
| B3 | **Consent ceremony UI on the host** | 🟡 wire-level state machine + M1RuntimeSession gate wired end-to-end 2026-07-02: `--consent-port` now parses real Approve/Deny decisions (blocking with a new `--consent-timeout-secs`, graceful exit on deny/timeout instead of a crash), and the actual request scope is broadcast over `--admin-port` so a connected UI has real content. `apps/sovereign-admin`'s `ConsentModal` already speaks this exact protocol. Covered by new smoke-test cases in `scripts/xenia-audio-e2e-smoke.sh`. | Done for the CLI/wire path; `sovereign-admin` itself still needs to ship as part of xenia-peer's own UX rather than a separate incubator app | Uses draft-03 SPEC §12 from xenia-wire. What's left is packaging/UX polish, not the underlying gate. |

---

## From Symthaea: carry-wholesale backlog (per VIEWER_PLAN §0.1)

### Carried (already here)

| Symthaea path | Landed here | Commit |
|---|---|---|
| `src/swarm/rdp_capture.rs` (trait + TestCapture + BlankCapture) | `crates/xenia-capture/src/lib.rs` | `bd081cf` |
| `src/swarm/rdp_codec.rs` (HDC hybrid tile-delta) | `crates/xenia-video/src/hdc.rs` | `9bb831f` |
| `crates/crates/symthaea-phone-embodiment/src/scrcpy/decoder.rs` (ffmpeg-next patterns) | `crates/xenia-video/src/h264.rs` (inspired; different codec) | `21d8cf3` |
| `src/swarm/rdp_input.rs` (InputInjector trait + Wayland/uinput backends) | `crates/xenia-inject/src/lib.rs` | `23a49a9` |
| `src/swarm/pqc_handshake.rs` (API shape only — fresh crypto impl) | `crates/xenia-handshake/src/lib.rs` | `4215ab1` |

### Still to carry (ranked by value)

**Tier 2 — makes this a real product:**

| # | Symthaea path | LOC | Maps to | Notes |
|---|---|---|---|---|
| ~~T2.1~~ | ~~`src/swarm/rdp_input.rs`~~ | ~~354~~ | ✅ shipped as `xenia-inject` (`23a49a9`). X11 backend dropped. Wayland + uinput are scaffold stubs; real plumbing lands with matching xenia-capture backend. |
| ~~T2.2~~ | ~~`src/swarm/quic_transport.rs`~~ | ~~785~~ | ✅ `xenia-transport-quic` crate + daemon/viewer CLI wiring shipped | Iroh QUIC. Primary transport per VIEWER_PLAN §4.5; also gives NAT-punch for phone-to-VM tests without Tailscale. |
| T2.3 | `src/swarm/rdp_clipboard.rs` | 223 | new `xenia-clipboard` crate or feature in `xenia-peer-core` | Bidirectional clipboard with sensitivity scrubbing. |
| T2.4 | `src/swarm/rdp_file_transfer.rs` | 198 | new `xenia-file-transfer` crate or feature | Chunked file transfer with BLAKE3. |

**Tier 3 — nice to have:**

| # | Symthaea path | LOC | Notes |
|---|---|---|---|
| T3.1 | `src/swarm/rdp_audio.rs` | ? | 🟡 RawAudio timing lane landed: 48 kHz stereo S16LE, deterministic sine/noise sources, jitter buffer, GUI/CLI accounting, TCP/WS/QUIC conformance. Device capture/playback, cpal, and Opus are still future work. |
| T3.2 | `src/swarm/rdp_recording.rs` | ? | Session recording / replay (`.xenia-session` format). |
| T3.3 | `src/swarm/rdp_adaptive.rs` | 280 | Adaptive bitrate skeleton; wire to `xenia-video` backends. |
| T3.4 | `crates/crates/symthaea-phone-embodiment/src/scrcpy/*` + `streaming_bridge.rs` | ~2000 | **Phone-as-source.** Unblocks the phone→desktop test leg by letting a desktop capture its phone's screen via USB + scrcpy. |

### Superseded — DO NOT port

| Symthaea path | Replaced by |
|---|---|
| `rdp_session.rs` | `xenia_wire::Session` (normative) |
| `rdp_protocol.rs` | `xenia_peer_core::frame::{RawFrame, RawInput}` |
| `rdp_transport.rs` | `xenia_peer_core::transport::Transport` trait |
| `rdp_wire.rs` | `xenia-wire` crate (repo sibling) |
| `rdp_server.rs` | `xenia-peer` binary (this repo) |
| `rdp_client.rs` | `xenia-viewer` binary (this repo) |
| `rdp_render_egui.rs` | `xenia-viewer::gui::ViewerApp` |

---

## Milestones on the product roadmap

Recapitulated from VIEWER_PLAN §3 with today's-actual status:

| Milestone | Exit criterion | Status |
|---|---|---|
| **M0** | Workspace + loopback TCP roundtrip | ✅ `cf4e37a` |
| **M1.1** | xenia-capture + xenia-video scaffold + pipeline wired end-to-end with passthrough | ✅ `bd081cf` |
| **M1.2b** | Real H.264 encode/decode via ffmpeg-next | ✅ `21d8cf3` |
| **M1.2c** | Real host display capture | ✅ ScapCapture wired + validated on KDE-Wayland 2026-07-02 (real 1920×1080 frames, zero errors, 16.76fps, `VERDICT: PASS`) — see **B2** above. Other OSes/compositors unmeasured. |
| **M2** | Input injection + consent-ceremony UI | 🟡 `xenia-inject` crate shipped (`23a49a9`); consent-ceremony gate wired end-to-end 2026-07-02 (**B3**); real input backend still pending |
| **M3.1** | WebSocket transport | ✅ `e765459` |
| **M3.2** | Iroh QUIC primary transport | ✅ library crate + conformance tests + daemon/viewer CLI smoke |
| **M4.0** | egui GUI on xenia-viewer | ✅ `fd28bc3` |
| **M4.1** | WASM browser viewer speaks daemon protocol | ✅ `e68c5ad` (in xenia-wire repo) |
| **M4.1b** | WebCodecs H.264 decode in browser | ❌ not started |
| **M4.1c** | HDC codec in the browser viewer | ❌ not started (~50 LOC WASM) |
| **M4.2** | HDC hybrid codec (port from Symthaea) | ✅ `9bb831f` |
| **M4.2b** | HDC codec RGB output (not grayscale-only) | ❌ not started |
| **M4.3** | RawAudio timing lane | ✅ sealed RawAudio + jitter buffer + synthetic source + native transport conformance |
| **M4.3b** | Opus audio payload | ❌ not started |

---

## The "three-way test matrix" (user's stated goal)

This is the concrete goal organizing the next round of work:

### ✅ Desktop ↔ Desktop (works today)

Two machines on the same LAN / Tailscale, both running the native
binaries. All three codecs, all native transports, CLI or GUI viewer.
By default both ends use the synthetic `TestCapture` gradient. Real
screen content works when built with `--features scap` (see **B2**) —
validated at 16.76fps on KDE-Wayland 2026-07-02, clearing the 15fps
bar. Still not the default build (requires `nix develop`'s PipeWire
dev headers); other display OSes/compositors are unmeasured.

### ✅ Desktop → Phone browser (works today)

Native daemon + `xenia-viewer-web/daemon.html` on the phone's
browser. Uses `--transport ws --codec passthrough`. Phone sees
the daemon's TestCapture pattern in real time. Blocked on real
content: **B2**. Blocked on H.264 / HDC in the browser: **M4.1b**
/ **M4.1c**.

### ❌ Phone → Desktop (not yet)

The missing leg. Two plausible paths:

- **Path A — phone as daemon**: cross-compile `xenia-peer` to
  aarch64-linux-android, `adb push`, run under Termux or a direct
  shell. Real phone screen capture would need the Android screen-
  record API (`MediaProjection`), which is a new code path
  entirely.
- **Path B — desktop as daemon of phone's screen**: port Symthaea's
  `scrcpy/*` + `streaming_bridge.rs` so the desktop runs a daemon
  that captures the phone's screen via USB/scrcpy and reframes it as
  Xenia frames. Then a different desktop (or the phone's own
  browser, looped back through Tailscale) can view. **T3.4** above.

Path B is strictly less product work — Symthaea's scrcpy code is
proven (Phase I.B per the parent roadmap). Path A is more honest
but multi-week.

---

## Open questions (for humans)

Things the maintainer should explicitly decide before more
autonomous shipping:

1. **Browser handshake wiring: done, but frame decode still needs
   lane-envelope + rekey support.** `xenia-viewer-web`'s `WasmHandshake`
   (2026-07-02) reimplements the same ML-KEM-768 + Ed25519 + HKDF flow as
   native `xenia-handshake::HandshakeManager`, proven byte-identical via a
   cross-compat test and a real end-to-end run against a live daemon.
   What's still missing, discovered during that live test: `LaneSession`'s
   4-key lane-envelope wire format and the mandatory post-handshake rekey
   — neither of which existed (or this repo's author was aware of) when
   this row was first written. See B1's row above for detail. Browser
   sessions are not deployment-grade until that lands.
2. **Universal ingestion vs B3 ordering:** with B1 at the crate layer,
   real display/audio/telemetry backends (B2) and the consent UI (B3)
   are the last two blockers for real deployment. B2 unblocks visible
   host content and metrics; B3 unblocks the consent-ceremony promise.
   Neither depends strictly on the other, but production input
   injection should wait for B3.
3. **Phone → Desktop leg: Path A or Path B?** Path B is faster but
   requires a USB-tethered phone every time. Path A is real-world
   deployable but multi-week.
4. **Phone-as-target binary.** Do we want the Android `xenia-peer`
   port as a separate crate / target triple, or build it ad-hoc
   when a phone test comes up?
5. ~~**Licensing drift check.**~~ Resolved 2026-04-18 (`996ec60`).
   ADR-002 formalized "libraries Apache/MIT, binaries AGPL";
   `xenia-capture` / `xenia-video` / `xenia-transport-ws` flipped
   to match. `xenia-inject` / `xenia-handshake` born Apache/MIT.

These don't block shipping the Tier 1/2 items above. They only
matter if the answer would change WHAT we ship.

---

## Unification arc (2026-04-18)

A five-step unification pass closed the "Symthaea ↔ xenia consumption
pathway" question. Recorded here because the commits tell part of
the story but not the why.

| Step | What | Commit | Notes |
|---|---|---|---|
| U1 | Flip library crates AGPL → Apache/MIT | `996ec60` | `xenia-capture`, `xenia-video`, `xenia-transport-ws` were inheriting AGPL from ported Symthaea files. Matches the ADR-001 "libraries permissive" intent. |
| U2 | Author ADR-002 documenting the license split | `996ec60` | Makes the rule explicit for future library crates. |
| U3 | `xenia-handshake` crate (PQC hybrid) | `4215ab1` | **Fresh impl** against RustCrypto, NOT a carry of `symthaea/src/swarm/pqc_handshake.rs` — that file depends on `mycelix-crypto` from the monorepo and would pull it transitively. API shape aligned so a reverse-migration is mechanical. |
| U4 | `xenia-inject` crate | `23a49a9` | Input-injection abstraction. Port of `symthaea/src/swarm/rdp_input.rs` minus the X11 backend (ADR-001 is Wayland-only). |
| U5 | Roadmap refresh | (this commit) | Reflects B1 partial completion, license decision resolved, M2 progress. |

**Symthaea-side migration (deferred, next session):** delete
`symthaea/src/swarm/{rdp_session,rdp_protocol,rdp_transport,rdp_wire,
rdp_input,pqc_handshake,...}.rs` and replace with `git = "…"`
dependencies on the xenia crates. Not published to crates.io yet per
maintainer preference ("let's wait").

**Cross-repo publish plan (deferred):** once wire-level spec
stabilizes past draft-02r2, publish xenia library crates to
crates.io under Apache/MIT. Binaries stay on GitHub-only under AGPL.

---

## Conventions

- **`main` is always shippable.** Every commit on this branch
  must build + test + clippy cleanly on the default feature set.
  H.264 / HDC / GUI are behind feature flags so the default build
  stays lean.
- **Feature-gated code lives in its own crate.** `xenia-video`
  (codecs), `xenia-capture` (screen capture), `xenia-transport-ws`
  (WebSocket), `xenia-transport-quic`, `xenia-inject`, etc.
- **Pattern for new Symthaea carries:** inline the minimal
  dependencies (e.g. `ContinuousHV` in `hdc.rs`) rather than
  cross-crate paths, unless the upstream dep is already published
  to crates.io.
- **Every milestone ends in a live smoke test** (not just unit
  tests). The byte-exact `--verify` path on passthrough is the
  canonical regression gate.
