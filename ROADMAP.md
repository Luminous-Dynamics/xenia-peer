# xenia-peer roadmap + status

Single source of truth for what's shipped, what's next, and what's
deferred. Updated by humans, not by commits. Last refresh:
2026-04-18 (post-U1–U4 unification arc).

If this file disagrees with reality, the file is wrong.

---

## What's shipped

### Repository state

| Item | Status | Notes |
|---|---|---|
| 9-crate workspace | ✅ | `xenia-peer-core`, `xenia-peer`, `xenia-viewer`, `xenia-capture`, `xenia-video`, `xenia-transport-ws`, `xenia-inject`, `xenia-handshake` + workspace root |
| `flake.nix` | ✅ | H.264 + Wayland/DBus/PipeWire + libGL/libxkbcommon on LD_LIBRARY_PATH |
| CI (GitHub Actions) | ✅ | fmt + clippy + test (ubuntu/macos/windows) + MSRV 1.85 + docs + h264 matrix |
| ADR-001 architecture decisions | ✅ | `docs/ADR-001-m0-architecture.md` — monorepo, Wayland-exclusive, AGPL split |
| ADR-002 library licensing | ✅ | `docs/ADR-002-library-licensing.md` — all library crates Apache/MIT; binaries AGPL. Extends ADR-001. |

### Codecs (3)

| Codec | Feature | Status | Typical bandwidth (320×200 TestCapture @ 30 fps) |
|---|---|---|---|
| Passthrough | (default) | ✅ live | 256 KB / frame always |
| H.264 (libx264) | `h264` | ✅ live | 11.8 KB keyframe + ~2.7 KB P-frame |
| HDC hybrid tile-delta | `hdc` | ✅ live | 64.5 KB keyframe + 37 B per static delta frame |

### Transports (2)

| Transport | Crate | Status |
|---|---|---|
| TCP length-prefix | `xenia-peer-core::transport::TcpTransport` | ✅ live |
| WebSocket (binary frames) | `xenia-transport-ws` | ✅ live |

### Viewers (3)

| Viewer | Lives in | Status |
|---|---|---|
| CLI (`xenia-viewer`) | this repo | ✅ live, used by `--verify` smoke tests |
| egui GUI (`--gui` flag) | this repo | ✅ live, renders decoded RGBA at 1:1 |
| Browser (`xenia-viewer-web/daemon.html`) | `xenia-wire` repo | ✅ live (passthrough codec only so far) |

### Test matrix that works today

| Daemon | Viewer | Transport | Codec | Status |
|---|---|---|---|---|
| `xenia-peer` on desktop | CLI | tcp / ws | all three | ✅ loopback + LAN |
| `xenia-peer` on desktop | egui `--gui` | tcp / ws | all three | ✅ visually verifiable |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | passthrough | ✅ |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | h264 | ❌ needs WebCodecs wiring |
| `xenia-peer` on desktop | browser (phone or desktop) | ws | hdc | ❌ needs bincode+grayscale decoder in WASM (~50 LOC) |
| **Phone → desktop** (phone as daemon) | desktop viewer | any | any | ❌ needs phone-side daemon port |

---

## Hard blockers for real deployment

These MUST land before anyone uses xenia-peer on anything that
handles real traffic. Today every binary uses a hardcoded fixture
AEAD key — that's fine for a loopback demo, catastrophic for a
deployment.

| # | Item | Status | Estimate | Why it blocks |
|---|---|---|---|---|
| B1 | **PQC handshake** (ML-KEM-768 + Ed25519 + HKDF-SHA256) | 🟡 crate shipped (`xenia-handshake`, `4215ab1`, 15 tests); **wiring into binaries pending** | 0.5 day to wire | Fresh-impl against RustCrypto `ml-kem` 0.3.0-rc.2 + `ed25519-dalek` 2 + `hkdf` 0.12. Not a Symthaea carry — symthaea's version depended on `mycelix-crypto`. API shape aligned for easy reverse-migration. Still need: replace `FIXTURE_KEY` in `xenia-peer` + `xenia-viewer` + browser viewer with real handshake. |
| B2 | **Real Wayland capture** | ❌ Write fresh against `wayland-client` + `xdg-desktop-portal` | 3–5 days (wlroots) + 5–7 days (portal) | Without this, daemon only shares synthetic TestCapture frames. `xenia-capture::{WlrootsCapture, PortalCapture}` are `Unavailable` stubs today. |
| B3 | **Consent ceremony UI on the host** | ❌ Uses draft-03 SPEC §12 from xenia-wire | 2–3 days | The wire-level state machine exists; the UX to prompt a user "technician-X wants to share your screen, approve?" does not. |

---

## From Symthaea: carry-wholesale backlog (per VIEWER_PLAN §0.1)

### Carried (already here)

| Symthaea path | Landed here | Commit |
|---|---|---|
| `src/swarm/rdp_capture.rs` (trait + TestCapture + BlankCapture) | `crates/xenia-capture/src/lib.rs` | `bd081cf` |
| `src/swarm/rdp_codec.rs` (HDC hybrid tile-delta) | `crates/xenia-video/src/hdc.rs` | `9bb831f` |
| `crates/symthaea-phone-embodiment/src/scrcpy/decoder.rs` (ffmpeg-next patterns) | `crates/xenia-video/src/h264.rs` (inspired; different codec) | `21d8cf3` |
| `src/swarm/rdp_input.rs` (InputInjector trait + Wayland/uinput backends) | `crates/xenia-inject/src/lib.rs` | `23a49a9` |
| `src/swarm/pqc_handshake.rs` (API shape only — fresh crypto impl) | `crates/xenia-handshake/src/lib.rs` | `4215ab1` |

### Still to carry (ranked by value)

**Tier 2 — makes this a real product:**

| # | Symthaea path | LOC | Maps to | Notes |
|---|---|---|---|---|
| ~~T2.1~~ | ~~`src/swarm/rdp_input.rs`~~ | ~~354~~ | ✅ shipped as `xenia-inject` (`23a49a9`). X11 backend dropped. Wayland + uinput are scaffold stubs; real plumbing lands with matching xenia-capture backend. |
| T2.2 | `src/swarm/quic_transport.rs` | 785 | new `xenia-transport-quic` crate | Iroh QUIC. Primary transport per VIEWER_PLAN §4.5; also gives NAT-punch for phone-to-VM tests without Tailscale. |
| T2.3 | `src/swarm/rdp_clipboard.rs` | 223 | new `xenia-clipboard` crate or feature in `xenia-peer-core` | Bidirectional clipboard with sensitivity scrubbing. |
| T2.4 | `src/swarm/rdp_file_transfer.rs` | 198 | new `xenia-file-transfer` crate or feature | Chunked file transfer with BLAKE3. |

**Tier 3 — nice to have:**

| # | Symthaea path | LOC | Notes |
|---|---|---|---|
| T3.1 | `src/swarm/rdp_audio.rs` | ? | Audio streaming. |
| T3.2 | `src/swarm/rdp_recording.rs` | ? | Session recording / replay (`.xenia-session` format). |
| T3.3 | `src/swarm/rdp_adaptive.rs` | 280 | Adaptive bitrate skeleton; wire to `xenia-video` backends. |
| T3.4 | `crates/symthaea-phone-embodiment/src/scrcpy/*` + `streaming_bridge.rs` | ~2000 | **Phone-as-source.** Unblocks the phone→desktop test leg by letting a desktop capture its phone's screen via USB + scrcpy. |

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
| **M1.2c** | Real Wayland screen capture (wlr-screencopy + xdg-portal) | ❌ not started — this is **B2** above |
| **M2** | Input injection + consent-ceremony UI | 🟡 `xenia-inject` crate shipped (`23a49a9`); real backend + consent UI pending (**B3**) |
| **M3.1** | WebSocket transport | ✅ `e765459` |
| **M3.2** | Iroh QUIC primary transport | ❌ not started — **T2.2** |
| **M4.0** | egui GUI on xenia-viewer | ✅ `fd28bc3` |
| **M4.1** | WASM browser viewer speaks daemon protocol | ✅ `e68c5ad` (in xenia-wire repo) |
| **M4.1b** | WebCodecs H.264 decode in browser | ❌ not started |
| **M4.1c** | HDC codec in the browser viewer | ❌ not started (~50 LOC WASM) |
| **M4.2** | HDC hybrid codec (port from Symthaea) | ✅ `9bb831f` |
| **M4.2b** | HDC codec RGB output (not grayscale-only) | ❌ not started |

---

## The "three-way test matrix" (user's stated goal)

This is the concrete goal organizing the next round of work:

### ✅ Desktop ↔ Desktop (works today)

Two machines on the same LAN / Tailscale, both running the native
binaries. All three codecs, both transports, CLI or GUI viewer.
Only caveat: real screen content requires **B2** (Wayland capture);
today both ends use the synthetic `TestCapture` gradient.

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

1. **B1 wiring order:** the crate is shipped; what's left is wiring
   `xenia-handshake::HandshakeManager` into `xenia-peer` (daemon) +
   `xenia-viewer` (both CLI and egui) + the browser viewer so the
   fixture key goes away. Do we want it behind a feature flag
   initially (explicit `--insecure-fixture-key` opt-out) or a
   hard cutover?
2. **B2 vs B3 ordering:** with B1 at the crate layer, real Wayland
   capture (B2) and the consent UI (B3) are the last two blockers
   for real deployment. B2 unblocks visible content; B3 unblocks
   the consent-ceremony promise. Neither depends on the other.
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
  (WebSocket), future `xenia-transport-quic`, `xenia-inject`, etc.
- **Pattern for new Symthaea carries:** inline the minimal
  dependencies (e.g. `ContinuousHV` in `hdc.rs`) rather than
  cross-crate paths, unless the upstream dep is already published
  to crates.io.
- **Every milestone ends in a live smoke test** (not just unit
  tests). The byte-exact `--verify` path on passthrough is the
  canonical regression gate.
