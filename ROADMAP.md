# xenia-peer roadmap + status

Single source of truth for what's shipped, what's next, and what's
deferred. Updated by humans, not by commits. Last refresh:
2026-07-02 (B1/B2/B3 real handshake/capture/consent wiring, first live
validations, and a real `XdgPortalInjector` input backend — see
B1/B2/B3/M1.2c/M2 below).

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
| B1 | **PQC handshake** (ML-KEM-768 + Ed25519 + HKDF-SHA256) | ✅ **fully done 2026-07-02**, including the lane-envelope + rekey scope discovered after this row was first written. `xenia-viewer-web`'s `WasmHandshake::finish` now returns the full transcript-bound key schedule (all 7 `SessionKeySchedule` fields + transcript hash, not just the single `aead` key). New `WasmLaneSession` (4 independently-keyed `xenia_wire::Session`s, one per lane, mirroring native `LaneSession`) decodes real `XLN1`-lane-tagged video/capabilities/rekey frames via `openLaneFrame`. New `WasmRekeyState` validates each inbound `RawRekey::Proposal`, derives + installs the new epoch's lane keys, and builds the Ack — handles rekeys *continuously* (every few video frames by default), not as a one-off. `www/daemon.js` rewired end-to-end onto this. Verified three ways: (1) a dev-dependency cross-compat test proving all 7 schedule keys match the native `SessionKeySchedule` byte-for-byte; (2) a second cross-compat test driving a real native `LaneSession` (sealing) against `WasmLaneSession`/`WasmRekeyState` (opening) through a video frame → a full rekey Proposal/Ack exchange → a second post-rekey video frame, all byte-identical; (3) a live Node.js run against a real `xenia-peer --transport ws` daemon: real handshake, 10 real video frames decoded (byte-length verified), 4 real rekey proposals handled and acked continuously, daemon kept streaming throughout. Two real bugs caught before shipping by writing test (2) first: the rekey key-install order was backwards (sealed the Ack under the old key instead of the new one the daemon expects), and the Ack payload was missing the outer `RawFrame` wrapping every sealed frame actually needs (wire `Frame.payload` is bincode(RawFrame), not the inner payload type directly). | Done | Fresh-impl against RustCrypto `ml-kem` 0.3.0-rc.2 + `ed25519-dalek` 2 + `hkdf` 0.12, exact-pinned to match `xenia-handshake`'s resolved versions (a plain semver range silently resolved a newer, API-incompatible `ml-kem`/`kem` in testing). Not a Symthaea carry — symthaea's version depended on `mycelix-crypto`. |
| B2 | **Universal host ingestion** | ✅ display backend (ScapCapture) wired into the daemon and validated on KDE-Wayland 2026-07-02: real 1920×1080 frames, zero decode errors, **16.76 effective fps — clears the 15fps bar** (`VERDICT: PASS`). Earlier same-day runs measured 0.33–8.70fps against a static desktop; root-caused to PipeWire's damage-driven ScreenCast (only pushes frames on visible screen changes), not a code defect — see `mycelix-sovereign/docs/capture-validation-runbook.md`. A separate real integration bug (encoder built from `--width`/`--height` CLI defaults, silently dropping every real-resolution frame) was also found and fixed the same day. 🟡 GNOME-Wayland attempted 2026-07-02/03 in a dedicated NixOS test VM — **blocked on a real environmental gap, not a code defect**, narrowed across three rounds. Round 1: no DRM render node at all (`xdg-desktop-portal-gnome`'s Zink/GBM picker path had nothing to render against). Round 2: added a real GL-accelerated virtio-gpu (`virtio-vga-gl` + `egl-headless` off the host's Intel iGPU render node) — got a render node, but virgl negotiated without blob/host-visible resources and the picker failed identically. Round 3: added `blob=true` + a memfd-backed memory-backend — blob resources genuinely negotiated this time, and the failure signature changed (Mesa now tries AMD's `radv` via `vdrm_device_connect` instead of Intel's `anv`, on a host with no AMD GPU at all) but capture still fails identically end to end (`VERDICT: FAIL`, 0 frames, `LinCapError { msg: "Did not get response" }` after all 5 retries). Read as a virglrenderer/Mesa native-context vendor-selection mismatch specific to this QEMU/virglrenderer/kernel combination — stopped chasing further `qemu.options` guesses at that point. KDE's own portal doesn't share this hard GPU dependency (its D-Bus race was purely timing, resolved by retrying). Full writeup, including three other real NixOS-VM infra findings surfaced along the way (SLIRP DNS proxy drops EDNS0 queries; tmpfs writable-store overlay too small for a full GNOME devShell), in `mycelix-sovereign/docs/capture-validation-runbook.md`. wlroots/macOS/Windows still unmeasured; real input backends beyond xdg-portal: uinput now done (see M2), wlroots/wayland-virtual still pending; real audio capture+playback is now done (see T3.1). | Done for display on KDE-Wayland; GNOME-Wayland now needs either a host reboot (may or may not clear the native-context mismatch — untested) or a real GNOME-Wayland operator, not further test-VM config tweaks; 3–7 days per remaining audio/input backend; unknown for other display OSes/compositors | Capture is no longer synthetic-only and meets its own performance bar on the one platform measured so far. `xenia-capture` exposes host-agnostic display, audio, input, and telemetry traits; native daemon/viewer stream sealed `sysinfo` telemetry with explicit `basic`/`system`/`off` policy, plus synthetic RawAudio frames for jitter/timing validation. |
| B3 | **Consent ceremony UI on the host** | ✅ **fully done 2026-07-03** — wire-level state machine + M1RuntimeSession gate wired end-to-end 2026-07-02: `--consent-port` parses real Approve/Deny decisions (blocking with `--consent-timeout-secs`, graceful exit on deny/timeout instead of a crash), and the actual request scope is broadcast over `--admin-port`. Packaging gap closed 2026-07-03: `apps/sovereign-admin`'s built console is now embedded directly into the `xenia-peer` binary (`admin_ui.rs`, via `rust-embed`) and served from the same axum router as `/ws` — visiting `http://127.0.0.1:<admin-port>/` gets the real operator console straight from the daemon, no separate `trunk serve` process or standalone app required. Two real bugs caught and fixed while closing this: `sovereign-admin/index.html` referenced the crate's old name (`xenia-admin` vs. the actual `sovereign-admin`), which meant `trunk build` had never actually succeeded before — nothing had run it for real until this pass; and `scripts/xenia-audio-e2e-smoke.sh`'s log-grep assertions were fragile to `tracing_subscriber`'s ANSI auto-detection corrupting the literal substrings they grep for (fixed with a forced `NO_COLOR=1`). Verified live: real `xenia-peer` binary curled for its embedded HTML/CSS/JS/WASM (correct content-types, byte-identical sizes, 404 on unknown paths, `/ws` still upgrades correctly alongside the new routes), and the full smoke test (tcp/ws/quic + negative-consent + real consent-approve/consent-deny) passes clean against the same router. | Done | Uses draft-03 SPEC §12 from xenia-wire. All three "hard blockers for real deployment" (B1, B2's KDE leg, B3) are now cleared. |
| B4 | **PQC signature agility** (`docs/crypto/FULL_PQC_MIGRATION_PLAN.md` Stage 2: ML-DSA-65 transcript signing) | ✅ **native + browser both done 2026-07-03** — `xenia-handshake`'s `HandshakeManager` gained an ML-DSA-65 identity (`ml_dsa_public_key_bytes`/`sign_ml_dsa`/`verify_ml_dsa`), and the live `xenia-peer-core` handshake driver (`perform_host_handshake_with_transcript_and_context`/`perform_viewer_handshake_with_transcript`) dual-signs: `HostHello`/`ViewerResponse`/`HostFinalize` all carry an ML-DSA-65 public key and/or signature alongside the existing Ed25519 ones, both signature transcripts (`viewer_signature_transcript`/`host_signature_transcript`) bind the new fields, and verification requires **both** algorithms to pass (AND composition, no classical-only fallback). This is "Hybrid PQ/T" per the migration plan's claim-boundary vocabulary, not yet "Full-PQC" — Ed25519 stays as a co-signer until a later stage removes it. `xenia-viewer-web`'s `WasmHandshake` (separate `xenia-wire` repo) now mirrors this exactly — verified via the real `handshake_cross_compat` test (drives a REAL native host handshake against the WASM implementation, not a mock) after catching a real interop bug: two label constants (`TRANSCRIPT_SIGNATURE_SUITE_LABEL`, `HANDSHAKE_POLICY_PROFILE`) had been updated natively for Stage 2 but not mirrored in the WASM copy, causing a genuine transcript-hash mismatch the cross-compat test caught immediately. `cargo test --workspace`/`cargo clippy` clean natively; `cargo test`/`cargo clippy`/`cargo build --release --target wasm32-unknown-unknown` clean in `xenia-viewer-web`. | Done, both native and browser | Interop gap from the native-only Stage 2 landing (2026-07-02) is now closed — a dual-signing native peer and the browser viewer can complete a real handshake together. |

### B2 follow-up: two real capture memory leaks found and fixed (2026-07-04)

Live capture on KDE-Wayland was found to grow RSS unboundedly under heaptrack
(738MB+ within ~80s). Two distinct, real bugs, found via heaptrack profiling
(not source-reading guesses — an earlier D-Bus `remove_match`-token-leak
hypothesis was investigated and disproven via a live A/B isolation test before
this):

1. **Fixed, in this repo**: `xenia-capture`'s own `scap_backend.rs` used an
   unbounded `std::sync::mpsc::channel()` to ferry frames from the scap
   worker thread to the daemon. Bounded it to `mpsc::sync_channel(1)`.
   Verified clean (`cargo test`/`cargo clippy` both pass).
2. **Root-caused via heaptrack, fixed only in a local patch (not pushed)**:
   `scap` itself (the `Luminous-Dynamics/scap` fork,
   `fix/linux-engine-two-level-frame-enum` branch) has its own *separate*
   unbounded `mpsc::channel()` in `capturer/mod.rs`, ferrying frames from the
   PipeWire callback thread (`engine::linux::process_callback`, which
   unconditionally `to_vec()`s every frame buffer PipeWire delivers,
   independent of whether `get_next_frame()` is being called) to
   `Capturer::get_next_frame()`. Any time the daemon's downstream
   (encode/network) lags PipeWire's delivery rate even briefly, frames pile
   up here with zero backpressure. heaptrack confirmed this as ~1.44G of
   1.47G total leaked in a 25.76s repro, 100% attributed to that call site.
   Patched locally to `mpsc::sync_channel(2)` (propagated through
   `Engine::new`'s `tx` parameter type and the Linux engine's
   `ListenerUserData`/`pipewire_capturer`/`LinuxCapturer::new`). Re-verified:
   same repro run 5x longer (136.74s) now leaks only ~77.6MB total, and that
   remaining figure is dominated by `gimli`/`addr2line` panic-backtrace
   formatting overhead from the retry loop's `catch_unwind` (debug-build
   noise, unrelated to frame data) — the `process_callback` leak site is
   completely gone from the profile. `cargo test -p xenia-capture
   --features scap-backend` (11/11) still passes against the patched dep.
   **Pushed 2026-07-04** to `Luminous-Dynamics/scap`'s
   `fix/linux-engine-two-level-frame-enum` branch (`42e0745..be78534`) —
   `xenia-capture/Cargo.toml`'s existing git dependency on that branch
   picks it up directly; the temporary local `[patch]` override has been
   removed and `cargo build`/`cargo test`/`cargo clippy` all re-verified
   clean against the real upstream commit (`#be785343`).

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
| ~~T2.3~~ | ~~`src/swarm/rdp_clipboard.rs`~~ | ~~223~~ | ✅ shipped as `--clipboard {off,host-to-viewer,bidirectional}` in `xenia-peer-core`/`xenia-peer`/`xenia-viewer` (wire protocol `f5c5340`, real OS I/O `60c5644`) | Text-only, no sensitivity scrubbing (e.g. no password/secret detection or redaction) -- that part of the original scope is not implemented. |
| ~~T2.4~~ | ~~`src/swarm/rdp_file_transfer.rs`~~ | ~~198~~ | ✅ shipped in `xenia-peer-core`/`xenia-peer`/`xenia-viewer` (`eff2bd1`) | Chunked (64 KiB), BLAKE3-verified, bidirectional (`--send-file`/`--recv-file-dir` on both ends, `xenia-viewer --gui` only). Whole file buffered in memory, capped by `--file-transfer-max-bytes` (200 MB default) -- no streaming-to-disk yet. |

**Tier 3 — nice to have:**

| # | Symthaea path | LOC | Notes |
|---|---|---|---|
| T3.1 | `src/swarm/rdp_audio.rs` | ? | ✅ **real device capture+playback verified live 2026-07-03** (on top of the RawAudio timing lane: 48 kHz stereo S16LE, deterministic sine/noise sources, jitter buffer, GUI/CLI accounting, TCP/WS/QUIC conformance). `CpalAudioCapture::new_default_input` (daemon, real mic) had a real bug: it only checked `device.default_input_config()` — the rate the OS/sound server currently has the device opened at (44100 Hz on this machine's PipeWire setup) — and hard-failed if it wasn't exactly 48000 Hz. That's a *current setting*, not a hardware limit; fixed by searching `supported_input_configs()` for a ≤2-channel range whose range actually covers 48000 Hz, preferring stereo. Verified end-to-end on real hardware (Jabra headset default mic + speakers), not synthetic sine/noise: a real daemon captured real mic audio at 48kHz/stereo, streamed it over WS through a real handshake + multiple rekeys, and a real viewer decoded and played 18 real frames to the real speaker (`audio last: stream=1 sequence=19 rate=48000 channels=2`). `DeviceAudioSink` (viewer, real speaker playback) needed no equivalent fix — it doesn't hard-require 48kHz, it just uses whatever the output device reports. **Opus confirmed working too, including combined with real hardware** (2026-07-03): the existing `scripts/xenia-audio-e2e-smoke.sh --with-opus` path already passed cleanly against synthetic sine/noise sources over tcp/ws/quic before this session; separately, a real end-to-end run combining both fixes — real mic capture (48kHz) + real Opus encode + WS transport + real Opus decode + real speaker playback — produced the same clean result (20 frames decoded, 18 played, `rate=48000 channels=2`) as the raw-pcm real-hardware run, just Opus-compressed this time. Opus is not just implemented, it's proven against real hardware. |
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
| **M2** | Input injection + consent-ceremony UI | ✅ **input pipeline fully wired end-to-end 2026-07-02**, real hardware confirmed. Consent-ceremony gate wired (**B3**). `XdgPortalInjector` (`org.freedesktop.portal.RemoteDesktop` via `ashpd`) validated on KDE-Wayland — 8/8 real pointer/key/touch injections (see `mycelix-sovereign/docs/input-injection-validation-runbook.md`). Daemon receive-loop: `Transport` split into `SendEnvelope`/`RecvEnvelope` halves for all 3 backends (TCP/WS/QUIC), `LaneSession::seal_input_event`/`open_input` added (control-lane key, no `XLN1` wrap), `apps/xenia-peer` runs a dedicated recv task dispatching lane-tagged control frames (rekey acks) vs. bare envelopes (input, gated through `M1RuntimeSession::allow_input_flow`) to the `--input-backend {noop,log,xdg-portal}` injector (constructed lazily so `noop` never triggers the portal dialog). `apps/xenia-viewer/src/gui.rs` now captures real egui pointer motion/buttons and a common-subset keymap (letters/digits/nav/F-keys → Linux evdev codes), normalized against the actual rendered-image rect, sent over a split outbound path to the daemon. **Live end-to-end proof (2026-07-02, real KDE-Wayland desktop, `--input-backend log`)**: operator moved the mouse and typed inside a real running `xenia-viewer` GUI window connected to a real `xenia-peer` daemon; the daemon's `LoggingInjector` recorded 1,280 pointer-motion events, 27 button presses, and 202 key events, all with correctly denormalized/mapped values — proof the whole path (egui capture → seal → transport → lane open → bincode decode → M1 gate → inject) works for real. **Stretch validation also done the same day**: (1) same live loop with `--input-backend xdg-portal` — a real consent dialog appeared (not a cached grant), operator approved it, and their real host mouse cursor moved in response to the viewer's captured pointer motion; (2) the real (non-bypassed) M1 Approve/Deny consent ceremony verified end-to-end for the first time this session (every earlier live test used `--m1-preprod-auto-consent`) — Deny: daemon exits, 0 frames ever flow; Approve: 15 frames streamed and byte-verified. See `mycelix-sovereign/docs/input-injection-validation-runbook.md` for both. `WaylandInputInjector` remains a scaffold stub. **`UinputInjector` implemented for real 2026-07-03** using the `input-linux` crate (chosen over the older, unmaintained `uinput` crate on crates.io, which pulls in a ~2018-era nix 0.10/gcc chain): real kernel-level `/dev/uinput` virtual device with absolute pointer (ABS_X/ABS_Y, same [0,1] denormalization convention as `XdgPortalInjector`), the full keyboard keycode range (raw `UI_SET_KEYBIT` ioctl, not the crate's typed `Key` enum, since transmuting arbitrary evdev codes into it would be UB), and single-point touch (multi-touch needs the `ABS_MT_*` slot protocol, not implemented). Wired in as `--input-backend uinput` (feature-gated, off by default) — this needs no compositor, portal, or Wayland session at all, only `/dev/uinput` access, making it the path for headless hosts or compositors without a working RemoteDesktop portal. Verified for real: independently confirmed via `/proc/bus/input/devices` that a real kernel-recognized device ("xenia-virtual-input", `EV=b` for SYN|KEY|ABS, `ABS=3` for X+Y) appears, handled by the kernel as a real evdev+mouse node. A full live daemon+viewer round trip with real cursor movement was deliberately not attempted — unlike the `xdg-portal` validation above (done inside an isolated VM), this would move the operator's actual cursor on their real desktop session without their active involvement. |
| **M3.1** | WebSocket transport | ✅ `e765459` |
| **M3.2** | Iroh QUIC primary transport | ✅ library crate + conformance tests + daemon/viewer CLI smoke |
| **M4.0** | egui GUI on xenia-viewer | ✅ `fd28bc3` |
| **M4.1** | WASM browser viewer speaks daemon protocol | ✅ `e68c5ad` (in xenia-wire repo) |
| **M4.1b** | WebCodecs H.264 decode in browser | ✅ **done 2026-07-04** (in the `xenia-wire` repo, `xenia-viewer-web` crate) — `src/h264.rs`: minimal Annex-B NAL parsing recovers the two things the wire format doesn't carry that WebCodecs needs: `EncodedVideoChunk`'s keyframe flag (IDR NAL scan) and `VideoDecoder.configure()`'s exact `avc1.PPCCLL` codec string (from the real first-seen SPS's profile/constraint-flags/level bytes, not guessed). Actual decode runs in the browser's native `VideoDecoder`, not WASM. `daemon.js` lazily configures a `VideoDecoder` on the first codec string seen and draws each output `VideoFrame` via `ctx.drawImage` (closing it immediately after — `VideoFrame`s hold real GPU/native memory). Verified three ways: (1) unit tests against hand-built Annex-B fixtures; (2) a cross-compat test (gated behind an opt-in `h264-test` feature so a plain `cargo test` doesn't need libav headers) driving a REAL native `H264Encoder`/libx264 through a keyframe + 19 more frames, asserting keyframe detection agrees with the encoder's own flag and a valid codec string comes out of the real inline SPS; (3) a genuine headless-Chromium end-to-end run via raw CDP (not a mock): 10 real Annex-B chunks from the actual native encoder decoded successfully by a real `VideoDecoder` at the correct 64×64 dimensions, codec string `avc1.42c014` matching libx264's own reported "Constrained Baseline, level 2.0". Needed `--disable-accelerated-video-decode` to work around this sandbox's broken VA-API drivers, and real wall-clock CDP polling instead of `--virtual-time-budget` (incompatible with Chromium's real cross-process video-decode scheduling). Full test suite/clippy/wasm32 build clean. |
| **M4.1c** | HDC codec in the browser viewer | ✅ **done 2026-07-04** (in the `xenia-wire` repo, `xenia-viewer-web` crate) — decode-only reimplementation of `xenia_video::hdc`'s wire format (`src/hdc.rs`: shadow packet/patch structs + keyframe/delta canvas-patching, matching the native decoder byte-for-byte). `WasmLaneSession` holds a persistent per-lane `HdcDecoderState` (HDC is delta-coded, needs session-lifetime canvas state, not one-shot decode); `openLaneFrame` dispatches `PixelFormat::Hdc` frames through it, returning the same `{width,height,rgba,frame_id,...}` shape as passthrough plus `pts_ms`. `daemon.js` draws both identically. Verified via a new cross-compat test (dev-dependency on the real `xenia-video` crate): drives a real native `HdcEncoder` through a two-tone-color keyframe + delta, asserts byte-identical WASM decode at both steps — also exercises M4.2b's RGB fix, not just wire framing. Full test suite/clippy/`wasm32-unknown-unknown` build clean. |
| **M4.2** | HDC hybrid codec (port from Symthaea) | ✅ `9bb831f` |
| **M4.2b** | HDC codec RGB output (not grayscale-only) | ✅ **done 2026-07-04** — `extract_tile_grayscale` replaced with `extract_tile_rgb` (3 bytes/pixel, no alpha); decoder expands RGB straight into the RGBA canvas (A=255) instead of replicating a single luminance byte across R/G/B. Change-detection/classification still run on HDC features computed from the original pixels (unaffected) — only the *transmitted* tile payload changed. Caught and fixed a real correctness bug in the same pass: `HdcEncoder` accepts both RGBA and BGRA input, and grayscale output was accidentally order-invariant (luminance sums are symmetric), but true RGB isn't — added an explicit channel swap for BGRA-tagged frames so colors don't come out with red/blue swapped. Two new tests (`decoded_output_preserves_true_color_not_just_luminance`, `bgra_input_normalizes_to_true_rgb_on_the_wire`) assert real non-grayscale color round-trips correctly for both input orders. `cargo test -p xenia-video --features hdc` (13/13) and full `cargo test --workspace --features "xenia-peer/hdc xenia-viewer/hdc"` both clean. |
| **M4.3** | RawAudio timing lane | ✅ sealed RawAudio + jitter buffer + synthetic source + native transport conformance |
| **M4.3b** | Opus audio payload | ❌ not started |
| **M4.3c** | Clipboard sync (T2.3) | ✅ **done 2026-07-05** — `--clipboard {off,host-to-viewer,bidirectional}` on both `xenia-peer` and `xenia-viewer`. Host-to-viewer rides the existing lane-envelope system (new `PixelFormat::Clipboard`, forward path via `RawClipboard::into_frame`/`seal_frame`, routed onto the control lane); viewer-to-host (bidirectional only) mirrors `RawInput`'s bare-envelope reverse path with its own payload type (`PAYLOAD_TYPE_CLIPBOARD = 0x30`) so the daemon's recv loop can distinguish a clipboard update from an input event by peeking `xenia_wire::envelope_payload_type` (cleartext nonce byte) without a wasted decrypt attempt. Viewer-to-host apply is gated by a new `M1Permission::ClipboardSync` (mirrors `InjectInput`). Real OS I/O via `arboard` (wayland-data-control + x11), a fresh `Clipboard` opened per poll rather than cached (not `Send` on Linux, can't cross an `.await` shared between tasks). **Verified live** on a real KDE-Wayland session: real daemon + real headless `xenia-viewer` over a real TCP socket, host clipboard change observed/sealed/sent/decoded/applied to the viewer's OS clipboard, confirmed via log lines on both sides, not just unit tests. Also caught a real bug the same way: `arboard::Clipboard::clear()` doesn't reliably override a selection still served by an earlier `set_text()` call from a different connection (stale value kept reading back after `clear()` returned `Ok`) -- `ClipboardContent::Cleared` uses `set_text("")` instead, which does override it; `examples/clipboard_smoke.rs` is a permanent manual regression check for this (needs a real compositor, not run in CI). Text-only; no sensitivity scrubbing (password/secret detection) from the original Symthaea scope. |
| **M4.3d** | File transfer (T2.4) | ✅ **done 2026-07-05** — `FileTransferMessage` (Offer/Accept/Reject/Chunk/Complete/Verified), symmetric bare-envelope protocol usable from either side, gated by new `M1Permission::FileTransfer`. `--send-file <path>` offers a file once connected; `--recv-file-dir <dir>` (off by default) is required to accept anything, writes to a sanitized bare filename only (no path traversal). 64 KiB chunks; whole file buffered in memory both ends, capped by `--file-transfer-max-bytes` (200 MB default) -- no disk-streaming yet. `xenia-viewer` only wires this into `--gui` mode; the headless CLI probe mode rejects the flags outright rather than silently no-op'ing. **Two real bugs caught via live daemon+viewer testing, both now regression-tested**: (1) sealing both directions' messages under one shared payload type let host's and viewer's independent per-session nonce counters collide under the shared `source_id` -- an actual AEAD nonce reuse, not just a replay-window false positive; fixed with a payload type per *sealing side* (`PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST`/`_VIEWER`), same pattern that already keeps input/clipboard-reverse safe. (2) the viewer's `--send-file` Offer was sent immediately after the crypto handshake, racing ahead of the daemon's own blocking `perform_rekey` (send Proposal, block on recv Ack) -- the daemon's Ack-shaped `recv_envelope()` call picked up the Offer envelope instead; fixed by deferring the viewer's initial Offer until after its own Rekey Ack is sent. Verified live: real daemon + real GUI viewer over a real TCP socket, both directions offered/accepted/chunked/verified, BLAKE3 hashes of received files matched originals byte-for-byte. |
| **M4.4** | Migrate xenia-viewer-web frontend to Leptos | 🟡 **in progress 2026-07-05** (in the `xenia-wire` repo, new `xenia-viewer-web/leptos-app` Trunk-built CSR crate) — wraps the existing `xenia-viewer-web` WASM handshake/lane-session/decode APIs (`WasmHandshake::begin_inner`/`finish_inner`, `WasmLaneSession`, `WasmRekeyState`, `open_lane_frame_inner`) in a small reactive UI; connection state and frame count are `RwSignal`s, but the `web_sys::WebSocket`-holding `Connection` itself is a plain `Rc<RefCell<Option<Connection>>>` outside the signal system (it isn't `Send`, which `RwSignal`'s default `SyncStorage` requires even in single-threaded WASM). Needed `#[wasm_bindgen(start)] fn main()` + `#![no_main]` at the crate root — a plain `fn main()` in a wasm32 bin-target crate is never invoked by wasm-bindgen's JS glue, and the attribute alone conflicts with Rust's implicit binary entry point without `#![no_main]`. Verified live: real `xenia-peer --transport ws` daemon, completes the full PQC handshake, decodes and canvas-renders a real HDC frame (1920×1080). **WebCodecs H.264 decode landed 2026-07-05** — new `h264.rs` ports daemon.js's `handleH264Frame`/`drawVideoFrame`; web-sys's WebCodecs bindings need `--cfg=web_sys_unstable_apis` (added via `.cargo/config.toml`), which also swapped `put_image_data`'s stable f64-arg overload for an i32-arg unstable one (fixed the one call site). `VideoDecoderConfig` has no typed `avc` field in web-sys, set via raw `js_sys::Reflect`. Verified live: real `xenia-peer --transport ws --codec h264` daemon + this Leptos app in real headless Chromium via CDP, 199 real frames decoded through the browser's native `VideoDecoder`, zero errors. Building this crate needs `nix shell nixpkgs#trunk nixpkgs#wasm-bindgen-cli nixpkgs#binaryen` rather than xenia-peer's own flake devShell -- its pinned rustc 1.94.0 is older than this crate's `rust-version = "1.95"`; no native GUI libs needed since it's a WASM build. A clipboard UI is the one remaining unported vanilla-JS feature — daemon-side clipboard (wire protocol + real OS I/O via `arboard`, see M4.3c) and the rekey state machine already exist and work from the vanilla-JS viewer, just not yet exercised from this crate. |

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
browser. Real screen content works via `--codec passthrough` (B2)
and now also via `--codec hdc` (M4.1c) or `--codec h264` (M4.1b) --
both decode fully in-browser as of 2026-07-04. **Real live-phone-browser
test done 2026-07-04**: real Pixel 8 Pro (Brave browser, USB/ADB
reverse-forwarded to the daemon's port) connected to a real `xenia-peer`
daemon and rendered live passthrough frames correctly — confirmed
correct orientation/content, not just automated headless verification.
Frame cadence was very slow (~1 frame/30s+) during this run, but that's
attributed to severe host CPU contention from concurrent sessions (see
M1.2c/B2's damage-driven-capture note), not a phone/browser-path defect;
a clean FPS re-measurement on an idle host is still pending (task #32).

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
2. **Universal ingestion vs B3 ordering: resolved, B3 landed 2026-07-02.**
   Consent-ceremony gate is wired end-to-end (real `--consent-port`
   Approve/Deny, no more crash-on-unapproved). `XdgPortalInjector` (a
   real input backend, see M2) was built after B3 per this note's
   original guidance — but its portal `Start()` call completed with no
   visible consent dialog (see `input-injection-validation-runbook.md`'s
   "open finding" section), which needs resolving before treating input
   injection as properly consent-gated in practice, independent of
   xenia-peer's own B3 gate being correct.
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
