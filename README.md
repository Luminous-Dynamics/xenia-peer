# xenia-peer

Application-layer crates for Xenia: a peer-to-peer, consciousness-first
remote-session stack built on top of
[`xenia-wire`](https://github.com/Luminous-Dynamics/xenia-wire)
(the PQC-sealed protocol, separate repo).

```text
  ╔═══════════════════════════════════════════════════════════════╗
  ║  PRE-ALPHA — NOT USABLE AS A PRODUCT YET                      ║
  ║                                                               ║
  ║  Well past the original M0 scaffold this box used to          ║
  ║  describe. Real, tested, and merged: screen capture            ║
  ║  (scap-backed + synthetic fallback), H.264/passthrough video, ║
  ║  input injection, an operator RBAC + consent ceremony (a      ║
  ║  browser console, apps/sovereign-admin, drives challenge/      ║
  ║  response auth, role-scoped tokens, a signed+verifiable        ║
  ║  consent ledger, and live operator revocation), and a PQC-     ║
  ║  sealed operator channel with two non-interoperable suites    ║
  ║  (ML-KEM-768+Ed25519+ML-DSA-65 and, for higher assurance,      ║
  ║  ML-KEM-1024+Ed25519+ML-DSA-87 -- both forward-secret via a    ║
  ║  fresh per-handshake KEM keypair, plus host-fingerprint        ║
  ║  trust-on-first-use pinning and rekey). None of that adds up   ║
  ║  to a finished product yet -- see Status below and ROADMAP.md ║
  ║  for what's still missing.                                    ║
  ║                                                               ║
  ║  For a working remote-desktop tool today: RustDesk,           ║
  ║  MeshCentral, or Apache Guacamole.                            ║
  ╚═══════════════════════════════════════════════════════════════╝
```

## Architecture at a glance

Two peers. No relay, no central server, no trust authority. One peer
**hosts** its screen; the other peer **views** it. Both speak
`xenia-wire` underneath; both are ordinary Linux processes.

```
┌─────────────────────────────┐      xenia-wire       ┌─────────────────────────────┐
│  xenia-peer (daemon)        │ ◀───(sealed)────────▶ │  xenia-viewer (CLI/GUI)     │
│  - hosts screen             │                        │  - decodes frames           │
│  - accepts incoming viewers │                        │  - sends input events       │
│  - drives consent ceremony  │                        │  - renders (M4+)            │
│  SessionRole::Host          │                        │  SessionRole::Viewer        │
└─────────────────────────────┘                        └─────────────────────────────┘
            │                                                          │
            └─────────── shared library ──────────────────────────────┘
                              xenia-peer-core
         (Session wrapper, transport trait, raw frame/input types)
```

No "server" in the MSP / client-server sense — the repo was renamed
from `xenia-server` to `xenia-peer` in commit `a861501` precisely
because that legacy naming was actively misleading about the
decentralized trust model. See
[`docs/ADR-001-m0-architecture.md`](docs/ADR-001-m0-architecture.md)
for the full architectural decisions.

## Crate layout

Single Cargo workspace. Core crates:

| Crate | Kind | License | Purpose |
|---|---|---|---|
| [`xenia-peer-core`](crates/xenia-peer-core/) | library | **Apache-2.0 OR MIT** | Shared library: `Session`, `Transport` trait, `TcpTransport`, `RawFrame` / `RawInput`. Reusable by third-party clients. |
| [`xenia-peer`](crates/xenia-peer/) | binary (daemon) | **AGPL-3.0-or-later** | The machine sharing its screen. Listens for viewer connections, hosts the session, drives the consent UI (M2+). |
| [`xenia-viewer`](crates/xenia-viewer/) | binary (CLI → GUI at M4) | **AGPL-3.0-or-later** | The machine watching. Connects to a daemon, decodes frames, renders. Today a CLI probe tool; egui GUI lands at M4. |
| [`xenia-transport-ws`](crates/xenia-transport-ws/) | library | **Apache-2.0 OR MIT** | Binary-envelope WebSocket transport. |
| [`xenia-transport-quic`](crates/xenia-transport-quic/) | library | **Apache-2.0 OR MIT** | Iroh QUIC transport over a long-lived bidirectional stream. |

**Why split the licenses?** The library stays permissive so any tool
(browser client, VS Code extension, TUI, etc.) can link against it.
The binaries are the value-add application layer — AGPL forces a
commercial-user or modify-and-distribute organization to either open
source their stack or negotiate a commercial license. The `xenia-wire`
protocol itself remains Apache-2.0 OR MIT to maximize adoption of the
wire format.

Full reasoning: [ADR-001 §Decision 3](docs/ADR-001-m0-architecture.md).

## Status

The single source of truth for what's done, blocked, and queued is
[`ROADMAP.md`](ROADMAP.md). Short version:

**Live today** — TCP, WebSocket, and Iroh QUIC daemon/viewer
transports, shared transport conformance coverage, passthrough codec
by default, H.264 / HDC behind feature flags, and native CLI / egui
viewer paths. The daemon sends synthetic capture frames through
capture → encode → `xenia-wire` seal → transport, and the viewer can
verify passthrough frames byte-for-byte. The daemon also samples host
telemetry via `sysinfo` and sends it as sealed metadata frames on the
same session; the GUI viewer shows the latest CPU/memory values in a
host panel. A synthetic raw-audio lane is available for protocol
bring-up and jitter accounting; it does not use device capture,
playback, cpal, or Opus yet.

**Hard blockers before real deployment** — real host capture beyond
synthetic frames, consent-ceremony UI, and browser-viewer handshake
wiring. See ROADMAP §"Hard blockers for real deployment".

**Still-to-carry from Symthaea** — platform input backend wiring,
clipboard, file transfer, audio, recording, and richer transport
fallback policy. See ROADMAP §"From Symthaea: carry-wholesale
backlog".

Full VIEWER_PLAN (the parent design doc) is in the sibling repo:
[`plans/VIEWER_PLAN.md`](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/plans/VIEWER_PLAN.md).

## Platform policy

`xenia-capture` is now a host-ingestion abstraction for display,
audio, input, and telemetry. Display capture is intended to be
cross-platform through `scap` where possible: Windows Graphics Capture
on Windows, ScreenCaptureKit on macOS, and PipeWire /
xdg-desktop-portal on Linux.

On Linux, X11 is explicitly out of scope. The X11 server's core design
permits any client to read any other client's keystrokes and screen
content, which is fundamentally incompatible with Xenia's
end-to-end-encrypted consent-gated threat model.

Supported Wayland paths:

- **wlroots compositors** (Sway, Hyprland, labwc): stable
  `wlr-screencopy-unstable-v1` + `libei` for capture + input.
- **GNOME / KDE**: `xdg-desktop-portal`'s `ScreenCast` + `RemoteDesktop`
  interfaces.

Both require an explicit consent prompt from the compositor, which
aligns with Xenia's consent-ceremony UX rather than fighting it.

X11-only systems (older Ubuntu LTS, unmaintained distros) are
unsupported targets. A community X11 backend as a separate
`xenia-peer-x11` fork would be acceptable but is not upstream.

Full reasoning: [ADR-001 §Decision 2](docs/ADR-001-m0-architecture.md).

## Quick start (developers)

### Clone + test

```console
$ git clone https://github.com/Luminous-Dynamics/xenia-peer
$ cd xenia-peer
$ cargo test --workspace
```

Expected: the workspace test suite passes, including the real-TCP
100-frame + 10-input seal/open loopback.

### Run end-to-end (passthrough codec — always available)

Two terminals:

```console
# terminal 1 — host daemon, sends 30 synthetic frames
$ cargo run --release -p xenia-peer -- --listen 127.0.0.1:4747 --frames 30 --codec passthrough

# terminal 2 — viewer, verifies every frame byte-for-byte
$ cargo run --release -p xenia-viewer -- --connect 127.0.0.1:4747 --frames 30 --codec passthrough --verify
```

The viewer locally regenerates each expected frame via a mirror
`TestCapture` and asserts byte-exact equality against what it
decoded. Mismatch = pipeline broken.

The daemon's default `--transport auto` accepts TCP and WebSocket on
the listen address and also starts QUIC/Iroh. A default viewer pointed
at `host:port` first reads the daemon's transport advertisement and
upgrades to QUIC automatically when available. `ws://...` still selects
WebSocket directly, and `iroh:...` can still be passed explicitly.
The daemon samples host telemetry every second by default; tune with
`--telemetry-interval-ms`.

Telemetry policy is explicit:

- `--telemetry-level basic` (default): CPU and memory only.
- `--telemetry-level system`: CPU, memory, hostname, and OS version.
- `--telemetry-level off`: no telemetry metadata frames.

Synthetic audio is explicit and independent of telemetry policy:

- `--audio off` (default): no audio frames.
- `--audio sine`: deterministic 48 kHz stereo S16LE sine frames.
- `--audio noise`: deterministic 48 kHz stereo S16LE noise frames.
- `--audio-interval-ms 20` controls generation cadence.

The viewer validates the audio lane with a jitter buffer and reports
sequence, age, gaps, duplicates, late frames, and underruns. It does
not play audio yet.

For explicit QUIC testing, pass the daemon's printed
`QUIC_CONNECT=iroh:...` value to the viewer:

```console
# terminal 1
$ cargo run --release -p xenia-peer -- --frames 10 --codec passthrough

# terminal 2
$ cargo run --release -p xenia-viewer -- --connect 'iroh:...' --frames 10 --codec passthrough --verify
```

### Run end-to-end (H.264 codec)

H.264 requires libav + libclang at build time. Easiest path is
the bundled Nix flake:

```console
$ nix develop                                 # inside xenia-peer/
$ cargo build --release --workspace --features "xenia-peer/h264 xenia-viewer/h264"
$ ./target/release/xenia-peer --listen 127.0.0.1:4747 --frames 30 --codec h264 --bitrate-kbps 2000 &
$ ./target/release/xenia-viewer --connect 127.0.0.1:4747 --frames 30 --codec h264
```

Outside Nix, install ffmpeg dev + llvm dev packages through your
distro (`libavcodec-dev libavformat-dev libavutil-dev libswscale-dev
libswresample-dev libclang-dev` on Debian/Ubuntu) and rebuild with
the same `--features` flags.

On the synthetic 320×240 gradient at 30 fps the H.264 stream comes
in around 11 KB for the keyframe + ~3 KB per P-frame — ~100× smaller
than passthrough's 256 KB/frame. Real desktop content compresses
further.

## M0 exit criterion (achieved)

> `cargo test -p xenia-peer-core` green; real-TCP loopback test
> exchanges 100 RGBA frames + 10 input events through the full
> `xenia-wire` seal/open path; both binaries (`xenia-peer` and
> `xenia-viewer`) compile and complete a loopback probe exchange.

```
running 4 tests
test session_fixture_constructors_work_without_runtime ... ok
test replay_protection_across_real_transport ... ok
test oversize_envelope_is_rejected_before_allocation ... ok
test hundred_frames_plus_inputs_roundtrip_over_tcp ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured
```

Plus replay protection (duplicate envelope rejected) and oversize-
envelope safety (forged 100 MiB length prefix doesn't OOM the receiver).

## Operator RBAC & sealed operator channel

Landed after M0, not yet reflected above: a role-based operator
authorization system and a PQC-sealed channel for delivering consent
decisions, both with their own consent ledger.

- **`apps/sovereign-admin`** — a Leptos 0.8 CSR browser console. Runs the
  challenge/response auth ceremony against the daemon's `/auth/*` routes
  (both Ed25519 and ML-DSA-65 signatures required, no classical-only
  fallback), holds a role-scoped session token, and asks the native operator
  agent to sign each consent decision / revocation. The daemon independently
  re-verifies every per-action signature rather than trusting the socket or
  browser.
- **Roles**: `Viewer < Approver < Operator < Admin`, strictly hierarchical
  (`docs/security/OPERATOR_RBAC_PLAN.md`). Enforced identically on daemon
  and console via the shared, signing-key-free and I/O-free
  `xenia-operator-proto` crate, so a role the console greys out is exactly a
  role the daemon also refuses and both sides construct identical canonical
  transcripts.
- **Sealed operator channel** (`--operator-sealed`) — consent decisions
  travel inside PQC-sealed envelopes over a handshake-authenticated
  channel instead of a plaintext socket. Two non-interoperable suites,
  selected out-of-band (a daemon flag matched by a console setting, not
  wire-negotiated): the standard ML-KEM-768 + Ed25519 + ML-DSA-65 suite,
  and `--operator-high-security` (ML-KEM-1024 + Ed25519 + ML-DSA-87, NIST
  category 5). Both generate a fresh KEM keypair per handshake (forward-
  secret against a later compromise of the daemon's long-term state) and
  support in-place forward-secrecy rekey on long-lived connections.
  Authorization requires the *enrolled pair* of keys to match (not
  Ed25519 alone), and enrollment is suite-aware -- an operator enrolled
  only for the standard suite cannot use the high-security channel merely
  by sharing an Ed25519 key.
- **Host-fingerprint pinning** — the console trusts a daemon's signing
  identity on first connection (TOFU) and refuses any later connection
  whose fingerprint changed, before sealing or sending anything, with an
  explicit "forget this pin" action for legitimate daemon key rotation.
- **Consent ledger** — every decision is a hash-chained, Ed25519-signed
  `xenia-ledger` entry; the console verifies the chain and each entry's
  signature client-side and can export a self-contained, independently
  verifiable JSON attestation.
- **Live revocation** — an Admin can revoke a compromised operator by id;
  the revocation list is consulted on every channel, live, no daemon
  restart required.
- **`apps/xenia-operator-agent`** — a small native process that holds the
  operator's Ed25519 + ML-DSA seeds in a `0600` file instead of browser
  `localStorage`. It never serves those seeds to the browser: its
  token-authenticated, `127.0.0.1`-only API verifies daemon identity evidence,
  pins host identities, drives the sealed-channel handshake, verifies
  daemon-attested typed consent offers, and signs canonical transcripts.
  Broad grants such as remote input, clipboard access, file transfer, host
  audio capture, or system-identity telemetry require a separate native
  confirmation. Run it once (`cargo run -p xenia-operator-agent`) and paste
  the printed pairing token into the console's Sessions page.

The consent protocol and its exact threat-model boundary are documented in
`docs/security/CONSENT_OFFER_PROTOCOL.md`.

None of this is a finished security story yet. See
`docs/security/OPERATOR_SECURITY_MODEL.md` for the current threat model
and open gaps.

## Licensing

| Layer | License |
|---|---|
| [`xenia-wire`](https://github.com/Luminous-Dynamics/xenia-wire) (protocol) | Apache-2.0 OR MIT |
| `xenia-peer-core` (library) | Apache-2.0 OR MIT |
| `xenia-peer` (daemon binary) | AGPL-3.0-or-later |
| `xenia-viewer` (viewer binary) | AGPL-3.0-or-later |

Full license texts in [`LICENSE-APACHE`](LICENSE-APACHE),
[`LICENSE-MIT`](LICENSE-MIT), and [`LICENSE-AGPL-3.0`](LICENSE-AGPL-3.0).

Dual commercial licensing for the AGPL binaries is available on
request for organizations whose policies preclude AGPL adoption —
the repository author is the sole copyright holder and can grant
exceptions on a case-by-case basis.

## Security

See
[xenia-wire's SECURITY.md](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/SECURITY.md)
for the disclosure policy — `xenia-peer` inherits the same posture.
Do not report security issues via public GitHub issues.

For the audit claim boundary, see
[`docs/security/LEDGER_VERIFICATION_BOUNDARY.md`](docs/security/LEDGER_VERIFICATION_BOUNDARY.md).


For compacted-ledger retention and the explicitly authorized, reversible
quarantine workflow, see
[`docs/security/COMPACTED_STATE_CUTOVER_AND_GC.md`](docs/security/COMPACTED_STATE_CUTOVER_AND_GC.md)
and
[`docs/security/CONSENT_ARTIFACT_RETIREMENT.md`](docs/security/CONSENT_ARTIFACT_RETIREMENT.md).

## Relationship to Track A

[`xenia-wire`](https://github.com/Luminous-Dynamics/xenia-wire) is
Track A: the wire protocol + SPEC draft-03 + paper + demo pages +
(as of `0.2.0-alpha.5`+) its own optional handshake implementations,
currently at `0.2.0-alpha.8`. This repo is Track B: the actual
application layer. Track A is feature-complete-pending-external-review;
Track B is well past its original M0 signal gate -- see Status above.
