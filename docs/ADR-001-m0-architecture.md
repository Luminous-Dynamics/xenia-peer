# ADR-001: M0 architectural decisions

**Status**: accepted
**Date**: 2026-04-18
**Deciders**: tstoltz

## Context

The `xenia-peer` repository (previously `xenia-server`, renamed in
commit `a861501`) is the application-layer half of the Xenia
remote-session stack. The protocol half is the sibling repo
`xenia-wire`, which ships `0.2.0-alpha.3` with SPEC draft-03.

Going into M0 scaffolding, three decisions from `VIEWER_PLAN.md` §6
were still open:

1. Repo layout for the application suite (daemon + viewer).
2. Policy for X11 vs Wayland.
3. Licensing for the application-layer crates.

This ADR records the answers and the reasoning. Subsequent milestones
(M1+) will reference this document rather than re-litigating.

## Decisions

### Decision 1 — Workspace layout

**Decision.** Single Cargo workspace inside this repository. Three
crates:

| Crate | Kind | License | Status |
|---|---|---|---|
| `xenia-peer-core` | library | Apache-2.0 OR MIT | M0 shipped |
| `xenia-peer` | binary (daemon) | AGPL-3.0-or-later | M0 stub |
| `xenia-viewer` | binary (CLI now, GUI at M4) | AGPL-3.0-or-later | M0 stub |

`xenia-wire` stays in a separate repository and continues to ship as
Apache-2.0 OR MIT. The protocol is a public commons; the application
layer is not.

**Rationale.**

- `xenia-peer` (daemon) and `xenia-viewer` (client) will always ship
  against the **same** `xenia-peer-core` version. Splitting them
  into separate repos creates a version-skew hazard whenever the
  core's state-machine API changes; a monorepo makes same-commit
  updates atomic.
- The heavy OS-coupled dependencies (`ffmpeg-next`, `wayland-client`,
  eventually `windows-rs` and `objc2-*` if we cross-platform later)
  are already going to be pulled in once. No point isolating them
  per-repo when the isolation boundary that actually matters is
  between the protocol crate (lean, widely reusable) and the
  application stack (heavy, OS-specific).
- `VIEWER_PLAN.md` originally imagined `xenia-viewer-native` as a
  separate repo to keep licensing discussions isolated. This ADR
  supersedes that: we're comfortable taking the AGPL stance upfront,
  so the isolation argument no longer applies.

### Decision 2 — Wayland exclusively; X11 is out of scope

**Decision.** `xenia-peer` will support Wayland-native capture and
input injection only. X11 is explicitly out of scope for the
foreseeable future. No `x11rb`, no `xcb`, no XTest injection path.

**Rationale.**

- X11's core design permits any client to read keyboard input and
  screen contents of any other client without elevation. For a
  remote-session tool whose entire security model is end-to-end
  consent + sealed transport, running on X11 completely undoes the
  threat model upstream of the wire. The user machine's local
  security is presumed to isolate the session from other desktop
  applications; X11 breaks that presumption.
- Wayland's screen-capture story in 2026 is viable on both major
  paths:
  - **wlroots compositors** (Sway, Hyprland, labwc): stable
    `wlr-screencopy-unstable-v1` protocol.
  - **GNOME / KDE**: `xdg-desktop-portal` with the
    `org.freedesktop.portal.ScreenCast` interface. GNOME's
    post-46 pipewire screencast is reliable; KDE 6's is also good.
- Wayland's input-injection story is less uniform:
  - **libei** (on wlroots compositors that support it) — emerging
    standard.
  - **xdg-desktop-portal `RemoteDesktop`** — works on GNOME/KDE.
  - Both require an explicit consent prompt from the compositor,
    which actually aligns with the Xenia consent-ceremony UX
    (§12.5 of the wire spec).
- Deployments on X11-only systems (old MSP endpoints on pre-2022
  Ubuntu LTS, etc.) are explicitly NOT the target audience for
  this codebase. If a compatibility gap emerges later and the
  demand is strong enough to justify the security cost, a
  separate `xenia-peer-x11` crate can be authored as a
  community-maintained fork. The reference implementation will
  not ship one.

### Decision 3 — Dual-license split: AGPL app layer, Apache/MIT libraries

**Decision.**

- `xenia-wire` (protocol): **Apache-2.0 OR MIT** (unchanged).
- `xenia-peer-core` (library): **Apache-2.0 OR MIT**.
- `xenia-peer` (binary, daemon): **AGPL-3.0-or-later**.
- `xenia-viewer` (binary, client): **AGPL-3.0-or-later**.

**Rationale.**

- The **protocol** exists to be adopted. Apache/MIT on `xenia-wire`
  lets any tool (OSS or commercial) build a compatible
  implementation. This was decided in Week 1 of Track A; unchanged.
- The **application**-layer binaries are the value-add. An MSP
  vendor should not be able to take the pre-built `xenia-peer` +
  `xenia-viewer` stack, rebrand it, and sell a proprietary remote-
  access product without contributing back. AGPL-3.0 forces the
  "modification-and-network-use triggers distribution" clause that
  covers that exact scenario.
- **`xenia-peer-core` is the library** both binaries share. Keeping
  it Apache/MIT lets third-party projects (e.g. a future browser-
  based viewer, a VS Code extension host, a TUI client) use the
  transport + session plumbing without inheriting AGPL obligations.
  This mirrors the Matrix / Element split (protocol+SDK permissive,
  flagship client AGPL).
- **Dual-licensing option for commercial users** — the AGPL-3.0 is
  the default. A commercial license can be negotiated on a
  case-by-case basis; the repository author is the sole copyright
  holder and can grant exceptions. This is deliberate: we want the
  default to be reciprocity, with an escape valve for organizations
  whose internal policies forbid AGPL code.

## Non-goals

- **No iOS/macOS/Windows support in M0-M3.** Cross-platform is M3+,
  and scoped per that milestone's own ADR when we get there.
- **No browser-based viewer in this workspace.** The existing
  `xenia-viewer-web` (Rust → WASM) lives in `xenia-wire/` as a
  demo artifact; a production browser viewer is a future separate
  crate.
- **No HDC / consciousness-coupled codec.** That research lives in
  Symthaea. `xenia-peer` is a straightforward remote-session tool.

## Consequences

**Accepted:**

- One repo to maintain for both application binaries.
- A hard dependency on Wayland means Linux-X11-only users can't run
  this; they get a clear, upfront "not supported" rather than a
  degraded experience. Honest is better than polite here.
- AGPL will exclude some potential commercial adopters. That's the
  point.

**Deferred:**

- The M1 capture/inject/codec crates (`xenia-capture`,
  `xenia-inject`, `xenia-video`) are NOT scaffolded in M0. They land
  as separate crates when M1 starts real screen-capture work. Empty
  trait scaffolds today would be pre-engineering.
- Iroh QUIC transport (the VIEWER_PLAN primary transport) is
  deferred to M3. M0 ships with the simpler TCP transport from
  `xenia-peer-core`; that's sufficient to prove the wire + state
  machine end-to-end. Switching to QUIC doesn't change the wire
  format (SPEC §1.3).
- A future ADR will cover handshake (ML-KEM-768) and the
  consent-ceremony UX.

## References

- `VIEWER_PLAN.md` §1 (crate layout), §5.1 (Wayland risk), §5.6
  (license question).
- `xenia-wire` SPEC draft-03 §12 (consent ceremony) — the daemon's
  consent UI will drive this state machine.
- Matrix/Element licensing split:
  <https://matrix.org/blog/2021/12/22/licensing-update/>.
- GNU AGPL-3.0 FAQ:
  <https://www.gnu.org/licenses/agpl-3.0.html>.
