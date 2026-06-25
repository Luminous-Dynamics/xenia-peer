# Xenia Nix Development Shell

The Xenia dev shell is the source of truth for native system dependencies used
by capture, video, viewer, and transport work. Keep it boring and repeatable.

## Shells

| Shell | Purpose |
|---|---|
| `nix develop` or `nix develop .#default` | Full local development shell with Rust, H.264, Wayland/PipeWire, audit tools, and web/WASM tooling. |
| `nix develop .#ci` | Smaller CI shell with Rust, H.264, Wayland/PipeWire, and audit tools, but no rust-analyzer or web build tools. |
| `nix develop .#web` | Explicit browser/admin shell with Trunk and wasm-bindgen tools. |

## Standard checks

From the product workspace root:

```bash
scripts/xenia-validate.sh .
scripts/nix-xenia-check.sh .
```

The Nix-backed check runs `nix flake check --show-trace` and then executes the
normal validator inside the `.#ci` shell.

## Dependency rules

1. Add native libraries to `flake.nix` before relying on them in Rust build
   scripts, examples, or CI.
2. Keep Linux capture/viewer dependencies explicit: Wayland, DBus, PipeWire,
   libxkbcommon, and libGL.
3. Keep H.264 pinned to `ffmpeg_7` until the `xenia-video` backend is validated
   against a newer libav API.
4. Do not add absolute `<workspace-root>/...` paths to Nix, Cargo, or shell
   scripts. Use workspace-relative paths or feature-gated adapters.
5. If a tool is only useful interactively, keep it out of `.#ci`.

## Preflight reports

For a quick handoff artifact before asking another agent to touch Xenia, run:

```bash
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-report.md
```

Attach the report instead of raw terminal scrollback. It captures layout, hygiene,
Cargo-boundary status, and optional Cargo/Nix metadata without mutating the tree.
