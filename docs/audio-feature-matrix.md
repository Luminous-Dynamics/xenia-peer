# Xenia Audio Feature Matrix

Xenia keeps audio capture, audio playback, audio codec, and audio transport as separate concerns. Do not let a device API define the wire protocol.

## Cargo Features

| Feature | Scope | Native deps | Purpose |
| --- | --- | --- | --- |
| `xenia-peer/audio-capture` | daemon | ALSA on Linux via CPAL | Capture real host input audio into RawAudio frames. |
| `xenia-viewer/audio-output` | viewer | ALSA on Linux via CPAL | Play decoded RawAudio frames through a local output device. |
| `xenia-peer/audio-opus` | daemon | libopus | Encode RawAudio PCM frames as Opus payloads. |
| `xenia-viewer/audio-opus` | viewer | libopus | Decode Opus payloads back to RawAudio PCM. |
| `xenia-peer-core/opus` | protocol/core | libopus | Unit-testable Opus codec implementation. |

## Runtime Modes

| Binary | Flag | Values | Default |
| --- | --- | --- | --- |
| `xenia-peer` | `--audio` | `off`, `sine`, `noise`, `capture` | `off` |
| `xenia-peer` | `--audio-codec` | `auto`, `raw-pcm`, `opus` when built | `raw-pcm` |
| `xenia-viewer` | `--play-audio` | `off`, `synthetic`, `device` | `off` |
| `xenia-viewer` | `--audio-codec` | `auto`, `raw-pcm`, `opus` when built | `auto` |

## Validation

Use the flake apps as the canonical local gates:

```bash
nix run .#fast
nix run .#audio
nix run .#ci
```

The audio gate verifies ALSA and Opus pkg-config discovery, daemon capture builds, viewer output builds, core Opus tests, and daemon/viewer Opus feature builds.
It also runs the synthetic audio end-to-end smoke over TCP, WebSocket, and QUIC for raw PCM and Opus, plus a negative consent smoke that verifies audio does not flow without the local M1 consent grant.

## Design Rules

RawAudio remains the timing and transport contract. CPAL is only a device adapter. Opus is only a codec adapter. The viewer GUI owns CPAL playback on the UI thread and receives decoded PCM through a bounded channel from the network task. Runtime smokes must use `--operator-key-path` with a temporary path so operator keys are not written into the repository root.
