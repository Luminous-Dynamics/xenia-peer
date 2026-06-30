# Xenia Audio Device Runbook

This runbook covers manual host audio checks. Automated CI should use synthetic audio and the flake audio gate; real devices vary by host, desktop session, permissions, and available ALSA/PipeWire routes.

## Build Checks

```bash
nix run .#audio
```

This verifies ALSA and Opus discovery, CPAL capture/playback builds, Opus builds, and the synthetic audio end-to-end smoke.

## Synthetic Playback

Terminal 1:

```bash
nix develop -c cargo run -p xenia-peer --features preprod-fixtures -- \
  --transport tcp \
  --listen 127.0.0.1:4747 \
  --frames 120 \
  --audio sine \
  --audio-interval-ms 20 \
  --telemetry-level off \
  --operator-key-path /tmp/xenia-audio-synthetic-operator.key \
  --m1-preprod-auto-consent
```

Terminal 2:

```bash
nix develop -c cargo run -p xenia-viewer -- \
  --transport tcp \
  --connect 127.0.0.1:4747 \
  --frames 90 \
  --play-audio synthetic
```

Expected viewer output includes `audio summary:` with nonzero `decoded`, `inserted`, `emitted`, `played`, and `samples`.

## Device Playback

Use synthetic daemon audio first. This proves the viewer output path without capturing a microphone.

```bash
nix develop -c cargo run -p xenia-viewer --features audio-output -- \
  --transport tcp \
  --connect 127.0.0.1:4747 \
  --frames 90 \
  --play-audio device
```

Use `--audio-output-device <name-substring>` if the default output device is not the intended sink.

## Device Capture

Real capture is explicit and consent-gated. Start with local synthetic playback or headphones to avoid feedback.

Terminal 1:

```bash
nix develop -c cargo run -p xenia-peer --features "audio-capture preprod-fixtures" -- \
  --transport tcp \
  --listen 127.0.0.1:4747 \
  --frames 120 \
  --audio capture \
  --audio-interval-ms 20 \
  --telemetry-level off \
  --operator-key-path /tmp/xenia-audio-capture-operator.key \
  --m1-preprod-auto-consent
```

Terminal 2:

```bash
nix develop -c cargo run -p xenia-viewer --features audio-output -- \
  --transport tcp \
  --connect 127.0.0.1:4747 \
  --frames 90 \
  --play-audio device
```

Expected daemon logs include `audio input stream started` and `M1 consent scope offered` with `audio: host device capture`. Expected viewer output includes an `audio summary:` line with nonzero decoded and played counters.

## Opus Smoke

Build both sides with Opus and request Opus explicitly.

```bash
nix develop -c cargo run -p xenia-peer --features "audio-opus preprod-fixtures" -- \
  --transport tcp \
  --listen 127.0.0.1:4747 \
  --frames 120 \
  --audio sine \
  --audio-codec opus \
  --telemetry-level off \
  --operator-key-path /tmp/xenia-audio-opus-operator.key \
  --m1-preprod-auto-consent
```

```bash
nix develop -c cargo run -p xenia-viewer --features audio-opus -- \
  --transport tcp \
  --connect 127.0.0.1:4747 \
  --frames 90 \
  --play-audio synthetic \
  --audio-codec opus
```

## Policy Checks

Audio policy is independent from telemetry:

| Policy | Expected behavior |
| --- | --- |
| `--audio off` | No RawAudio frames are emitted. |
| `--audio sine` / `noise` | Synthetic RawAudio frames are emitted after consent. |
| `--audio capture` | Device capture requires an `audio-capture` build and explicit M1 consent. |
| `--telemetry-level off` | Telemetry is disabled; audio behavior is unchanged. |

Do not use `--m1-preprod-auto-consent` outside local smoke testing. It exists only until the real consent approval source drives the runtime gate, and the daemon refuses it unless the binary was built with `xenia-peer/preprod-fixtures`.
