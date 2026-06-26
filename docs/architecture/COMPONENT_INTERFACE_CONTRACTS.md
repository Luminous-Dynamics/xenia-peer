# Xenia Component Interface Contracts

This document captures the expected dependency direction between major Xenia
components. It is a design contract for future refactors and agent work.

## Direction of dependency

```text
apps -> libraries -> xenia-wire
```

`xenia-wire` must not know about apps, capture backends, viewers, admin panels,
or product policy. Product behavior belongs above it.

## Component contracts

| Component | Owns | Must not own |
| --- | --- | --- |
| `xenia-wire` | protocol frames, encodings, test vectors | peer auth policy, UI, capture backends |
| `xenia-peer-core` | shared runtime types | app-specific behavior |
| `xenia-handshake` | identity/session bootstrap | screen capture, UI |
| `xenia-ledger` | audit/provenance records | authority decisions not backed by policy |
| `xenia-capture` | capture abstractions/backends | transport authority |
| `xenia-video` | encode/decode pipeline | session consent |
| `xenia-transport-*` | transport framing/reconnect behavior | operator UI |
| `xenia-inject` | input injection abstraction | consent policy storage |
| apps | policy composition and UX | reusable protocol truth |
