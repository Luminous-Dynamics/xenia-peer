# Application Flow Control Profile V1

V14 makes application-producer pressure a named security/availability boundary rather than an implementation accident. The policy is deliberately semantic: a video frame, a pointer-motion sample, and a key release do not have the same correctness requirements when a bounded queue is full.

## Input schema migration

`xenia_inject::InputEvent` keeps its original first three bincode variants in place:

0. legacy `Pointer`
1. `Key`
2. `Touch`

V14 appends:

3. `PointerMove`
4. `PointerButton`

The sealed session capabilities now also carry `input_event_schema_version = 2`. `PendingSessionSurface` rejects any other version before exposing an authenticated application surface, and because `RawCapabilities` is part of the negotiated context hash the schema version is transcript-bound rather than a local convention.

Appending rather than replacing/reordering preserves the bincode discriminants of historical `Pointer`, `Key`, and `Touch` payloads. New desktop and Android producers emit only the explicit pointer forms. The ambiguous legacy mobile/C ABI remains for compatibility but is no longer used by the current Android UI.

The semantic consequence is important: `PointerButton { pressed: false }` is unambiguously a release, while `PointerMove` is unambiguously a supersedable sample. Queue overflow policy can therefore be chosen from meaning rather than guessing from `button=0, pressed=false`.

## V1 producer policies

| Semantic producer | Bound | Overflow behavior | Reason |
|---|---:|---|---|
| pointer motion | 256 | drop newest | later motion supersedes it |
| key/button/touch state transition | 256 | bounded backpressure | losing release/up/cancel can leave remote state stuck |
| desktop video presentation | 1 | coalesce latest | displaying stale backlog is worse than dropping it |
| mobile video presentation | 4 | drop oldest | small decode/display smoothing window, bounded memory |
| desktop telemetry presentation | 1 | coalesce latest | telemetry UI wants current state, not history backlog |
| desktop audio playback | 64 | drop newest | finite playback latency/memory; current implementation records rejection |
| mobile file-transfer UI events | 64 | drop oldest | progress/history UI queue is not the transfer state machine |

These descriptors live in `xenia_peer_core::producer_flow`; source contracts tie the corresponding concrete queue/slot sizes to the profile. They do not replace the underlying transport's V12 send-stall deadline.

## Mobile input policy

The current mobile API applies the same semantic distinction as desktop:

- `PointerMove` and touch phase `Move` use non-blocking lossy `try_send`;
- `PointerButton`, `Key`, and touch Down/Up/Cancel use bounded `blocking_send`;
- the older ambiguous `sendPointer`/`xenia_send_pointer` entry points remain compatibility shims and retain their historical lossy behavior.

The synchronous state-transition path can briefly block an Android/UI caller if the fixed 256-event queue is saturated. This is preferable to silently discarding a release, but it is still a UI-quality tradeoff. A future API may expose an explicit async/fail-session result instead of blocking the calling thread.

## What V1 does not claim

V1 does not yet define a universal producer policy for clipboard updates, outbound file-transfer commands, encoded host media production, or future multi-stream QUIC lanes. Those need explicit semantics rather than being forced into this table prematurely.

The security rule is: **all producer queues must be finite, and overflow behavior must follow the semantic consequence of losing or delaying that event.**
