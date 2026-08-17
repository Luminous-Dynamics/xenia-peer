# Application Lane Latency Profile V1

V16 distinguishes **bounded memory** from **bounded useful latency**. A queue can be finite and still retain enough stale media to make a remote session unusable. This profile names the current native audio/video buffering and file-admission contracts so future changes are reviewed as semantic policy rather than unexplained container sizes.

These are **local implementation policies**, not peer-visible wire semantics. They are therefore not added to the authenticated session transcript. Any future change that affects what a peer is allowed to send or how it must interpret a lane still requires a versioned authenticated capability/profile.

## Native audio

The protocol permits audio frames up to 20 ms. V16 bounds the native pipeline by time-derived stages:

| Stage | Bound | Approx. max at 20 ms frames |
|---|---:|---:|
| host CPAL capture FIFO | 100 ms | 100 ms |
| viewer sequence jitter depth | 6 frames | 120 ms |
| network/decode → GUI playback queue | 4 frames | 80 ms |
| device PCM FIFO | 80 ms | 80 ms |

The viewer-side application buffering contract is therefore at most **280 ms** before OS/hardware buffering. The host capture FIFO is a separate 100 ms bound. Network latency, codec execution time, and platform audio-driver buffering are not included and are not claimed by this profile.

The historical desktop GUI queue retained 64 frames. At the wire maximum frame duration that alone represented about 1.28 seconds of stale audio. V16 retains the historical V1 descriptor for audit history but the implementation now uses `DESKTOP_AUDIO_PLAYBACK_V2` with four frames.

Device PCM capacity is calculated from the actual output sample rate and channel count, not from a fixed `48_000 * 2` sample constant. The host CPAL capture FIFO similarly derives its sample count from sample rate, active channel count, and the 100 ms budget.

## Host video

The current daemon video path is intentionally synchronous:

`capture → encode → seal → send`

There is no intermediate frame queue, so transport backpressure cannot accumulate an unbounded capture backlog. V16 makes the latency consequence explicit:

- at most one captured frame is active in the pipeline;
- if capture + encode takes more than 500 ms before send begins, the encoded result is superseded and dropped;
- a video-envelope send may block at most 1,000 ms;
- a video send timeout is **session-fatal**, because canceling a stream send can leave framing partially consumed and the same session must not resume.

This lane-specific send deadline is stricter than the general V12 transport send-stall ceiling. It is a responsiveness policy for screen frames, not a replacement for transport availability policy.

## Mobile file admission

The native mobile viewer admits at most 100 MiB per outbound file command. The command queue remains capacity two with explicit rejection.

V16 adds `xenia_check_send_file(handle, data_len)`: JNI invokes it **before** `GetByteArrayElements`, so an obviously oversized, closed-session, or currently-full command is rejected before JNI asks the VM for native byte-array access/copying. `xenia_try_send_file` performs the same check again before copying and enqueuing.

The pre-check is deliberately **not a reservation**. Queue capacity can change between preflight and final `try_send`; callers must still handle the final result.

## Security rule

**Finite memory is necessary but not sufficient. Latency-sensitive lanes need time-derived budgets, supersedable media should be dropped when stale, correctness-sensitive state must not be silently lost, and cancellation of a partial framed send remains session-fatal.**
