# Application Producer Backpressure V1

V13 removes the desktop viewer's unbounded input producer queue.

The synchronous GUI-to-network queue is bounded at **256 events**. Overflow is
semantic rather than uniform:

- pointer **motion samples** are lossy and use non-blocking `try_send`; a full
  queue drops the newest motion sample because later motion supersedes it;
- keyboard and pointer-button **state transitions** use bounded
  `blocking_send`, so queue saturation does not silently discard a key-up or
  button-release and leave remote input logically stuck.

The network sender remains gated behind `AuthenticatedSessionSurface` and its
actual transport send is bounded by V12's 15-second send-stall deadline. A
closed/stalled network task therefore cannot drive unbounded queue memory.

This pass does not claim the same fine-grained policy for the mobile input API.
Mobile was already bounded, but its current pointer event shape uses
`button=0, pressed=false` for both motion and left-button release, so lossiness
cannot be classified safely from the serialized event alone. A future input
schema should separate pointer motion from button transitions before applying
this exact policy there.
