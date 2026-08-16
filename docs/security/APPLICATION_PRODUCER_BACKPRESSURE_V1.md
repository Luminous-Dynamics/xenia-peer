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

V13 originally left mobile on the ambiguous legacy pointer shape. V14 closes
that gap by appending explicit `PointerMove` and `PointerButton` input variants
without changing the historical bincode indices of legacy Pointer/Key/Touch.
Current Android UI/JNI/native paths use the explicit forms; the legacy pointer
entry point remains only as a compatibility shim.
