# Xenia Application Session Teardown V15

Status: **source/model hardening candidate; Rust runtime merge gates remain required**.

V15 hardens the application-facing failure boundary that follows V14's semantic
producer policy. It does not change the authenticated input schema version (still
`2`) and does not add a carrier or move Xenia below L4.

## Invariants

### 1. Pointer motion is not a button release

`InputInjector` now separates:

- `inject_pointer_move(x, y)`
- `inject_pointer_button(x, y, button, pressed)`

The legacy combined `inject_pointer(...)` method remains only for source/ABI
compatibility. Current `InputEvent::PointerMove` dispatch never calls the
combined method.

Every current backend implements the split explicitly. In particular, uinput
pure motion writes only absolute-axis events and does not emit `EV_KEY`; the
portal path has separate move/button worker commands; Windows sends an absolute
move without a button flag; and macOS selects a drag/move CoreGraphics event
without synthesizing a release.

### 2. Session-owned injected state is unwound on teardown

`SessionInputInjector` wraps the concrete host backend and tracks only successful
state-establishing operations:

- pressed keyboard codes;
- pressed pointer buttons and their latest successful pointer positions;
- active touch slots and their last position/pressure.

Successful pure pointer motion updates the remembered position of every held
button, so teardown releases a drag where it actually ended rather than moving
the host pointer back to the original press coordinate.

When the input/control receive loop ends, the daemon explicitly calls
`release_all()`. It sends touch Cancel, pointer-button release, and key release
operations in deterministic key order and reports attempted/released/failed
counts. Successful releases leave the tracker immediately; failed releases
remain tracked for a later retry. `Drop` makes one final best-effort attempt so
task abort is safer than silently abandoning held state.

This is local host cleanup, not a wire-level acknowledgement. If the operating
system/backend itself is unavailable during teardown, V15 can report/retry but
cannot guarantee the physical host accepted every release.

### 3. Touch Cancel is fail-closed on uinput

The documented input phases are `0=Down`, `1=Move`, `2=Up`, `3=Cancel`. uinput
previously treated phase `3` as still pressed. V15 changes the low-level rule to
`pressed iff phase is 0 or 1`; Up, Cancel, and unknown phase values release
`BTN_TOUCH`.

### 4. Mobile clipboard is latest-value state

Viewer-to-host clipboard updates no longer use a 16-entry FIFO with lossy
`try_send`. They use a Tokio `watch` slot carrying at most one pending value.
When the producer outpaces the network, stale intermediate clipboard states are
coalesced and only the latest state remains pending.

The reviewable producer policy is:

- semantic class: `mobile-clipboard-outbound`
- capacity: `1`
- overflow: `CoalesceLatest`

### 5. User file-transfer enqueue failure is explicit

The mobile file-command queue remains finite at two entries, but saturation is
no longer silently ignored. `ViewerEngine::send_file` returns either success or
`FileTransferEnqueueError::{QueueFull, SessionClosed}`.

The C ABI adds `xenia_try_send_file` with explicit status codes. The historical
fire-and-forget `xenia_send_file` remains as a compatibility wrapper. Android
JNI/Kotlin uses the result-aware path and surfaces a local enqueue failure to the
user rather than pretending a transfer started.

This immediate result means only "accepted by the local bounded command queue."
Remote Offer/Accept/Done semantics remain asynchronous file-transfer events.

## Independent reduced evidence

`scripts/model_check_application_teardown_v15.py` checks:

- all 64 reduced held-state combinations unwind to empty;
- all 729 length-6 motion/button traces preserve button state across pure motion;
- all 256 touch phase byte values follow fail-closed Down/Move-vs-release logic;
- 1,024 clipboard updates collapse to exactly the newest value;
- the two-entry file-command queue accepts the first two actions and explicitly
  rejects later actions instead of dropping an existing command.

`scripts/check_application_teardown_v15.py` pins the source-level wiring for the
split injector API, daemon teardown, clipboard watch slot, explicit file enqueue
result, JNI/Kotlin result propagation, and backend split.

## Runtime merge gates

Source/model evidence is not a substitute for execution. Under the repository's
Rust 1.94 environment run at minimum:

```bash
cargo check --workspace --all-targets --locked
cargo test -p xenia-inject --all-features --locked
cargo test -p xenia-mobile-ffi --all-targets --locked
cargo test -p xenia-peer --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Platform validation should additionally verify Windows drag, macOS drag,
xdg-portal drag, and uinput drag/cancel behavior against real host input state.
Kill/reset the session after key/button/touch Down and verify teardown releases
or cancels the host state.

## Non-goals / remaining work

- V15 does not yet give host capture -> encode -> transport queues a first-class
  semantic pressure profile.
- Audio is still described primarily by a queue capacity rather than an explicit
  latency budget.
- The mobile stateful input API can synchronously block its UI caller during
  severe pressure; a future explicit async/fail-session API may be preferable.
- A backend can fail during teardown. The tracker preserves failed state for a
  retry, but there is no privileged OS-wide "release everything" primitive.
- Peer-visible semantic lane policy changes should receive an authenticated
  profile revision rather than silently changing in place.
