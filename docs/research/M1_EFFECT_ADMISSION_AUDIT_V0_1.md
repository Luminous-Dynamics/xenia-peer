# M1 Permission Admission vs Actual Input Effect Outcome

**Status:** Incremental live-path integration v0.2; synchronous input and host clipboard API owners are integrated. File, frame/video, audio, telemetry and network-delivery outcomes remain separate work.
**Tracking:** [Xenia #541](https://github.com/Luminous-Dynamics/xenia-peer/issues/541).
**Related:** #504 local effect/revoke ordering, #508 exact authority, #510 stage evidence, #512 route inventory, #532 gate reference model.

## 1. Finding

The M1 state machine previously appended audit labels such as `InputInjected`, `HostClipboardWritten` and `FileSentToViewer` from methods that only checked `require_active(permission)`. In the live daemon these methods commonly ran before the OS API or transport call.

Examples:
- Reverse input: M1 permission gate ran, then the daemon called `SessionInputInjector::process_events`. The old audit label existed before the platform injector returned.
- Reverse clipboard: permission gate ran, then `apply_clipboard_content` attempted to apply the clipboard update; that function can fail.
- File send: a permission gate ran before the source chunk was read, sealed and passed to the transport.
- File receive: a permission gate ran before chunk append or verified staging publication.

Those old event names overstated what the producer had established. The human consent ledger already skipped these operation events; this correction changes the M1 in-memory audit transcript semantics without turning every input/clipboard/file event into a consent decision.

## 2. New event vocabulary

The historical variants remain in `M1AuditEvent` for compatibility with existing source/transcript readers, but new state-machine permission methods no longer emit them.

New permission admission events:
- `FramePermissionAdmitted`
- `TelemetryPermissionAdmitted`
- `AudioPermissionAdmitted`
- `InputPermissionAdmitted`
- `HostClipboardReadPermissionAdmitted`
- `HostClipboardWritePermissionAdmitted`
- `FileSendPermissionAdmitted`
- `FileReceivePermissionAdmitted`

New input owner outcomes:
- `InputPlatformAccepted`: the selected platform injector returned `Ok(())` for the submitted event. This does not prove the target application acted or a pixel changed.
- `InputOutcomeUnknown`: the platform injector returned a backend error. A batch may have partially applied before the error.
- `InputNotAttempted`: the backend was unavailable (or the daemon's no-op fallback was installed); no platform call was made.

The input admission and outcome methods are separate. The outcome method also rechecks that the M1 session is still active and the input permission remains granted.

New clipboard owner outcomes:
- `HostClipboardReadCompleted`: the host clipboard read API completed; it does not mean content was sent to the peer.
- `HostClipboardReadOutcomeUnknown`: the API returned an error after invocation.
- `HostClipboardReadNotAttempted`: the API was not invoked, for example when clipboard setup failed.
- `HostClipboardWriteApplied`: the host OS clipboard write API returned success.
- `HostClipboardWriteOutcomeUnknown`: the write API returned an error; external application is not assumed absent.
- `HostClipboardWriteNotAttempted`: no write API call was made, for example because payload size validation or clipboard setup rejected first.

No clipboard bytes or text are stored in the M1 operation event. Only stage and outcome labels are retained.


## 3. Actual input effect-owner integration

The daemon's reverse input path now calls `M1RuntimeSession::with_input_effect`. The caller must hold the shared `Arc<tokio::sync::Mutex<M1RuntimeSession>>` while this method runs.

The sequence is:
1. Recheck M1 active state and exact `InjectInput` permission.
2. Append/flush `InputPermissionAdmitted`.
3. Invoke the synchronous `SessionInputInjector::process_events` callback.
4. Classify the returned result as platform accepted, outcome unknown, or not attempted.
5. Append/flush that outcome before releasing the shared M1 runtime mutex.

The daemon's revoke task uses the same mutex. Therefore, locally, revoke cannot linearize between input admission and the synchronous injector call/result record:
- if input acquired the M1 runtime lock first, the bounded synchronous call and its outcome append complete before revoke obtains the lock;
- if revoke acquired the lock first, input admission fails and the effect closure is never invoked.

This is a **local input-owner linearization**. It is not global distributed revocation and does not prove the target application accepted the event.

### Unavailable/no-op backend

`build_input_injector` intentionally falls back to `NoopInjector` when a real backend cannot be constructed. A successful no-op return must not be called platform acceptance. The live path detects `backend_name() == "noop"` and returns `InjectError::Unavailable` through the owner wrapper, producing `InputNotAttempted`.

## 4. Actual host clipboard effect-owner integration

Both synchronous host clipboard APIs now run inside their respective `M1RuntimeSession::with_host_clipboard_*_effect` wrapper while the caller holds the shared M1 runtime mutex.

### Host-to-viewer read path
1. The polling loop first obtains the M1 runtime lock.
2. The runtime checks `ReadHostClipboard` permission and records `HostClipboardReadPermissionAdmitted`.
3. Only then does `read_host_clipboard_text` instantiate the clipboard adapter and call `get_text`.
4. The result is recorded as `Completed(Some(text))`, `Completed(None)`, `NotAttempted`, or `OutcomeUnknown`.
5. The lock is released. If content changed, the daemon seals it into a clipboard frame and separately checks frame-send permission before sending.

The M1 read receipt establishes only that the local read API completed. It does **not** establish network dispatch, peer receipt, or peer application. Clipboard content never appears in the audit event; only the operation stage is recorded.

### Viewer-to-host write path
1. The inbound payload is authenticated/decrypted and checked against bidirectional clipboard mode.
2. The daemon obtains the M1 runtime lock and checks `WriteHostClipboard`.
3. Only then does the callback call `arboard::Clipboard::new` and `set_text`.
4. The outcome is recorded as `Applied`, `NotAttempted`, or `OutcomeUnknown` before unlocking.

Oversize payload rejection and clipboard adapter construction failure are `NotAttempted`, because no `set_text` call happened. An error from `set_text` itself is `OutcomeUnknown`; the daemon does not assume the OS or compositor made no change.

The helper logs only the clipboard kind and byte count, never the clipboard content. `Cleared` is applied by setting empty text to replace a previously served selection on Wayland.

Revocation uses the same M1 mutex. Therefore, local revoke cannot linearize between permission admission, the synchronous API call and the corresponding outcome append. This is process-local serialization, not distributed revocation.

## 5. Consent ledger boundary

`m1_ledger::disposition_for_m1_event` continues to skip operation events as `NotConsentBoundary`, including all new permission-admission, input-outcome and clipboard-outcome events. The ledger remains reserved for consent request, grant, denial, revoke and violation boundaries.

The signed/append-only consent ledger must not be inflated into a per-keystroke or per-frame event log. A future durable operation-evidence export can bind operation-stage receipts to the session transcript without rewriting consent semantics (#510/#450).

## 6. Tests authored

The current changes add/adjust tests for:
1. All eight M1 permission methods append admission labels, not legacy success-shaped labels.
2. Input outcomes appear after input admission and remain three distinct states.
3. A definitive unavailable/no-op backend is recorded as not attempted.
4. Backend error is recorded as unknown, not success.
5. Outcome recording is rejected if input permission is no longer active.
6. Input callback is never invoked without permission.
7. All new operation/admission/outcome events remain excluded from the human consent journal.
8. A multithreaded daemon test attempts revoke while an input callback is in progress; revoke must acquire the shared runtime lock only after the callback and outcome append finish.
9. Host clipboard read/write runtime wrappers record the local API outcome and suppress callbacks when the corresponding permission is absent.
10. All clipboard outcome events remain excluded from the human consent journal.

These tests are authored, not executed in this environment.

## 7. Remaining live effect owners

This PR intentionally does not claim to solve the other routes yet:

| Route | Admission event now truthful | Effect outcome still needed |
|---|---|---|
| Input injection | Yes | Local injector return is recorded; target-app consumption remains unknown |
| Host clipboard read | Yes | Local read API result is recorded; peer disclosure/receipt remains separate |
| Host clipboard write | Yes | Local `set_text` API result is recorded; reader application consumption remains unknown |
| File send | Permission admission only | Per-chunk operation identity and send/peer receipt; timeout becomes UNKNOWN |
| File receive | Permission admission only | Distinguish offer accepted, chunk staged, digest verified, final publication success |
| Frame/video | Permission admission only | Local send, peer receipt, decode and presentation remain separate |
| Telemetry/audio | Permission admission only | Local send and stronger observation remain separate |

Do not hold the M1 runtime mutex across an entire async network send or file transfer. Keep the critical section short at the actual synchronous local effect-owner boundary, and reconcile ambiguous network outcomes by stable operation ID.

## 8. Claim boundary

**Implemented in this increment:** truthful permission-admission labels for all eight lanes; post-call synchronous input and clipboard API result labels; explicit not-attempted vs unknown states; shared-lock input/clipboard vs local revoke ordering; no clipboard content in operation events; preserved consent-ledger boundary.

**Not claimed:** peer-side clipboard receipt/application, file/frame/audio/telemetry effect receipts, global/distributed revocation, target-application input acceptance, physical input-to-photon, durable signed operation evidence, compilation, test execution, Clippy, rustfmt or hosted CI pass.

The reference operation ledger (#531) and gate (#532) remain complementary but are not yet the durable evidence backend for this M1 path.