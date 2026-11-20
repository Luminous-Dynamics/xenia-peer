# M1 Permission Admission vs Actual Input Effect Outcome

**Status:** Incremental live-path integration v0.1; the input effect owner is integrated, other operation lanes are relabelled as admission only.
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

## 4. Consent ledger boundary

`m1_ledger::disposition_for_m1_event` continues to skip operation events as `NotConsentBoundary`, including all new permission-admission and input-outcome events. The ledger remains reserved for consent request, grant, denial, revoke and violation boundaries.

The signed/append-only consent ledger must not be inflated into a per-keystroke or per-frame event log. A future durable operation-evidence export can bind operation-stage receipts to the session transcript without rewriting consent semantics (#510/#450).

## 5. Tests authored

The current changes add/adjust tests for:
1. All eight M1 permission methods append admission labels, not legacy success-shaped labels.
2. Input outcomes appear after input admission and remain three distinct states.
3. A definitive unavailable/no-op backend is recorded as not attempted.
4. Backend error is recorded as unknown, not success.
5. Outcome recording is rejected if input permission is no longer active.
6. Input callback is never invoked without permission.
7. All new operation/admission/outcome events remain excluded from the human consent journal.
8. A multithreaded daemon test attempts revoke while an input callback is in progress; revoke must acquire the shared runtime lock only after the callback and outcome append finish.

These tests are authored, not executed in this environment.

## 6. Remaining live effect owners

This PR intentionally does not claim to solve the other routes yet:

| Route | Admission event now truthful | Effect outcome still needed |
|---|---|---|
| Input injection | Yes | Local injector return is recorded |
| Host clipboard read/disclosure | Permission admission only | Need bind actual read digest and outbound transport acceptance; no clipboard bytes in evidence |
| Host clipboard write | Permission admission only | Need `arboard::set_text` success/error result and UNKNOWN semantics |
| File send | Permission admission only | Per-chunk operation identity and send/peer receipt; timeout becomes UNKNOWN |
| File receive | Permission admission only | Distinguish offer accepted, chunk staged, digest verified, final publication success |
| Frame/video | Permission admission only | Local send, peer receipt, decode and presentation remain separate |
| Telemetry/audio | Permission admission only | Local send and stronger observation remain separate |

Do not hold the M1 runtime mutex across an entire async network send or file transfer. Keep the critical section short at the actual synchronous local effect-owner boundary, and reconcile ambiguous network outcomes by stable operation ID.

## 7. Claim boundary

**Implemented in this increment:** truthful permission-admission labels for all eight lanes; post-call synchronous input result labels; no-op/unavailable distinction; shared-lock input/revocation ordering; preserved consent-ledger boundary.

**Not claimed:** completed clipboard/file/frame/audio/telemetry effect receipts, global/distributed revocation, target-application input acceptance, physical input-to-photon, durable signed operation evidence, compilation, test execution, Clippy, rustfmt or hosted CI pass.

The reference operation ledger (#531) and gate (#532) remain complementary but are not yet the durable evidence backend for this M1 path.