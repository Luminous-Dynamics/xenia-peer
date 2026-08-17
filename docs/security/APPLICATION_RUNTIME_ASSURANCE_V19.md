# Application runtime assurance profile V19

V19 strengthens **local runtime evidence and diagnostic fidelity** around the V18 file-command reservation path. It does not change Xenia carrier, wire, capability, or input-event protocol semantics.

## Deterministic reservation clock

Reservation deadlines now use `tokio::time::Instant`, the same clock that drives the async expiry worker. The reaper sleeps with `tokio::time::sleep_until()` against the current absolute deadline and re-reads the reservation after every wake. This preserves V18's near-expiry claim rule while making the behavior testable with Tokio's paused clock.

The `xenia-mobile-ffi` test configuration enables Tokio `test-util`, and the authored runtime tests cover:

- claim just before the 30-second admission deadline;
- survival past the original deadline after entering the 60-second copy lease;
- capacity restoration when that copy lease expires;
- repeated claims not extending the copy lease.

These tests remain merge-time runtime evidence until they execute under the repository's Rust environment.

## Exact Android admission results

The native Rust/C result codes remain the stable `0..7` mapping introduced by V15/V17. V19 adds a JNI `trySendFile` path that returns the exact code to Kotlin instead of reducing every local rejection to `false`.

`XeniaSession.trySendFile()` maps the native code to `FileSendResult`, allowing UI policy to distinguish queue pressure, session closure, the fixed 100 MiB ceiling, and reservation expiry/size mismatch. The historical Boolean `sendFile()` remains as a compatibility convenience.

A local `FileTransferAdmissionSnapshotV1` also exposes point-in-time Reserved/Copying counts and bounded command-slot availability through Rust → C → JNI/Kotlin. This is diagnostic evidence only; it is not authenticated protocol state.

## Compatibility and evidence

`XENIA_APPLICATION_RUNTIME_ASSURANCE_V19_VECTOR.json` pins the clock model, exact status-code mapping, snapshot fields, and the fact that these diagnostics remain local. `scripts/check_application_runtime_assurance_v19.py` checks the source mapping across Rust/C/Kotlin, while `scripts/model_check_application_runtime_assurance_v19.py` independently models the expiry and bounded-capacity invariants.
