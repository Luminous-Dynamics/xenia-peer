# Application runtime evidence profile V18

V18 strengthens the local evidence and admission layer around Xenia's already-authenticated application session. It does not change the carrier or input wire schema.

## File-transfer reservation state machine

V17 reserved a real Tokio MPSC slot before JNI copied a potentially large Java byte array. V18 separates **admission time** from **copy/commit time**:

1. `Reserved`: the queue slot is held for at most 30 seconds while the caller prepares to copy.
2. `Copying`: the caller claims the token immediately before materialization/copy; the first claim establishes a 60-second copy lease.
3. repeated claims are idempotent and do not extend the copy lease;
4. commit requires the token to still be live and in `Copying` state;
5. cancel, expiry, disconnect, or engine drop releases the owned permit.

The expiry task does not blindly remove the token after the original 30-second sleep. It re-reads the reservation's current deadline, so a legitimate claim near the end of the admission window cannot race the old timer and lose its queue slot during the copy.

This remains **local queue admission**, not remote transfer acceptance.

## Pressure evidence

`LanePressureSnapshotV1` now has aggregate helpers. Desktop audio displays superseded/rejected ingress counts in the native viewer diagnostics, and the host emits a structured video-pressure summary on normal session teardown when pressure occurred.

These counters are local diagnostic evidence only. They are intentionally not authenticated session state.

## FFI layout hygiene

The Android file-transfer event header has one canonical 32-byte layout. V18 removes a duplicate `name_len` store at offset 28 and pins the offsets in the V18 source contract/vector.

## CI contract closure

`scripts/run_transport_session_contracts.sh` runs the accumulated V10-V18 source contracts and reduced models. CI's existing flake job already compiles/tests Rust; V18 adds the contract runner as an explicit CI step so source/model evidence cannot silently disappear while runtime tests remain green.

This runner still cannot execute Rust 1.94, so V18 does not claim local Rust runtime evidence. The repository CI and merge environment remain responsible for the authored Rust tests.
