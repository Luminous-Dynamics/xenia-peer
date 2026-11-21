# Xenia runtime log minimization and privacy-preserving activity receipts

**Status:** coarse event-class logging implemented in the associated work branch; the activity receipt stream below is a proposed next increment, not yet implemented.

## 1. Logging boundary

Xenia must not turn ordinary operational logs into a record of a user's remote input or copied content. Debugging an injector does not require keeping the data that the injector acted on.

The runtime log may record:

- coarse input class: `pointer`, `keyboard`, or `touch`;
- selected injection backend;
- outcome: injected or failed;
- for viewer-originated clipboard apply, `text` versus `cleared`;
- error category/message where the underlying platform error is safe to report.

The runtime log must not record:

- keycodes/scancodes or modifier masks;
- pointer coordinates, button identity/state, or path;
- touch index, coordinates, phase, or pressure;
- clipboard text or other clipboard payload;
- file names, paths, file contents, or other per-file identifiers.

The current daemon input loop uses a typed `InputEvent` to drive `SessionInputInjector`. Its full debug representation is deliberately not suitable as a log field. A dedicated classifier maps variants to a small, fixed vocabulary; it does not serialize, format, or return event values. Clipboard apply logging follows the same rule and records only `text` or `cleared`.

## 2. Separate consent records from activity receipts

The consent ledger is for **authority lifecycle boundaries**:

`request → approval/denial → revocation / violation`

It should not receive one record per key, pointer movement, frame, or clipboard byte. Doing so would create a high-volume ledger, introduce avoidable disclosure, and confuse consent facts with activity telemetry. The existing M1 ledger adapter intentionally skips operation events rather than misrepresenting them as consent events.

A separate activity receipt format can prove coarse operational facts without retaining user payloads. That receipt stream must be independently versioned, signed, verifiable, and explicitly described as an activity summary—not a transcript or proof of the semantic content of an operation.

## 3. Proposed activity receipt schema

Proposed schema name: `xenia-activity-receipt/v1`.

A receipt represents one bounded host-side time/count window for one session. A candidate structure is:

| Field | Meaning |
|---|---|
| `schema_version` | Exact version label |
| `session_id`, `request_id` | Bind receipt to the consented session |
| `sequence` | Strictly increasing per-session receipt sequence |
| `window_start_elapsed_ns`, `window_end_elapsed_ns` | Host monotonic elapsed time relative to session start; no cross-host subtraction |
| `previous_receipt_digest` | Hash link to the previous receipt |
| `operation_counts` | Fixed set of counts for pointer, keyboard, touch, clipboard apply, file transfer, and other explicitly enabled operation classes |
| `outcome_counts` | Accepted, denied by permission, backend failure, cancelled/unknown |
| `backend_class` | Bounded backend identifier, not a device-specific secret |
| `receipt_digest` | Hash over the canonical receipt payload, including the prior digest |
| `host_signature` | Signature over the receipt digest with the daemon's host signing identity |

No receipt field may carry raw keys, modifiers, coordinates, touch pressure, clipboard values, file paths, file names, or file bytes. Exact transfer byte counts should be omitted or bucketed only after a privacy review because exact sizes can become a side channel.

The receipt verifies that a host identity attested to a coarse summary for a session window. It does **not** prove what was typed, what a human saw, or whether a remote application interpreted input in a particular way.

## 4. Bounded buffering and flush policy

Activity accounting must not reintroduce an unbounded queue or create a latency cliff:

- Keep a fixed-size accumulator with a fixed vocabulary of counters; no per-event history.
- Flush on either a short time window (initial research target: 1 second) or a count threshold (initial research target: 64 operation attempts).
- Bound any asynchronous persistence queue. A full queue must produce an explicit saturation outcome; it must never grow without limit.
- Keep terminal authority transitions (approval, denial, revocation, failure) on the existing durable consent-ledger path. Activity receipts cannot substitute for a consent record.
- On teardown, flush the final accumulator and report whether it was durably committed. An incomplete final window is marked incomplete, not silently treated as complete.
- Define behavior for process crash, disk-full, and network/storage failure before promoting the receipt stream into a release gate.

The first implementation should benchmark the accumulator in isolation before coupling it to the live input hot path.

## 5. Qualification targets

The following are **proposed engineering targets**, not measured results:

| Dimension | Target |
|---|---:|
| Retained input-operation history in live M1 runtime | Constant with respect to total session event count |
| Activity accumulator memory | Fixed upper bound, independent of number of input events |
| Receipt write batch | At most 64 operation attempts or 1 second |
| Additional input-gate p99 overhead | ≤ 1 ms for counter update, measured on a fixed reference host |
| Raw input values in daemon logs | 0 |
| Clipboard payload bytes in daemon logs | 0 |
| Receipt chain integrity | 100% detection of mutated, removed, reordered, or replayed receipt cases in the verifier negative-control suite |
| Consent transcript compatibility | No schema or event changes to existing consent lifecycle ledger |

Measure the hot-path overhead with a release build and fixed input event mix. Report p50/p95/p99, CPU cost, memory high-water mark, and receipt queue saturation. A low median alone is not sufficient.

## 6. Negative controls

Required adversarial tests:

- Inject unique synthetic keycodes/coordinates/clipboard strings and verify none appear in captured logs.
- Change pointer movement frequency by 100× and verify retained runtime memory remains bounded.
- Fill the activity receipt persistence queue and verify its behavior matches the documented saturation policy.
- Mutate, delete, reorder, replay, and substitute a receipt in an offline verifier fixture.
- Revoke a session between receipt windows and verify no later receipt claims activity after the revocation boundary.
- Confirm the existing consent ledger still contains only lifecycle boundary events and remains independently verifiable.

## 7. Industry differentiation

Audit logging, session recording and permission management are already established features in commercial remote-support systems. Xenia should differentiate by making the *minimum necessary activity summary* independently verifiable, rather than by recording more of a user's behavior. The design goal is accountability with data minimization: operators can demonstrate the scope and coarse outcome of a session without creating a keylogging or clipboard-retention system.

