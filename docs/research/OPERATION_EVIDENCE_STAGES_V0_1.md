# Stage-Accurate Operation Evidence for Xenia

**Status:** Additive reference implementation v0.1 — transport-free, in-memory model.  
**Tracking:** [Xenia #510](https://github.com/Luminous-Dynamics/xenia-peer/issues/510), with effect linearization owned separately by [#504](https://github.com/Luminous-Dynamics/xenia-peer/issues/504).  
**Related:** [#508 delegated M1 authority](https://github.com/Luminous-Dynamics/xenia-peer/issues/508), [#512 route inventory](https://github.com/Luminous-Dynamics/xenia-peer/issues/512), [#450 portable session evidence](https://github.com/Luminous-Dynamics/xenia-peer/issues/450).

## 1. Problem

The legacy M1 session machine records operation-named audit events when a permission check succeeds. Those are useful lane-admission records, but their labels can be read as stronger evidence than the producer establishes. For example, `InputInjected` can be recorded before the OS injector is invoked, and `FileSentToViewer` can be recorded before transmission or receiver verification.

The evidence boundary must be explicit:

`Authorization != Attempt != Local commit != Remote observation`

A timeout after dispatch does not prove failure or success. It is **UNKNOWN** until the effect owner or an independent layer reconciles the operation.

This implementation is additive. It does not rename or rewrite legacy audit events, change consent semantics, or write per-frame activity into the human consent ledger.

## 2. New reference model

The pure Rust model is in `crates/xenia-peer-core/src/operation_evidence.rs`, exported from `xenia-peer-core`.

One protected operation is identified by:
- stable caller-generated 128-bit operation/idempotency ID;
- monotonic operation sequence within the session;
- authenticated session fingerprint;
- exact M1 permission lane and direction;
- privacy-preserving resource identity digest;
- consent-boundary reference digest;
- policy digest;
- optional semantic-authority commitment digest and authority epoch.

No payload bytes, screen/audio media, clipboard content, raw input, file contents, bearer token or CapSecret is part of the schema.

### Stage lifecycle

| Stage | Meaning | Evidence ceiling |
|---|---|---|
| AuthorizationAdmitted | Recipient consent and applicable authority checks admitted the operation | Permission was admitted; no external effect has happened yet |
| EffectAttempted | The effect-owning subsystem actually invoked the call | Invocation occurred; no commit implied |
| EffectCommitted | The local effect owner crossed its defined commit point | Local commit only; no remote observation implied |
| OutcomeObserved | A stronger layer-specific observer supplied a receipt | Only the claim supported by that observer |
| Rejected | Operation was rejected before effect attempt | No effect was attempted |
| NotCommitted | Effect was attempted; owner proves local commit did not occur | Attempt happened, but local commit did not; not equivalent to preflight rejection |
| Unknown | Attempt occurred but outcome is ambiguous | Neither success nor failure; retry blocked |
| Reconciled | A receipt resolves the UNKNOWN state | Only the receipt's explicit outcome |

Examples:
- Input: platform injector accepted/rejected; never claim the target application acted.
- Clipboard write: OS clipboard API result; never claim another process read it.
- File send: local send/enqueue is not receiver hash verification.
- File receive: staging/chunk receipt is not final verified publication.
- Screen/audio: local send or compositor submission is not proof of remote rendering or photon presentation.

### State transitions

`Admitted -> Attempted -> Committed -> Observed`

Other valid paths:
- `Admitted -> Rejected` (no effect invocation)
- `Attempted -> NotCommitted` (effect invoked; local owner proves commit did not occur)
- `Attempted -> Unknown -> ReconciledNotCommitted`
- `Attempted -> Unknown -> ReconciledCommitted -> ReconciledObserved`
- `Attempted -> Unknown -> ReconciledCommitted`
- `Attempted -> Unknown -> ReconciledObserved`

The last path is allowed only when the reconciliation receipt itself proves the stronger observed outcome.

Illegal stage skips are rejected. An ambiguous operation cannot be attempted again through the same record. The caller must reconcile using the stable operation ID.

## 3. Evidence integrity

Events are appended to a bounded, session-local BLAKE3 hash chain. Each event binds:
- global event sequence;
- operation ID and operation sequence;
- digest of the complete operation context;
- stage event kind;
- local clock-domain ID and monotonic tick;
- evidence/receipt digest;
- previous event hash.

The verifier checks event sequence, chain links, event hashes, clock-domain binding and monotonic local ticks.

**Claim boundary:** this is a tamper-evident in-memory chain, not a signature, external timestamp, independent trust anchor, durable export, or proof that the supplied effect-owner receipt is truthful. A caller must still authenticate/verify the receipt and bind the final digest to a durable signed session bundle. Portable persistence/export remains separate work under #450.

## 4. Bounded resource use

V0.1 caps one ledger at:
- 4,096 operation records;
- 32,768 stage events.

Capacity exhaustion is an explicit error; records are not silently evicted from an active session. A product integration must define a durable flush/rotation lifecycle before reaching those limits. It must never evict an UNKNOWN operation or erase a receipt needed for reconciliation.

## 5. Adversarial tests

The current unit tests cover:
1. Admission → attempt → commit → observed progression.
2. UNKNOWN blocks another attempt and requires a reconciliation receipt.
3. Duplicate admission with identical context is idempotent; changed context conflicts.
4. Commit/observation cannot be claimed before attempt.
5. Rejection is only legal before attempt.
6. Operation sequence and local clock ticks must be monotonic.
7. Foreign session fingerprint is rejected.
8. Event digest tampering is detected.
9. Event clock-domain tampering is detected.
10. Conflicting reconciliation receipts cannot overwrite one another.

[operation-evidence-stages-v0.1.json](../../benchmarks/operation-evidence-stages-v0.1.json) defines 12 synthetic stage/fault scenarios. The corpus contains no real effect observations and cannot produce a release PASS.

## 6. Next integration boundary

Do not wire this model into live operations by merely calling `mark_committed` after the existing preflight method. The effect owner must establish the correct commit point.

The proper sequence is:
1. Freeze exact per-lane effect boundaries using #512 route inventory.
2. Add the per-operation local serialization gate from #504 so revoke-vs-commit races have one linearization order.
3. Invoke the effect owner and append Attempted/Committed/Unknown from the actual call result.
4. Reconcile ambiguous outcomes by operation ID; no blind retry.
5. Add signed/durable portable export under #450.
6. Independently verify per-lane outcome evidence and route coverage.

This module does not itself serialize a remote OS call with revocation, does not consume Mycelix ROS-005 authority, and does not prove global/distributed revocation.

## 7. Industry and assurance positioning

Tamper-evident audit logs and fine-grained access controls are already present in established enterprise remote support and open-source systems. Xenia's opportunity is not the existence of a log; it is the precise, independently checkable distinction between admission, attempted effect, local commit, stronger observation and unresolved outcomes—bound to the exact lane, direction, session and authority/consent context.

The benchmark must report false permits, missed effects, UNKNOWN duration/reconciliation, receipt completeness and verifier errors independently. Do not blend these into latency or one opaque trust score.

## 8. Current evidence state

- Pure Rust reference module authored and exported.
- Ten focused unit tests authored.
- Source-level read-back confirms bounded limits, explicit state transitions and hash-chain verification.
- Rust compilation, unit-test execution, rustfmt, Clippy and hosted CI are not claimed.
- No live daemon integration, persistence/export, digital signature, external review, OS effect qualification, or production readiness is claimed.

The draft is a reference contract and testable starting point, not closure of #504/#510.