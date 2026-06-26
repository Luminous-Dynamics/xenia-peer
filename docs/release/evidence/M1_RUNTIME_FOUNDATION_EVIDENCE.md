# M1 Runtime Foundation Evidence

**Status:** implemented as deterministic pre-network foundation  
**Scope:** consent lifecycle, ledger mapping, transcript verification, daemon-local runtime skeleton  
**Out of scope:** real networking, real capture, real input injection, GUI consent flow

## Merged implementation anchors

- **#30 — M1 session state machine**
  - Adds a pure deterministic M1 lifecycle machine.
  - Models Idle, Offered, Active, Denied, Revoked, Ended, and Failed.
  - Gates frame streaming and input injection behind Active state.

- **#31 — M1 session events to ledger records**
  - Adds daemon-layer adapter from M1 audit events to `xenia-ledger` consent records.
  - Maps consent-boundary events to Request, Approval, Denial, Revocation, and Violation.
  - Deliberately skips frame/input operation events so they are not misrepresented as consent events.

- **#32 — M1 ledger transcript fixture**
  - Drives a deterministic M1 lifecycle.
  - Appends consent-boundary records to a signed hash chain.
  - Verifies the resulting ledger transcript.
  - Proves frame/input operation events are absent from the consent transcript.

- **#33 — M1 runtime session skeleton**
  - Adds daemon-local runtime-shaped session bridge.
  - Owns session machine, ledger chain, source/session/request identity, scope, and audit cursor.
  - Flushes only new consent-boundary events into the ledger.
  - Verifies the resulting ledger chain.

## Current guarantees

M1 now proves:

1. A session must be offered before consent can be granted.
2. Frames and input are denied before consent.
3. Frames and input are allowed only in Active state.
4. Revocation disables privileged frame/input flow.
5. Denial and revocation are distinct terminal consent outcomes.
6. Normal session end is not falsely recorded as revocation.
7. Failed session flow records protocol violation.
8. Consent-boundary events are appendable to a signed ledger chain.
9. The ledger transcript verifies using the operator public key.
10. Frame/input operation events are not falsely encoded as consent records.

## Remaining M1 work

Next implementation layers should remain narrow:

1. Add daemon CLI smoke path for deterministic M1 runtime transcript.
2. Add in-process host/viewer lifecycle harness.
3. Connect consent approval source to M1 runtime.
4. Gate real frame path through M1 runtime.
5. Gate real input path through M1 runtime.
6. Persist and reload M1 ledger transcript evidence.
7. Add release evidence artifact for a local M1 session run.

## Non-claims

This milestone does not claim production remote desktop readiness.

It does not yet provide:

- real networked M1 session negotiation,
- user-facing GUI consent,
- production screen capture,
- production input injection,
- complete operation telemetry schema,
- production ledger persistence UX.

The value of this milestone is that the consent/accountability core is now deterministic, testable, and reviewable before risky runtime integrations are added.
