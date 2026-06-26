# Consent State Machine

This document defines the minimum privileged-session state model Xenia should
implement before any remote-control or capture path is considered releaseable.

## States

```text
Idle
  No privileged session exists.

Requested
  A peer has requested capture/control authority.

Presented
  The controlled side has visible, local UI/CLI evidence of the request.

Granted
  The controlled side explicitly approved the request.

Active
  Privileged data/control flow is occurring and ledger events are being emitted.

Revoking
  The controlled side requested stop/revoke.

Revoked
  Privileged flow has stopped. Further flow requires a new request.

Denied
  The controlled side refused the request.

Expired
  The grant timed out.

FaultClosed
  A validation, transport, ledger, or UI fault occurred and privilege stopped.
```

## Allowed transitions

```text
Idle -> Requested
Requested -> Presented
Presented -> Granted
Presented -> Denied
Granted -> Active
Active -> Revoking
Revoking -> Revoked
Active -> Expired
Requested -> FaultClosed
Presented -> FaultClosed
Granted -> FaultClosed
Active -> FaultClosed
```

No transition may skip `Presented` for a human-controlled privileged session.

## Invariants

- `Active` requires a prior `Granted` transition.
- `Granted` requires visible local presentation.
- `Revoking`, `Revoked`, `Denied`, `Expired`, and `FaultClosed` stop privileged
  capture/control flow.
- Ledger/audit events are emitted for request, presentation, grant, active start,
  revoke, denial, expiry, and fault-close.
- Transport reconnect must not silently restore `Active` without revalidating the
  grant and revocation state.

## Suggested event names

```text
consent.requested
consent.presented
consent.granted
consent.denied
session.active_started
session.revocation_requested
consent.revoked
consent.protocol_violation
session.expired
session.fault_closed
```

These names now line up with `docs/observability/EVENT_TAXONOMY.md` for the
ledger-backed consent/admin events exposed by `xenia-ledger`.
