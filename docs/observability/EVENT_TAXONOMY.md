# Xenia Event Taxonomy

Audit and telemetry events should be stable enough that users, admins, and tests
can reason about them. This document names the first event families; it does not
require a final schema yet.

## Event families

| Family | Purpose | Examples |
| --- | --- | --- |
| `session.*` | session lifecycle | `session.started`, `session.revoked`, `session.expired` |
| `consent.*` | authority and revocation | `consent.requested`, `consent.granted`, `consent.denied`, `consent.revoked` |
| `capture.*` | capture lifecycle/errors | `capture.started`, `capture.stopped`, `capture.backend_unavailable` |
| `input.*` | input authority/errors | `input.enabled`, `input.blocked`, `input.backend_unavailable` |
| `transport.*` | network state | `transport.connected`, `transport.disconnected`, `transport.replay_rejected` |
| `ledger.*` | audit persistence | `ledger.appended`, `ledger.unavailable`, `ledger.integrity_warning` |
| `admin.*` | operator/admin actions | `admin.action_requested`, `admin.action_denied`, `admin.action_applied` |

## Event rules

- Privileged actions should have a corresponding event.
- Denials are first-class events, not silent branches.
- Test mode should be visible in events.
- Events should avoid storing secrets, raw credentials, or unnecessary personal
  data.
