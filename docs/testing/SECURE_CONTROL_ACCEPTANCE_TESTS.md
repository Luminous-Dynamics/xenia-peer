# Secure Control Acceptance Tests

Xenia should not become good at remote control before it is good at refusing
unsafe control. These acceptance tests define the minimum behavior for capture,
viewer, admin, and input authority paths.

## Minimum behavioral tests

| Case | Stimulus | Expected result |
| --- | --- | --- |
| Unknown consent | Start capture/input without consent state | deny fail-closed |
| Consent denied | Operator requests session; user denies | no capture, no input, event recorded |
| Revocation mid-session | User revokes active session | capture/input stop; transport authority invalidated |
| Lost revocation channel | Control channel drops | privileged actions stop or require re-auth |
| Stale reconnect | Transport reconnects with old session | no inherited authority without revalidation |
| Ledger unavailable | Audit sink unavailable | privileged session blocked unless explicit local test mode |
| Admin action denied | Unauthorized admin request | deny and record attempt |
| Malformed frame | Bad wire/control frame | reject without panic |
| Replay frame | Duplicate control/input frame | reject as stale or duplicate |
| Test mode | Local test capture/input simulation | visible test-mode event marker |

## Evidence mapping

Each accepted implementation should eventually map every row to:

- test name
- crate/app path
- expected event family from `docs/observability/EVENT_TAXONOMY.md`
- failure mode
- whether the test runs in CI

Until this table is mapped, RC1 should remain blocked for production-like claims.
