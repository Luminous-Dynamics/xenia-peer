# Secure Defaults Test Plan

This plan maps Xenia's secure-default policy to tests that should exist before
RC1.

## Static gates

```bash
scripts/check-secure-defaults.py .
scripts/check-codeowners.py .
scripts/generate-release-dashboard.py . --markdown _archive/release-dashboard.md
```

## Runtime tests to add

| Area | Test | Expected result |
| --- | --- | --- |
| Bind defaults | Start peer/viewer with no flags | Loopback only |
| Public bind | Start with public bind flag | Explicit warning and audit event |
| Capture default | Start peer with no consent | No capture frames emitted |
| Injection default | Start peer with no consent | No input events injected |
| Consent grant | Approve requested session | Active only after local approval |
| Revocation | Revoke active session | Flow stops and fails closed |
| Transport reconnect | Drop/reconnect link | No silent privilege restoration |
| Ledger failure | Ledger write fails | Privileged session fault-closes |
| Viewer crash | Viewer disappears mid-session | Controlled side revokes/fault-closes |
| Admin mistake | Admin UI tries bypass | Request is denied or review-gated |

## Property-style tests

The consent state machine should be tested with generated sequences:

- no sequence reaches `Active` without `Granted`;
- every revocation-like state stops privileged flow;
- every fault path lands in `FaultClosed` or a non-privileged state;
- reconnect does not restore privilege unless a valid grant still exists.
