# Xenia Fault-Injection Plan

Xenia needs fault tests before it needs more features. The first useful tests are
small, deterministic, and hostile to assumptions.

## Minimum RC1 fault cases

| Area | Fault | Expected behavior |
| --- | --- | --- |
| Handshake | malformed hello/session frame | reject and log without panic |
| Consent | stale consent response | deny capture/input |
| Consent | revocation arrives during active session | stop privileged actions fail-closed |
| Transport | disconnect mid-frame | drop partial frame and require re-auth/re-sync |
| Transport | replayed control frame | reject as duplicate or stale |
| Capture | backend unavailable | fall back to test capture or fail closed |
| Video | malformed encoded frame | reject without daemon panic |
| Input | injection backend unavailable | report error; never retry blindly |
| Ledger | audit sink unavailable | block privileged session or mark explicit test mode |
| Admin | unauthorized admin action | deny and record attempt |

## How to use this plan

Each case should eventually map to a test name, crate, and expected event. Until
then, it is a planning document and an RC1 gate.
