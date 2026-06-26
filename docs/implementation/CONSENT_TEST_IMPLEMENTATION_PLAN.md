# Consent Test Implementation Plan

Xenia's highest-risk future capability is privileged capture/control. Before RC1,
the consent model needs executable tests, not only policy text.

## Minimum invariant tests

1. `Active` cannot be reached from `Idle`, `Requested`, or `Presented` directly.
2. `Active` requires `Presented -> Granted -> Active`.
3. `Revoked`, `Denied`, `Expired`, and `FaultClosed` cannot resume `Active`.
4. Reconnect does not silently restore an active privileged session.
5. Revocation stops capture/control even if transport is still connected.
6. Ledger/audit events exist for request, presentation, grant, active start,
   revoke, denial, expiry, and fault-close.

## Scaffold command

```bash
scripts/scaffold-consent-tests.py . --stdout
```

To write the default skeleton:

```bash
scripts/scaffold-consent-tests.py .
```

The default target is:

```text
xenia-peer/crates/xenia-peer-core/tests/consent_state_invariants.rs
```

Adjust the target if the real consent state machine lands in `xenia-handshake`.

## Coverage scan

```bash
scripts/check-consent-coverage.py . --json _archive/consent-coverage.json
```

The scan is advisory until the real state machine exists. Later, CI can run:

```bash
scripts/check-consent-coverage.py . --strict
```
