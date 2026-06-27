# M1 Runtime Smoke Evidence

**Status:** CI-protected executable smoke path
**Command:** `scripts/xenia-m1-runtime-smoke.sh .`
**Binary path:** `cargo run -p xenia-peer -- --m1-runtime-smoke`

## Purpose

This evidence note records the first daemon-executable M1 consent/accountability proof.

The smoke path exercises the daemon-local M1 runtime skeleton without starting networking, screen capture, GUI consent, or real input injection.

## Expected output

```text
M1 runtime smoke passed
entries: 3
consent.requested
consent.granted
consent.revoked


```

## What this proves

The smoke path proves that the daemon binary can:

1. create a deterministic M1 runtime session,
2. offer a session,
3. grant consent,
4. allow frame and input operations only after consent,
5. revoke consent,
6. append only consent-boundary events to the ledger,
7. skip frame/input operation events in the consent ledger,
8. verify the resulting signed ledger transcript,
9. print stable consent event names.

## CI protection

The smoke path is protected by:

- `scripts/xenia-m1-runtime-smoke.sh`
- `.github/workflows/m1-runtime-smoke.yml`

The workflow verifies the exact output so regressions in event ordering, event naming, transcript length, or executable behavior fail CI.

## Non-claims

This smoke path does not claim production remote desktop readiness.

It does not yet provide:

- networked host/viewer session negotiation,
- real capture,
- real input injection,
- user-facing consent UI,
- persistent user-facing ledger UX,
- complete operation telemetry schema.

Its value is that the daemon now has an executable, deterministic, CI-protected accountability proof before risky runtime integrations are added.
