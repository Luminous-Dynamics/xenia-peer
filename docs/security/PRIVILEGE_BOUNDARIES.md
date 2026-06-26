# Xenia Privilege Boundaries

Xenia crosses sensitive boundaries: display capture, input injection, transport,
operator administration, and audit logging. These boundaries should be treated
as separate trust zones even on a single developer machine.

## Boundary model

| Boundary | Examples | Default posture |
| --- | --- | --- |
| Capture | screen/audio/window capture | disabled until consent is established |
| Input | keyboard/mouse/control injection | disabled until consent is established |
| Transport | WebSocket/QUIC sessions | authenticated, replay-resistant, revocable |
| Viewer | human operator UI | least privilege, visible session state |
| Admin | sovereign/operator controls | authenticated, audited, explicit action grants |
| Ledger | audit/provenance stream | append-only semantics where possible |

## Fail-closed rules

- Unknown consent state means no capture and no input.
- Lost revocation channel means privileged actions stop.
- Audit failure blocks privileged sessions unless explicitly running in a local
  test mode.
- Transport reconnects must not silently inherit stale authority.

## Review checklist

For every change that touches these boundaries, answer:

1. What new authority does this code gain?
2. Who can revoke it?
3. Where is the event recorded?
4. What happens if the transport drops mid-action?
5. What happens if decoding, capture, or input injection fails?
