# Xenia Transport Availability Profile V1

Status: V12 authenticated L4/L5 availability contract

Xenia already authenticates *what carrier/framing contract* a session uses via
`TransportProfileV1`. V12 adds a separate `TransportAvailabilityProfileV1` so
failure/liveness behavior is not an ambient implementation detail.

The current profile is intentionally small and common across TCP, WebSocket,
and QUIC:

| Field | Current value | Meaning |
|---|---:|---|
| schema | `xenia-transport-availability-profile-v1` | domain/version label |
| send stall timeout | 15,000 ms | a blocked application-envelope send fails the session instead of waiting forever |
| receive envelope timeout | 120,000 ms | one complete Xenia application envelope must arrive before the absolute deadline |
| graceful close timeout | 3,000 ms | bounded teardown budget where an explicit graceful close is available |
| application keepalive interval | 0 ms | Xenia V12 emits no synthetic application keepalive |
| carrier keepalive resets application idle | `false` | WebSocket ping/pong and carrier-level QUIC traffic cannot keep an application session alive indefinitely without Xenia envelopes |

## Why this is a separate profile

Carrier semantics and availability semantics evolve at different rates. V12
therefore does **not** silently rename TCP `/0`, WebSocket `/1`, or QUIC `/0`.
Instead `NegotiatedSessionContextV3` commits both:

- the exact `TransportProfileV1`; and
- the exact `TransportAvailabilityProfileV1`.

Changing a timeout or keepalive rule changes the authenticated V3 session
context even when wire framing/ALPN/subprotocol bytes remain unchanged.

## Fail-closed behavior

`TransportError::TimedOut` is the common failure for a bounded transport
operation. The current implementation enforces:

- TCP: the whole length-prefix + body receive is bounded; the whole
  length-prefix + body + flush send is bounded.
- WebSocket: the entire control-frame-skipping receive loop is enclosed by one
  absolute timeout. A stream of ping/pong frames cannot refresh the deadline.
- QUIC: the entire length-prefix + body receive and send are bounded on the one
  authenticated logical stream.

A timeout is a session failure, not a request to continue using a possibly
half-written/half-read carrier state.

## Deliberate non-claims

V12 does not claim:

- distributed availability or Byzantine-liveness guarantees;
- TCP/QUIC connection-establishment deadlines;
- bandwidth/fairness guarantees;
- a carrier-independent guarantee about kernel/network buffering before Xenia
  sees bytes;
- that WebSocket fragmentation exposes a separate "first fragment" versus
  "completion" clock through tungstenite;
- that carrier keepalives prove application health.

Those require separate profiles or lower-level carrier-specific evidence.

## Evolution rule

Availability semantics are exact-match. If a future deployment needs a
long-idle profile, an explicit application heartbeat, a different send-stall
budget, or carrier-specific keepalive behavior, define a new named availability
profile and bind it into a new negotiated session context. Do not silently turn
these into local knobs after authentication.
