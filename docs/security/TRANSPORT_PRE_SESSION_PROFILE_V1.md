# Xenia Transport Pre-Session Profile V1

V13 separates **unauthenticated carrier-establishment resource policy** from
V12's authenticated application-envelope availability policy.

The current schema is `xenia-transport-pre-session-profile-v1`.

| Carrier | connect / connect+upgrade | server protocol upgrade | logical stream open |
|---|---:|---:|---:|
| TCP | 10 s | n/a | n/a |
| WebSocket `/1` | 20 s total client connect+HTTP upgrade | 10 s | n/a |
| QUIC `/0` | 15 s QUIC handshake | n/a | 10 s one-stream open/accept + preface |

A listener waiting for a *new peer* is not itself given a short timeout: idle
service availability is different from the amount of time one selected,
unauthenticated peer may consume during establishment.

After the cryptographic handshake, `NegotiatedSessionContextV4` commits the
exact pre-session profile together with the carrier profile, V12 availability
profile, wire profile, handshake policy, key-schedule schema and capabilities.
This is retrospective authentication of the policy that was enforced before
peer authentication was possible.

Timeouts are fail-closed. A carrier whose connect/upgrade/stream operation times
out is discarded; it is never resumed as a partially established session.

The WebSocket client API exposes connect + HTTP upgrade as one future, so V1
binds a 20-second combined client ceiling while independently bounding an
already-accepted server-side HTTP upgrade at 10 seconds.

`XENIA_TRANSPORT_PRE_SESSION_V1_VECTOR.json` freezes language-neutral bincode-v1
fixture bytes for all three profiles.
