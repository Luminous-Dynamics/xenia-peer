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
| Transport | oversized envelope or message | reject before session decode and without poisoning the connection |
| Transport | non-envelope WebSocket message | reject as protocol fault without attempting session decode |
| Transport | replayed control frame | reject as duplicate or stale |
| Capture | backend unavailable | fall back to test capture or fail closed |
| Video | malformed encoded frame | reject without daemon panic |
| Input | injection backend unavailable | report error; never retry blindly |
| Ledger | audit sink unavailable | block privileged session or mark explicit test mode |
| Admin | unauthorized admin action | deny and record attempt |

## How to use this plan

Each case should eventually map to a test name, crate, and expected event. Until
then, it is a planning document and an RC1 gate.

## RC1 mapped transport fault tests

| Test | Crate | Fault covered |
| --- | --- | --- |
| `tcp_detects_truncated_envelope_as_unexpected_eof` | `xenia-transport-ws` conformance suite | TCP peer closes before advertised envelope length is satisfied. |
| `tcp_rejects_oversize_receive_before_allocation` | `xenia-transport-ws` conformance suite | Forged TCP length prefix above `MAX_ENVELOPE_BYTES`. |
| `websocket_rejects_oversize_send_without_poisoning_connection` | `xenia-transport-ws` conformance suite | WebSocket local oversized envelope is rejected without poisoning the connection. |
| `websocket_rejects_text_protocol_fault` | `xenia-transport-ws` conformance suite | WebSocket peer sends a text frame instead of sealed binary envelope bytes. |
| `quic_rejects_oversize_send_without_poisoning_connection` | `xenia-transport-quic` conformance suite | QUIC local oversized envelope is rejected and the stream remains usable. |

These cases are intentionally device-independent and run in the normal Cargo
test path. They are not a complete hostile-network simulation; they are the
minimum RC1 evidence that malformed transport inputs fail closed at the envelope
boundary.
