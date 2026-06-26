# RC1 Transport Fault-Injection Evidence

This evidence was generated from the normalized Xenia source tree.
It proves the current transport conformance suite covers the minimum
RC1 malformed-transport cases without relying on local machine paths,
runtime state, or device-dependent infrastructure.

- generated_at_utc: `2026-06-26T08:56:57+00:00`
- all_cases_passed: `true`
- cases: `5`

## Covered cases

| Case | Crate | Test | Result |
| --- | --- | --- | --- |
| `tcp-truncated-envelope` | `xenia-transport-ws` | `tcp_detects_truncated_envelope_as_unexpected_eof` | `PASS` |
| `tcp-oversize-prefix` | `xenia-transport-ws` | `tcp_rejects_oversize_receive_before_allocation` | `PASS` |
| `websocket-oversize-binary` | `xenia-transport-ws` | `websocket_rejects_oversize_send_without_poisoning_connection` | `PASS` |
| `websocket-text-frame` | `xenia-transport-ws` | `websocket_rejects_text_protocol_fault` | `PASS` |
| `quic-oversize-send` | `xenia-transport-quic` | `quic_rejects_oversize_send_without_poisoning_connection` | `PASS` |

## RC1 conclusion

The transport fault-injection soft blocker is satisfied only when every
listed case passes and `xenia.release.toml` removes only the matching
soft blocker. Xenia remains `pre-rc`; this evidence does not promote the
release train by itself.
