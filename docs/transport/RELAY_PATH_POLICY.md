# Xenia relay and network-path policy

**Status:** first configuration increment implemented in `xenia-transport-quic`; exact-head compile/tests pending. Full route telemetry, context binding, reconnect semantics and NAT-matrix qualification remain planned under [#480](https://github.com/Luminous-Dynamics/xenia-peer/issues/480).

## 1. Current code contract

The native host and viewer both use `bind_xenia_endpoint()`. That function now resolves one shared environment-variable policy and applies it to Iroh's endpoint builder while retaining the `presets::Minimal` TLS and socket configuration.

| Mode | Environment | Behavior | Intended deployment |
|---|---|---|---|
| Direct-only (default) | unset, `direct-only`, or `disabled` | Iroh relay disabled; requires directly reachable peer address | LAN, air-gapped, controlled lab |
| Public relay | `public-relay` or `public` | Iroh default public relay map; allows relay-assisted reachability / NAT hole punching | Explicitly opted-in internet connectivity |
| Custom relay | `custom-relay` or `custom` | Uses operator-supplied HTTPS relay URL list | Self-hosted / sovereign installations |

Configuration:

```sh
# Existing direct-only behavior (the default)
unset XENIA_IROH_RELAY_MODE
unset XENIA_IROH_RELAY_URLS

# Public relay mode. Apply to both host and viewer processes.
export XENIA_IROH_RELAY_MODE=public-relay

# Self-hosted relay mode. Supply one or more comma-separated HTTPS URLs.
export XENIA_IROH_RELAY_MODE=custom-relay
export XENIA_IROH_RELAY_URLS='https://relay-a.example.net,https://relay-b.example.net'
```

Custom mode rejects a missing list, empty entries, non-HTTPS URLs, malformed URLs, duplicate canonical URLs and unknown mode values. The parser and endpoint builder are shared by both binaries; there is no separate browser-side or host-side interpretation of the mode.

The setting must be applied consistently to both peers. A host with relay disabled cannot offer a relay-only route to a viewer with relay enabled, and a viewer with relay disabled cannot use the relay URL included in a remote endpoint address. Configuration mismatch is expected to fail connection establishment; there is no silent switch to a weaker or different policy.

## 2. What a relay can and cannot see

Iroh relay servers forward encrypted QUIC packets addressed to endpoint identities. The relay is not a Xenia application endpoint and cannot decrypt Xenia's end-to-end sealed envelopes.

Relay use is not metadata-free. The selected relay operator can observe network-level metadata, including endpoint identifiers used for routing, connection times/durations, packet sizes, direction, approximate volume and the relay region. The relay does not need to be trusted with Xenia's application plaintext, but it is still part of the availability and metadata threat model.

For this reason:

- Direct-only remains the default.
- Public relays require explicit operator opt-in.
- Custom relays use HTTPS URLs and are intended for operators who control their relay infrastructure.
- Do not print raw local/private address inventories in ordinary logs.
- Do not log raw endpoint locator tokens as generic diagnostic fields. The explicit `QUIC_CONNECT` value remains a user-mediated connection locator and should be handled as session metadata.
- Do not claim that relay operation proves confidentiality of traffic metadata.

Iroh's public relay infrastructure may rate-limit relayed traffic. It is a connectivity fallback and should not be treated as a guaranteed high-bitrate media backbone. Self-hosted deployments should provision geographic and capacity redundancy where needed.

## 3. Direct path, relay fallback, and recovery

The policy increment configures which relay map the Iroh endpoint may use. It does **not** yet provide a Xenia-level route telemetry or recovery protocol.

Iroh's endpoint path-selection and relay behavior should be treated as a transport facility, not as a substitute for Xenia's session-state guarantees. In particular, the current Xenia stack still needs:

1. A versioned, redacted route-observation record: direct / relay / unavailable, path ID if available, observation clock, RTT source, loss/jitter source, and route-change reason.
2. A tested direct-to-relay and relay-to-direct transition matrix.
3. Reconnect semantics that preserve the same authorization generation and event sequence.
4. Acknowledgement/reconciliation protocol for operations whose delivery outcome becomes unknown during path loss.
5. A strict rule that state-changing input/file operations are never replayed merely because a transport reconnect occurred.
6. Bounded queues and release handling for input state; stale video frames may be dropped, but key/button release and authority transitions may not be silently discarded.

The full work is tracked in [issue #480](https://github.com/Luminous-Dynamics/xenia-peer/issues/480).

## 4. QUIC multipath and standardization

The IETF published [RFC 10069, Managing Multiple Paths for a QUIC Connection](https://www.rfc-editor.org/rfc/rfc10069.html) in November 2026. It specifies path identifiers and management mechanisms for simultaneous QUIC paths.

Important scope boundary: RFC 10069 does not specify address discovery or how an application schedules traffic across paths. It also does not imply that a particular QUIC library or Xenia build implements it.

The pinned Xenia dependency is Iroh 1.0.2. The current source uses one Xenia bidirectional stream per QUIC connection. We must verify the exact pinned Iroh build's multi-path behavior and APIs before describing Xenia as multipath-capable. The initial programme should compare:

- Iroh's default direct/relay path selection;
- direct-only mode;
- one configured relay;
- multiple custom relays;
- independent QUIC connection recovery after path loss;
- future simultaneous multipath, if supported by the library and peer.

A potential future traffic policy is to keep latency-sensitive control on the best validated path and allow bulk media/data to use a separate path or scheduler. That requires explicit per-path congestion, fairness and ordering measurements. It is not part of this first increment.

## 5. Qualification matrix

The following are proposed tests and targets, not measured results.

| Scenario | Fixture | Expected behavior |
|---|---|---|
| Direct LAN | Both endpoints on same subnet, relay disabled | Direct QUIC succeeds; no relay dependency |
| Public IPv4 host | One endpoint directly reachable | Direct path succeeds |
| Home NAT | Both endpoints behind ordinary NAT | Public/custom relay assists connection, then direct path is attempted |
| CGNAT | At least one endpoint behind carrier-grade NAT | Session remains viable via a configured relay when direct hole punching fails |
| Symmetric NAT | Both endpoints behind restrictive NAT mapping | Relay path used if available |
| UDP restricted, HTTPS egress available | Enterprise egress fixture | QUIC relay mode reports failure honestly; transport fallback policy may choose TCP/WebSocket where allowed |
| Relay unavailable | Custom relay stopped or DNS/TLS failure | Clear connection error; no silent direct-only downgrade when caller selected relay-only conditions |
| One of multiple relays down | Two or more custom relays | Endpoint remains reachable through another configured relay, subject to library behavior |
| Route transition | Direct path removed after connect | Session either remains live through relay or reconnects with authorization state preserved |
| Reconnect ambiguity | Drop transport during a state-changing operation | Host outcome is reconciled before retransmission; no duplicate mutation |
| Relay metadata policy | Public/custom relay selected | Operator-visible disclosure and route telemetry, with no plaintext application data at relay |

Proposed thresholds to qualify after the instrumentation harness exists:

- At least 99% connection success within 10 seconds across the published NAT/firewall matrix when a configured relay path is available.
- Route-class transition surfaced within 1 second of a confirmed transition.
- Zero duplicate accepted input/file-transfer state transitions across path change and reconnect fixtures.
- No authorization downgrade, replay acceptance, unbounded queue growth, or stuck input state during path loss.
- Direct path remains preferred when its measured quality is equivalent; relay is used as fallback or when direct connectivity is unavailable.

Do not conflate connection success, media quality, control latency, privacy and authorization into one score.

## 6. Sources

- [Iroh 1.0 crate documentation](https://docs.rs/iroh/1.0.0/iroh/) — endpoint identities, relay forwarding and direct path establishment.
- [Iroh 1.0 RelayMode source](https://docs.rs/crate/iroh/1.0.0/source/src/endpoint.rs) — Disabled, Default, Staging and Custom relay modes.
- [Iroh 1.0 release announcement](https://www.iroh.computer/blog/v1) — public relay lifecycle and operational caveats.
- [RFC 10069](https://www.rfc-editor.org/rfc/rfc10069.html) — QUIC multipath extension.
- [Microsoft RDP Multipath](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-multipath) — industry comparison for continuous monitoring and selection of multiple UDP paths.
- [Microsoft RDP Shortpath](https://learn.microsoft.com/en-us/windows-365/enterprise/understanding-remote-desktop-protocol-traffic) — direct UDP, TURN relay and TCP fallback paths.
