# Xenia across the OSI model

Status: architecture boundary, V10

Xenia is **not** intended to replace Ethernet, IP, TCP, or QUIC. Its product
boundary is a cross-layer security/session plane carried by existing network
stacks. The strongest Xenia-owned semantics live at OSI Layers 5–7, with a
small Layer-4 adapter surface that preserves sealed-envelope boundaries and
backpressure.

## Layer ownership

| OSI layer | Xenia ownership | Current responsibility |
|---|---|---|
| 7 Application | Strong | consent, operator authorization, capabilities, delegation, evidence, credential/proof policy, file/input/clipboard/session semantics |
| 6 Presentation | Strong | canonical transcripts, bincode/protocol framing, signatures, ML-KEM/ML-DSA/Ed25519, sealed envelopes, ZK objects, typed capability encoding |
| 5 Session | Strong | hybrid handshake, peer authentication, transcript binding, session/lane key schedule, replay state, rekey epochs, immutable negotiated session context |
| 4 Transport | Adapter / partial | TCP/WebSocket/QUIC carriers, envelope boundaries, byte ceilings, ordering/reliability contract, backpressure, QUIC ALPN |
| 3 Network | Not owned | IP routing, addressing, NAT behavior and path selection are supplied by the carrier/runtime (for example Iroh/QUIC) |
| 2 Data link | Not owned | Ethernet/Wi-Fi/link framing and MAC behavior |
| 1 Physical | Not owned | radio, optical, copper, PHY/modulation/hardware signaling |

This boundary is deliberate. Reimplementing reliable transport, congestion
control, global routing, Wi-Fi, or physical signaling would increase the
trusted and maintenance surface without strengthening Xenia's differentiated
security model.

## The V10 cross-layer contract

Before V10, the authenticated negotiated context committed a carrier enum such
as `Tcp`, `WebSocket`, or `Quic` plus the sealed capabilities frame. That bound
*which family* of transport was intended but left several Layer-4/5 semantics
ambient: framing revision, Xenia transport protocol identifier, byte ceilings,
and whether the session assumed an ordered/reliable single logical stream.

V10 introduces `TransportProfileV1`. The current profile commits:

- carrier kind;
- Xenia transport protocol identifier and revision;
- envelope framing semantics;
- maximum session envelope size;
- smaller unauthenticated handshake parser ceiling;
- reliability and ordering expectations;
- logical stream count.

`Transport::transport_profile()` makes this a property of the concrete live
transport implementation. The daemon and viewers hash the **actual transport
object's profile** into `NegotiatedSessionContextV2`; they no longer construct
the authenticated transport contract from only a manually selected enum.

The V2 context additionally commits the current Xenia sealed-envelope profile,
handshake policy profile, handshake transcript schema, session key-schedule
schema, and immutable sealed capabilities.

Conceptually:

```text
Application consent / authorization / capabilities                 L7
        |
Canonical protocol + sealed-envelope + crypto profile              L6
        |
Hybrid authenticated handshake + transcript + rekey/session state  L5
        |
Authenticated TransportProfileV1                                   L4/L5 boundary
        |
TCP | binary WebSocket | one ordered Iroh QUIC stream              L4
        |
IP / routing / NAT / link / physical network                       L3-L1
```

A framing/version/limit change therefore cannot silently ride under the same
"QUIC" or "WebSocket" label. It needs an explicit new transport profile and
changes the authenticated session context.

## Fail-closed compatibility rule

`TransportProfileV1::is_current_supported_profile()` accepts only an **exact**
defined profile. A peer or implementation cannot negotiate a profile by freely
mixing fields from different versions.

For example, all of the following are protocol changes rather than harmless
runtime knobs:

- changing `u32` length-prefix framing to varints;
- changing the QUIC ALPN/profile revision;
- increasing the pre-allocation envelope ceiling;
- increasing the unauthenticated handshake parser ceiling;
- changing from one ordered logical stream to multiple streams;
- changing reliability/ordering semantics.

A future profile can support those changes, but it must be named/versioned and
reviewed explicitly.

## Unauthenticated-phase resource boundary

The general transport ceiling remains 16 MiB because media envelopes can be
large. Hybrid handshake messages are far smaller, so V10 adds a separate 16 KiB
handshake ceiling and checks it **before bincode deserialization**.

This protects the handshake parser from accepting media-sized unauthenticated
objects. V11 additionally configures the WebSocket carrier's native message and
frame ceilings before tungstenite assembles an application message, while the
Xenia envelope check remains as defense in depth. TCP/QUIC continue to reject
the general length prefix before allocating the declared envelope body.

## Security properties supplied by lower layers

Xenia may benefit from lower-layer security without treating it as the source
of end-to-end authorization:

- QUIC supplies transport encryption, congestion control, reliability and path
  behavior.
- `wss://` may hide Xenia message contents and metadata from parts of the path.
- TCP supplies ordered reliable byte transport.

Xenia still authenticates its own transcript and seals its own session payloads.
A TLS/QUIC certificate or successful TCP connection does not by itself grant a
Xenia capability.

## Future extensions

Extensions should preserve the ownership boundary above. High-value future work
includes:

1. a future QUIC profile revision only through a new ALPN/profile pair (V11 now pins altered-ALPN and altered-stream-preface rejection as regressions);
2. carrier-native handshake-phase ceilings below the general envelope ceiling
   where the QUIC/TCP implementations can enforce them before buffering;
3. optional multiple QUIC streams only through a new profile that also binds
   lane-to-stream mapping and replay/order semantics;
4. timeout/idle/keepalive policy binding where those values are security- or
   availability-relevant;
5. process/network enforcement in Nixward using Xenia identities/capabilities,
   without moving IP routing into Xenia itself.

The architectural rule is: **move downward only when doing so makes an Xenia
security invariant enforceable. Do not move downward merely to own more of the
network stack.**
