# WebSocket Transport Profile `/1` Migration

V11 upgrades the Xenia session WebSocket carrier from
`xenia/transport/websocket/0` to `xenia/transport/websocket/1`.

The `/1` profile requires the exact RFC 6455 subprotocol token:

`xenia.transport.websocket.v1`

Native `xenia-transport-ws` clients offer that token automatically and the
server rejects an upgrade that omits or changes it. The server also installs
its 16 MiB message/frame receive ceiling in tungstenite before session-envelope
parsing.

## Browser companion change

The browser viewer lives in the separate `xenia-wire` repository, so it is not
modified by this patch tranche. Its WebSocket construction must migrate from a
no-subprotocol connection to the browser equivalent of:

`new WebSocket(url, "xenia.transport.websocket.v1")`

If the browser implementation independently constructs or validates the V2
negotiated-session context, it must use the `/1` WebSocket transport profile:

- protocol ID: `xenia/transport/websocket/1`
- protocol version: `1`
- framing: one binary WebSocket message per Xenia envelope
- maximum session envelope: `16,777,216` bytes
- maximum handshake envelope: `16,384` bytes
- reliable: `true`
- ordered: `true`
- logical streams: `1`

The browser should also verify that `WebSocket.protocol` equals the exact token
after the upgrade. A missing or different token is a protocol/profile mismatch,
not a condition for silently falling back to `/0`.

## Channels not affected

This migration applies only to the Xenia **session transport** implemented by
`xenia-transport-ws`. Operator/admin/consent WebSockets are separate protocols
and must not start advertising this subprotocol unless their own protocol is
versioned to do so.

## Rollout

Deploy the browser `/1` companion change together with the V11 daemon if browser
sessions must remain available. Native CLI/GUI/mobile Xenia session clients in
this repository use the profile automatically.
