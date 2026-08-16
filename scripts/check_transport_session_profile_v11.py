#!/usr/bin/env python3
"""Fail-closed source contract for Xenia transport/session V11."""
from pathlib import Path
import re, sys
root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
fail=[]
def read(rel):
    p=root/rel
    if not p.exists(): fail.append(f'missing {rel}'); return ''
    return p.read_text()
transport=read('crates/xenia-peer-core/src/transport.rs')
handshake=read('crates/xenia-peer-core/src/handshake.rs')
ws=read('crates/xenia-transport-ws/src/lib.rs')
viewer=read('apps/xenia-viewer/src/main.rs')
mobile=read('crates/xenia-mobile-ffi/src/engine.rs')
host=read('apps/xenia-peer/src/main.rs')
osi=read('docs/architecture/OSI_SECURITY_PLANE.md')
roadmap=read('ROADMAP.md')
ws_migration=read('docs/security/WEBSOCKET_PROFILE_V1_MIGRATION.md')
ws_tests=read('crates/xenia-transport-ws/tests/transport_conformance.rs')
quic=read('crates/xenia-transport-quic/src/lib.rs')
quic_tests=read('crates/xenia-transport-quic/tests/transport_conformance.rs')
checks=[
 (transport,'WEBSOCKET_PROTOCOL_ID: &str = "xenia/transport/websocket/1"','WS profile revision /1'),
 (transport,'TransportKind::WebSocket => 1','WS protocol version 1'),
 (ws,'XENIA_WEBSOCKET_SUBPROTOCOL: &str = "xenia.transport.websocket.v1"','WS subprotocol token'),
 (ws,'max_message_size: Some(MAX_ENVELOPE_BYTES as usize)','native WS message ceiling'),
 (ws,'max_frame_size: Some(MAX_ENVELOPE_BYTES as usize)','native WS frame ceiling'),
 (ws,'connect_async_with_config(request, Some(websocket_config()), true)','bounded WS client constructor'),
 (ws,'accept_hdr_async_with_config(','bounded WS server constructor'),
 (ws,'accept_xenia_subprotocol','WS subprotocol validation'),
 (ws,'server_rejects_client_without_xenia_subprotocol','WS missing-subprotocol regression'),
 (ws,'native_limit_rejects_oversize_receive','WS carrier-native oversize regression'),
 (ws,'pub struct WsTransport','opaque bounded WS transport'),
 (handshake,'pub struct PendingSessionSurface','pending typestate'),
 (handshake,'pub struct AuthenticatedSessionSurface','authenticated typestate'),
 (handshake,'pub fn authenticate_capabilities(\n        self,','consuming typestate transition'),
 (viewer,'PendingSessionSurface::new_with_availability(','viewer typestate adoption'),
 (viewer,'authenticated_surface: Option<AuthenticatedSessionSurface>','viewer authenticated state'),
 (viewer,'tokio::sync::watch::channel(false)','viewer outbound auth latch'),
 (mobile,'PendingSessionSurface::new_with_availability(','mobile typestate adoption'),
 (mobile,'authenticated_surface: Option<AuthenticatedSessionSurface>','mobile authenticated state'),
 (mobile,'watch::channel(false)','mobile outbound auth latch'),
 (quic,'pub const XENIA_QUIC_ALPN: &[u8] = QUIC_PROTOCOL_ID.as_bytes();','QUIC ALPN derived from authenticated protocol ID'),
 (quic_tests,'quic_rejects_altered_alpn_before_xenia_stream_open','QUIC ALPN downgrade regression'),
 (quic_tests,'quic_rejects_altered_stream_preface','QUIC stream-preface downgrade regression'),
]
for text, token, desc in checks:
    if token not in text: fail.append(f'missing {desc}: {token}')
if 'pub enum WsTransport' in ws: fail.append('WsTransport variants remain publicly constructible')
if 'SessionCapabilityGuard' in handshake or 'SessionCapabilityGuard' in viewer:
    fail.append('legacy boolean-style SessionCapabilityGuard remains available')
if 'capabilities_received' in mobile: fail.append('mobile viewer still uses capabilities_received boolean')
if 'WsTransport::Server' in ws_tests or 'WsTransport::Client' in ws_tests:
    fail.append('transport conformance tests bypass bounded WsTransport constructors')
# Outbound user-driven sends must be parked until surface readiness.
for rel,text in [('viewer',viewer),('mobile',mobile)]:
    if text.count('surface_ready.changed().await') < 2:
        fail.append(f'{rel}: input/clipboard tasks are not both parked on authentication latch')
# Capability transitions should consume PendingSessionSurface, preventing a second transition.
if not re.search(r'pub fn authenticate_capabilities\s*\(\s*self,', handshake):
    fail.append('PendingSessionSurface transition does not consume self')
pending_decl = handshake[handshake.find('/// Pre-capability session surface'):handshake.find('impl PendingSessionSurface')]
if '#[derive(Debug, Clone)]' in pending_decl or '#[derive(Clone' in pending_decl:
    fail.append('PendingSessionSurface must not be Clone; cloning would defeat one-shot typestate')

# Host must advertise the immutable capability contract before splitting into
# long-lived application send/receive tasks. This is intentionally a source
# contract in addition to receiver-side fail-closed checks.
cap_send = host.find('info!("sealed session capabilities sent")')
split = host.find('let (mut send_half, recv_half) = transport.split();')
if cap_send < 0 or split < 0 or cap_send >= split:
    fail.append('host capability advertisement no longer precedes application transport split')
if "carrier's native message and" not in osi:
    fail.append('OSI security-plane doc does not record V11 carrier-native WebSocket limit')
if 'browser client needs the companion `/1` subprotocol migration' not in roadmap:
    fail.append('roadmap does not disclose browser companion migration for WebSocket /1')
if 'new WebSocket(url, "xenia.transport.websocket.v1")' not in ws_migration:
    fail.append('browser WebSocket /1 companion migration is not documented')
if 'Operator/admin/consent WebSockets are separate protocols' not in ws_migration:
    fail.append('WebSocket migration doc does not preserve operator/consent protocol separation')

if fail:
    print('transport/session V11 source contract FAILED', file=sys.stderr)
    for f in fail: print(' - '+f, file=sys.stderr)
    raise SystemExit(1)
print('transport/session V11 source contract passed')
