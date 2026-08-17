#!/usr/bin/env python3
"""Fail-closed source contract for Xenia transport/session V13."""
from pathlib import Path
import hashlib, json, struct, sys
root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
fail=[]
def read(rel):
    p=root/rel
    if not p.exists():
        fail.append(f'missing {rel}'); return ''
    return p.read_text(encoding='utf-8')
transport=read('crates/xenia-peer-core/src/transport.rs')
handshake=read('crates/xenia-peer-core/src/handshake.rs')
ws=read('crates/xenia-transport-ws/src/lib.rs')
quic=read('crates/xenia-transport-quic/src/lib.rs')
peer=read('apps/xenia-peer/src/main.rs')
viewer=read('apps/xenia-viewer/src/main.rs')
gui=read('apps/xenia-viewer/src/gui.rs')
mobile=read('crates/xenia-mobile-ffi/src/engine.rs')
vector_text=read('docs/security/XENIA_TRANSPORT_PRE_SESSION_V1_VECTOR.json')
checks=[
 (transport,'TRANSPORT_PRE_SESSION_PROFILE_SCHEMA: &str = "xenia-transport-pre-session-profile-v1"','pre-session schema'),
 (transport,'pub struct TransportPreSessionProfileV1','pre-session profile type'),
 (transport,'TCP_CONNECT_TIMEOUT_MS: u64 = 10_000','TCP connect deadline'),
 (transport,'WEBSOCKET_CONNECT_UPGRADE_TIMEOUT_MS: u64 = 20_000','WS client deadline'),
 (transport,'WEBSOCKET_UPGRADE_TIMEOUT_MS: u64 = 10_000','WS server upgrade deadline'),
 (transport,'QUIC_CONNECT_TIMEOUT_MS: u64 = 15_000','QUIC connect deadline'),
 (transport,'QUIC_STREAM_OPEN_TIMEOUT_MS: u64 = 10_000','QUIC stream deadline'),
 (transport,'fn pre_session_profile(&self) -> TransportPreSessionProfileV1','live pre-session API'),
 (transport,'operation: "tcp_connect"','TCP timeout wiring'),
 (ws,'operation: "websocket_connect_upgrade"','WS client timeout wiring'),
 (ws,'operation: "websocket_server_upgrade"','WS server timeout wiring'),
 (ws,'accept_stream_with_timeout','WS upgrade regression helper'),
 (quic,'operation: "quic_connect"','QUIC connect timeout wiring'),
 (quic,'operation: "quic_accept_connection"','QUIC accept timeout wiring'),
 (quic,'operation: "quic_open_stream"','QUIC open stream timeout wiring'),
 (quic,'operation: "quic_accept_stream"','QUIC accept stream timeout wiring'),
 (handshake,'xenia-negotiated-session-context-v4','session context V4 schema'),
 (handshake,'pub struct NegotiatedSessionContextV4','session context V4 type'),
 (handshake,'pub pre_session_profile: TransportPreSessionProfileV1','pre-session transcript binding'),
 (handshake,'UnsupportedPreSessionProfile','pre-session fail-closed validation'),
 (handshake,'negotiated_session_context_hash_with_profiles','V4 profile hash API'),
 (handshake,'pub fn new_with_profiles(','V4 pending surface binding'),
 (peer,'let pre_session_profile = transport.pre_session_profile();','host live pre-session capture'),
 (peer,'negotiated_session_context_hash_with_profiles(','host V4 context binding'),
 (viewer,'let pre_session_profile = transport.pre_session_profile();','viewer live pre-session capture'),
 (viewer,'PendingSessionSurface::new_with_profiles(','viewer V4 typestate binding'),
 (mobile,'let pre_session_profile = transport.pre_session_profile();','mobile live pre-session capture'),
 (mobile,'PendingSessionSurface::new_with_profiles(','mobile V4 typestate binding'),
 (viewer,'DESKTOP_INPUT_QUEUE_CAP: usize = 256','bounded desktop input queue'),
 (viewer,'tokio::sync::mpsc::channel::<xenia_inject::InputEvent>','bounded desktop input channel'),
 (gui,'fn send_lossy_input(&self, event: InputEvent)','lossy motion overflow policy'),
 (gui,'let _ = tx.try_send(event);','lossy nonblocking send'),
 (gui,'fn send_stateful_input(&self, event: InputEvent)','stateful input policy'),
 (gui,'let _ = tx.blocking_send(event);','stateful bounded backpressure'),
]
for text,token,desc in checks:
    if token not in text: fail.append(f'missing {desc}: {token}')
if 'unbounded_channel::<xenia_inject::InputEvent>' in viewer or 'UnboundedSender<InputEvent>' in gui:
    fail.append('desktop input path still exposes an unbounded queue')
try:
    vec=json.loads(vector_text)
    schema=b'xenia-transport-pre-session-profile-v1'
    vals=[('tcp',0,10_000,0,0),('websocket',1,20_000,10_000,0),('quic',2,15_000,0,10_000)]
    for name,kind,c,u,st in vals:
        row=next(x for x in vec['profiles'] if x['kind']==name)
        raw=struct.pack('<Q',len(schema))+schema+struct.pack('<IQQQ',kind,c,u,st)
        if row['length'] != len(raw): fail.append(f'{name}: pre-session vector length drift')
        if row['bincode_v1_fixedint_little_endian_hex'] != raw.hex(): fail.append(f'{name}: bincode vector drift')
        if row['sha256_of_bincode_bytes'] != hashlib.sha256(raw).hexdigest(): fail.append(f'{name}: SHA-256 vector drift')
except Exception as exc:
    fail.append(f'unable to validate V13 vector: {exc}')
if fail:
    print('transport/session V13 source contract FAILED',file=sys.stderr)
    for x in fail: print(' - '+x,file=sys.stderr)
    raise SystemExit(1)
print('transport/session V13 source contract passed')
