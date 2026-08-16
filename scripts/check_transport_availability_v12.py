#!/usr/bin/env python3
"""Fail-closed source contract for Xenia transport/session availability V12."""
from pathlib import Path
import hashlib, json, struct, sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
fail = []

def read(rel):
    p = root / rel
    if not p.exists():
        fail.append(f'missing {rel}')
        return ''
    return p.read_text(encoding='utf-8')

transport = read('crates/xenia-peer-core/src/transport.rs')
handshake = read('crates/xenia-peer-core/src/handshake.rs')
ws = read('crates/xenia-transport-ws/src/lib.rs')
quic = read('crates/xenia-transport-quic/src/lib.rs')
peer = read('apps/xenia-peer/src/main.rs')
viewer = read('apps/xenia-viewer/src/main.rs')
mobile = read('crates/xenia-mobile-ffi/src/engine.rs')
quic_cargo = read('crates/xenia-transport-quic/Cargo.toml')
vector_text = read('docs/security/XENIA_TRANSPORT_AVAILABILITY_V1_VECTOR.json')

checks = [
    (transport, 'TRANSPORT_AVAILABILITY_PROFILE_SCHEMA: &str = "xenia-transport-availability-profile-v1"', 'availability schema'),
    (transport, 'SEND_STALL_TIMEOUT_MS: u64 = 15_000', 'send stall deadline'),
    (transport, 'RECEIVE_ENVELOPE_TIMEOUT_MS: u64 = 120_000', 'receive envelope deadline'),
    (transport, 'GRACEFUL_CLOSE_TIMEOUT_MS: u64 = 3_000', 'graceful close deadline'),
    (transport, 'pub struct TransportAvailabilityProfileV1', 'availability profile type'),
    (transport, 'pub carrier_keepalive_resets_application_idle: bool', 'control-frame idle semantics'),
    (transport, 'fn availability_profile(&self) -> TransportAvailabilityProfileV1', 'live transport availability API'),
    (transport, 'TimedOut {', 'uniform timeout error'),
    (transport, 'write_envelope_with_timeout(', 'TCP bounded send helper'),
    (transport, 'read_envelope_with_timeout(', 'TCP bounded receive helper'),
    (transport, 'partial_tcp_envelope_times_out_fail_closed', 'TCP slow/partial receive regression'),
    (transport, 'stalled_tcp_send_times_out_fail_closed', 'TCP backpressure regression'),
    (handshake, 'xenia-negotiated-session-context-v3', 'session context V3 schema'),
    (handshake, 'pub struct NegotiatedSessionContextV3', 'session context V3 type'),
    (handshake, 'pub availability_profile: TransportAvailabilityProfileV1', 'availability transcript binding'),
    (handshake, 'UnsupportedAvailabilityProfile', 'availability fail-closed validation'),
    (handshake, 'negotiated_session_context_hash_with_availability', 'explicit availability context hash'),
    (handshake, 'pub fn new_with_availability(', 'pending-surface availability binding'),
    (ws, 'tokio::time::timeout(timeout, async {', 'WebSocket receive absolute deadline'),
    (ws, 'RECEIVE_ENVELOPE_TIMEOUT_MS', 'WebSocket receive policy wiring'),
    (ws, 'ping_pong_does_not_extend_application_receive_deadline', 'WebSocket keepalive deadline regression'),
    (ws, 'SEND_STALL_TIMEOUT_MS', 'WebSocket send policy wiring'),
    (quic, 'RECEIVE_ENVELOPE_TIMEOUT_MS', 'QUIC receive policy wiring'),
    (quic, 'SEND_STALL_TIMEOUT_MS', 'QUIC send policy wiring'),
    (quic_cargo, 'tokio.workspace = true', 'QUIC runtime timeout dependency'),
    (peer, 'let availability_profile = transport.availability_profile();', 'host live availability capture'),
    (peer, 'negotiated_session_context_hash_with_profiles(', 'host current context binding'),
    (viewer, 'let availability_profile = transport.availability_profile();', 'viewer live availability capture'),
    (viewer, 'PendingSessionSurface::new_with_profiles(', 'viewer current typestate binding'),
    (mobile, 'let availability_profile = transport.availability_profile();', 'mobile live availability capture'),
    (mobile, 'PendingSessionSurface::new_with_profiles(', 'mobile current typestate binding'),
    (peer, 'Duration::from_millis(GRACEFUL_CLOSE_TIMEOUT_MS)', 'profile-derived graceful QUIC close'),
]
for text, token, desc in checks:
    if token not in text:
        fail.append(f'missing {desc}: {token}')

# WebSocket ping/pong must be handled inside one outer timeout, not by applying a
# fresh timeout to each control frame.
recv_start = ws.find('async fn recv_envelope_with_timeout(')
recv_end = ws.find('/// Split into independently-owned', recv_start)
recv_block = ws[recv_start:recv_end]
if recv_start < 0 or recv_block.count('tokio::time::timeout') != 1 or 'loop {' not in recv_block:
    fail.append('WebSocket control-frame loop is not covered by one absolute envelope deadline')

# Current transport profiles themselves remain V10/V11 carrier identities; V12
# adds a separately authenticated availability profile rather than silently
# rewriting framing/ALPN/subprotocol identities.
for token in [
    'TCP_PROTOCOL_ID: &str = "xenia/transport/tcp/0"',
    'WEBSOCKET_PROTOCOL_ID: &str = "xenia/transport/websocket/1"',
    'QUIC_PROTOCOL_ID: &str = "xenia/transport/quic/0"',
]:
    if token not in transport:
        fail.append(f'carrier identity drifted during availability-only V12: {token}')


# Validate the language-neutral bincode compatibility fixture independently of
# the Rust source constants. This is deliberately SHA-256 fixture integrity;
# runtime profile_hash remains BLAKE3-256.
try:
    vector = json.loads(vector_text)
    schema = b'xenia-transport-availability-profile-v1'
    for index, name in enumerate(('tcp', 'websocket', 'quic')):
        row = next(p for p in vector['profiles'] if p['kind'] == name)
        raw = (
            struct.pack('<Q', len(schema)) + schema + struct.pack('<I', index)
            + struct.pack('<QQQQ', 15_000, 120_000, 3_000, 0) + b'\x00'
        )
        if row['bincode_v1_fixedint_little_endian_hex'] != raw.hex():
            fail.append(f'{name}: availability fixture bincode bytes drift')
        if row['sha256_of_bincode_bytes'] != hashlib.sha256(raw).hexdigest():
            fail.append(f'{name}: availability fixture SHA-256 drift')
except Exception as exc:
    fail.append(f'unable to validate V12 availability vector: {exc}')

if fail:
    print('transport/session V12 availability source contract FAILED', file=sys.stderr)
    for item in fail:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)
print('transport/session V12 availability source contract passed')
