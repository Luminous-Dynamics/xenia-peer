#!/usr/bin/env python3
"""Fail-closed source contract for Xenia's V10 L4-L7 session profile.

This is intentionally a source-shape check for runners without Rust. It does
not replace cargo check/test. It verifies that transport semantics, the
negotiated session context, and concrete transport implementations stay wired
together rather than drifting independently.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
failures: list[str] = []


def read(rel: str) -> str:
    p = root / rel
    if not p.exists():
        failures.append(f"missing {rel}")
        return ""
    return p.read_text(encoding="utf-8")


transport = read("crates/xenia-peer-core/src/transport.rs")
handshake = read("crates/xenia-peer-core/src/handshake.rs")
quic = read("crates/xenia-transport-quic/src/lib.rs")
ws = read("crates/xenia-transport-ws/src/lib.rs")
peer = read("apps/xenia-peer/src/main.rs")
viewer = read("apps/xenia-viewer/src/main.rs")
mobile = read("crates/xenia-mobile-ffi/src/engine.rs")
core_lib = read("crates/xenia-peer-core/src/lib.rs")

required_transport_tokens = [
    'TRANSPORT_PROFILE_SCHEMA: &str = "xenia-transport-profile-v1"',
    'TCP_PROTOCOL_ID: &str = "xenia/transport/tcp/0"',
    'WEBSOCKET_PROTOCOL_ID: &str = "xenia/transport/websocket/0"',
    'QUIC_PROTOCOL_ID: &str = "xenia/transport/quic/0"',
    'MAX_HANDSHAKE_ENVELOPE_BYTES: u32 = 16 * 1024',
    'pub struct TransportProfileV1',
    'pub max_envelope_bytes: u32',
    'pub max_handshake_envelope_bytes: u32',
    'pub reliable: bool',
    'pub ordered: bool',
    'pub logical_streams: u16',
    'fn transport_profile(&self) -> TransportProfileV1;',
    'self == &Self::current(self.kind)',
]
for token in required_transport_tokens:
    if token not in transport:
        failures.append(f"transport contract missing: {token}")

required_handshake_tokens = [
    'xenia-negotiated-session-context-v2',
    'xenia-wire-sealed-envelope-v1',
    'pub struct NegotiatedSessionContextV2',
    'pub transport_profile: TransportProfileV1',
    'pub handshake_policy_profile: String',
    'pub handshake_transcript_schema: String',
    'pub session_key_schedule_schema: String',
    'if !transport_profile.is_current_supported_profile()',
    'ensure_handshake_message_size(bytes.len())?',
    'recv_handshake_envelope(transport).await?',
    'send_handshake_envelope(transport, &response_bytes).await?',
]
for token in required_handshake_tokens:
    if token not in handshake:
        failures.append(f"session-context contract missing: {token}")

# The QUIC ALPN must be derived from the same protocol identifier that is
# transcript-bound. A duplicated byte literal is exactly the drift V10 removes.
if 'pub const XENIA_QUIC_ALPN: &[u8] = QUIC_PROTOCOL_ID.as_bytes();' not in quic:
    failures.append("QUIC ALPN is not derived from QUIC_PROTOCOL_ID")

# Every concrete/erased Transport implementation must expose the actual profile.
for rel, text in [
    ("crates/xenia-peer-core/src/transport.rs", transport),
    ("crates/xenia-transport-quic/src/lib.rs", quic),
    ("crates/xenia-transport-ws/src/lib.rs", ws),
    ("apps/xenia-peer/src/main.rs", peer),
    ("apps/xenia-viewer/src/main.rs", viewer),
]:
    impl_count = len(re.findall(r"impl\s+Transport\s+for\s+", text))
    profile_count = len(re.findall(r"fn\s+transport_profile\s*\([^)]*\)\s*->[^;{]+\{", text))
    if impl_count != profile_count:
        failures.append(
            f"{rel}: Transport impl/profile mismatch: impls={impl_count}, profiles={profile_count}"
        )

# Host, desktop viewer, and mobile viewer must derive the authenticated context
# from the actual Transport object, not a manually selected carrier enum.
if 'let transport_profile = transport.transport_profile();' not in peer:
    failures.append("daemon does not capture actual transport profile")
if 'negotiated_session_context_hash(\n            &transport_profile,' not in peer:
    failures.append("daemon context hash is not built from actual transport profile")
if viewer.count('let transport_profile = transport.transport_profile();') < 2:
    failures.append("viewer paths do not capture actual transport profile")
if 'capability_guard.accept(&transport_profile, &capabilities)' not in viewer:
    failures.append("viewer capability guard is not bound to actual transport profile")
if 'let transport_profile = transport.transport_profile();' not in mobile:
    failures.append("mobile viewer does not capture actual TCP transport profile")
if 'negotiated_session_context_hash(&transport_profile, capabilities.clone())' not in mobile:
    failures.append("mobile context check is not bound to actual transport profile")

# Keep the diagnostic xenia-wire constant honest with the root dependency.
try:
    with (root / "Cargo.toml").open("rb") as f:
        cargo = tomllib.load(f)
    req = cargo["workspace"]["dependencies"]["xenia-wire"]
    if isinstance(req, dict):
        req = req.get("version")
    m = re.search(r'XENIA_WIRE_VERSION:\s*&str\s*=\s*"([^"]+)"', core_lib)
    if not m:
        failures.append("XENIA_WIRE_VERSION constant missing")
    elif m.group(1) != req:
        failures.append(
            f"XENIA_WIRE_VERSION drift: source={m.group(1)!r} Cargo.toml={req!r}"
        )
except Exception as exc:  # source guard should fail closed
    failures.append(f"unable to compare xenia-wire dependency/version constant: {exc}")

if failures:
    print("transport/session V10 source contract FAILED", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("transport/session V10 source contract passed")
