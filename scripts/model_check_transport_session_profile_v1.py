#!/usr/bin/env python3
"""Reduced model for Xenia transport/session downgrade binding.

The Rust implementation uses bincode+BLAKE3. This model deliberately uses a
small independent canonical encoding+SHA-256 so it can test the *invariant*
without duplicating the implementation: every security-relevant transport
field is committed, only exact current profiles are accepted, and carrier
profiles are unambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256

MAX_ENVELOPE = 16 * 1024 * 1024
MAX_HANDSHAKE = 16 * 1024


@dataclass(frozen=True)
class Profile:
    schema: str
    kind: int
    protocol_id: str
    protocol_version: int
    framing: int
    max_envelope: int
    max_handshake: int
    reliable: bool
    ordered: bool
    logical_streams: int


def current(kind: int) -> Profile:
    protocol_id, framing = {
        1: ("xenia/transport/tcp/0", 1),
        2: ("xenia/transport/websocket/0", 2),
        3: ("xenia/transport/quic/0", 1),
    }[kind]
    return Profile(
        "xenia-transport-profile-v1",
        kind,
        protocol_id,
        0,
        framing,
        MAX_ENVELOPE,
        MAX_HANDSHAKE,
        True,
        True,
        1,
    )


def enc_bytes(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def canonical_profile(p: Profile) -> bytes:
    return b"".join(
        [
            enc_bytes(p.schema.encode()),
            p.kind.to_bytes(1, "big"),
            enc_bytes(p.protocol_id.encode()),
            p.protocol_version.to_bytes(2, "big"),
            p.framing.to_bytes(1, "big"),
            p.max_envelope.to_bytes(4, "big"),
            p.max_handshake.to_bytes(4, "big"),
            bytes([p.reliable, p.ordered]),
            p.logical_streams.to_bytes(2, "big"),
        ]
    )


def context_digest(p: Profile, capabilities: bytes = b"capabilities-v1") -> bytes:
    body = b"".join(
        [
            enc_bytes(b"xenia-negotiated-session-context-v2"),
            enc_bytes(canonical_profile(p)),
            enc_bytes(b"xenia-wire-sealed-envelope-v1"),
            enc_bytes(b"hybrid-pq-transcript-v1"),
            enc_bytes(b"xenia-handshake-transcript-v1"),
            enc_bytes(b"xenia-session-key-schedule-v1"),
            enc_bytes(capabilities),
        ]
    )
    return sha256(body).digest()


profiles = [current(k) for k in (1, 2, 3)]
assert len({canonical_profile(p) for p in profiles}) == 3
assert len({context_digest(p) for p in profiles}) == 3
assert MAX_HANDSHAKE < MAX_ENVELOPE

mutations = []
for p in profiles:
    mutations.extend(
        [
            replace(p, schema=p.schema + "-downgrade"),
            replace(p, protocol_id=p.protocol_id + "-other"),
            replace(p, protocol_version=1),
            replace(p, framing=2 if p.framing == 1 else 1),
            replace(p, max_envelope=p.max_envelope - 1),
            replace(p, max_handshake=p.max_handshake + 1),
            replace(p, reliable=False),
            replace(p, ordered=False),
            replace(p, logical_streams=2),
        ]
    )

for mutated in mutations:
    base = current(mutated.kind)
    assert mutated != base, mutated
    assert canonical_profile(mutated) != canonical_profile(base), mutated
    assert context_digest(mutated) != context_digest(base), mutated

# A capability change must also alter the authenticated context independently of
# the transport profile.
for p in profiles:
    assert context_digest(p, b"caps-a") != context_digest(p, b"caps-b")

print(
    "transport/session profile model passed: "
    f"profiles={len(profiles)} field_mutations={len(mutations)} "
    f"capability_mutations={len(profiles)}"
)
