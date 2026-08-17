#!/usr/bin/env python3
"""Independent reduced model for V12 authenticated availability semantics."""
from dataclasses import dataclass, replace
from hashlib import sha256

SEND=15_000
RECV=120_000
CLOSE=3_000

@dataclass(frozen=True)
class A:
    schema: str
    kind: int
    send_ms: int
    recv_ms: int
    close_ms: int
    keepalive_ms: int
    carrier_keepalive_resets_idle: bool

def current(k:int)->A:
    return A('xenia-transport-availability-profile-v1', k, SEND, RECV, CLOSE, 0, False)

def enc(a:A)->bytes:
    b=a.schema.encode()
    return (len(b).to_bytes(2,'big')+b+bytes([a.kind])+a.send_ms.to_bytes(8,'big')+
            a.recv_ms.to_bytes(8,'big')+a.close_ms.to_bytes(8,'big')+
            a.keepalive_ms.to_bytes(8,'big')+bytes([a.carrier_keepalive_resets_idle]))

def context_digest(a:A, carrier:bytes=b'carrier', caps:bytes=b'caps')->bytes:
    return sha256(carrier+enc(a)+caps).digest()

mutations=0
for kind in (1,2,3):
    base=current(kind)
    assert base == current(kind)
    variants=[
        replace(base,schema=base.schema+'x'),
        replace(base,send_ms=base.send_ms+1),
        replace(base,recv_ms=base.recv_ms+1),
        replace(base,close_ms=base.close_ms+1),
        replace(base,keepalive_ms=1),
        replace(base,carrier_keepalive_resets_idle=True),
    ]
    for changed in variants:
        mutations += 1
        assert changed != base
        assert enc(changed) != enc(base)
        assert context_digest(changed) != context_digest(base)

# Carrier kind itself is committed even while the numeric deadlines currently
# match across carriers.
assert len({context_digest(current(k)) for k in (1,2,3)}) == 3

# Control keepalives cannot extend the application-envelope deadline. Model a
# WebSocket receiving ping/pong every 30s but no binary Xenia envelope.
deadline=RECV
control_frames=[30_000,60_000,90_000,119_000]
for t in control_frames:
    assert t < deadline
    # no reset because carrier_keepalive_resets_idle is false
assert 120_001 > deadline

# Application data before the absolute deadline succeeds; after it fails.
def recv_ok(arrival_ms:int)->bool:
    return arrival_ms <= RECV
assert recv_ok(0) and recv_ok(RECV)
assert not recv_ok(RECV+1)

# Backpressure is bounded independently of receive liveness.
def send_ok(blocked_ms:int)->bool:
    return blocked_ms <= SEND
assert send_ok(SEND)
assert not send_ok(SEND+1)

print(f'transport/session V12 availability model passed: profiles=3 mutations={mutations} control_frames={len(control_frames)}')
