#!/usr/bin/env python3
"""Independent reduced model for V13 pre-session deadlines and fault closure."""
from dataclasses import dataclass, replace
from hashlib import sha256

TCP_CONNECT=10_000
WS_CONNECT_UPGRADE=20_000
WS_UPGRADE=10_000
QUIC_CONNECT=15_000
QUIC_STREAM=10_000

@dataclass(frozen=True)
class P:
    schema: str
    kind: int
    connect_ms: int
    upgrade_ms: int
    stream_ms: int

def current(k:int)->P:
    if k == 0:
        vals=(TCP_CONNECT,0,0)
    elif k == 1:
        vals=(WS_CONNECT_UPGRADE,WS_UPGRADE,0)
    elif k == 2:
        vals=(QUIC_CONNECT,0,QUIC_STREAM)
    else:
        raise ValueError(k)
    return P('xenia-transport-pre-session-profile-v1', k, *vals)

def enc(p:P)->bytes:
    b=p.schema.encode()
    return (len(b).to_bytes(2,'big')+b+bytes([p.kind])+p.connect_ms.to_bytes(8,'big')+
            p.upgrade_ms.to_bytes(8,'big')+p.stream_ms.to_bytes(8,'big'))

def ctx(p:P)->bytes:
    return sha256(b'carrier'+enc(p)+b'availability'+b'caps').digest()

mutations=0
for kind in (0,1,2):
    base=current(kind)
    variants=[
        replace(base,schema=base.schema+'x'),
        replace(base,connect_ms=base.connect_ms+1),
        replace(base,upgrade_ms=base.upgrade_ms+1),
        replace(base,stream_ms=base.stream_ms+1),
    ]
    for changed in variants:
        mutations += 1
        assert changed != base
        assert enc(changed) != enc(base)
        assert ctx(changed) != ctx(base)
assert len({ctx(current(k)) for k in (0,1,2)}) == 3

# Deadline boundaries are fail closed.
def within(elapsed:int, budget:int)->bool:
    return budget == 0 or elapsed <= budget
for p in map(current,(0,1,2)):
    if p.connect_ms:
        assert within(p.connect_ms,p.connect_ms)
        assert not within(p.connect_ms+1,p.connect_ms)
    if p.upgrade_ms:
        assert within(p.upgrade_ms,p.upgrade_ms)
        assert not within(p.upgrade_ms+1,p.upgrade_ms)
    if p.stream_ms:
        assert within(p.stream_ms,p.stream_ms)
        assert not within(p.stream_ms+1,p.stream_ms)

# Reduced session state model: transport close/reset during capability auth or
# rekey is terminal. There is no transition that resumes a partially consumed
# carrier/session after a fatal transport error.
PRE, HANDSHAKE, CAPS, AUTH, REKEY, CLOSED = range(6)
def step(state,event):
    if state == CLOSED:
        return CLOSED
    if event in ('close','reset','timeout'):
        return CLOSED
    table={
        (PRE,'carrier'):HANDSHAKE,
        (HANDSHAKE,'handshake_ok'):CAPS,
        (CAPS,'capabilities_ok'):AUTH,
        (AUTH,'rekey_start'):REKEY,
        (REKEY,'rekey_ok'):AUTH,
    }
    return table.get((state,event), state)
for vulnerable in (HANDSHAKE,CAPS,AUTH,REKEY):
    for fatal in ('close','reset','timeout'):
        assert step(vulnerable,fatal) == CLOSED
        assert step(CLOSED,'handshake_ok') == CLOSED
        assert step(CLOSED,'capabilities_ok') == CLOSED
        assert step(CLOSED,'rekey_ok') == CLOSED

# Desktop input producer policy: lossy pointer-motion samples may be dropped on
# a full bounded queue; state transitions must backpressure rather than silently
# disappear. This is a semantic model, not runtime execution.
CAP=256
queue=[]
for i in range(CAP):
    queue.append(('motion',i))
# a full motion sample is allowed to drop
assert len(queue) == CAP
# a state transition is not modeled as dropped; it must wait until one slot is
# consumed, then become visible in FIFO order.
queue.pop(0)
queue.append(('key_up',7))
assert queue[-1] == ('key_up',7)

print(f'transport/session V13 model passed: profiles=3 mutations={mutations} fatal_state_cases=12 queue_cap={CAP}')
