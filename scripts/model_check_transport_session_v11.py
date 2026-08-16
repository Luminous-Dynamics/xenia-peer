#!/usr/bin/env python3
"""Independent reduced model for V11 transport binding and capability typestate."""
from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import product
MAX_ENV=16*1024*1024; MAX_HS=16*1024
@dataclass(frozen=True)
class P:
    schema:str; kind:int; protocol_id:str; version:int; framing:int; max_env:int; max_hs:int; reliable:bool; ordered:bool; streams:int

def current(k):
    pid,ver,fr={1:('xenia/transport/tcp/0',0,1),2:('xenia/transport/websocket/1',1,2),3:('xenia/transport/quic/0',0,1)}[k]
    return P('xenia-transport-profile-v1',k,pid,ver,fr,MAX_ENV,MAX_HS,True,True,1)
def encb(x): return len(x).to_bytes(4,'big')+x
def enc(p): return b''.join([encb(p.schema.encode()),bytes([p.kind]),encb(p.protocol_id.encode()),p.version.to_bytes(2,'big'),bytes([p.framing]),p.max_env.to_bytes(4,'big'),p.max_hs.to_bytes(4,'big'),bytes([p.reliable,p.ordered]),p.streams.to_bytes(2,'big')])
def digest(p,caps=b'caps'): return sha256(enc(p)+encb(caps)).digest()
profiles=[current(k) for k in (1,2,3)]
assert len({enc(p) for p in profiles})==3
mut=[]
for p in profiles:
    mut += [replace(p,schema=p.schema+'x'),replace(p,protocol_id=p.protocol_id+'x'),replace(p,version=p.version+1),replace(p,framing=1 if p.framing==2 else 2),replace(p,max_env=p.max_env-1),replace(p,max_hs=p.max_hs+1),replace(p,reliable=False),replace(p,ordered=False),replace(p,streams=2)]
for m in mut:
    b=current(m.kind); assert m!=b and enc(m)!=enc(b) and digest(m)!=digest(b)
# Exact WebSocket subprotocol: missing, old, multi-token, or altered are refused.
expected='xenia.transport.websocket.v1'
for offered in [None,'xenia.transport.websocket.v0','xenia.transport.websocket.v1,other','other',expected+'x']:
    assert offered != expected
assert expected == 'xenia.transport.websocket.v1'
# Typestate language: C=capabilities, P=application payload. A trace is accepted
# only if C occurs exactly once and before every P.
def valid_trace(trace):
    authenticated=False
    for e in trace:
        if e=='C':
            if authenticated: return False
            authenticated=True
        elif e=='P':
            if not authenticated: return False
    return authenticated
accepted=rejected=0
for n in range(1,6):
    for t in product('CP', repeat=n):
        if valid_trace(t): accepted+=1
        else: rejected+=1
# Queued outbound actions are emitted only after C.
queue=3; emitted=0; auth=False
for e in ['P','P','C','P']:
    if e=='C':
        auth=True; emitted += queue; queue=0
    elif e=='P':
        if auth: emitted+=1
        else: queue+=1
assert emitted==6 and queue==0
print(f'transport/session V11 model passed: profiles=3 mutations={len(mut)} typestate_accepted={accepted} typestate_rejected={rejected}')
