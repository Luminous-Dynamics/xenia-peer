#!/usr/bin/env python3
"""Executable reference/adversarial model for XZKENV01.

This does not substitute for Rust tests. It independently checks the intended
length-prefix and canonical framing rules on no-toolchain review runners.
"""
from __future__ import annotations
import struct
import hashlib
MAGIC=b'XZKENV01'; MAX_PROOF=512*1024; MAX_SIG=16*1024; MAX_AUTH=4; MAX_FRAME=1024*1024

def text(s:bytes):
    assert len(s)<=64
    return bytes([len(s)])+s

def sample(proof_len=64,sig_len=96):
    b=bytearray(MAGIC)
    b+=struct.pack('<I',3)+text(b'XENIA')+text(b'Access')+text(b'RangeCredential')+struct.pack('<I',3)
    b+=struct.pack('<H',1)+bytes([0x11])*32+bytes([0x22])*32+struct.pack('<Q',1800000000)
    b+=bytes([0x33])*32+bytes([0x44])*32+struct.pack('<I',proof_len)+bytes([0x55])*proof_len
    b+=bytes([0x88])*32+struct.pack('<H',1)+struct.pack('<H',2)+bytes([0x66])*32
    b+=struct.pack('<I',sig_len)+bytes([0x77])*sig_len
    return bytes(b)

class Reject(Exception): pass
class Cur:
    def __init__(self,b): self.b=b; self.i=0
    def rem(self): return len(self.b)-self.i
    def take(self,n):
        if n<0 or self.i+n>len(self.b): raise Reject('truncated')
        v=self.b[self.i:self.i+n];self.i+=n;return v
    def u8(self): return self.take(1)[0]
    def u16(self): return struct.unpack('<H',self.take(2))[0]
    def u32(self): return struct.unpack('<I',self.take(4))[0]
    def u64(self): return struct.unpack('<Q',self.take(8))[0]
    def blob(self,limit):
        n=self.u32()
        if n>limit: raise Reject('limit')
        if n>self.rem(): raise Reject('declared beyond frame')
        return self.take(n)

def decode(b):
    if not b or len(b)>MAX_FRAME: raise Reject('frame')
    c=Cur(b)
    if c.take(8)!=MAGIC: raise Reject('magic')
    version=c.u32()
    parts=[]
    for _ in range(3):
        n=c.u8()
        if n>64: raise Reject('text limit')
        raw=c.take(n); raw.decode('utf-8'); parts.append(raw)
    statement_version=c.u32(); proof_system=c.u16()
    if statement_version==0 or proof_system==0: raise Reject('reserved')
    verifier=c.take(32); params=c.take(32); ts=c.u64(); nonce=c.take(32); inputs=c.take(32)
    proof=c.blob(MAX_PROOF); ext=c.take(32); count=c.u16()
    if count>MAX_AUTH: raise Reject('auth count')
    if count*38>c.rem(): raise Reject('auth min frame')
    auth=[]
    for _ in range(count):
        suite=c.u16()
        if suite==0: raise Reject('suite')
        key=c.take(32); sig=c.blob(MAX_SIG); auth.append((suite,key,sig))
    if c.rem(): raise Reject('trailing')
    return (version,parts,statement_version,proof_system,verifier,params,ts,nonce,inputs,proof,ext,auth)

good=sample(); expected=decode(good)
assert len(good)==419
assert hashlib.sha256(good).hexdigest()=='beffde62e2308699923c6354ab7a5e043e9be824558431b175670eb816358d50'
# Every strict prefix must reject; the full frame must accept.
for end in range(len(good)):
    try: decode(good[:end]); raise AssertionError(f'truncation accepted at {end}')
    except Reject: pass
assert decode(good)==expected
for n in (1,2,8,64):
    try: decode(good+b'X'*n); raise AssertionError('trailing bytes accepted')
    except Reject: pass
# Mutate proof length to huge without providing bytes.
probe=bytearray(good)
# Locate the unique LE 64 proof length immediately followed by 0x55 bytes.
needle=struct.pack('<I',64)+bytes([0x55])*16
idx=probe.index(needle)
probe[idx:idx+4]=struct.pack('<I',MAX_PROOF+1)
try: decode(bytes(probe)); raise AssertionError('oversized proof accepted')
except Reject: pass
# Signature declared length larger than policy.
probe=bytearray(good); needle=struct.pack('<I',96)+bytes([0x77])*16; idx=probe.index(needle)
probe[idx:idx+4]=struct.pack('<I',MAX_SIG+1)
try: decode(bytes(probe)); raise AssertionError('oversized signature accepted')
except Reject: pass
print(f'zk-binary-codec-v1 model: PASS ({len(good)}-byte canonical fixture; {len(good)} truncations rejected)')
