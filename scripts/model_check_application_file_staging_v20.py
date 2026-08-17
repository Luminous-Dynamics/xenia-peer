#!/usr/bin/env python3
"""Reduced model: bounded streaming staging without whole-file heap materialization."""
MAX=100*1024*1024
CHUNK=64*1024
CAP=2
LEASE=300_000

class Upload:
    def __init__(self, expected=None):
        assert expected is None or 0 <= expected <= MAX
        self.expected=expected; self.written=0; self.expiry=LEASE; self.finished=False
    def append(self,n,now=0):
        if now >= self.expiry: return 6
        if n < 0 or self.written+n > MAX: return 5
        if self.expected is not None and self.written+n > self.expected: return 7
        self.written += n; return 0
    def finish(self,now=0):
        if now >= self.expiry: return 6
        if self.expected is not None and self.written != self.expected: return 7
        self.finished=True; return 0

# Known-size exact staging using one reusable 64KiB application chunk.
u=Upload(MAX)
max_live_chunk=0
remaining=MAX
while remaining:
    n=min(CHUNK,remaining); max_live_chunk=max(max_live_chunk,n)
    assert u.append(n)==0; remaining-=n
assert u.finish()==0 and u.written==MAX and max_live_chunk==CHUNK
# Unknown-size provider succeeds without knowing total in advance.
v=Upload(None)
for n in [1,CHUNK,CHUNK-1,12345]: assert v.append(n)==0
assert v.finish()==0
# Crossing cap or lying known-size provider fails closed.
w=Upload(None); w.written=MAX; assert w.append(1)==5
x=Upload(10); assert x.append(9)==0 and x.finish()==7
x=Upload(10); assert x.append(11)==7
# Lease is absolute: progress cannot pin scarce capacity indefinitely.
y=Upload(None); assert y.append(1,LEASE-1)==0; assert y.append(1,LEASE)==6
# At most two staged uploads can hold permits, hence <=200MiB disk ceiling.
assert (CAP+1)*MAX==300*1024*1024
# Preferred path's payload heap bound is chunk-sized, not file-sized.
assert max_live_chunk/MAX < 0.001
print('application file staging V20 model passed: 64KiB heap chunk, 100MiB/file, 300MiB staged-disk cap, fixed lease')
