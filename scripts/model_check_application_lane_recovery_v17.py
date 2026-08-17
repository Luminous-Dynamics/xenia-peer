#!/usr/bin/env python3
"""Independent reduced model for V17 freshness recovery and file reservations."""
from collections import deque

# Desktop audio: same four-frame bound, but drop-oldest converges to newest data.
CAP=4
q=deque()
dropped=0
for seq in range(32):
    if len(q)>=CAP:
        q.popleft(); dropped+=1
    q.append(seq)
assert list(q)==[28,29,30,31]
assert dropped==28
assert len(q)<=CAP
assert CAP*20==80

# Lane counters are monotonic evidence only.
counters={k:0 for k in ('dropped_superseded','rejected','stale','fatal_deadline')}
for key in counters:
    counters[key]+=1
assert all(v==1 for v in counters.values())

# Host video semantics remain: stale work drops before send; send deadline is fatal.
def video(capture_encode_ms, send_ms):
    if capture_encode_ms>500: return 'drop-stale'
    if send_ms>1000: return 'fail-session'
    return 'sent'
assert video(501,0)=='drop-stale'
assert video(500,1001)=='fail-session'
assert video(500,1000)=='sent'

# Two-slot reservation model. Reserving consumes capacity before payload copy.
CAP=2
slots=[None]*CAP
next_token=1

def reserve(length):
    global next_token
    if length>100*1024*1024: return ('too-large',0)
    try: i=slots.index(None)
    except ValueError: return ('full',0)
    tok=next_token; next_token+=1
    slots[i]=(tok,length)
    return ('ok',tok)

def cancel(tok):
    for i,item in enumerate(slots):
        if item and item[0]==tok:
            slots[i]=None; return True
    return False

def commit(tok,length):
    for i,item in enumerate(slots):
        if item and item[0]==tok:
            slots[i]=None
            return 'ok' if item[1]==length else 'size-mismatch'
    return 'invalid'

s,a=reserve(10); assert s=='ok'
s,b=reserve(20); assert s=='ok'
assert reserve(1)[0]=='full'
assert cancel(a)
s,c=reserve(30); assert s=='ok'
assert commit(c,31)=='size-mismatch'  # reservation released fail-closed
s,d=reserve(40); assert s=='ok'
assert commit(d,40)=='ok'
assert commit(d,40)=='invalid'
assert reserve(100*1024*1024+1)[0]=='too-large'
print(f'application lane recovery V17 model passed: audio_dropped={dropped} queue={list(q)} reservation_cap={CAP}')
