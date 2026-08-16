#!/usr/bin/env python3
"""Independent reduced model for Xenia application flow-control V14."""
from collections import deque

# Historical bincode enum positions must remain stable; V14 appends explicit
# pointer semantics instead of reordering the first three deployed variants.
indices={'legacy_pointer':0,'key':1,'touch':2,'pointer_move':3,'pointer_button':4}
assert indices['legacy_pointer']==0 and indices['key']==1 and indices['touch']==2
assert indices['pointer_move'] > indices['touch']
assert indices['pointer_button'] > indices['pointer_move']

CAP=256
# Lossy pointer motion: once full, newest motion may be dropped and memory stays bounded.
q=deque(("motion",i) for i in range(CAP))
for i in range(1000):
    if len(q) < CAP:
        q.append(("motion",CAP+i))
assert len(q)==CAP

# Stateful transition: never model silent loss. Producer waits until one slot is
# available, then transition becomes visible in FIFO order.
q.popleft()
q.append(("key_release",42))
assert len(q)==CAP and q[-1]==("key_release",42)

# Touch semantics: phase 1 is motion/lossy; every other defined phase is stateful.
def touch_policy(phase):
    return 'drop-newest' if phase == 1 else 'backpressure'
assert touch_policy(0)=='backpressure'
assert touch_policy(1)=='drop-newest'
assert touch_policy(2)=='backpressure'
assert touch_policy(3)=='backpressure'

# Latest-value slots: arbitrary producer volume leaves exactly one newest item.
latest=None
for i in range(10_000): latest=i
assert latest==9_999

# Mobile video: drop-oldest bounded history preserves newest four values.
video=deque(maxlen=4)
for i in range(100): video.append(i)
assert list(video)==[96,97,98,99]

# Drop-newest audio queue remains bounded and preserves already queued order.
audio=deque(range(64))
for i in range(1000,1100):
    if len(audio) < 64: audio.append(i)
assert len(audio)==64 and list(audio)==list(range(64))

print('application flow-control V14 model passed: variants=5 input_cap=256 latest_slot=1 mobile_video_cap=4 audio_cap=64')
