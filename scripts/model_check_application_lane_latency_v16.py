#!/usr/bin/env python3
"""Independent reduced model for V16 lane-latency/admission semantics."""
# Audio viewer application buffering at max wire frame duration.
frame_ms=20
ingress_frames=4
jitter_frames=6
device_ms=80
viewer_buffer_ms=(ingress_frames+jitter_frames)*frame_ms+device_ms
assert viewer_buffer_ms == 280
assert viewer_buffer_ms < 1000
# Historical 64-frame ingress alone was 1.28 seconds at the same max duration.
assert 64*frame_ms == 1280
# Host capture FIFO is sample-rate/channel-derived and exactly 100 ms.
def samples(rate,channels,budget_ms):
    return rate*max(1,channels)*budget_ms//1000
assert samples(48000,2,100)==9600
assert samples(48000,1,100)==4800
assert samples(24000,2,100)==4800
# Video: no backlog (>1 active frame), stale encode drops, send timeout is fatal.
def video_outcome(capture_encode_ms, send_ms):
    if capture_encode_ms > 500: return 'drop-stale'
    if send_ms > 1000: return 'fail-session'
    return 'sent'
video_cases=0
for ce in (0,499,500,501,5000):
    for send in (0,999,1000,1001,15000):
        outcome=video_outcome(ce,send)
        if ce>500: assert outcome=='drop-stale'
        elif send>1000: assert outcome=='fail-session'
        else: assert outcome=='sent'
        video_cases+=1
# Mobile file admission: exact byte boundary, finite queue, advisory preflight.
MAX=100*1024*1024
assert MAX==104857600
assert MAX <= MAX and MAX+1 > MAX
capacity=2
q=[]
def preflight(size):
    if size>MAX: return 'too-large'
    if len(q)>=capacity: return 'queue-full'
    return 'ok'
assert preflight(MAX)=='ok'
assert preflight(MAX+1)=='too-large'
q.extend(['a','b'])
assert preflight(1)=='queue-full'
# A preflight is not a reservation: two callers can both observe capacity before
# either commits, so final enqueue MUST still be fallible/rechecked.
q.clear()
a=preflight(1); b=preflight(1)
assert a==b=='ok'
q.extend(['winner','other'])
assert preflight(1)=='queue-full'
print('application lane latency V16 model passed: '
      f'viewer_audio_buffer_ms={viewer_buffer_ms} video_cases={video_cases} '
      f'file_max_bytes={MAX} queue_cap={capacity}')
