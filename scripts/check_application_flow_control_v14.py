#!/usr/bin/env python3
"""Fail-closed source contract for Xenia application flow-control V14."""
from pathlib import Path
import json, sys
root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
fail=[]
def read(rel):
    p=root/rel
    if not p.exists():
        fail.append(f'missing {rel}'); return ''
    return p.read_text(encoding='utf-8')
inject=read('crates/xenia-inject/src/lib.rs')
frame=read('crates/xenia-peer-core/src/frame.rs')
handshake=read('crates/xenia-peer-core/src/handshake.rs')
flow=read('crates/xenia-peer-core/src/producer_flow.rs')
lib=read('crates/xenia-peer-core/src/lib.rs')
viewer=read('apps/xenia-viewer/src/main.rs')
peer=read('apps/xenia-peer/src/main.rs')
gui=read('apps/xenia-viewer/src/gui.rs')
mobile=read('crates/xenia-mobile-ffi/src/engine.rs')
ffi=read('crates/xenia-mobile-ffi/src/lib.rs')
android=read('apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/XeniaViewerActivity.kt')
session=read('apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/XeniaSession.kt')
jni=read('apps/xenia-viewer-android/src/main/cpp/xenia_jni.c')
vec_text=read('docs/security/XENIA_APPLICATION_FLOW_CONTROL_V1_VECTOR.json')
# Preserve historical enum ordering by requiring old declarations before appended ones.
positions={name: inject.find(token) for name,token in {
    'legacy_pointer':'Pointer {', 'key':'Key {', 'touch':'Touch {',
    'pointer_move':'PointerMove {', 'pointer_button':'PointerButton {'}.items()}
if any(v < 0 for v in positions.values()):
    fail.append(f'input variants missing: {positions}')
elif not (positions['legacy_pointer'] < positions['key'] < positions['touch'] < positions['pointer_move'] < positions['pointer_button']):
    fail.append(f'input variant order changed: {positions}')
checks=[
 (lib,'pub mod producer_flow;','producer-flow module export'),
 (flow,'pub enum ProducerOverflowPolicy','overflow policy enum'),
 (flow,'pub const POINTER_MOTION_V1','pointer-motion policy'),
 (flow,'capacity: 256','bounded input capacity'),
 (flow,'overflow: ProducerOverflowPolicy::Backpressure','state-transition backpressure'),
 (flow,'pub const DESKTOP_VIDEO_PRESENTATION_V1','desktop video policy'),
 (flow,'pub const MOBILE_VIDEO_PRESENTATION_V1','mobile video policy'),
 (flow,'pub const DESKTOP_AUDIO_PLAYBACK_V1','audio policy'),
 (inject,'pub const MAX_BINCODE_INPUT_EVENT_BYTES: usize = 256','input parser ceiling'),
 (frame,'pub const INPUT_EVENT_SCHEMA_VERSION: u16 = 2','input schema version'),
 (frame,'pub input_event_schema_version: u16','capability input schema field'),
 (frame,'supports_current_input_event_schema','input schema support predicate'),
 (handshake,'UnsupportedInputEventSchema','fail-closed input schema rejection'),
 (handshake,'capabilities.supports_current_input_event_schema()','capability schema enforcement'),
 (peer,'input.payload.len() > xenia_inject::MAX_BINCODE_INPUT_EVENT_BYTES','host input parser ceiling enforcement'),
 (gui,'InputEvent::PointerMove { x, y }','desktop explicit motion'),
 (gui,'InputEvent::PointerButton {','desktop explicit button'),
 (viewer,'InputEvent::PointerButton {','synthetic explicit button'),
 (mobile,'pub fn send_pointer_move','mobile explicit motion API'),
 (mobile,'pub fn send_pointer_button','mobile explicit button API'),
 (mobile,'if phase == 1','touch move classification'),
 (mobile,'self.send_stateful_input(InputEvent::Key','mobile key backpressure'),
 (ffi,'pub extern "C" fn xenia_send_pointer_move','C ABI motion API'),
 (ffi,'pub extern "C" fn xenia_send_pointer_button','C ABI button API'),
 (jni,'NativeBindings_sendPointerMove','JNI motion bridge'),
 (jni,'NativeBindings_sendPointerButton','JNI button bridge'),
 (session,'fun sendPointerMove','Kotlin motion API'),
 (session,'fun sendPointerButton','Kotlin button API'),
 (android,'session.sendPointerMove(cursorX, cursorY)','Android UI explicit motion'),
 (android,'session.sendPointerButton(cursorX, cursorY, 0, false)','Android UI explicit release'),
 (viewer,'const DESKTOP_INPUT_QUEUE_CAP: usize = 256','desktop bounded input queue'),
 (viewer,'producer_flow::INPUT_STATE_TRANSITION_V1.capacity','desktop queue/profile compile-time tie'),
 (mobile,'const INPUT_QUEUE_CAP: usize = 256','mobile bounded input queue'),
 (mobile,'producer_flow::INPUT_STATE_TRANSITION_V1.capacity','mobile queue/profile compile-time tie'),
]
for text,token,desc in checks:
    if token not in text: fail.append(f'missing {desc}: {token}')
# Current Android UI must not use the ambiguous compatibility method.
if 'session.sendPointer(' in android:
    fail.append('current Android UI still uses ambiguous sendPointer compatibility API')
try:
    vec=json.loads(vec_text)
    if vec.get('input_event_schema_version') != 2: fail.append('V14 input schema version drift')
    expected_indices={'legacy_pointer':0,'key':1,'touch':2,'pointer_move':3,'pointer_button':4}
    if vec.get('input_event_bincode_variant_indices') != expected_indices:
        fail.append('V14 input-event index vector drift')
    expected={
      'pointer-motion':(256,'drop-newest'),
      'input-state-transition':(256,'backpressure'),
      'desktop-video-presentation':(1,'coalesce-latest'),
      'mobile-video-presentation':(4,'drop-oldest'),
      'desktop-telemetry-presentation':(1,'coalesce-latest'),
      'desktop-audio-playback':(64,'drop-newest'),
      'mobile-file-transfer-events':(64,'drop-oldest'),
    }
    got={row['name']:(row['capacity'],row['overflow']) for row in vec['producer_policies']}
    if got != expected: fail.append(f'V14 producer-policy vector drift: {got}')
except Exception as exc:
    fail.append(f'unable to validate V14 vector: {exc}')
if fail:
    print('application flow-control V14 source contract FAILED',file=sys.stderr)
    for x in fail: print(' - '+x,file=sys.stderr)
    raise SystemExit(1)
print('application flow-control V14 source contract passed')
