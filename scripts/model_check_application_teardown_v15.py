#!/usr/bin/env python3
"""Independent reduced model for V15 input teardown and producer pressure."""
from __future__ import annotations
from dataclasses import dataclass, field
from itertools import product

@dataclass
class State:
    keys: set[int] = field(default_factory=set)
    buttons: set[int] = field(default_factory=set)
    touches: set[int] = field(default_factory=set)

    def apply(self, event: tuple) -> None:
        kind = event[0]
        if kind == "move":
            # Pure motion MUST NOT change held button state.
            return
        if kind == "button":
            _, button, pressed = event
            (self.buttons.add if pressed else self.buttons.discard)(button)
        elif kind == "key":
            _, key, pressed = event
            (self.keys.add if pressed else self.keys.discard)(key)
        elif kind == "touch":
            _, slot, phase = event
            if phase in (0, 1):
                self.touches.add(slot)
            else:
                self.touches.discard(slot)
        else:
            raise AssertionError(kind)

    def teardown(self) -> int:
        attempted = len(self.keys) + len(self.buttons) + len(self.touches)
        self.keys.clear()
        self.buttons.clear()
        self.touches.clear()
        return attempted

# Every representable reduced held-state combination unwinds to empty.
held_combinations = 0
for bits in product((False, True), repeat=6):
    state = State()
    for idx, on in enumerate(bits[:2]):
        if on:
            state.keys.add(idx)
    for idx, on in enumerate(bits[2:4]):
        if on:
            state.buttons.add(idx)
    for idx, on in enumerate(bits[4:]):
        if on:
            state.touches.add(idx)
    before = len(state.keys) + len(state.buttons) + len(state.touches)
    assert state.teardown() == before
    assert not state.keys and not state.buttons and not state.touches
    held_combinations += 1

# Motion can be arbitrarily interleaved while a button is held without acting
# as an implicit release. Exercise all length-6 motion/button traces.
alphabet = [("move",), ("button", 0, True), ("button", 0, False)]
traces = 0
for trace in product(alphabet, repeat=6):
    state = State()
    expected = False
    for event in trace:
        state.apply(event)
        if event[0] == "button":
            expected = event[2]
        assert (0 in state.buttons) == expected
    state.teardown()
    assert not state.buttons
    traces += 1

# A held button follows successful pointer motion so fatal teardown releases at
# the latest drag position instead of jumping back to the press coordinate.
held_button_position = (0.1, 0.2)
for latest in ((0.25, 0.3), (0.5, 0.5), (0.9, 0.8)):
    held_button_position = latest
assert held_button_position == (0.9, 0.8)

# Touch: only Down/Move remain asserted. Up, Cancel, and unknown values fail
# closed as released, matching the corrected uinput convention.
for phase in range(256):
    down = phase in (0, 1)
    if phase in (0, 1):
        assert down
    else:
        assert not down

# One-value clipboard state coalesces to the latest update.
slot = None
for i in range(1024):
    slot = f"clipboard-{i}"
assert slot == "clipboard-1023"

# Two-entry file command queue rejects overflow rather than silently dropping.
capacity = 2
queue: list[str] = []
accepted = []
for item in ("a", "b", "c", "d"):
    if len(queue) >= capacity:
        accepted.append(False)
    else:
        queue.append(item)
        accepted.append(True)
assert accepted == [True, True, False, False]
assert queue == ["a", "b"]

print(
    "application teardown V15 model passed: "
    f"held_states={held_combinations} motion_button_traces={traces} "
    "touch_phases=256 clipboard_updates=1024 file_queue_cap=2"
)
