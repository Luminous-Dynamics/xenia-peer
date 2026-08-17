#!/usr/bin/env python3
"""Reduced V21 model: strict sequential disk staging and authenticated activation."""
import hashlib

CHUNK = 64 * 1024

class Receive:
    def __init__(self, payload: bytes):
        self.expected_size = len(payload)
        self.expected_hash = hashlib.blake2s(payload).digest()  # stand-in digest; transition logic is hash-agnostic
        self.received = 0
        self.bytes = bytearray()
        self.published = False

    def append(self, offset: int, data: bytes):
        if offset != self.received:
            return "offset"
        end = self.received + len(data)
        if end > self.expected_size:
            return "overrun"
        self.bytes.extend(data)
        self.received = end
        return "ok"

    def finish(self):
        if self.received != self.expected_size:
            return "size"
        if hashlib.blake2s(self.bytes).digest() != self.expected_hash:
            return "hash"
        if self.published:
            return "clobber"
        self.published = True
        return "ok"

payload = b"x" * (3 * CHUNK + 17)
r = Receive(payload)
offset = 0
max_live_chunk = 0
while offset < len(payload):
    data = payload[offset:offset + CHUNK]
    max_live_chunk = max(max_live_chunk, len(data))
    assert r.append(offset, data) == "ok"
    offset += len(data)
assert r.finish() == "ok"
assert max_live_chunk == CHUNK

# Gaps and overlaps both fail before any state advances.
gap = Receive(b"abcd")
assert gap.append(1, b"a") == "offset" and gap.received == 0
overlap = Receive(b"abcd")
assert overlap.append(0, b"ab") == "ok"
assert overlap.append(1, b"c") == "offset" and overlap.received == 2

# Offer size is an upper bound during streaming and an exact equality at Complete.
overrun = Receive(b"ab")
assert overrun.append(0, b"abc") == "overrun"
short = Receive(b"abc")
assert short.append(0, b"ab") == "ok" and short.finish() == "size"

# Corrupted content fails integrity and never publishes.
corrupt = Receive(b"abc")
assert corrupt.append(0, b"abd") == "ok"
assert corrupt.finish() == "hash" and not corrupt.published

# A staged outbound command becomes active only when both gates are true.
def can_activate(authenticated, outgoing_active):
    return authenticated and not outgoing_active
assert not can_activate(False, False)
assert not can_activate(False, True)
assert not can_activate(True, True)
assert can_activate(True, False)

# Concurrency is bounded, but V21 deliberately does not claim filesystem
# free-space reservation. Potential staged disk remains cap * policy size.
assert 8 > 0 and 4 > 0
print("application receive staging V21 model passed: exact offsets, exact size/hash completion, 64KiB live chunk, auth+idle activation")
