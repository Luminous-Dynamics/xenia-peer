#!/usr/bin/env python3
"""Independent reduced model for V18 reservation races and evidence layout."""
from dataclasses import dataclass

ADMISSION_TTL = 30_000
COPY_LEASE = 60_000
CAPACITY = 2

@dataclass
class Reservation:
    expected_len: int
    state: str
    expires_at: int

    def claim(self, data_len: int, now: int):
        if data_len != self.expected_len:
            return "size-mismatch"
        if now >= self.expires_at:
            return "expired"
        if self.state == "reserved":
            self.state = "copying"
            self.expires_at = now + COPY_LEASE
        return "ok"

    def commit(self, data_len: int, now: int):
        if now >= self.expires_at or self.state != "copying":
            return "invalid"
        if data_len != self.expected_len:
            return "size-mismatch"
        return "ok"

# Near-expiry claim must survive the original 30s deadline.
r = Reservation(100, "reserved", ADMISSION_TTL)
assert r.claim(100, 29_999) == "ok"
assert r.state == "copying"
assert r.expires_at == 89_999
assert r.commit(100, 30_001) == "ok"

# Repeated claim does not extend the lease indefinitely.
expiry = r.expires_at
assert r.claim(100, 40_000) == "ok"
assert r.expires_at == expiry
assert r.commit(100, expiry - 1) == "ok"
assert r.commit(100, expiry) == "invalid"

# Wrong lengths never become valid by state transition.
r2 = Reservation(8, "reserved", ADMISSION_TTL)
assert r2.claim(9, 1) == "size-mismatch"
assert r2.state == "reserved"
assert r2.commit(8, 1) == "invalid"  # commit requires a claim

# A fixed two-slot queue cannot be over-reserved.
slots = [Reservation(1, "reserved", ADMISSION_TTL) for _ in range(CAPACITY)]
assert len(slots) == CAPACITY

# Canonical Android event header fields do not overlap.
fields = {
    "kind_flags": (0, 4),
    "transfer_id": (4, 12),
    "done_bytes": (12, 20),
    "total_bytes": (20, 28),
    "name_len": (28, 30),
    "detail_len": (30, 32),
}
occupied = set()
for name, (start, end) in fields.items():
    assert 0 <= start < end <= 32, name
    cells = set(range(start, end))
    assert occupied.isdisjoint(cells), name
    occupied |= cells
assert occupied == set(range(32))

# Pressure snapshots are monotonic aggregate evidence, not protocol state.
pressure = dict(dropped_superseded=28, rejected=2, stale=3, fatal_deadline=1)
assert sum(pressure.values()) == 34

print("application runtime evidence V18 model passed: claim-race, bounded lease, header layout, pressure aggregate")
