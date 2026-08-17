#!/usr/bin/env python3
"""Independent reduced model for V19 reservation clock, status, and diagnostics."""
from dataclasses import dataclass

ADMISSION_TTL = 30_000
COPY_LEASE = 60_000
CAPACITY = 2

@dataclass
class Reservation:
    expected_len: int
    state: str = 'reserved'
    expires_at: int = ADMISSION_TTL

    def claim(self, data_len: int, now: int):
        if data_len != self.expected_len:
            return 7
        if now >= self.expires_at:
            return 6
        if self.state == 'reserved':
            self.state = 'copying'
            self.expires_at = now + COPY_LEASE
        return 0

# Claim at 29.999 s survives original 30 s deadline and expires at 89.999 s.
r = Reservation(100)
assert r.claim(100, 29_999) == 0
assert r.state == 'copying' and r.expires_at == 89_999
assert 30_000 < r.expires_at
expiry = r.expires_at
assert r.claim(100, 40_000) == 0
assert r.expires_at == expiry, 'repeat claim must not extend copy lease'
assert r.claim(101, 40_001) == 7 and r.expires_at == expiry

# Fixed exact status mapping must stay unique and contiguous.
codes = {
    'ok':0, 'invalid_argument':1, 'invalid_handle':2, 'queue_full':3,
    'session_closed':4, 'too_large':5, 'invalid_reservation':6,
    'reservation_size_mismatch':7,
}
assert sorted(codes.values()) == list(range(8))
assert len(set(codes.values())) == len(codes)

# Point-in-time diagnostics cannot claim more active reservations plus free
# capacity than the fixed command lane; queued commands account for the rest.
def snapshot(active_reserved, active_copying, available):
    assert 0 <= active_reserved <= CAPACITY
    assert 0 <= active_copying <= CAPACITY
    assert 0 <= available <= CAPACITY
    assert active_reserved + active_copying + available <= CAPACITY
    return (active_reserved, active_copying, available, CAPACITY)

assert snapshot(2, 0, 0) == (2, 0, 0, 2)
assert snapshot(1, 1, 0) == (1, 1, 0, 2)
# One expired reservation returns one slot while the claimed one remains.
assert snapshot(0, 1, 1) == (0, 1, 1, 2)
# After committing the claimed token, its permit becomes a queued command,
# so active reservations can be zero while only one slot is free.
assert snapshot(0, 0, 1) == (0, 0, 1, 2)

print('application runtime assurance V19 model passed: paused-clock race, exact statuses, bounded diagnostic snapshots')
