// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-window rate limiting for every credential-checked route.
//!
//! `apps/xenia-peer`'s daemon has bounded auth attempts against
//! `POST /auth/verify` since the RBAC work landed
//! (`operator_auth::RateLimiter`, applied in `operator_http.rs` before any
//! signature verification runs). This agent never got the same treatment --
//! `POST /v1/pair` compares an attacker-controlled header against the
//! pairing token (`constant_time_eq`, but with no bound on *how many*
//! guesses a caller can make), and every `/v1/sign/*`/`/v1/handshake/*`
//! route does real crypto (MAC verification, `ed25519`/`ML-DSA` signing) on
//! every request with no bound on how often a caller can trigger it either.
//! `docs/roadmap/*` flagged this gap repeatedly without it being closed;
//! this module closes it.
//!
//! Deliberately not shared with `apps/xenia-peer`'s `operator_auth::
//! RateLimiter` -- the two are separate binaries with no crate boundary
//! between them, and the type is a dozen lines of pure, easily-duplicated
//! logic (see `docs/roadmap/NEXT_SESSION_PLAN_2026-07-27.md`'s note on the
//! separately-tracked `secure_file.rs`-style duplication for the case
//! *against* casually sharing state-holding types across these two apps).
//! The algorithm and shape are intentionally identical so the two crates'
//! behavior is easy to reason about together.

/// Default rate limit for this agent's authenticated surface: attempts
/// allowed per window, and window length. A single limiter bounds every
/// credential-checked route uniformly (see `auth_and_cors_middleware`) --
/// this agent binds to `127.0.0.1` only and is talked to by exactly one
/// caller (the console), so a single process-wide counter is the right
/// granularity, matching the daemon's own `AUTH_RATE_MAX`/
/// `AUTH_RATE_WINDOW_SECS`.
pub(crate) const AGENT_RATE_MAX: u32 = 30;
pub(crate) const AGENT_RATE_WINDOW_SECS: u64 = 60;

/// A fixed-window rate limiter. `allow(now)` returns whether an attempt is
/// permitted, consuming one slot; the window resets when it elapses. Pure
/// and time-injectable for testing.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    window_secs: u64,
    max: u32,
    window_start: u64,
    count: u32,
}

impl RateLimiter {
    pub(crate) fn new(max: u32, window_secs: u64) -> Self {
        Self {
            window_secs,
            max,
            window_start: 0,
            count: 0,
        }
    }

    /// Record an attempt; return whether it is within the limit. Once the
    /// window elapses the counter resets.
    pub(crate) fn allow(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window_start) >= self.window_secs {
            self.window_start = now;
            self.count = 0;
        }
        if self.count < self.max {
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Seconds remaining until the current window resets, for a
    /// `Retry-After` header. Only meaningful called with the same `now`
    /// immediately after `allow(now)` returned `false` -- purely a read of
    /// existing state, doesn't affect `allow`'s own behavior.
    pub(crate) fn retry_after_secs(&self, now: u64) -> u64 {
        self.window_secs
            .saturating_sub(now.saturating_sub(self.window_start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_attempts_per_window() {
        let mut limiter = RateLimiter::new(3, 60);
        assert!(limiter.allow(0));
        assert!(limiter.allow(0));
        assert!(limiter.allow(0));
        assert!(!limiter.allow(0));
        assert!(!limiter.allow(10));
    }

    #[test]
    fn resets_once_the_window_elapses() {
        let mut limiter = RateLimiter::new(1, 60);
        assert!(limiter.allow(0));
        assert!(!limiter.allow(30));
        // A new window starts once `window_secs` has elapsed since the
        // window began, not since the last attempt.
        assert!(limiter.allow(60));
        assert!(!limiter.allow(65));
    }

    #[test]
    fn zero_max_never_allows() {
        let mut limiter = RateLimiter::new(0, 60);
        assert!(!limiter.allow(0));
        assert!(!limiter.allow(1_000));
    }

    #[test]
    fn retry_after_counts_down_to_the_window_reset() {
        let mut limiter = RateLimiter::new(1, 60);
        // `window_start` defaults to 0 and this first `now` (0) doesn't
        // clear the `>= window_secs` reset threshold in `allow`, so the
        // window opens at 0, not at this call's timestamp -- matches
        // `resets_once_the_window_elapses` above, which anchors the same
        // way for the same reason.
        assert!(limiter.allow(0));
        // Window opened at 0, resets at 60.
        assert_eq!(limiter.retry_after_secs(0), 60);
        assert_eq!(limiter.retry_after_secs(30), 30);
        assert_eq!(limiter.retry_after_secs(59), 1);
        // Never negative, even past the reset instant.
        assert_eq!(limiter.retry_after_secs(60), 0);
        assert_eq!(limiter.retry_after_secs(1_000), 0);
    }
}
