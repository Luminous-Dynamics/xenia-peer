// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pending-handshake state for Track B
//! (`docs/security/SIGNER_DELEGATION_DESIGN.md`): the agent-driven
//! sealed-channel handshake.
//!
//! Unlike Track A, Track B needs no daemon-signed evidence relayed to it
//! at all -- the handshake's own cryptography *is* the host-authentication
//! evidence. The browser relays the daemon's `HostHello`/`HostFinalize`
//! bytes (received over its own WebSocket connection -- the agent never
//! originates that connection) to `POST /v1/handshake/begin` and
//! `POST /v1/handshake/finish`; in between, the agent must hold the
//! in-progress `ViewerHandshake`/`ViewerHandshakeHighSec` state across
//! those two separate HTTP requests. This module owns that state.
//!
//! ## Lifetime and concurrency limits
//!
//! - **30-second lifetime**, measured against monotonic time (`Instant`,
//!   not wall-clock, which can be adjusted).
//! - **Concurrency caps**: 8 pending handshakes per distinct `Origin`
//!   (the closest thing this agent has to a caller "session" -- every
//!   request already carries a validated `Origin` per
//!   `auth_and_cors_middleware`, and it's what a pending entry is bound
//!   to), 32 process-wide. This bounds resource use per misbehaving/buggy
//!   caller without needing a real session concept this agent doesn't
//!   otherwise have (the pairing token authenticates every caller
//!   identically; `Origin` is a coarse fairness/accounting key here, not
//!   an independent trust boundary).
//! - **Handshake id**: 128 random bits.
//! - Each pending entry is bound to the `Origin` and `suite` it was opened
//!   under; `/v1/handshake/finish` must be called with the same binding
//!   ([`HandshakeState::take`] enforces this by refusing to return an
//!   entry to a mismatched `Origin`).
//! - State is removed on every exit path: success, a failed `finish` (a
//!   bad/forged `HostFinalize` consumes the attempt -- no retrying
//!   attacker-controlled responses against the same pending state),
//!   expiry, or agent shutdown (the whole map is just process memory, so
//!   shutdown reclaims it with no extra code). There is no explicit
//!   `/v1/handshake/cancel` endpoint in this first version -- an abandoned
//!   handshake (e.g. the operator closed the tab) simply expires; this
//!   mirrors the design doc's own "response-loss resilience deferred to a
//!   later iteration" scoping.
//! - **Zeroization is best-effort, not a guarantee**, and this is stated
//!   plainly rather than overclaimed: `xenia_wire::handshake::ViewerHandshake`
//!   and `ViewerHandshakeHighSec` implement neither `Drop` nor `Zeroize`
//!   themselves (verified by reading the crate source), so removing an
//!   entry from the map and dropping it relies entirely on whatever
//!   zeroize-on-drop `ed25519-dalek`'s own `zeroize` feature gives the
//!   Ed25519 half of the key material -- the ML-DSA signing key and any
//!   ephemeral KEM secret material get no such guarantee from this crate.
//!   This is the same honest caveat already documented on
//!   `sovereign-admin`'s `OperatorIdentity`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use xenia_wire::handshake::ViewerHandshake;
use xenia_wire::handshake_highsec::ViewerHandshakeHighSec;

/// Default pending-handshake lifetime. A separate constant (rather than
/// baking `30` into [`HandshakeState::new`]'s only production call site)
/// so tests can construct a [`HandshakeState`] with a much shorter TTL and
/// exercise expiry without a real 30-second sleep.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);
/// Maximum pending handshakes per distinct `Origin`.
pub const MAX_PENDING_PER_ORIGIN: usize = 8;
/// Maximum pending handshakes process-wide, regardless of `Origin`.
pub const MAX_PENDING_PROCESS_WIDE: usize = 32;

/// The in-progress viewer handshake state for one suite. Both variants are
/// plain, `Send`, safe-Rust crypto state (verified by reading
/// `xenia-wire`'s source: no `Rc`/`RefCell`/raw pointers, no wasm-only
/// surface), so holding one across an `.await` point between two HTTP
/// requests is fine on a native/tokio agent. Boxed -- both variants hold
/// multi-KB signing state (`ViewerHandshakeHighSec`'s ML-DSA-87 material
/// alone is ~13KB), and an unboxed enum would size every `PendingSuite`
/// (and hence every `HashMap` entry in [`HandshakeState`]) to the larger
/// variant regardless of which one is actually held -- the same reasoning
/// `apps/xenia-peer`'s `OperatorHostIdentity` enum already documents for
/// the identical shape on the daemon side.
pub enum PendingSuite {
    Standard(Box<ViewerHandshake>),
    HighSec(Box<ViewerHandshakeHighSec>),
}

struct PendingHandshake {
    suite: PendingSuite,
    origin: String,
    /// The caller's normalized `daemon_endpoint` from `/v1/handshake/begin`
    /// -- carried through to `/v1/handshake/finish` so the host-trust check
    /// there can scope its pin-store lookup by the same stable label the
    /// caller supplied at `begin` time (see
    /// `xenia_operator_agent_proto::HandshakeRequestCommon::daemon_endpoint`).
    /// Not identity evidence -- purely a pin-store scope key.
    daemon_endpoint: String,
    created_at: Instant,
}

/// What [`HandshakeState::take`] returns: the pending handshake state and
/// the `daemon_endpoint` scope it was opened under.
pub struct TakenHandshake {
    pub suite: PendingSuite,
    pub daemon_endpoint: String,
}

/// Why looking up a pending handshake failed. Both variants are
/// deliberately reported as the *same* [`Self::not_found_message`] to the
/// caller -- distinguishing "wrong Origin" from "doesn't exist" would leak
/// information a caller with the wrong Origin shouldn't get for free.
#[derive(Debug)]
pub enum TakeError {
    NotFoundOrExpired,
    OriginMismatch,
}

impl TakeError {
    pub fn not_found_message(&self) -> &'static str {
        "unknown or expired handshake_id"
    }
}

/// Why starting a new pending handshake was refused.
#[derive(Debug)]
pub enum BeginError {
    TooManyPendingForOrigin,
    TooManyPendingProcessWide,
}

impl BeginError {
    pub fn message(&self) -> &'static str {
        match self {
            BeginError::TooManyPendingForOrigin => {
                "too many pending handshakes for this origin -- finish or let an earlier one expire first"
            }
            BeginError::TooManyPendingProcessWide => {
                "too many pending handshakes agent-wide -- try again shortly"
            }
        }
    }
}

/// The agent's pending Track B handshakes: one process-wide map, keyed by
/// a 128-bit handshake id.
pub struct HandshakeState {
    pending: HashMap<[u8; 16], PendingHandshake>,
    ttl: Duration,
}

impl HandshakeState {
    pub fn new(ttl: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            ttl,
        }
    }

    /// Drop every entry older than `ttl`. Called at the start of
    /// [`Self::begin`] (and available to call before [`Self::take`] too,
    /// though `take` also independently checks expiry on the entry it
    /// looks up) -- there is no background sweep task; expiry is enforced
    /// lazily, on access, which is simple and adequate for a low-volume,
    /// human-paced, interactive API like this one.
    pub fn purge_expired(&mut self) {
        let ttl = self.ttl;
        self.pending.retain(|_, p| p.created_at.elapsed() < ttl);
    }

    /// Insert a newly-begun handshake bound to `origin`, enforcing the
    /// concurrency caps. `daemon_endpoint` is the caller's (already
    /// normalized) host-trust scope key, carried through to the matching
    /// [`Self::take`] so `/v1/handshake/finish` can check the completed
    /// handshake's fingerprint against the same scope `begin` was opened
    /// under. Generates and returns a fresh random handshake id. Callers
    /// should call [`Self::purge_expired`] first so an about-to-expire
    /// entry doesn't spuriously count against the caps.
    pub fn begin(
        &mut self,
        origin: &str,
        suite: PendingSuite,
        daemon_endpoint: String,
    ) -> Result<[u8; 16], BeginError> {
        if self.pending.len() >= MAX_PENDING_PROCESS_WIDE {
            return Err(BeginError::TooManyPendingProcessWide);
        }
        let per_origin = self.pending.values().filter(|p| p.origin == origin).count();
        if per_origin >= MAX_PENDING_PER_ORIGIN {
            return Err(BeginError::TooManyPendingForOrigin);
        }

        let id = rand::random::<[u8; 16]>();
        self.pending.insert(
            id,
            PendingHandshake {
                suite,
                origin: origin.to_string(),
                daemon_endpoint,
                created_at: Instant::now(),
            },
        );
        Ok(id)
    }

    /// Remove and return the pending handshake for `id`, if any, bound to
    /// `origin`. **Always removes the entry if found**, regardless of
    /// whether the `Origin` matches -- a handshake id is single-use no
    /// matter what: a caller presenting a stolen/guessed id from a
    /// different Origin still burns the attempt rather than being able to
    /// retry it. An expired entry is treated as absent (and is removed
    /// too, as routine cleanup).
    pub fn take(&mut self, id: &[u8; 16], origin: &str) -> Result<TakenHandshake, TakeError> {
        let Some(entry) = self.pending.remove(id) else {
            return Err(TakeError::NotFoundOrExpired);
        };
        if entry.created_at.elapsed() >= self.ttl {
            return Err(TakeError::NotFoundOrExpired);
        }
        if entry.origin != origin {
            return Err(TakeError::OriginMismatch);
        }
        Ok(TakenHandshake {
            suite: entry.suite,
            daemon_endpoint: entry.daemon_endpoint,
        })
    }

    #[cfg(test)]
    fn suite_label_for_test(&self, id: &[u8; 16]) -> Option<&str> {
        self.pending.get(id).map(|p| match &p.suite {
            PendingSuite::Standard(_) => "standard",
            PendingSuite::HighSec(_) => "highsec",
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_pending() -> PendingSuite {
        PendingSuite::Standard(Box::new(
            ViewerHandshake::from_identity(&[1u8; 32], &[2u8; 32])
                .expect("32-byte seeds always construct"),
        ))
    }

    const TEST_ENDPOINT: &str = "wss://daemon.test.example/operator";

    fn begin_standard(state: &mut HandshakeState, origin: &str) -> [u8; 16] {
        state
            .begin(origin, standard_pending(), TEST_ENDPOINT.to_string())
            .unwrap()
    }

    #[test]
    fn begin_then_take_round_trips_and_is_single_use() {
        let mut state = HandshakeState::new(DEFAULT_TTL);
        let id = begin_standard(&mut state, "http://localhost:8134");
        assert_eq!(state.suite_label_for_test(&id), Some("standard"));

        let taken = state.take(&id, "http://localhost:8134").unwrap();
        assert!(matches!(taken.suite, PendingSuite::Standard(_)));
        assert_eq!(taken.daemon_endpoint, TEST_ENDPOINT);
        // Gone: a second take fails even with the right Origin.
        assert!(matches!(
            state.take(&id, "http://localhost:8134"),
            Err(TakeError::NotFoundOrExpired)
        ));
    }

    #[test]
    fn take_with_the_wrong_origin_is_refused_and_still_consumes_the_entry() {
        let mut state = HandshakeState::new(DEFAULT_TTL);
        let id = begin_standard(&mut state, "http://localhost:8134");

        assert!(matches!(
            state.take(&id, "http://evil.example"),
            Err(TakeError::OriginMismatch)
        ));
        // Consumed regardless -- the right Origin can't retry it either.
        assert!(matches!(
            state.take(&id, "http://localhost:8134"),
            Err(TakeError::NotFoundOrExpired)
        ));
    }

    #[test]
    fn expired_entries_are_treated_as_absent_by_take() {
        let mut state = HandshakeState::new(Duration::from_millis(1));
        let id = begin_standard(&mut state, "http://localhost:8134");
        std::thread::sleep(Duration::from_millis(10));
        assert!(matches!(
            state.take(&id, "http://localhost:8134"),
            Err(TakeError::NotFoundOrExpired)
        ));
    }

    #[test]
    fn purge_expired_removes_stale_entries_but_keeps_fresh_ones() {
        // A wide TTL/sleep margin: this ran flaky under a heavily loaded
        // shared test runner (25+ load average, many concurrent processes)
        // with a 20ms TTL / 30ms sleep, because scheduling jitter alone could
        // exceed the gap between "stale" and "fresh". 200ms/400ms keeps the
        // same test intent with headroom real thread-pool contention can't
        // eat through.
        let mut state = HandshakeState::new(Duration::from_millis(200));
        let stale = begin_standard(&mut state, "http://localhost:8134");
        std::thread::sleep(Duration::from_millis(400));
        let fresh = begin_standard(&mut state, "http://localhost:8134");

        state.purge_expired();
        assert_eq!(state.len(), 1);
        assert!(state.suite_label_for_test(&stale).is_none());
        assert!(state.suite_label_for_test(&fresh).is_some());
    }

    #[test]
    fn per_origin_cap_is_enforced_independently_of_other_origins() {
        let mut state = HandshakeState::new(DEFAULT_TTL);
        for _ in 0..MAX_PENDING_PER_ORIGIN {
            begin_standard(&mut state, "http://a.example");
        }
        assert!(matches!(
            state.begin(
                "http://a.example",
                standard_pending(),
                TEST_ENDPOINT.to_string()
            ),
            Err(BeginError::TooManyPendingForOrigin)
        ));
        // A different Origin is unaffected by "a.example" being at cap.
        assert!(
            state
                .begin(
                    "http://b.example",
                    standard_pending(),
                    TEST_ENDPOINT.to_string()
                )
                .is_ok()
        );
    }

    #[test]
    fn process_wide_cap_is_enforced_across_origins() {
        let mut state = HandshakeState::new(DEFAULT_TTL);
        // Fill the process-wide cap using many distinct origins so the
        // per-origin cap (8) never fires first.
        for i in 0..MAX_PENDING_PROCESS_WIDE {
            let origin = format!("http://origin-{i}.example");
            begin_standard(&mut state, &origin);
        }
        assert!(matches!(
            state.begin(
                "http://one-more.example",
                standard_pending(),
                TEST_ENDPOINT.to_string()
            ),
            Err(BeginError::TooManyPendingProcessWide)
        ));
    }
}
