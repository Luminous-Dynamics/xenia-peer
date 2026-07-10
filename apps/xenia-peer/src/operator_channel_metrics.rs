// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attack-signal counters for the sealed operator endpoint
//! (`--operator-sealed`). That endpoint is the daemon's most privileged remote
//! surface and is typically internet-adjacent (behind a reverse proxy), so
//! *probing* it — connections from keys that aren't enrolled operators, or that
//! can't complete the PQC handshake — is a security signal a defender wants to
//! see and alert on, not just a debug log line.
//!
//! These counters are process-lifetime totals, incremented as
//! [`crate::operator_sealed_channel::run_sealed_operator_endpoint`] handles each
//! connection. A rejection also emits a structured `tracing::warn!` carrying the
//! running total, so a log pipeline (journald → SIEM) can alert on a spike in
//! `not_enrolled` or `handshake_failure` events without scraping a metrics port.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lifetime counters for the sealed operator endpoint. Cheap, lock-free
/// (`Relaxed` atomics — these are monotonic diagnostics, not synchronization).
#[derive(Debug, Default)]
pub(crate) struct OperatorChannelMetrics {
    connections_accepted: AtomicU64,
    handshake_failures: AtomicU64,
    not_enrolled_rejections: AtomicU64,
    revoked_rejections: AtomicU64,
    channels_established: AtomicU64,
    terminal_decisions: AtomicU64,
}

/// A point-in-time copy of [`OperatorChannelMetrics`], for logging or a future
/// status endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct OperatorChannelMetricsSnapshot {
    /// Connections that completed the WebSocket upgrade (real operator attempts).
    pub connections_accepted: u64,
    /// Connections whose PQC handshake failed, or whose WS upgrade failed —
    /// includes malformed/hostile probes.
    pub handshake_failures: u64,
    /// Cryptographically valid handshakes from keys that are NOT enrolled
    /// operators. A rising count here is the strongest probe signal.
    pub not_enrolled_rejections: u64,
    /// Enrolled operators refused because their id is on the live revocation
    /// list — a *known* operator's key used after revocation (possible key
    /// compromise), distinct from an unenrolled probe.
    pub revoked_rejections: u64,
    /// Handshakes that authenticated an enrolled operator and opened a channel.
    pub channels_established: u64,
    /// Channels ended by a terminal (Deny/Revoke) decision.
    pub terminal_decisions: u64,
}

impl OperatorChannelMetrics {
    /// Record an accepted operator connection (post WS-upgrade).
    pub(crate) fn record_connection(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed handshake (or WS upgrade); returns the new running total.
    pub(crate) fn record_handshake_failure(&self) -> u64 {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record a valid-handshake-but-not-enrolled rejection; returns the new
    /// running total (the value worth alerting on).
    pub(crate) fn record_not_enrolled(&self) -> u64 {
        self.not_enrolled_rejections.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record an enrolled-but-revoked operator rejection; returns the new total.
    pub(crate) fn record_revoked(&self) -> u64 {
        self.revoked_rejections.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record an authenticated, enrolled operator channel being established.
    pub(crate) fn record_established(&self) {
        self.channels_established.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a terminal (Deny/Revoke) decision that ended the endpoint.
    pub(crate) fn record_terminal(&self) {
        self.terminal_decisions.fetch_add(1, Ordering::Relaxed);
    }

    /// A consistent-enough snapshot for logging/export. Reads are independent
    /// `Relaxed` loads (no global lock), so counts can be momentarily skewed
    /// mid-update — fine for monotonic diagnostics.
    pub(crate) fn snapshot(&self) -> OperatorChannelMetricsSnapshot {
        OperatorChannelMetricsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            not_enrolled_rejections: self.not_enrolled_rejections.load(Ordering::Relaxed),
            revoked_rejections: self.revoked_rejections.load(Ordering::Relaxed),
            channels_established: self.channels_established.load(Ordering::Relaxed),
            terminal_decisions: self.terminal_decisions.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero_and_increment_independently() {
        let m = OperatorChannelMetrics::default();
        assert_eq!(
            m.snapshot(),
            OperatorChannelMetricsSnapshot {
                connections_accepted: 0,
                handshake_failures: 0,
                not_enrolled_rejections: 0,
                revoked_rejections: 0,
                channels_established: 0,
                terminal_decisions: 0,
            }
        );

        m.record_connection();
        m.record_connection();
        assert_eq!(m.record_not_enrolled(), 1);
        assert_eq!(m.record_not_enrolled(), 2);
        assert_eq!(m.record_handshake_failure(), 1);
        assert_eq!(m.record_revoked(), 1);
        m.record_established();
        m.record_terminal();

        let s = m.snapshot();
        assert_eq!(s.connections_accepted, 2);
        assert_eq!(s.not_enrolled_rejections, 2);
        assert_eq!(s.handshake_failures, 1);
        assert_eq!(s.revoked_rejections, 1);
        assert_eq!(s.channels_established, 1);
        assert_eq!(s.terminal_decisions, 1);
    }

    #[test]
    fn snapshot_serializes_to_json() {
        let m = OperatorChannelMetrics::default();
        m.record_not_enrolled();
        let json = serde_json::to_string(&m.snapshot()).unwrap();
        assert!(json.contains("\"not_enrolled_rejections\":1"));
    }
}
