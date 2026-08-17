// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Explicit bounded-producer semantics for application-facing Xenia queues.
//!
//! Transport backpressure alone is not enough to keep a remote-desktop style
//! session safe: different application events have different meanings when a
//! local producer outruns the network/consumer. A stale video frame may be
//! discarded, while a key-up/button-release must not silently disappear.
//! These V1 descriptors make those choices reviewable and reusable without
//! pretending every queue can share one overflow policy.

use std::sync::atomic::{AtomicU64, Ordering};

/// What a bounded producer does when no capacity is immediately available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerOverflowPolicy {
    /// Drop the new item; a later sample can supersede it.
    DropNewest,
    /// Drop the oldest buffered item and retain the newest state/sample.
    DropOldest,
    /// Keep only the latest value rather than a backlog of intermediate values.
    CoalesceLatest,
    /// Apply bounded backpressure rather than silently losing the state change.
    Backpressure,
    /// Reject the producer action explicitly; the caller decides whether to
    /// retry, surface an error, or fail the session.
    Reject,
}

/// Reviewable queue/slot policy for one semantic producer class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerFlowPolicyV1 {
    /// Stable semantic class name for logs/evidence.
    pub name: &'static str,
    /// Maximum number of buffered values. A latest-value slot uses `1`.
    pub capacity: usize,
    /// Behavior when the producer reaches the bound.
    pub overflow: ProducerOverflowPolicy,
}

/// Desktop/mobile pointer-motion samples: bounded and lossy.
pub const POINTER_MOTION_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "pointer-motion",
    capacity: 256,
    overflow: ProducerOverflowPolicy::DropNewest,
};

/// Key/button/touch state transitions: bounded but never silently dropped.
pub const INPUT_STATE_TRANSITION_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "input-state-transition",
    capacity: 256,
    overflow: ProducerOverflowPolicy::Backpressure,
};

/// Desktop decoded video presentation uses one latest-frame slot.
pub const DESKTOP_VIDEO_PRESENTATION_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "desktop-video-presentation",
    capacity: 1,
    overflow: ProducerOverflowPolicy::CoalesceLatest,
};

/// Mobile decoded/encoded video presentation keeps a very small recent window.
pub const MOBILE_VIDEO_PRESENTATION_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "mobile-video-presentation",
    capacity: 4,
    overflow: ProducerOverflowPolicy::DropOldest,
};

/// Desktop telemetry is state-like: only the newest batch is relevant to UI.
pub const DESKTOP_TELEMETRY_PRESENTATION_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "desktop-telemetry-presentation",
    capacity: 1,
    overflow: ProducerOverflowPolicy::CoalesceLatest,
};

/// Desktop audio playback queue is finite; newest audio is rejected on overflow
/// rather than growing memory without bound.
pub const DESKTOP_AUDIO_PLAYBACK_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "desktop-audio-playback",
    capacity: 64,
    overflow: ProducerOverflowPolicy::DropNewest,
};


/// Time-based audio buffering contract for the native desktop viewer.
///
/// Queue lengths alone are a poor latency contract: at the protocol's maximum
/// 20 ms audio-frame duration, the historical 64-frame GUI queue could retain
/// roughly 1.28 seconds of stale sound before the device queue was considered.
/// V16 names the buffering stages in milliseconds/frames so changes remain
/// reviewable as latency policy rather than accidental container sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopAudioLatencyPolicyV1 {
    /// Maximum frames waiting between network/decode and the GUI playback sink.
    pub ingress_capacity_frames: usize,
    /// Maximum sequence-jitter depth retained before the oldest sequence is
    /// advanced/dropped.
    pub jitter_max_depth_frames: usize,
    /// Minimum buffered depth before normal playout begins.
    pub jitter_target_delay_frames: usize,
    /// Maximum PCM time retained by the native output-device FIFO.
    pub device_buffer_ms: u32,
    /// Maximum protocol frame duration used to calculate the explicit bound.
    pub max_frame_duration_ms: u16,
}

/// V16 native audio policy: <= 4 ingress frames (80 ms at the wire maximum),
/// <= 6 jitter frames (120 ms), and <= 80 ms of device PCM. This is an
/// application-buffering bound, not a promise about OS/hardware/network latency.
pub const DESKTOP_AUDIO_LATENCY_V1: DesktopAudioLatencyPolicyV1 = DesktopAudioLatencyPolicyV1 {
    ingress_capacity_frames: 4,
    jitter_max_depth_frames: 6,
    jitter_target_delay_frames: 2,
    device_buffer_ms: 80,
    max_frame_duration_ms: 20,
};

/// V16 desktop network/decode -> GUI audio queue. Newest audio is rejected on
/// saturation rather than allowing unbounded growth; the much smaller V16
/// capacity limits the amount of stale sound this can preserve.
pub const DESKTOP_AUDIO_PLAYBACK_V2: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "desktop-audio-playback-v2",
    capacity: DESKTOP_AUDIO_LATENCY_V1.ingress_capacity_frames,
    overflow: ProducerOverflowPolicy::DropNewest,
};

/// V17 freshness-recovery policy for the desktop audio ingress. The bounded
/// capacity stays identical to V16, but saturation now discards the oldest
/// queued frame before admitting the newest one. This converges playback
/// toward the present instead of preserving stale audio.
pub const DESKTOP_AUDIO_PLAYBACK_V3: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "desktop-audio-playback-v3",
    capacity: DESKTOP_AUDIO_LATENCY_V1.ingress_capacity_frames,
    overflow: ProducerOverflowPolicy::DropOldest,
};

/// Snapshot of semantic pressure observed at an application lane boundary.
/// These counters are diagnostic evidence only; they do not alter protocol
/// semantics or become part of the authenticated session transcript.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LanePressureSnapshotV1 {
    pub dropped_superseded: u64,
    pub rejected: u64,
    pub stale: u64,
    pub fatal_deadline: u64,
}

/// Lock-free counters shared by local producer/consumer paths so overload and
/// freshness recovery are observable rather than hidden behind queue bounds.
#[derive(Debug, Default)]
pub struct LanePressureCountersV1 {
    dropped_superseded: AtomicU64,
    rejected: AtomicU64,
    stale: AtomicU64,
    fatal_deadline: AtomicU64,
}

impl LanePressureCountersV1 {
    pub fn record_dropped_superseded(&self) -> u64 {
        self.dropped_superseded.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_rejected(&self) -> u64 {
        self.rejected.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_stale(&self) -> u64 {
        self.stale.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_fatal_deadline(&self) -> u64 {
        self.fatal_deadline.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn snapshot(&self) -> LanePressureSnapshotV1 {
        LanePressureSnapshotV1 {
            dropped_superseded: self.dropped_superseded.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            stale: self.stale.load(Ordering::Relaxed),
            fatal_deadline: self.fatal_deadline.load(Ordering::Relaxed),
        }
    }
}

/// Host video freshness contract. The daemon is intentionally a synchronous
/// capture -> encode -> seal -> send pipeline today (no hidden frame backlog).
/// Frames that spend too long in capture/encode are discarded, and a send that
/// exceeds the lane-specific deadline is session-fatal because cancellation can
/// leave a stream mid-envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostVideoFreshnessPolicyV1 {
    /// Maximum local age from capture start until the daemon begins sending the
    /// encoded result. Older output is superseded by a future capture.
    pub max_capture_to_send_ms: u64,
    /// Maximum time one video envelope may spend in the transport send call.
    /// Timeout is fatal; Xenia does not resume the same framing stream.
    pub max_send_stall_ms: u64,
    /// The current synchronous pipeline permits at most one captured frame to
    /// be active before transport backpressure reaches the capture loop.
    pub max_frames_in_flight: usize,
}

pub const HOST_VIDEO_FRESHNESS_V1: HostVideoFreshnessPolicyV1 = HostVideoFreshnessPolicyV1 {
    max_capture_to_send_ms: 500,
    max_send_stall_ms: 1_000,
    max_frames_in_flight: 1,
};

/// Mobile outbound clipboard state is latest-value state, not a history.
pub const MOBILE_CLIPBOARD_OUTBOUND_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "mobile-clipboard-outbound",
    capacity: 1,
    overflow: ProducerOverflowPolicy::CoalesceLatest,
};

/// User-triggered mobile file-transfer commands are rare correctness-sensitive
/// actions. Queue saturation is surfaced explicitly instead of dropping them.
pub const MOBILE_FILE_TRANSFER_COMMAND_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "mobile-file-transfer-command",
    capacity: 2,
    overflow: ProducerOverflowPolicy::Reject,
};

/// Maximum size of one mobile-originated file command admitted by the native
/// viewer before enqueue/copy work. This matches the current Android picker
/// ceiling and the daemon/viewer default transfer cap.
pub const MOBILE_FILE_TRANSFER_MAX_BYTES_V1: usize = 100 * 1024 * 1024;

/// Mobile file-transfer UI notifications retain the newest bounded history.
pub const MOBILE_FILE_TRANSFER_EVENTS_V1: ProducerFlowPolicyV1 = ProducerFlowPolicyV1 {
    name: "mobile-file-transfer-events",
    capacity: 64,
    overflow: ProducerOverflowPolicy::DropOldest,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_are_not_lossy() {
        assert_eq!(
            INPUT_STATE_TRANSITION_V1.overflow,
            ProducerOverflowPolicy::Backpressure
        );
        assert_eq!(POINTER_MOTION_V1.capacity, INPUT_STATE_TRANSITION_V1.capacity);
    }

    #[test]
    fn presentation_buffers_are_finite() {
        for policy in [
            DESKTOP_VIDEO_PRESENTATION_V1,
            MOBILE_VIDEO_PRESENTATION_V1,
            DESKTOP_TELEMETRY_PRESENTATION_V1,
            DESKTOP_AUDIO_PLAYBACK_V1,
            DESKTOP_AUDIO_PLAYBACK_V2,
            DESKTOP_AUDIO_PLAYBACK_V3,
            MOBILE_CLIPBOARD_OUTBOUND_V1,
            MOBILE_FILE_TRANSFER_COMMAND_V1,
            MOBILE_FILE_TRANSFER_EVENTS_V1,
        ] {
            assert!(policy.capacity > 0);
            assert!(policy.capacity <= 256);
        }
    }
    #[test]
    fn desktop_audio_latency_budget_is_explicit_and_subsecond() {
        let p = DESKTOP_AUDIO_LATENCY_V1;
        assert!(p.jitter_target_delay_frames < p.jitter_max_depth_frames);
        assert_eq!(DESKTOP_AUDIO_PLAYBACK_V2.capacity, p.ingress_capacity_frames);
        let buffered_ms = (p.ingress_capacity_frames + p.jitter_max_depth_frames)
            * usize::from(p.max_frame_duration_ms)
            + p.device_buffer_ms as usize;
        assert_eq!(buffered_ms, 280);
        assert!(buffered_ms < 1_000);
    }

    #[test]
    fn desktop_audio_v17_recovers_toward_freshness() {
        assert_eq!(
            DESKTOP_AUDIO_PLAYBACK_V3.capacity,
            DESKTOP_AUDIO_PLAYBACK_V2.capacity
        );
        assert_eq!(
            DESKTOP_AUDIO_PLAYBACK_V3.overflow,
            ProducerOverflowPolicy::DropOldest
        );
    }

    #[test]
    fn lane_pressure_counters_snapshot_monotonically() {
        let counters = LanePressureCountersV1::default();
        assert_eq!(counters.record_dropped_superseded(), 1);
        assert_eq!(counters.record_rejected(), 1);
        assert_eq!(counters.record_stale(), 1);
        assert_eq!(counters.record_fatal_deadline(), 1);
        assert_eq!(
            counters.snapshot(),
            LanePressureSnapshotV1 {
                dropped_superseded: 1,
                rejected: 1,
                stale: 1,
                fatal_deadline: 1,
            }
        );
    }

    #[test]
    fn host_video_has_no_backlog_and_fails_before_general_transport_stall() {
        assert_eq!(HOST_VIDEO_FRESHNESS_V1.max_frames_in_flight, 1);
        assert!(HOST_VIDEO_FRESHNESS_V1.max_capture_to_send_ms > 0);
        assert!(
            HOST_VIDEO_FRESHNESS_V1.max_send_stall_ms
                >= HOST_VIDEO_FRESHNESS_V1.max_capture_to_send_ms
        );
        assert!(HOST_VIDEO_FRESHNESS_V1.max_send_stall_ms < 15_000);
    }

    #[test]
    fn mobile_file_admission_has_a_fixed_byte_ceiling() {
        assert_eq!(MOBILE_FILE_TRANSFER_MAX_BYTES_V1, 104_857_600);
        assert!(MOBILE_FILE_TRANSFER_MAX_BYTES_V1 < usize::MAX);
    }

}
