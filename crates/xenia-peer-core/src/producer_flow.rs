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
            MOBILE_FILE_TRANSFER_EVENTS_V1,
        ] {
            assert!(policy.capacity > 0);
            assert!(policy.capacity <= 256);
        }
    }
}
