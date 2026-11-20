// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Deterministic, bounded scheduling policy for interactive Xenia sessions.
//!
//! This module is deliberately independent of transports, clocks, codecs,
//! authorization and operating-system effects. The caller supplies monotonic
//! ticks from one local clock domain and performs the actual send only after
//! selecting an item. A selected item is not proof of remote receipt,
//! decoding, presentation or effect commit.
//!
//! V0.1 uses weighted deficit round robin (WDRR) with byte-cost accounting.
//! Control transitions are ordered and non-coalescible; video is freshness-first
//! but preserves declared reference dependencies; audio is deadline-bound;
//! telemetry is coalesced by metric key; bulk transfer is bounded and never
//! silently superseded. Quantum weights are provisional benchmark parameters.

use std::collections::VecDeque;

/// Maximum number of recently dispatched video frame IDs retained for
/// dependency validation in this V0.1 policy model.
pub const VIDEO_REFERENCE_HISTORY: usize = 16;

const MAX_LANE_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_LANE_QUEUE_ITEMS: usize = 4_096;
const MIN_QUANTUM_BYTES: usize = 8 * 1024;

/// One scheduling class with a distinct delivery contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryClass {
    /// Ordered state transitions and session-control operations.
    Control,
    /// Decodable screen frames; stale work may be superseded safely.
    Video,
    /// Time-sensitive audio packets with explicit playout deadlines.
    Audio,
    /// Replaceable latest-value telemetry samples.
    Telemetry,
    /// Durable file-transfer chunks with bounded backpressure.
    Bulk,
}

impl DeliveryClass {
    const ALL: [Self; 5] = [
        Self::Control,
        Self::Video,
        Self::Audio,
        Self::Telemetry,
        Self::Bulk,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Video => 1,
            Self::Audio => 2,
            Self::Telemetry => 3,
            Self::Bulk => 4,
        }
    }
}

/// Semantically meaningful control transition carried by a non-droppable item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlTransition {
    /// A key became pressed.
    KeyDown,
    /// A key became released.
    KeyUp,
    /// A pointer button became pressed.
    ButtonDown,
    /// A pointer button became released.
    ButtonUp,
    /// A consent decision or consent-boundary update.
    Consent,
    /// A revocation signal.
    Revoke,
    /// A session key-epoch transition.
    Rekey,
    /// Another explicitly ordered control transition.
    Other,
}

/// Typed work identity and dependency information for one scheduling class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkKind {
    /// Ordered control event. Operation IDs are caller-created stable IDs;
    /// this scheduler does not interpret them as authorization.
    Control {
        /// Monotonic sequence within the caller's control stream.
        sequence: u64,
        /// Stable operation identity for deduplication/reconciliation upstream.
        operation_id: [u8; 16],
        /// Meaning of the state transition.
        transition: ControlTransition,
    },
    /// Video frame. `depends_on = None` denotes an independently decodable
    /// recovery point (for example, a keyframe). A delta names one required
    /// reference frame ID. V0.1 models one dependency per frame.
    Video {
        /// Unique frame identity within the session.
        frame_id: u64,
        /// Required reference frame, or `None` for an independent frame.
        depends_on: Option<u64>,
    },
    /// Audio packet in one ordered audio sequence.
    Audio {
        /// Monotonic sequence within the caller's audio stream.
        sequence: u64,
    },
    /// Replaceable latest-value telemetry sample.
    Telemetry {
        /// Stable metric key used to coalesce older queued values.
        metric_key: u16,
    },
    /// File-transfer chunk. The caller owns transfer-level verification,
    /// acknowledgement, retry and unknown-outcome reconciliation.
    Bulk {
        /// Stable transfer identity.
        transfer_id: [u8; 16],
        /// Byte offset within the transfer.
        offset: u64,
        /// Digest of this exact chunk.
        digest: [u8; 32],
    },
}

impl WorkKind {
    /// Return the delivery class associated with this typed work item.
    pub const fn class(&self) -> DeliveryClass {
        match self {
            Self::Control { .. } => DeliveryClass::Control,
            Self::Video { .. } => DeliveryClass::Video,
            Self::Audio { .. } => DeliveryClass::Audio,
            Self::Telemetry { .. } => DeliveryClass::Telemetry,
            Self::Bulk { .. } => DeliveryClass::Bulk,
        }
    }

    fn video_frame_id(&self) -> Option<u64> {
        match self {
            Self::Video { frame_id, .. } => Some(*frame_id),
            _ => None,
        }
    }

    fn video_dependency(&self) -> Option<Option<u64>> {
        match self {
            Self::Video { depends_on, .. } => Some(*depends_on),
            _ => None,
        }
    }
}

/// A payload-free scheduler descriptor. Payload bytes remain owned by the
/// transport/application pipeline; `cost_bytes` is accounting metadata only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkItem {
    /// Unique scheduler-local item identity.
    pub id: u64,
    /// Enqueue tick from this scheduler's local monotonic clock domain.
    pub enqueued_at_ticks: u64,
    /// Optional absolute local deadline in the same tick domain.
    pub deadline_ticks: Option<u64>,
    /// Bounded byte-cost estimate used for queue accounting.
    pub cost_bytes: usize,
    /// Typed delivery class and semantic identity.
    pub kind: WorkKind,
}

impl WorkItem {
    /// Return the item's delivery class.
    pub const fn class(&self) -> DeliveryClass {
        self.kind.class()
    }
}

/// Item-count and byte limits for one delivery class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneLimit {
    /// Maximum queued items for this class; must be non-zero.
    pub max_items: usize,
    /// Maximum queued byte-cost for this class; must be non-zero.
    pub max_bytes: usize,
    /// Optional maximum residence age in local monotonic ticks.
    pub max_age_ticks: Option<u64>,
}

/// Queue limits and age budgets for all five delivery classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Ordered-control queue limits.
    pub control: LaneLimit,
    /// Freshness-first video queue limits.
    pub video: LaneLimit,
    /// Deadline-bound audio queue limits.
    pub audio: LaneLimit,
    /// Latest-value telemetry queue limits.
    pub telemetry: LaneLimit,
    /// Durable bulk-transfer queue limits.
    pub bulk: LaneLimit,
    /// Per-visit byte quanta in Control, Video, Audio, Telemetry, Bulk order.
    /// These are provisional policy weights and must be benchmarked.
    pub quantum_bytes: [usize; 5],
}

impl SchedulerConfig {
    fn limit(self, class: DeliveryClass) -> LaneLimit {
        match class {
            DeliveryClass::Control => self.control,
            DeliveryClass::Video => self.video,
            DeliveryClass::Audio => self.audio,
            DeliveryClass::Telemetry => self.telemetry,
            DeliveryClass::Bulk => self.bulk,
        }
    }

    fn limits(self) -> [LaneLimit; 5] {
        [
            self.control,
            self.video,
            self.audio,
            self.telemetry,
            self.bulk,
        ]
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            control: LaneLimit {
                max_items: 256,
                max_bytes: 64 * 1024,
                max_age_ticks: None,
            },
            video: LaneLimit {
                max_items: 4,
                max_bytes: 16 * 1024 * 1024,
                max_age_ticks: Some(1_000),
            },
            audio: LaneLimit {
                max_items: 12,
                max_bytes: 256 * 1024,
                max_age_ticks: Some(100),
            },
            telemetry: LaneLimit {
                max_items: 32,
                max_bytes: 64 * 1024,
                max_age_ticks: Some(5_000),
            },
            bulk: LaneLimit {
                max_items: 16,
                max_bytes: 16 * 1024 * 1024,
                max_age_ticks: None,
            },
            quantum_bytes: [
                64 * 1024,
                256 * 1024,
                64 * 1024,
                16 * 1024,
                32 * 1024,
            ],
        }
    }
}

/// Configuration validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerConfigError {
    /// One or more lanes have a zero item or byte capacity.
    ZeroCapacity,
    /// A configured age budget is zero and would expire every item at enqueue.
    ZeroAgeBudget,
    /// A configured lane byte or item capacity exceeds its bounded work limit.
    CapacityTooLarge,
    /// A configured byte quantum is below the safe minimum for bounded selection work.
    QuantumTooSmall,
    /// A configured byte quantum exceeds its lane's byte capacity.
    QuantumExceedsLaneCapacity,
}

/// Explicit admission result. Coalescing and supersession are never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueDisposition {
    /// A new item was appended.
    Accepted,
    /// An older telemetry sample with the same key was replaced.
    Coalesced {
        /// ID of the replaced sample.
        replaced_id: u64,
    },
    /// A keyframe safely replaced an obsolete queued video dependency chain.
    Superseded {
        /// Number of queued video items removed.
        removed_items: usize,
    },
    /// Item was not admitted; the caller must handle the reason explicitly.
    Rejected(RejectReason),
}

/// Reason an item was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The item was already past its deadline or age budget on arrival.
    Expired,
    /// The enqueue tick is later than the supplied current tick.
    ClockRegression,
    /// The item has zero byte cost.
    ZeroCost,
    /// The item is larger than its lane's total byte capacity.
    TooLarge,
    /// The lane has no available item/byte capacity.
    Full,
    /// A control sequence was not strictly greater than the last admitted one.
    NonMonotonicControl,
    /// An audio sequence was not strictly greater than the last admitted one.
    NonMonotonicAudio,
    /// A video frame ID was not strictly greater than the last admitted one.
    NonMonotonicVideo,
    /// A delta frame references a frame not queued or known as dispatched.
    MissingVideoReference,
}

/// Bounded queue counters. These are local aggregate counts, not user data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulerStats {
    /// Newly admitted items, including accepted coalescing/supersession.
    pub accepted: u64,
    /// Replaced telemetry samples.
    pub coalesced: u64,
    /// Items intentionally superseded by independent video recovery points.
    pub superseded_video: u64,
    /// Items removed because their deadline or maximum age elapsed.
    pub expired: u64,
    /// Video deltas removed because a required queued reference was dropped.
    pub invalidated_video_dependencies: u64,
    /// Rejected admissions.
    pub rejected: u64,
    /// Items selected for dispatch.
    pub dispatched: u64,
    /// Selected caller-supplied byte-cost per lane, not measured wire bytes.
    pub selected_cost_bytes: [u64; 5],
    /// Number of once-per-round quantum grants to each lane.
    pub lane_visits: [u64; 5],
}

/// Snapshot of one class's bounded queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneSnapshot {
    /// Number of queued items.
    pub queued_items: usize,
    /// Total queued byte-cost.
    pub queued_bytes: usize,
    /// Configured item capacity.
    pub max_items: usize,
    /// Configured byte capacity.
    pub max_bytes: usize,
    /// Deficit credit currently earned but not yet spent.
    pub deficit_bytes: usize,
}

/// Read-only aggregate scheduler snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulerSnapshot {
    /// Queue state in Control, Video, Audio, Telemetry, Bulk order.
    pub lanes: [LaneSnapshot; 5],
    /// Aggregate local counters.
    pub stats: SchedulerStats,
}

#[derive(Debug, Default)]
struct LaneQueue {
    items: VecDeque<WorkItem>,
    bytes: usize,
}

impl LaneQueue {
    fn can_fit(&self, item: &WorkItem, limit: LaneLimit) -> bool {
        self.items.len() < limit.max_items
            && item.cost_bytes <= limit.max_bytes.saturating_sub(self.bytes)
    }

    fn push(&mut self, item: WorkItem) {
        self.bytes = self.bytes.saturating_add(item.cost_bytes);
        self.items.push_back(item);
    }

    fn pop(&mut self) -> Option<WorkItem> {
        let item = self.items.pop_front()?;
        self.bytes = self.bytes.saturating_sub(item.cost_bytes);
        Some(item)
    }

    fn remove(&mut self, index: usize) -> Option<WorkItem> {
        let item = self.items.remove(index)?;
        self.bytes = self.bytes.saturating_sub(item.cost_bytes);
        Some(item)
    }
}

/// Pure, deterministic session scheduler with bounded per-class queues.
///
/// Selection uses weighted deficit round robin (WDRR) in bytes, not item
/// counts. Each class accumulates its configured quantum while other classes
/// are visited; a queued item is selected only when its byte cost is covered.
/// This prevents large media/file items from being treated as equal-cost to
/// tiny control events, while preserving a positive service share for every
/// non-empty class. Quantum weights are provisional benchmark parameters.
#[derive(Debug)]
pub struct DeliveryScheduler {
    config: SchedulerConfig,
    queues: [LaneQueue; 5],
    cursor: usize,
    deficits: [usize; 5],
    visit_active: bool,
    max_visits_per_selection: usize,
    last_control_sequence: Option<u64>,
    last_audio_sequence: Option<u64>,
    last_video_frame_id: Option<u64>,
    known_video_references: VecDeque<u64>,
    stats: SchedulerStats,
}

impl DeliveryScheduler {
    /// Construct a scheduler after validating all queue limits.
    pub fn new(config: SchedulerConfig) -> Result<Self, SchedulerConfigError> {
        for limit in config.limits() {
            if limit.max_items == 0 || limit.max_bytes == 0 {
                return Err(SchedulerConfigError::ZeroCapacity);
            }
            if limit.max_bytes > MAX_LANE_QUEUE_BYTES
                || limit.max_items > MAX_LANE_QUEUE_ITEMS
            {
                return Err(SchedulerConfigError::CapacityTooLarge);
            }
            if limit.max_age_ticks == Some(0) {
                return Err(SchedulerConfigError::ZeroAgeBudget);
            }
        }
        if config
            .quantum_bytes
            .iter()
            .any(|quantum| *quantum < MIN_QUANTUM_BYTES)
        {
            return Err(SchedulerConfigError::QuantumTooSmall);
        }
        for class in DeliveryClass::ALL {
            if config.quantum_bytes[class.index()] > config.limit(class).max_bytes {
                return Err(SchedulerConfigError::QuantumExceedsLaneCapacity);
            }
        }
        let max_lane_bytes = config
            .limits()
            .iter()
            .map(|limit| limit.max_bytes)
            .max()
            .unwrap_or(0);
        let min_quantum = config
            .quantum_bytes
            .iter()
            .copied()
            .min()
            .unwrap_or(MIN_QUANTUM_BYTES);
        let rounds = max_lane_bytes
            .saturating_add(min_quantum - 1)
            / min_quantum
            + 1;
        let max_visits_per_selection = rounds.saturating_mul(DeliveryClass::ALL.len());
        Ok(Self {
            config,
            queues: std::array::from_fn(|_| LaneQueue::default()),
            cursor: 0,
            deficits: [0; 5],
            visit_active: false,
            max_visits_per_selection,
            last_control_sequence: None,
            last_audio_sequence: None,
            last_video_frame_id: None,
            known_video_references: VecDeque::new(),
            stats: SchedulerStats::default(),
        })
    }

    /// Admit one item using the caller's current local monotonic tick.
    ///
    /// The caller must use the same tick domain for enqueue, deadline and
    /// selection within this scheduler instance. No host/viewer clock
    /// comparison is performed here.
    pub fn enqueue(&mut self, item: WorkItem, now_ticks: u64) -> EnqueueDisposition {
        if item.enqueued_at_ticks > now_ticks {
            return self.reject(RejectReason::ClockRegression);
        }
        if item.cost_bytes == 0 {
            return self.reject(RejectReason::ZeroCost);
        }

        let class = item.class();
        let limit = self.config.limit(class);
        if item.cost_bytes > limit.max_bytes {
            return self.reject(RejectReason::TooLarge);
        }

        self.prune_expired(now_ticks);
        if Self::is_expired(&item, now_ticks, limit) {
            return self.reject(RejectReason::Expired);
        }

        let control_sequence = match &item.kind {
            WorkKind::Control { sequence, .. } => Some(*sequence),
            _ => None,
        };
        if control_sequence.is_some_and(|sequence| {
            self.last_control_sequence
                .is_some_and(|previous| sequence <= previous)
        }) {
            return self.reject(RejectReason::NonMonotonicControl);
        }
        let audio_sequence = match &item.kind {
            WorkKind::Audio { sequence } => Some(*sequence),
            _ => None,
        };
        if audio_sequence.is_some_and(|sequence| {
            self.last_audio_sequence
                .is_some_and(|previous| sequence <= previous)
        }) {
            return self.reject(RejectReason::NonMonotonicAudio);
        }

        let video_frame_id = item.kind.video_frame_id();
        if video_frame_id.is_some_and(|frame_id| {
            self.last_video_frame_id
                .is_some_and(|previous| frame_id <= previous)
        }) {
            return self.reject(RejectReason::NonMonotonicVideo);
        }

        let video_delta_reference = match &item.kind {
            WorkKind::Video {
                frame_id,
                depends_on: Some(reference),
            } => {
                if frame_id == reference {
                    return self.reject(RejectReason::MissingVideoReference);
                }
                Some(*reference)
            }
            _ => None,
        };
        if let Some(reference) = video_delta_reference {
            let pending_reference = self.queues[DeliveryClass::Video.index()]
                .items
                .iter()
                .any(|queued| queued.kind.video_frame_id() == Some(reference));
            if !self.known_video_references.contains(&reference) && !pending_reference {
                return self.reject(RejectReason::MissingVideoReference);
            }
        }

        let telemetry_key = match &item.kind {
            WorkKind::Telemetry { metric_key } => Some(*metric_key),
            _ => None,
        };
        if let Some(metric_key) = telemetry_key {
            let queue = &mut self.queues[DeliveryClass::Telemetry.index()];
            if let Some(index) = queue.items.iter().position(|queued| {
                matches!(
                    &queued.kind,
                    WorkKind::Telemetry {
                        metric_key: existing
                    } if *existing == metric_key
                )
            }) {
                let (old_cost, replaced_id) = match queue.items.get(index) {
                    Some(old) => (old.cost_bytes, old.id),
                    None => {
                        self.stats.rejected = self.stats.rejected.saturating_add(1);
                        return EnqueueDisposition::Rejected(RejectReason::Full);
                    }
                };
                let new_bytes = queue
                    .bytes
                    .saturating_sub(old_cost)
                    .saturating_add(item.cost_bytes);
                if new_bytes > limit.max_bytes {
                    self.stats.rejected = self.stats.rejected.saturating_add(1);
                    return EnqueueDisposition::Rejected(RejectReason::Full);
                }
                if queue.remove(index).is_none() {
                    self.stats.rejected = self.stats.rejected.saturating_add(1);
                    return EnqueueDisposition::Rejected(RejectReason::Full);
                }
                queue.push(item);
                self.stats.accepted = self.stats.accepted.saturating_add(1);
                self.stats.coalesced = self.stats.coalesced.saturating_add(1);
                return EnqueueDisposition::Coalesced { replaced_id };
            }
        }

        let is_video_keyframe = matches!(
            &item.kind,
            WorkKind::Video {
                depends_on: None,
                ..
            }
        );
        if is_video_keyframe {
            let queue = &mut self.queues[DeliveryClass::Video.index()];
            let removed = queue.items.len();
            queue.items.clear();
            queue.bytes = 0;
            self.deficits[DeliveryClass::Video.index()] = 0;
            if self.cursor == DeliveryClass::Video.index() {
                self.visit_active = false;
            }
            self.known_video_references.clear();
            queue.push(item);
            self.last_video_frame_id = video_frame_id;
            self.stats.superseded_video = self
                .stats
                .superseded_video
                .saturating_add(removed as u64);
            self.stats.accepted = self.stats.accepted.saturating_add(1);
            return if removed == 0 {
                EnqueueDisposition::Accepted
            } else {
                EnqueueDisposition::Superseded {
                    removed_items: removed,
                }
            };
        }
        let queue = &mut self.queues[class.index()];
        if queue.can_fit(&item, limit) {
            if let Some(sequence) = control_sequence {
                self.last_control_sequence = Some(sequence);
            }
            if let Some(sequence) = audio_sequence {
                self.last_audio_sequence = Some(sequence);
            }
            if let Some(frame_id) = video_frame_id {
                self.last_video_frame_id = Some(frame_id);
            }
            queue.push(item);
            self.stats.accepted = self.stats.accepted.saturating_add(1);
            return EnqueueDisposition::Accepted;
        }

        // Under pressure, a newer video sibling may replace only the final
        // queued frame when both depend on the same reference. It is safe
        // because no queued child can reference the removed tail.
        if let WorkKind::Video {
            depends_on: Some(new_reference),
            ..
        } = &item.kind
        {
            if let Some(index) = queue.items.len().checked_sub(1) {
                let replaceable = queue.items.get(index).is_some_and(|last| {
                    last.kind.video_dependency() == Some(Some(*new_reference))
                });
                if replaceable {
                    let (old_cost, replaced_id) = match queue.items.get(index) {
                        Some(old) => (old.cost_bytes, old.id),
                        None => {
                            self.stats.rejected = self.stats.rejected.saturating_add(1);
                            return EnqueueDisposition::Rejected(RejectReason::Full);
                        }
                    };
                    let new_bytes = queue
                        .bytes
                        .saturating_sub(old_cost)
                        .saturating_add(item.cost_bytes);
                    if new_bytes <= limit.max_bytes && queue.remove(index).is_some() {
                        queue.push(item);
                        self.last_video_frame_id = video_frame_id;
                        self.stats.accepted = self.stats.accepted.saturating_add(1);
                        self.stats.coalesced = self.stats.coalesced.saturating_add(1);
                        return EnqueueDisposition::Coalesced { replaced_id };
                    }
                }
            }
        }

        self.reject(RejectReason::Full)
    }

    /// Select the next eligible item using weighted deficit round robin.
    ///
    /// Expired audio, video and telemetry items are pruned first. Control and
    /// bulk work is never aged out by this scheduler. A selected item is only
    /// a local dispatch decision, not proof of remote observation or commit.
    pub fn next_ready(&mut self, now_ticks: u64) -> Option<WorkItem> {
        self.prune_expired(now_ticks);
        if self.queues.iter().all(|queue| queue.items.is_empty()) {
            self.deficits = [0; 5];
            self.visit_active = false;
            return None;
        }

        for _ in 0..self.max_visits_per_selection {
            let class = DeliveryClass::ALL[self.cursor];
            let index = class.index();
            let front_cost = self.queues[index]
                .items
                .front()
                .map(|item| item.cost_bytes);

            let Some(cost_bytes) = front_cost else {
                self.deficits[index] = 0;
                self.cursor = (self.cursor + 1) % DeliveryClass::ALL.len();
                self.visit_active = false;
                continue;
            };

            // Add one quantum only when entering this class's visit. A class
            // may dispatch multiple items while its accumulated deficit covers
            // them, but it cannot mint a new quantum until every other class
            // has had its turn.
            if !self.visit_active {
                self.deficits[index] =
                    self.deficits[index].saturating_add(self.config.quantum_bytes[index]);
                self.stats.lane_visits[index] =
                    self.stats.lane_visits[index].saturating_add(1);
                self.visit_active = true;
            }

            if self.deficits[index] >= cost_bytes {
                if let Some(item) = self.queues[index].pop() {
                    self.deficits[index] -= cost_bytes;
                    self.stats.dispatched = self.stats.dispatched.saturating_add(1);
                    self.stats.selected_cost_bytes[index] = self.stats.dispatched_bytes[index]
                        .saturating_add(item.cost_bytes as u64);
                    if self.queues[index].items.is_empty() {
                        self.deficits[index] = 0;
                        self.cursor = (self.cursor + 1) % DeliveryClass::ALL.len();
                        self.visit_active = false;
                    }
                    return Some(item);
                }
            }

            // The current visit has insufficient deficit for the head item.
            // Retain unused credits for the next round, then yield to the next
            // class instead of replenishing this lane repeatedly.
            self.cursor = (self.cursor + 1) % DeliveryClass::ALL.len();
            self.visit_active = false;
        }
        None
    }

    /// Record that a video frame was successfully handed to the ordered
    /// transport stream. This does not prove remote receipt or presentation.
    ///
    /// A caller must not invoke this after an ambiguous send result; the
    /// session should be closed/reconciled instead.
    pub fn record_video_dispatched(&mut self, frame_id: u64) {
        if self.known_video_references.contains(&frame_id) {
            return;
        }
        self.known_video_references.push_back(frame_id);
        while self.known_video_references.len() > VIDEO_REFERENCE_HISTORY {
            self.known_video_references.pop_front();
        }
    }

    /// Invalidate queued deltas that depend on a video frame known not to
    /// have been sent. This must only be called when the transport proves the
    /// selected frame was not sent. For an ambiguous send outcome, stop the
    /// session and reconcile; do not infer failure or retry a state mutation.
    ///
    /// Returns the number of queued dependent frames removed.
    pub fn invalidate_video_after_known_send_failure(&mut self, frame_id: u64) -> usize {
        let queue = &mut self.queues[DeliveryClass::Video.index()];
        let mut invalidated = VecDeque::from([frame_id]);
        let mut retained = VecDeque::new();
        let mut removed = 0_u64;

        while let Some(item) = queue.pop() {
            let depends_on = item.kind.video_dependency().flatten();
            if depends_on.is_some_and(|reference| invalidated.contains(&reference)) {
                if let Some(dependent_id) = item.kind.video_frame_id() {
                    invalidated.push_back(dependent_id);
                }
                removed = removed.saturating_add(1);
            } else {
                retained.push_back(item);
            }
        }

        while let Some(item) = retained.pop_front() {
            queue.push(item);
        }
        self.stats.invalidated_video_dependencies = self
            .stats
            .invalidated_video_dependencies
            .saturating_add(removed);
        removed as usize
    }

    /// Install an externally established decoder reference, for example
    /// after a new session/keyframe context is established.
    ///
    /// Any queued video from the previous decoder context is discarded,
    /// because its reference chain cannot be assumed valid. The method resets
    /// video-lane deficit state and returns the number of queued frames
    /// discarded. This is not a photon or presentation acknowledgement.
    pub fn set_initial_video_reference(&mut self, frame_id: u64) -> usize {
        let index = DeliveryClass::Video.index();
        let queue = &mut self.queues[index];
        let removed = queue.items.len();
        queue.items.clear();
        queue.bytes = 0;
        self.deficits[index] = 0;
        if self.cursor == index {
            self.visit_active = false;
        }
        self.stats.superseded_video = self
            .stats
            .superseded_video
            .saturating_add(removed as u64);
        self.known_video_references.clear();
        self.known_video_references.push_back(frame_id);
        self.last_video_frame_id = Some(frame_id);
        removed
    }

    /// Return a bounded snapshot of queue occupancy and local counters.
    pub fn snapshot(&self) -> SchedulerSnapshot {
        let mut lanes = [LaneSnapshot::default(); 5];
        for class in DeliveryClass::ALL {
            let queue = &self.queues[class.index()];
            let limit = self.config.limit(class);
            lanes[class.index()] = LaneSnapshot {
                queued_items: queue.items.len(),
                queued_bytes: queue.bytes,
                max_items: limit.max_items,
                max_bytes: limit.max_bytes,
                deficit_bytes: self.deficits[class.index()],
            };
        }
        SchedulerSnapshot {
            lanes,
            stats: self.stats,
        }
    }

    fn reject(&mut self, reason: RejectReason) -> EnqueueDisposition {
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        EnqueueDisposition::Rejected(reason)
    }

    fn is_expired(item: &WorkItem, now_ticks: u64, limit: LaneLimit) -> bool {
        if matches!(item.class(), DeliveryClass::Control | DeliveryClass::Bulk) {
            return false;
        }
        if item.deadline_ticks.is_some_and(|deadline| now_ticks >= deadline) {
            return true;
        }
        limit.max_age_ticks.is_some_and(|max_age| {
            now_ticks.saturating_sub(item.enqueued_at_ticks) >= max_age
        })
    }

    fn prune_expired(&mut self, now_ticks: u64) {
        let video_limit = self.config.video;
        let video = &mut self.queues[DeliveryClass::Video.index()];
        let mut invalidated = Vec::new();
        let mut retained = VecDeque::new();
        while let Some(item) = video.pop() {
            let frame_id = item.kind.video_frame_id();
            let depends_on = item.kind.video_dependency().flatten();
            let expired = Self::is_expired(&item, now_ticks, video_limit);
            let depends_on_invalid = depends_on
                .is_some_and(|reference| invalidated.contains(&reference));
            if expired || depends_on_invalid {
                if let Some(id) = frame_id {
                    invalidated.push(id);
                }
                if expired {
                    self.stats.expired = self.stats.expired.saturating_add(1);
                } else {
                    self.stats.invalidated_video_dependencies = self
                        .stats
                        .invalidated_video_dependencies
                        .saturating_add(1);
                }
            } else {
                retained.push_back(item);
            }
        }
        while let Some(item) = retained.pop_front() {
            video.push(item);
        }

        for class in [DeliveryClass::Audio, DeliveryClass::Telemetry] {
            let limit = self.config.limit(class);
            let queue = &mut self.queues[class.index()];
            let mut retained = VecDeque::new();
            while let Some(item) = queue.pop() {
                if Self::is_expired(&item, now_ticks, limit) {
                    self.stats.expired = self.stats.expired.saturating_add(1);
                } else {
                    retained.push_back(item);
                }
            }
            while let Some(item) = retained.pop_front() {
                queue.push(item);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(
        id: u64,
        enqueued_at_ticks: u64,
        deadline_ticks: Option<u64>,
        cost_bytes: usize,
        kind: WorkKind,
    ) -> WorkItem {
        WorkItem {
            id,
            enqueued_at_ticks,
            deadline_ticks,
            cost_bytes,
            kind,
        }
    }

    fn new_scheduler(config: SchedulerConfig) -> DeliveryScheduler {
        DeliveryScheduler::new(config)
            .unwrap_or_else(|error| panic!("valid scheduler config rejected: {error:?}"))
    }

    fn selected(scheduler: &mut DeliveryScheduler, now_ticks: u64) -> WorkItem {
        scheduler
            .next_ready(now_ticks)
            .unwrap_or_else(|| panic!("expected an eligible queued item"))
    }

    fn control(id: u64, sequence: u64) -> WorkItem {
        item(
            id,
            0,
            None,
            8,
            WorkKind::Control {
                sequence,
                operation_id: [sequence as u8; 16],
                transition: ControlTransition::KeyUp,
            },
        )
    }

    fn video(id: u64, frame_id: u64, depends_on: Option<u64>, deadline: Option<u64>) -> WorkItem {
        item(
            id,
            0,
            deadline,
            128,
            WorkKind::Video {
                frame_id,
                depends_on,
            },
        )
    }

    fn audio(id: u64, sequence: u64, deadline: u64) -> WorkItem {
        item(
            id,
            0,
            Some(deadline),
            64,
            WorkKind::Audio { sequence },
        )
    }

    fn config_with_capacity(items: usize) -> SchedulerConfig {
        let lane = LaneLimit {
            max_items: items,
            max_bytes: 1024 * 1024,
            max_age_ticks: None,
        };
        SchedulerConfig {
            control: lane,
            video: lane,
            audio: lane,
            telemetry: lane,
            bulk: lane,
            quantum_bytes: [
                MIN_QUANTUM_BYTES,
                MIN_QUANTUM_BYTES,
                MIN_QUANTUM_BYTES,
                MIN_QUANTUM_BYTES,
                MIN_QUANTUM_BYTES,
            ],
        }
    }

    #[test]
    fn control_transitions_are_ordered_and_non_monotonic_sequences_rejected() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(scheduler.enqueue(control(1, 1), 0), EnqueueDisposition::Accepted);
        assert_eq!(scheduler.enqueue(control(2, 2), 0), EnqueueDisposition::Accepted);
        assert_eq!(
            scheduler.enqueue(control(3, 1), 0),
            EnqueueDisposition::Rejected(RejectReason::NonMonotonicControl)
        );
        assert_eq!(selected(&mut scheduler, 0).id, 1);
        assert_eq!(selected(&mut scheduler, 0).id, 2);
    }

    #[test]
    fn full_control_queue_rejects_explicitly_without_losing_existing_transition() {
        let mut config = SchedulerConfig::default();
        config.control.max_items = 1;
        let mut scheduler = new_scheduler(config);
        assert_eq!(scheduler.enqueue(control(1, 1), 0), EnqueueDisposition::Accepted);
        assert_eq!(
            scheduler.enqueue(control(2, 2), 0),
            EnqueueDisposition::Rejected(RejectReason::Full)
        );
        assert_eq!(selected(&mut scheduler, 0).id, 1);
        assert_eq!(scheduler.enqueue(control(2, 2), 0), EnqueueDisposition::Accepted);
    }

    #[test]
    fn telemetry_coalesces_only_the_same_metric_key() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        let first = item(1, 0, None, 16, WorkKind::Telemetry { metric_key: 7 });
        let second = item(2, 1, None, 16, WorkKind::Telemetry { metric_key: 7 });
        assert_eq!(scheduler.enqueue(first, 0), EnqueueDisposition::Accepted);
        assert_eq!(
            scheduler.enqueue(second, 1),
            EnqueueDisposition::Coalesced { replaced_id: 1 }
        );
        let selected = selected(&mut scheduler, 1);
        assert_eq!(selected.id, 2);
        assert_eq!(scheduler.snapshot().stats.coalesced, 1);

        let second_metric = item(
            3,
            2,
            None,
            16,
            WorkKind::Telemetry { metric_key: 8 },
        );
        assert_eq!(
            scheduler.enqueue(second_metric, 2),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.snapshot().lanes[DeliveryClass::Telemetry.index()].queued_items,
            2
        );
    }

    #[test]
    fn independent_video_frame_supersedes_pending_dependency_chain() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(scheduler.enqueue(video(1, 10, None, None), 0), EnqueueDisposition::Accepted);
        assert_eq!(
            scheduler.enqueue(video(2, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(3, 20, None, None), 0),
            EnqueueDisposition::Superseded { removed_items: 2 }
        );
        assert_eq!(scheduler.snapshot().lanes[DeliveryClass::Video.index()].queued_items, 1);
        assert_eq!(selected(&mut scheduler, 0).id, 3);
    }

    #[test]
    fn stale_video_reference_invalidates_its_dependent_delta_chain() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(
            scheduler.enqueue(video(1, 10, None, Some(5)), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(2, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(3, 12, Some(11), None), 0),
            EnqueueDisposition::Accepted
        );
        assert!(scheduler.next_ready(5).is_none());
        assert_eq!(scheduler.snapshot().lanes[DeliveryClass::Video.index()].queued_items, 0);
        assert_eq!(scheduler.snapshot().stats.expired, 1);
        assert_eq!(
            scheduler.snapshot().stats.invalidated_video_dependencies,
            2
        );
    }

    #[test]
    fn delta_frame_without_a_queued_or_dispatched_reference_is_rejected() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(
            scheduler.enqueue(video(1, 11, Some(10), None), 0),
            EnqueueDisposition::Rejected(RejectReason::MissingVideoReference)
        );
        scheduler.set_initial_video_reference(10);
        assert_eq!(
            scheduler.enqueue(video(2, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
    }

    #[test]
    fn video_frame_id_must_be_strictly_monotonic() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(
            scheduler.enqueue(video(1, 10, None, None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(2, 9, None, None), 0),
            EnqueueDisposition::Rejected(RejectReason::NonMonotonicVideo)
        );
        assert_eq!(
            scheduler.enqueue(video(3, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
    }

    #[test]
    fn audio_sequence_must_be_strictly_monotonic() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(
            scheduler.enqueue(audio(1, 2, u64::MAX), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(audio(2, 1, u64::MAX), 0),
            EnqueueDisposition::Rejected(RejectReason::NonMonotonicAudio)
        );
        assert_eq!(
            scheduler.enqueue(audio(3, 3, u64::MAX), 0),
            EnqueueDisposition::Accepted
        );
    }

    #[test]
    fn known_unsent_video_frame_invalidates_only_its_dependent_chain() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        scheduler.set_initial_video_reference(5);
        assert_eq!(
            scheduler.enqueue(video(1, 10, Some(5), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(2, 20, Some(5), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(3, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(selected(&mut scheduler, 0).id, 1);
        assert_eq!(scheduler.invalidate_video_after_known_send_failure(10), 1);
        assert_eq!(
            scheduler.snapshot().lanes[DeliveryClass::Video.index()].queued_items,
            1
        );
        assert_eq!(selected(&mut scheduler, 0).id, 2);
    }

    #[test]
    fn excessive_item_count_capacity_is_rejected() {
        let mut config = SchedulerConfig::default();
        config.telemetry.max_items = MAX_LANE_QUEUE_ITEMS + 1;
        assert_eq!(
            DeliveryScheduler::new(config).err(),
            Some(SchedulerConfigError::CapacityTooLarge)
        );
    }

    #[test]
    fn audio_after_deadline_is_not_dispatched() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        assert_eq!(scheduler.enqueue(audio(1, 1, 5), 0), EnqueueDisposition::Accepted);
        assert!(scheduler.next_ready(5).is_none());
        assert_eq!(scheduler.snapshot().stats.expired, 1);
    }

    #[test]
    fn bulk_transfer_is_never_expired_by_media_age_policy() {
        let mut config = SchedulerConfig::default();
        config.bulk.max_age_ticks = Some(1);
        let mut scheduler = new_scheduler(config);
        let chunk = item(
            1,
            0,
            Some(1),
            32,
            WorkKind::Bulk {
                transfer_id: [9; 16],
                offset: 0,
                digest: [7; 32],
            },
        );
        assert_eq!(scheduler.enqueue(chunk, 0), EnqueueDisposition::Accepted);
        assert_eq!(selected(&mut scheduler, 10_000).id, 1);
    }

    #[test]
    fn weighted_deficit_services_every_backlogged_class_by_byte_cost() {
        let mut config = config_with_capacity(8);
        config.quantum_bytes = [
            MIN_QUANTUM_BYTES,
            4 * MIN_QUANTUM_BYTES,
            MIN_QUANTUM_BYTES,
            MIN_QUANTUM_BYTES,
            2 * MIN_QUANTUM_BYTES,
        ];
        let mut scheduler = new_scheduler(config);
        let large_cost = 128 * 1024;

        assert_eq!(
            scheduler.enqueue(
                item(
                    1,
                    0,
                    None,
                    large_cost,
                    WorkKind::Control {
                        sequence: 1,
                        operation_id: [1; 16],
                        transition: ControlTransition::KeyUp,
                    }
                ),
                0
            ),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(
                item(
                    2,
                    0,
                    None,
                    large_cost,
                    WorkKind::Video {
                        frame_id: 20,
                        depends_on: None,
                    }
                ),
                0
            ),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(
                item(
                    3,
                    0,
                    Some(u64::MAX),
                    large_cost,
                    WorkKind::Audio { sequence: 1 }
                ),
                0
            ),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(
                item(
                    4,
                    0,
                    None,
                    large_cost,
                    WorkKind::Telemetry { metric_key: 1 }
                ),
                0
            ),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(
                item(
                    5,
                    0,
                    None,
                    large_cost,
                    WorkKind::Bulk {
                        transfer_id: [1; 16],
                        offset: 0,
                        digest: [2; 32],
                    }
                ),
                0
            ),
            EnqueueDisposition::Accepted
        );

        let mut selected_classes = [false; 5];
        for _ in 0..5 {
            let next = selected(&mut scheduler, 0);
            selected_classes[next.class().index()] = true;
        }
        assert!(selected_classes.iter().all(|selected| *selected));
    }

    #[test]
    fn wdrr_service_lag_stays_within_one_maximum_item_per_visit() {
        let mut config = config_with_capacity(128);
        config.quantum_bytes = [
            MIN_QUANTUM_BYTES,
            MIN_QUANTUM_BYTES + 4 * 1024,
            MIN_QUANTUM_BYTES + 8 * 1024,
            MIN_QUANTUM_BYTES + 12 * 1024,
            MIN_QUANTUM_BYTES + 16 * 1024,
        ];
        let mut scheduler = new_scheduler(config);
        scheduler.set_initial_video_reference(0);
        let sizes = [4 * 1024, 16 * 1024, 8 * 1024, 12 * 1024];
        let max_item_bytes = [16 * 1024; 5];

        for sequence in 1..=64_u64 {
            let size = sizes[((sequence - 1) as usize) % sizes.len()];
            assert_eq!(
                scheduler.enqueue(
                    item(
                        sequence,
                        0,
                        None,
                        size,
                        WorkKind::Control {
                            sequence,
                            operation_id: [sequence as u8; 16],
                            transition: ControlTransition::KeyDown,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        100 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Video {
                            frame_id: sequence,
                            depends_on: Some(sequence - 1),
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        200 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Audio { sequence },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        300 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Telemetry {
                            metric_key: sequence as u16,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        400 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Bulk {
                            transfer_id: [7; 16],
                            offset: sequence,
                            digest: [sequence as u8; 32],
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
        }

        for _ in 0..100 {
            let next = selected(&mut scheduler, 0);
            if let WorkKind::Video { frame_id, .. } = next.kind {
                scheduler.record_video_dispatched(frame_id);
            }
        }

        let snapshot = scheduler.snapshot();
        for class in DeliveryClass::ALL {
            let index = class.index();
            let quantum = scheduler.config.quantum_bytes[index] as u64;
            let visits = snapshot.stats.lane_visits[index];
            let served = snapshot.stats.selected_cost_bytes[index];
            let deficit = snapshot.lanes[index].deficit_bytes as u64;
            assert!(
                served
                    .saturating_add(deficit)
                    .saturating_add(max_item_bytes[index] as u64)
                    >= visits.saturating_mul(quantum),
                "lane {class:?}: {served}+{deficit} < {visits}*{quantum}"
            );
            assert!(
                snapshot.lanes[index].queued_items > 0,
                "class {class:?} must remain backlogged"
            );
        }
    }

    #[test]
    fn wdrr_accounting_matches_quantum_grants_under_continuous_backlog() {
        let mut config = config_with_capacity(128);
        config.quantum_bytes = [
            MIN_QUANTUM_BYTES,
            MIN_QUANTUM_BYTES + 4 * 1024,
            MIN_QUANTUM_BYTES + 8 * 1024,
            MIN_QUANTUM_BYTES + 12 * 1024,
            MIN_QUANTUM_BYTES + 16 * 1024,
        ];
        let mut scheduler = new_scheduler(config);
        scheduler.set_initial_video_reference(0);
        let sizes = [4 * 1024, 16 * 1024, 8 * 1024, 12 * 1024];
        let max_item_bytes = [16 * 1024; 5];

        for sequence in 1..=64_u64 {
            let size = sizes[((sequence - 1) as usize) % sizes.len()];
            assert_eq!(
                scheduler.enqueue(
                    item(
                        sequence,
                        0,
                        None,
                        size,
                        WorkKind::Control {
                            sequence,
                            operation_id: [sequence as u8; 16],
                            transition: ControlTransition::KeyDown,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        100 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Video {
                            frame_id: sequence,
                            depends_on: Some(sequence - 1),
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        200 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Audio { sequence },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        300 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Telemetry {
                            metric_key: sequence as u16,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        400 + sequence,
                        0,
                        None,
                        size,
                        WorkKind::Bulk {
                            transfer_id: [7; 16],
                            offset: sequence,
                            digest: [sequence as u8; 32],
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
        }

        for _ in 0..100 {
            let next = selected(&mut scheduler, 0);
            if let WorkKind::Video { frame_id, .. } = next.kind {
                scheduler.record_video_dispatched(frame_id);
            }
        }

        let snapshot = scheduler.snapshot();
        for class in DeliveryClass::ALL {
            let index = class.index();
            let quantum = scheduler.config.quantum_bytes[index] as u64;
            let visits = snapshot.stats.lane_visits[index];
            let served = snapshot.stats.dispatched_bytes[index];
            let deficit = snapshot.lanes[index].deficit_bytes as u64;
            assert_eq!(
                served.saturating_add(deficit),
                visits.saturating_mul(quantum),
                "lane {class:?}: service plus deficit must equal granted quanta"
            );
            assert!(
                snapshot.lanes[index].queued_items > 0,
                "class {class:?} must remain continuously backlogged"
            );
            if !(scheduler.visit_active && scheduler.cursor == index) {
                assert!(
                    deficit < max_item_bytes[index] as u64,
                    "inactive lane {class:?} must retain less than one maximum item"
                );
            }
        }
    }

    #[test]
    fn deficit_round_robin_yields_after_each_class_quantum() {
        let mut config = config_with_capacity(8);
        config.quantum_bytes = [MIN_QUANTUM_BYTES; 5];
        let mut scheduler = new_scheduler(config);
        scheduler.set_initial_video_reference(0);

        let item_cost = MIN_QUANTUM_BYTES;
        for sequence in 1..=2_u64 {
            assert_eq!(
                scheduler.enqueue(
                    item(
                        sequence,
                        0,
                        None,
                        item_cost,
                        WorkKind::Control {
                            sequence,
                            operation_id: [sequence as u8; 16],
                            transition: ControlTransition::KeyUp,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        10 + sequence,
                        0,
                        None,
                        item_cost,
                        WorkKind::Video {
                            frame_id: sequence,
                            depends_on: Some(sequence - 1),
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        20 + sequence,
                        0,
                        None,
                        item_cost,
                        WorkKind::Audio { sequence },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        30 + sequence,
                        0,
                        None,
                        item_cost,
                        WorkKind::Telemetry {
                            metric_key: sequence as u16,
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
            assert_eq!(
                scheduler.enqueue(
                    item(
                        40 + sequence,
                        0,
                        None,
                        item_cost,
                        WorkKind::Bulk {
                            transfer_id: [4; 16],
                            offset: sequence,
                            digest: [sequence as u8; 32],
                        },
                    ),
                    0,
                ),
                EnqueueDisposition::Accepted
            );
        }

        let expected = [
            DeliveryClass::Control,
            DeliveryClass::Video,
            DeliveryClass::Audio,
            DeliveryClass::Telemetry,
            DeliveryClass::Bulk,
            DeliveryClass::Control,
            DeliveryClass::Video,
            DeliveryClass::Audio,
            DeliveryClass::Telemetry,
            DeliveryClass::Bulk,
        ];
        for class in expected {
            let next = selected(&mut scheduler, 0);
            assert_eq!(next.class(), class);
            if let WorkKind::Video { frame_id, .. } = next.kind {
                scheduler.record_video_dispatched(frame_id);
            }
        }
    }

    #[test]
    fn all_queue_capacities_remain_within_configured_bounds() {
        let mut scheduler = new_scheduler(config_with_capacity(8));
        scheduler.set_initial_video_reference(0);
        for sequence in 1..=8 {
            let _ = scheduler.enqueue(control(sequence, sequence), 0);
            let _ = scheduler.enqueue(video(100 + sequence, sequence, Some(sequence - 1), None), 0);
            let _ = scheduler.enqueue(audio(200 + sequence, sequence, u64::MAX), 0);
            let _ = scheduler.enqueue(
                item(
                    300 + sequence,
                    0,
                    None,
                    8,
                    WorkKind::Telemetry {
                        metric_key: sequence as u16,
                    },
                ),
                0,
            );
            let _ = scheduler.enqueue(
                item(
                    400 + sequence,
                    0,
                    None,
                    8,
                    WorkKind::Bulk {
                        transfer_id: [2; 16],
                        offset: sequence,
                        digest: [sequence as u8; 32],
                    },
                ),
                0,
            );
            let snapshot = scheduler.snapshot();
            for lane in snapshot.lanes {
                assert!(lane.queued_items <= lane.max_items);
                assert!(lane.queued_bytes <= lane.max_bytes);
            }
        }
    }

    #[test]
    fn keyframe_resets_old_reference_history() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        scheduler.set_initial_video_reference(10);
        assert_eq!(
            scheduler.enqueue(video(1, 20, None, None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(2, 21, Some(10), None), 0),
            EnqueueDisposition::Rejected(RejectReason::MissingVideoReference)
        );
        assert_eq!(
            scheduler.enqueue(video(3, 21, Some(20), None), 0),
            EnqueueDisposition::Accepted
        );
    }

    #[test]
    fn control_transition_is_not_aged_out() {
        let mut config = SchedulerConfig::default();
        config.control.max_age_ticks = Some(1);
        let mut scheduler = new_scheduler(config);
        let transition = item(
            1,
            0,
            Some(1),
            8,
            WorkKind::Control {
                sequence: 1,
                operation_id: [3; 16],
                transition: ControlTransition::ButtonUp,
            },
        );
        assert_eq!(
            scheduler.enqueue(transition, 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(selected(&mut scheduler, 10).id, 1);
    }

    #[test]
    fn full_video_queue_coalesces_only_an_unreferenced_tail_sibling() {
        let mut config = SchedulerConfig::default();
        config.video.max_items = 2;
        config.video.max_bytes = 1024;
        let mut scheduler = new_scheduler(config);
        scheduler.set_initial_video_reference(10);
        let first = item(
            1,
            0,
            None,
            400,
            WorkKind::Video {
                frame_id: 11,
                depends_on: Some(10),
            },
        );
        let second = item(
            2,
            0,
            None,
            400,
            WorkKind::Video {
                frame_id: 12,
                depends_on: Some(10),
            },
        );
        let third = item(
            3,
            0,
            None,
            400,
            WorkKind::Video {
                frame_id: 13,
                depends_on: Some(10),
            },
        );
        assert_eq!(scheduler.enqueue(first, 0), EnqueueDisposition::Accepted);
        assert_eq!(scheduler.enqueue(second, 0), EnqueueDisposition::Accepted);
        assert_eq!(
            scheduler.enqueue(third, 0),
            EnqueueDisposition::Coalesced { replaced_id: 2 }
        );
        assert_eq!(
            scheduler.snapshot().lanes[DeliveryClass::Video.index()].queued_items,
            2
        );
    }

    #[test]
    fn oversized_lane_capacity_is_rejected() {
        let mut config = SchedulerConfig::default();
        config.bulk.max_bytes = MAX_LANE_QUEUE_BYTES + 1;
        assert_eq!(
            DeliveryScheduler::new(config).err(),
            Some(SchedulerConfigError::CapacityTooLarge)
        );
    }

    #[test]
    fn quantum_larger_than_lane_capacity_is_rejected() {
        let mut config = SchedulerConfig::default();
        config.control.max_bytes = MIN_QUANTUM_BYTES;
        config.quantum_bytes[DeliveryClass::Control.index()] = MIN_QUANTUM_BYTES * 2;
        assert_eq!(
            DeliveryScheduler::new(config).err(),
            Some(SchedulerConfigError::QuantumExceedsLaneCapacity)
        );
    }

    #[test]
    fn resetting_initial_video_reference_discards_old_queued_dependencies() {
        let mut scheduler = new_scheduler(SchedulerConfig::default());
        scheduler.set_initial_video_reference(10);
        assert_eq!(
            scheduler.enqueue(video(1, 11, Some(10), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(2, 12, Some(11), None), 0),
            EnqueueDisposition::Accepted
        );

        assert_eq!(scheduler.set_initial_video_reference(20), 2);
        assert_eq!(
            scheduler.snapshot().lanes[DeliveryClass::Video.index()].queued_items,
            0
        );
        assert_eq!(scheduler.snapshot().stats.superseded_video, 2);
        assert_eq!(
            scheduler.enqueue(video(3, 21, Some(20), None), 0),
            EnqueueDisposition::Accepted
        );
        assert_eq!(
            scheduler.enqueue(video(4, 22, Some(11), None), 0),
            EnqueueDisposition::Rejected(RejectReason::MissingVideoReference)
        );
    }

    #[test]
    fn too_small_quantum_is_rejected() {
        let mut config = SchedulerConfig::default();
        config.quantum_bytes[DeliveryClass::Telemetry.index()] = MIN_QUANTUM_BYTES - 1;
        assert_eq!(
            DeliveryScheduler::new(config).err(),
            Some(SchedulerConfigError::QuantumTooSmall)
        );
    }

    #[test]
    fn zero_capacity_is_rejected_at_construction() {
        let mut config = SchedulerConfig::default();
        config.video.max_items = 0;
        assert_eq!(
            DeliveryScheduler::new(config).err(),
            Some(SchedulerConfigError::ZeroCapacity)
        );
    }
}
