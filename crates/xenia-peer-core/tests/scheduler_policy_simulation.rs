// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Deterministic policy comparison for the Xenia delivery scheduler.
//!
//! This is a synthetic single-server backlog model. One byte of work consumes
//! one service tick. It compares global FIFO, per-class item round robin and
//! the actual xenia-peer-core WDRR policy. The resulting ticks are synthetic
//! byte-time units, not milliseconds, network measurements or physical I2P.

use std::collections::VecDeque;

use xenia_peer_core::delivery_scheduler::{
    ControlTransition, DeliveryClass, DeliveryScheduler, EnqueueDisposition, LaneLimit,
    SchedulerConfig, WorkItem, WorkKind,
};

const CYCLES: usize = 32;
const VIDEO_BYTES: usize = 256 * 1024;
const AUDIO_BYTES: usize = 4 * 1024;
const TELEMETRY_BYTES: usize = 1024;
const BULK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Completion {
    class: DeliveryClass,
    item_id: u64,
    finished_at_byte_ticks: u64,
}

fn class_index(class: DeliveryClass) -> usize {
    match class {
        DeliveryClass::Control => 0,
        DeliveryClass::Video => 1,
        DeliveryClass::Audio => 2,
        DeliveryClass::Telemetry => 3,
        DeliveryClass::Bulk => 4,
    }
}

fn workload(cycles: usize) -> Vec<WorkItem> {
    let mut items = Vec::with_capacity(cycles.saturating_mul(5));
    for cycle in 0..cycles {
        let cycle_u64 = cycle as u64;
        let id = cycle_u64.saturating_mul(5);

        // Deliberately place large work before the control event in the input
        // trace so the global FIFO reference exhibits head-of-line delay.
        items.push(WorkItem {
            id: id + 1,
            enqueued_at_ticks: 0,
            deadline_ticks: None,
            cost_bytes: VIDEO_BYTES,
            kind: WorkKind::Video {
                frame_id: cycle_u64 + 1,
                depends_on: Some(cycle_u64),
            },
        });
        items.push(WorkItem {
            id: id + 2,
            enqueued_at_ticks: 0,
            deadline_ticks: None,
            cost_bytes: BULK_BYTES,
            kind: WorkKind::Bulk {
                transfer_id: [0xA5; 16],
                offset: cycle_u64.saturating_mul(BULK_BYTES as u64),
                digest: [cycle as u8; 32],
            },
        });
        items.push(WorkItem {
            id: id + 3,
            enqueued_at_ticks: 0,
            deadline_ticks: None,
            cost_bytes: AUDIO_BYTES,
            kind: WorkKind::Audio {
                sequence: cycle_u64 + 1,
            },
        });
        items.push(WorkItem {
            id: id + 4,
            enqueued_at_ticks: 0,
            deadline_ticks: None,
            cost_bytes: TELEMETRY_BYTES,
            kind: WorkKind::Telemetry {
                metric_key: (cycle + 1) as u16,
            },
        });
        items.push(WorkItem {
            id: id + 5,
            enqueued_at_ticks: 0,
            deadline_ticks: None,
            cost_bytes: 128,
            kind: WorkKind::Control {
                sequence: cycle_u64 + 1,
                operation_id: [cycle as u8; 16],
                transition: ControlTransition::ButtonUp,
            },
        });
    }
    items
}

fn fifo_reference(items: &[WorkItem]) -> Vec<Completion> {
    let mut queue: VecDeque<WorkItem> = items.iter().cloned().collect();
    let mut byte_ticks = 0_u64;
    let mut completed = Vec::with_capacity(items.len());

    while let Some(item) = queue.pop_front() {
        byte_ticks = byte_ticks.saturating_add(item.cost_bytes as u64);
        completed.push(Completion {
            class: item.class(),
            item_id: item.id,
            finished_at_byte_ticks: byte_ticks,
        });
    }
    completed
}

fn item_round_robin_reference(items: &[WorkItem]) -> Vec<Completion> {
    let mut queues: [VecDeque<WorkItem>; 5] =
        std::array::from_fn(|_| VecDeque::new());
    for item in items {
        queues[class_index(item.class())].push_back(item.clone());
    }

    let mut byte_ticks = 0_u64;
    let mut completed = Vec::with_capacity(items.len());
    while queues.iter().any(|queue| !queue.is_empty()) {
        for class in [
            DeliveryClass::Control,
            DeliveryClass::Video,
            DeliveryClass::Audio,
            DeliveryClass::Telemetry,
            DeliveryClass::Bulk,
        ] {
            if let Some(item) = queues[class_index(class)].pop_front() {
                byte_ticks = byte_ticks.saturating_add(item.cost_bytes as u64);
                completed.push(Completion {
                    class,
                    item_id: item.id,
                    finished_at_byte_ticks: byte_ticks,
                });
            }
        }
    }
    completed
}

fn wdrr_candidate(items: &[WorkItem]) -> Vec<Completion> {
    let count = items.len().max(1);
    let config = SchedulerConfig {
        control: LaneLimit {
            max_items: count,
            max_bytes: 64 * 1024,
            max_age_ticks: None,
        },
        video: LaneLimit {
            max_items: count,
            max_bytes: 16 * 1024 * 1024,
            max_age_ticks: None,
        },
        audio: LaneLimit {
            max_items: count,
            max_bytes: 256 * 1024,
            max_age_ticks: None,
        },
        telemetry: LaneLimit {
            max_items: count,
            max_bytes: 64 * 1024,
            max_age_ticks: None,
        },
        bulk: LaneLimit {
            max_items: count,
            max_bytes: 32 * 1024 * 1024,
            max_age_ticks: None,
        },
        quantum_bytes: [
            64 * 1024,
            256 * 1024,
            64 * 1024,
            16 * 1024,
            32 * 1024,
        ],
    };
    let mut scheduler = DeliveryScheduler::new(config)
        .unwrap_or_else(|error| panic!("simulation config rejected: {error:?}"));
    scheduler.set_initial_video_reference(0);

    for item in items {
        assert_eq!(
            scheduler.enqueue(item.clone(), 0),
            EnqueueDisposition::Accepted
        );
    }

    let mut byte_ticks = 0_u64;
    let mut completed = Vec::with_capacity(items.len());
    while let Some(item) = scheduler.next_ready(byte_ticks) {
        byte_ticks = byte_ticks.saturating_add(item.cost_bytes as u64);
        if let WorkKind::Video { frame_id, .. } = item.kind {
            scheduler.record_video_dispatched(frame_id);
        }
        completed.push(Completion {
            class: item.class(),
            item_id: item.id,
            finished_at_byte_ticks: byte_ticks,
        });
    }
    completed
}

fn control_p99(completions: &[Completion]) -> u64 {
    let mut values: Vec<u64> = completions
        .iter()
        .filter(|item| item.class == DeliveryClass::Control)
        .map(|item| item.finished_at_byte_ticks)
        .collect();
    values.sort_unstable();
    let rank = values.len().saturating_mul(99).div_ceil(100);
    values.get(rank.saturating_sub(1)).copied().unwrap_or(0)
}

fn completion_counts(completions: &[Completion]) -> [usize; 5] {
    let mut counts = [0_usize; 5];
    for item in completions {
        counts[class_index(item.class)] += 1;
    }
    counts
}

#[test]
fn wdrr_reduces_control_tail_wait_on_heterogeneous_backlog() {
    let items = workload(CYCLES);
    let fifo = fifo_reference(&items);
    let item_rr = item_round_robin_reference(&items);
    let wdrr = wdrr_candidate(&items);

    let fifo_p99 = control_p99(&fifo);
    let item_rr_p99 = control_p99(&item_rr);
    let wdrr_p99 = control_p99(&wdrr);

    assert!(fifo_p99 > 0);
    assert!(item_rr_p99 > 0);
    assert!(
        wdrr_p99.saturating_mul(100) < fifo_p99.saturating_mul(70),
        "WDRR control p99 {wdrr_p99} should be at least 30% below FIFO {fifo_p99}"
    );
    assert!(
        wdrr_p99.saturating_mul(100) < item_rr_p99.saturating_mul(70),
        "WDRR control p99 {wdrr_p99} should be at least 30% below item-RR {item_rr_p99}"
    );
    assert_eq!(completion_counts(&fifo), [CYCLES; 5]);
    assert_eq!(completion_counts(&item_rr), [CYCLES; 5]);
    assert_eq!(completion_counts(&wdrr), [CYCLES; 5]);

    // This deliberately does not assert a millisecond target. It verifies
    // relative byte-time behavior on this exact synthetic backlog only.
}

#[test]
fn all_policies_complete_the_same_total_byte_work() {
    let items = workload(CYCLES);
    let expected_bytes = items
        .iter()
        .map(|item| item.cost_bytes as u64)
        .fold(0_u64, u64::saturating_add);

    let fifo = fifo_reference(&items);
    let item_rr = item_round_robin_reference(&items);
    let wdrr = wdrr_candidate(&items);

    for completions in [&fifo, &item_rr, &wdrr] {
        let final_tick = completions
            .iter()
            .map(|item| item.finished_at_byte_ticks)
            .max()
            .unwrap_or(0);
        assert_eq!(final_tick, expected_bytes);
        assert_eq!(completions.len(), items.len());
    }
}
