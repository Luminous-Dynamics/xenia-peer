// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bounded, key-epoch-bound video-fragment reassembly reference model.
//!
//! This module is transport-free and does not change the current Xenia wire
//! format. It defines the receiver-side invariants needed before a later
//! negotiated stream/datagram fragmentation envelope can be implemented.
//! A frame is exposed to the decoder only after every fragment is present,
//! lengths agree, and the full-frame BLAKE3 digest verifies.
//!
//! Fragment authentication is expected from the negotiated sealed transport
//! envelope. The frame digest provides assembly consistency; it is not a
//! replacement for AEAD, a sender signature, or authorization.

use std::collections::HashMap;

use crate::frame::PixelFormat;

/// Maximum in-flight incomplete video frames in one receiver reassembler.
pub const DEFAULT_MAX_IN_FLIGHT_FRAMES: usize = 8;
/// Maximum reserved reassembly payload bytes.
pub const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum encoded payload bytes in one frame.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes carried by one application fragment.
pub const DEFAULT_MAX_FRAGMENT_BYTES: usize = 64 * 1024;
/// Maximum fragment descriptors reserved across all in-flight frames.
pub const DEFAULT_MAX_TOTAL_FRAGMENTS: usize = 4_096;
/// Maximum fragments per frame.
pub const DEFAULT_MAX_FRAGMENTS_PER_FRAME: u16 = 1_024;

/// Identity of one frame within a session and negotiated key epoch.
///
/// Xenia frame IDs may reset on rekey; the key epoch is therefore part of the
/// assembly identity and prevents fragments from different epochs joining.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FragmentFrameKey {
    /// Negotiated Xenia key epoch.
    pub key_epoch: u64,
    /// Monotonic frame ID within that epoch.
    pub frame_id: u64,
}

/// Metadata that must agree across every fragment of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentFrameMetadata {
    /// Capture timestamp as carried by the original frame.
    pub timestamp_ms: u64,
    /// Logical frame width.
    pub width: u32,
    /// Logical frame height.
    pub height: u32,
    /// Encoded pixel/codec format.
    pub pixel_format: PixelFormat,
}

/// One application-level fragment of an encoded frame.
///
/// The containing Xenia transport must authenticate this envelope and bind
/// it to the same session/key epoch. `frame_digest` is BLAKE3 over the
/// complete encoded frame payload after concatenating fragments by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameFragment {
    /// Session fingerprint from the authenticated Xenia handshake.
    pub session_fingerprint: [u8; 32],
    /// Frame identity including key epoch.
    pub key: FragmentFrameKey,
    /// Original frame metadata; identical across all fragments.
    pub metadata: FragmentFrameMetadata,
    /// Zero-based fragment index.
    pub fragment_index: u16,
    /// Total fragment count for this frame.
    pub fragment_count: u16,
    /// Expected full encoded frame payload length.
    pub total_frame_bytes: usize,
    /// BLAKE3 digest of the complete encoded frame payload.
    pub frame_digest: [u8; 32],
    /// Payload bytes for this fragment.
    pub payload: Vec<u8>,
}

/// Hard receiver-side reassembly resource and age limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameReassemblyConfig {
    /// Maximum number of incomplete frames.
    pub max_in_flight_frames: usize,
    /// Maximum reserved bytes across all incomplete frames.
    pub max_reassembly_bytes: usize,
    /// Maximum full encoded size of one frame.
    pub max_frame_bytes: usize,
    /// Maximum payload bytes in one fragment.
    pub max_fragment_bytes: usize,
    /// Maximum total fragment descriptors across incomplete frames.
    pub max_total_fragments: usize,
    /// Maximum fragments in one frame.
    pub max_fragments_per_frame: u16,
    /// Maximum residence age in one local monotonic clock domain.
    pub max_age_ticks: u64,
}

impl Default for FrameReassemblyConfig {
    fn default() -> Self {
        Self {
            max_in_flight_frames: DEFAULT_MAX_IN_FLIGHT_FRAMES,
            max_reassembly_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_fragment_bytes: DEFAULT_MAX_FRAGMENT_BYTES,
            max_total_fragments: DEFAULT_MAX_TOTAL_FRAGMENTS,
            max_fragments_per_frame: DEFAULT_MAX_FRAGMENTS_PER_FRAME,
            max_age_ticks: 2_000,
        }
    }
}

/// Construction-time configuration error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameReassemblyConfigError {
    /// A configured capacity or age limit is zero.
    ZeroLimit,
    /// A per-frame size limit exceeds the aggregate byte reservation.
    FrameLimitExceedsAggregate,
    /// Fragment descriptors cannot represent at least one allowed frame.
    FragmentLimitInconsistent,
}

/// Why a fragment was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFragmentError {
    /// Fragment came from another authenticated Xenia session.
    SessionMismatch,
    /// Fragment belongs to an old or unnegotiated key epoch.
    KeyEpochMismatch {
        /// Current reassembler epoch.
        current: u64,
        /// Fragment epoch.
        observed: u64,
    },
    /// A frame must contain at least one fragment and stay within the bound.
    InvalidFragmentCount,
    /// Fragment index is outside the declared count.
    FragmentIndexOutOfRange,
    /// Empty fragments are not accepted.
    EmptyFragment,
    /// One fragment exceeds the configured application send quantum.
    FragmentTooLarge,
    /// Declared complete frame exceeds the configured frame size.
    FrameTooLarge,
    /// Width or height is zero.
    InvalidDimensions,
    /// Same frame key arrived with inconsistent immutable metadata.
    MetadataConflict,
    /// Same fragment index arrived with different payload bytes.
    ConflictingDuplicate,
    /// Accumulated payload exceeds the declared full-frame size.
    ExceedsDeclaredFrameSize,
    /// All fragments arrived but total bytes do not equal the declared size.
    IncompleteLength,
    /// Full-frame digest did not match.
    FrameDigestMismatch,
    /// In-flight frame capacity is exhausted.
    FrameCapacityFull,
    /// Reserved byte capacity is exhausted.
    ReassemblyBytesFull,
    /// Aggregate fragment-descriptor capacity is exhausted.
    FragmentDescriptorCapacityFull,
    /// Caller supplied a regressed local monotonic tick.
    ClockRegression {
        /// Last observed tick.
        previous: u64,
        /// Regressed tick.
        observed: u64,
    },
    /// The requested new key epoch is not strictly greater than the current.
    NonMonotonicKeyEpoch {
        /// Current key epoch.
        current: u64,
        /// Requested key epoch.
        requested: u64,
    },
}

/// Result of accepting one fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameFragmentDisposition {
    /// A new fragment was stored, but the frame is not decoder-visible yet.
    Accepted {
        /// Fragments received so far.
        received_fragments: u16,
        /// Total fragments required.
        total_fragments: u16,
    },
    /// Exact duplicate fragment; no memory or state was changed.
    Duplicate {
        /// Number of distinct fragments already stored.
        received_fragments: u16,
        /// Total fragments required.
        total_fragments: u16,
    },
    /// Complete, length-checked and digest-verified frame.
    Completed(CompletedFrame),
}

/// Frame output after complete bounded reassembly and digest verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedFrame {
    /// Session/epoch/frame identity.
    pub key: FragmentFrameKey,
    /// Original frame metadata.
    pub metadata: FragmentFrameMetadata,
    /// Verified complete encoded payload, in fragment-index order.
    pub payload: Vec<u8>,
    /// Verified BLAKE3 frame digest.
    pub frame_digest: [u8; 32],
}

/// Read-only memory/queue state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameReassemblySnapshot {
    /// Current authenticated session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Currently accepted key epoch.
    pub key_epoch: u64,
    /// Number of incomplete frames.
    pub in_flight_frames: usize,
    /// Reserved full-frame bytes for incomplete frames.
    pub reserved_bytes: usize,
    /// Reserved fragment descriptors for incomplete frames.
    pub reserved_fragments: usize,
    /// Configured aggregate byte bound.
    pub max_reassembly_bytes: usize,
}

/// One incomplete frame's immutable metadata and indexed payload fragments.
#[derive(Debug)]
struct FrameAssembly {
    metadata: FragmentFrameMetadata,
    fragment_count: u16,
    total_frame_bytes: usize,
    frame_digest: [u8; 32],
    created_at_ticks: u64,
    fragments: Vec<Option<Vec<u8>>>,
    received_fragments: u16,
    received_bytes: usize,
}

/// Receiver-side bounded reassembler for one authenticated Xenia session.
///
/// This type has no socket, async task, codec, authorization or host-effect
/// integration. It only verifies fragment structure and assembles complete
/// encoded frames. Callers must separately enforce freshness and decoder
/// dependency semantics.
#[derive(Debug)]
pub struct FrameReassembler {
    session_fingerprint: [u8; 32],
    key_epoch: u64,
    config: FrameReassemblyConfig,
    assemblies: HashMap<FragmentFrameKey, FrameAssembly>,
    reserved_bytes: usize,
    reserved_fragments: usize,
    last_now_ticks: Option<u64>,
}

impl FrameReassembler {
    /// Construct a reassembler for one authenticated session and key epoch.
    pub fn new(
        session_fingerprint: [u8; 32],
        key_epoch: u64,
        config: FrameReassemblyConfig,
    ) -> Result<Self, FrameReassemblyConfigError> {
        if config.max_in_flight_frames == 0
            || config.max_reassembly_bytes == 0
            || config.max_frame_bytes == 0
            || config.max_fragment_bytes == 0
            || config.max_total_fragments == 0
            || config.max_fragments_per_frame == 0
            || config.max_age_ticks == 0
        {
            return Err(FrameReassemblyConfigError::ZeroLimit);
        }
        if config.max_frame_bytes > config.max_reassembly_bytes {
            return Err(FrameReassemblyConfigError::FrameLimitExceedsAggregate);
        }
        if usize::from(config.max_fragments_per_frame) > config.max_total_fragments {
            return Err(FrameReassemblyConfigError::FragmentLimitInconsistent);
        }
        Ok(Self {
            session_fingerprint,
            key_epoch,
            config,
            assemblies: HashMap::new(),
            reserved_bytes: 0,
            reserved_fragments: 0,
            last_now_ticks: None,
        })
    }

    /// Add one fragment. A frame is returned only after every fragment arrives
    /// and the assembled payload has exactly the declared size and digest.
    ///
    /// `now_ticks` is a receiver-local monotonic clock, never a source-host
    /// timestamp. Expired incomplete assemblies are discarded before the new
    /// fragment is considered.
    pub fn push(
        &mut self,
        fragment: FrameFragment,
        now_ticks: u64,
    ) -> Result<FrameFragmentDisposition, FrameFragmentError> {
        self.observe_clock(now_ticks)?;
        self.expire_at(now_ticks);

        if fragment.session_fingerprint != self.session_fingerprint {
            return Err(FrameFragmentError::SessionMismatch);
        }
        if fragment.key.key_epoch != self.key_epoch {
            return Err(FrameFragmentError::KeyEpochMismatch {
                current: self.key_epoch,
                observed: fragment.key.key_epoch,
            });
        }
        if fragment.fragment_count == 0
            || fragment.fragment_count > self.config.max_fragments_per_frame
            || usize::from(fragment.fragment_count) > fragment.total_frame_bytes
        {
            return Err(FrameFragmentError::InvalidFragmentCount);
        }
        if fragment.fragment_index >= fragment.fragment_count {
            return Err(FrameFragmentError::FragmentIndexOutOfRange);
        }
        if fragment.payload.is_empty() {
            return Err(FrameFragmentError::EmptyFragment);
        }
        if fragment.payload.len() > self.config.max_fragment_bytes {
            return Err(FrameFragmentError::FragmentTooLarge);
        }
        if fragment.total_frame_bytes == 0
            || fragment.total_frame_bytes > self.config.max_frame_bytes
        {
            return Err(FrameFragmentError::FrameTooLarge);
        }
        if fragment.metadata.width == 0 || fragment.metadata.height == 0 {
            return Err(FrameFragmentError::InvalidDimensions);
        }

        let existing_state = self.assemblies.get(&fragment.key).map(|existing| {
            let metadata_matches = existing.metadata == fragment.metadata
                && existing.fragment_count == fragment.fragment_count
                && existing.total_frame_bytes == fragment.total_frame_bytes
                && existing.frame_digest == fragment.frame_digest;
            let duplicate = existing
                .fragments
                .get(usize::from(fragment.fragment_index))
                .and_then(Option::as_ref)
                .map(|payload| payload == &fragment.payload);
            (
                metadata_matches,
                duplicate,
                existing.received_fragments,
                existing.fragment_count,
            )
        });
        if let Some((metadata_matches, duplicate, received, total)) = existing_state {
            if !metadata_matches {
                self.remove_assembly(fragment.key);
                return Err(FrameFragmentError::MetadataConflict);
            }
            if let Some(identical) = duplicate {
                if identical {
                    return Ok(FrameFragmentDisposition::Duplicate {
                        received_fragments: received,
                        total_fragments: total,
                    });
                }
                self.remove_assembly(fragment.key);
                return Err(FrameFragmentError::ConflictingDuplicate);
            }
        } else {
            if self.assemblies.len() >= self.config.max_in_flight_frames {
                return Err(FrameFragmentError::FrameCapacityFull);
            }
            if self
                .reserved_bytes
                .saturating_add(fragment.total_frame_bytes)
                > self.config.max_reassembly_bytes
            {
                return Err(FrameFragmentError::ReassemblyBytesFull);
            }
            let count = usize::from(fragment.fragment_count);
            if self.reserved_fragments.saturating_add(count)
                > self.config.max_total_fragments
            {
                return Err(FrameFragmentError::FragmentDescriptorCapacityFull);
            }
            self.reserved_bytes = self
                .reserved_bytes
                .saturating_add(fragment.total_frame_bytes);
            self.reserved_fragments = self.reserved_fragments.saturating_add(count);
            self.assemblies.insert(
                fragment.key,
                FrameAssembly {
                    metadata: fragment.metadata,
                    fragment_count: fragment.fragment_count,
                    total_frame_bytes: fragment.total_frame_bytes,
                    frame_digest: fragment.frame_digest,
                    created_at_ticks: now_ticks,
                    fragments: (0..count).map(|_| None).collect(),
                    received_fragments: 0,
                    received_bytes: 0,
                },
            );
        }

        let exceeds_declared_size = self
            .assemblies
            .get(&fragment.key)
            .is_some_and(|assembly| {
                assembly
                    .received_bytes
                    .saturating_add(fragment.payload.len())
                    > assembly.total_frame_bytes
            });
        if exceeds_declared_size {
            self.remove_assembly(fragment.key);
            return Err(FrameFragmentError::ExceedsDeclaredFrameSize);
        }

        let assembly = self
            .assemblies
            .get_mut(&fragment.key)
            .ok_or(FrameFragmentError::MetadataConflict)?;
        let next_received_bytes = assembly
            .received_bytes
            .saturating_add(fragment.payload.len());
        let slot = assembly
            .fragments
            .get_mut(usize::from(fragment.fragment_index))
            .ok_or(FrameFragmentError::FragmentIndexOutOfRange)?;
        if slot.is_some() {
            return Err(FrameFragmentError::ConflictingDuplicate);
        }
        *slot = Some(fragment.payload);
        assembly.received_fragments = assembly.received_fragments.saturating_add(1);
        assembly.received_bytes = next_received_bytes;

        if assembly.received_fragments < assembly.fragment_count {
            return Ok(FrameFragmentDisposition::Accepted {
                received_fragments: assembly.received_fragments,
                total_fragments: assembly.fragment_count,
            });
        }

        let completed = self
            .remove_assembly(fragment.key)
            .ok_or(FrameFragmentError::MetadataConflict)?;
        if completed.received_bytes != completed.total_frame_bytes {
            return Err(FrameFragmentError::IncompleteLength);
        }

        let mut payload = Vec::with_capacity(completed.total_frame_bytes);
        for part in completed.fragments {
            match part {
                Some(bytes) => payload.extend_from_slice(&bytes),
                None => return Err(FrameFragmentError::IncompleteLength),
            }
        }
        let digest = *blake3::hash(&payload).as_bytes();
        if digest != completed.frame_digest {
            return Err(FrameFragmentError::FrameDigestMismatch);
        }

        Ok(FrameFragmentDisposition::Completed(CompletedFrame {
            key: fragment.key,
            metadata: completed.metadata,
            payload,
            frame_digest: digest,
        }))
    }

    /// Expire incomplete frames whose receiver-local residence age reached
    /// the configured maximum. Returns the number discarded.
    pub fn expire(&mut self, now_ticks: u64) -> Result<usize, FrameFragmentError> {
        self.observe_clock(now_ticks)?;
        Ok(self.expire_at(now_ticks))
    }

    /// Advance to a strictly newer key epoch and discard every incomplete
    /// frame from the previous epoch.
    ///
    /// Frame IDs may restart within the new epoch; epoch binding prevents
    /// fragments from being combined across rekey.
    pub fn advance_key_epoch(&mut self, new_epoch: u64) -> Result<usize, FrameFragmentError> {
        if new_epoch <= self.key_epoch {
            return Err(FrameFragmentError::NonMonotonicKeyEpoch {
                current: self.key_epoch,
                requested: new_epoch,
            });
        }
        let discarded = self.assemblies.len();
        self.assemblies.clear();
        self.reserved_bytes = 0;
        self.reserved_fragments = 0;
        self.key_epoch = new_epoch;
        Ok(discarded)
    }

    /// Abort one incomplete frame, for example after a deadline or dependency
    /// invalidation decision made by the caller.
    pub fn abort_frame(&mut self, key: FragmentFrameKey) -> bool {
        self.remove_assembly(key).is_some()
    }

    /// Snapshot current bounded state.
    pub fn snapshot(&self) -> FrameReassemblySnapshot {
        FrameReassemblySnapshot {
            session_fingerprint: self.session_fingerprint,
            key_epoch: self.key_epoch,
            in_flight_frames: self.assemblies.len(),
            reserved_bytes: self.reserved_bytes,
            reserved_fragments: self.reserved_fragments,
            max_reassembly_bytes: self.config.max_reassembly_bytes,
        }
    }

    fn observe_clock(&mut self, now_ticks: u64) -> Result<(), FrameFragmentError> {
        if let Some(previous) = self.last_now_ticks {
            if now_ticks < previous {
                return Err(FrameFragmentError::ClockRegression {
                    previous,
                    observed: now_ticks,
                });
            }
        }
        self.last_now_ticks = Some(now_ticks);
        Ok(())
    }

    fn expire_at(&mut self, now_ticks: u64) -> usize {
        let expired: Vec<FragmentFrameKey> = self
            .assemblies
            .iter()
            .filter_map(|(key, assembly)| {
                (now_ticks.saturating_sub(assembly.created_at_ticks)
                    >= self.config.max_age_ticks)
                    .then_some(*key)
            })
            .collect();
        let count = expired.len();
        for key in expired {
            self.remove_assembly(key);
        }
        count
    }

    fn remove_assembly(&mut self, key: FragmentFrameKey) -> Option<FrameAssembly> {
        let assembly = self.assemblies.remove(&key)?;
        self.reserved_bytes = self
            .reserved_bytes
            .saturating_sub(assembly.total_frame_bytes);
        self.reserved_fragments = self
            .reserved_fragments
            .saturating_sub(usize::from(assembly.fragment_count));
        Some(assembly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> FragmentFrameMetadata {
        FragmentFrameMetadata {
            timestamp_ms: 123,
            width: 1280,
            height: 720,
            pixel_format: PixelFormat::H264,
        }
    }

    fn reassembler() -> FrameReassembler {
        FrameReassembler::new([1; 32], 4, FrameReassemblyConfig::default())
            .unwrap_or_else(|error| panic!("reassembler creation failed: {error:?}"))
    }

    fn fragment(
        frame_id: u64,
        index: u16,
        count: u16,
        total: usize,
        digest: [u8; 32],
        payload: &[u8],
    ) -> FrameFragment {
        FrameFragment {
            session_fingerprint: [1; 32],
            key: FragmentFrameKey {
                key_epoch: 4,
                frame_id,
            },
            metadata: metadata(),
            fragment_index: index,
            fragment_count: count,
            total_frame_bytes: total,
            frame_digest: digest,
            payload: payload.to_vec(),
        }
    }

    fn frame_digest(payload: &[u8]) -> [u8; 32] {
        *blake3::hash(payload).as_bytes()
    }

    #[test]
    fn complete_frame_is_returned_only_after_all_fragments_and_digest_verify() {
        let payload = b"abcdefghijkl";
        let digest = frame_digest(payload);
        let mut reassembler = reassembler();
        assert!(matches!(
            reassembler.push(fragment(1, 0, 3, 12, digest, b"abcd"), 0),
            Ok(FrameFragmentDisposition::Accepted {
                received_fragments: 1,
                total_fragments: 3
            })
        ));
        assert!(matches!(
            reassembler.push(fragment(1, 1, 3, 12, digest, b"efgh"), 1),
            Ok(FrameFragmentDisposition::Accepted {
                received_fragments: 2,
                total_fragments: 3
            })
        ));
        let result = reassembler
            .push(fragment(1, 2, 3, 12, digest, b"ijkl"), 2)
            .unwrap_or_else(|error| panic!("final fragment failed: {error:?}"));
        match result {
            FrameFragmentDisposition::Completed(frame) => {
                assert_eq!(frame.payload, payload);
                assert_eq!(frame.frame_digest, digest);
                assert_eq!(frame.key.frame_id, 1);
            }
            other => panic!("expected completed frame, got {other:?}"),
        }
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn out_of_order_fragments_are_assembled_by_index() {
        let payload = b"abcdefghijkl";
        let digest = frame_digest(payload);
        let mut reassembler = reassembler();
        assert!(matches!(
            reassembler.push(fragment(2, 2, 3, 12, digest, b"ijkl"), 0),
            Ok(FrameFragmentDisposition::Accepted { .. })
        ));
        assert!(matches!(
            reassembler.push(fragment(2, 0, 3, 12, digest, b"abcd"), 1),
            Ok(FrameFragmentDisposition::Accepted { .. })
        ));
        let result = reassembler
            .push(fragment(2, 1, 3, 12, digest, b"efgh"), 2)
            .unwrap_or_else(|error| panic!("frame assembly failed: {error:?}"));
        assert!(matches!(
            result,
            FrameFragmentDisposition::Completed(CompletedFrame { .. })
        ));
    }

    #[test]
    fn identical_duplicate_fragment_is_idempotent() {
        let payload = b"abcdefgh";
        let digest = frame_digest(payload);
        let mut reassembler = reassembler();
        assert!(matches!(
            reassembler.push(fragment(3, 0, 2, 8, digest, b"abcd"), 0),
            Ok(FrameFragmentDisposition::Accepted { .. })
        ));
        assert!(matches!(
            reassembler.push(fragment(3, 0, 2, 8, digest, b"abcd"), 1),
            Ok(FrameFragmentDisposition::Duplicate {
                received_fragments: 1,
                total_fragments: 2
            })
        ));
        assert_eq!(reassembler.snapshot().reserved_bytes, 8);
    }

    #[test]
    fn conflicting_duplicate_discards_the_partial_frame() {
        let payload = b"abcdefgh";
        let digest = frame_digest(payload);
        let mut reassembler = reassembler();
        assert!(reassembler
            .push(fragment(4, 0, 2, 8, digest, b"abcd"), 0)
            .is_ok());
        assert_eq!(
            reassembler.push(fragment(4, 0, 2, 8, digest, b"xxxx"), 1),
            Err(FrameFragmentError::ConflictingDuplicate)
        );
        assert_eq!(reassembler.snapshot().in_flight_frames, 0);
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn full_frame_digest_mismatch_discards_assembly() {
        let mut reassembler = reassembler();
        assert!(reassembler
            .push(fragment(5, 0, 2, 8, [9; 32], b"abcd"), 0)
            .is_ok());
        assert_eq!(
            reassembler.push(fragment(5, 1, 2, 8, [9; 32], b"efgh"), 1),
            Err(FrameFragmentError::FrameDigestMismatch)
        );
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn metadata_conflict_discards_partial_frame() {
        let payload = b"abcdefgh";
        let digest = frame_digest(payload);
        let mut reassembler = reassembler();
        assert!(reassembler
            .push(fragment(6, 0, 2, 8, digest, b"abcd"), 0)
            .is_ok());
        let mut second = fragment(6, 1, 2, 8, digest, b"efgh");
        second.metadata.width = 1920;
        assert_eq!(
            reassembler.push(second, 1),
            Err(FrameFragmentError::MetadataConflict)
        );
        assert_eq!(reassembler.snapshot().in_flight_frames, 0);
    }

    #[test]
    fn foreign_session_fragment_is_rejected() {
        let payload = b"abcdefgh";
        let mut fragment = fragment(7, 0, 2, 8, frame_digest(payload), b"abcd");
        fragment.session_fingerprint = [2; 32];
        let mut reassembler = reassembler();
        assert_eq!(
            reassembler.push(fragment, 0),
            Err(FrameFragmentError::SessionMismatch)
        );
    }

    #[test]
    fn old_key_epoch_fragment_is_rejected() {
        let payload = b"abcdefgh";
        let mut fragment = fragment(8, 0, 2, 8, frame_digest(payload), b"abcd");
        fragment.key.key_epoch = 3;
        let mut reassembler = reassembler();
        assert_eq!(
            reassembler.push(fragment, 0),
            Err(FrameFragmentError::KeyEpochMismatch {
                current: 4,
                observed: 3,
            })
        );
    }

    #[test]
    fn advancing_key_epoch_discards_incomplete_frames_and_allows_id_reset() {
        let payload = b"abcdefgh";
        let mut reassembler = reassembler();
        assert!(reassembler
            .push(fragment(9, 0, 2, 8, frame_digest(payload), b"abcd"), 0)
            .is_ok());
        assert_eq!(reassembler.advance_key_epoch(5), Ok(1));
        let mut next = fragment(1, 0, 2, 8, frame_digest(payload), b"abcd");
        next.key.key_epoch = 5;
        assert!(matches!(
            reassembler.push(next, 1),
            Ok(FrameFragmentDisposition::Accepted { .. })
        ));
        assert_eq!(reassembler.snapshot().key_epoch, 5);
    }

    #[test]
    fn frame_capacity_and_reserved_byte_capacity_are_bounded() {
        let config = FrameReassemblyConfig {
            max_in_flight_frames: 1,
            max_reassembly_bytes: 8,
            max_frame_bytes: 8,
            max_fragment_bytes: 8,
            max_total_fragments: 4,
            max_fragments_per_frame: 4,
            max_age_ticks: 10,
        };
        let mut reassembler = FrameReassembler::new([1; 32], 4, config)
            .unwrap_or_else(|error| panic!("config rejected: {error:?}"));
        let payload = b"abcdefgh";
        let first = fragment(10, 0, 2, 8, frame_digest(payload), b"abcd");
        assert!(reassembler.push(first, 0).is_ok());
        assert_eq!(
            reassembler.push(
                fragment(11, 0, 2, 8, frame_digest(payload), b"abcd"),
                1
            ),
            Err(FrameFragmentError::FrameCapacityFull)
        );
        assert_eq!(reassembler.snapshot().reserved_bytes, 8);
    }

    #[test]
    fn incomplete_frame_expires_and_releases_all_reservations() {
        let config = FrameReassemblyConfig {
            max_age_ticks: 5,
            ..FrameReassemblyConfig::default()
        };
        let mut reassembler = FrameReassembler::new([1; 32], 4, config)
            .unwrap_or_else(|error| panic!("config rejected: {error:?}"));
        let payload = b"abcdefgh";
        assert!(reassembler
            .push(fragment(12, 0, 2, 8, frame_digest(payload), b"abcd"), 10)
            .is_ok());
        assert_eq!(reassembler.expire(14), Ok(0));
        assert_eq!(reassembler.expire(15), Ok(1));
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
        assert_eq!(reassembler.snapshot().in_flight_frames, 0);
    }

    #[test]
    fn clock_regression_is_rejected() {
        let mut reassembler = reassembler();
        assert_eq!(reassembler.expire(10), Ok(0));
        assert_eq!(
            reassembler.expire(9),
            Err(FrameFragmentError::ClockRegression {
                previous: 10,
                observed: 9,
            })
        );
    }

    #[test]
    fn non_monotonic_key_epoch_is_rejected() {
        let mut reassembler = reassembler();
        assert_eq!(
            reassembler.advance_key_epoch(4),
            Err(FrameFragmentError::NonMonotonicKeyEpoch {
                current: 4,
                requested: 4,
            })
        );
    }

    #[test]
    fn fragment_bounds_are_rejected_before_reservation() {
        let config = FrameReassemblyConfig {
            max_fragment_bytes: 4,
            max_frame_bytes: 8,
            max_reassembly_bytes: 8,
            ..FrameReassemblyConfig::default()
        };
        let mut reassembler = FrameReassembler::new([1; 32], 4, config)
            .unwrap_or_else(|error| panic!("config rejected: {error:?}"));
        let payload = b"abcdefgh";
        assert_eq!(
            reassembler.push(
                fragment(13, 0, 2, 8, frame_digest(payload), b"abcde"),
                0
            ),
            Err(FrameFragmentError::FragmentTooLarge)
        );
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn complete_frame_bytes_must_match_the_declared_total() {
        let payload = b"abcdefgh";
        let mut reassembler = reassembler();
        let digest = frame_digest(payload);
        assert!(reassembler
            .push(fragment(14, 0, 2, 8, digest, b"abcd"), 0)
            .is_ok());
        assert_eq!(
            reassembler.push(fragment(14, 1, 2, 8, digest, b"efghi"), 1),
            Err(FrameFragmentError::ExceedsDeclaredFrameSize)
        );
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn abort_frame_releases_reserved_memory() {
        let payload = b"abcdefgh";
        let mut reassembler = reassembler();
        assert!(reassembler
            .push(fragment(15, 0, 2, 8, frame_digest(payload), b"abcd"), 0)
            .is_ok());
        assert!(reassembler.abort_frame(FragmentFrameKey {
            key_epoch: 4,
            frame_id: 15,
        }));
        assert_eq!(reassembler.snapshot().reserved_bytes, 0);
    }
}
