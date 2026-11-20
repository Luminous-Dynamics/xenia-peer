// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Lazy, bounded application fragmentation for validated video frames.
//!
//! The iterator borrows the source frame and creates only one fragment payload
//! at a time. A sender can write/schedule one yielded fragment, then request
//! the next one, avoiding a second full-frame allocation. This module defines
//! application fragments only; it does not choose a transport or send them.

use crate::frame::{PixelFormat, RawFrame};
use crate::frame_reassembly::{
    DEFAULT_MAX_FRAGMENT_BYTES, DEFAULT_MAX_FRAGMENTS_PER_FRAME, DEFAULT_MAX_FRAME_BYTES,
    FrameFragment, FragmentFrameKey, FragmentFrameMetadata,
};

/// Errors returned before fragment iteration begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFragmentationError {
    /// The raw frame failed its declared-format payload validation.
    InvalidFrame,
    /// Frame width or height is zero.
    InvalidDimensions,
    /// The frame format is not a video/pixel format.
    UnsupportedPixelFormat,
    /// Empty frame payloads cannot be fragmented.
    EmptyFrame,
    /// The full encoded frame exceeds the receiver hard maximum.
    FrameTooLarge,
    /// Fragment size must be within the receiver-supported nonzero bound.
    InvalidFragmentSize,
    /// The requested fragment size would produce too many fragments.
    TooManyFragments,
}

/// Lazy iterator yielding one bounded fragment payload at a time.
///
/// The iterator borrows the original frame, stores the full-frame digest once,
/// and materializes only the current fragment's `Vec<u8>`. Do not collect the
/// entire iterator when bounded peak memory is required; consume and dispatch
/// each fragment before asking for the next one.
#[derive(Debug)]
pub struct FrameFragmentIter<'a> {
    frame: &'a RawFrame,
    session_fingerprint: [u8; 32],
    key: FragmentFrameKey,
    metadata: FragmentFrameMetadata,
    frame_digest: [u8; 32],
    fragment_size: usize,
    fragment_count: u16,
    next_index: u16,
}

impl<'a> FrameFragmentIter<'a> {
    /// Create a lazy fragment iterator for one validated video frame.
    ///
    /// `max_fragment_bytes` is an application-level upper bound. For QUIC
    /// DATAGRAM it must be derived from the negotiated DATAGRAM payload limit
    /// after subtracting every outer envelope/authentication header. It is
    /// never inferred from the path MTU here.
    pub fn new(
        frame: &'a RawFrame,
        session_fingerprint: [u8; 32],
        key_epoch: u64,
        max_fragment_bytes: usize,
    ) -> Result<Self, FrameFragmentationError> {
        if max_fragment_bytes == 0 || max_fragment_bytes > DEFAULT_MAX_FRAGMENT_BYTES {
            return Err(FrameFragmentationError::InvalidFragmentSize);
        }
        if !matches!(
            frame.pixel_format,
            PixelFormat::Rgba8
                | PixelFormat::Bgra8
                | PixelFormat::H264
                | PixelFormat::Vp9
                | PixelFormat::Passthrough
                | PixelFormat::Hdc
        ) {
            return Err(FrameFragmentationError::UnsupportedPixelFormat);
        }
        if frame.width == 0 || frame.height == 0 {
            return Err(FrameFragmentationError::InvalidDimensions);
        }
        if frame.pixels.is_empty() {
            return Err(FrameFragmentationError::EmptyFrame);
        }
        if !frame.validate() {
            return Err(FrameFragmentationError::InvalidFrame);
        }
        if frame.pixels.len() > DEFAULT_MAX_FRAME_BYTES {
            return Err(FrameFragmentationError::FrameTooLarge);
        }

        let fragment_count = frame.pixels.len().div_ceil(max_fragment_bytes);
        if fragment_count == 0
            || fragment_count > usize::from(DEFAULT_MAX_FRAGMENTS_PER_FRAME)
        {
            return Err(FrameFragmentationError::TooManyFragments);
        }

        Ok(Self {
            frame,
            session_fingerprint,
            key: FragmentFrameKey {
                key_epoch,
                frame_id: frame.frame_id,
            },
            metadata: FragmentFrameMetadata {
                timestamp_ms: frame.timestamp_ms,
                width: frame.width,
                height: frame.height,
                pixel_format: frame.pixel_format,
            },
            frame_digest: *blake3::hash(&frame.pixels).as_bytes(),
            fragment_size: max_fragment_bytes,
            fragment_count: fragment_count as u16,
            next_index: 0,
        })
    }

    /// Total fragments in this frame.
    pub const fn total_fragments(&self) -> u16 {
        self.fragment_count
    }

    /// Number of fragments not yet yielded.
    pub const fn remaining_fragments(&self) -> u16 {
        self.fragment_count - self.next_index
    }
}

impl Iterator for FrameFragmentIter<'_> {
    type Item = FrameFragment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.fragment_count {
            return None;
        }
        let index = self.next_index;
        let start = usize::from(index).saturating_mul(self.fragment_size);
        let end = start
            .saturating_add(self.fragment_size)
            .min(self.frame.pixels.len());
        let payload = self.frame.pixels.get(start..end)?.to_vec();
        self.next_index = self.next_index.saturating_add(1);

        Some(FrameFragment {
            session_fingerprint: self.session_fingerprint,
            key: self.key,
            metadata: self.metadata,
            fragment_index: index,
            fragment_count: self.fragment_count,
            total_frame_bytes: self.frame.pixels.len(),
            frame_digest: self.frame_digest,
            payload,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining_fragments());
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FrameFragmentIter<'_> {
    fn len(&self) -> usize {
        usize::from(self.remaining_fragments())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_reassembly::{
        FrameFragmentDisposition, FrameReassembler, FrameReassemblyConfig,
    };

    fn encoded_frame(frame_id: u64, bytes: Vec<u8>) -> RawFrame {
        RawFrame::encoded(
            frame_id,
            123,
            1280,
            720,
            PixelFormat::H264,
            bytes,
        )
    }

    #[test]
    fn lazy_fragments_round_trip_through_receiver_out_of_order() {
        let source = (0..37_u8).collect::<Vec<_>>();
        let frame = encoded_frame(42, source.clone());
        let iter = FrameFragmentIter::new(&frame, [7; 32], 11, 8)
            .unwrap_or_else(|error| panic!("fragmenter rejected frame: {error:?}"));
        assert_eq!(iter.len(), 5);
        let mut fragments = iter.collect::<Vec<_>>();
        assert!(fragments
            .iter()
            .all(|fragment| fragment.payload.len() <= 8));

        let mut receiver = FrameReassembler::new(
            [7; 32],
            11,
            FrameReassemblyConfig {
                max_fragment_bytes: 8,
                ..FrameReassemblyConfig::default()
            },
        )
        .unwrap_or_else(|error| panic!("receiver rejected config: {error:?}"));
        fragments.reverse();

        let mut completed = None;
        for fragment in fragments {
            let result = receiver
                .push(fragment, 1)
                .unwrap_or_else(|error| panic!("receiver rejected fragment: {error:?}"));
            if let FrameFragmentDisposition::Completed(frame) = result {
                completed = Some(frame);
            }
        }
        let restored = completed.unwrap_or_else(|| panic!("frame did not complete"));
        assert_eq!(restored.payload, source);
        assert_eq!(restored.key.frame_id, 42);
        assert_eq!(restored.key.key_epoch, 11);
    }

    #[test]
    fn iterator_materializes_one_bounded_fragment_at_a_time() {
        let frame = encoded_frame(43, vec![0xA5; 130 * 1024]);
        let mut iter = FrameFragmentIter::new(&frame, [8; 32], 12, 64 * 1024)
            .unwrap_or_else(|error| panic!("fragmenter rejected frame: {error:?}"));
        assert_eq!(iter.len(), 3);
        let first = iter
            .next()
            .unwrap_or_else(|| panic!("first fragment missing"));
        assert_eq!(first.payload.len(), 64 * 1024);
        assert_eq!(iter.len(), 2);
        let second = iter
            .next()
            .unwrap_or_else(|| panic!("second fragment missing"));
        assert_eq!(second.payload.len(), 64 * 1024);
        let third = iter
            .next()
            .unwrap_or_else(|| panic!("third fragment missing"));
        assert_eq!(third.payload.len(), 2 * 1024);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn single_fragment_preserves_frame_metadata_and_digest() {
        let frame = encoded_frame(44, b"one-frame".to_vec());
        let mut iter = FrameFragmentIter::new(&frame, [9; 32], 2, 64)
            .unwrap_or_else(|error| panic!("fragmenter rejected frame: {error:?}"));
        let fragment = iter
            .next()
            .unwrap_or_else(|| panic!("fragment missing"));
        assert_eq!(fragment.fragment_index, 0);
        assert_eq!(fragment.fragment_count, 1);
        assert_eq!(fragment.total_frame_bytes, frame.pixels.len());
        assert_eq!(fragment.metadata.width, frame.width);
        assert_eq!(fragment.metadata.timestamp_ms, frame.timestamp_ms);
        assert_eq!(
            fragment.frame_digest,
            *blake3::hash(&frame.pixels).as_bytes()
        );
    }

    #[test]
    fn zero_or_oversized_fragment_size_is_rejected() {
        let frame = encoded_frame(45, b"payload".to_vec());
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 0).err(),
            Some(FrameFragmentationError::InvalidFragmentSize)
        );
        assert_eq!(
            FrameFragmentIter::new(
                &frame,
                [1; 32],
                1,
                DEFAULT_MAX_FRAGMENT_BYTES + 1,
            )
            .err(),
            Some(FrameFragmentationError::InvalidFragmentSize)
        );
    }

    #[test]
    fn too_many_fragments_is_rejected_before_iteration() {
        let frame = encoded_frame(46, vec![1; 2_000]);
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 1).err(),
            Some(FrameFragmentationError::TooManyFragments)
        );
    }

    #[test]
    fn invalid_rgba_payload_is_rejected() {
        let frame = RawFrame {
            frame_id: 47,
            timestamp_ms: 1,
            width: 2,
            height: 2,
            pixel_format: PixelFormat::Rgba8,
            pixels: vec![1; 3],
        };
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 2).err(),
            Some(FrameFragmentationError::InvalidFrame)
        );
    }

    #[test]
    fn non_video_format_is_rejected() {
        let frame = RawFrame::encoded(
            48,
            1,
            1280,
            720,
            PixelFormat::Audio,
            vec![1, 2, 3],
        );
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 2).err(),
            Some(FrameFragmentationError::UnsupportedPixelFormat)
        );
    }

    #[test]
    fn zero_dimensions_are_rejected() {
        let frame = RawFrame::encoded(
            51,
            1,
            0,
            720,
            PixelFormat::H264,
            vec![1, 2, 3],
        );
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 2).err(),
            Some(FrameFragmentationError::InvalidDimensions)
        );
    }

    #[test]
    fn hard_maximum_frame_size_is_enforced() {
        let frame = encoded_frame(52, vec![1; DEFAULT_MAX_FRAME_BYTES + 1]);
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, DEFAULT_MAX_FRAGMENT_BYTES).err(),
            Some(FrameFragmentationError::FrameTooLarge)
        );
    }

    #[test]
    fn empty_frame_is_rejected() {
        let frame = encoded_frame(49, Vec::new());
        assert_eq!(
            FrameFragmentIter::new(&frame, [1; 32], 1, 2).err(),
            Some(FrameFragmentationError::EmptyFrame)
        );
    }

    #[test]
    fn lazy_iterator_yields_exact_fragment_count() {
        let frame = encoded_frame(50, vec![1; 21]);
        let iter = FrameFragmentIter::new(&frame, [1; 32], 1, 5)
            .unwrap_or_else(|error| panic!("fragmenter rejected frame: {error:?}"));
        assert_eq!(iter.len(), 5);
        assert_eq!(iter.size_hint(), (5, Some(5)));
        let fragments = iter.collect::<Vec<_>>();
        assert_eq!(fragments.len(), 5);
        assert_eq!(fragments.last().map(|fragment| fragment.payload.len()), Some(1));
    }
}
