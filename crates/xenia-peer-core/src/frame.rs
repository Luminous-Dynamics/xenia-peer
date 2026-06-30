// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Framing types for M0.
//!
//! Raw RGBA only — no encoding, no delta compression, no patch format.
//! Real codecs land in `xenia-video` (M1).

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_wire::{Sealable, WireError};

/// Pixel layout of a [`RawFrame`]. M0 supports RGBA8 only; other
/// variants are reserved so future formats (BGRA, YUV420, encoded
/// H.264 NALs) can be added without breaking wire compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PixelFormat {
    /// 8 bits per channel, red-green-blue-alpha order, 4 bytes per pixel.
    Rgba8 = 0,
    /// 8 bits per channel, blue-green-red-alpha order, 4 bytes per pixel.
    /// Reserved — not yet produced by any capture backend.
    Bgra8 = 1,
    /// Encoded H.264 access unit (SPS/PPS + slice). Reserved for
    /// M1.2b when the real ffmpeg-next backend lands.
    H264 = 16,
    /// Encoded VP9 frame. Reserved for M1.
    Vp9 = 17,
    /// xenia-video passthrough codec payload (M1 working path —
    /// identity-encoded RGBA with a 12-byte magic/header). See
    /// `xenia_video::passthrough`.
    Passthrough = 32,
    /// xenia-video HDC hybrid tile-delta codec payload (bincode-
    /// serialized `HdcPacket`). See `xenia_video::hdc`. Ported
    /// from Symthaea's `rdp_codec.rs`.
    Hdc = 33,
    /// Reserved forward-path metadata frame carrying bincode-
    /// serialized [`RawTelemetry`].
    Telemetry = 240,
    /// Reserved forward-path audio frame carrying bincode-serialized
    /// [`RawAudio`].
    Audio = 241,
    /// Reserved sealed session metadata frame carrying bincode-
    /// serialized [`RawCapabilities`].
    Capabilities = 242,
}

/// Scalar telemetry value carried inside a [`RawTelemetry`] payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TelemetryValue {
    /// Signed integer value.
    I64(i64),
    /// Unsigned integer value.
    U64(u64),
    /// Floating-point value.
    F64(f64),
    /// Boolean value.
    Bool(bool),
    /// Short text value.
    Text(String),
}

/// One host telemetry measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySample {
    /// Stable metric name, e.g. `cpu.total.percent`.
    pub name: String,
    /// Metric value.
    pub value: TelemetryValue,
    /// Optional unit, e.g. `%`, `bytes`, `celsius`.
    pub unit: Option<String>,
    /// Sample timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

/// Host telemetry batch sealed on the forward path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawTelemetry {
    /// Monotonic metadata frame identifier.
    pub frame_id: u64,
    /// Host timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Backend name that produced the samples.
    pub backend: String,
    /// Telemetry samples.
    pub samples: Vec<TelemetrySample>,
}

/// Session capabilities sealed immediately after handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapabilities {
    /// Monotonic metadata frame identifier.
    pub frame_id: u64,
    /// Host timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Audio lane capabilities selected for this session.
    pub audio: Option<crate::advertisement::AudioAdvertisement>,
    /// Selected video pixel/codec format.
    pub video_format: PixelFormat,
    /// Telemetry lane is enabled for this session.
    pub telemetry_enabled: bool,
    /// Input-control lane is enabled for this session.
    pub input_control_enabled: bool,
}

/// Audio sample payload format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AudioSampleFormat {
    /// Signed 16-bit little-endian interleaved PCM.
    PcmS16Le = 0,
    /// Opus packet payload. Timing metadata remains in [`RawAudio`].
    Opus = 1,
}

/// Raw audio frame flags.
pub mod audio_flags {
    /// No special handling.
    pub const NONE: u16 = 0;
    /// Gap or clock discontinuity before this frame.
    pub const DISCONTINUITY: u16 = 1 << 0;
    /// Payload represents intentional silence/mute.
    pub const MUTED: u16 = 1 << 1;
    /// Audio stream configuration changed at this frame.
    pub const CONFIG_CHANGE: u16 = 1 << 2;

    /// Synthetic audio source, not host/device capture.
    pub const SYNTHETIC: u16 = 1 << 3;

    /// End of this logical audio stream.
    pub const END_OF_STREAM: u16 = 1 << 4;

    /// All currently understood flags.
    pub const KNOWN_MASK: u16 = DISCONTINUITY | MUTED | CONFIG_CHANGE | SYNTHETIC | END_OF_STREAM;
}

/// Raw audio schema version used by the v0.1 timing lane.
pub const RAW_AUDIO_SCHEMA_VERSION: u16 = 1;
/// v0.1 audio clock domain: host capture timestamps in Unix epoch milliseconds.
pub const RAW_AUDIO_CLOCK_UNIX_MS: u16 = 1;
/// v0.1 synthetic/raw lane sample rate.
pub const RAW_AUDIO_SAMPLE_RATE_HZ: u32 = 48_000;
/// v0.1 maximum channel count.
pub const RAW_AUDIO_MAX_CHANNELS: u16 = 2;
/// v0.1 maximum frame duration.
pub const RAW_AUDIO_MAX_FRAME_DURATION_MS: u16 = 20;
/// v0.1 maximum raw PCM payload bytes.
pub const RAW_AUDIO_MAX_PAYLOAD_BYTES: usize = 48_000 / 1_000 * 20 * 2 * 2;
/// v0.1 maximum single Opus packet bytes.
pub const RAW_AUDIO_MAX_OPUS_PAYLOAD_BYTES: usize = 1_275;

/// Raw audio packet sealed on the forward path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAudio {
    /// RawAudio schema version.
    pub schema_version: u16,
    /// Clock domain for capture timestamps.
    pub clock_domain: u16,
    /// Logical audio stream identifier.
    pub stream_id: u32,
    /// Monotonic per-stream sequence.
    pub sequence: u64,
    /// Host capture timestamp in milliseconds since Unix epoch.
    pub capture_timestamp_ms: u64,
    /// Sample rate in Hz.
    pub sample_rate_hz: u32,
    /// Interleaved channel count.
    pub channels: u16,
    /// Sample payload format.
    pub sample_format: AudioSampleFormat,
    /// Frame duration in milliseconds.
    pub frame_duration_ms: u16,
    /// Bitfield of [`audio_flags`] values.
    pub flags: u16,
    /// Interleaved audio bytes.
    pub payload: Vec<u8>,
}

impl RawAudio {
    /// Standard bring-up format: 48 kHz, stereo, 20 ms, S16LE.
    pub fn pcm_s16le_48k_stereo_20ms(
        stream_id: u32,
        sequence: u64,
        capture_timestamp_ms: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            schema_version: RAW_AUDIO_SCHEMA_VERSION,
            clock_domain: RAW_AUDIO_CLOCK_UNIX_MS,
            stream_id,
            sequence,
            capture_timestamp_ms,
            sample_rate_hz: RAW_AUDIO_SAMPLE_RATE_HZ,
            channels: 2,
            sample_format: AudioSampleFormat::PcmS16Le,
            frame_duration_ms: 20,
            flags: audio_flags::NONE,
            payload,
        }
    }

    /// Expected payload byte length for this frame's declared format.
    pub fn expected_payload_len(&self) -> Option<usize> {
        let bytes_per_sample = match self.sample_format {
            AudioSampleFormat::PcmS16Le => 2usize,
            AudioSampleFormat::Opus => return None,
        };
        let sample_ms =
            u64::from(self.sample_rate_hz).checked_mul(u64::from(self.frame_duration_ms))?;
        if sample_ms % 1_000 != 0 {
            return None;
        }
        let samples_per_channel = sample_ms / 1_000;
        let bytes = samples_per_channel
            .checked_mul(u64::from(self.channels))?
            .checked_mul(bytes_per_sample as u64)?;
        usize::try_from(bytes).ok()
    }

    /// Validate timing/configuration and payload length.
    pub fn validate(&self) -> bool {
        let allowed_duration = matches!(self.frame_duration_ms, 10 | 20);
        let payload_valid = match self.sample_format {
            AudioSampleFormat::PcmS16Le => {
                self.payload.len() <= RAW_AUDIO_MAX_PAYLOAD_BYTES
                    && self.expected_payload_len() == Some(self.payload.len())
            }
            AudioSampleFormat::Opus => {
                !self.payload.is_empty() && self.payload.len() <= RAW_AUDIO_MAX_OPUS_PAYLOAD_BYTES
            }
        };
        self.schema_version == RAW_AUDIO_SCHEMA_VERSION
            && self.clock_domain == RAW_AUDIO_CLOCK_UNIX_MS
            && self.stream_id != 0
            && self.sample_rate_hz == RAW_AUDIO_SAMPLE_RATE_HZ
            && (1..=RAW_AUDIO_MAX_CHANNELS).contains(&self.channels)
            && allowed_duration
            && self.frame_duration_ms <= RAW_AUDIO_MAX_FRAME_DURATION_MS
            && self.flags & !audio_flags::KNOWN_MASK == 0
            && payload_valid
    }

    /// Build an audio metadata frame.
    pub fn into_frame(self, frame_id: u64) -> Result<RawFrame, WireError> {
        let timestamp_ms = self.capture_timestamp_ms;
        let payload = bincode::serialize(&self).map_err(WireError::encode)?;
        Ok(RawFrame::encoded(
            frame_id,
            timestamp_ms,
            0,
            0,
            PixelFormat::Audio,
            payload,
        ))
    }

    /// Decode an audio metadata frame.
    pub fn from_frame(frame: &RawFrame) -> Result<Self, WireError> {
        if frame.pixel_format != PixelFormat::Audio {
            return Err(WireError::decode("RawFrame is not audio"));
        }
        bincode::deserialize(&frame.pixels).map_err(WireError::decode)
    }
}

/// Errors produced by audio codec adapters.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AudioCodecError {
    /// The frame does not satisfy the RawAudio lane contract.
    #[error("invalid RawAudio frame")]
    InvalidRawAudio,
    /// The codec does not support the declared frame format.
    #[error("unsupported audio format: {0}")]
    UnsupportedFormat(&'static str),
    /// Codec backend failure.
    #[error("audio codec failure: {0}")]
    CodecFailure(String),
}

/// Audio codec boundary for the RawAudio timing lane.
///
/// The codec operates on validated [`RawAudio`] frames so capture,
/// timing, transport, and playback can evolve independently.
pub trait AudioCodec: Send {
    /// Codec label used in logs and future capability negotiation.
    fn name(&self) -> &'static str;

    /// Encode a captured PCM frame for transport.
    fn encode(&mut self, frame: RawAudio) -> Result<RawAudio, AudioCodecError>;

    /// Decode a received frame back to PCM-compatible RawAudio.
    fn decode(&mut self, frame: RawAudio) -> Result<RawAudio, AudioCodecError>;
}

/// Raw PCM passthrough codec for v0.1 timing bring-up.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawPcmAudioCodec;

impl RawPcmAudioCodec {
    /// Create a raw PCM passthrough codec.
    pub fn new() -> Self {
        Self
    }

    fn require_supported(frame: RawAudio) -> Result<RawAudio, AudioCodecError> {
        if frame.sample_format != AudioSampleFormat::PcmS16Le {
            return Err(AudioCodecError::UnsupportedFormat("expected pcm_s16le"));
        }
        if !frame.validate() {
            return Err(AudioCodecError::InvalidRawAudio);
        }
        Ok(frame)
    }
}

impl AudioCodec for RawPcmAudioCodec {
    fn name(&self) -> &'static str {
        "raw-pcm-s16le"
    }

    fn encode(&mut self, frame: RawAudio) -> Result<RawAudio, AudioCodecError> {
        Self::require_supported(frame)
    }

    fn decode(&mut self, frame: RawAudio) -> Result<RawAudio, AudioCodecError> {
        Self::require_supported(frame)
    }
}

#[cfg(feature = "opus")]
fn opus_channels(channels: u16) -> Result<opus::Channels, AudioCodecError> {
    match channels {
        1 => Ok(opus::Channels::Mono),
        2 => Ok(opus::Channels::Stereo),
        _ => Err(AudioCodecError::UnsupportedFormat(
            "opus supports mono or stereo",
        )),
    }
}

#[cfg(feature = "opus")]
fn raw_audio_i16_samples(frame: &RawAudio) -> Vec<i16> {
    frame
        .payload
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect()
}

/// Opus codec for production audio transport.
#[cfg(feature = "opus")]
pub struct OpusAudioCodec {
    encoder_channels: Option<u16>,
    decoder_channels: Option<u16>,
    encoder: Option<opus::Encoder>,
    decoder: Option<opus::Decoder>,
    bitrate_bps: i32,
    complexity: i32,
}

#[cfg(feature = "opus")]
impl OpusAudioCodec {
    /// Create an Opus codec with Xenia's default interactive-audio settings.
    pub fn new() -> Result<Self, AudioCodecError> {
        Ok(Self {
            encoder_channels: None,
            decoder_channels: None,
            encoder: None,
            decoder: None,
            bitrate_bps: 64_000,
            complexity: 5,
        })
    }

    /// Set Opus encoder bitrate in bits per second.
    pub fn with_bitrate_bps(mut self, bitrate_bps: i32) -> Self {
        self.bitrate_bps = bitrate_bps;
        self
    }

    /// Set Opus encoder complexity from 0 to 10.
    pub fn with_complexity(mut self, complexity: i32) -> Self {
        self.complexity = complexity.clamp(0, 10);
        self
    }

    fn encoder(&mut self, channels: u16) -> Result<&mut opus::Encoder, AudioCodecError> {
        if self.encoder_channels != Some(channels) {
            let mut encoder = opus::Encoder::new(
                RAW_AUDIO_SAMPLE_RATE_HZ,
                opus_channels(channels)?,
                opus::Application::Audio,
            )
            .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?;
            encoder
                .set_bitrate(opus::Bitrate::Bits(self.bitrate_bps))
                .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?;
            encoder
                .set_complexity(self.complexity)
                .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?;
            self.encoder = Some(encoder);
            self.encoder_channels = Some(channels);
        }
        self.encoder
            .as_mut()
            .ok_or_else(|| AudioCodecError::CodecFailure("opus encoder unavailable".to_string()))
    }

    fn decoder(&mut self, channels: u16) -> Result<&mut opus::Decoder, AudioCodecError> {
        if self.decoder_channels != Some(channels) {
            self.decoder = Some(
                opus::Decoder::new(RAW_AUDIO_SAMPLE_RATE_HZ, opus_channels(channels)?)
                    .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?,
            );
            self.decoder_channels = Some(channels);
        }
        self.decoder
            .as_mut()
            .ok_or_else(|| AudioCodecError::CodecFailure("opus decoder unavailable".to_string()))
    }
}

#[cfg(feature = "opus")]
impl AudioCodec for OpusAudioCodec {
    fn name(&self) -> &'static str {
        "opus"
    }

    fn encode(&mut self, mut frame: RawAudio) -> Result<RawAudio, AudioCodecError> {
        if frame.sample_format != AudioSampleFormat::PcmS16Le {
            return Err(AudioCodecError::UnsupportedFormat(
                "opus encoder expects pcm_s16le",
            ));
        }
        if !frame.validate() {
            return Err(AudioCodecError::InvalidRawAudio);
        }
        let channels = frame.channels;
        let samples = raw_audio_i16_samples(&frame);
        let packet = self
            .encoder(channels)?
            .encode_vec(&samples, RAW_AUDIO_MAX_OPUS_PAYLOAD_BYTES)
            .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?;

        frame.sample_format = AudioSampleFormat::Opus;
        frame.payload = packet;
        if frame.validate() {
            Ok(frame)
        } else {
            Err(AudioCodecError::InvalidRawAudio)
        }
    }

    fn decode(&mut self, mut frame: RawAudio) -> Result<RawAudio, AudioCodecError> {
        if frame.sample_format != AudioSampleFormat::Opus {
            return Err(AudioCodecError::UnsupportedFormat(
                "opus decoder expects opus",
            ));
        }
        if !frame.validate() {
            return Err(AudioCodecError::InvalidRawAudio);
        }
        let channels = frame.channels;
        let samples_per_channel =
            usize::from(frame.frame_duration_ms) * RAW_AUDIO_SAMPLE_RATE_HZ as usize / 1_000;
        let mut decoded = vec![0i16; samples_per_channel * usize::from(channels)];
        let decoded_per_channel = self
            .decoder(channels)?
            .decode(&frame.payload, &mut decoded, false)
            .map_err(|err| AudioCodecError::CodecFailure(err.to_string()))?;
        decoded.truncate(decoded_per_channel * usize::from(channels));

        let mut payload = Vec::with_capacity(decoded.len() * 2);
        for sample in decoded {
            payload.extend_from_slice(&sample.to_le_bytes());
        }
        frame.sample_format = AudioSampleFormat::PcmS16Le;
        frame.payload = payload;
        if frame.validate() {
            Ok(frame)
        } else {
            Err(AudioCodecError::InvalidRawAudio)
        }
    }
}

/// Synthetic audio generator shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticAudioKind {
    /// 440 Hz sine wave.
    Sine,
    /// Deterministic pseudo-random noise.
    Noise,
}

/// Deterministic 48 kHz stereo S16LE audio source for protocol tests.
pub struct SyntheticAudioSource {
    stream_id: u32,
    sequence: u64,
    kind: SyntheticAudioKind,
    phase: f64,
    rng: u32,
}

impl SyntheticAudioSource {
    /// Create a deterministic synthetic audio source.
    pub fn new(stream_id: u32, kind: SyntheticAudioKind) -> Self {
        Self {
            stream_id,
            sequence: 0,
            kind,
            phase: 0.0,
            rng: 0xC0FFEE,
        }
    }

    /// Generate one 20 ms, 48 kHz, stereo S16LE audio frame.
    pub fn next_frame(&mut self, capture_timestamp_ms: u64) -> RawAudio {
        const SAMPLE_RATE: u32 = 48_000;
        const CHANNELS: usize = 2;
        const FRAME_MS: u16 = 20;
        const SAMPLES_PER_CHANNEL: usize = SAMPLE_RATE as usize * FRAME_MS as usize / 1_000;

        let mut payload = Vec::with_capacity(SAMPLES_PER_CHANNEL * CHANNELS * 2);
        for _ in 0..SAMPLES_PER_CHANNEL {
            let sample = match self.kind {
                SyntheticAudioKind::Sine => {
                    let value = (self.phase.sin() * 12_000.0) as i16;
                    self.phase += std::f64::consts::TAU * 440.0 / f64::from(SAMPLE_RATE);
                    if self.phase > std::f64::consts::TAU {
                        self.phase -= std::f64::consts::TAU;
                    }
                    value
                }
                SyntheticAudioKind::Noise => {
                    self.rng = self.rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    ((self.rng >> 16) as i16).saturating_div(4)
                }
            };
            for _ in 0..CHANNELS {
                payload.extend_from_slice(&sample.to_le_bytes());
            }
        }

        let frame = RawAudio::pcm_s16le_48k_stereo_20ms(
            self.stream_id,
            self.sequence,
            capture_timestamp_ms,
            payload,
        );
        let frame = RawAudio {
            flags: audio_flags::SYNTHETIC,
            ..frame
        };
        self.sequence = self.sequence.wrapping_add(1);
        frame
    }
}

/// Result of inserting into an [`AudioJitterBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterInsert {
    /// Frame accepted.
    Inserted,
    /// Duplicate frame ignored.
    Duplicate,
    /// Frame arrived too late for the current playout cursor.
    Late,
}

/// Jitter buffer counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JitterStats {
    /// Accepted frames.
    pub inserted: u64,
    /// Frames emitted in sequence order.
    pub emitted: u64,
    /// Duplicate frames.
    pub duplicates: u64,
    /// Late frames.
    pub late: u64,
    /// Buffered frames dropped by depth policy.
    pub dropped: u64,
    /// Pop attempts where expected sequence was not available.
    pub underruns: u64,
    /// Missing sequence gaps observed on insert.
    pub gaps: u64,
}

/// Minimal sequence-based jitter buffer for raw audio bring-up.
pub struct AudioJitterBuffer {
    expected_sequence: u64,
    max_depth: usize,
    target_delay_frames: usize,
    frames: std::collections::BTreeMap<u64, RawAudio>,
    stats: JitterStats,
}

impl AudioJitterBuffer {
    /// Create a jitter buffer expecting `initial_sequence` first.
    pub fn new(initial_sequence: u64, max_depth: usize) -> Self {
        Self {
            expected_sequence: initial_sequence,
            max_depth: max_depth.max(1),
            target_delay_frames: 0,
            frames: std::collections::BTreeMap::new(),
            stats: JitterStats::default(),
        }
    }

    /// Create a jitter buffer that waits for `target_delay_frames` buffered frames
    /// before releasing the next expected sequence.
    pub fn with_playout_delay(
        initial_sequence: u64,
        max_depth: usize,
        target_delay_frames: usize,
    ) -> Self {
        let max_depth = max_depth.max(1);
        Self {
            expected_sequence: initial_sequence,
            max_depth,
            target_delay_frames: target_delay_frames.min(max_depth.saturating_sub(1)),
            frames: std::collections::BTreeMap::new(),
            stats: JitterStats::default(),
        }
    }

    /// Insert an audio frame.
    pub fn push(&mut self, frame: RawAudio) -> JitterInsert {
        if frame.sequence < self.expected_sequence {
            self.stats.late += 1;
            return JitterInsert::Late;
        }
        if self.frames.contains_key(&frame.sequence) {
            self.stats.duplicates += 1;
            return JitterInsert::Duplicate;
        }
        if frame.sequence > self.expected_sequence
            && !self.frames.contains_key(&self.expected_sequence)
        {
            self.stats.gaps += 1;
        }
        self.frames.insert(frame.sequence, frame);
        self.stats.inserted += 1;

        while self.frames.len() > self.max_depth {
            let Some((&sequence, _)) = self.frames.iter().next() else {
                break;
            };
            self.frames.remove(&sequence);
            self.stats.dropped += 1;
            if sequence == self.expected_sequence {
                self.expected_sequence = self.expected_sequence.wrapping_add(1);
                self.stats.underruns += 1;
            }
        }
        JitterInsert::Inserted
    }

    /// Pop the next expected frame when available.
    pub fn pop_next(&mut self) -> Option<RawAudio> {
        if let Some(frame) = self.frames.remove(&self.expected_sequence) {
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
            self.stats.emitted += 1;
            Some(frame)
        } else {
            self.stats.underruns += 1;
            None
        }
    }

    /// Pop the next frame only when enough buffered depth exists for playout.
    pub fn pop_ready(&mut self) -> Option<RawAudio> {
        if self.next_ready() {
            self.pop_next()
        } else {
            None
        }
    }

    /// Return true when the next expected frame is ready.
    pub fn next_ready(&self) -> bool {
        self.frames.contains_key(&self.expected_sequence)
            && self.frames.len() > self.target_delay_frames
    }

    /// Return the next expected sequence number.
    pub fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    /// Return jitter statistics.
    pub fn stats(&self) -> JitterStats {
        self.stats
    }
}

/// A single captured-screen frame on the forward path.
///
/// The `pixels` field carries raw bytes whose layout is determined by
/// `pixel_format`. For `Rgba8`, `pixels.len()` MUST equal
/// `width * height * 4`. The receiver is responsible for validating;
/// a malformed frame surfaces as a `RawFrame::validate` failure.
///
/// This struct is `Sealable`, which means it flows through the Xenia
/// wire as payload type `0x10` (FRAME) or `0x12` (FRAME_LZ4). The
/// server-side capture loop produces these; the viewer opens them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawFrame {
    /// Monotonic frame identifier. Resets on rekey (SPEC §6).
    pub frame_id: u64,
    /// Server-local milliseconds-since-Unix-epoch at capture time.
    /// Viewer uses this for latency measurement and frame-drop detection.
    pub timestamp_ms: u64,
    /// Frame width in pixels (or logical units for encoded formats).
    pub width: u32,
    /// Frame height.
    pub height: u32,
    /// Pixel layout / codec identifier.
    pub pixel_format: PixelFormat,
    /// Raw pixel bytes. For `Rgba8`, length MUST be `width * height * 4`.
    pub pixels: Vec<u8>,
}

impl RawFrame {
    /// Construct an `Rgba8` frame. Panics in debug builds if the pixel
    /// buffer's length doesn't match the declared dimensions.
    pub fn rgba8(
        frame_id: u64,
        timestamp_ms: u64,
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    ) -> Self {
        debug_assert_eq!(
            pixels.len() as u64,
            u64::from(width) * u64::from(height) * 4,
            "RawFrame::rgba8: pixel buffer length mismatch",
        );
        Self {
            frame_id,
            timestamp_ms,
            width,
            height,
            pixel_format: PixelFormat::Rgba8,
            pixels,
        }
    }

    /// Construct a frame carrying already-encoded bytes (H.264 NAL,
    /// VP9 packet, or xenia-video passthrough payload).
    ///
    /// `width` and `height` remain the logical frame dimensions — the
    /// decoder uses them for output buffer sizing. `bytes` is opaque;
    /// the decoder that produced it is responsible for interpreting
    /// the format.
    pub fn encoded(
        frame_id: u64,
        timestamp_ms: u64,
        width: u32,
        height: u32,
        format: PixelFormat,
        bytes: Vec<u8>,
    ) -> Self {
        debug_assert!(
            matches!(
                format,
                PixelFormat::H264
                    | PixelFormat::Vp9
                    | PixelFormat::Passthrough
                    | PixelFormat::Hdc
                    | PixelFormat::Telemetry
                    | PixelFormat::Audio
                    | PixelFormat::Capabilities
            ),
            "RawFrame::encoded requires an encoded PixelFormat variant",
        );
        Self {
            frame_id,
            timestamp_ms,
            width,
            height,
            pixel_format: format,
            pixels: bytes,
        }
    }

    /// Runtime check that the pixel buffer matches the declared layout.
    /// Called by the receive path before rendering; returns `false`
    /// when the frame should be dropped.
    pub fn validate(&self) -> bool {
        match self.pixel_format {
            PixelFormat::Rgba8 | PixelFormat::Bgra8 => {
                self.pixels.len() as u64 == u64::from(self.width) * u64::from(self.height) * 4
            }
            PixelFormat::H264
            | PixelFormat::Vp9
            | PixelFormat::Passthrough
            | PixelFormat::Hdc
            | PixelFormat::Telemetry
            | PixelFormat::Capabilities => {
                // Encoded and metadata formats are opaque here; the
                // relevant decoder has the actual say.
                !self.pixels.is_empty()
            }
            PixelFormat::Audio => RawAudio::from_frame(self).is_ok_and(|audio| audio.validate()),
        }
    }
}

impl RawTelemetry {
    /// Build a telemetry metadata frame.
    pub fn into_frame(self) -> Result<RawFrame, WireError> {
        let payload = bincode::serialize(&self).map_err(WireError::encode)?;
        Ok(RawFrame::encoded(
            self.frame_id,
            self.timestamp_ms,
            0,
            0,
            PixelFormat::Telemetry,
            payload,
        ))
    }

    /// Decode a telemetry metadata frame.
    pub fn from_frame(frame: &RawFrame) -> Result<Self, WireError> {
        if frame.pixel_format != PixelFormat::Telemetry {
            return Err(WireError::decode("RawFrame is not telemetry"));
        }
        bincode::deserialize(&frame.pixels).map_err(WireError::decode)
    }
}

impl RawCapabilities {
    /// Build a capabilities metadata frame.
    pub fn into_frame(self) -> Result<RawFrame, WireError> {
        let payload = bincode::serialize(&self).map_err(WireError::encode)?;
        Ok(RawFrame::encoded(
            self.frame_id,
            self.timestamp_ms,
            0,
            0,
            PixelFormat::Capabilities,
            payload,
        ))
    }

    /// Decode a capabilities metadata frame.
    pub fn from_frame(frame: &RawFrame) -> Result<Self, WireError> {
        if frame.pixel_format != PixelFormat::Capabilities {
            return Err(WireError::decode("RawFrame is not capabilities"));
        }
        bincode::deserialize(&frame.pixels).map_err(WireError::decode)
    }
}

impl Sealable for RawFrame {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// A viewer-side input event traveling on the reverse path.
///
/// The `payload` is opaque bytes with caller-defined semantics. For
/// M0 the convention is a UTF-8 JSON object, matching what
/// `xenia-viewer-web`'s viewer MVP emits. Future milestones may
/// switch to a typed enum; the opaque-bytes shape is deliberate so
/// the core crate doesn't have to ship a stable `InputEvent`
/// taxonomy before the viewer ecosystem agrees on one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawInput {
    /// Monotonic per-session input sequence. Independent of
    /// `xenia_wire`'s nonce sequence.
    pub sequence: u64,
    /// Viewer-local milliseconds-since-Unix-epoch at capture time.
    pub timestamp_ms: u64,
    /// Event payload. M0 convention: UTF-8 JSON.
    pub payload: Vec<u8>,
}

impl Sealable for RawInput {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_red(w: u32, h: u32) -> Vec<u8> {
        (0..(w * h)).flat_map(|_| [255u8, 0, 0, 255]).collect()
    }

    #[test]
    fn rgba8_roundtrip_preserves_bytes() {
        let frame = RawFrame::rgba8(1, 1_700_000_000_000, 4, 2, solid_red(4, 2));
        let bytes = frame.to_bin().unwrap();
        let decoded = RawFrame::from_bin(&bytes).unwrap();
        assert_eq!(decoded, frame);
        assert!(decoded.validate());
    }

    #[test]
    fn validate_rejects_mismatched_buffer() {
        let frame = RawFrame {
            frame_id: 1,
            timestamp_ms: 0,
            width: 10,
            height: 10,
            pixel_format: PixelFormat::Rgba8,
            pixels: vec![0u8; 5],
        };
        assert!(!frame.validate());
    }

    #[test]
    fn encoded_frame_accepts_opaque_bytes() {
        let frame = RawFrame {
            frame_id: 7,
            timestamp_ms: 0,
            width: 1920,
            height: 1080,
            pixel_format: PixelFormat::H264,
            pixels: vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42],
        };
        assert!(frame.validate());
    }

    #[test]
    fn input_roundtrip() {
        let input = RawInput {
            sequence: 42,
            timestamp_ms: 1_700_000_000_050,
            payload: br#"{"type":"mousemove","x":0.5,"y":0.5}"#.to_vec(),
        };
        let bytes = input.to_bin().unwrap();
        let decoded = RawInput::from_bin(&bytes).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn telemetry_roundtrip_through_raw_frame() {
        let telemetry = RawTelemetry {
            frame_id: 9,
            timestamp_ms: 1_700_000_000_100,
            backend: "test".to_string(),
            samples: vec![TelemetrySample {
                name: "cpu.total.percent".to_string(),
                value: TelemetryValue::F64(12.5),
                unit: Some("%".to_string()),
                timestamp_ms: 1_700_000_000_100,
            }],
        };
        let frame = telemetry.clone().into_frame().unwrap();
        assert_eq!(frame.pixel_format, PixelFormat::Telemetry);
        assert!(frame.validate());
        assert_eq!(RawTelemetry::from_frame(&frame).unwrap(), telemetry);
    }

    #[test]
    fn raw_audio_roundtrip_through_raw_frame() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_200);
        assert!(audio.validate());
        assert_eq!(audio.expected_payload_len(), Some(48_000 / 50 * 2 * 2));
        let frame = audio.clone().into_frame(11).unwrap();
        assert_eq!(frame.pixel_format, PixelFormat::Audio);
        assert!(frame.validate());
        assert_eq!(RawAudio::from_frame(&frame).unwrap(), audio);
    }

    #[test]
    fn raw_pcm_audio_codec_roundtrips_valid_audio() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_100);
        let mut codec = RawPcmAudioCodec::new();

        let encoded = codec.encode(audio.clone()).unwrap();
        let decoded = codec.decode(encoded).unwrap();

        assert_eq!(codec.name(), "raw-pcm-s16le");
        assert_eq!(decoded, audio);
    }

    #[test]
    fn raw_pcm_audio_codec_rejects_invalid_audio() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let mut audio = source.next_frame(1_700_000_000_100);
        audio.payload.pop();
        let mut codec = RawPcmAudioCodec::new();

        assert_eq!(codec.encode(audio), Err(AudioCodecError::InvalidRawAudio));
    }

    #[cfg(feature = "opus")]
    #[test]
    fn opus_audio_codec_compresses_and_decodes_to_valid_pcm() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_100);
        let mut codec = OpusAudioCodec::new().unwrap();

        let encoded = codec.encode(audio.clone()).unwrap();
        assert_eq!(encoded.sample_format, AudioSampleFormat::Opus);
        assert!(encoded.payload.len() < audio.payload.len());
        assert!(encoded.validate());

        let decoded = codec.decode(encoded).unwrap();
        assert_eq!(decoded.sample_format, AudioSampleFormat::PcmS16Le);
        assert_eq!(decoded.stream_id, audio.stream_id);
        assert_eq!(decoded.sequence, audio.sequence);
        assert_eq!(decoded.capture_timestamp_ms, audio.capture_timestamp_ms);
        assert_eq!(decoded.frame_duration_ms, audio.frame_duration_ms);
        assert!(decoded.validate());
        assert_eq!(decoded.payload.len(), audio.payload.len());
    }

    #[cfg(feature = "opus")]
    #[test]
    fn opus_audio_codec_rejects_raw_decode_input() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_100);
        let mut codec = OpusAudioCodec::new().unwrap();

        assert_eq!(
            codec.decode(audio),
            Err(AudioCodecError::UnsupportedFormat(
                "opus decoder expects opus"
            ))
        );
    }

    #[test]
    fn raw_audio_rejects_unsupported_schema_and_clock() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_200);
        assert!(audio.validate());

        let mut bad_schema = audio.clone();
        bad_schema.schema_version = RAW_AUDIO_SCHEMA_VERSION + 1;
        assert!(!bad_schema.validate());

        let mut bad_clock = audio;
        bad_clock.clock_domain = RAW_AUDIO_CLOCK_UNIX_MS + 1;
        assert!(!bad_clock.validate());
    }

    #[test]
    fn raw_audio_rejects_out_of_policy_config_and_flags() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_200);

        let mut bad_rate = audio.clone();
        bad_rate.sample_rate_hz = 96_000;
        assert!(!bad_rate.validate());

        let mut bad_channels = audio.clone();
        bad_channels.channels = RAW_AUDIO_MAX_CHANNELS + 1;
        bad_channels.payload.resize(48_000 / 50 * 3 * 2, 0);
        assert!(!bad_channels.validate());

        let mut bad_duration = audio.clone();
        bad_duration.frame_duration_ms = 30;
        bad_duration.payload.resize(48_000 / 1_000 * 30 * 2 * 2, 0);
        assert!(!bad_duration.validate());

        let mut bad_flags = audio;
        bad_flags.flags = audio_flags::KNOWN_MASK | (1 << 15);
        assert!(!bad_flags.validate());
    }

    #[test]
    fn raw_audio_rejects_oversized_and_truncated_payloads() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let mut audio = source.next_frame(1_700_000_000_200);
        audio.payload.push(0);
        assert!(!audio.validate());

        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let mut audio = source.next_frame(1_700_000_000_200);
        audio.payload.pop();
        assert!(!audio.validate());
    }

    #[test]
    fn raw_audio_frame_rejects_malformed_bincode_payload() {
        let frame = RawFrame::encoded(
            12,
            1_700_000_000_200,
            0,
            0,
            PixelFormat::Audio,
            vec![1, 2, 3],
        );
        assert!(!frame.validate());
        assert!(RawAudio::from_frame(&frame).is_err());
    }

    #[test]
    fn synthetic_audio_is_deterministic() {
        let mut a = SyntheticAudioSource::new(1, SyntheticAudioKind::Noise);
        let mut b = SyntheticAudioSource::new(1, SyntheticAudioKind::Noise);
        assert_eq!(
            a.next_frame(1_700_000_000_000).payload,
            b.next_frame(1_700_000_000_000).payload
        );
    }

    #[test]
    fn jitter_buffer_accepts_mild_reordering() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let f0 = source.next_frame(0);
        let f1 = source.next_frame(20);
        let mut jitter = AudioJitterBuffer::new(0, 8);
        assert_eq!(jitter.push(f1.clone()), JitterInsert::Inserted);
        assert_eq!(jitter.push(f0.clone()), JitterInsert::Inserted);
        assert_eq!(jitter.pop_next().unwrap().sequence, 0);
        assert_eq!(jitter.pop_next().unwrap().sequence, 1);
        assert_eq!(jitter.expected_sequence(), 2);
        assert_eq!(jitter.stats().emitted, 2);
    }

    #[test]
    fn jitter_buffer_detects_duplicate_late_gap_and_underrun() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let f0 = source.next_frame(0);
        let f1 = source.next_frame(20);
        let f2 = source.next_frame(40);
        let mut jitter = AudioJitterBuffer::new(0, 8);
        assert_eq!(jitter.push(f1.clone()), JitterInsert::Inserted);
        assert_eq!(jitter.push(f1), JitterInsert::Duplicate);
        assert!(jitter.pop_next().is_none());
        assert_eq!(jitter.push(f0.clone()), JitterInsert::Inserted);
        assert_eq!(jitter.pop_next().unwrap().sequence, 0);
        assert_eq!(jitter.pop_next().unwrap().sequence, 1);
        assert_eq!(jitter.push(f0), JitterInsert::Late);
        assert_eq!(jitter.push(f2), JitterInsert::Inserted);
        let stats = jitter.stats();
        assert_eq!(stats.duplicates, 1);
        assert_eq!(stats.late, 1);
        assert!(stats.gaps >= 1);
        assert!(stats.underruns >= 1);
    }

    #[test]
    fn jitter_buffer_honors_target_playout_delay() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let f0 = source.next_frame(0);
        let f1 = source.next_frame(20);
        let f2 = source.next_frame(40);
        let mut jitter = AudioJitterBuffer::with_playout_delay(0, 8, 2);

        assert_eq!(jitter.push(f0), JitterInsert::Inserted);
        assert!(!jitter.next_ready());
        assert_eq!(jitter.push(f1), JitterInsert::Inserted);
        assert!(!jitter.next_ready());
        assert_eq!(jitter.push(f2), JitterInsert::Inserted);
        assert_eq!(jitter.pop_ready().unwrap().sequence, 0);
        assert_eq!(jitter.stats().emitted, 1);
    }

    #[test]
    fn jitter_buffer_counts_depth_drops() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let f0 = source.next_frame(0);
        let f1 = source.next_frame(20);
        let f2 = source.next_frame(40);
        let mut jitter = AudioJitterBuffer::new(0, 2);

        assert_eq!(jitter.push(f0), JitterInsert::Inserted);
        assert_eq!(jitter.push(f1), JitterInsert::Inserted);
        assert_eq!(jitter.push(f2), JitterInsert::Inserted);
        assert_eq!(jitter.stats().dropped, 1);
        assert_eq!(jitter.stats().underruns, 1);
        assert_eq!(jitter.expected_sequence(), 1);
    }
}
