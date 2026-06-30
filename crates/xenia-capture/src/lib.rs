// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions derived from `symthaea/src/swarm/rdp_capture.rs`.
// Relicensed to Apache-2.0 OR MIT for this crate by the copyright
// holder (same author); see ADR-002 for the library-vs-binary
// licensing rationale. Per VIEWER_PLAN §0.1, `rdp_capture.rs` was
// explicitly listed as a "carry wholesale" artifact for this crate;
// the pure-Rust trait + TestCapture + BlankCapture pieces below are
// extracted directly. The X11 implementation present in the
// upstream was dropped per ADR-001 Decision 2 (Wayland-only).

//! # xenia-capture
//!
//! Host-ingestion abstractions for the Xenia remote-session stack.
//!
//! The crate is deliberately trait-first: daemon code consumes stable
//! display, audio, input, and telemetry interfaces while platform
//! backends hide OS-specific APIs behind those traits.
//!
//! Implements a platform-agnostic [`ScreenCapture`] trait with these
//! display implementations:
//!
//! - [`TestCapture`] — deterministic synthetic gradient frames with a
//!   per-frame-varying "active region" that simulates cursor motion.
//!   Always available. Used by unit + integration tests.
//! - [`BlankCapture`] — solid-color frames. Always available. Useful
//!   for bandwidth smoke tests where content is irrelevant.
//! - `ScapCapture` — cross-platform (Windows WGC, macOS
//!   ScreenCaptureKit, Linux PipeWire via xdg-desktop-portal)
//!   backed by the `scap` crate. Feature-gated on `scap-backend`.
//!   Primary backend per `mycelix-sovereign` ADR 0001.
//! - `WlrootsCapture` — wlr-screencopy-unstable-v1 on wlroots
//!   compositors (Sway, Hyprland, labwc). Feature-gated on
//!   `wayland-wlroots`. Scaffold only; superseded by `scap-backend`
//!   for most deployments via the xdg-desktop-portal-wlr bridge.
//! - `PortalCapture` — hand-rolled xdg-desktop-portal ScreenCast on
//!   GNOME/KDE. Feature-gated on `wayland-portal`. Scaffold only;
//!   superseded by `scap-backend`.
//!
//! X11 is explicitly out of scope — see the repo-level
//! `docs/ADR-001-m0-architecture.md` for the reasoning. The X11
//! server's shared-buffer design permits any client to read any
//! other client's input and framebuffer, which fundamentally undoes
//! Xenia's end-to-end threat model.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "scap-backend")]
mod scap_backend;

#[cfg(feature = "scap-backend")]
pub use scap_backend::{ScapCapture, ScapOptions, ScapResolution};

use serde::{Deserialize, Serialize};
#[cfg(feature = "audio-cpal")]
use std::collections::VecDeque;
#[cfg(feature = "audio-cpal")]
use std::sync::{Arc, Mutex};
use sysinfo::System;
use thiserror::Error;

/// Errors surfaced by a capture backend.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Backend-specific failure. Wrapped for logs; callers should
    /// drop the frame and retry on the next tick.
    #[error("capture backend: {0}")]
    Backend(String),

    /// The requested capture backend is not built into this binary
    /// (missing Cargo feature) or not available on the current
    /// system (compositor doesn't speak the required protocol).
    #[error("capture unavailable: {0}")]
    Unavailable(String),

    /// The compositor's user-consent prompt was denied, cancelled,
    /// or timed out. Distinct from [`CaptureError::Backend`]
    /// because callers may want to surface a UX message rather
    /// than retry.
    #[error("capture consent denied")]
    ConsentDenied,
}

/// Errors surfaced by non-display ingestion backends.
#[derive(Debug, Error)]
pub enum IngestionError {
    /// Backend-specific failure.
    #[error("ingestion backend: {0}")]
    Backend(String),

    /// The requested backend is not available on this host or build.
    #[error("ingestion unavailable: {0}")]
    Unavailable(String),

    /// The operating system or user denied permission.
    #[error("ingestion consent denied")]
    ConsentDenied,
}

/// Frame capture result, potentially wrapping a DMABUF handle.
#[derive(Clone, Debug)]
pub struct CapturedFrame {
    /// Captured frame width in pixels.
    pub width: u32,
    /// Captured frame height in pixels.
    pub height: u32,
    /// Captured frame backing data.
    pub data: FrameData,
}

/// Backing storage for a captured frame.
#[derive(Clone, Debug)]
pub enum FrameData {
    /// Tightly packed RGBA pixel bytes.
    Pixels(Vec<u8>),
    /// DMA-BUF frame handle and plane metadata.
    Dmabuf {
        /// File descriptor for the DMA-BUF.
        fd: i32,
        /// DRM fourcc pixel format.
        format: u32,
        /// DRM format modifier.
        modifier: u64,
        /// Plane offsets and strides.
        planes: Vec<Plane>,
    },
}

/// One DMA-BUF plane.
#[derive(Debug, Clone)]
pub struct Plane {
    /// Byte offset of the plane in the buffer.
    pub offset: u32,
    /// Row stride in bytes.
    pub stride: u32,
}

impl CapturedFrame {
    /// Return tightly packed pixel bytes when this frame is CPU-backed.
    pub fn pixels(&self) -> Option<&[u8]> {
        match &self.data {
            FrameData::Pixels(pixels) => Some(pixels),
            FrameData::Dmabuf { .. } => None,
        }
    }
}

/// Monitor information for multi-monitor enumeration.
#[derive(Debug, Clone)]
pub struct MonitorDescriptor {
    /// Monitor index (0-based).
    pub index: u8,
    /// Display name (e.g., "eDP-1", "HDMI-A-1", "DP-2").
    pub name: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Whether this is the primary monitor.
    pub is_primary: bool,
    /// X offset in the virtual desktop (for multi-monitor layouts).
    pub x_offset: i32,
    /// Y offset in the virtual desktop.
    pub y_offset: i32,
}

/// Platform-agnostic screen-capture interface.
///
/// Implementations are `Send` so a capture loop can run on a
/// dedicated tokio task. They are NOT `Sync` because most underlying
/// Wayland bindings hold non-Sync state (wayland-client
/// `EventQueue`, portal DBus connections).
pub trait ScreenCapture: Send {
    /// Capture the current screen contents.
    ///
    /// Returns `Ok(Some(frame))` on success, `Ok(None)` if the
    /// backend has no new frame to report this tick (e.g., the
    /// compositor hasn't submitted one yet), and `Err(_)` on fatal
    /// failures the caller should surface to the user.
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError>;

    /// Screen width in pixels.
    fn width(&self) -> u32;

    /// Screen height in pixels.
    fn height(&self) -> u32;

    /// Enumerate available monitors. Default: single monitor at
    /// `0, 0` with `(width(), height())`.
    fn enumerate_monitors(&self) -> Vec<MonitorDescriptor> {
        vec![MonitorDescriptor {
            index: 0,
            name: "default".to_string(),
            width: self.width(),
            height: self.height(),
            is_primary: true,
            x_offset: 0,
            y_offset: 0,
        }]
    }

    /// Select a specific monitor for capture. Returns `true` if the
    /// backend accepted the selection.
    fn select_monitor(&mut self, _index: u8) -> bool {
        true
    }

    /// Identifier string for the active backend. Used for
    /// observability; stable for a given crate version.
    fn backend_name(&self) -> &str;
}

/// Interleaved PCM audio captured from a host source.
#[derive(Clone, Debug, PartialEq)]
pub struct AudioFrame {
    /// Sample rate in Hz.
    pub sample_rate_hz: u32,
    /// Channel count.
    pub channels: u16,
    /// Signed 16-bit interleaved samples.
    pub samples_i16: Vec<i16>,
    /// Capture timestamp in milliseconds since Unix epoch when known.
    pub timestamp_ms: u64,
}

/// Platform-agnostic audio-capture interface.
///
/// Real device backends may be thread-affine. For example, CPAL
/// streams are intentionally not `Send` on every platform, so callers
/// should keep capture on the task/thread that owns the backend.
pub trait AudioCapture {
    /// Capture the next audio frame, or `Ok(None)` when no data is
    /// currently available.
    fn capture_audio(&mut self) -> Result<Option<AudioFrame>, IngestionError>;

    /// Identifier string for the active backend.
    fn backend_name(&self) -> &str;
}

/// Pointer button for host input injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerButton {
    /// Primary button.
    Primary,
    /// Secondary button.
    Secondary,
    /// Middle button.
    Middle,
}

/// Host input event expressed in display-coordinate space.
#[derive(Clone, Debug, PartialEq)]
pub enum InputEvent {
    /// Move pointer to absolute coordinates.
    PointerMove {
        /// X coordinate in display space.
        x: i32,
        /// Y coordinate in display space.
        y: i32,
    },
    /// Press or release a pointer button.
    PointerButton {
        /// Pointer button.
        button: PointerButton,
        /// `true` for press, `false` for release.
        pressed: bool,
    },
    /// Scroll wheel or touchpad delta.
    Scroll {
        /// Horizontal scroll delta.
        delta_x: f32,
        /// Vertical scroll delta.
        delta_y: f32,
    },
    /// Keyboard key by platform-neutral symbolic name.
    Key {
        /// Symbolic key name.
        key: String,
        /// `true` for press, `false` for release.
        pressed: bool,
    },
    /// UTF-8 text input.
    Text(String),
}

/// Platform-agnostic input-injection interface.
pub trait InputInjector: Send {
    /// Inject one input event into the host OS.
    fn inject(&mut self, event: InputEvent) -> Result<(), IngestionError>;

    /// Identifier string for the active backend.
    fn backend_name(&self) -> &str;
}

/// Scalar telemetry value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// Platform-agnostic telemetry stream.
pub trait TelemetryStream: Send {
    /// Poll currently available telemetry samples.
    fn poll_samples(&mut self) -> Result<Vec<TelemetrySample>, IngestionError>;

    /// Identifier string for the active backend.
    fn backend_name(&self) -> &str;
}

/// Host capabilities exposed by an ingestion backend.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestionCapabilities {
    /// Display frames are available.
    pub display: bool,
    /// Host loopback or microphone audio is available.
    pub audio: bool,
    /// Input injection is available.
    pub input: bool,
    /// System telemetry is available.
    pub telemetry: bool,
}

/// Test audio source that emits silence.
pub struct SilentAudioCapture {
    sample_rate_hz: u32,
    channels: u16,
    frame_samples: usize,
}

impl SilentAudioCapture {
    /// Create a silent audio source.
    pub fn new(sample_rate_hz: u32, channels: u16, frame_samples: usize) -> Self {
        Self {
            sample_rate_hz,
            channels,
            frame_samples,
        }
    }
}

impl AudioCapture for SilentAudioCapture {
    fn capture_audio(&mut self) -> Result<Option<AudioFrame>, IngestionError> {
        Ok(Some(AudioFrame {
            sample_rate_hz: self.sample_rate_hz,
            channels: self.channels,
            samples_i16: vec![0; self.frame_samples * usize::from(self.channels)],
            timestamp_ms: 0,
        }))
    }

    fn backend_name(&self) -> &str {
        "silent-audio"
    }
}

/// CPAL-backed host audio capture.
///
/// The backend captures from the default input device and emits 20 ms
/// S16LE-equivalent frames. Linux builds require ALSA development
/// headers because CPAL 0.15 uses ALSA on Linux.
#[cfg(feature = "audio-cpal")]
pub struct CpalAudioCapture {
    sample_rate_hz: u32,
    channels: u16,
    frame_samples_per_channel: usize,
    buffer: Arc<Mutex<VecDeque<i16>>>,
    _stream: cpal::Stream,
}

#[cfg(feature = "audio-cpal")]
impl CpalAudioCapture {
    /// Create a capture stream from the default host input device.
    pub fn new_default_input() -> Result<Self, IngestionError> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or_else(|| IngestionError::Unavailable("no default audio input device".into()))?;
        let device_name = device.name().unwrap_or_else(|_| "unknown".to_string());
        let supported = device
            .default_input_config()
            .map_err(|err| IngestionError::Backend(err.to_string()))?;
        let sample_rate_hz = supported.sample_rate().0;
        let channels = supported.channels();
        if channels == 0 {
            return Err(IngestionError::Unavailable(
                "default audio input reports zero channels".into(),
            ));
        }

        if sample_rate_hz != 48_000 {
            return Err(IngestionError::Unavailable(format!(
                "default audio input uses {sample_rate_hz} Hz; RawAudio v0.1 capture requires 48000 Hz"
            )));
        }
        if channels > 2 {
            return Err(IngestionError::Unavailable(format!(
                "default audio input reports {channels} channels; RawAudio v0.1 capture supports at most 2"
            )));
        }

        let frame_samples_per_channel = usize::try_from(sample_rate_hz / 50)
            .map_err(|_| IngestionError::Backend("sample rate does not fit usize".into()))?;

        let config: cpal::StreamConfig = supported.clone().into();
        let buffer = Arc::new(Mutex::new(VecDeque::<i16>::new()));
        let err_fn = |err| tracing::warn!(error = %err, "audio input stream error");
        let stream = match supported.sample_format() {
            cpal::SampleFormat::F32 => {
                let buffer = Arc::clone(&buffer);
                device.build_input_stream(
                    &config,
                    move |data: &[f32], _| push_f32_samples(data, &buffer),
                    err_fn,
                    None,
                )
            }
            cpal::SampleFormat::I16 => {
                let buffer = Arc::clone(&buffer);
                device.build_input_stream(
                    &config,
                    move |data: &[i16], _| push_i16_samples(data, &buffer),
                    err_fn,
                    None,
                )
            }
            cpal::SampleFormat::U16 => {
                let buffer = Arc::clone(&buffer);
                device.build_input_stream(
                    &config,
                    move |data: &[u16], _| push_u16_samples(data, &buffer),
                    err_fn,
                    None,
                )
            }
            other => {
                return Err(IngestionError::Unavailable(format!(
                    "unsupported input sample format: {other:?}"
                )));
            }
        }
        .map_err(|err| IngestionError::Backend(err.to_string()))?;
        stream
            .play()
            .map_err(|err| IngestionError::Backend(err.to_string()))?;

        tracing::info!(
            device = %device_name,
            sample_rate_hz,
            channels,
            sample_format = ?supported.sample_format(),
            "audio input stream started"
        );

        Ok(Self {
            sample_rate_hz,
            channels,
            frame_samples_per_channel,
            buffer,
            _stream: stream,
        })
    }
}

#[cfg(feature = "audio-cpal")]
impl AudioCapture for CpalAudioCapture {
    fn capture_audio(&mut self) -> Result<Option<AudioFrame>, IngestionError> {
        let samples_needed = self
            .frame_samples_per_channel
            .checked_mul(usize::from(self.channels))
            .ok_or_else(|| IngestionError::Backend("audio frame sample count overflow".into()))?;
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| IngestionError::Backend("audio input buffer poisoned".into()))?;
        if buffer.len() < samples_needed {
            return Ok(None);
        }

        let mut samples_i16 = Vec::with_capacity(samples_needed);
        for _ in 0..samples_needed {
            if let Some(sample) = buffer.pop_front() {
                samples_i16.push(sample);
            }
        }
        drop(buffer);

        Ok(Some(AudioFrame {
            sample_rate_hz: self.sample_rate_hz,
            channels: self.channels,
            samples_i16,
            timestamp_ms: now_ms(),
        }))
    }

    fn backend_name(&self) -> &str {
        "cpal-audio"
    }
}

#[cfg(feature = "audio-cpal")]
fn push_i16_samples(data: &[i16], buffer: &Arc<Mutex<VecDeque<i16>>>) {
    push_samples(data.iter().copied(), buffer);
}

#[cfg(feature = "audio-cpal")]
fn push_f32_samples(data: &[f32], buffer: &Arc<Mutex<VecDeque<i16>>>) {
    push_samples(
        data.iter()
            .map(|sample| (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round() as i16),
        buffer,
    );
}

#[cfg(feature = "audio-cpal")]
fn push_u16_samples(data: &[u16], buffer: &Arc<Mutex<VecDeque<i16>>>) {
    push_samples(
        data.iter()
            .map(|sample| i32::from(*sample) - 32_768)
            .map(|sample| sample.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16),
        buffer,
    );
}

#[cfg(feature = "audio-cpal")]
fn push_samples(samples: impl IntoIterator<Item = i16>, buffer: &Arc<Mutex<VecDeque<i16>>>) {
    const MAX_BUFFERED_SAMPLES: usize = 48_000 * 2;
    if let Ok(mut buffer) = buffer.lock() {
        for sample in samples {
            if buffer.len() >= MAX_BUFFERED_SAMPLES {
                buffer.pop_front();
            }
            buffer.push_back(sample);
        }
    }
}

/// Input injector used by tests and dry-run deployments.
#[derive(Default)]
pub struct NullInputInjector {
    events: Vec<InputEvent>,
}

impl NullInputInjector {
    /// Return injected events captured so far.
    pub fn events(&self) -> &[InputEvent] {
        &self.events
    }
}

impl InputInjector for NullInputInjector {
    fn inject(&mut self, event: InputEvent) -> Result<(), IngestionError> {
        self.events.push(event);
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "null-input"
    }
}

/// Deterministic telemetry source for tests and demos.
pub struct TestTelemetryStream {
    tick: u64,
}

impl TestTelemetryStream {
    /// Create a deterministic telemetry stream.
    pub fn new() -> Self {
        Self { tick: 0 }
    }
}

impl Default for TestTelemetryStream {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryStream for TestTelemetryStream {
    fn poll_samples(&mut self) -> Result<Vec<TelemetrySample>, IngestionError> {
        self.tick += 1;
        Ok(vec![TelemetrySample {
            name: "test.tick".to_string(),
            value: TelemetryValue::U64(self.tick),
            unit: None,
            timestamp_ms: self.tick,
        }])
    }

    fn backend_name(&self) -> &str {
        "test-telemetry"
    }
}

/// Cross-platform telemetry source backed by `sysinfo`.
pub struct SysinfoTelemetryStream {
    system: System,
}

impl SysinfoTelemetryStream {
    /// Create a sysinfo-backed telemetry stream.
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_memory();
        system.refresh_cpu();
        Self { system }
    }
}

impl Default for SysinfoTelemetryStream {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryStream for SysinfoTelemetryStream {
    fn poll_samples(&mut self) -> Result<Vec<TelemetrySample>, IngestionError> {
        self.system.refresh_memory();
        self.system.refresh_cpu();
        let timestamp_ms = now_ms();
        let mut samples = vec![
            TelemetrySample {
                name: "cpu.total.percent".to_string(),
                value: TelemetryValue::F64(f64::from(self.system.global_cpu_info().cpu_usage())),
                unit: Some("%".to_string()),
                timestamp_ms,
            },
            TelemetrySample {
                name: "memory.total.bytes".to_string(),
                value: TelemetryValue::U64(self.system.total_memory()),
                unit: Some("bytes".to_string()),
                timestamp_ms,
            },
            TelemetrySample {
                name: "memory.used.bytes".to_string(),
                value: TelemetryValue::U64(self.system.used_memory()),
                unit: Some("bytes".to_string()),
                timestamp_ms,
            },
        ];

        if let Some(host_name) = System::host_name() {
            samples.push(TelemetrySample {
                name: "host.name".to_string(),
                value: TelemetryValue::Text(host_name),
                unit: None,
                timestamp_ms,
            });
        }
        if let Some(os_version) = System::long_os_version() {
            samples.push(TelemetrySample {
                name: "host.os.version".to_string(),
                value: TelemetryValue::Text(os_version),
                unit: None,
                timestamp_ms,
            });
        }

        Ok(samples)
    }

    fn backend_name(&self) -> &str {
        "sysinfo"
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
}

// ───────────────────────── TestCapture ─────────────────────────────

/// Deterministic test capture: generates synthetic gradient frames.
///
/// Each frame has a unique pattern based on a frame counter, which
/// makes it useful for reproducible delta-detection, codec, and
/// end-to-end pipeline testing.
pub struct TestCapture {
    width: u32,
    height: u32,
    frame_counter: u64,
    /// `(x, y, size)` region that changes each frame (simulates
    /// cursor or selection-rectangle motion).
    active_region: (u32, u32, u32),
}

impl TestCapture {
    /// Create a test capture with given resolution. The active
    /// region defaults to a 64×64 square at `(100, 100)`.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            frame_counter: 0,
            active_region: (100, 100, 64),
        }
    }

    /// Override the active-region rectangle.
    pub fn set_active_region(&mut self, x: u32, y: u32, size: u32) {
        self.active_region = (x, y, size);
    }

    /// Current frame counter. Useful for per-test assertions.
    pub fn frame_counter(&self) -> u64 {
        self.frame_counter
    }
}

impl ScreenCapture for TestCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        let w = self.width as usize;
        let h = self.height as usize;
        let mut pixels = vec![0u8; w * h * 4];

        // Static background: gradient based on position (deterministic).
        for y in 0..h {
            for x in 0..w {
                let offset = (y * w + x) * 4;
                pixels[offset] = (x * 255 / w) as u8; // R: horizontal
                pixels[offset + 1] = (y * 255 / h) as u8; // G: vertical
                pixels[offset + 2] = 128; // B: constant
                pixels[offset + 3] = 255; // A: opaque
            }
        }

        // Active region: changes each frame (simulates user activity).
        let (rx, ry, rs) = self.active_region;
        let phase = (self.frame_counter % 256) as u8;
        for dy in 0..rs as usize {
            let y = ry as usize + dy;
            if y >= h {
                break;
            }
            for dx in 0..rs as usize {
                let x = rx as usize + dx;
                if x >= w {
                    break;
                }
                let offset = (y * w + x) * 4;
                pixels[offset] = phase;
                pixels[offset + 1] = phase.wrapping_add(64);
                pixels[offset + 2] = phase.wrapping_add(128);
            }
        }

        self.frame_counter += 1;

        Ok(Some(CapturedFrame {
            data: FrameData::Pixels(pixels),
            width: self.width,
            height: self.height,
        }))
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn backend_name(&self) -> &str {
        "test"
    }
}

// ───────────────────────── BlankCapture ────────────────────────────

/// Solid-color capture. Returns the same bytes every tick.
///
/// Useful for bandwidth smoke tests where content doesn't matter —
/// the encoded stream compresses to essentially nothing, so you
/// measure pure framing and transport overhead.
pub struct BlankCapture {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

impl BlankCapture {
    /// Create a blank capture at `width × height` filled with
    /// `(r, g, b, 255)`.
    pub fn new(width: u32, height: u32, r: u8, g: u8, b: u8) -> Self {
        let n = width as usize * height as usize;
        let mut pixels = vec![0u8; n * 4];
        for i in 0..n {
            pixels[i * 4] = r;
            pixels[i * 4 + 1] = g;
            pixels[i * 4 + 2] = b;
            pixels[i * 4 + 3] = 255;
        }
        Self {
            width,
            height,
            pixels,
        }
    }
}

impl ScreenCapture for BlankCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        Ok(Some(CapturedFrame {
            data: FrameData::Pixels(self.pixels.clone()),
            width: self.width,
            height: self.height,
        }))
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn backend_name(&self) -> &str {
        "blank"
    }
}

// ───────────────────────── Wayland backends (scaffold) ─────────────

/// wlr-screencopy-unstable-v1 capture for wlroots-based compositors
/// (Sway, Hyprland, labwc).
///
/// **M1 scaffold only.** The wayland-client handshake, protocol
/// negotiation, and DMA-BUF plumbing land in M1.2b. Today the type
/// exists so the `ScreenCapture` dyn-trait path compiles against a
/// future caller, and so downstream code can `#[cfg]`-select on
/// feature availability without breaking.
///
/// Requires the `wayland-wlroots` feature.
#[cfg(feature = "wayland-wlroots")]
pub struct WlrootsCapture {
    width: u32,
    height: u32,
}

#[cfg(feature = "wayland-wlroots")]
impl WlrootsCapture {
    /// Connect to the compositor and negotiate wlr-screencopy.
    /// **Currently unimplemented.**
    pub fn new() -> Result<Self, CaptureError> {
        Err(CaptureError::Unavailable(
            "wlr-screencopy backend lands in M1.2b; scaffold only".into(),
        ))
    }
}

#[cfg(feature = "wayland-wlroots")]
impl ScreenCapture for WlrootsCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        Err(CaptureError::Unavailable(
            "wlr-screencopy backend lands in M1.2b".into(),
        ))
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn backend_name(&self) -> &str {
        "wlroots-screencopy"
    }
}

/// xdg-desktop-portal ScreenCast capture for GNOME / KDE and other
/// portal-speaking compositors.
///
/// **M1 scaffold only.** The portal DBus handshake + PipeWire
/// stream-read loop land in M1.2c.
///
/// Requires the `wayland-portal` feature.
#[cfg(feature = "wayland-portal")]
pub struct PortalCapture {
    width: u32,
    height: u32,
}

#[cfg(feature = "wayland-portal")]
impl PortalCapture {
    /// Call the portal's `CreateSession` + `SelectSources` +
    /// `Start` interfaces. **Currently unimplemented.**
    pub fn new() -> Result<Self, CaptureError> {
        Err(CaptureError::Unavailable(
            "portal ScreenCast backend lands in M1.2c; scaffold only".into(),
        ))
    }
}

#[cfg(feature = "wayland-portal")]
impl ScreenCapture for PortalCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        Err(CaptureError::Unavailable(
            "portal ScreenCast backend lands in M1.2c".into(),
        ))
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn backend_name(&self) -> &str {
        "xdg-portal-screencast"
    }
}

// ───────────────────────── Tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_produces_frame_of_declared_size() {
        let mut cap = TestCapture::new(160, 120);
        let f = cap.capture().unwrap().unwrap();
        assert_eq!(f.width, 160);
        assert_eq!(f.height, 120);
        assert_eq!(f.pixels().unwrap().len(), 160 * 120 * 4);
    }

    #[test]
    fn test_capture_frames_are_deterministic_but_not_identical() {
        let mut cap = TestCapture::new(64, 64);
        // Default active_region is (100, 100) — out of bounds for
        // 64×64. Place it in-bounds so successive frames differ.
        cap.set_active_region(8, 8, 16);
        let f0 = cap.capture().unwrap().unwrap();
        let f1 = cap.capture().unwrap().unwrap();
        // Different frame counter ⇒ the active region differs.
        assert_ne!(f0.pixels().unwrap(), f1.pixels().unwrap());
        // But recreate cap and the sequence is identical.
        let mut cap2 = TestCapture::new(64, 64);
        cap2.set_active_region(8, 8, 16);
        let g0 = cap2.capture().unwrap().unwrap();
        assert_eq!(f0.pixels().unwrap(), g0.pixels().unwrap());
    }

    #[test]
    fn blank_capture_is_idempotent() {
        let mut cap = BlankCapture::new(32, 32, 0x10, 0x20, 0x30);
        let f0 = cap.capture().unwrap().unwrap();
        let f1 = cap.capture().unwrap().unwrap();
        let p0 = f0.pixels().unwrap();
        let p1 = f1.pixels().unwrap();
        assert_eq!(p0, p1);
        assert_eq!(p0[0], 0x10);
        assert_eq!(p0[1], 0x20);
        assert_eq!(p0[2], 0x30);
        assert_eq!(p0[3], 255);
    }

    #[test]
    fn default_enumerate_returns_single_monitor() {
        let cap = TestCapture::new(800, 600);
        let mons = cap.enumerate_monitors();
        assert_eq!(mons.len(), 1);
        assert_eq!(mons[0].width, 800);
        assert_eq!(mons[0].height, 600);
        assert!(mons[0].is_primary);
    }

    #[test]
    fn silent_audio_capture_emits_interleaved_silence() {
        let mut audio = SilentAudioCapture::new(48_000, 2, 480);
        let frame = audio.capture_audio().unwrap().unwrap();
        assert_eq!(frame.sample_rate_hz, 48_000);
        assert_eq!(frame.channels, 2);
        assert_eq!(frame.samples_i16.len(), 960);
        assert!(frame.samples_i16.iter().all(|sample| *sample == 0));
    }

    #[test]
    fn null_input_records_events() {
        let mut input = NullInputInjector::default();
        input
            .inject(InputEvent::PointerMove { x: 10, y: 20 })
            .unwrap();
        assert_eq!(input.events(), &[InputEvent::PointerMove { x: 10, y: 20 }]);
    }

    #[test]
    fn test_telemetry_stream_ticks_forward() {
        let mut telemetry = TestTelemetryStream::new();
        let first = telemetry.poll_samples().unwrap();
        let second = telemetry.poll_samples().unwrap();
        assert_eq!(first[0].value, TelemetryValue::U64(1));
        assert_eq!(second[0].value, TelemetryValue::U64(2));
    }

    #[test]
    fn sysinfo_telemetry_reports_basic_host_metrics() {
        let mut telemetry = SysinfoTelemetryStream::new();
        let samples = telemetry.poll_samples().unwrap();
        assert!(samples.iter().any(|s| s.name == "cpu.total.percent"));
        assert!(samples.iter().any(|s| s.name == "memory.total.bytes"));
        assert!(samples.iter().any(|s| s.name == "memory.used.bytes"));
    }
}
