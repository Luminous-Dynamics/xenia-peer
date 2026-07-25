// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `xenia-viewer` — native client that connects to an `xenia-peer`
//! daemon and receives + decodes sealed frames.
//!
//! Two output modes, selected by `--gui`:
//!
//! - **CLI (default)** — logs frame-receive statistics to stdout.
//!   Useful for smoke tests, the `--verify` byte-exact check, and
//!   headless CI.
//! - **GUI (`--gui`)** — opens an egui window and renders every
//!   decoded frame at 1:1. Status bar shows codec + transport +
//!   frames-received + last-wire-bytes + fps.
//!
//! Both modes share the same receive/decode pipeline; the flag
//! selects the output sink.

#[cfg(feature = "audio-output")]
use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(feature = "audio-output")]
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tracing::{info, warn};
use xenia_capture::{ScreenCapture, TestCapture};
#[cfg(feature = "audio-opus")]
use xenia_peer_core::OpusAudioCodec;
use xenia_peer_core::advertisement::{
    AdvertisedAudioCodec, AdvertisedTransport, TransportAdvertisement,
};
use xenia_peer_core::frame::{
    PixelFormat as FramePixelFormat, RawAudio, RawCapabilities, RawClipboard, RawRekey,
    RawTelemetry, audio_flags,
};
use xenia_peer_core::handshake::{
    NegotiatedTransport, SessionCapabilityGuard, perform_viewer_handshake_with_transcript,
};
use xenia_peer_core::transport::{
    RecvEnvelope, SendEnvelope, TcpRecvHalf, TcpSendHalf, TcpTransport, Transport, TransportError,
};
use xenia_peer_core::{
    AudioCodec, AudioJitterBuffer, ClipboardContent, HandshakeManager, LaneSession,
    RawPcmAudioCodec, RekeyPolicy, SessionEpochState, derive_negotiated_context_key,
};
use xenia_transport_quic::{
    QuicRecvHalf, QuicSendHalf, QuicTransport, bind_xenia_endpoint, decode_endpoint_addr,
};
use xenia_transport_ws::{WsRecvHalf, WsSendHalf, WsTransport};
use xenia_video::passthrough::PassthroughDecoder;
use xenia_video::{Decoder, EncodedPacket};

mod gui;
use gui::{AudioData, FrameData, FrameSlot, TelemetryData, ViewerApp, ViewerConfig};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TransportChoice {
    Auto,
    Tcp,
    Ws,
    Quic,
}

#[allow(clippy::large_enum_variant)] // see xenia-peer's identical note
enum AnyTransport {
    Tcp(TcpTransport),
    PreloadedTcp {
        first: Option<Vec<u8>>,
        transport: TcpTransport,
    },
    Ws(WsTransport),
    Quic {
        _endpoint: xenia_transport_quic::iroh::Endpoint,
        transport: QuicTransport,
    },
}

struct ConnectedTransport {
    transport: AnyTransport,
    advertisement: Option<TransportAdvertisement>,
}

impl Transport for AnyTransport {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        match self {
            AnyTransport::Tcp(t) => t.send_envelope(bytes).await,
            AnyTransport::PreloadedTcp { transport, .. } => transport.send_envelope(bytes).await,
            AnyTransport::Ws(t) => t.send_envelope(bytes).await,
            AnyTransport::Quic { transport, .. } => transport.send_envelope(bytes).await,
        }
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        match self {
            AnyTransport::Tcp(t) => t.recv_envelope().await,
            AnyTransport::PreloadedTcp { first, transport } => {
                if let Some(bytes) = first.take() {
                    Ok(bytes)
                } else {
                    transport.recv_envelope().await
                }
            }
            AnyTransport::Ws(t) => t.recv_envelope().await,
            AnyTransport::Quic { transport, .. } => transport.recv_envelope().await,
        }
    }
}

impl AnyTransport {
    fn negotiated_transport(&self) -> NegotiatedTransport {
        match self {
            AnyTransport::Tcp(_) | AnyTransport::PreloadedTcp { .. } => NegotiatedTransport::Tcp,
            AnyTransport::Ws(_) => NegotiatedTransport::WebSocket,
            AnyTransport::Quic { .. } => NegotiatedTransport::Quic,
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let AnyTransport::Quic {
            _endpoint,
            transport,
        } = self
        {
            let finish_result = transport.finish();
            _endpoint.close().await;
            finish_result?;
        }
        Ok(())
    }

    /// Split into independently-owned send/recv halves so a dedicated
    /// task can keep receiving frames while the main loop sends
    /// captured input events. See [`Transport`]'s doc comment for why
    /// splitting exists.
    ///
    /// Must only be called after any buffered `PreloadedTcp` first
    /// envelope has already been consumed (true by construction — the
    /// preload only exists to let transport auto-detection peek at
    /// the first envelope during the handshake, long before a caller
    /// would split).
    fn split(self) -> (AnySendHalf, AnyRecvHalf) {
        match self {
            AnyTransport::Tcp(t) => {
                let (send, recv) = t.split();
                (AnySendHalf::Tcp(send), AnyRecvHalf::Tcp(recv))
            }
            AnyTransport::PreloadedTcp { first, transport } => {
                debug_assert!(
                    first.is_none(),
                    "split() called before preloaded envelope was consumed"
                );
                let (send, recv) = transport.split();
                (AnySendHalf::Tcp(send), AnyRecvHalf::Tcp(recv))
            }
            AnyTransport::Ws(t) => {
                let (send, recv) = t.split();
                (AnySendHalf::Ws(send), AnyRecvHalf::Ws(recv))
            }
            AnyTransport::Quic {
                _endpoint,
                transport,
            } => {
                let (send, recv) = transport.split();
                (
                    AnySendHalf::Quic { _endpoint, send },
                    AnyRecvHalf::Quic(recv),
                )
            }
        }
    }
}

/// Send-only half of a split [`AnyTransport`].
enum AnySendHalf {
    Tcp(TcpSendHalf),
    Ws(WsSendHalf),
    Quic {
        _endpoint: xenia_transport_quic::iroh::Endpoint,
        send: QuicSendHalf,
    },
}

impl SendEnvelope for AnySendHalf {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        match self {
            AnySendHalf::Tcp(t) => t.send_envelope(bytes).await,
            AnySendHalf::Ws(t) => t.send_envelope(bytes).await,
            AnySendHalf::Quic { send, .. } => send.send_envelope(bytes).await,
        }
    }
}

impl AnySendHalf {
    /// Mirrors `AnyTransport::close` for the post-split send half.
    async fn close(&mut self) -> Result<(), TransportError> {
        if let AnySendHalf::Quic { _endpoint, send } = self {
            let finish_result = send.finish();
            _endpoint.close().await;
            finish_result?;
        }
        Ok(())
    }
}

/// Receive-only half of a split [`AnyTransport`].
enum AnyRecvHalf {
    Tcp(TcpRecvHalf),
    Ws(WsRecvHalf),
    Quic(QuicRecvHalf),
}

impl RecvEnvelope for AnyRecvHalf {
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        match self {
            AnyRecvHalf::Tcp(t) => t.recv_envelope().await,
            AnyRecvHalf::Ws(t) => t.recv_envelope().await,
            AnyRecvHalf::Quic(t) => t.recv_envelope().await,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CodecChoice {
    Passthrough,
    H264,
    Hdc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum PlayAudioMode {
    Off,
    Synthetic,
    Device,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AudioCodecChoice {
    Auto,
    RawPcm,
    #[cfg(feature = "audio-opus")]
    Opus,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AudioPlaybackStats {
    pub(crate) frames_played: u64,
    pub(crate) samples_played: u64,
    pub(crate) rejected: u64,
}

pub(crate) trait AudioPlaybackSink {
    fn submit(&mut self, frame: &RawAudio);
    fn stats(&self) -> AudioPlaybackStats;
}

#[cfg(any(feature = "audio-output", test))]
fn raw_audio_i16_samples(frame: &RawAudio) -> impl Iterator<Item = i16> + '_ {
    frame
        .payload
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
}

#[derive(Debug, Default)]
struct NullAudioSink {
    stats: AudioPlaybackStats,
}

impl AudioPlaybackSink for NullAudioSink {
    fn submit(&mut self, _frame: &RawAudio) {}

    fn stats(&self) -> AudioPlaybackStats {
        self.stats
    }
}

#[derive(Debug, Default)]
struct SyntheticAudioSink {
    stats: AudioPlaybackStats,
}

impl AudioPlaybackSink for SyntheticAudioSink {
    fn submit(&mut self, frame: &RawAudio) {
        if frame.flags & audio_flags::SYNTHETIC == 0 {
            self.stats.rejected += 1;
            return;
        }
        if frame.sample_format != xenia_peer_core::AudioSampleFormat::PcmS16Le {
            self.stats.rejected += 1;
            return;
        }
        let bytes_per_sample = 2u64;
        let samples = frame.payload.len() as u64 / bytes_per_sample;
        self.stats.frames_played += 1;
        self.stats.samples_played = self.stats.samples_played.saturating_add(samples);
    }

    fn stats(&self) -> AudioPlaybackStats {
        self.stats
    }
}

struct ChannelAudioSink {
    sender: mpsc::SyncSender<RawAudio>,
    stats: AudioPlaybackStats,
}

impl ChannelAudioSink {
    fn new(sender: mpsc::SyncSender<RawAudio>) -> Self {
        Self {
            sender,
            stats: AudioPlaybackStats::default(),
        }
    }
}

impl AudioPlaybackSink for ChannelAudioSink {
    fn submit(&mut self, frame: &RawAudio) {
        match self.sender.try_send(frame.clone()) {
            Ok(()) => {
                self.stats.frames_played += 1;
                self.stats.samples_played = self
                    .stats
                    .samples_played
                    .saturating_add(frame.payload.len() as u64 / 2);
            }
            Err(_) => {
                self.stats.rejected += 1;
            }
        }
    }

    fn stats(&self) -> AudioPlaybackStats {
        self.stats
    }
}

enum ViewerAudioSink {
    Off(NullAudioSink),
    Synthetic(SyntheticAudioSink),
    #[cfg(feature = "audio-output")]
    Device(DeviceAudioSink),
}

impl ViewerAudioSink {
    fn new(
        mode: PlayAudioMode,
        output_device: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match mode {
            PlayAudioMode::Off => Ok(Self::Off(NullAudioSink::default())),
            PlayAudioMode::Synthetic => Ok(Self::Synthetic(SyntheticAudioSink::default())),
            PlayAudioMode::Device => build_device_audio_sink(output_device),
        }
    }
}

impl AudioPlaybackSink for ViewerAudioSink {
    fn submit(&mut self, frame: &RawAudio) {
        match self {
            ViewerAudioSink::Off(sink) => sink.submit(frame),
            ViewerAudioSink::Synthetic(sink) => sink.submit(frame),
            #[cfg(feature = "audio-output")]
            ViewerAudioSink::Device(sink) => sink.submit(frame),
        }
    }

    fn stats(&self) -> AudioPlaybackStats {
        match self {
            ViewerAudioSink::Off(sink) => sink.stats(),
            ViewerAudioSink::Synthetic(sink) => sink.stats(),
            #[cfg(feature = "audio-output")]
            ViewerAudioSink::Device(sink) => sink.stats(),
        }
    }
}

#[cfg(not(feature = "audio-output"))]
fn build_device_audio_sink(
    _output_device: Option<&str>,
) -> Result<ViewerAudioSink, Box<dyn std::error::Error + Send + Sync>> {
    Err("xenia-viewer was built without device audio output; rebuild with `cargo build -p xenia-viewer --features audio-output`, or use --play-audio synthetic".into())
}

#[cfg(feature = "audio-output")]
struct DeviceAudioSink {
    queue: Arc<Mutex<VecDeque<i16>>>,
    stats: AudioPlaybackStats,
    output_sample_rate_hz: u32,
    output_channels: u16,
    _stream: cpal::Stream,
}

#[cfg(feature = "audio-output")]
impl DeviceAudioSink {
    const MAX_BUFFERED_SAMPLES: usize = 48_000 * 2;

    fn new(output_device: Option<&str>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

        let host = cpal::default_host();
        let device = if let Some(query) = output_device {
            let query = query.to_ascii_lowercase();
            host.output_devices()?
                .find(|device| {
                    device
                        .name()
                        .is_ok_and(|name| name.to_ascii_lowercase().contains(&query))
                })
                .ok_or_else(|| format!("no output audio device matched `{query}`"))?
        } else {
            host.default_output_device()
                .ok_or("no default audio output device available")?
        };
        let device_name = device.name().unwrap_or_else(|_| "unknown".to_string());
        let supported = device.default_output_config()?;
        let output_sample_rate_hz = supported.sample_rate().0;
        let output_channels = supported.channels();
        if output_channels == 0 {
            return Err("default output device reported zero channels".into());
        }
        if output_channels > xenia_peer_core::frame::RAW_AUDIO_MAX_CHANNELS {
            warn!(
                output_channels,
                "audio output device uses more than two channels; stereo frames will be expanded"
            );
        }

        let config: cpal::StreamConfig = supported.clone().into();
        let queue = Arc::new(Mutex::new(VecDeque::<i16>::new()));
        let err_fn = |err| warn!(error = %err, "audio output stream error");

        let stream = match supported.sample_format() {
            cpal::SampleFormat::F32 => {
                let queue = Arc::clone(&queue);
                device.build_output_stream(
                    &config,
                    move |data: &mut [f32], _| fill_output_f32(data, &queue),
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::I16 => {
                let queue = Arc::clone(&queue);
                device.build_output_stream(
                    &config,
                    move |data: &mut [i16], _| fill_output_i16(data, &queue),
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::U16 => {
                let queue = Arc::clone(&queue);
                device.build_output_stream(
                    &config,
                    move |data: &mut [u16], _| fill_output_u16(data, &queue),
                    err_fn,
                    None,
                )?
            }
            other => {
                return Err(format!("unsupported output sample format: {other:?}").into());
            }
        };
        stream.play()?;
        info!(
            device = %device_name,
            output_sample_rate_hz,
            output_channels,
            sample_format = ?supported.sample_format(),
            "audio output stream started"
        );

        Ok(Self {
            queue,
            stats: AudioPlaybackStats::default(),
            output_sample_rate_hz,
            output_channels,
            _stream: stream,
        })
    }
}

#[cfg(feature = "audio-output")]
impl AudioPlaybackSink for DeviceAudioSink {
    fn submit(&mut self, frame: &RawAudio) {
        if !frame.validate() {
            self.stats.rejected += 1;
            return;
        }

        let adapted = adapt_audio_samples(frame, self.output_sample_rate_hz, self.output_channels);
        let mut queue = self.queue.lock().expect("audio queue poisoned");
        for sample in adapted {
            if queue.len() >= Self::MAX_BUFFERED_SAMPLES {
                queue.pop_front();
            }
            queue.push_back(sample);
        }
        drop(queue);

        self.stats.frames_played += 1;
        self.stats.samples_played = self
            .stats
            .samples_played
            .saturating_add(frame.payload.len() as u64 / 2);
    }

    fn stats(&self) -> AudioPlaybackStats {
        self.stats
    }
}

#[cfg(feature = "audio-output")]
fn build_device_audio_sink(
    output_device: Option<&str>,
) -> Result<ViewerAudioSink, Box<dyn std::error::Error + Send + Sync>> {
    Ok(ViewerAudioSink::Device(DeviceAudioSink::new(
        output_device,
    )?))
}

#[cfg(any(feature = "audio-output", test))]
fn adapt_audio_samples(
    frame: &RawAudio,
    output_sample_rate_hz: u32,
    output_channels: u16,
) -> Vec<i16> {
    let input_channels = usize::from(frame.channels);
    let output_channels = usize::from(output_channels.max(1));
    let input_samples: Vec<i16> = raw_audio_i16_samples(frame).collect();
    if input_channels == 0 || input_samples.is_empty() {
        return Vec::new();
    }
    let input_frames = input_samples.len() / input_channels;
    if input_frames == 0 {
        return Vec::new();
    }

    let output_frames = ((input_frames as u64)
        .saturating_mul(u64::from(output_sample_rate_hz))
        .saturating_add(u64::from(frame.sample_rate_hz) - 1)
        / u64::from(frame.sample_rate_hz)) as usize;
    let mut adapted = Vec::with_capacity(output_frames.saturating_mul(output_channels));

    for output_frame in 0..output_frames {
        let src_pos = output_frame as f64 * f64::from(frame.sample_rate_hz)
            / f64::from(output_sample_rate_hz);
        let left = src_pos.floor() as usize;
        let right = (left + 1).min(input_frames - 1);
        let frac = src_pos - left as f64;

        for output_channel in 0..output_channels {
            let input_channel = match (input_channels, output_channels) {
                (1, _) => 0,
                (_, 1) => 0,
                _ => output_channel.min(input_channels - 1),
            };
            let a = f64::from(input_samples[left * input_channels + input_channel]);
            let b = f64::from(input_samples[right * input_channels + input_channel]);
            let sample = a + (b - a) * frac;
            adapted.push(
                sample
                    .round()
                    .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16,
            );
        }
    }

    adapted
}

#[cfg(feature = "audio-output")]
fn fill_output_i16(data: &mut [i16], queue: &Arc<Mutex<VecDeque<i16>>>) {
    let mut queue = queue.lock().expect("audio queue poisoned");
    for sample in data {
        *sample = queue.pop_front().unwrap_or(0);
    }
}

#[cfg(feature = "audio-output")]
fn fill_output_f32(data: &mut [f32], queue: &Arc<Mutex<VecDeque<i16>>>) {
    let mut queue = queue.lock().expect("audio queue poisoned");
    for sample in data {
        *sample = f32::from(queue.pop_front().unwrap_or(0)) / f32::from(i16::MAX);
    }
}

#[cfg(feature = "audio-output")]
fn fill_output_u16(data: &mut [u16], queue: &Arc<Mutex<VecDeque<i16>>>) {
    let mut queue = queue.lock().expect("audio queue poisoned");
    for sample in data {
        let signed = i32::from(queue.pop_front().unwrap_or(0));
        *sample = (signed + 32_768) as u16;
    }
}

fn make_decoder(
    choice: CodecChoice,
) -> Result<Box<dyn Decoder + Send>, Box<dyn std::error::Error>> {
    match choice {
        CodecChoice::Passthrough => Ok(Box::new(PassthroughDecoder::new())),
        CodecChoice::H264 => build_h264_decoder(),
        CodecChoice::Hdc => build_hdc_decoder(),
    }
}

#[cfg(feature = "h264")]
fn build_h264_decoder() -> Result<Box<dyn Decoder + Send>, Box<dyn std::error::Error>> {
    let dec = xenia_video::h264::H264Decoder::new()?;
    Ok(Box::new(dec))
}

#[cfg(not(feature = "h264"))]
fn build_h264_decoder() -> Result<Box<dyn Decoder + Send>, Box<dyn std::error::Error>> {
    Err("xenia-viewer was built without the `h264` feature; rebuild with `cargo build -p xenia-viewer --features h264`, or connect to a daemon using --codec passthrough".into())
}

#[cfg(feature = "hdc")]
fn build_hdc_decoder() -> Result<Box<dyn Decoder + Send>, Box<dyn std::error::Error>> {
    Ok(Box::new(xenia_video::hdc::HdcDecoder::new()))
}

#[cfg(not(feature = "hdc"))]
fn build_hdc_decoder() -> Result<Box<dyn Decoder + Send>, Box<dyn std::error::Error>> {
    Err("xenia-viewer was built without the `hdc` feature; rebuild with `cargo build -p xenia-viewer --features hdc`".into())
}

fn codec_to_frame_format(choice: CodecChoice) -> FramePixelFormat {
    match choice {
        CodecChoice::Passthrough => FramePixelFormat::Passthrough,
        CodecChoice::H264 => FramePixelFormat::H264,
        CodecChoice::Hdc => FramePixelFormat::Hdc,
    }
}

fn make_audio_codec(
    choice: AudioCodecChoice,
) -> Result<Box<dyn AudioCodec>, Box<dyn std::error::Error + Send + Sync>> {
    match choice {
        AudioCodecChoice::Auto => make_audio_codec(AudioCodecChoice::RawPcm),
        AudioCodecChoice::RawPcm => Ok(Box::new(RawPcmAudioCodec::new())),
        #[cfg(feature = "audio-opus")]
        AudioCodecChoice::Opus => Ok(Box::new(OpusAudioCodec::new()?)),
    }
}

fn choose_audio_codec(
    requested: AudioCodecChoice,
    advertisement: Option<&TransportAdvertisement>,
) -> Result<AudioCodecChoice, Box<dyn std::error::Error + Send + Sync>> {
    if requested != AudioCodecChoice::Auto {
        return Ok(requested);
    }
    let Some(advertisement) = advertisement else {
        return Ok(AudioCodecChoice::RawPcm);
    };
    let Some(audio) = &advertisement.audio else {
        return Ok(AudioCodecChoice::RawPcm);
    };
    match audio.selected_codec {
        AdvertisedAudioCodec::RawPcm => Ok(AudioCodecChoice::RawPcm),
        AdvertisedAudioCodec::Opus => {
            #[cfg(feature = "audio-opus")]
            {
                Ok(AudioCodecChoice::Opus)
            }
            #[cfg(not(feature = "audio-opus"))]
            {
                Err(
                    "daemon selected Opus audio, but xenia-viewer was built without `audio-opus`"
                        .into(),
                )
            }
        }
    }
}

fn choose_audio_codec_from_capabilities(
    requested: AudioCodecChoice,
    capabilities: &RawCapabilities,
) -> Result<AudioCodecChoice, Box<dyn std::error::Error + Send + Sync>> {
    if requested != AudioCodecChoice::Auto {
        return Ok(requested);
    }
    let Some(audio) = &capabilities.audio else {
        return Ok(AudioCodecChoice::RawPcm);
    };
    match audio.selected_codec {
        AdvertisedAudioCodec::RawPcm => Ok(AudioCodecChoice::RawPcm),
        AdvertisedAudioCodec::Opus => {
            #[cfg(feature = "audio-opus")]
            {
                Ok(AudioCodecChoice::Opus)
            }
            #[cfg(not(feature = "audio-opus"))]
            {
                Err(
                    "daemon selected Opus audio, but xenia-viewer was built without `audio-opus`"
                        .into(),
                )
            }
        }
    }
}

/// Read the viewer's own OS clipboard text, if any. A fresh
/// `arboard::Clipboard` is opened per call rather than cached across polls
/// -- see `xenia-peer`'s `read_host_clipboard_text` for why (not `Send` on
/// Linux, cheap enough to reopen at typical poll intervals).
fn read_viewer_clipboard_text() -> Option<String> {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(err) => {
            warn!(error = %err, "failed to open viewer clipboard for reading");
            return None;
        }
    };
    match clipboard.get_text() {
        Ok(text) => Some(text),
        Err(arboard::Error::ContentNotAvailable) => None,
        Err(err) => {
            warn!(error = %err, "failed to read viewer clipboard text");
            None
        }
    }
}

/// Apply a daemon-originated clipboard update to the viewer's own OS
/// clipboard. Called whenever `--clipboard` is not `off`.
fn apply_clipboard_content_to_viewer(content: &ClipboardContent) {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(err) => {
            warn!(error = %err, "failed to open viewer clipboard for writing");
            return;
        }
    };
    // `Cleared` deliberately uses `set_text("")` rather than `clipboard.clear()`
    // -- see the matching comment in xenia-peer's `apply_clipboard_content`
    // for why (`clear()` doesn't reliably override a selection still served
    // by an earlier `set_text()` call, verified live on KDE-Wayland).
    let result = match content {
        ClipboardContent::Text(text) => clipboard.set_text(text.clone()),
        ClipboardContent::Cleared => clipboard.set_text(String::new()),
    };
    if let Err(err) = result {
        warn!(error = %err, "failed to apply daemon clipboard update to viewer clipboard");
    } else {
        info!(
            ?content,
            "applied daemon clipboard update to viewer clipboard"
        );
    }
}

/// A transfer this side is sending. One at a time in this first cut --
/// `--send-file` offers a single file per viewer run.
struct OutgoingTransfer {
    transfer_id: u64,
    data: Vec<u8>,
}

/// A transfer this side is receiving.
struct IncomingTransfer {
    name: String,
    expected_size: u64,
    expected_hash: [u8; 32],
    buffer: Vec<u8>,
}

/// Reduce a wire-provided filename to a bare basename with no path
/// separators, mirroring `xenia-peer`'s identically-named helper -- see
/// its doc comment for why.
fn sanitize_transfer_filename(name: &str) -> Option<String> {
    let candidate = std::path::Path::new(name)
        .file_name()?
        .to_str()?
        .to_string();
    if candidate.is_empty() || candidate == "." || candidate == ".." {
        return None;
    }
    Some(candidate)
}

/// Decode and act on one file-transfer bare envelope, replying over
/// `send_half` as needed. Only wired into the GUI receive loop -- the
/// headless CLI probe mode doesn't support file transfer at all (checked
/// in `main`). No M1 consent gate here: M1 is a host(daemon)-side concept
/// protecting the daemon's local resources; the viewer has no equivalent.
#[allow(clippy::too_many_arguments)]
async fn handle_file_transfer_message(
    message: xenia_peer_core::FileTransferMessage,
    send_half: &Arc<tokio::sync::Mutex<AnySendHalf>>,
    session: &Arc<tokio::sync::Mutex<LaneSession>>,
    outgoing: &mut Option<OutgoingTransfer>,
    incoming: &mut std::collections::HashMap<u64, IncomingTransfer>,
    recv_file_dir: Option<&std::path::Path>,
    max_bytes: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match message {
        xenia_peer_core::FileTransferMessage::Offer {
            transfer_id,
            name,
            size,
            blake3_hash,
        } => {
            let (accept, reason) = match (recv_file_dir, sanitize_transfer_filename(&name)) {
                (None, _) => (
                    false,
                    "file transfer is disabled on this viewer".to_string(),
                ),
                (Some(_), None) => (false, "unusable filename".to_string()),
                (Some(_), Some(_)) if size > max_bytes => {
                    (false, format!("file exceeds {max_bytes}-byte cap"))
                }
                (Some(_), Some(_)) => (true, String::new()),
            };
            if accept {
                let safe_name = sanitize_transfer_filename(&name).expect("checked above");
                incoming.insert(
                    transfer_id,
                    IncomingTransfer {
                        name: safe_name,
                        expected_size: size,
                        expected_hash: blake3_hash,
                        buffer: Vec::with_capacity(size.min(max_bytes) as usize),
                    },
                );
                info!(transfer_id, name, size, "file transfer offer accepted");
            } else {
                info!(
                    transfer_id,
                    name, size, reason, "file transfer offer rejected"
                );
            }
            let reply = if accept {
                xenia_peer_core::FileTransferMessage::Accept { transfer_id }
            } else {
                xenia_peer_core::FileTransferMessage::Reject {
                    transfer_id,
                    reason,
                }
            };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(reply, false)?;
            send_half.lock().await.send_envelope(&envelope).await?;
        }
        xenia_peer_core::FileTransferMessage::Accept { transfer_id } => {
            let Some(transfer) = outgoing.as_ref().filter(|t| t.transfer_id == transfer_id) else {
                warn!(transfer_id, "Accept for unknown/stale outgoing transfer");
                return Ok(());
            };
            info!(
                transfer_id,
                bytes = transfer.data.len(),
                "transfer accepted, sending chunks"
            );
            let chunk_size = xenia_peer_core::FILE_TRANSFER_CHUNK_SIZE;
            for (i, chunk) in transfer.data.chunks(chunk_size).enumerate() {
                let msg = xenia_peer_core::FileTransferMessage::Chunk {
                    transfer_id,
                    offset: (i * chunk_size) as u64,
                    data: chunk.to_vec(),
                };
                let envelope = session
                    .lock()
                    .await
                    .seal_file_transfer_message(msg, false)?;
                send_half.lock().await.send_envelope(&envelope).await?;
            }
            let complete = xenia_peer_core::FileTransferMessage::Complete { transfer_id };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(complete, false)?;
            send_half.lock().await.send_envelope(&envelope).await?;
            info!(transfer_id, "all chunks sent, awaiting verification");
        }
        xenia_peer_core::FileTransferMessage::Reject {
            transfer_id,
            reason,
        } => {
            if outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                warn!(transfer_id, reason, "outgoing transfer rejected by peer");
                *outgoing = None;
            }
        }
        xenia_peer_core::FileTransferMessage::Chunk {
            transfer_id,
            offset,
            data,
        } => {
            let Some(transfer) = incoming.get_mut(&transfer_id) else {
                warn!(transfer_id, "chunk for unknown/stale incoming transfer");
                return Ok(());
            };
            let off = offset as usize;
            if off.saturating_add(data.len()) > transfer.expected_size as usize {
                warn!(
                    transfer_id,
                    "chunk exceeds offered file size; dropping transfer"
                );
                incoming.remove(&transfer_id);
                return Ok(());
            }
            if transfer.buffer.len() < off + data.len() {
                transfer.buffer.resize(off + data.len(), 0);
            }
            transfer.buffer[off..off + data.len()].copy_from_slice(&data);
        }
        xenia_peer_core::FileTransferMessage::Complete { transfer_id } => {
            let Some(transfer) = incoming.remove(&transfer_id) else {
                warn!(transfer_id, "Complete for unknown/stale incoming transfer");
                return Ok(());
            };
            let actual_hash = *blake3::hash(&transfer.buffer).as_bytes();
            let ok = actual_hash == transfer.expected_hash;
            if ok {
                let dest = recv_file_dir
                    .expect("incoming transfer only exists when recv_file_dir is set")
                    .join(&transfer.name);
                match std::fs::write(&dest, &transfer.buffer) {
                    Ok(()) => {
                        info!(transfer_id, path = %dest.display(), bytes = transfer.buffer.len(), "file transfer verified and written")
                    }
                    Err(err) => {
                        warn!(transfer_id, error = %err, "verified file failed to write to disk")
                    }
                }
            } else {
                warn!(
                    transfer_id,
                    "file transfer failed BLAKE3 verification, not written"
                );
            }
            let verified = xenia_peer_core::FileTransferMessage::Verified { transfer_id, ok };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(verified, false)?;
            send_half.lock().await.send_envelope(&envelope).await?;
        }
        xenia_peer_core::FileTransferMessage::Verified { transfer_id, ok } => {
            if outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                info!(transfer_id, ok, "outgoing transfer verification result");
                *outgoing = None;
            }
        }
    }
    Ok(())
}

fn decode_telemetry_frame(raw_frame: &xenia_peer_core::RawFrame) -> Option<TelemetryData> {
    match RawTelemetry::from_frame(raw_frame) {
        Ok(telemetry) => {
            let mut data = TelemetryData {
                backend: telemetry.backend.clone(),
                samples: telemetry.samples.len(),
                timestamp_ms: telemetry.timestamp_ms,
                ..TelemetryData::default()
            };
            for sample in telemetry.samples {
                info!(
                    backend = %telemetry.backend,
                    metric = %sample.name,
                    value = ?sample.value,
                    unit = ?sample.unit,
                    "telemetry sample"
                );
                match (sample.name.as_str(), sample.value) {
                    ("cpu.total.percent", xenia_peer_core::TelemetryValue::F64(value)) => {
                        data.cpu_percent = Some(value);
                    }
                    ("memory.total.bytes", xenia_peer_core::TelemetryValue::U64(value)) => {
                        data.memory_total_bytes = Some(value);
                    }
                    ("memory.used.bytes", xenia_peer_core::TelemetryValue::U64(value)) => {
                        data.memory_used_bytes = Some(value);
                    }
                    ("host.name", xenia_peer_core::TelemetryValue::Text(value)) => {
                        data.host_name = Some(value);
                    }
                    ("host.os.version", xenia_peer_core::TelemetryValue::Text(value)) => {
                        data.os_version = Some(value);
                    }
                    _ => {}
                }
            }
            Some(data)
        }
        Err(err) => {
            warn!(error = %err, "failed to decode telemetry frame");
            None
        }
    }
}

fn process_audio_frame(
    raw_frame: &xenia_peer_core::RawFrame,
    jitter: &mut AudioJitterBuffer,
    codec: &mut dyn AudioCodec,
    sink: &mut dyn AudioPlaybackSink,
    frames_decoded: &mut u64,
) -> Option<AudioData> {
    match RawAudio::from_frame(raw_frame) {
        Ok(audio) => {
            let audio = match codec.decode(audio) {
                Ok(audio) => audio,
                Err(err) => {
                    warn!(error = %err, "dropping undecodable audio frame");
                    return None;
                }
            };
            let last = audio.clone();
            let insert = jitter.push(audio);
            *frames_decoded += 1;
            while jitter.next_ready() {
                if let Some(frame) = jitter.pop_ready() {
                    sink.submit(&frame);
                }
            }
            let stats = jitter.stats();
            let playback = sink.stats();
            info!(
                stream_id = last.stream_id,
                sequence = last.sequence,
                result = ?insert,
                "audio frame processed"
            );
            Some(AudioData {
                frames_decoded: *frames_decoded,
                frames_inserted: stats.inserted,
                frames_emitted: stats.emitted,
                frames_played: playback.frames_played,
                samples_played: playback.samples_played,
                playback_rejected: playback.rejected,
                last_sequence: last.sequence,
                stream_id: last.stream_id,
                sample_rate_hz: last.sample_rate_hz,
                channels: last.channels,
                frame_duration_ms: last.frame_duration_ms,
                capture_timestamp_ms: last.capture_timestamp_ms,
                duplicates: stats.duplicates,
                late: stats.late,
                dropped: stats.dropped,
                gaps: stats.gaps,
                underruns: stats.underruns,
            })
        }
        Err(err) => {
            warn!(error = %err, "failed to decode audio frame");
            None
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "xenia-viewer",
    version,
    about = "Native viewer for Xenia sessions"
)]
struct Args {
    /// Address of the xenia-peer daemon to connect to.
    #[arg(long, default_value = "127.0.0.1:4747")]
    connect: String,

    /// Known-hosts file for trust-on-first-use host verification. On the
    /// first connection to a given `--connect` address the host's identity
    /// fingerprint is recorded here; on later connections it must match, or
    /// the viewer refuses (an active MITM presenting substitute keys yields a
    /// different fingerprint). Off by default -- when unset, the host
    /// fingerprint is logged but not pinned.
    #[arg(long)]
    known_hosts: Option<std::path::PathBuf>,

    /// Require the host's identity fingerprint to equal this exact hex value
    /// (64 hex chars). Verified out-of-band; a mismatch aborts the
    /// connection. Takes precedence over `--known-hosts`.
    #[arg(long)]
    host_fingerprint: Option<String>,

    /// Fixed source_id (hex, 16 chars). MUST match daemon.
    #[arg(long, default_value = "7878656e69617068")]
    source_id_hex: String,

    /// Fixed epoch. MUST match daemon.
    #[arg(long, default_value_t = 0x01)]
    epoch: u8,

    /// Stop after this many frames (0 = unbounded). In GUI mode the
    /// default is 0 (run until the user closes the window or the
    /// daemon disconnects); in CLI mode the default is 30.
    #[arg(long)]
    frames: Option<u64>,

    /// Capture width used by the daemon (for `--verify`).
    #[arg(long, default_value_t = 320)]
    width: u32,

    /// Capture height used by the daemon (for `--verify`).
    #[arg(long, default_value_t = 200)]
    height: u32,

    /// CLI mode only: instantiate a local mirror `TestCapture` and
    /// byte-compare every decoded frame to what the daemon should
    /// have produced. Fails fast on mismatch. Exit-criterion check
    /// for the passthrough codec; H.264 is lossy so this flag is
    /// only meaningful with `--codec passthrough`.
    #[arg(long)]
    verify: bool,

    /// CLI mode only: send exactly one synthetic `xenia_inject::InputEvent`
    /// (a centered pointer press) immediately after the handshake, through
    /// the same seal_input_event + send_envelope path `--gui` mode's real
    /// captured-OS-event sender uses. Real captured input requires an
    /// actual windowing system (`--gui` + a compositor/Xvfb) to generate --
    /// this exists so headless test harnesses (see
    /// docs/security/POST_DELEGATION_HARDENING_PLAN.md item 6) can prove
    /// the daemon's consent-gated input path end-to-end without one, the
    /// same way `--play-audio synthetic` supplies audio without a real
    /// microphone.
    #[arg(long)]
    send_synthetic_input: bool,

    /// CLI mode only, requires `--send-synthetic-input`: wait for this many
    /// real decoded frames before sending the synthetic input event, instead
    /// of sending it immediately after the handshake. Frames only flow after
    /// M1 consent is granted, so `0` (default) exercises the pre-consent
    /// rejection path and a positive value exercises the post-consent
    /// acceptance path -- see item 6's property 8.
    #[arg(long, default_value_t = 0, requires = "send_synthetic_input")]
    send_synthetic_input_after_frames: u64,

    /// Codec the daemon is using. Must match the daemon's
    /// `--codec` flag.
    #[arg(long, value_enum, default_value_t = CodecChoice::Passthrough)]
    codec: CodecChoice,

    /// Viewer-side audio playout sink. `synthetic` accepts only
    /// synthetic RawAudio frames and does not open an OS audio device.
    #[arg(long, value_enum, default_value_t = PlayAudioMode::Off)]
    play_audio: PlayAudioMode,

    #[arg(long, value_enum, default_value_t = AudioCodecChoice::RawPcm)]
    audio_codec: AudioCodecChoice,

    /// Optional output-device name substring for `--play-audio device`.
    #[arg(long)]
    audio_output_device: Option<String>,

    /// Transport. `auto` infers from `--connect`: `iroh:...` uses
    /// QUIC, `ws://...` / `wss://...` uses WebSocket, otherwise TCP.
    #[arg(long, value_enum, default_value_t = TransportChoice::Auto)]
    transport: TransportChoice,

    /// Open an egui window and render each decoded frame there.
    /// Without `--gui`, the viewer runs headless and logs frame
    /// statistics to stdout.
    #[arg(long)]
    gui: bool,

    /// Clipboard sync mode (GUI mode only). `off` (default) never
    /// touches the viewer's real OS clipboard. `host-to-viewer` applies
    /// daemon clipboard updates to the viewer's OS clipboard only.
    /// `bidirectional` also polls the viewer's own OS clipboard and
    /// sends its changes to the daemon (which needs a matching
    /// `--clipboard bidirectional` to actually apply them).
    #[arg(long, value_enum, default_value_t = ClipboardMode::Off)]
    clipboard: ClipboardMode,

    /// How often to poll the viewer's own clipboard for changes
    /// (bidirectional mode only).
    #[arg(long, default_value_t = 500)]
    clipboard_interval_ms: u64,

    /// Directory to write files the daemon sends. Not set (default) means
    /// the viewer rejects every inbound file-transfer offer.
    #[arg(long)]
    recv_file_dir: Option<std::path::PathBuf>,

    /// A local file to offer to the daemon once connected. One transfer
    /// per viewer run in this first cut.
    #[arg(long)]
    send_file: Option<std::path::PathBuf>,

    /// Reject/refuse to send any file larger than this many bytes. The
    /// whole file is buffered in memory (both sending and receiving), so
    /// this is also a memory-use cap, not just a policy knob.
    #[arg(long, default_value_t = 200 * 1024 * 1024)]
    file_transfer_max_bytes: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ClipboardMode {
    Off,
    HostToViewer,
    Bidirectional,
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Verify the host's identity fingerprint against the viewer's trust policy
/// before treating the session as authenticated. `--host-fingerprint` (an
/// out-of-band pinned value) takes precedence; otherwise `--known-hosts`
/// provides trust-on-first-use. With neither set the fingerprint is logged
/// but the host is trusted blindly (documented, opt-in pinning).
fn verify_host_identity(
    fingerprint: &[u8; 32],
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let fp_hex = to_hex(fingerprint);

    if let Some(expected) = &args.host_fingerprint {
        let expected = expected.trim();
        if expected.eq_ignore_ascii_case(&fp_hex) {
            info!(fingerprint = %fp_hex, "host identity matches --host-fingerprint");
            return Ok(());
        }
        return Err(format!(
            "host identity fingerprint mismatch: expected {expected}, got {fp_hex} -- \
             refusing to connect (possible man-in-the-middle)"
        )
        .into());
    }

    if let Some(path) = &args.known_hosts {
        return pin_or_verify_known_hosts(path, &args.connect, &fp_hex);
    }

    warn!(
        fingerprint = %fp_hex,
        "host identity is NOT pinned (pass --known-hosts or --host-fingerprint to verify it); \
         trusting this host blindly"
    );
    Ok(())
}

/// Trust-on-first-use against a known-hosts file. Each line is
/// `<connect-address> <fingerprint-hex>`. First contact for an address pins
/// its fingerprint; a later mismatch is refused; a match passes silently.
fn pin_or_verify_known_hosts(
    path: &std::path::Path,
    host_addr: &str,
    fp_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    for line in existing.lines() {
        let mut parts = line.split_whitespace();
        let (Some(addr), Some(fp)) = (parts.next(), parts.next()) else {
            continue;
        };
        if addr == host_addr {
            if fp.eq_ignore_ascii_case(fp_hex) {
                info!(host = host_addr, fingerprint = %fp_hex, "host identity matches known_hosts");
                return Ok(());
            }
            return Err(format!(
                "host {host_addr} identity fingerprint changed: known_hosts has {fp}, host \
                 presented {fp_hex} -- refusing to connect (possible man-in-the-middle). \
                 Remove the stale line from {} if this change is expected.",
                path.display()
            )
            .into());
        }
    }

    // First contact: pin it.
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("{host_addr} {fp_hex}\n"));
    std::fs::write(path, updated)?;
    info!(
        host = host_addr,
        fingerprint = %fp_hex,
        path = %path.display(),
        "pinned host identity on first use (trust-on-first-use)"
    );
    Ok(())
}

/// Send exactly one synthetic `xenia_inject::InputEvent` (a centered
/// pointer press) through the same seal_input_event + send_envelope path
/// `--gui` mode's real captured-OS-event sender uses -- see `--send-
/// synthetic-input`'s doc comment on [`Args`].
async fn send_synthetic_input(
    transport: &mut AnyTransport,
    session: &mut LaneSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let event = xenia_inject::InputEvent::Pointer {
        x: 0.5,
        y: 0.5,
        button: 0,
        pressed: true,
    };
    let payload = bincode::serialize(&event).map_err(|e| -> Box<dyn std::error::Error> {
        format!("encode synthetic input: {e}").into()
    })?;
    let envelope =
        session
            .seal_input_event(payload)
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!("seal synthetic input: {e}").into()
            })?;
    transport.send_envelope(&envelope).await?;
    info!("sent synthetic input event (--send-synthetic-input headless test hook)");
    Ok(())
}

fn parse_source_id(hex: &str) -> Result<[u8; 8], String> {
    if hex.len() != 16 {
        return Err(format!("source_id must be 16 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("source_id hex[{i}]: {e}"))?;
    }
    Ok(out)
}

// ─── Main entry: split CLI vs GUI paths ────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    if !args.gui && (args.recv_file_dir.is_some() || args.send_file.is_some()) {
        return Err(
            "--recv-file-dir/--send-file are only supported with --gui; the headless CLI \
             probe mode doesn't wire file transfer"
                .into(),
        );
    }

    if args.gui {
        run_gui(args)
    } else {
        run_cli(args)
    }
}

// ─── CLI path ──────────────────────────────────────────────────────

fn run_cli(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(cli_async(args))
}

async fn cli_async(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let frame_limit = args.frames.unwrap_or(30);
    let source_id = parse_source_id(&args.source_id_hex)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    info!(peer = %args.connect, frames = frame_limit, verify = args.verify, codec = ?args.codec, transport = ?args.transport, "connecting to xenia-peer daemon");
    warn!("M1 scaffold: CLI probe mode. Use --gui for a window.");

    let connected = connect_transport(&args).await?;
    let selected_audio_codec =
        choose_audio_codec(args.audio_codec, connected.advertisement.as_ref())
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    let mut transport = connected.transport;
    let mut handshake_mgr = HandshakeManager::new();
    let handshake =
        perform_viewer_handshake_with_transcript(&mut transport, &mut handshake_mgr, "daemon")
            .await?;
    verify_host_identity(&handshake.host_identity_fingerprint, &args)?;
    info!(
        transcript_hash = ?handshake.transcript_hash,
        "viewer handshake transcript bound"
    );
    let mut session = LaneSession::with_fixture(source_id, args.epoch);
    session.install_schedule(&handshake.key_schedule);

    if args.send_synthetic_input && args.send_synthetic_input_after_frames == 0 {
        send_synthetic_input(&mut transport, &mut session).await?;
    }

    let mut decoder = make_decoder(args.codec)?;
    let expected_frame_fmt = codec_to_frame_format(args.codec);
    info!(codec = ?args.codec, "decoder ready");
    let verify_is_meaningful = args.codec == CodecChoice::Passthrough;
    let mut expected_mirror = if args.verify && verify_is_meaningful {
        Some(TestCapture::new(args.width, args.height))
    } else {
        if args.verify && !verify_is_meaningful {
            warn!("--verify with a lossy codec (H.264) would fail trivially; mirror disabled");
        }
        None
    };

    let mut received: u64 = 0;
    let mut audio_decoded: u64 = 0;
    let mut last_audio_data: Option<AudioData> = None;
    let mut audio_jitter = AudioJitterBuffer::with_playout_delay(0, 16, 2);
    let mut audio_codec = make_audio_codec(selected_audio_codec)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    info!(
        audio_codec = audio_codec.name(),
        "viewer audio codec configured"
    );
    let mut audio_sink = ViewerAudioSink::new(args.play_audio, args.audio_output_device.as_deref())
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    let negotiated_transport = transport.negotiated_transport();
    let mut capability_guard = SessionCapabilityGuard::new(handshake.negotiated_context_hash);
    let mut epoch_state = SessionEpochState::new(handshake.transcript_hash, RekeyPolicy::smoke());
    loop {
        if frame_limit != 0 && received >= frame_limit {
            info!(received, "reached --frames, exiting");
            break;
        }
        let envelope = match transport.recv_envelope().await {
            Ok(e) => e,
            Err(err) => {
                info!(error = %err, received, "daemon disconnected");
                break;
            }
        };
        let wire_bytes = envelope.len();
        let raw_frame = match session.open_frame(&envelope) {
            Ok(f) => f,
            Err(err) => {
                warn!(error = %err, "failed to open frame");
                continue;
            }
        };
        if raw_frame.pixel_format == FramePixelFormat::Capabilities {
            let capabilities = RawCapabilities::from_frame(&raw_frame)?;
            let negotiated_context_hash =
                capability_guard.accept(negotiated_transport, &capabilities)?;
            let _negotiated_context_key =
                derive_negotiated_context_key(&handshake.key_schedule, &negotiated_context_hash);
            info!(
                transport = ?negotiated_transport,
                context_hash = ?negotiated_context_hash,
                "negotiated session context accepted"
            );
            let negotiated_audio_codec =
                choose_audio_codec_from_capabilities(args.audio_codec, &capabilities)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
            audio_codec = make_audio_codec(negotiated_audio_codec)
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
            info!(
                audio_codec = audio_codec.name(),
                video_format = ?capabilities.video_format,
                telemetry_enabled = capabilities.telemetry_enabled,
                input_control_enabled = capabilities.input_control_enabled,
                "sealed session capabilities applied"
            );
            continue;
        }
        if !capability_guard.is_accepted() {
            return Err("daemon sent session payload before sealed capabilities".into());
        }
        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            let _ = decode_telemetry_frame(&raw_frame);
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Rekey {
            let RawRekey::Proposal {
                key_epoch: proposed_epoch,
                base_transcript_hash,
                previous_epoch_hash: proposed_previous_hash,
                reason,
                epoch_hash,
            } = RawRekey::from_frame(&raw_frame)?
            else {
                return Err("viewer received unexpected rekey ack".into());
            };
            let context = epoch_state.validate_proposal(
                proposed_epoch,
                base_transcript_hash,
                proposed_previous_hash,
                reason,
                epoch_hash,
            )?;
            let keys = epoch_state.derive_and_install(&handshake.key_schedule, &context)?;
            session.install_rekey_keys(&keys);
            let ack = RawRekey::Ack {
                key_epoch: epoch_state.current_epoch(),
                epoch_hash,
            }
            .into_frame(0, 0)?;
            let envelope = session.seal_control_frame(&ack)?;
            transport.send_envelope(&envelope).await?;
            info!(key_epoch = epoch_state.current_epoch(), epoch_hash = ?epoch_hash, "session rekey installed");
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Audio {
            if let Some(audio) = process_audio_frame(
                &raw_frame,
                &mut audio_jitter,
                &mut *audio_codec,
                &mut audio_sink,
                &mut audio_decoded,
            ) {
                last_audio_data = Some(audio);
            }
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Clipboard {
            if args.clipboard != ClipboardMode::Off {
                match RawClipboard::from_frame(&raw_frame) {
                    Ok(clipboard) => apply_clipboard_content_to_viewer(&clipboard.content),
                    Err(err) => warn!(error = %err, "failed to decode clipboard frame"),
                }
            }
            continue;
        }
        if raw_frame.pixel_format != expected_frame_fmt {
            warn!(
                fmt = ?raw_frame.pixel_format,
                expected = ?expected_frame_fmt,
                "frame format mismatch (daemon and viewer must agree on --codec)"
            );
            continue;
        }
        let packet = EncodedPacket {
            bytes: raw_frame.pixels,
            pts_ms: raw_frame.timestamp_ms,
            is_keyframe: true,
        };
        let frames = match decoder.decode(&packet) {
            Ok(f) => f,
            Err(err) => {
                warn!(error = %err, "decode failed");
                continue;
            }
        };
        for decoded in frames {
            received += 1;

            if args.send_synthetic_input
                && args.send_synthetic_input_after_frames != 0
                && received == args.send_synthetic_input_after_frames
            {
                send_synthetic_input(&mut transport, &mut session).await?;
            }

            if let Some(ref mut mirror) = expected_mirror {
                let expected = match mirror.capture() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => return Err("verify: mirror did not produce frame".into()),
                    Err(err) => return Err(format!("verify: mirror capture failed: {err}").into()),
                };
                let expected_pixels = expected
                    .pixels()
                    .ok_or("verify: mirror produced non-pixel frame data")?;
                if decoded.pixels != expected_pixels {
                    return Err(format!(
                        "verify: decoded frame {received} did not match local mirror (byte-for-byte diff)"
                    )
                    .into());
                }
                if received <= 3 || received.is_multiple_of(10) {
                    info!(received, "frame verified byte-for-byte vs mirror");
                }
            } else if received <= 3 || received.is_multiple_of(10) {
                info!(
                    received,
                    width = decoded.width,
                    height = decoded.height,
                    bytes = decoded.pixels.len(),
                    wire_bytes,
                    "frame received + decoded"
                );
            }
        }
    }

    transport.close().await?;

    if args.verify && frame_limit != 0 && received != frame_limit {
        return Err(format!("verify: expected {frame_limit} frames, received {received}").into());
    }
    if args.verify {
        info!(verified = received, "verify: all frames matched mirror");
    }
    let playback = audio_sink.stats();
    let jitter = audio_jitter.stats();
    println!(
        "audio summary: decoded={} inserted={} emitted={} played={} samples={} rejected={} gaps={} duplicates={} late={} dropped={} underruns={}",
        audio_decoded,
        jitter.inserted,
        jitter.emitted,
        playback.frames_played,
        playback.samples_played,
        playback.rejected,
        jitter.gaps,
        jitter.duplicates,
        jitter.late,
        jitter.dropped,
        jitter.underruns
    );
    if let Some(audio) = last_audio_data {
        println!(
            "audio last: stream={} sequence={} rate={} channels={} duration_ms={}",
            audio.stream_id,
            audio.last_sequence,
            audio.sample_rate_hz,
            audio.channels,
            audio.frame_duration_ms
        );
    }
    info!(received, "viewer exiting");
    Ok(())
}

// ─── GUI path ──────────────────────────────────────────────────────

fn run_gui(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let slot = FrameSlot::new();
    let config = ViewerConfig {
        codec: format!("{:?}", args.codec),
        transport: format!("{:?}", args.transport),
        peer_addr: args.connect.clone(),
    };
    let audio_sink = ViewerAudioSink::new(args.play_audio, args.audio_output_device.as_deref())
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    let (audio_tx, audio_rx) = mpsc::sync_channel(64);
    // Captured pointer/keyboard events flow GUI thread -> network
    // task. `UnboundedSender::send` is a sync method, so the egui
    // thread can call it directly without needing to be inside an
    // async context.
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel::<xenia_inject::InputEvent>();

    // Spawn the receive/decode pipeline on a dedicated tokio thread.
    // eframe wants to own the main thread; tokio runs beside it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;
    let slot_for_task = Arc::clone(&slot);
    let args_for_task = args.clone();
    rt.spawn(async move {
        if let Err(err) = gui_receive_loop(args_for_task, slot_for_task, audio_tx, input_rx).await {
            tracing::error!(error = %err, "gui receive loop exited with error");
        }
    });
    // Keep the runtime alive for the duration of the GUI.
    let _rt_guard = rt.enter();

    let native_opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("xenia-viewer — {}", args.connect))
            .with_inner_size([args.width as f32 + 20.0, args.height as f32 + 80.0]),
        ..Default::default()
    };

    eframe::run_native(
        "xenia-viewer",
        native_opts,
        Box::new(move |_cc| {
            Ok(Box::new(ViewerApp::new(
                slot,
                config,
                Some(audio_rx),
                Box::new(audio_sink),
                Some(input_tx),
            )))
        }),
    )
    .map_err(|e| -> Box<dyn std::error::Error> { format!("eframe: {e}").into() })?;

    // eframe blocks until the window closes; runtime drops here.
    drop(rt);
    Ok(())
}

async fn gui_receive_loop(
    args: Args,
    slot: Arc<FrameSlot>,
    audio_tx: mpsc::SyncSender<RawAudio>,
    mut input_rx: tokio::sync::mpsc::UnboundedReceiver<xenia_inject::InputEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source_id = parse_source_id(&args.source_id_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    info!(peer = %args.connect, codec = ?args.codec, transport = ?args.transport, "GUI connecting to xenia-peer daemon");

    let connected = connect_transport(&args)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let selected_audio_codec =
        choose_audio_codec(args.audio_codec, connected.advertisement.as_ref())?;
    let mut transport = connected.transport;

    let mut handshake_mgr = HandshakeManager::new();
    let handshake =
        perform_viewer_handshake_with_transcript(&mut transport, &mut handshake_mgr, "daemon")
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    verify_host_identity(&handshake.host_identity_fingerprint, &args)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    info!(
        transcript_hash = ?handshake.transcript_hash,
        "viewer handshake transcript bound"
    );
    let mut session = LaneSession::with_fixture(source_id, args.epoch);
    session.install_schedule(&handshake.key_schedule);
    let negotiated_transport = transport.negotiated_transport();

    // Split the transport so captured input can be sent concurrently
    // with the frame-receive loop below. `session` and the send half
    // move behind async mutexes shared with the spawned input-sender
    // task: `session` because sealing an outbound input event and
    // opening/installing an inbound rekey share the same control-lane
    // key state, and the send half because both this loop's rekey
    // acks and the input task's sealed events go out over it.
    let (send_half, mut recv_half) = transport.split();
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let send_half = Arc::new(tokio::sync::Mutex::new(send_half));

    {
        let session = Arc::clone(&session);
        let send_half = Arc::clone(&send_half);
        tokio::spawn(async move {
            while let Some(event) = input_rx.recv().await {
                let payload = match bincode::serialize(&event) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        warn!(error = %err, "failed to encode captured InputEvent");
                        continue;
                    }
                };
                let envelope = {
                    let mut session = session.lock().await;
                    match session.seal_input_event(payload) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            warn!(error = %err, "failed to seal captured input event");
                            continue;
                        }
                    }
                };
                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {
                    info!(error = %err, "input send loop ending (daemon disconnected)");
                    break;
                }
            }
        });
    }

    if args.clipboard == ClipboardMode::Bidirectional {
        let session = Arc::clone(&session);
        let send_half = Arc::clone(&send_half);
        let poll_interval = Duration::from_millis(args.clipboard_interval_ms.max(1));
        tokio::spawn(async move {
            let mut last_sent: Option<String> = None;
            loop {
                tokio::time::sleep(poll_interval).await;
                let Some(text) = read_viewer_clipboard_text() else {
                    continue;
                };
                if Some(&text) == last_sent.as_ref() {
                    continue;
                }
                let envelope = {
                    let mut session = session.lock().await;
                    match session.seal_clipboard_event(ClipboardContent::Text(text.clone())) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            warn!(error = %err, "failed to seal captured clipboard update");
                            continue;
                        }
                    }
                };
                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {
                    info!(error = %err, "clipboard send loop ending (daemon disconnected)");
                    break;
                }
                last_sent = Some(text);
            }
        });
    }

    let mut outgoing_transfer: Option<OutgoingTransfer> = None;
    let mut incoming_transfers: std::collections::HashMap<u64, IncomingTransfer> =
        std::collections::HashMap::new();
    // Prepared here (read the file, hash it) but NOT sent yet -- the actual
    // Offer send is deferred until after the initial rekey exchange
    // completes (see the Rekey-handling branch below). Sending it here,
    // immediately after the handshake, raced ahead of the daemon's own
    // blocking `perform_rekey` (which does `send Proposal; recv Ack`
    // synchronously before ever reaching its split recv task): a live test
    // showed the daemon's `recv_envelope()` call meant for the Rekey Ack
    // picking up this bare file-transfer envelope instead, since this
    // pre-loop code ran (and sent) before the loop below ever received or
    // acted on the daemon's Rekey Proposal.
    let mut pending_initial_offer: Option<(u64, String, Vec<u8>, [u8; 32])> = None;
    if let Some(path) = &args.send_file {
        let data = std::fs::read(path)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
        if data.len() as u64 > args.file_transfer_max_bytes {
            return Err(format!(
                "--send-file {} is {} bytes, exceeds --file-transfer-max-bytes {}",
                path.display(),
                data.len(),
                args.file_transfer_max_bytes
            )
            .into());
        }
        let blake3_hash = *blake3::hash(&data).as_bytes();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("transfer")
            .to_string();
        pending_initial_offer = Some((1, name, data, blake3_hash));
    }

    let mut decoder = make_decoder(args.codec)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let expected_frame_fmt = codec_to_frame_format(args.codec);

    let frame_limit = args.frames.unwrap_or(0);
    let mut received: u64 = 0;
    let mut audio_decoded: u64 = 0;
    let mut audio_jitter = AudioJitterBuffer::with_playout_delay(0, 16, 2);
    let mut audio_codec = make_audio_codec(selected_audio_codec)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    info!(
        audio_codec = audio_codec.name(),
        "viewer audio codec configured"
    );
    let mut audio_sink: Box<dyn AudioPlaybackSink + Send> =
        Box::new(ChannelAudioSink::new(audio_tx));
    let mut capability_guard = SessionCapabilityGuard::new(handshake.negotiated_context_hash);
    let mut epoch_state = SessionEpochState::new(handshake.transcript_hash, RekeyPolicy::smoke());
    loop {
        if frame_limit != 0 && received >= frame_limit {
            info!(received, "reached --frames, closing receive loop");
            break;
        }
        let envelope = match recv_half.recv_envelope().await {
            Ok(e) => e,
            Err(err) => {
                info!(error = %err, received, "daemon disconnected");
                break;
            }
        };
        let wire_bytes = envelope.len();

        // File-transfer messages are bare envelopes (like input/clipboard
        // reverse-path), not lane-enveloped -- check before `open_frame`,
        // which only understands the lane-envelope shape.
        if matches!(
            xenia_wire::envelope_payload_type(&envelope),
            Some(xenia_peer_core::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST)
                | Some(xenia_peer_core::PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER)
        ) {
            if !capability_guard.is_accepted() {
                return Err("daemon sent file-transfer payload before sealed capabilities".into());
            }
            let message = match session.lock().await.open_file_transfer_message(&envelope) {
                Ok(message) => message,
                Err(err) => {
                    warn!(error = %err, "failed to open file-transfer envelope");
                    continue;
                }
            };
            handle_file_transfer_message(
                message,
                &send_half,
                &session,
                &mut outgoing_transfer,
                &mut incoming_transfers,
                args.recv_file_dir.as_deref(),
                args.file_transfer_max_bytes,
            )
            .await?;
            continue;
        }

        let raw_frame = match session.lock().await.open_frame(&envelope) {
            Ok(f) => f,
            Err(err) => {
                warn!(error = %err, "failed to open frame");
                continue;
            }
        };
        if raw_frame.pixel_format == FramePixelFormat::Capabilities {
            let capabilities = RawCapabilities::from_frame(&raw_frame).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;
            let negotiated_context_hash = capability_guard
                .accept(negotiated_transport, &capabilities)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let _negotiated_context_key =
                derive_negotiated_context_key(&handshake.key_schedule, &negotiated_context_hash);
            info!(
                transport = ?negotiated_transport,
                context_hash = ?negotiated_context_hash,
                "negotiated session context accepted"
            );
            let negotiated_audio_codec =
                choose_audio_codec_from_capabilities(args.audio_codec, &capabilities)?;
            audio_codec = make_audio_codec(negotiated_audio_codec).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;
            info!(
                audio_codec = audio_codec.name(),
                video_format = ?capabilities.video_format,
                telemetry_enabled = capabilities.telemetry_enabled,
                input_control_enabled = capabilities.input_control_enabled,
                "sealed session capabilities applied"
            );
            continue;
        }
        if !capability_guard.is_accepted() {
            return Err("daemon sent session payload before sealed capabilities".into());
        }
        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            if let Some(telemetry) = decode_telemetry_frame(&raw_frame) {
                slot.put_telemetry(telemetry);
            }
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Rekey {
            let RawRekey::Proposal {
                key_epoch: proposed_epoch,
                base_transcript_hash,
                previous_epoch_hash: proposed_previous_hash,
                reason,
                epoch_hash,
            } = RawRekey::from_frame(&raw_frame).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?
            else {
                return Err("viewer received unexpected rekey ack".into());
            };
            let context = epoch_state
                .validate_proposal(
                    proposed_epoch,
                    base_transcript_hash,
                    proposed_previous_hash,
                    reason,
                    epoch_hash,
                )
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    e.to_string().into()
                })?;
            let keys = epoch_state
                .derive_and_install(&handshake.key_schedule, &context)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    e.to_string().into()
                })?;
            session.lock().await.install_rekey_keys(&keys);
            let ack = RawRekey::Ack {
                key_epoch: epoch_state.current_epoch(),
                epoch_hash,
            }
            .into_frame(0, 0)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
            let envelope = session.lock().await.seal_control_frame(&ack).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;
            send_half
                .lock()
                .await
                .send_envelope(&envelope)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    e.to_string().into()
                })?;
            info!(key_epoch = epoch_state.current_epoch(), epoch_hash = ?epoch_hash, "session rekey installed");

            // Now safe to send: the initial rekey handshake (the daemon's
            // blocking send-Proposal/recv-Ack pair) is fully resolved from
            // the daemon's perspective once this Ack lands, so any
            // subsequent bare envelope from us will be read by the
            // daemon's split recv task rather than mistaken for the Ack it
            // was waiting on.
            if let Some((transfer_id, name, data, blake3_hash)) = pending_initial_offer.take() {
                let offer = xenia_peer_core::FileTransferMessage::Offer {
                    transfer_id,
                    name: name.clone(),
                    size: data.len() as u64,
                    blake3_hash,
                };
                let envelope = session
                    .lock()
                    .await
                    .seal_file_transfer_message(offer, false)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        e.to_string().into()
                    })?;
                send_half
                    .lock()
                    .await
                    .send_envelope(&envelope)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        e.to_string().into()
                    })?;
                info!(
                    transfer_id,
                    name,
                    size = data.len(),
                    "file transfer offered"
                );
                outgoing_transfer = Some(OutgoingTransfer { transfer_id, data });
            }
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Audio {
            if let Some(audio) = process_audio_frame(
                &raw_frame,
                &mut audio_jitter,
                &mut *audio_codec,
                audio_sink.as_mut(),
                &mut audio_decoded,
            ) {
                slot.put_audio(audio);
            }
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Clipboard {
            if args.clipboard != ClipboardMode::Off {
                match RawClipboard::from_frame(&raw_frame) {
                    Ok(clipboard) => apply_clipboard_content_to_viewer(&clipboard.content),
                    Err(err) => warn!(error = %err, "failed to decode clipboard frame"),
                }
            }
            continue;
        }
        if raw_frame.pixel_format != expected_frame_fmt {
            warn!(
                fmt = ?raw_frame.pixel_format,
                expected = ?expected_frame_fmt,
                "frame format mismatch"
            );
            continue;
        }
        let packet = EncodedPacket {
            bytes: raw_frame.pixels,
            pts_ms: raw_frame.timestamp_ms,
            is_keyframe: true,
        };
        let frames = match decoder.decode(&packet) {
            Ok(f) => f,
            Err(err) => {
                warn!(error = %err, "decode failed");
                continue;
            }
        };
        for decoded in frames {
            received += 1;
            slot.put(FrameData {
                width: decoded.width,
                height: decoded.height,
                rgba: decoded.pixels,
                seq: received,
                wire_bytes,
                timestamp_ms: decoded.pts_ms,
            });
        }
    }
    send_half
        .lock()
        .await
        .close()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    Ok(())
}

// ─── Shared helper ─────────────────────────────────────────────────

async fn connect_transport(args: &Args) -> Result<ConnectedTransport, TransportError> {
    match args.transport {
        TransportChoice::Auto => connect_auto(&args.connect).await,
        TransportChoice::Tcp => Ok(ConnectedTransport {
            transport: connect_tcp(&args.connect).await?,
            advertisement: None,
        }),
        TransportChoice::Ws => Ok(ConnectedTransport {
            transport: connect_ws(&args.connect).await?,
            advertisement: None,
        }),
        TransportChoice::Quic => Ok(ConnectedTransport {
            transport: connect_quic(&args.connect).await?,
            advertisement: None,
        }),
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use xenia_peer_core::{SyntheticAudioKind, SyntheticAudioSource};

    #[test]
    fn to_hex_encodes_lowercase_fixed_width() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn known_hosts_pins_on_first_use_then_verifies() {
        let dir = std::env::temp_dir().join(format!("xenia-known-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_file(&path);

        // First contact: pins, succeeds, and writes the entry.
        pin_or_verify_known_hosts(&path, "10.0.0.1:4747", "aabbcc").unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("10.0.0.1:4747 aabbcc")
        );

        // Same fingerprint: passes (case-insensitive).
        pin_or_verify_known_hosts(&path, "10.0.0.1:4747", "AABBCC").unwrap();

        // Changed fingerprint for the same host: refused.
        let err = pin_or_verify_known_hosts(&path, "10.0.0.1:4747", "deadbeef").unwrap_err();
        assert!(err.to_string().contains("fingerprint changed"));

        // A different host pins independently.
        pin_or_verify_known_hosts(&path, "10.0.0.2:4747", "1234").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("10.0.0.1:4747 aabbcc"));
        assert!(contents.contains("10.0.0.2:4747 1234"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn synthetic_audio_sink_accepts_only_synthetic_frames() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let synthetic = source.next_frame(1_700_000_000_000);
        let mut captured = synthetic.clone();
        captured.flags &= !audio_flags::SYNTHETIC;

        let mut sink = SyntheticAudioSink::default();
        sink.submit(&captured);
        assert_eq!(sink.stats().rejected, 1);
        assert_eq!(sink.stats().frames_played, 0);

        sink.submit(&synthetic);
        assert_eq!(sink.stats().rejected, 1);
        assert_eq!(sink.stats().frames_played, 1);
        assert_eq!(sink.stats().samples_played, 48_000 / 50 * 2);
    }

    #[test]
    fn channel_audio_sink_reports_backpressure() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let frame = source.next_frame(1_700_000_000_000);
        let (tx, rx) = mpsc::sync_channel(1);
        let mut sink = ChannelAudioSink::new(tx);

        sink.submit(&frame);
        sink.submit(&frame);

        assert_eq!(sink.stats().frames_played, 1);
        assert_eq!(sink.stats().rejected, 1);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn process_audio_frame_reports_playback_sink_counters() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let mut jitter = AudioJitterBuffer::with_playout_delay(0, 8, 1);
        let mut codec = RawPcmAudioCodec::new();
        let mut sink = ViewerAudioSink::new(PlayAudioMode::Synthetic, None).unwrap();
        let mut decoded = 0;

        let first = source.next_frame(1_700_000_000_000).into_frame(1).unwrap();
        let data =
            process_audio_frame(&first, &mut jitter, &mut codec, &mut sink, &mut decoded).unwrap();
        assert_eq!(data.frames_decoded, 1);
        assert_eq!(data.frames_inserted, 1);
        assert_eq!(data.frames_emitted, 0);
        assert_eq!(data.frames_played, 0);

        let second = source.next_frame(1_700_000_000_020).into_frame(2).unwrap();
        let data =
            process_audio_frame(&second, &mut jitter, &mut codec, &mut sink, &mut decoded).unwrap();
        assert_eq!(data.frames_decoded, 2);
        assert_eq!(data.frames_inserted, 2);
        assert_eq!(data.frames_emitted, 1);
        assert_eq!(data.frames_played, 1);
        assert_eq!(data.playback_rejected, 0);
    }

    #[test]
    fn process_audio_frame_rejects_invalid_codec_payload() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let mut audio = source.next_frame(1_700_000_000_000);
        audio.payload.pop();
        let frame = audio.into_frame(1).unwrap();
        let mut jitter = AudioJitterBuffer::with_playout_delay(0, 8, 1);
        let mut codec = RawPcmAudioCodec::new();
        let mut sink = ViewerAudioSink::new(PlayAudioMode::Synthetic, None).unwrap();
        let mut decoded = 0;

        assert!(
            process_audio_frame(&frame, &mut jitter, &mut codec, &mut sink, &mut decoded).is_none()
        );
        assert_eq!(decoded, 0);
        assert_eq!(jitter.stats().inserted, 0);
        assert_eq!(sink.stats().frames_played, 0);
    }

    #[test]
    fn auto_audio_codec_defaults_to_raw_without_advertisement() {
        assert_eq!(
            choose_audio_codec(AudioCodecChoice::Auto, None).unwrap(),
            AudioCodecChoice::RawPcm
        );
    }

    #[test]
    fn auto_audio_codec_uses_advertised_raw_selection() {
        let advert = TransportAdvertisement::auto("iroh:test".to_string()).with_audio(
            xenia_peer_core::advertisement::AudioAdvertisement {
                codecs: vec![AdvertisedAudioCodec::RawPcm],
                selected_codec: AdvertisedAudioCodec::RawPcm,
                sample_rate_hz: 48_000,
                max_channels: 2,
                frame_duration_ms: vec![10, 20],
            },
        );

        assert_eq!(
            choose_audio_codec(AudioCodecChoice::Auto, Some(&advert)).unwrap(),
            AudioCodecChoice::RawPcm
        );
    }

    #[test]
    fn audio_adapter_expands_mono_to_stereo() {
        let samples_per_channel = 48_000 / 100;
        let mut payload = Vec::with_capacity(samples_per_channel * 2);
        for _ in 0..samples_per_channel {
            payload.extend_from_slice(&1_000i16.to_le_bytes());
        }
        let frame = RawAudio {
            schema_version: xenia_peer_core::frame::RAW_AUDIO_SCHEMA_VERSION,
            clock_domain: xenia_peer_core::frame::RAW_AUDIO_CLOCK_UNIX_MS,
            stream_id: 1,
            sequence: 0,
            capture_timestamp_ms: 1_700_000_000_000,
            sample_rate_hz: xenia_peer_core::frame::RAW_AUDIO_SAMPLE_RATE_HZ,
            channels: 1,
            sample_format: xenia_peer_core::AudioSampleFormat::PcmS16Le,
            frame_duration_ms: 10,
            flags: audio_flags::SYNTHETIC,
            payload,
        };

        assert!(frame.validate());
        let adapted = adapt_audio_samples(&frame, 48_000, 2);
        assert_eq!(adapted.len(), samples_per_channel * 2);
        assert!(adapted.chunks_exact(2).all(|pair| pair == [1_000, 1_000]));
    }

    #[test]
    fn audio_adapter_resamples_to_output_rate() {
        let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
        let frame = source.next_frame(1_700_000_000_000);
        let adapted = adapt_audio_samples(&frame, 24_000, 2);
        assert_eq!(adapted.len(), 48_000 / 50 / 2 * 2);
    }
}

async fn connect_auto(connect: &str) -> Result<ConnectedTransport, TransportError> {
    if connect.starts_with("iroh:") {
        Ok(ConnectedTransport {
            transport: connect_quic(connect).await?,
            advertisement: None,
        })
    } else if connect.starts_with("ws://") || connect.starts_with("wss://") {
        Ok(ConnectedTransport {
            transport: connect_ws(connect).await?,
            advertisement: None,
        })
    } else {
        connect_auto_with_advertisement(connect).await
    }
}

async fn connect_tcp(connect: &str) -> Result<AnyTransport, TransportError> {
    Ok(AnyTransport::Tcp(TcpTransport::connect(connect).await?))
}

async fn connect_auto_with_advertisement(
    connect: &str,
) -> Result<ConnectedTransport, TransportError> {
    let mut tcp = TcpTransport::connect(connect).await?;
    let first = tcp.recv_envelope().await?;
    let advert =
        TransportAdvertisement::decode(&first).map_err(|e| std::io::Error::other(e.to_string()))?;
    let Some(advert) = advert else {
        info!("daemon did not send a transport advertisement; continuing on TCP");
        return Ok(ConnectedTransport {
            transport: AnyTransport::PreloadedTcp {
                first: Some(first),
                transport: tcp,
            },
            advertisement: None,
        });
    };

    if let Some(quic_connect) = advert
        .quic_connect
        .as_deref()
        .filter(|_| advert.transports.contains(&AdvertisedTransport::Quic))
    {
        info!("daemon advertised QUIC; reconnecting over Iroh");
        return Ok(ConnectedTransport {
            transport: connect_quic(quic_connect).await?,
            advertisement: Some(advert),
        });
    }

    info!("daemon advertisement did not include QUIC; continuing on TCP");
    Ok(ConnectedTransport {
        transport: AnyTransport::Tcp(tcp),
        advertisement: Some(advert),
    })
}

async fn connect_ws(connect: &str) -> Result<AnyTransport, TransportError> {
    let url = if connect.starts_with("ws://") || connect.starts_with("wss://") {
        connect.to_string()
    } else {
        format!("ws://{connect}")
    };
    Ok(AnyTransport::Ws(WsTransport::connect(&url).await?))
}

async fn connect_quic(connect: &str) -> Result<AnyTransport, TransportError> {
    let remote = decode_endpoint_addr(connect)?;
    let endpoint = bind_xenia_endpoint().await?;
    let transport = QuicTransport::connect(&endpoint, remote).await?;
    Ok(AnyTransport::Quic {
        _endpoint: endpoint,
        transport,
    })
}
