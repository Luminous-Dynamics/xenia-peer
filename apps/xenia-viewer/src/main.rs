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

use std::sync::Arc;

use clap::{Parser, ValueEnum};
use tracing::{info, warn};
use xenia_capture::{ScreenCapture, TestCapture};
use xenia_peer_core::advertisement::{AdvertisedTransport, TransportAdvertisement};
use xenia_peer_core::frame::{PixelFormat as FramePixelFormat, RawAudio, RawTelemetry};
use xenia_peer_core::handshake::perform_viewer_handshake;
use xenia_peer_core::transport::{TcpTransport, Transport, TransportError};
use xenia_peer_core::{AudioJitterBuffer, HandshakeManager, Session, SessionRole};
use xenia_transport_quic::{QuicTransport, bind_xenia_endpoint, decode_endpoint_addr};
use xenia_transport_ws::WsTransport;
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
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CodecChoice {
    Passthrough,
    H264,
    Hdc,
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
    frames_received: &mut u64,
) -> Option<AudioData> {
    match RawAudio::from_frame(raw_frame) {
        Ok(audio) => {
            if !audio.validate() {
                warn!(sequence = audio.sequence, "dropping invalid audio frame");
                return None;
            }
            let last = audio.clone();
            let insert = jitter.push(audio);
            *frames_received += 1;
            while jitter.next_ready() {
                let _ = jitter.pop_next();
            }
            let stats = jitter.stats();
            info!(
                stream_id = last.stream_id,
                sequence = last.sequence,
                result = ?insert,
                "audio frame accepted"
            );
            Some(AudioData {
                frames_received: *frames_received,
                last_sequence: last.sequence,
                stream_id: last.stream_id,
                sample_rate_hz: last.sample_rate_hz,
                channels: last.channels,
                frame_duration_ms: last.frame_duration_ms,
                capture_timestamp_ms: last.capture_timestamp_ms,
                duplicates: stats.duplicates,
                late: stats.late,
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

    /// Codec the daemon is using. Must match the daemon's
    /// `--codec` flag.
    #[arg(long, value_enum, default_value_t = CodecChoice::Passthrough)]
    codec: CodecChoice,

    /// Transport. `auto` infers from `--connect`: `iroh:...` uses
    /// QUIC, `ws://...` / `wss://...` uses WebSocket, otherwise TCP.
    #[arg(long, value_enum, default_value_t = TransportChoice::Auto)]
    transport: TransportChoice,

    /// Open an egui window and render each decoded frame there.
    /// Without `--gui`, the viewer runs headless and logs frame
    /// statistics to stdout.
    #[arg(long)]
    gui: bool,
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

    let mut transport = connect_transport(&args).await?;
    let mut handshake_mgr = HandshakeManager::new();
    let session_key =
        perform_viewer_handshake(&mut transport, &mut handshake_mgr, "daemon").await?;

    let mut session = Session::with_fixture(SessionRole::Viewer, source_id, args.epoch);
    session.install_key(session_key);

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
    let mut audio_received: u64 = 0;
    let mut audio_jitter = AudioJitterBuffer::new(0, 16);
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
        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            let _ = decode_telemetry_frame(&raw_frame);
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Audio {
            let _ = process_audio_frame(&raw_frame, &mut audio_jitter, &mut audio_received);
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

    // Spawn the receive/decode pipeline on a dedicated tokio thread.
    // eframe wants to own the main thread; tokio runs beside it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;
    let slot_for_task = Arc::clone(&slot);
    let args_for_task = args.clone();
    rt.spawn(async move {
        if let Err(err) = gui_receive_loop(args_for_task, slot_for_task).await {
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
        Box::new(move |_cc| Ok(Box::new(ViewerApp::new(slot, config)))),
    )
    .map_err(|e| -> Box<dyn std::error::Error> { format!("eframe: {e}").into() })?;

    // eframe blocks until the window closes; runtime drops here.
    drop(rt);
    Ok(())
}

async fn gui_receive_loop(
    args: Args,
    slot: Arc<FrameSlot>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source_id = parse_source_id(&args.source_id_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    info!(peer = %args.connect, codec = ?args.codec, transport = ?args.transport, "GUI connecting to xenia-peer daemon");

    let mut transport = connect_transport(&args)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut handshake_mgr = HandshakeManager::new();
    let session_key = perform_viewer_handshake(&mut transport, &mut handshake_mgr, "daemon")
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut session = Session::with_fixture(SessionRole::Viewer, source_id, args.epoch);
    session.install_key(session_key);

    let mut decoder = make_decoder(args.codec)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let expected_frame_fmt = codec_to_frame_format(args.codec);

    let frame_limit = args.frames.unwrap_or(0);
    let mut received: u64 = 0;
    let mut audio_received: u64 = 0;
    let mut audio_jitter = AudioJitterBuffer::new(0, 16);
    loop {
        if frame_limit != 0 && received >= frame_limit {
            info!(received, "reached --frames, closing receive loop");
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
        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            if let Some(telemetry) = decode_telemetry_frame(&raw_frame) {
                slot.put_telemetry(telemetry);
            }
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Audio {
            if let Some(audio) =
                process_audio_frame(&raw_frame, &mut audio_jitter, &mut audio_received)
            {
                slot.put_audio(audio);
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
            });
        }
    }
    Ok(())
}

// ─── Shared helper ─────────────────────────────────────────────────

async fn connect_transport(args: &Args) -> Result<AnyTransport, TransportError> {
    match args.transport {
        TransportChoice::Auto => connect_auto(&args.connect).await,
        TransportChoice::Tcp => connect_tcp(&args.connect).await,
        TransportChoice::Ws => connect_ws(&args.connect).await,
        TransportChoice::Quic => connect_quic(&args.connect).await,
    }
}

async fn connect_auto(connect: &str) -> Result<AnyTransport, TransportError> {
    if connect.starts_with("iroh:") {
        connect_quic(connect).await
    } else if connect.starts_with("ws://") || connect.starts_with("wss://") {
        connect_ws(connect).await
    } else {
        connect_auto_with_advertisement(connect).await
    }
}

async fn connect_tcp(connect: &str) -> Result<AnyTransport, TransportError> {
    Ok(AnyTransport::Tcp(TcpTransport::connect(connect).await?))
}

async fn connect_auto_with_advertisement(connect: &str) -> Result<AnyTransport, TransportError> {
    let mut tcp = TcpTransport::connect(connect).await?;
    let first = tcp.recv_envelope().await?;
    let advert =
        TransportAdvertisement::decode(&first).map_err(|e| std::io::Error::other(e.to_string()))?;
    let Some(advert) = advert else {
        info!("daemon did not send a transport advertisement; continuing on TCP");
        return Ok(AnyTransport::PreloadedTcp {
            first: Some(first),
            transport: tcp,
        });
    };

    if let Some(quic_connect) = advert
        .quic_connect
        .as_deref()
        .filter(|_| advert.transports.contains(&AdvertisedTransport::Quic))
    {
        info!("daemon advertised QUIC; reconnecting over Iroh");
        return connect_quic(quic_connect).await;
    }

    info!("daemon advertisement did not include QUIC; continuing on TCP");
    Ok(AnyTransport::Tcp(tcp))
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
