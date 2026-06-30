// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

/// `xenia-peer` — headless daemon that hosts a Xenia session.
use clap::{Parser, ValueEnum};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};
use uuid::Uuid;

use ed25519_dalek::SigningKey;
#[cfg(any(feature = "audio-capture", test))]
use xenia_capture::{AudioCapture, AudioFrame};
use xenia_capture::{
    FrameData as CaptureFrameData, ScreenCapture, SysinfoTelemetryStream, TelemetryStream,
    TestCapture,
};
use xenia_handshake::HandshakeManager;
use xenia_ledger::{Chain, LedgerEntry};
#[cfg(feature = "audio-opus")]
use xenia_peer_core::OpusAudioCodec;
#[cfg(any(feature = "audio-capture", test))]
use xenia_peer_core::frame::audio_flags;
use xenia_peer_core::{
    AudioCodec, RawPcmAudioCodec, Session, SessionRole,
    advertisement::{AdvertisedAudioCodec, AudioAdvertisement, TransportAdvertisement},
    frame::{
        PixelFormat as FramePixelFormat, RawAudio, RawFrame, RawTelemetry, SyntheticAudioKind,
        SyntheticAudioSource, TelemetrySample as WireTelemetrySample,
        TelemetryValue as WireTelemetryValue,
    },
    handshake::perform_host_handshake_with_transcript,
    transport::{TcpTransport, Transport},
};
use xenia_transport_quic::{QuicTransport, bind_xenia_endpoint, encode_endpoint_addr};
use xenia_transport_ws::WsTransport;
use xenia_video::{
    EncodeParams, Encoder, PixelFormat as VideoPixelFormat, passthrough::PassthroughEncoder,
};

#[cfg(feature = "audio-capture")]
use xenia_capture::CpalAudioCapture;
#[cfg(feature = "scap")]
use xenia_capture::ScapCapture;

mod governance;
mod m1_ledger;
mod m1_runtime;
use crate::governance::{GovernanceBridge, MitigationRule};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: String,

    #[arg(short, long, default_value = "passthrough")]
    codec: CodecChoice,

    #[arg(long, default_value_t = 320)]
    width: u32,

    #[arg(long, default_value_t = 200)]
    height: u32,

    #[arg(long, default_value_t = 30)]
    fps: u32,

    #[arg(long, default_value_t = 0)]
    frames: u64,

    #[arg(long, default_value = "auto")]
    transport: TransportChoice,

    #[arg(long, default_value = "7878656e69617068")]
    source_id_hex: String,

    #[arg(long, default_value_t = 0x01)]
    epoch: u8,

    #[arg(long, default_value_t = 8081)]
    admin_port: u16,

    #[arg(long, default_value_t = 8082)]
    consent_port: u16,

    #[arg(long, default_value_t = 1_000)]
    telemetry_interval_ms: u64,

    #[arg(long, value_enum, default_value_t = TelemetryLevel::Basic)]
    telemetry_level: TelemetryLevel,

    #[arg(long, value_enum, default_value_t = AudioMode::Off)]
    audio: AudioMode,

    #[arg(long, value_enum, default_value_t = AudioCodecChoice::RawPcm)]
    audio_codec: AudioCodecChoice,

    #[arg(long, default_value_t = 20)]
    audio_interval_ms: u64,

    /// Run a deterministic M1 runtime smoke check and exit.
    #[arg(long)]
    m1_runtime_smoke: bool,

    /// Optional directory for `--m1-runtime-smoke` to write a verifier-consumable
    /// transcript-bound evidence bundle.
    #[arg(long, requires = "m1_runtime_smoke")]
    m1_runtime_smoke_evidence_dir: Option<std::path::PathBuf>,

    /// Evidence profile requested by `--m1-runtime-smoke-evidence-dir`.
    /// `full-pqc-v1` is intentionally refused until PQ signatures land.
    #[arg(
        long,
        default_value = "hybrid-pre-pqc-v1",
        requires = "m1_runtime_smoke_evidence_dir"
    )]
    m1_runtime_smoke_evidence_profile: String,

    /// Verify a transcript-bound M1 evidence bundle directory and exit.
    #[arg(long, value_name = "DIR")]
    verify_evidence_bundle: Option<std::path::PathBuf>,

    /// Hex-encoded Ed25519 public key for `--verify-evidence-bundle`.
    #[arg(long, requires = "verify_evidence_bundle")]
    evidence_public_key_hex: Option<String>,

    /// PRE-PRODUCTION ONLY: auto-grant the local M1 runtime gate after handshake.
    ///
    /// This exists until the real consent approval source drives the M1 runtime.
    /// It is refused at runtime unless built with `xenia-peer/preprod-fixtures`.
    /// Without this flag, live frame flow fails closed after the M1 session offer.
    #[arg(long, help_heading = "Pre-production fixtures")]
    m1_preprod_auto_consent: bool,

    /// Operator signing key path. Smokes should point this at a temporary path
    /// so runtime keys are not written into the repository root.
    #[arg(long, default_value = "operator.key")]
    operator_key_path: std::path::PathBuf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CodecChoice {
    Passthrough,
    H264,
    Hdc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TransportChoice {
    Auto,
    Tcp,
    Ws,
    Quic,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TelemetryLevel {
    Off,
    Basic,
    System,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AudioMode {
    Off,
    Sine,
    Noise,
    Capture,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AudioCodecChoice {
    Auto,
    RawPcm,
    #[cfg(feature = "audio-opus")]
    Opus,
}

enum DaemonAudioSource {
    Synthetic(SyntheticAudioSource),
    #[cfg(any(feature = "audio-capture", test))]
    Capture {
        stream_id: u32,
        sequence: u64,
        capture: Box<dyn AudioCapture>,
    },
}

enum AnyTransport {
    Tcp(TcpTransport),
    Ws(WsTransport),
    Quic {
        _endpoint: xenia_transport_quic::iroh::Endpoint,
        transport: QuicTransport,
    },
}

#[allow(clippy::large_enum_variant)] // WsTransport is intentionally stored inline; mirrors xenia-viewer transport enum policy.
enum AutoAcceptedTransport {
    Tcp(TcpTransport),
    Ws(WsTransport),
}

impl Transport for AnyTransport {
    async fn send_envelope(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), xenia_peer_core::transport::TransportError> {
        match self {
            AnyTransport::Tcp(t) => t.send_envelope(bytes).await,
            AnyTransport::Ws(t) => t.send_envelope(bytes).await,
            AnyTransport::Quic { transport, .. } => transport.send_envelope(bytes).await,
        }
    }
    async fn recv_envelope(
        &mut self,
    ) -> Result<Vec<u8>, xenia_peer_core::transport::TransportError> {
        match self {
            AnyTransport::Tcp(t) => t.recv_envelope().await,
            AnyTransport::Ws(t) => t.recv_envelope().await,
            AnyTransport::Quic { transport, .. } => transport.recv_envelope().await,
        }
    }
}

impl AnyTransport {
    async fn close(&mut self) -> Result<(), xenia_peer_core::transport::TransportError> {
        if let AnyTransport::Quic {
            _endpoint,
            transport,
        } = self
        {
            let finish_result = transport.finish();
            let _ = tokio::time::timeout(Duration::from_secs(3), transport.closed()).await;
            _endpoint.close().await;
            finish_result?;
        }
        Ok(())
    }
}

async fn accept_auto_tcp_or_ws_probe(
    listener: TcpListener,
) -> Result<AutoAcceptedTransport, xenia_peer_core::transport::TransportError> {
    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true).ok();
    if looks_like_websocket(&stream).await? {
        info!(peer = %peer, "auto transport selected websocket");
        Ok(AutoAcceptedTransport::Ws(
            WsTransport::accept_stream(stream).await?,
        ))
    } else {
        info!(peer = %peer, "auto transport accepted tcp discovery probe");
        Ok(AutoAcceptedTransport::Tcp(TcpTransport::new(stream)))
    }
}

async fn looks_like_websocket(
    stream: &TcpStream,
) -> Result<bool, xenia_peer_core::transport::TransportError> {
    let mut buf = [0u8; 3];
    match tokio::time::timeout(Duration::from_millis(250), stream.peek(&mut buf)).await {
        Ok(Ok(n)) => Ok(n == 3 && &buf == b"GET"),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Ok(false),
    }
}

async fn accept_quic() -> Result<AnyTransport, xenia_peer_core::transport::TransportError> {
    let endpoint = bind_xenia_endpoint().await?;
    print_quic_connect(&endpoint)?;
    let transport = QuicTransport::accept_one(&endpoint).await?;
    Ok(AnyTransport::Quic {
        _endpoint: endpoint,
        transport,
    })
}

fn print_quic_connect(
    endpoint: &xenia_transport_quic::iroh::Endpoint,
) -> Result<String, xenia_peer_core::transport::TransportError> {
    let cli_addr = encode_endpoint_addr(&endpoint.addr())?;
    println!("QUIC_CONNECT={cli_addr}");
    info!(
        iroh_addr = %cli_addr,
        "xenia-peer QUIC endpoint ready; pass this value to xenia-viewer --connect"
    );
    Ok(cli_addr)
}

async fn accept_transport(
    args: &Args,
    audio_advertisement: AudioAdvertisement,
) -> Result<AnyTransport, xenia_peer_core::transport::TransportError> {
    match args.transport {
        TransportChoice::Auto => {
            let listener = TcpListener::bind(&args.listen).await?;
            let endpoint = bind_xenia_endpoint().await?;
            let quic_connect = print_quic_connect(&endpoint)?;
            let quic_endpoint = endpoint.clone();
            let tcp_or_ws = accept_auto_tcp_or_ws_probe(listener);
            let quic = QuicTransport::accept_one(&quic_endpoint);
            tokio::select! {
                result = tcp_or_ws => {
                    match result? {
                        AutoAcceptedTransport::Ws(ws) => {
                            endpoint.close().await;
                            Ok(AnyTransport::Ws(ws))
                        }
                        AutoAcceptedTransport::Tcp(mut tcp) => {
                            let advert = TransportAdvertisement::auto(quic_connect)
                                .with_audio(audio_advertisement)
                                .encode()
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            tcp.send_envelope(&advert).await?;
                            info!("sent transport advertisement; waiting briefly for viewer QUIC upgrade");
                            match tokio::time::timeout(
                                Duration::from_secs(3),
                                QuicTransport::accept_one(&quic_endpoint),
                            )
                            .await
                            {
                                Ok(result) => Ok(AnyTransport::Quic {
                                    _endpoint: endpoint,
                                    transport: result?,
                                }),
                                Err(_) => {
                                    info!("viewer did not upgrade to QUIC; continuing on TCP");
                                    endpoint.close().await;
                                    Ok(AnyTransport::Tcp(tcp))
                                }
                            }
                        }
                    }
                }
                result = quic => Ok(AnyTransport::Quic {
                    _endpoint: endpoint,
                    transport: result?,
                }),
            }
        }
        TransportChoice::Tcp => {
            let listener = TcpListener::bind(&args.listen).await?;
            let (stream, _) = listener.accept().await?;
            Ok(AnyTransport::Tcp(TcpTransport::new(stream)))
        }
        TransportChoice::Ws => {
            let (ws, _) = WsTransport::bind_and_accept_one(&args.listen).await?;
            Ok(AnyTransport::Ws(ws))
        }
        TransportChoice::Quic => accept_quic().await,
    }
}

fn parse_source_id(hex: &str) -> Result<[u8; 8], String> {
    let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "Source ID must be 8 bytes (16 hex chars)".to_string())
}

fn make_encoder(
    choice: CodecChoice,
    params: EncodeParams,
) -> Result<Box<dyn Encoder>, Box<dyn std::error::Error>> {
    match choice {
        CodecChoice::Passthrough => Ok(Box::new(PassthroughEncoder::new(params))),
        CodecChoice::H264 => build_h264_encoder(params),
        CodecChoice::Hdc => build_hdc_encoder(params),
    }
}

#[cfg(feature = "h264")]
fn build_h264_encoder(
    params: EncodeParams,
) -> Result<Box<dyn Encoder>, Box<dyn std::error::Error>> {
    Ok(Box::new(xenia_video::h264::H264Encoder::new(params)?))
}

#[cfg(not(feature = "h264"))]
fn build_h264_encoder(
    _params: EncodeParams,
) -> Result<Box<dyn Encoder>, Box<dyn std::error::Error>> {
    Err("xenia-peer was built without the `h264` feature; rebuild with `cargo build -p xenia-peer --features h264`, or use --codec passthrough".into())
}

#[cfg(feature = "hdc")]
fn build_hdc_encoder(params: EncodeParams) -> Result<Box<dyn Encoder>, Box<dyn std::error::Error>> {
    Ok(Box::new(xenia_video::hdc::HdcEncoder::new(params)))
}

#[cfg(not(feature = "hdc"))]
fn build_hdc_encoder(
    _params: EncodeParams,
) -> Result<Box<dyn Encoder>, Box<dyn std::error::Error>> {
    Err("xenia-peer was built without the `hdc` feature; rebuild with `cargo build -p xenia-peer --features hdc`, or use --codec passthrough".into())
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
) -> Result<Box<dyn AudioCodec>, Box<dyn std::error::Error>> {
    match choice {
        AudioCodecChoice::Auto => make_audio_codec(resolve_audio_codec_choice(choice)),
        AudioCodecChoice::RawPcm => Ok(Box::new(RawPcmAudioCodec::new())),
        #[cfg(feature = "audio-opus")]
        AudioCodecChoice::Opus => Ok(Box::new(OpusAudioCodec::new()?)),
    }
}

fn resolve_audio_codec_choice(choice: AudioCodecChoice) -> AudioCodecChoice {
    match choice {
        AudioCodecChoice::Auto => {
            #[cfg(feature = "audio-opus")]
            {
                AudioCodecChoice::Opus
            }
            #[cfg(not(feature = "audio-opus"))]
            {
                AudioCodecChoice::RawPcm
            }
        }
        other => other,
    }
}

fn advertised_audio_codec(choice: AudioCodecChoice) -> AdvertisedAudioCodec {
    match resolve_audio_codec_choice(choice) {
        AudioCodecChoice::RawPcm => AdvertisedAudioCodec::RawPcm,
        #[cfg(feature = "audio-opus")]
        AudioCodecChoice::Opus => AdvertisedAudioCodec::Opus,
        AudioCodecChoice::Auto => unreachable!("audio codec choice should be resolved"),
    }
}

fn audio_advertisement(choice: AudioCodecChoice) -> AudioAdvertisement {
    let codecs = vec![AdvertisedAudioCodec::RawPcm];
    #[cfg(feature = "audio-opus")]
    let codecs = {
        let mut codecs = codecs;
        codecs.push(AdvertisedAudioCodec::Opus);
        codecs
    };
    AudioAdvertisement {
        codecs,
        selected_codec: advertised_audio_codec(choice),
        sample_rate_hz: xenia_peer_core::frame::RAW_AUDIO_SAMPLE_RATE_HZ,
        max_channels: xenia_peer_core::frame::RAW_AUDIO_MAX_CHANNELS,
        frame_duration_ms: vec![10, 20],
    }
}

fn session_capabilities_frame(
    frame_id: u64,
    audio: AudioAdvertisement,
    video_format: FramePixelFormat,
    telemetry_level: TelemetryLevel,
) -> Result<RawFrame, Box<dyn std::error::Error>> {
    xenia_peer_core::RawCapabilities {
        frame_id,
        timestamp_ms: now_ms(),
        audio: Some(audio),
        video_format,
        telemetry_enabled: telemetry_level != TelemetryLevel::Off,
        input_control_enabled: false,
    }
    .into_frame()
    .map_err(Into::into)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn telemetry_value_to_wire(value: xenia_capture::TelemetryValue) -> WireTelemetryValue {
    match value {
        xenia_capture::TelemetryValue::I64(value) => WireTelemetryValue::I64(value),
        xenia_capture::TelemetryValue::U64(value) => WireTelemetryValue::U64(value),
        xenia_capture::TelemetryValue::F64(value) => WireTelemetryValue::F64(value),
        xenia_capture::TelemetryValue::Bool(value) => WireTelemetryValue::Bool(value),
        xenia_capture::TelemetryValue::Text(value) => WireTelemetryValue::Text(value),
    }
}

fn telemetry_sample_to_wire(sample: xenia_capture::TelemetrySample) -> WireTelemetrySample {
    WireTelemetrySample {
        name: sample.name,
        value: telemetry_value_to_wire(sample.value),
        unit: sample.unit,
        timestamp_ms: sample.timestamp_ms,
    }
}

fn telemetry_sample_allowed(
    level: TelemetryLevel,
    sample: &xenia_capture::TelemetrySample,
) -> bool {
    match level {
        TelemetryLevel::Off => false,
        TelemetryLevel::Basic => matches!(
            sample.name.as_str(),
            "cpu.total.percent" | "memory.total.bytes" | "memory.used.bytes"
        ),
        TelemetryLevel::System => true,
    }
}

fn m1_consent_scope(telemetry_level: TelemetryLevel, audio_mode: AudioMode) -> String {
    let telemetry = match telemetry_level {
        TelemetryLevel::Off => "telemetry: off",
        TelemetryLevel::Basic => "telemetry: basic host performance",
        TelemetryLevel::System => "telemetry: system identity and performance",
    };
    let audio = match audio_mode {
        AudioMode::Off => "audio: off",
        AudioMode::Sine | AudioMode::Noise => "audio: synthetic test signal",
        AudioMode::Capture => "audio: host device capture",
    };
    format!("display: screen stream; {telemetry}; {audio}")
}

fn synthetic_audio_kind(mode: AudioMode) -> Option<SyntheticAudioKind> {
    match mode {
        AudioMode::Off => None,
        AudioMode::Sine => Some(SyntheticAudioKind::Sine),
        AudioMode::Noise => Some(SyntheticAudioKind::Noise),
        AudioMode::Capture => None,
    }
}

fn build_audio_source(
    mode: AudioMode,
) -> Result<Option<DaemonAudioSource>, Box<dyn std::error::Error>> {
    Ok(match mode {
        AudioMode::Off => None,
        AudioMode::Sine | AudioMode::Noise => {
            let kind = synthetic_audio_kind(mode).expect("synthetic audio mode should map to kind");
            Some(DaemonAudioSource::Synthetic(SyntheticAudioSource::new(
                1, kind,
            )))
        }
        AudioMode::Capture => {
            return build_capture_audio_source();
        }
    })
}

#[cfg(feature = "audio-capture")]
fn build_capture_audio_source() -> Result<Option<DaemonAudioSource>, Box<dyn std::error::Error>> {
    Ok(Some(DaemonAudioSource::Capture {
        stream_id: 1,
        sequence: 0,
        capture: Box::new(CpalAudioCapture::new_default_input()?),
    }))
}

#[cfg(not(feature = "audio-capture"))]
fn build_capture_audio_source() -> Result<Option<DaemonAudioSource>, Box<dyn std::error::Error>> {
    Err("xenia-peer was built without real daemon audio capture; rebuild with `cargo build -p xenia-peer --features audio-capture`, or use --audio sine/noise for synthetic protocol tests".into())
}

impl DaemonAudioSource {
    fn next_raw_audio(
        &mut self,
        fallback_timestamp_ms: u64,
    ) -> Result<Option<RawAudio>, Box<dyn std::error::Error>> {
        match self {
            Self::Synthetic(source) => Ok(Some(source.next_frame(fallback_timestamp_ms))),
            #[cfg(any(feature = "audio-capture", test))]
            Self::Capture {
                stream_id,
                sequence,
                capture,
            } => {
                let Some(frame) = capture.capture_audio()? else {
                    return Ok(None);
                };
                let raw = raw_audio_from_capture_frame(
                    *stream_id,
                    *sequence,
                    fallback_timestamp_ms,
                    frame,
                )?;
                *sequence = sequence.wrapping_add(1);
                Ok(Some(raw))
            }
        }
    }
}

#[cfg(any(feature = "audio-capture", test))]
fn raw_audio_from_capture_frame(
    stream_id: u32,
    sequence: u64,
    fallback_timestamp_ms: u64,
    frame: AudioFrame,
) -> Result<RawAudio, Box<dyn std::error::Error>> {
    if frame.channels == 0 {
        return Err("captured audio frame has zero channels".into());
    }
    if frame.sample_rate_hz != xenia_peer_core::frame::RAW_AUDIO_SAMPLE_RATE_HZ {
        return Err(format!(
            "captured audio frame uses {} Hz; RawAudio v0.1 requires 48000 Hz",
            frame.sample_rate_hz
        )
        .into());
    }
    if !frame
        .samples_i16
        .len()
        .is_multiple_of(usize::from(frame.channels))
    {
        return Err("captured audio samples are not divisible by channel count".into());
    }

    let samples_per_channel = frame.samples_i16.len() / usize::from(frame.channels);
    let frame_duration_ms = samples_per_channel as u64 * 1_000 / u64::from(frame.sample_rate_hz);
    if !matches!(frame_duration_ms, 10 | 20) {
        return Err(format!(
            "captured audio frame duration is {frame_duration_ms} ms; RawAudio v0.1 supports 10 or 20 ms"
        )
        .into());
    }
    if samples_per_channel as u64 * 1_000 != frame_duration_ms * u64::from(frame.sample_rate_hz) {
        return Err("captured audio frame duration is not an exact millisecond duration".into());
    }

    let mut payload = Vec::with_capacity(frame.samples_i16.len() * 2);
    for sample in frame.samples_i16 {
        payload.extend_from_slice(&sample.to_le_bytes());
    }

    let raw = RawAudio {
        schema_version: xenia_peer_core::frame::RAW_AUDIO_SCHEMA_VERSION,
        clock_domain: xenia_peer_core::frame::RAW_AUDIO_CLOCK_UNIX_MS,
        stream_id,
        sequence,
        capture_timestamp_ms: if frame.timestamp_ms == 0 {
            fallback_timestamp_ms
        } else {
            frame.timestamp_ms
        },
        sample_rate_hz: frame.sample_rate_hz,
        channels: frame.channels,
        sample_format: xenia_peer_core::AudioSampleFormat::PcmS16Le,
        frame_duration_ms: frame_duration_ms as u16,
        flags: audio_flags::NONE,
        payload,
    };
    if raw.validate() {
        Ok(raw)
    } else {
        Err("captured audio frame did not satisfy RawAudio v0.1 validation".into())
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let source_id = parse_source_id(&args.source_id_hex)?;

    if args.m1_runtime_smoke {
        run_m1_runtime_smoke(
            source_id,
            args.m1_runtime_smoke_evidence_dir.as_deref(),
            &args.m1_runtime_smoke_evidence_profile,
        )?;
        return Ok(());
    }

    if let Some(bundle_dir) = args.verify_evidence_bundle.as_deref() {
        let public_key_hex = args
            .evidence_public_key_hex
            .as_deref()
            .ok_or("--verify-evidence-bundle requires --evidence-public-key-hex")?;
        let public_key = parse_ed25519_public_key_hex(public_key_hex)?;
        let report = crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir(
            bundle_dir,
            &public_key,
        )?;
        println!("evidence bundle verified");
        println!("profile: {}", report.profile);
        println!("entries: {}", report.ledger_entries);
        println!("session: {}", report.session_id);
        return Ok(());
    }

    info!(addr = %args.listen, "xenia-peer daemon listening");

    let signing_key = if args.operator_key_path.exists() {
        let key_bytes = std::fs::read(&args.operator_key_path)?;
        SigningKey::from_bytes(&key_bytes.try_into().map_err(|_| "Invalid key length")?)
    } else {
        let key = SigningKey::generate(&mut rand::thread_rng());
        std::fs::write(&args.operator_key_path, key.to_bytes())?;
        key
    };

    let mut telemetry = SysinfoTelemetryStream::new();
    let mut audio = build_audio_source(args.audio)?;
    let audio_codec_choice = resolve_audio_codec_choice(args.audio_codec);
    let audio_advertisement = audio_advertisement(audio_codec_choice);
    let mut audio_codec = make_audio_codec(audio_codec_choice)?;
    info!(
        audio_codec = audio_codec.name(),
        "daemon audio codec configured"
    );

    let ledger_path = std::path::Path::new("consent.ledger");
    let ledger = if ledger_path.exists() {
        let bytes = std::fs::read(ledger_path)?;
        let entries: Vec<LedgerEntry> = bincode::deserialize(&bytes)?;
        Chain::from_entries(entries, signing_key.clone())
    } else {
        Chain::new(signing_key.clone())
    };
    let shared_ledger = std::sync::Arc::new(tokio::sync::Mutex::new(ledger));

    let policy_path = std::path::Path::new("policy.json");
    let rules: Vec<MitigationRule> = if policy_path.exists() {
        let content = std::fs::read_to_string(policy_path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        vec![]
    };
    let shared_rules = std::sync::Arc::new(rules);
    let session_id = Uuid::new_v4();

    use axum::{
        Router,
        extract::ws::{WebSocket, WebSocketUpgrade},
        response::IntoResponse,
        routing::get,
    };
    use futures::StreamExt;

    async fn ws_handler(ws: WebSocketUpgrade, bridge: Arc<GovernanceBridge>) -> impl IntoResponse {
        ws.on_upgrade(move |socket| handle_socket(socket, bridge))
    }

    async fn handle_socket(mut socket: WebSocket, bridge: Arc<GovernanceBridge>) {
        let mut rx = bridge.subscribe();
        while let Ok(msg) = rx.recv().await {
            if socket
                .send(axum::extract::ws::Message::Text(msg.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    }
    let bridge = Arc::new(GovernanceBridge::new(
        shared_ledger.clone(),
        signing_key.verifying_key(),
        shared_rules.clone(),
        [0u8; 32],
        session_id,
    ));
    bridge.start_sentinel();
    bridge.start_signal_listener();
    bridge.broadcast("daemon ready");

    let app = Router::new().route(
        "/ws",
        get({
            let bridge = bridge.clone();
            move |ws| ws_handler(ws, bridge.clone())
        }),
    );

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.admin_port)).await?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "admin websocket server exited");
        }
    });

    // Initialize Capture Backend
    let mut capture: Box<dyn ScreenCapture> = {
        #[cfg(feature = "scap")]
        if ScapCapture::is_available() {
            info!("Initializing ScapCapture backend");
            match ScapCapture::new() {
                Ok(capture) => Box::new(capture),
                Err(err) => {
                    warn!(error = %err, "ScapCapture initialization failed; falling back to TestCapture");
                    Box::new(TestCapture::new(args.width, args.height))
                }
            }
        } else {
            info!("ScapCapture unavailable, falling back to TestCapture");
            Box::new(TestCapture::new(args.width, args.height))
        }
        #[cfg(not(feature = "scap"))]
        {
            info!("ScapCapture not built-in, using TestCapture");
            Box::new(TestCapture::new(args.width, args.height))
        }
    };

    // Performance Telemetry: Periodically log session latency.
    {
        let capture_backend = capture.backend_name().to_string();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                // Note: In production, this would be a thread-safe handle
                // to the Session instance. For now, log the telemetry.
                info!(backend = %capture_backend, "Session heartbeat active");
            }
        });
    }

    let mut transport = accept_transport(&args, audio_advertisement.clone()).await?;

    let mut mgr = HandshakeManager::new();
    let handshake =
        perform_host_handshake_with_transcript(&mut transport, &mut mgr, "viewer").await?;
    let session_key = handshake.session_key;
    info!("Handshake successful, session key established and transcript hash computed");

    // Consent Ceremony: Simple CLI prompt
    // In a real implementation, this would be a GUI-based consent flow
    // integrated with a desktop portal or the admin crate.
    info!("Waiting for consent request...");

    // Server task for processing consent responses.
    let consent_addr = format!("127.0.0.1:{}", args.consent_port);
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&consent_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(addr = %consent_addr, error = %err, "consent websocket bind failed");
                return;
            }
        };

        match listener.accept().await {
            Ok((stream, _)) => match tokio_tungstenite::accept_async(stream).await {
                Ok(mut ws_stream) => {
                    while let Some(result) = ws_stream.next().await {
                        match result {
                            Ok(msg) => {
                                if let Ok(text) = msg.to_text() {
                                    info!("Received consent response: {}", text);
                                    // Process Approve/Deny...
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "consent websocket receive failed");
                                break;
                            }
                        }
                    }
                }
                Err(err) => tracing::warn!(error = %err, "consent websocket handshake failed"),
            },
            Err(err) => tracing::warn!(error = %err, "consent websocket accept failed"),
        }
    });

    let mut session = Session::with_fixture(SessionRole::Host, source_id, args.epoch);
    session.install_key(session_key);
    let frame_format = codec_to_frame_format(args.codec);
    let capabilities = session_capabilities_frame(
        session.next_frame_id(),
        audio_advertisement.clone(),
        frame_format,
        args.telemetry_level,
    )?;
    let envelope = session.seal_control_frame(&capabilities)?;
    transport.send_envelope(&envelope).await?;
    info!("sealed session capabilities sent");

    let m1_signing_key = SigningKey::from_bytes(&[0x41u8; 32]);
    let m1_scope = m1_consent_scope(args.telemetry_level, args.audio);
    let m1_scope_for_log = m1_scope.clone();
    let mut m1_runtime = crate::m1_runtime::M1RuntimeSession::new(
        m1_signing_key,
        expand_source_id_for_m1(source_id),
        session_id,
        Uuid::new_v4(),
        m1_scope,
    );
    m1_runtime.bind_session_transcript_hash(handshake.transcript_hash);
    m1_runtime.offer()?;
    info!(scope = %m1_scope_for_log, "M1 consent scope offered");

    if args.m1_preprod_auto_consent {
        grant_preprod_auto_consent(&mut m1_runtime)?;
    } else {
        warn!("M1 runtime gate offered but not approved; live frame flow will fail closed");
    }

    let params = EncodeParams {
        width: args.width,
        height: args.height,
        pixel_format: VideoPixelFormat::Rgba,
        target_fps: args.fps.max(1),
        bitrate_kbps: 2_000,
    };
    let mut encoder = make_encoder(args.codec, params)?;
    let frame_interval = Duration::from_millis(1_000 / u64::from(args.fps.max(1)));
    let mut ticker = tokio::time::interval(frame_interval);
    let telemetry_interval = Duration::from_millis(args.telemetry_interval_ms.max(1));
    let mut last_telemetry_sent = std::time::Instant::now() - telemetry_interval;
    let audio_interval = Duration::from_millis(args.audio_interval_ms.max(1));
    let mut last_audio_sent = std::time::Instant::now() - audio_interval;
    let mut sent_frames = 0u64;
    let mut sent_telemetry = 0u64;
    let mut sent_audio = 0u64;

    loop {
        if args.frames != 0 && sent_frames >= args.frames {
            info!(sent = sent_frames, "reached --frames, daemon exiting");
            break;
        }

        ticker.tick().await;
        if args.telemetry_level != TelemetryLevel::Off
            && last_telemetry_sent.elapsed() >= telemetry_interval
        {
            m1_runtime.preflight_frame_flow()?;
            match telemetry.poll_samples() {
                Ok(samples) if !samples.is_empty() => {
                    let samples: Vec<_> = samples
                        .into_iter()
                        .filter(|sample| telemetry_sample_allowed(args.telemetry_level, sample))
                        .collect();
                    if samples.is_empty() {
                        last_telemetry_sent = std::time::Instant::now();
                        continue;
                    }
                    let frame_id = session.next_frame_id();
                    let telemetry_frame = RawTelemetry {
                        frame_id,
                        timestamp_ms: now_ms(),
                        backend: telemetry.backend_name().to_string(),
                        samples: samples.into_iter().map(telemetry_sample_to_wire).collect(),
                    }
                    .into_frame()?;
                    let envelope = session.seal_frame(&telemetry_frame)?;
                    m1_runtime.allow_frame_flow()?;
                    transport.send_envelope(&envelope).await?;
                    sent_telemetry += 1;
                    last_telemetry_sent = std::time::Instant::now();
                    if sent_telemetry <= 3 || sent_telemetry.is_multiple_of(10) {
                        info!(
                            sent = sent_telemetry,
                            frame_id, "telemetry batch sealed and sent"
                        );
                    }
                }
                Ok(_) => {}
                Err(err) => warn!(error = %err, "telemetry poll failed"),
            }
        }

        if let Some(audio) = &mut audio
            && last_audio_sent.elapsed() >= audio_interval
        {
            m1_runtime.preflight_frame_flow()?;
            if let Some(raw_audio) = audio.next_raw_audio(now_ms())? {
                let raw_audio = audio_codec.encode(raw_audio)?;
                let frame_id = session.next_frame_id();
                let audio_frame = raw_audio.into_frame(frame_id)?;
                let envelope = session.seal_frame(&audio_frame)?;
                m1_runtime.allow_frame_flow()?;
                transport.send_envelope(&envelope).await?;
                sent_audio += 1;
                last_audio_sent = std::time::Instant::now();
                if sent_audio <= 3 || sent_audio.is_multiple_of(50) {
                    info!(sent = sent_audio, frame_id, "audio frame sealed and sent");
                }
            }
        }

        m1_runtime.preflight_frame_flow()?;
        let Some(frame) = capture.capture()? else {
            continue;
        };
        let pixels = match frame.data {
            CaptureFrameData::Pixels(pixels) => pixels,
            CaptureFrameData::Dmabuf { .. } => {
                warn!("capture returned DMABUF frame; CPU encode path requires pixels");
                continue;
            }
        };
        if frame.width != args.width || frame.height != args.height {
            warn!(
                width = frame.width,
                height = frame.height,
                expected_width = args.width,
                expected_height = args.height,
                "capture dimensions changed; dropping frame"
            );
            continue;
        }

        let captured_at = now_ms();
        let packets = encoder.encode(&pixels, captured_at)?;
        for packet in packets {
            let frame_id = session.next_frame_id();
            let raw = RawFrame::encoded(
                frame_id,
                packet.pts_ms,
                args.width,
                args.height,
                frame_format,
                packet.bytes,
            );
            let envelope = session.seal_frame(&raw)?;
            m1_runtime.allow_frame_flow()?;
            transport.send_envelope(&envelope).await?;
            sent_frames += 1;
            if sent_frames <= 3 || sent_frames.is_multiple_of(10) {
                info!(
                    sent = sent_frames,
                    frame_id, "frame encoded, sealed, and sent"
                );
            }
            if args.frames != 0 && sent_frames >= args.frames {
                break;
            }
        }
    }

    transport.close().await?;
    Ok(())
}

fn grant_preprod_auto_consent(
    m1_runtime: &mut crate::m1_runtime::M1RuntimeSession,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "preprod-fixtures")]
    {
        warn!("PRE-PRODUCTION ONLY: auto-granting M1 runtime consent gate after handshake");
        m1_runtime.grant_consent()?;
        Ok(())
    }

    #[cfg(not(feature = "preprod-fixtures"))]
    {
        let _ = m1_runtime;
        Err("--m1-preprod-auto-consent requires building with feature `xenia-peer/preprod-fixtures`; use only for local smoke tests".into())
    }
}

fn parse_ed25519_public_key_hex(
    hex_text: &str,
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_text)?;
    let public_key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be exactly 32 bytes")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)?)
}

fn expand_source_id_for_m1(source_id_short: [u8; 8]) -> [u8; 32] {
    let mut source_id = [0u8; 32];
    source_id[..8].copy_from_slice(&source_id_short);
    source_id
}

fn run_m1_runtime_smoke(
    source_id_short: [u8; 8],
    evidence_dir: Option<&std::path::Path>,
    evidence_profile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[0x4Du8; 32]);
    let verifying_key = signing_key.verifying_key();

    let source_id = expand_source_id_for_m1(source_id_short);

    let mut runtime = crate::m1_runtime::M1RuntimeSession::new(
        signing_key,
        source_id,
        Uuid::from_bytes([0x11; 16]),
        Uuid::from_bytes([0x22; 16]),
        "m1 runtime cli smoke",
    );
    runtime.bind_session_transcript_hash([0x33; 32]);

    runtime.offer()?;
    runtime.grant_consent()?;
    runtime.stream_frame()?;
    runtime.inject_input()?;
    runtime.revoke()?;
    runtime.verify(&verifying_key)?;

    let transcript_path = std::env::temp_dir().join(format!(
        "xenia-m1-runtime-smoke-{}-{}.bin",
        std::process::id(),
        Uuid::from_bytes([0x22; 16])
    ));
    runtime.persist_entries_bincode(&transcript_path)?;
    let persisted_entries =
        crate::m1_runtime::M1RuntimeSession::load_entries_bincode(&transcript_path)?;
    crate::m1_runtime::M1RuntimeSession::verify_entries(&persisted_entries, &verifying_key)?;
    let _ = std::fs::remove_file(&transcript_path);

    let entries = runtime.entries();
    if entries != persisted_entries {
        return Err("M1 persisted transcript mismatch".into());
    }

    if let Some(dir) = evidence_dir {
        let paths = runtime.write_transcript_bound_evidence_bundle_for_profile(
            &verifying_key,
            dir,
            evidence_profile,
        )?;
        println!("evidence bundle: {}", paths.dir.display());
        println!("manifest: {}", paths.manifest.display());
        println!("ledger entries: {}", paths.ledger_entries.display());
        println!(
            "session transcript binding: {}",
            paths.session_transcript_binding.display()
        );
        println!(
            "verification report: {}",
            paths.verification_report.display()
        );
    }

    println!("M1 runtime smoke passed");
    println!("entries: {}", entries.len());

    for entry in entries {
        println!("{}", entry.event.stable_name());
    }

    Ok(())
}

#[cfg(test)]
mod audio_tests {
    use super::*;
    use xenia_capture::SilentAudioCapture;

    #[test]
    fn m1_scope_names_audio_off_and_telemetry_policy() {
        assert_eq!(
            m1_consent_scope(TelemetryLevel::Basic, AudioMode::Off),
            "display: screen stream; telemetry: basic host performance; audio: off"
        );
    }

    #[test]
    fn m1_scope_names_real_audio_capture_explicitly() {
        assert_eq!(
            m1_consent_scope(TelemetryLevel::System, AudioMode::Capture),
            "display: screen stream; telemetry: system identity and performance; audio: host device capture"
        );
    }

    #[test]
    fn audio_advertisement_names_selected_raw_codec() {
        let advert = audio_advertisement(AudioCodecChoice::RawPcm);

        assert_eq!(advert.selected_codec, AdvertisedAudioCodec::RawPcm);
        assert!(advert.codecs.contains(&AdvertisedAudioCodec::RawPcm));
        assert_eq!(
            advert.sample_rate_hz,
            xenia_peer_core::frame::RAW_AUDIO_SAMPLE_RATE_HZ
        );
        assert_eq!(
            advert.max_channels,
            xenia_peer_core::frame::RAW_AUDIO_MAX_CHANNELS
        );
        assert_eq!(advert.frame_duration_ms, vec![10, 20]);
    }

    #[test]
    fn captured_audio_frame_converts_to_valid_raw_audio() {
        let frame = AudioFrame {
            sample_rate_hz: 48_000,
            channels: 2,
            samples_i16: vec![0; 48_000 / 50 * 2],
            timestamp_ms: 1_700_000_000_000,
        };

        let raw = raw_audio_from_capture_frame(7, 3, 99, frame).unwrap();

        assert!(raw.validate());
        assert_eq!(raw.stream_id, 7);
        assert_eq!(raw.sequence, 3);
        assert_eq!(raw.capture_timestamp_ms, 1_700_000_000_000);
        assert_eq!(raw.frame_duration_ms, 20);
        assert_eq!(raw.flags & audio_flags::SYNTHETIC, 0);
    }

    #[test]
    fn captured_audio_uses_fallback_timestamp_when_backend_has_none() {
        let frame = AudioFrame {
            sample_rate_hz: 48_000,
            channels: 1,
            samples_i16: vec![0; 48_000 / 100],
            timestamp_ms: 0,
        };

        let raw = raw_audio_from_capture_frame(7, 3, 1_700_000_000_123, frame).unwrap();

        assert!(raw.validate());
        assert_eq!(raw.capture_timestamp_ms, 1_700_000_000_123);
        assert_eq!(raw.channels, 1);
        assert_eq!(raw.frame_duration_ms, 10);
    }

    #[test]
    fn captured_audio_rejects_unsupported_sample_rate() {
        let frame = AudioFrame {
            sample_rate_hz: 44_100,
            channels: 2,
            samples_i16: vec![0; 441 * 2],
            timestamp_ms: 1_700_000_000_000,
        };

        assert!(raw_audio_from_capture_frame(7, 3, 99, frame).is_err());
    }

    #[test]
    fn daemon_capture_source_advances_sequence() {
        let mut source = DaemonAudioSource::Capture {
            stream_id: 9,
            sequence: 0,
            capture: Box::new(SilentAudioCapture::new(48_000, 2, 960)),
        };

        let first = source.next_raw_audio(1_700_000_000_000).unwrap().unwrap();
        let second = source.next_raw_audio(1_700_000_000_020).unwrap().unwrap();

        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(first.flags & audio_flags::SYNTHETIC, 0);
        assert!(first.validate());
        assert!(second.validate());
    }
}
