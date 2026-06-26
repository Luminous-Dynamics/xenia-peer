use std::sync::Arc;
// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

/// `xenia-peer` — headless daemon that hosts a Xenia session.
use clap::{Parser, ValueEnum};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};
use uuid::Uuid;

use ed25519_dalek::SigningKey;
use xenia_capture::{
    FrameData as CaptureFrameData, ScreenCapture, SysinfoTelemetryStream, TelemetryStream,
    TestCapture,
};
use xenia_handshake::HandshakeManager;
use xenia_ledger::{Chain, LedgerEntry};
use xenia_peer_core::{
    Session, SessionRole,
    advertisement::TransportAdvertisement,
    frame::{
        PixelFormat as FramePixelFormat, RawFrame, RawTelemetry, SyntheticAudioKind,
        SyntheticAudioSource, TelemetrySample as WireTelemetrySample,
        TelemetryValue as WireTelemetryValue,
    },
    handshake::perform_host_handshake,
    transport::{TcpTransport, Transport},
};
use xenia_transport_quic::{QuicTransport, bind_xenia_endpoint, encode_endpoint_addr};
use xenia_transport_ws::WsTransport;
use xenia_video::{
    EncodeParams, Encoder, PixelFormat as VideoPixelFormat, passthrough::PassthroughEncoder,
};

#[cfg(feature = "scap")]
use xenia_capture::ScapCapture;

mod governance;
mod m1_ledger;
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

    #[arg(long, default_value_t = 20)]
    audio_interval_ms: u64,
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
                            let advert = TransportAdvertisement::auto(quic_connect).encode()
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

fn synthetic_audio_kind(mode: AudioMode) -> Option<SyntheticAudioKind> {
    match mode {
        AudioMode::Off => None,
        AudioMode::Sine => Some(SyntheticAudioKind::Sine),
        AudioMode::Noise => Some(SyntheticAudioKind::Noise),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let source_id = parse_source_id(&args.source_id_hex)?;

    info!(addr = %args.listen, "xenia-peer daemon listening");

    let key_path = std::path::Path::new("operator.key");
    let signing_key = if key_path.exists() {
        let key_bytes = std::fs::read(key_path)?;
        SigningKey::from_bytes(&key_bytes.try_into().map_err(|_| "Invalid key length")?)
    } else {
        let key = SigningKey::generate(&mut rand::thread_rng());
        std::fs::write(key_path, key.to_bytes())?;
        key
    };

    let mut telemetry = SysinfoTelemetryStream::new();
    let mut audio = synthetic_audio_kind(args.audio).map(|kind| SyntheticAudioSource::new(1, kind));

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

    let mut transport = accept_transport(&args).await?;

    let mut mgr = HandshakeManager::new();
    let session_key = perform_host_handshake(&mut transport, &mut mgr, "viewer").await?;
    info!("Handshake successful, session key established");

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

    let params = EncodeParams {
        width: args.width,
        height: args.height,
        pixel_format: VideoPixelFormat::Rgba,
        target_fps: args.fps.max(1),
        bitrate_kbps: 2_000,
    };
    let mut encoder = make_encoder(args.codec, params)?;
    let frame_format = codec_to_frame_format(args.codec);
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
            let frame_id = session.next_frame_id();
            let audio_frame = audio.next_frame(now_ms()).into_frame(frame_id)?;
            let envelope = session.seal_frame(&audio_frame)?;
            transport.send_envelope(&envelope).await?;
            sent_audio += 1;
            last_audio_sent = std::time::Instant::now();
            if sent_audio <= 3 || sent_audio.is_multiple_of(50) {
                info!(sent = sent_audio, frame_id, "audio frame sealed and sent");
            }
        }

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
