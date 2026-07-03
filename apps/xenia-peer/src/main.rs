// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

/// `xenia-peer` — headless daemon that hosts a Xenia session.
use clap::{Parser, ValueEnum};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};
use uuid::Uuid;

use xenia_inject::{InputInjector, LoggingInjector, NoopInjector};

use ed25519_dalek::SigningKey;
#[cfg(any(feature = "audio-capture", test))]
use xenia_capture::{AudioCapture, AudioFrame};
use xenia_capture::{
    FrameData as CaptureFrameData, ScreenCapture, SysinfoTelemetryStream, TelemetryStream,
    TestCapture,
};
use xenia_handshake::{HandshakeManager, derive_negotiated_context_key};
use xenia_ledger::{Chain, Ed25519EvidenceSignatureBackend, LedgerEntry};
#[cfg(feature = "pqc-signatures")]
use xenia_ledger::{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend};
#[cfg(feature = "audio-opus")]
use xenia_peer_core::OpusAudioCodec;
#[cfg(any(feature = "audio-capture", test))]
use xenia_peer_core::frame::audio_flags;
use xenia_peer_core::{
    AudioCodec, LaneSession, RawPcmAudioCodec, RekeyPolicy, SessionEpochState,
    advertisement::{AdvertisedAudioCodec, AudioAdvertisement, TransportAdvertisement},
    frame::{
        LANE_ENVELOPE_MAGIC, PixelFormat as FramePixelFormat, RawAudio, RawFrame, RawRekey,
        RawTelemetry, SyntheticAudioKind, SyntheticAudioSource,
        TelemetrySample as WireTelemetrySample, TelemetryValue as WireTelemetryValue,
    },
    handshake::{
        NegotiatedTransport, negotiated_session_context_hash,
        perform_host_handshake_with_transcript_and_context,
    },
    transport::{RecvEnvelope, SendEnvelope, TcpRecvHalf, TcpSendHalf, TcpTransport, Transport},
};
use xenia_transport_quic::{
    QuicRecvHalf, QuicSendHalf, QuicTransport, bind_xenia_endpoint, encode_endpoint_addr,
};
use xenia_transport_ws::{WsRecvHalf, WsSendHalf, WsTransport};
use xenia_video::{
    EncodeParams, Encoder, PixelFormat as VideoPixelFormat, passthrough::PassthroughEncoder,
};

#[cfg(feature = "audio-capture")]
use xenia_capture::CpalAudioCapture;
#[cfg(feature = "scap")]
use xenia_capture::ScapCapture;

mod admin_ui;
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

    /// Seconds to wait for an Approve/Deny decision on --consent-port before
    /// giving up and exiting. Ignored when --m1-preprod-auto-consent is set.
    #[arg(long, default_value_t = 120)]
    consent_timeout_secs: u64,

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

    /// Rekey after this many video frames in the current epoch. 0 disables
    /// frame-count rekeying.
    #[arg(long, default_value_t = 4)]
    rekey_frames: u64,

    /// Rekey after this many sealed bytes in the current epoch. 0 disables
    /// byte-count rekeying.
    #[arg(long, default_value_t = 0)]
    rekey_bytes: u64,

    /// Disable automatic post-handshake rekeys after the initial epoch-1 rekey.
    #[arg(long)]
    rekey_disabled: bool,

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

    /// Hex-encoded evidence verifier public key for `--verify-evidence-bundle`.
    /// Ed25519 keys are 32 bytes; ML-DSA key lengths depend on the selected suite.
    #[arg(long, requires = "verify_evidence_bundle")]
    evidence_public_key_hex: Option<String>,

    /// Signature suite/backend to use when verifying an evidence bundle.
    #[arg(
        long,
        value_enum,
        default_value_t = EvidenceVerifierSuite::Ed25519Rfc8032,
        requires = "verify_evidence_bundle"
    )]
    evidence_signature_suite: EvidenceVerifierSuite,

    /// Refuse verification unless the evidence manifest declares this profile.
    /// Use this when an operator intends to require `full-pqc-v1` and must not
    /// accidentally accept a weaker hybrid evidence bundle.
    #[arg(long, value_enum, requires = "verify_evidence_bundle")]
    require_evidence_profile: Option<EvidenceProfileRequirement>,

    /// Verify a seven-file sealed full-PQC evidence bundle and exit.
    /// Requires explicit trusted key fingerprints; public-key binding files are
    /// not treated as self-authenticating identity claims.
    #[arg(long, value_name = "DIR")]
    verify_sealed_evidence_bundle: Option<std::path::PathBuf>,

    /// Trusted BLAKE3 fingerprint for the transcript verifier key.
    #[arg(long, requires = "verify_sealed_evidence_bundle")]
    trusted_transcript_key_fingerprint_hex: Option<String>,

    /// Trusted BLAKE3 fingerprint for the ledger verifier key.
    #[arg(long, requires = "verify_sealed_evidence_bundle")]
    trusted_ledger_key_fingerprint_hex: Option<String>,

    /// Signature suite/backend to use when verifying a sealed full-PQC bundle.
    #[arg(
        long,
        value_enum,
        default_value_t = EvidenceVerifierSuite::MlDsa65Fips204,
        requires = "verify_sealed_evidence_bundle"
    )]
    sealed_evidence_signature_suite: EvidenceVerifierSuite,

    /// Read trusted sealed full-PQC key fingerprints from an enrolled policy file.
    /// This is preferred for CI/operator workflows because it avoids copying
    /// fingerprints by hand. Do not combine with the manual trusted fingerprint flags.
    #[arg(
        long,
        value_name = "FILE",
        requires = "verify_sealed_evidence_bundle",
        conflicts_with_all = [
            "trusted_transcript_key_fingerprint_hex",
            "trusted_ledger_key_fingerprint_hex"
        ]
    )]
    sealed_evidence_trust_policy: Option<std::path::PathBuf>,

    /// Detached signature authenticating `--sealed-evidence-trust-policy` under
    /// an enrolled local policy-root key.
    #[arg(long, value_name = "FILE", requires = "sealed_evidence_trust_policy")]
    sealed_evidence_trust_policy_signature: Option<std::path::PathBuf>,

    /// Trusted BLAKE3 fingerprint for the policy-root key that signs the sealed
    /// evidence trust policy. Use either this manual root fingerprint or
    /// `--sealed-evidence-policy-roots`, not both.
    #[arg(
        long,
        requires = "sealed_evidence_trust_policy_signature",
        conflicts_with = "sealed_evidence_policy_roots"
    )]
    trusted_sealed_evidence_policy_root_fingerprint_hex: Option<String>,

    /// Enrolled policy-root registry used to authorize the root that signed the
    /// sealed evidence trust policy. This avoids manually pasting the trusted
    /// root fingerprint during CI/operator verification.
    #[arg(
        long,
        value_name = "FILE",
        requires = "sealed_evidence_trust_policy_signature",
        conflicts_with = "trusted_sealed_evidence_policy_root_fingerprint_hex"
    )]
    sealed_evidence_policy_roots: Option<std::path::PathBuf>,

    /// Require the signed policy to be authorized by this enrolled policy-root id.
    #[arg(long, value_name = "ID", requires = "sealed_evidence_policy_roots")]
    required_sealed_evidence_policy_root_id: Option<String>,

    /// Refuse an unsigned sealed evidence trust policy.
    #[arg(long, requires = "sealed_evidence_trust_policy")]
    require_signed_sealed_evidence_trust_policy: bool,

    /// Refuse a sealed trust policy whose policy_epoch is missing or below this value (`--minimum-sealed-evidence-policy-epoch`).
    #[arg(
        long = "minimum-sealed-evidence-policy-epoch",
        requires = "sealed_evidence_trust_policy"
    )]
    minimum_sealed_evidence_policy_epoch: Option<u64>,

    /// Write a sealed full-PQC verification_report.json after successful verification.
    /// Use `--write-sealed-evidence-report` only when the operator wants an
    /// archival audit handle. This report is an audit aid only; trust is still recomputed from the seven
    /// sealed artifacts and operator-supplied fingerprints.
    #[arg(
        long = "write-sealed-evidence-report",
        requires = "verify_sealed_evidence_bundle"
    )]
    write_sealed_evidence_report: bool,

    /// Audit a stored verification_report.json against the current bundle artifact bytes.
    /// Use as `--audit-evidence-report DIR`. This recomputes artifact digests only;
    /// use --verify-evidence-bundle for signature verification.
    #[arg(long, value_name = "DIR")]
    audit_evidence_report: Option<std::path::PathBuf>,

    /// Audit a stored sealed full-PQC verification_report.json against the current
    /// seven-file sealed bundle artifact bytes with `--audit-sealed-evidence-report`.
    /// This recomputes digests only; use
    /// --verify-sealed-evidence-bundle for signature and trust-anchor verification.
    #[arg(long = "audit-sealed-evidence-report", value_name = "DIR")]
    audit_sealed_evidence_report: Option<std::path::PathBuf>,

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

    /// Inbound viewer-input backend. `noop` (default) discards every
    /// input event -- a connected viewer is view-only and no OS-level
    /// injector is ever constructed, so no consent dialog appears.
    /// `log` records denormalized events for verification (no host
    /// permissions needed). `xdg-portal` actually moves the mouse /
    /// types keys via the RemoteDesktop portal (requires the
    /// `xdg-portal` build feature and triggers its own interactive
    /// consent dialog on first real input event).
    #[arg(long, value_enum, default_value_t = InputBackendChoice::Noop)]
    input_backend: InputBackendChoice,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CodecChoice {
    Passthrough,
    H264,
    Hdc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum InputBackendChoice {
    Noop,
    Log,
    #[cfg(feature = "xdg-portal")]
    XdgPortal,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum EvidenceVerifierSuite {
    Ed25519Rfc8032,
    MlDsa65Fips204,
    MlDsa87Fips204,
}

impl EvidenceVerifierSuite {
    const fn stable_label(self) -> &'static str {
        match self {
            Self::Ed25519Rfc8032 => "ed25519-rfc8032",
            Self::MlDsa65Fips204 => "ml-dsa-65-fips204",
            Self::MlDsa87Fips204 => "ml-dsa-87-fips204",
        }
    }

    const fn is_post_quantum(self) -> bool {
        !matches!(self, Self::Ed25519Rfc8032)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum EvidenceProfileRequirement {
    HybridPrePqcV1,
    FullPqcV1,
}

impl EvidenceProfileRequirement {
    const fn stable_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "hybrid-pre-pqc-v1",
            Self::FullPqcV1 => "full-pqc-v1",
        }
    }

    const fn expected_downgrade_policy_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "explicit-classical-signature-allowance",
            Self::FullPqcV1 => "reject-classical-signatures",
        }
    }
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
    fn negotiated_transport(&self) -> NegotiatedTransport {
        match self {
            AnyTransport::Tcp(_) => NegotiatedTransport::Tcp,
            AnyTransport::Ws(_) => NegotiatedTransport::WebSocket,
            AnyTransport::Quic { .. } => NegotiatedTransport::Quic,
        }
    }

    /// Split into independently-owned send/recv halves so a dedicated
    /// task can run an inbound `RawInput` receive loop concurrently
    /// with the outbound video/audio/telemetry send loop. See
    /// [`Transport`]'s doc comment for why splitting exists.
    fn split(self) -> (AnySendHalf, AnyRecvHalf) {
        match self {
            AnyTransport::Tcp(t) => {
                let (send, recv) = t.split();
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
                (AnySendHalf::Quic { _endpoint, send }, AnyRecvHalf::Quic(recv))
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
    async fn send_envelope(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), xenia_peer_core::transport::TransportError> {
        match self {
            AnySendHalf::Tcp(t) => t.send_envelope(bytes).await,
            AnySendHalf::Ws(t) => t.send_envelope(bytes).await,
            AnySendHalf::Quic { send, .. } => send.send_envelope(bytes).await,
        }
    }
}

impl AnySendHalf {
    /// Mirrors `AnyTransport::close` for the post-split send half —
    /// only the QUIC variant needs an explicit teardown sequence.
    async fn close(&mut self) -> Result<(), xenia_peer_core::transport::TransportError> {
        if let AnySendHalf::Quic { _endpoint, send } = self {
            let finish_result = send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(3), send.closed()).await;
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
    async fn recv_envelope(
        &mut self,
    ) -> Result<Vec<u8>, xenia_peer_core::transport::TransportError> {
        match self {
            AnyRecvHalf::Tcp(t) => t.recv_envelope().await,
            AnyRecvHalf::Ws(t) => t.recv_envelope().await,
            AnyRecvHalf::Quic(t) => t.recv_envelope().await,
        }
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
    input_backend: InputBackendChoice,
) -> Result<RawFrame, Box<dyn std::error::Error>> {
    xenia_peer_core::RawCapabilities {
        frame_id,
        timestamp_ms: now_ms(),
        audio: Some(audio),
        video_format,
        telemetry_enabled: telemetry_level != TelemetryLevel::Off,
        input_control_enabled: input_backend != InputBackendChoice::Noop,
        lane_envelope_version: xenia_peer_core::frame::LANE_ENVELOPE_SCHEMA_VERSION,
        lane_envelope_magic: xenia_peer_core::frame::LANE_ENVELOPE_MAGIC,
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

async fn perform_rekey(
    transport: &mut AnyTransport,
    session: &mut LaneSession,
    epoch_state: &mut SessionEpochState,
    schedule: &xenia_handshake::SessionKeySchedule,
    context: xenia_handshake::RekeyEpochContextV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let epoch_hash = context.epoch_hash()?;
    let proposal = RawRekey::Proposal {
        key_epoch: context.key_epoch,
        base_transcript_hash: context.base_transcript_hash,
        previous_epoch_hash: context.previous_epoch_hash,
        reason: context.reason,
        epoch_hash,
    }
    .into_frame(session.next_frame_id(), now_ms())?;
    let envelope = session.seal_control_frame(&proposal)?;
    transport.send_envelope(&envelope).await?;

    let frames_before_rekey = epoch_state.frames_in_epoch();
    let bytes_before_rekey = epoch_state.bytes_in_epoch();
    let audio_frames_before_rekey = epoch_state.audio_frames_in_epoch();
    let keys = epoch_state.derive_and_install(schedule, &context)?;
    session.install_rekey_keys(&keys);

    let ack_envelope = transport.recv_envelope().await?;
    let ack_frame = session.open_frame(&ack_envelope)?;
    match RawRekey::from_frame(&ack_frame)? {
        RawRekey::Ack {
            key_epoch,
            epoch_hash: ack_epoch_hash,
        } if key_epoch == epoch_state.current_epoch() && ack_epoch_hash == epoch_hash => {
            info!(
                key_epoch,
                reason = ?context.reason,
                frames_before_rekey,
                bytes_before_rekey,
                audio_frames_before_rekey,
                epoch_hash = ?epoch_hash,
                "session rekey acknowledged"
            );
            Ok(())
        }
        other => Err(format!("unexpected rekey ack: {other:?}").into()),
    }
}

/// Mirrors [`perform_rekey`] for use after the transport has been
/// split (`AnyTransport::split`): sends the proposal on the send half
/// and waits for the ack on `rekey_ack_rx` instead of a direct
/// `recv_envelope` -- once split, only the dedicated recv task may
/// call `recv_envelope`, so the ack has to reach this function via the
/// channel that task feeds. `session` is behind an async mutex because
/// the recv task also opens control-lane envelopes (input events)
/// concurrently with this function installing new rekey-epoch keys.
async fn perform_rekey_split(
    send_half: &mut AnySendHalf,
    session: &AsyncMutex<LaneSession>,
    rekey_ack_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    epoch_state: &mut SessionEpochState,
    schedule: &xenia_handshake::SessionKeySchedule,
    context: xenia_handshake::RekeyEpochContextV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let epoch_hash = context.epoch_hash()?;
    let proposal = RawRekey::Proposal {
        key_epoch: context.key_epoch,
        base_transcript_hash: context.base_transcript_hash,
        previous_epoch_hash: context.previous_epoch_hash,
        reason: context.reason,
        epoch_hash,
    }
    .into_frame(session.lock().await.next_frame_id(), now_ms())?;
    let envelope = session.lock().await.seal_control_frame(&proposal)?;
    send_half.send_envelope(&envelope).await?;

    let frames_before_rekey = epoch_state.frames_in_epoch();
    let bytes_before_rekey = epoch_state.bytes_in_epoch();
    let audio_frames_before_rekey = epoch_state.audio_frames_in_epoch();
    let keys = epoch_state.derive_and_install(schedule, &context)?;
    session.lock().await.install_rekey_keys(&keys);

    let ack_envelope = rekey_ack_rx
        .recv()
        .await
        .ok_or("rekey ack channel closed before an ack arrived (recv task ended)")?;
    let ack_frame = session.lock().await.open_frame(&ack_envelope)?;
    match RawRekey::from_frame(&ack_frame)? {
        RawRekey::Ack {
            key_epoch,
            epoch_hash: ack_epoch_hash,
        } if key_epoch == epoch_state.current_epoch() && ack_epoch_hash == epoch_hash => {
            info!(
                key_epoch,
                reason = ?context.reason,
                frames_before_rekey,
                bytes_before_rekey,
                audio_frames_before_rekey,
                epoch_hash = ?epoch_hash,
                "session rekey acknowledged"
            );
            Ok(())
        }
        other => Err(format!("unexpected rekey ack: {other:?}").into()),
    }
}

/// Construct the input-injection backend selected by `--input-backend`.
/// Called lazily on the first real inbound `InputEvent` (see the recv
/// task in `main`), not eagerly at startup, so a view-only session
/// never triggers `XdgPortalInjector`'s consent dialog.
fn build_input_injector(
    choice: InputBackendChoice,
    screen_width: u32,
    screen_height: u32,
) -> Box<dyn InputInjector> {
    match choice {
        InputBackendChoice::Noop => Box::new(NoopInjector),
        InputBackendChoice::Log => Box::new(LoggingInjector::new(screen_width, screen_height)),
        #[cfg(feature = "xdg-portal")]
        InputBackendChoice::XdgPortal => {
            match xenia_inject::XdgPortalInjector::new(
                screen_width,
                screen_height,
                Duration::from_secs(60),
            ) {
                Ok(injector) => Box::new(injector),
                Err(err) => {
                    warn!(
                        error = %err,
                        "XdgPortalInjector construction failed; input events will be discarded"
                    );
                    Box::new(NoopInjector)
                }
            }
        }
    }
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
        let public_key = parse_evidence_public_key_hex(public_key_hex)?;
        let report = verify_evidence_bundle_with_selected_suite(
            bundle_dir,
            &public_key,
            args.evidence_signature_suite,
            args.require_evidence_profile,
        )?;
        println!("evidence bundle verified");
        println!("profile: {}", report.profile);
        println!("ledger signature: {}", report.ledger_signature);
        println!("entries: {}", report.ledger_entries);
        println!("session: {}", report.session_id);
        println!(
            "artifact set blake3: {}",
            report.artifacts.artifact_set_blake3
        );
        return Ok(());
    }

    if let Some(bundle_dir) = args.verify_sealed_evidence_bundle.as_deref() {
        let trust = resolve_sealed_evidence_trust_anchors(
            args.sealed_evidence_trust_policy.as_deref(),
            args.sealed_evidence_trust_policy_signature.as_deref(),
            args.trusted_sealed_evidence_policy_root_fingerprint_hex
                .as_deref(),
            args.sealed_evidence_policy_roots.as_deref(),
            args.required_sealed_evidence_policy_root_id.as_deref(),
            args.trusted_transcript_key_fingerprint_hex.as_deref(),
            args.trusted_ledger_key_fingerprint_hex.as_deref(),
            args.sealed_evidence_signature_suite,
            args.minimum_sealed_evidence_policy_epoch,
            args.require_signed_sealed_evidence_trust_policy,
        )?;

        let mut report = verify_sealed_evidence_bundle_with_selected_suite(
            bundle_dir,
            trust.trusted_transcript_key_fingerprint,
            trust.trusted_ledger_key_fingerprint,
            args.sealed_evidence_signature_suite,
        )?;
        report.trust_policy = trust.trust_policy;
        println!("sealed evidence bundle verified");
        println!("profile: {}", report.profile);
        println!("transcript signature: {}", report.transcript_signature);
        println!("ledger signature: {}", report.ledger_signature);
        println!("entries: {}", report.ledger_entries);
        println!("session: {}", report.session_id);
        println!(
            "transcript key fingerprint: {}",
            report.transcript_public_key_fingerprint_hex
        );
        println!(
            "ledger key fingerprint: {}",
            report.ledger_public_key_fingerprint_hex
        );
        println!(
            "sealed artifact set blake3: {}",
            report.artifacts.artifact_set_blake3
        );
        if let Some(trust_policy) = &report.trust_policy {
            println!("trust policy source: {}", trust_policy.source);
            if let Some(policy_id) = trust_policy.policy_id.as_deref() {
                println!("trust policy id: {policy_id}");
            }
            if let Some(policy_blake3) = trust_policy.policy_blake3.as_deref() {
                println!("trust policy blake3: {policy_blake3}");
            }
            if let Some(policy_root_id) = trust_policy.policy_root_id.as_deref() {
                println!("policy root id: {policy_root_id}");
            }
            if let Some(policy_roots_blake3) = trust_policy.policy_roots_blake3.as_deref() {
                println!("policy roots blake3: {policy_roots_blake3}");
            }
        }
        if args.write_sealed_evidence_report {
            let report_path = crate::m1_runtime::write_sealed_evidence_verification_report_dir(
                bundle_dir, &report,
            )?;
            println!("sealed verification report: {}", report_path.display());
        }
        return Ok(());
    }

    if let Some(bundle_dir) = args.audit_evidence_report.as_deref() {
        let report =
            crate::m1_runtime::audit_evidence_verification_report_artifacts_dir(bundle_dir)?;
        println!("evidence verification report artifact audit passed");
        println!("profile: {}", report.profile);
        println!("ledger signature: {}", report.ledger_signature);
        println!("entries: {}", report.ledger_entries);
        println!("session: {}", report.session_id);
        println!(
            "artifact set blake3: {}",
            report.artifacts.artifact_set_blake3
        );
        return Ok(());
    }

    if let Some(bundle_dir) = args.audit_sealed_evidence_report.as_deref() {
        let report =
            crate::m1_runtime::audit_sealed_evidence_verification_report_artifacts_dir(bundle_dir)?;
        println!("sealed evidence verification report artifact audit passed");
        println!("profile: {}", report.profile);
        println!("transcript signature: {}", report.transcript_signature);
        println!("ledger signature: {}", report.ledger_signature);
        println!("entries: {}", report.ledger_entries);
        println!("session: {}", report.session_id);
        println!(
            "sealed artifact set blake3: {}",
            report.artifacts.artifact_set_blake3
        );
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

    let app = crate::admin_ui::mount(Router::new()).route(
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
    let negotiated_transport = transport.negotiated_transport();
    let mut session = LaneSession::with_fixture(source_id, args.epoch);
    let frame_format = codec_to_frame_format(args.codec);
    let capabilities = session_capabilities_frame(
        session.next_frame_id(),
        audio_advertisement.clone(),
        frame_format,
        args.telemetry_level,
        args.input_backend,
    )?;
    let negotiated_context_hash = negotiated_session_context_hash(
        negotiated_transport,
        xenia_peer_core::RawCapabilities::from_frame(&capabilities)?,
    )?;

    let mut mgr = HandshakeManager::new();
    let handshake = perform_host_handshake_with_transcript_and_context(
        &mut transport,
        &mut mgr,
        "viewer",
        Some(negotiated_context_hash),
    )
    .await?;
    info!("Handshake successful, session key established and transcript hash computed");

    // Consent Ceremony: the real decision arrives over --consent-port as a
    // plain "Approve" / "Deny" text message — the same convention already
    // spoken by apps/sovereign-admin's ConsentModal (a browser-based
    // operator console). The request itself is broadcast on --admin-port
    // (below, once m1_runtime.offer() succeeds) so a connected ConsentModal
    // has something real to show instead of an empty prompt.
    info!("Waiting for consent request...");

    let (consent_decision_tx, consent_decision_rx) = tokio::sync::oneshot::channel::<bool>();
    let mut consent_decision_tx = Some(consent_decision_tx);

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
                                    let decision = match text {
                                        "Approve" => Some(true),
                                        "Deny" => Some(false),
                                        other => {
                                            info!(
                                                text = other,
                                                "ignoring unrecognized consent message"
                                            );
                                            None
                                        }
                                    };
                                    if let Some(decision) = decision {
                                        info!(approved = decision, "consent decision received");
                                        if let Some(tx) = consent_decision_tx.take() {
                                            let _ = tx.send(decision);
                                        }
                                        break;
                                    }
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

    session.install_schedule(&handshake.key_schedule);
    let _negotiated_context_key =
        derive_negotiated_context_key(&handshake.key_schedule, &negotiated_context_hash);
    info!(
        transport = ?negotiated_transport,
        context_hash = ?negotiated_context_hash,
        "negotiated session context bound"
    );
    let envelope = session.seal_control_frame(&capabilities)?;
    transport.send_envelope(&envelope).await?;
    info!("sealed session capabilities sent");

    let rekey_policy = if args.rekey_disabled {
        RekeyPolicy::from_limits(0, 0)
    } else {
        RekeyPolicy::from_limits(args.rekey_frames, args.rekey_bytes)
    };
    let mut epoch_state = SessionEpochState::new(handshake.transcript_hash, rekey_policy);
    let initial_rekey = epoch_state.next_rekey_context(xenia_peer_core::RekeyReason::FrameCount);
    perform_rekey(
        &mut transport,
        &mut session,
        &mut epoch_state,
        &handshake.key_schedule,
        initial_rekey,
    )
    .await?;

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
        bridge.broadcast(&m1_scope_for_log);
        info!(
            consent_port = args.consent_port,
            timeout_secs = args.consent_timeout_secs,
            "consent request broadcast; waiting for Approve/Deny on --consent-port"
        );
        let timeout = Duration::from_secs(args.consent_timeout_secs.max(1));
        match tokio::time::timeout(timeout, consent_decision_rx).await {
            Ok(Ok(true)) => {
                m1_runtime.grant_consent()?;
                info!("M1 consent granted; frame flow unlocked");
            }
            Ok(Ok(false)) => {
                m1_runtime.deny_consent()?;
                warn!("M1 consent denied; exiting");
                return Ok(());
            }
            Ok(Err(_)) => {
                warn!("consent channel closed before a decision arrived; exiting");
                return Ok(());
            }
            Err(_) => {
                warn!(
                    timeout_secs = args.consent_timeout_secs,
                    "M1 consent timed out waiting for a decision; exiting"
                );
                return Ok(());
            }
        }
    }

    // Split the transport so a dedicated task can drain inbound
    // envelopes (viewer input events + rekey acks) concurrently with
    // the outbound video/audio/telemetry send loop below. `session`
    // and `m1_runtime` move behind async mutexes because both this
    // loop and the recv task need to seal/open lane traffic and gate
    // input through the M1 consent state.
    let (mut send_half, recv_half) = transport.split();
    let session = Arc::new(AsyncMutex::new(session));
    let m1_runtime = Arc::new(AsyncMutex::new(m1_runtime));
    let (rekey_ack_tx, mut rekey_ack_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    // Updated by the send loop below whenever the encoder is (re)built
    // from a real captured frame, so a lazily-constructed input
    // injector denormalizes coordinates against the actual screen
    // size rather than the --width/--height CLI defaults.
    let screen_dims = Arc::new((AtomicU32::new(args.width), AtomicU32::new(args.height)));

    {
        let session = Arc::clone(&session);
        let m1_runtime = Arc::clone(&m1_runtime);
        let screen_dims = Arc::clone(&screen_dims);
        let input_backend = args.input_backend;
        tokio::spawn(async move {
            let mut recv_half = recv_half;
            // Constructed lazily on the first real InputEvent, not at
            // task start -- a view-only session (`--input-backend
            // noop`, the default) never triggers `XdgPortalInjector`'s
            // consent dialog because it's simply never built.
            let mut injector: Option<Box<dyn InputInjector>> = None;
            loop {
                let envelope = match recv_half.recv_envelope().await {
                    Ok(envelope) => envelope,
                    Err(err) => {
                        info!(error = %err, "input/rekey-ack receive loop ending");
                        break;
                    }
                };

                if envelope.len() >= LANE_ENVELOPE_MAGIC.len()
                    && envelope[..LANE_ENVELOPE_MAGIC.len()] == LANE_ENVELOPE_MAGIC
                {
                    // Lane-enveloped control frame. The only thing a
                    // viewer sends this direction on the control lane
                    // today is a RawRekey::Ack -- forward the raw
                    // envelope to perform_rekey_split, which owns
                    // opening + validating it. Drop silently if nobody
                    // is currently waiting on one.
                    let _ = rekey_ack_tx.send(envelope).await;
                    continue;
                }

                // Bare (non-lane-wrapped) envelope: a viewer-captured
                // input event sealed directly under the control lane's
                // key (see `LaneSession::seal_input_event`).
                let input = {
                    let mut session = session.lock().await;
                    match session.open_input(&envelope) {
                        Ok(input) => input,
                        Err(err) => {
                            warn!(error = %err, "failed to open inbound input envelope");
                            continue;
                        }
                    }
                };
                let event: xenia_inject::InputEvent = match bincode::deserialize(&input.payload) {
                    Ok(event) => event,
                    Err(err) => {
                        warn!(error = %err, "failed to decode InputEvent payload");
                        continue;
                    }
                };
                {
                    let mut m1_runtime = m1_runtime.lock().await;
                    if let Err(err) = m1_runtime.allow_input_flow() {
                        warn!(error = %err, "input event rejected by M1 consent gate");
                        continue;
                    }
                }

                let width = screen_dims.0.load(Ordering::Relaxed);
                let height = screen_dims.1.load(Ordering::Relaxed);
                let injector = injector
                    .get_or_insert_with(|| build_input_injector(input_backend, width, height));
                match injector.process_events(std::slice::from_ref(&event)) {
                    Ok(()) => {
                        info!(?event, backend = injector.backend_name(), "input event injected");
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            backend = injector.backend_name(),
                            "input injection failed"
                        );
                    }
                }
            }
        });
    }

    // The encoder is built lazily from the first captured frame's real
    // dimensions rather than --width/--height. TestCapture/BlankCapture
    // frames already match those CLI defaults, so this is a no-op for the
    // synthetic path; a real backend like ScapCapture doesn't know its
    // output size until the first frame arrives (see
    // xenia-capture::ScapCapture's width()/height() doc comments), and its
    // native resolution essentially never matches the 320x200 CLI default.
    let mut effective_width = args.width;
    let mut effective_height = args.height;
    let mut encoder: Option<Box<dyn Encoder>> = None;
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
            m1_runtime.lock().await.preflight_frame_flow()?;
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
                    let frame_id = session.lock().await.next_frame_id();
                    let telemetry_frame = RawTelemetry {
                        frame_id,
                        timestamp_ms: now_ms(),
                        backend: telemetry.backend_name().to_string(),
                        samples: samples.into_iter().map(telemetry_sample_to_wire).collect(),
                    }
                    .into_frame()?;
                    let envelope = session.lock().await.seal_frame(&telemetry_frame)?;
                    m1_runtime.lock().await.allow_frame_flow()?;
                    send_half.send_envelope(&envelope).await?;
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
            m1_runtime.lock().await.preflight_frame_flow()?;
            if let Some(raw_audio) = audio.next_raw_audio(now_ms())? {
                let raw_audio = audio_codec.encode(raw_audio)?;
                let frame_id = session.lock().await.next_frame_id();
                let audio_frame = raw_audio.into_frame(frame_id)?;
                let envelope = session.lock().await.seal_frame(&audio_frame)?;
                m1_runtime.lock().await.allow_frame_flow()?;
                send_half.send_envelope(&envelope).await?;
                epoch_state.record_audio_frame(envelope.len());
                sent_audio += 1;
                last_audio_sent = std::time::Instant::now();
                if sent_audio <= 3 || sent_audio.is_multiple_of(50) {
                    info!(sent = sent_audio, frame_id, "audio frame sealed and sent");
                }
            }
        }

        m1_runtime.lock().await.preflight_frame_flow()?;
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
        if encoder.is_none() || frame.width != effective_width || frame.height != effective_height {
            if encoder.is_some() {
                info!(
                    old_width = effective_width,
                    old_height = effective_height,
                    new_width = frame.width,
                    new_height = frame.height,
                    "capture dimensions changed; rebuilding encoder"
                );
            }
            effective_width = frame.width;
            effective_height = frame.height;
            screen_dims.0.store(effective_width, Ordering::Relaxed);
            screen_dims.1.store(effective_height, Ordering::Relaxed);
            let params = EncodeParams {
                width: effective_width,
                height: effective_height,
                pixel_format: VideoPixelFormat::Rgba,
                target_fps: args.fps.max(1),
                bitrate_kbps: 2_000,
            };
            encoder = Some(make_encoder(args.codec, params)?);
        }
        let encoder = encoder.as_mut().expect("encoder built above");

        let captured_at = now_ms();
        let packets = encoder.encode(&pixels, captured_at)?;
        for packet in packets {
            let frame_id = session.lock().await.next_frame_id();
            let raw = RawFrame::encoded(
                frame_id,
                packet.pts_ms,
                effective_width,
                effective_height,
                frame_format,
                packet.bytes,
            );
            let envelope = session.lock().await.seal_frame(&raw)?;
            m1_runtime.lock().await.allow_frame_flow()?;
            send_half.send_envelope(&envelope).await?;
            epoch_state.record_video_frame(envelope.len());
            sent_frames += 1;
            if sent_frames <= 3 || sent_frames.is_multiple_of(10) {
                info!(
                    sent = sent_frames,
                    frame_id, "frame encoded, sealed, and sent"
                );
            }
            if let Some(rekey_context) = epoch_state.next_rekey_due() {
                perform_rekey_split(
                    &mut send_half,
                    &session,
                    &mut rekey_ack_rx,
                    &mut epoch_state,
                    &handshake.key_schedule,
                    rekey_context,
                )
                .await?;
            }
            if args.frames != 0 && sent_frames >= args.frames {
                break;
            }
        }
    }

    send_half.close().await?;
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

fn parse_evidence_public_key_hex(hex_text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_text)?;
    if bytes.is_empty() {
        return Err("evidence public key must not be empty".into());
    }
    Ok(bytes)
}

fn parse_evidence_key_fingerprint_hex(
    hex_text: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_text)?;
    let found = bytes.len();
    let fingerprint: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("evidence key fingerprint must be exactly 32 bytes, found {found}"))?;
    Ok(fingerprint)
}

struct ResolvedSealedEvidenceTrust {
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
    trust_policy: Option<crate::m1_runtime::SealedEvidenceTrustPolicyReceipt>,
}

fn resolve_sealed_evidence_trust_anchors(
    trust_policy_path: Option<&std::path::Path>,
    trust_policy_signature_path: Option<&std::path::Path>,
    trusted_policy_root_fingerprint_hex: Option<&str>,
    policy_roots_path: Option<&std::path::Path>,
    required_policy_root_id: Option<&str>,
    trusted_transcript_key_fingerprint_hex: Option<&str>,
    trusted_ledger_key_fingerprint_hex: Option<&str>,
    suite: EvidenceVerifierSuite,
    minimum_policy_epoch: Option<u64>,
    require_signed_policy: bool,
) -> Result<ResolvedSealedEvidenceTrust, Box<dyn std::error::Error>> {
    if let Some(path) = trust_policy_path {
        let policy = crate::m1_runtime::read_sealed_evidence_trust_policy_file(path)?;
        if let Some(minimum_policy_epoch) = minimum_policy_epoch {
            crate::m1_runtime::require_sealed_evidence_trust_policy_minimum_epoch(
                &policy,
                minimum_policy_epoch,
            )?;
        }
        let trust_anchors =
            crate::m1_runtime::sealed_evidence_trust_policy_anchors(&policy, suite.stable_label())?;
        let mut trust_policy = crate::m1_runtime::sealed_evidence_trust_policy_receipt_file(
            path,
            &policy,
            suite.stable_label(),
        )?;
        if let Some(signature_path) = trust_policy_signature_path {
            let (trusted_policy_root_fingerprint, root_receipt) = if let Some(roots_path) =
                policy_roots_path
            {
                if trusted_policy_root_fingerprint_hex.is_some() {
                    return Err("use either --sealed-evidence-policy-roots or --trusted-sealed-evidence-policy-root-fingerprint-hex, not both".into());
                }
                let root_receipt =
                    crate::m1_runtime::sealed_evidence_policy_root_receipt_file_for_signature(
                        roots_path,
                        signature_path,
                        suite.stable_label(),
                        required_policy_root_id,
                    )?;
                let trusted_policy_root_fingerprint = parse_evidence_key_fingerprint_hex(
                    &root_receipt.policy_root_key_fingerprint_hex,
                )?;
                (trusted_policy_root_fingerprint, Some(root_receipt))
            } else {
                if required_policy_root_id.is_some() {
                    return Err("--required-sealed-evidence-policy-root-id requires --sealed-evidence-policy-roots".into());
                }
                let root_fingerprint_hex = trusted_policy_root_fingerprint_hex.ok_or(
                        "--sealed-evidence-trust-policy-signature requires either --sealed-evidence-policy-roots or --trusted-sealed-evidence-policy-root-fingerprint-hex",
                    )?;
                (
                    parse_evidence_key_fingerprint_hex(root_fingerprint_hex)?,
                    None,
                )
            };

            let signature_receipt =
                verify_sealed_evidence_trust_policy_signature_with_selected_suite(
                    path,
                    signature_path,
                    suite,
                    trusted_policy_root_fingerprint,
                )?;
            crate::m1_runtime::attach_sealed_evidence_trust_policy_signature_receipt(
                &mut trust_policy,
                signature_receipt,
            );
            if let Some(root_receipt) = root_receipt {
                crate::m1_runtime::attach_sealed_evidence_policy_root_receipt(
                    &mut trust_policy,
                    root_receipt,
                );
            }
        } else if require_signed_policy {
            return Err("--require-signed-sealed-evidence-trust-policy requires --sealed-evidence-trust-policy-signature".into());
        } else if trusted_policy_root_fingerprint_hex.is_some() {
            return Err("--trusted-sealed-evidence-policy-root-fingerprint-hex requires --sealed-evidence-trust-policy-signature".into());
        } else if policy_roots_path.is_some() {
            return Err(
                "--sealed-evidence-policy-roots requires --sealed-evidence-trust-policy-signature"
                    .into(),
            );
        } else if required_policy_root_id.is_some() {
            return Err(
                "--required-sealed-evidence-policy-root-id requires --sealed-evidence-policy-roots"
                    .into(),
            );
        }
        return Ok(ResolvedSealedEvidenceTrust {
            trusted_transcript_key_fingerprint: trust_anchors.trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint: trust_anchors.trusted_ledger_key_fingerprint,
            trust_policy: Some(trust_policy),
        });
    }

    if trust_policy_signature_path.is_some()
        || trusted_policy_root_fingerprint_hex.is_some()
        || policy_roots_path.is_some()
        || required_policy_root_id.is_some()
        || require_signed_policy
    {
        return Err(
            "signed sealed evidence trust policy flags require --sealed-evidence-trust-policy"
                .into(),
        );
    }

    let transcript_fingerprint_hex = trusted_transcript_key_fingerprint_hex
        .ok_or("--verify-sealed-evidence-bundle requires either --sealed-evidence-trust-policy or --trusted-transcript-key-fingerprint-hex")?;
    let ledger_fingerprint_hex = trusted_ledger_key_fingerprint_hex
        .ok_or("--verify-sealed-evidence-bundle requires either --sealed-evidence-trust-policy or --trusted-ledger-key-fingerprint-hex")?;

    Ok(ResolvedSealedEvidenceTrust {
        trusted_transcript_key_fingerprint: parse_evidence_key_fingerprint_hex(
            transcript_fingerprint_hex,
        )?,
        trusted_ledger_key_fingerprint: parse_evidence_key_fingerprint_hex(ledger_fingerprint_hex)?,
        trust_policy: None,
    })
}

fn parse_ed25519_public_key_bytes(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error>> {
    let public_key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be exactly 32 bytes")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)?)
}

fn verify_evidence_bundle_with_selected_suite(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
    suite: EvidenceVerifierSuite,
    required_profile: Option<EvidenceProfileRequirement>,
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    preflight_evidence_verifier_selection(bundle_dir, suite, required_profile)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => {
            let public_key = parse_ed25519_public_key_bytes(public_key)?;
            let backend = Ed25519EvidenceSignatureBackend;
            Ok(
                crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
                    bundle_dir,
                    &public_key.to_bytes(),
                    &backend,
                )?,
            )
        }
        EvidenceVerifierSuite::MlDsa65Fips204 => {
            verify_ml_dsa_65_evidence_bundle(bundle_dir, public_key)
        }
        EvidenceVerifierSuite::MlDsa87Fips204 => {
            verify_ml_dsa_87_evidence_bundle(bundle_dir, public_key)
        }
    }
}

fn verify_sealed_evidence_bundle_with_selected_suite(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
    suite: EvidenceVerifierSuite,
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    validate_sealed_evidence_verifier_suite(suite)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => unreachable!(
            "validate_sealed_evidence_verifier_suite rejects classical sealed full-PQC verification"
        ),
        EvidenceVerifierSuite::MlDsa65Fips204 => verify_sealed_ml_dsa_65_evidence_bundle(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
        ),
        EvidenceVerifierSuite::MlDsa87Fips204 => verify_sealed_ml_dsa_87_evidence_bundle(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
        ),
    }
}

fn verify_sealed_evidence_trust_policy_signature_with_selected_suite(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    suite: EvidenceVerifierSuite,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    validate_sealed_evidence_verifier_suite(suite)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => unreachable!(
            "validate_sealed_evidence_verifier_suite rejects classical sealed full-PQC verification"
        ),
        EvidenceVerifierSuite::MlDsa65Fips204 => {
            verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
                policy_path,
                signature_path,
                trusted_policy_root_fingerprint,
            )
        }
        EvidenceVerifierSuite::MlDsa87Fips204 => {
            verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
                policy_path,
                signature_path,
                trusted_policy_root_fingerprint,
            )
        }
    }
}

fn validate_sealed_evidence_verifier_suite(
    suite: EvidenceVerifierSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    if suite.is_post_quantum() {
        Ok(())
    } else {
        Err("sealed full-PQC evidence verification requires an ML-DSA verifier suite".into())
    }
}

fn preflight_evidence_verifier_selection(
    bundle_dir: &std::path::Path,
    suite: EvidenceVerifierSuite,
    required_profile: Option<EvidenceProfileRequirement>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = crate::m1_runtime::read_evidence_crypto_manifest_export_dir(bundle_dir)?;
    let selected_label = suite.stable_label();

    if let Some(required_profile) = required_profile {
        validate_required_profile_suite(required_profile, suite)?;

        let required_label = required_profile.stable_label();
        if manifest.profile != required_label {
            return Err(format!(
                "evidence profile {:?} does not satisfy required evidence profile {required_label:?}",
                manifest.profile
            )
            .into());
        }

        let expected_downgrade_policy = required_profile.expected_downgrade_policy_label();
        if manifest.downgrade_policy != expected_downgrade_policy {
            return Err(format!(
                "evidence downgrade policy {:?} does not satisfy required evidence profile {required_label:?}; expected {expected_downgrade_policy:?}",
                manifest.downgrade_policy
            )
            .into());
        }
    }

    if manifest.transcript_signature != selected_label {
        return Err(format!(
            "evidence transcript signature {:?} does not match requested verifier suite {selected_label:?}",
            manifest.transcript_signature
        )
        .into());
    }

    if manifest.ledger_signature != selected_label {
        return Err(format!(
            "evidence ledger signature {:?} does not match requested verifier suite {selected_label:?}",
            manifest.ledger_signature
        )
        .into());
    }

    Ok(())
}

fn validate_required_profile_suite(
    required_profile: EvidenceProfileRequirement,
    suite: EvidenceVerifierSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    match required_profile {
        EvidenceProfileRequirement::HybridPrePqcV1
            if suite == EvidenceVerifierSuite::Ed25519Rfc8032 =>
        {
            Ok(())
        }
        EvidenceProfileRequirement::HybridPrePqcV1 => Err(format!(
            "evidence profile {:?} requires verifier suite {:?}, got {:?}",
            required_profile.stable_label(),
            EvidenceVerifierSuite::Ed25519Rfc8032.stable_label(),
            suite.stable_label()
        )
        .into()),
        EvidenceProfileRequirement::FullPqcV1 if suite.is_post_quantum() => Ok(()),
        EvidenceProfileRequirement::FullPqcV1 => Err(format!(
            "evidence profile {:?} requires a post-quantum verifier suite, got {:?}",
            required_profile.stable_label(),
            suite.stable_label()
        )
        .into()),
    }
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_65_evidence_bundle(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir, public_key, &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_65_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--evidence-signature-suite ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_87_evidence_bundle(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir, public_key, &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_87_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--evidence-signature-suite ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_sealed_ml_dsa_65_evidence_bundle(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_sealed_ml_dsa_65_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _trusted_transcript_key_fingerprint: [u8; 32],
    _trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--sealed-evidence-signature-suite ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_evidence_trust_policy_signature_file_with_backend(
            policy_path,
            signature_path,
            EvidenceVerifierSuite::MlDsa65Fips204.stable_label(),
            trusted_policy_root_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
    _policy_path: &std::path::Path,
    _signature_path: &std::path::Path,
    _trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    Err("--sealed-evidence-trust-policy-signature with ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_sealed_ml_dsa_87_evidence_bundle(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_sealed_ml_dsa_87_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _trusted_transcript_key_fingerprint: [u8; 32],
    _trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--sealed-evidence-signature-suite ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_evidence_trust_policy_signature_file_with_backend(
            policy_path,
            signature_path,
            EvidenceVerifierSuite::MlDsa87Fips204.stable_label(),
            trusted_policy_root_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
    _policy_path: &std::path::Path,
    _signature_path: &std::path::Path,
    _trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    Err("--sealed-evidence-trust-policy-signature with ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
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
mod evidence_verifier_preflight_tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn manifest_dir(test_name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-peer-pqc-preflight-{test_name}-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_manifest(
        dir: &Path,
        profile: &str,
        transcript_signature: &str,
        ledger_signature: &str,
        downgrade_policy: &str,
    ) {
        let manifest = serde_json::json!({
            "schema": "xenia-evidence-crypto-manifest-v1",
            "profile": profile,
            "kem": "ml-kem-768-fips203",
            "transcript_signature": transcript_signature,
            "ledger_signature": ledger_signature,
            "hash_chain": "blake3-256",
            "kdf": "hkdf-sha256",
            "aead": "chacha20-poly1305",
            "downgrade_policy": downgrade_policy,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(dir.join("evidence_manifest.json"), bytes).unwrap();
    }

    #[test]
    fn preflight_accepts_matching_hybrid_profile_and_ed25519_suite() {
        let dir = manifest_dir("hybrid-ok");
        write_manifest(
            &dir,
            "hybrid-pre-pqc-v1",
            "ed25519-rfc8032",
            "ed25519-rfc8032",
            "explicit-classical-signature-allowance",
        );

        preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::Ed25519Rfc8032,
            Some(EvidenceProfileRequirement::HybridPrePqcV1),
        )
        .unwrap();

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_rejects_transcript_suite_mismatch() {
        let dir = manifest_dir("transcript-mismatch");
        write_manifest(
            &dir,
            "full-pqc-v1",
            "ml-dsa-87-fips204",
            "ml-dsa-65-fips204",
            "reject-classical-signatures",
        );

        let err = preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::MlDsa65Fips204,
            Some(EvidenceProfileRequirement::FullPqcV1),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("evidence transcript signature"));
        assert!(err.contains("requested verifier suite"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_rejects_full_pqc_requirement_with_classical_suite() {
        let err = validate_required_profile_suite(
            EvidenceProfileRequirement::FullPqcV1,
            EvidenceVerifierSuite::Ed25519Rfc8032,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("requires a post-quantum verifier suite"));
    }

    #[test]
    fn preflight_rejects_required_profile_downgrade_policy_mismatch() {
        let dir = manifest_dir("downgrade-policy-mismatch");
        write_manifest(
            &dir,
            "full-pqc-v1",
            "ml-dsa-65-fips204",
            "ml-dsa-65-fips204",
            "explicit-classical-signature-allowance",
        );

        let err = preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::MlDsa65Fips204,
            Some(EvidenceProfileRequirement::FullPqcV1),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("evidence downgrade policy"));
        assert!(err.contains("reject-classical-signatures"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sealed_verifier_rejects_classical_suite() {
        let err = validate_sealed_evidence_verifier_suite(EvidenceVerifierSuite::Ed25519Rfc8032)
            .unwrap_err()
            .to_string();

        assert!(err.contains("sealed full-PQC"));
        assert!(err.contains("ML-DSA"));
    }

    #[test]
    fn evidence_key_fingerprint_parser_requires_32_bytes() {
        let ok = parse_evidence_key_fingerprint_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(ok, [0xAB; 32]);

        let err = parse_evidence_key_fingerprint_hex(&"ab".repeat(31))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exactly 32 bytes"));
    }
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
