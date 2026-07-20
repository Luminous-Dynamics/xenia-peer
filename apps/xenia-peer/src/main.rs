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
#[cfg(feature = "audio-opus")]
use xenia_peer_core::OpusAudioCodec;
#[cfg(any(feature = "audio-capture", test))]
use xenia_peer_core::frame::audio_flags;
use xenia_peer_core::{
    AudioCodec, ClipboardContent, LaneSession, M1PermissionSet, PAYLOAD_TYPE_CLIPBOARD,
    RawPcmAudioCodec, RekeyPolicy, SessionEpochState,
    advertisement::{AdvertisedAudioCodec, AudioAdvertisement, TransportAdvertisement},
    frame::{
        LANE_ENVELOPE_MAGIC, PixelFormat as FramePixelFormat, RawAudio, RawClipboard, RawFrame,
        RawRekey, RawTelemetry, SyntheticAudioKind, SyntheticAudioSource,
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
mod audit_ledger_store;
mod consent_authority;
mod consent_server;
mod evidence_verifier;
mod file_transfer;
mod governance;
mod m1_ledger;
mod m1_runtime;
mod operator;
mod operator_audit;
mod operator_auth;
mod operator_channel_metrics;
mod operator_exposure;
mod operator_http;
#[cfg(test)]
mod operator_live_smoke;
#[cfg(test)]
mod operator_rbac_smoke;
mod operator_revocations;
mod operator_sealed_channel;
#[cfg(test)]
mod operator_sealed_smoke;
use crate::evidence_verifier::{
    EvidenceProfileRequirement, EvidenceVerifierSuite, SealedEvidenceTrustInputs,
    parse_evidence_public_key_hex, resolve_sealed_evidence_trust_anchors,
    verify_evidence_bundle_with_selected_suite, verify_sealed_evidence_bundle_with_selected_suite,
};
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

    /// Capture a real Android phone's screen via scrcpy instead of the
    /// host display -- the ADB serial of the device to use (`adb devices`
    /// lists connected serials). Requires building with `--features
    /// scrcpy` and a device connected over USB with debugging authorized.
    /// Takes priority over the scap/TestCapture desktop backends when set.
    #[arg(long)]
    phone_serial: Option<String>,

    /// Host-side TCP port for the scrcpy reverse tunnel (`adb reverse`
    /// bridges the device's local abstract socket here). Only used with
    /// `--phone-serial`. 27183 matches upstream scrcpy's own default.
    #[arg(long, default_value_t = 27183)]
    phone_tcp_port: u16,

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

    /// Serve consent over a `xenia-wire`-sealed operator channel (PQC-hybrid
    /// handshake + AEAD) instead of the plaintext consent port. The console
    /// opens a WebSocket, runs the operator handshake (its enrolled Ed25519 +
    /// ML-DSA-65 key IS the proof of possession), and sends sealed consent
    /// decisions. See `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`. v1 is
    /// single-connection (no reconnect); requires `--operators-file`.
    #[arg(long)]
    operator_sealed: bool,

    /// Port for the sealed operator channel (`--operator-sealed`).
    #[arg(long, default_value_t = 8083)]
    operator_sealed_port: u16,

    /// Forward-secrecy key rotation interval (seconds) for a long-lived
    /// sealed operator channel connection. `0` (default) disables rekeying --
    /// the connection keeps the handshake-derived key for its whole lifetime,
    /// same as before this flag existed (every connection is short-lived in
    /// today's console usage, so this matters mainly for a future
    /// persistent-console mode, or a deliberately conservative deployment).
    /// See `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`.
    #[arg(long, default_value_t = 0)]
    operator_rekey_interval_secs: u64,

    /// Use the high-security operator-channel handshake suite (ML-KEM-1024 +
    /// Ed25519 + ML-DSA-87, NIST security category 5) instead of the default
    /// (ML-KEM-768 + ML-DSA-65, category 3). The console must be configured
    /// to match -- the two suites speak non-interoperable wire messages by
    /// design (see `xenia_wire::handshake_highsec`'s module doc comment), so
    /// a mismatched pairing fails the handshake rather than downgrading.
    #[arg(long)]
    operator_high_security: bool,

    /// Bind address for the operator surface (the admin `/auth` + `/ws` port
    /// and the consent port). Defaults to loopback. Binding to a non-loopback
    /// address (e.g. `0.0.0.0`) exposes the surface to the network and is
    /// **refused unless `--require-operator-auth` is set** — otherwise any host
    /// could send `Approve` on the consent port. Even with auth, terminate TLS
    /// in front for confidentiality (the app-layer signatures prevent forgery,
    /// not eavesdropping). See `docs/security/OPERATOR_RBAC_PLAN.md`.
    #[arg(long, default_value = "127.0.0.1")]
    operator_bind: String,

    /// Browser Origin allowed to call the admin HTTP surface's
    /// `/auth/*`, `/v1/audit/*`, and `/operator/revoke` routes
    /// (`crate::operator_http`). Repeatable. A request whose `Origin`
    /// header doesn't match any of these gets no
    /// `Access-Control-Allow-Origin` in the response, so a browser refuses
    /// to let the console's JS read it -- CORS is a browser-enforced
    /// policy, not a substitute for each route's own real authentication
    /// (a signed token, a challenge/response ceremony, or a deliberately
    /// public route). Defaults cover the console's Trunk dev-serve
    /// origins, mirroring `xenia-operator-agent --allowed-origin`'s
    /// default.
    #[arg(
        long,
        default_values = ["http://localhost:8134", "http://127.0.0.1:8134"]
    )]
    allowed_origin: Vec<String>,

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

    /// Operator signing key path. Defaults into a dedicated `xenia-peer-state/`
    /// subdirectory (created on first run), mirroring
    /// `xenia-operator-agent`'s `xenia-operator-agent-state/` convention --
    /// the predictable subdirectory a systemd `StateDirectory=` unit needs to
    /// point at. Smokes should point this at a temporary path.
    #[arg(long, default_value = "xenia-peer-state/operator.key")]
    operator_key_path: std::path::PathBuf,

    /// Live consent-ledger path (`shared_ledger`, backing `/v1/audit/*`).
    /// Loaded and cryptographically verified at startup if it exists --
    /// the daemon refuses to start rather than trust a ledger file that
    /// doesn't verify under `operator_key_path`. Every append (a consent
    /// decision or operator-action audit event) is durably, atomically
    /// persisted here before the action that produced it is considered
    /// complete. Smokes should point this at a temporary path.
    #[arg(long, default_value = "xenia-peer-state/consent.ledger")]
    consent_ledger_path: std::path::PathBuf,

    /// M1 consent-ledger signing key path. Signs the consent grant/deny/revoke
    /// boundary events; generated on first run with owner-only (0600)
    /// permissions. Must be a real per-host secret -- a shared or well-known
    /// key lets anyone forge a fully-verifying consent transcript.
    #[arg(long, default_value = "xenia-peer-state/consent-ledger.key")]
    m1_consent_key_path: std::path::PathBuf,

    /// Host signing-identity path (Ed25519 secret + ML-DSA-65 seed, 64 bytes).
    /// Generated on first run with owner-only (0600) permissions and reused
    /// thereafter, giving the host a stable identity a viewer can pin
    /// (trust-on-first-use). Its BLAKE3 fingerprint is logged at startup so
    /// an operator can share it out-of-band for verification.
    #[arg(long, default_value = "xenia-peer-state/host-identity.key")]
    host_identity_key_path: std::path::PathBuf,

    /// HTTP-auth ML-DSA-65 signing key path (32-byte seed). Generated on
    /// first run with owner-only (0600) permissions and reused thereafter.
    /// Signs issued session tokens and challenge/consent-action/revoke
    /// transcripts alongside `operator_key_path`'s Ed25519 signature -- a
    /// *separate* key, not a second algorithm folded into
    /// `operator_key_path` itself, since that key already has an
    /// established, independently-used role (the consent ledger's signing
    /// key) that hybridizing shouldn't disturb. See
    /// `xenia_operator_proto::daemon_delegation_transcript`'s doc comment.
    #[arg(long, default_value = "xenia-peer-state/operator-http-ml-dsa.key")]
    http_auth_ml_dsa_key_path: std::path::PathBuf,

    /// Operator enrollment file (JSON): the operators allowed to authenticate
    /// to this daemon's admin surface, each an Ed25519 + ML-DSA-65 public key
    /// bound to a role. When unset, the `/auth/*` endpoints still exist but no
    /// operator can authenticate (empty policy = deny all). See
    /// `docs/security/OPERATOR_RBAC_PLAN.md`.
    #[arg(long)]
    operators_file: Option<std::path::PathBuf>,

    /// Optional file listing revoked `operator_id`s (one per line; `#` comments
    /// and blank lines ignored). Consulted live by the `--operator-sealed`
    /// endpoint after the handshake authenticates a peer, so a compromised
    /// operator is refused fail-closed. Edit the file and send the daemon
    /// `SIGHUP` to reload it without a restart (existing sessions untouched).
    #[arg(long)]
    revoked_operators_file: Option<std::path::PathBuf>,

    /// Require an authenticated, role-authorized operator token for consent
    /// decisions. When off (default), the consent port accepts the legacy
    /// plain-text `Approve`/`Deny`/`Revoke` (backward compatible). When on,
    /// each decision must be a signed `AuthenticatedConsentAction` (token +
    /// per-action signature) from an enrolled operator whose role permits it;
    /// plain-text decisions are refused. Requires `--operators-file`.
    #[arg(long)]
    require_operator_auth: bool,

    /// Inbound viewer-input backend. `noop` (default) discards every
    /// input event -- a connected viewer is view-only and no OS-level
    /// injector is ever constructed, so no consent dialog appears.
    /// `log` records denormalized events for verification (no host
    /// permissions needed). `xdg-portal` actually moves the mouse /
    /// types keys via the RemoteDesktop portal (requires the
    /// `xdg-portal` build feature and triggers its own interactive
    /// consent dialog on first real input event). `uinput` injects via
    /// a real kernel-level `/dev/uinput` virtual device (requires the
    /// `uinput` build feature and `/dev/uinput` access -- root, `input`
    /// group membership, or a udev rule); unlike `xdg-portal`, this
    /// needs no compositor, portal, or active desktop session at all.
    #[arg(long, value_enum, default_value_t = InputBackendChoice::Noop)]
    input_backend: InputBackendChoice,

    /// Clipboard sync mode. `off` (default, view-only) never touches
    /// the real OS clipboard. `host-to-viewer` pushes host clipboard
    /// changes to the viewer only. `bidirectional` also applies
    /// viewer-originated clipboard updates to the real host clipboard
    /// -- this lets a remote viewer write to the host's clipboard, so
    /// it needs the same M1 consent gate as input injection.
    #[arg(long, value_enum, default_value_t = ClipboardMode::Off)]
    clipboard: ClipboardMode,

    /// How often to poll the host clipboard for changes (host-to-viewer
    /// direction). Ignored when `--clipboard off`.
    #[arg(long, default_value_t = 500)]
    clipboard_interval_ms: u64,

    /// Directory to write files the viewer sends. Not set (default) means
    /// the daemon rejects every inbound file-transfer offer -- the
    /// feature is off unless a real destination is configured.
    #[arg(long)]
    recv_file_dir: Option<std::path::PathBuf>,

    /// A local file to offer to the viewer once connected. One transfer
    /// per daemon run in this first cut.
    #[arg(long)]
    send_file: Option<std::path::PathBuf>,

    /// Reject/refuse to send any file larger than this many bytes. The
    /// whole file is buffered in memory (both sending and receiving), so
    /// this is also a memory-use cap, not just a policy knob.
    #[arg(long, default_value_t = 200 * 1024 * 1024)]
    file_transfer_max_bytes: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CodecChoice {
    Passthrough,
    H264,
    Hdc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ClipboardMode {
    Off,
    HostToViewer,
    Bidirectional,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum InputBackendChoice {
    Noop,
    Log,
    #[cfg(feature = "xdg-portal")]
    XdgPortal,
    #[cfg(feature = "uinput")]
    Uinput,
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

fn session_capabilities(
    frame_id: u64,
    audio: AudioAdvertisement,
    video_format: FramePixelFormat,
    args: &Args,
) -> xenia_peer_core::RawCapabilities {
    use xenia_peer_core::{
        AudioSourceCapability, ClipboardCapability, FileTransferCapability,
        InputControlCapability, TelemetryCapability,
    };

    let telemetry = match args.telemetry_level {
        TelemetryLevel::Off => TelemetryCapability::Off,
        TelemetryLevel::Basic => TelemetryCapability::BasicHostPerformance,
        TelemetryLevel::System => TelemetryCapability::SystemIdentityAndPerformance,
    };
    let audio_source = match args.audio {
        AudioMode::Off => AudioSourceCapability::Off,
        AudioMode::Sine | AudioMode::Noise => AudioSourceCapability::SyntheticTestSignal,
        AudioMode::Capture => AudioSourceCapability::HostDeviceCapture,
    };
    let input_control = if args.input_backend == InputBackendChoice::Noop {
        InputControlCapability::Off
    } else {
        InputControlCapability::RemoteInputInjection
    };
    let clipboard = match args.clipboard {
        ClipboardMode::Off => ClipboardCapability::Off,
        ClipboardMode::HostToViewer => ClipboardCapability::HostToViewer,
        ClipboardMode::Bidirectional => ClipboardCapability::Bidirectional,
    };
    let file_transfer = match (args.send_file.is_some(), args.recv_file_dir.is_some()) {
        (false, false) => FileTransferCapability::Off,
        (true, false) => FileTransferCapability::HostToViewer,
        (false, true) => FileTransferCapability::ViewerToHost,
        (true, true) => FileTransferCapability::Bidirectional,
    };

    xenia_peer_core::RawCapabilities {
        schema_version: xenia_peer_core::frame::CAPABILITIES_SCHEMA_VERSION,
        frame_id,
        timestamp_ms: now_ms(),
        audio: Some(audio),
        video_format,
        telemetry,
        audio_source,
        input_control,
        clipboard,
        file_transfer,
        lane_envelope_version: xenia_peer_core::frame::LANE_ENVELOPE_SCHEMA_VERSION,
        lane_envelope_magic: xenia_peer_core::frame::LANE_ENVELOPE_MAGIC,
    }
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
        #[cfg(feature = "uinput")]
        InputBackendChoice::Uinput => {
            match xenia_inject::UinputInjector::new(screen_width, screen_height) {
                Ok(injector) => Box::new(injector),
                Err(err) => {
                    warn!(
                        error = %err,
                        "UinputInjector construction failed; input events will be discarded"
                    );
                    Box::new(NoopInjector)
                }
            }
        }
    }
}

/// Read the current host clipboard text, if any.
///
/// A fresh `arboard::Clipboard` is opened per call rather than cached across
/// polls: `Clipboard` is not `Send` on Linux (both the X11 and
/// wayland-data-control backends hold non-thread-safe connection state), so
/// it cannot be held across an `.await` point shared between the poll loop
/// and the recv task. Opening a connection per poll (default every 500ms)
/// is cheap enough not to matter.
fn read_host_clipboard_text() -> Option<String> {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(err) => {
            warn!(error = %err, "failed to open host clipboard for reading");
            return None;
        }
    };
    match clipboard.get_text() {
        Ok(text) => Some(text),
        Err(arboard::Error::ContentNotAvailable) => None,
        Err(err) => {
            warn!(error = %err, "failed to read host clipboard text");
            None
        }
    }
}

/// Apply a viewer-originated clipboard update to the real host clipboard.
/// Only called in `--clipboard bidirectional` mode, after the M1 consent
/// gate has already allowed the flow.
/// Cap on a single viewer-originated clipboard update applied to the host
/// clipboard. Without a dedicated cap this is bounded only by the 16 MiB
/// envelope limit, letting a bidirectional viewer stuff megabytes into the
/// host clipboard on every update. 1 MiB is well above any realistic text
/// clipboard.
const MAX_INBOUND_CLIPBOARD_BYTES: usize = 1024 * 1024;

fn apply_clipboard_content(content: &ClipboardContent) {
    if let ClipboardContent::Text(text) = content
        && text.len() > MAX_INBOUND_CLIPBOARD_BYTES
    {
        warn!(
            len = text.len(),
            cap = MAX_INBOUND_CLIPBOARD_BYTES,
            "viewer clipboard update exceeds cap; ignoring"
        );
        return;
    }
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(err) => {
            warn!(error = %err, "failed to open host clipboard for writing");
            return;
        }
    };
    // `Cleared` deliberately uses `set_text("")` rather than `clipboard.clear()`.
    // Verified live on a real KDE-Wayland session: `clear()` only unsets the
    // calling connection's own (momentary) selection -- it does not preempt
    // a selection still actively served by an *earlier* `set_text()` call's
    // background wl-data-control server, so a stale value kept reading back
    // after `clear()` returned `Ok`. `set_text("")` actively claims
    // ownership with empty content, which does override it.
    let result = match content {
        ClipboardContent::Text(text) => clipboard.set_text(text.clone()),
        ClipboardContent::Cleared => clipboard.set_text(String::new()),
    };
    if let Err(err) = result {
        warn!(error = %err, "failed to apply viewer clipboard update to host clipboard");
    } else {
        info!(
            ?content,
            "applied viewer clipboard update to host clipboard"
        );
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

fn m1_consent_scope(
    capabilities: &xenia_peer_core::RawCapabilities,
) -> xenia_operator_proto::ConsentScopeV1 {
    use xenia_peer_core::{
        AudioSourceCapability, ClipboardCapability, FileTransferCapability,
        InputControlCapability, TelemetryCapability,
    };

    let telemetry = match capabilities.telemetry {
        TelemetryCapability::Off => xenia_operator_proto::ConsentTelemetryScope::Off,
        TelemetryCapability::BasicHostPerformance => {
            xenia_operator_proto::ConsentTelemetryScope::BasicHostPerformance
        }
        TelemetryCapability::SystemIdentityAndPerformance => {
            xenia_operator_proto::ConsentTelemetryScope::SystemIdentityAndPerformance
        }
    };
    let audio = match capabilities.audio_source {
        AudioSourceCapability::Off => xenia_operator_proto::ConsentAudioScope::Off,
        AudioSourceCapability::SyntheticTestSignal => {
            xenia_operator_proto::ConsentAudioScope::SyntheticTestSignal
        }
        AudioSourceCapability::HostDeviceCapture => {
            xenia_operator_proto::ConsentAudioScope::HostDeviceCapture
        }
    };
    let input = match capabilities.input_control {
        InputControlCapability::Off => xenia_operator_proto::ConsentInputScope::Off,
        InputControlCapability::RemoteInputInjection => {
            xenia_operator_proto::ConsentInputScope::RemoteInputInjection
        }
    };
    let clipboard = match capabilities.clipboard {
        ClipboardCapability::Off => xenia_operator_proto::ConsentClipboardScope::Off,
        ClipboardCapability::HostToViewer => {
            xenia_operator_proto::ConsentClipboardScope::HostToViewer
        }
        ClipboardCapability::ViewerToHost => {
            xenia_operator_proto::ConsentClipboardScope::ViewerToHost
        }
        ClipboardCapability::Bidirectional => {
            xenia_operator_proto::ConsentClipboardScope::Bidirectional
        }
    };
    let file_transfer = match capabilities.file_transfer {
        FileTransferCapability::Off => xenia_operator_proto::ConsentFileTransferScope::Off,
        FileTransferCapability::HostToViewer => {
            xenia_operator_proto::ConsentFileTransferScope::HostToViewer
        }
        FileTransferCapability::ViewerToHost => {
            xenia_operator_proto::ConsentFileTransferScope::ViewerToHost
        }
        FileTransferCapability::Bidirectional => {
            xenia_operator_proto::ConsentFileTransferScope::Bidirectional
        }
    };
    xenia_operator_proto::ConsentScopeV1::screen_with_capabilities(
        telemetry,
        audio,
        input,
        clipboard,
        file_transfer,
    )
}

/// Atomically create `path` at 0600 and write `bytes` -- no separate
/// write-then-chmod window where a raw secret sits briefly world-readable
/// (`fs::write` creates at the ambient umask, typically 0644). Also
/// tightens `path`'s parent directory to 0700 after creating it, since
/// `create_dir_all` alone leaves it at the ambient umask too (typically
/// 0755, world-listable). Mirrors two patterns that already exist
/// elsewhere in this repo -- `audit_ledger_store.rs`'s
/// `OpenOptions::create_new+mode` for the file, and
/// `apps/xenia-operator-agent/src/secure_file.rs`'s parent-directory
/// re-tightening -- applied here to close the same gap in this crate's own
/// key-generation code. `create_new(true)` is also a correctness
/// improvement over plain `fs::write`: it fails rather than silently
/// overwriting if the file was created by something else between the
/// caller's `path.exists()` check and this call.
#[cfg(unix)]
fn create_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)
}
#[cfg(not(unix))]
fn create_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

/// Load an Ed25519 signing key from `path`, or generate and persist a fresh
/// one on first use. The persisted key file is created with owner-only (0600)
/// permissions, and existing files are re-tightened to 0600 on load, so a
/// signing secret is never left group/world-readable on disk.
fn load_or_create_signing_key(
    path: &std::path::Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }

    if path.exists() {
        let key_bytes = std::fs::read(path)?;
        let key = SigningKey::from_bytes(&key_bytes.try_into().map_err(|_| "Invalid key length")?);
        restrict_permissions(path)?;
        Ok(key)
    } else {
        let key = SigningKey::generate(&mut rand::thread_rng());
        create_secret_file(path, &key.to_bytes())?;
        Ok(key)
    }
}

/// Load the HTTP-auth ML-DSA-65 seed from `path`, or generate and persist a
/// fresh one on first use -- the ML-DSA counterpart to
/// [`load_or_create_signing_key`]'s Ed25519 key, but a genuinely separate
/// key rather than a second algorithm for the same one (see
/// `Args::http_auth_ml_dsa_key_path`'s doc comment). A 32-byte seed (FIPS-204
/// ξ), not the full `xenia_handshake::MlDsaIdentity` -- reconstructed via
/// [`xenia_handshake::MlDsaIdentity::from_seed`] at each call site.
fn load_or_create_ml_dsa_seed(
    path: &std::path::Path,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    #[cfg(unix)]
    fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }

    if path.exists() {
        let bytes = std::fs::read(path)?;
        restrict_permissions(path)?;
        bytes
            .try_into()
            .map_err(|_| "Invalid ML-DSA seed length".into())
    } else {
        let seed: [u8; 32] = rand::random();
        create_secret_file(path, &seed)?;
        Ok(seed)
    }
}

/// Load the host's persistent signing identity from `path`, or generate and
/// persist a fresh one (0600) on first use. The file is a 64-byte blob:
/// 32-byte Ed25519 secret followed by a 32-byte ML-DSA-65 seed. Reconstructed
/// deterministically so the host's public identity (and fingerprint) is stable
/// across restarts -- the prerequisite for a viewer pinning it.
fn load_or_create_host_identity(
    path: &std::path::Path,
) -> Result<HandshakeManager, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }

    let blob: Vec<u8> = if path.exists() {
        let bytes = std::fs::read(path)?;
        restrict_permissions(path)?;
        if bytes.len() != 64 {
            return Err("host identity file must be exactly 64 bytes".into());
        }
        bytes
    } else {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        create_secret_file(path, &blob)?;
        blob
    };
    let mut ed25519_secret = [0u8; 32];
    let mut ml_dsa_seed = [0u8; 32];
    ed25519_secret.copy_from_slice(&blob[..32]);
    ml_dsa_seed.copy_from_slice(&blob[32..64]);
    Ok(HandshakeManager::from_identity_seeds(
        ed25519_secret,
        ml_dsa_seed,
    ))
}

/// Like [`load_or_create_host_identity`], but for the `--operator-high-security`
/// suite: reads/creates the *same* identity file (so both suites share one
/// persisted Ed25519 secret -- the identity a peer actually pins), then
/// derives the ML-DSA-87 seed from that secret via
/// `derive_ml_dsa_87_seed_from_ed25519_secret` rather than using the file's
/// own `[32..64]` bytes (that half is the *standard*-suite ML-DSA-65 seed --
/// a different parameter set, not reusable here).
fn load_or_create_host_identity_highsec(
    path: &std::path::Path,
) -> Result<xenia_wire::handshake_highsec::HostHandshakeHighSec, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }

    let blob: Vec<u8> = if path.exists() {
        let bytes = std::fs::read(path)?;
        restrict_permissions(path)?;
        if bytes.len() != 64 {
            return Err("host identity file must be exactly 64 bytes".into());
        }
        bytes
    } else {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        create_secret_file(path, &blob)?;
        blob
    };
    let mut ed25519_secret = [0u8; 32];
    ed25519_secret.copy_from_slice(&blob[..32]);
    let ml_dsa_seed =
        xenia_wire::handshake_highsec::derive_ml_dsa_87_seed_from_ed25519_secret(&ed25519_secret);
    Ok(
        xenia_wire::handshake_highsec::HostHandshakeHighSec::from_identity(
            &ed25519_secret,
            &ml_dsa_seed,
        ),
    )
}

/// Derive runtime consent permissions from the exact sealed capability object.
///
/// The same `RawCapabilities` value is hashed into the viewer handshake, sent
/// to the viewer, converted into the signed consent scope, and used here to
/// preserve each clipboard and file-transfer direction in the M1 gate itself.
fn configured_permission_set(capabilities: &xenia_peer_core::RawCapabilities) -> M1PermissionSet {
    use xenia_peer_core::{ClipboardCapability, FileTransferCapability, InputControlCapability};

    M1PermissionSet {
        stream_frame: true,
        inject_input: matches!(
            capabilities.input_control,
            InputControlCapability::RemoteInputInjection
        ),
        read_host_clipboard: matches!(
            capabilities.clipboard,
            ClipboardCapability::HostToViewer | ClipboardCapability::Bidirectional
        ),
        write_host_clipboard: matches!(
            capabilities.clipboard,
            ClipboardCapability::ViewerToHost | ClipboardCapability::Bidirectional
        ),
        send_file_to_viewer: matches!(
            capabilities.file_transfer,
            FileTransferCapability::HostToViewer | FileTransferCapability::Bidirectional
        ),
        receive_file_from_viewer: matches!(
            capabilities.file_transfer,
            FileTransferCapability::ViewerToHost | FileTransferCapability::Bidirectional
        ),
    }
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

    // Fail closed before doing any work: never expose the operator surface to
    // the network without operator auth (Phase 6 — remote operators).
    crate::operator_exposure::validate_operator_exposure(
        &args.operator_bind,
        args.require_operator_auth,
    )?;
    if !crate::operator_exposure::is_loopback_bind(&args.operator_bind) {
        tracing::warn!(
            bind = %args.operator_bind,
            "operator surface bound to a NON-loopback address — reachable from the network. \
             Operator auth is enforced (forgery-safe), but terminate TLS in front for \
             confidentiality."
        );
    }

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
        let trust = resolve_sealed_evidence_trust_anchors(SealedEvidenceTrustInputs {
            trust_policy_path: args.sealed_evidence_trust_policy.as_deref(),
            trust_policy_signature_path: args.sealed_evidence_trust_policy_signature.as_deref(),
            trusted_policy_root_fingerprint_hex: args
                .trusted_sealed_evidence_policy_root_fingerprint_hex
                .as_deref(),
            policy_roots_path: args.sealed_evidence_policy_roots.as_deref(),
            required_policy_root_id: args.required_sealed_evidence_policy_root_id.as_deref(),
            trusted_transcript_key_fingerprint_hex: args
                .trusted_transcript_key_fingerprint_hex
                .as_deref(),
            trusted_ledger_key_fingerprint_hex: args.trusted_ledger_key_fingerprint_hex.as_deref(),
            suite: args.sealed_evidence_signature_suite,
            minimum_policy_epoch: args.minimum_sealed_evidence_policy_epoch,
            require_signed_policy: args.require_signed_sealed_evidence_trust_policy,
        })?;

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

    let signing_key = load_or_create_signing_key(&args.operator_key_path)?;

    let mut telemetry = SysinfoTelemetryStream::new();
    let mut audio = build_audio_source(args.audio)?;
    let audio_codec_choice = resolve_audio_codec_choice(args.audio_codec);
    let audio_advertisement = audio_advertisement(audio_codec_choice);
    let mut audio_codec = make_audio_codec(audio_codec_choice)?;
    info!(
        audio_codec = audio_codec.name(),
        "daemon audio codec configured"
    );

    // Fails closed: a present-but-corrupt-or-tampered consent-ledger file
    // refuses startup rather than being silently trusted or discarded.
    // See `audit_ledger_store`'s module doc comment for the two gaps this
    // closes (no persistence at all, and an unverified reload path).
    let ledger_path = std::sync::Arc::new(args.consent_ledger_path.clone());
    let ledger = audit_ledger_store::load_verified(&ledger_path, &signing_key).map_err(
        |err| -> Box<dyn std::error::Error> {
            format!(
                "failed to load --consent-ledger-path {}: {err}",
                ledger_path.display()
            )
            .into()
        },
    )?;
    info!(
        path = %ledger_path.display(),
        entries = ledger.len(),
        "consent ledger loaded and verified"
    );
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

    // Operator-auth state: the enrolled-operator policy (empty = deny all if
    // no --operators-file), a challenge store, and the daemon's key for
    // signing issued tokens.
    let operator_policy = match &args.operators_file {
        Some(path) => match crate::operator::OperatorPolicy::load(path) {
            Ok(policy) => {
                info!(operators = policy.len(), path = %path.display(), "operator policy loaded");
                policy
            }
            Err(err) => {
                return Err(
                    format!("failed to load --operators-file {}: {err}", path.display()).into(),
                );
            }
        },
        None => crate::operator::OperatorPolicy::default(),
    };
    // The host identity is loaded again here (idempotent -- reads the
    // already-persisted file the same way the sealed-channel setup below
    // does) solely to build `daemon_certificate`: the host identity's
    // delegation of trust to `signing_key`/`http_auth_ml_dsa` (the
    // *separate* keys that sign HTTP auth tokens/challenges/consent-action/
    // revoke transcripts), so a caller with no live connection to this
    // daemon -- the operator agent -- can verify that delegation itself
    // rather than trust a caller-supplied daemon identity. See
    // `DaemonIdentityCertificate`'s doc comment in `xenia_operator_proto`.
    let operator_auth_host_identity = load_or_create_host_identity(&args.host_identity_key_path)?;
    let http_auth_ml_dsa_seed = load_or_create_ml_dsa_seed(&args.http_auth_ml_dsa_key_path)?;
    let http_auth_ml_dsa = xenia_handshake::MlDsaIdentity::from_seed(http_auth_ml_dsa_seed);
    let operator_auth_state = Arc::new(crate::operator_http::OperatorAuthState::new(
        operator_policy,
        signing_key.clone(),
        http_auth_ml_dsa,
        operator_auth_host_identity,
        crate::operator_auth::AUTH_RATE_MAX,
        crate::operator_auth::AUTH_RATE_WINDOW_SECS,
    ));

    // Live operator revocation list — shared by the admin `/operator/revoke`
    // endpoint (below) and the sealed operator endpoint. A failed load is fatal:
    // we won't run the privileged surfaces without the list we were told to
    // enforce (fail-closed).
    let revocations = match &args.revoked_operators_file {
        Some(path) => {
            let r = crate::operator_revocations::OperatorRevocations::from_file(path).map_err(
                |err| -> Box<dyn std::error::Error> {
                    format!(
                        "failed to load --revoked-operators-file {}: {err}",
                        path.display()
                    )
                    .into()
                },
            )?;
            info!(path = %path.display(), revoked = r.len(), "loaded operator revocation list");
            r
        }
        None => crate::operator_revocations::OperatorRevocations::empty(),
    };
    // Reload the revocation file on SIGHUP (no restart), only when a file is
    // configured so SIGHUP disposition is otherwise unchanged.
    #[cfg(unix)]
    if args.revoked_operators_file.is_some() {
        let reload = revocations.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut hup) = signal(SignalKind::hangup()) else {
                return;
            };
            while hup.recv().await.is_some() {
                match reload.reload() {
                    Ok(n) => info!(revoked = n, "reloaded operator revocation list on SIGHUP"),
                    Err(err) => {
                        tracing::error!(error = %err, "failed to reload revocation list on SIGHUP")
                    }
                }
            }
        });
    }

    let app = crate::admin_ui::mount(Router::new())
        .route(
            "/ws",
            get({
                let bridge = bridge.clone();
                move |ws| ws_handler(ws, bridge.clone())
            }),
        )
        .merge(crate::operator_http::router(
            operator_auth_state.clone(),
            revocations.clone(),
            shared_ledger.clone(),
            std::sync::Arc::new(args.allowed_origin.clone()),
            args.operators_file.clone(),
        ));

    let listener = TcpListener::bind(format!("{}:{}", args.operator_bind, args.admin_port)).await?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "admin websocket server exited");
        }
    });

    // Initialize Capture Backend
    // The `'backend` label is only broken to from the `scrcpy`-gated arm
    // below, so it reads as unused in a default (non-scrcpy) build.
    #[cfg_attr(not(feature = "scrcpy"), allow(unused_labels))]
    let mut capture: Box<dyn ScreenCapture> = 'backend: {
        if let Some(serial) = &args.phone_serial {
            #[cfg(feature = "scrcpy")]
            {
                info!(
                    serial,
                    tcp_port = args.phone_tcp_port,
                    "Initializing ScrcpyScreenCapture backend (phone-as-source)"
                );
                break 'backend Box::new(xenia_capture_scrcpy::ScrcpyScreenCapture::launch(
                    serial,
                    args.phone_tcp_port,
                )?);
            }
            #[cfg(not(feature = "scrcpy"))]
            {
                let _ = serial;
                return Err(
                    "--phone-serial requires building with feature `xenia-peer/scrcpy`".into(),
                );
            }
        }
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
    let raw_capabilities = session_capabilities(
        session.next_frame_id(),
        audio_advertisement.clone(),
        frame_format,
        &args,
    );
    let capabilities = raw_capabilities.clone().into_frame()?;
    let negotiated_context_hash =
        negotiated_session_context_hash(negotiated_transport, raw_capabilities.clone())?;

    let mut mgr = load_or_create_host_identity(&args.host_identity_key_path)?;
    info!(
        fingerprint = %hex::encode(mgr.identity_fingerprint()),
        path = %args.host_identity_key_path.display(),
        "host signing identity loaded; share this fingerprint out-of-band for viewer pinning"
    );
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

    // When --require-operator-auth is set, consent decisions must be signed,
    // role-authorized operator actions. The
    // per-action signature binds to this session's host-attested typed offer,
    // and each authenticated decision is attributed in the ledger (Phase 4).
    let require_operator_auth = args.require_operator_auth;
    // Computed here as a canonical typed value (a pure function of the
    // daemon's own CLI config, not handshake/runtime state) rather than down
    // at the `m1_scope` presentation binding
    // below, so both consent-server branches immediately below can bind
    // their per-action signatures to this session's actual offered scope --
    // never trusting anything relayed back through the console/agent
    // round-trip for that binding. Reused verbatim (not recomputed) for the
    // M1 consent-scope offer/broadcast below, so semantics, display text,
    // audit text, and the signature digest all share one source of truth.
    let consent_scope = m1_consent_scope(&raw_capabilities);
    let offered_permissions = configured_permission_set(&raw_capabilities);
    let m1_scope = consent_scope.summary();
    let offer_issued_at = now_ms() / 1_000;
    let consent_offer = xenia_operator_proto::ConsentOfferV2::new(
        *session_id.as_bytes(),
        handshake.transcript_hash,
        consent_scope,
        offer_issued_at,
        offer_issued_at.saturating_add(args.consent_timeout_secs.max(1)),
    );
    let consent_offer_bytes = consent_offer.canonical_bytes();
    let attested_consent_offer = xenia_operator_proto::AttestedConsentOfferV2 {
        offer: consent_offer,
        host_ed_signature_hex: hex::encode(
            operator_auth_state
                .host_identity
                .sign(&consent_offer_bytes)
                .to_bytes(),
        ),
        host_ml_dsa_signature_hex: hex::encode(
            operator_auth_state
                .host_identity
                .sign_ml_dsa(&consent_offer_bytes),
        ),
    };
    let consent_service = Arc::new(crate::consent_authority::ConsentDecisionService::new(
        require_operator_auth,
        operator_auth_state.clone(),
        consent_offer,
        revocations.clone(),
        shared_ledger.clone(),
        ledger_path.clone(),
        consent_decision_tx,
    ));
    {
        let consent_service = Arc::clone(&consent_service);
        let mut revocation_changes = revocations.subscribe();
        tokio::spawn(async move {
            while revocation_changes.changed().await.is_ok() {
                if consent_service.revoke_if_approver_revoked().await {
                    break;
                }
            }
        });
    }

    // Consent server. With --operator-sealed the console talks over a
    // xenia-wire-sealed operator channel (PQC confidentiality + handshake
    // channel-auth); otherwise the plaintext consent port. Both own the single
    // per-session grant oneshot, so it's one or the other. Bind here so a bind
    // failure just skips the server rather than dying silently inside the task.
    if args.operator_sealed {
        let sealed_addr = format!("{}:{}", args.operator_bind, args.operator_sealed_port);
        match TcpListener::bind(&sealed_addr).await {
            Ok(listener) => {
                // A second host identity with the *same* persisted secret, so
                // the console pins one daemon fingerprint. Suite selected by
                // --operator-high-security; see that flag's doc comment.
                let identity = if args.operator_high_security {
                    crate::operator_sealed_channel::OperatorHostIdentity::HighSecurity(Box::new(
                        load_or_create_host_identity_highsec(&args.host_identity_key_path)?,
                    ))
                } else {
                    crate::operator_sealed_channel::OperatorHostIdentity::Standard(Box::new(
                        load_or_create_host_identity(&args.host_identity_key_path)?,
                    ))
                };
                // Uses the `revocations` handle created above (shared with the
                // admin /operator/revoke endpoint), so a live revoke reaches the
                // sealed channel immediately.
                let deps = crate::operator_sealed_channel::SealedConsentDeps {
                    service: Arc::clone(&consent_service),
                    rekey_interval: (args.operator_rekey_interval_secs > 0)
                        .then(|| Duration::from_secs(args.operator_rekey_interval_secs)),
                };
                let policy = operator_auth_state.policy.clone();
                let sealed_metrics = std::sync::Arc::new(
                    crate::operator_channel_metrics::OperatorChannelMetrics::default(),
                );
                info!(addr = %sealed_addr, "sealed operator endpoint listening");
                tokio::spawn(
                    crate::operator_sealed_channel::run_sealed_operator_endpoint(
                        listener,
                        identity,
                        policy,
                        deps,
                        sealed_metrics,
                    ),
                );
            }
            Err(err) => {
                tracing::error!(addr = %sealed_addr, error = %err, "sealed operator endpoint bind failed");
            }
        }
    } else {
        let consent_addr = format!("{}:{}", args.operator_bind, args.consent_port);
        match TcpListener::bind(&consent_addr).await {
            Ok(listener) => {
                let server = crate::consent_server::ConsentServer {
                    service: Arc::clone(&consent_service),
                };
                tokio::spawn(server.run(listener));
            }
            Err(err) => {
                tracing::error!(addr = %consent_addr, error = %err, "consent websocket bind failed");
            }
        }
    }

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

    let m1_signing_key = load_or_create_signing_key(&args.m1_consent_key_path)?;
    // The typed scope, persisted permission descriptor, and runtime gate all
    // derive from the same `raw_capabilities` value computed before either
    // consent transport starts.
    let m1_scope_for_log = m1_scope.clone();
    let mut m1_runtime = crate::m1_runtime::M1RuntimeSession::new(
        m1_signing_key,
        expand_source_id_for_m1(source_id),
        session_id,
        Uuid::new_v4(),
        offered_permissions,
    );
    m1_runtime.bind_session_transcript_hash(handshake.transcript_hash);
    m1_runtime.offer()?;
    info!(scope = %m1_scope_for_log, "M1 consent scope offered");

    if args.m1_preprod_auto_consent {
        grant_preprod_auto_consent(&mut m1_runtime)?;
    } else {
        // Broadcast the host-attested typed offer that the native agent will
        // independently verify before signing. `scope_v1` and `session_id`
        // remain compatibility fields derived from the same offer; `scope` is
        // derived human-readable text. A legacy
        // plaintext console just shows the text and still sends
        // "Approve"/"Deny", which a daemon without --require-operator-auth
        // accepts -- so this shape change is backward compatible.
        let consent_prompt = serde_json::json!({
            "session_id": hex::encode(session_id.as_bytes()),
            "scope": m1_scope_for_log,
            "scope_v1": consent_scope,
            "attested_offer": &attested_consent_offer,
        })
        .to_string();
        bridge.broadcast(&consent_prompt);
        info!(
            consent_port = args.consent_port,
            timeout_secs = args.consent_timeout_secs,
            "consent request broadcast; waiting for Approve/Deny on --consent-port"
        );
        let timeout = Duration::from_secs(args.consent_timeout_secs.max(1));
        match tokio::time::timeout(timeout, consent_decision_rx).await {
            Ok(Ok(true)) => {
                let granted = offered_permissions;
                m1_runtime.grant_consent_scoped(granted)?;
                if let Some(receipt) = consent_service.approval_receipt() {
                    m1_runtime.bind_operator_authorization(
                        receipt.action_id,
                        receipt.offer_digest,
                        &receipt.operator_id,
                        receipt.operator_ed25519_pubkey,
                    )?;
                } else if require_operator_auth {
                    return Err(
                        "authenticated consent grant committed without an approval receipt"
                            .into(),
                    );
                }
                info!(
                    inject_input = granted.inject_input,
                    read_host_clipboard = granted.read_host_clipboard,
                    write_host_clipboard = granted.write_host_clipboard,
                    send_file_to_viewer = granted.send_file_to_viewer,
                    receive_file_from_viewer = granted.receive_file_from_viewer,
                    "M1 consent granted; only the operator-enabled directions unlocked"
                );
            }
            Ok(Ok(false)) => {
                m1_runtime.deny_consent()?;
                warn!("M1 consent denied; exiting");
                return Ok(());
            }
            Ok(Err(_)) => {
                consent_service.fail_pending().await;
                warn!("consent channel closed before a decision arrived; exiting");
                return Ok(());
            }
            Err(_) => {
                consent_service.expire_pending().await;
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
    let mut runtime_consent_state = consent_service.subscribe_state();
    if runtime_consent_state.borrow().runtime_must_stop() {
        let state = *runtime_consent_state.borrow();
        if let Err(err) = m1_runtime.lock().await.revoke() {
            warn!(error = %err, ?state, "failed to record pre-runtime consent termination");
        }
        info!(?state, "consent terminated before privileged runtime startup");
        return Ok(());
    }
    let (rekey_ack_tx, mut rekey_ack_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    // File-transfer envelopes are forwarded here rather than opened in the
    // recv task, because replying (Accept/Reject/Chunk/Verified) needs
    // `send_half`, which the main send loop below owns exclusively (unlike
    // xenia-viewer, which already wraps its send half in an Arc<Mutex>).
    let (ft_tx, mut ft_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    let mut ft_state = file_transfer::FileTransferState::new();
    if let Some(path) = &args.send_file {
        let data = std::fs::read(path)?;
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
        let transfer_id = 1;
        m1_runtime.lock().await.allow_file_send_to_viewer()?;
        let offer = xenia_peer_core::FileTransferMessage::Offer {
            transfer_id,
            name: name.clone(),
            size: data.len() as u64,
            blake3_hash,
        };
        let envelope = session
            .lock()
            .await
            .seal_file_transfer_message(offer, true)?;
        send_half.send_envelope(&envelope).await?;
        info!(
            transfer_id,
            name,
            size = data.len(),
            "file transfer offered"
        );
        ft_state.outgoing = Some(file_transfer::OutgoingTransfer {
            transfer_id,
            data,
            started: false,
        });
    }

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
        let clipboard_mode = args.clipboard;
        let ft_tx = ft_tx.clone();
        let mut recv_consent_state = consent_service.subscribe_state();
        tokio::spawn(async move {
            let mut recv_half = recv_half;
            // Constructed lazily on the first real InputEvent, not at
            // task start -- a view-only session (`--input-backend
            // noop`, the default) never triggers `XdgPortalInjector`'s
            // consent dialog because it's simply never built.
            let mut injector: Option<Box<dyn InputInjector>> = None;
            loop {
                let envelope = tokio::select! {
                    changed = recv_consent_state.changed() => {
                        if changed.is_err() || recv_consent_state.borrow().runtime_must_stop() {
                            info!(state = ?*recv_consent_state.borrow(), "consent lifecycle stopped inbound privileged flow");
                            break;
                        }
                        continue;
                    }
                    received = recv_half.recv_envelope() => match received {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            info!(error = %err, "input/rekey-ack receive loop ending");
                            break;
                        }
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

                // Bare (non-lane-wrapped) envelope: either a viewer-captured
                // input event or a viewer-originated clipboard update, both
                // sealed directly under the control lane's key. The payload
                // type byte is cleartext (nonce byte 6) so this is checked
                // without attempting -- and potentially misfiring -- a
                // decrypt against the wrong opener.
                if matches!(
                    xenia_wire::envelope_payload_type(&envelope),
                    Some(xenia_peer_core::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST)
                        | Some(xenia_peer_core::PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER)
                ) {
                    let _ = ft_tx.send(envelope).await;
                    continue;
                }

                if xenia_wire::envelope_payload_type(&envelope) == Some(PAYLOAD_TYPE_CLIPBOARD) {
                    let clipboard = {
                        let mut session = session.lock().await;
                        match session.open_clipboard(&envelope) {
                            Ok(clipboard) => clipboard,
                            Err(err) => {
                                warn!(error = %err, "failed to open inbound clipboard envelope");
                                continue;
                            }
                        }
                    };
                    if clipboard_mode != ClipboardMode::Bidirectional {
                        warn!("ignoring viewer clipboard update: --clipboard is not bidirectional");
                        continue;
                    }
                    {
                        let mut m1_runtime = m1_runtime.lock().await;
                        if let Err(err) = m1_runtime.allow_host_clipboard_write() {
                            warn!(error = %err, "clipboard update rejected by M1 consent gate");
                            continue;
                        }
                    }
                    apply_clipboard_content(&clipboard.content);
                    continue;
                }

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
                        info!(
                            ?event,
                            backend = injector.backend_name(),
                            "input event injected"
                        );
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
    let clipboard_interval = Duration::from_millis(args.clipboard_interval_ms.max(1));
    let mut last_clipboard_check = std::time::Instant::now() - clipboard_interval;
    let mut last_sent_clipboard_text: Option<String> = None;
    let mut clipboard_seq = 0u64;
    let mut sent_frames = 0u64;
    let mut sent_telemetry = 0u64;
    let mut sent_audio = 0u64;
    let mut sent_clipboard = 0u64;

    loop {
        if args.frames != 0 && sent_frames >= args.frames {
            info!(sent = sent_frames, "reached --frames, daemon exiting");
            break;
        }

        tokio::select! {
            _ = ticker.tick() => {}
            changed = runtime_consent_state.changed() => {
                if changed.is_err() || runtime_consent_state.borrow().runtime_must_stop() {
                    let state = *runtime_consent_state.borrow();
                    if let Err(err) = m1_runtime.lock().await.revoke() {
                        warn!(error = %err, ?state, "failed to record consent termination");
                    }
                    info!(?state, "consent lifecycle stopped outbound privileged flow");
                    break;
                }
                continue;
            }
        }

        while let Ok(envelope) = ft_rx.try_recv() {
            let ft_config = file_transfer::FileTransferConfig {
                recv_file_dir: args.recv_file_dir.as_deref(),
                max_bytes: args.file_transfer_max_bytes,
            };
            file_transfer::handle_envelope(
                &envelope,
                &mut send_half,
                &session,
                &m1_runtime,
                &mut ft_state,
                &ft_config,
            )
            .await?;
        }

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

        if args.clipboard != ClipboardMode::Off
            && last_clipboard_check.elapsed() >= clipboard_interval
        {
            last_clipboard_check = std::time::Instant::now();
            if let Some(text) = read_host_clipboard_text()
                && Some(&text) != last_sent_clipboard_text.as_ref()
            {
                m1_runtime.lock().await.allow_host_clipboard_read()?;
                m1_runtime.lock().await.preflight_frame_flow()?;
                let frame_id = session.lock().await.next_frame_id();
                let seq = clipboard_seq;
                clipboard_seq += 1;
                let clipboard_frame = RawClipboard {
                    sequence: seq,
                    timestamp_ms: now_ms(),
                    content: ClipboardContent::Text(text.clone()),
                }
                .into_frame(frame_id)?;
                let envelope = session.lock().await.seal_frame(&clipboard_frame)?;
                m1_runtime.lock().await.allow_frame_flow()?;
                send_half.send_envelope(&envelope).await?;
                last_sent_clipboard_text = Some(text);
                sent_clipboard += 1;
                if sent_clipboard <= 3 || sent_clipboard.is_multiple_of(10) {
                    info!(
                        sent = sent_clipboard,
                        frame_id, "clipboard update sealed and sent"
                    );
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
        M1PermissionSet::all(),
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

    fn configured_scope(args: &Args) -> xenia_operator_proto::ConsentScopeV1 {
        let capabilities = session_capabilities(
            1,
            audio_advertisement(args.audio_codec),
            codec_to_frame_format(args.codec),
            args,
        );
        m1_consent_scope(&capabilities)
    }

    #[test]
    fn m1_scope_names_audio_off_and_telemetry_policy() {
        let mut args = Args::parse_from(["xenia-peer"]);
        args.telemetry_level = TelemetryLevel::Basic;
        args.audio = AudioMode::Off;
        assert_eq!(
            configured_scope(&args).summary(),
            "display: screen stream; telemetry: basic host performance; audio: off; input: off; clipboard: off; file transfer: off"
        );
    }

    #[test]
    fn m1_scope_names_real_audio_capture_explicitly() {
        let mut args = Args::parse_from(["xenia-peer"]);
        args.telemetry_level = TelemetryLevel::System;
        args.audio = AudioMode::Capture;
        assert_eq!(
            configured_scope(&args).summary(),
            "display: screen stream; telemetry: system identity and performance; audio: host device capture; input: off; clipboard: off; file transfer: off"
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

#[cfg(test)]
mod consent_scope_tests {
    use super::*;

    fn args_with(
        input_backend: InputBackendChoice,
        clipboard: ClipboardMode,
        recv_file_dir: Option<std::path::PathBuf>,
        send_file: Option<std::path::PathBuf>,
    ) -> Args {
        let mut args = Args::parse_from(["xenia-peer"]);
        args.input_backend = input_backend;
        args.clipboard = clipboard;
        args.recv_file_dir = recv_file_dir;
        args.send_file = send_file;
        args
    }

    fn configured_capabilities(args: &Args) -> xenia_peer_core::RawCapabilities {
        session_capabilities(
            1,
            audio_advertisement(args.audio_codec),
            codec_to_frame_format(args.codec),
            args,
        )
    }

    fn configured_scope(args: &Args) -> xenia_operator_proto::ConsentScopeV1 {
        m1_consent_scope(&configured_capabilities(args))
    }

    fn configured_permissions(args: &Args) -> M1PermissionSet {
        configured_permission_set(&configured_capabilities(args))
    }

    #[test]
    fn view_only_daemon_grants_only_frame_streaming() {
        let args = args_with(InputBackendChoice::Noop, ClipboardMode::Off, None, None);
        let granted = configured_permissions(&args);
        assert!(granted.stream_frame);
        assert!(!granted.inject_input);
        assert!(!granted.read_host_clipboard);
        assert!(!granted.write_host_clipboard);
        assert!(!granted.send_file_to_viewer);
        assert!(!granted.receive_file_from_viewer);
    }

    #[test]
    fn each_enabled_capability_unlocks_exactly_its_own_direction() {
        let input = args_with(InputBackendChoice::Log, ClipboardMode::Off, None, None);
        let granted = configured_permissions(&input);
        assert!(granted.inject_input);
        assert!(!granted.read_host_clipboard);
        assert!(!granted.write_host_clipboard);

        let host_clipboard = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::HostToViewer,
            None,
            None,
        );
        let granted = configured_permissions(&host_clipboard);
        assert!(granted.read_host_clipboard);
        assert!(!granted.write_host_clipboard);

        let bidirectional_clipboard = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Bidirectional,
            None,
            None,
        );
        let granted = configured_permissions(&bidirectional_clipboard);
        assert!(granted.read_host_clipboard);
        assert!(granted.write_host_clipboard);

        let send = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Off,
            None,
            Some(std::path::PathBuf::from("/tmp/outbound")),
        );
        let granted = configured_permissions(&send);
        assert!(granted.send_file_to_viewer);
        assert!(!granted.receive_file_from_viewer);

        let recv = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Off,
            Some(std::path::PathBuf::from("/tmp/inbox")),
            None,
        );
        let granted = configured_permissions(&recv);
        assert!(!granted.send_file_to_viewer);
        assert!(granted.receive_file_from_viewer);
    }

    #[test]
    fn consent_scope_describes_every_configured_capability_and_direction() {
        let args = args_with(
            InputBackendChoice::Log,
            ClipboardMode::Bidirectional,
            Some(std::path::PathBuf::from("/tmp/inbox")),
            Some(std::path::PathBuf::from("/tmp/outbound")),
        );
        let scope = configured_scope(&args);
        assert_eq!(
            scope.input,
            xenia_operator_proto::ConsentInputScope::RemoteInputInjection
        );
        assert_eq!(
            scope.clipboard,
            xenia_operator_proto::ConsentClipboardScope::Bidirectional
        );
        assert_eq!(
            scope.file_transfer,
            xenia_operator_proto::ConsentFileTransferScope::Bidirectional
        );

        let one_way = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::HostToViewer,
            None,
            Some(std::path::PathBuf::from("/tmp/outbound")),
        );
        let scope = configured_scope(&one_way);
        assert_eq!(
            scope.clipboard,
            xenia_operator_proto::ConsentClipboardScope::HostToViewer
        );
        assert_eq!(
            scope.file_transfer,
            xenia_operator_proto::ConsentFileTransferScope::HostToViewer
        );
    }
}
