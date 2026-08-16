// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

/// `xenia-peer` — headless daemon that hosts a Xenia session.
use clap::{Parser, ValueEnum};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
        NegotiatedTransport, negotiated_session_context_hash_with_profiles,
        perform_host_handshake_with_transcript_and_context,
    },
    transport::{
        GRACEFUL_CLOSE_TIMEOUT_MS, RecvEnvelope, SendEnvelope, TcpRecvHalf, TcpSendHalf,
        TcpTransport, Transport,
    },
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
// Consent-ledger maintenance ceremony modules ported from PR #99 (Phase 1 of
// a 4-phase re-derivation onto current main). Landed but NOT wired into the
// CLI dispatch yet -- that's Phase 2. Each is
// self-contained (verified: zero references to the scope-binding consent-
// action types or to m1_runtime.rs) and carries its own inline unit tests,
// so `#[allow(dead_code)]` here is scoped to "nothing calls this yet," not
// "this is unreviewed" -- see each module's own doc comment.
#[allow(dead_code)]
mod consent_artifact_paths;
// Phase 3 of the re-derivation: a real end-to-end test driving the full
// operator sequence through these same ceremony functions. See the
// module's own doc comment.
#[cfg(test)]
mod consent_ceremony_end_to_end_tests;
#[allow(dead_code)]
mod consent_compaction;
#[allow(dead_code)]
mod consent_final_destruction;
mod consent_ledger_persistence;
#[allow(dead_code)]
mod consent_maintenance;
#[allow(dead_code)]
mod consent_purge;
#[allow(dead_code)]
mod consent_purge_custody;
#[allow(dead_code)]
mod consent_purge_retention;
#[allow(dead_code)]
mod consent_retirement;
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

    /// Seconds a connected peer has to complete the handshake before the
    /// daemon drops it and accepts the next one.
    ///
    /// Availability control, not a performance knob: without a deadline here,
    /// a peer that connects and simply never sends its handshake response
    /// parks the daemon's single session slot forever (`read_exact` has no
    /// deadline of its own), which is a pre-auth denial of service costing
    /// the attacker one idle socket. See `THREAT_MODEL.md` §Availability.
    #[arg(long, default_value_t = 30)]
    handshake_timeout_secs: u64,

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

    /// Activated compacted consent-ledger state to use for normal daemon
    /// startup instead of `--consent-ledger-path`. The file contains the
    /// signed compaction cutover, archived replay/terminal indexes, current
    /// signed head, and resident suffix. It is fully verified before admin,
    /// consent, or viewer listeners are opened.
    #[arg(long, value_name = "FILE")]
    consent_ledger_compacted_state: Option<std::path::PathBuf>,

    /// Verify a compacted snapshot against its cold archive, atomically
    /// materialize an activated compacted state at FILE, and exit. This is the
    /// only operation that may create the initial active-state envelope;
    /// normal startup never trusts an unactivated snapshot directly.
    #[arg(
        long,
        value_name = "FILE",
        requires = "consent_ledger_activation_snapshot",
        conflicts_with_all = [
            "advance_consent_ledger_checkpoint",
            "export_consent_ledger_archive_segment",
            "export_consent_ledger_compaction_bundle",
            "verify_consent_ledger_compaction_bundle",
            "export_consent_ledger_compacted_snapshot",
            "verify_consent_ledger_compacted_snapshot",
            "advance_consent_ledger_compacted_state_pin",
            "export_consent_ledger_compaction_gc_certificate",
            "verify_consent_ledger_compaction_gc_certificate"
        ]
    )]
    activate_consent_ledger_compacted_state: Option<std::path::PathBuf>,

    /// Compacted snapshot input for
    /// `--activate-consent-ledger-compacted-state`.
    #[arg(
        long,
        value_name = "FILE",
        requires = "activate_consent_ledger_compacted_state"
    )]
    consent_ledger_activation_snapshot: Option<std::path::PathBuf>,

    /// Detailed cold archive segment used to verify compacted-state
    /// activation. Repeat in chronological order from genesis.
    #[arg(
        long,
        value_name = "FILE",
        requires = "activate_consent_ledger_compacted_state"
    )]
    consent_ledger_activation_archive_segment: Vec<std::path::PathBuf>,

    /// Independently retained signed compacted-state pin. During normal
    /// compacted startup, the active state must equal or cryptographically
    /// extend this pin before any listener opens.
    #[arg(long, value_name = "FILE", requires = "consent_ledger_compacted_state")]
    trusted_consent_ledger_compacted_state_pin: Option<std::path::PathBuf>,

    /// Atomically create or advance an independently retained compacted-state
    /// pin and exit. An existing pin is overwritten only after the current
    /// active state proves append-only extension from it.
    #[arg(
        long,
        value_name = "FILE",
        requires = "consent_ledger_compacted_state",
        conflicts_with_all = [
            "activate_consent_ledger_compacted_state",
            "export_consent_ledger_compaction_gc_certificate",
            "verify_consent_ledger_compaction_gc_certificate"
        ]
    )]
    advance_consent_ledger_compacted_state_pin: Option<std::path::PathBuf>,

    /// Cold archive segment used to certify or verify compaction
    /// garbage-collection readiness. Repeat in chronological order from
    /// genesis. The certificate is non-destructive and never deletes files.
    #[arg(long, value_name = "FILE")]
    consent_ledger_gc_archive_segment: Vec<std::path::PathBuf>,

    /// Export a signed, non-destructive garbage-collection readiness
    /// certificate and exit. Requires an activated compacted state, a retained
    /// state pin, and the complete cold archive represented by the activation.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = [
            "consent_ledger_compacted_state",
            "trusted_consent_ledger_compacted_state_pin"
        ],
        conflicts_with_all = [
            "activate_consent_ledger_compacted_state",
            "verify_consent_ledger_compaction_gc_certificate"
        ]
    )]
    export_consent_ledger_compaction_gc_certificate: Option<std::path::PathBuf>,

    /// Verify a signed garbage-collection readiness certificate and exit. This
    /// is a read-only proof check; no live or archived artifact is removed.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = [
            "consent_ledger_compacted_state",
            "trusted_consent_ledger_compacted_state_pin"
        ],
        conflicts_with_all = [
            "activate_consent_ledger_compacted_state",
            "export_consent_ledger_compaction_gc_certificate"
        ]
    )]
    verify_consent_ledger_compaction_gc_certificate: Option<std::path::PathBuf>,

    /// Signed GC-readiness certificate used as a prerequisite for explicit
    /// retirement planning or quarantine. This is an input artifact, not the
    /// read-only verification operation above.
    #[arg(long, value_name = "FILE")]
    consent_retirement_gc_certificate: Option<std::path::PathBuf>,

    /// Export a short-lived, ledger-signed plan for exact superseded artifact
    /// bytes. No file is moved or deleted by this operation.
    #[arg(long, value_name = "FILE")]
    export_consent_retirement_plan: Option<std::path::PathBuf>,

    /// Existing canonical directory under which a unique quarantine
    /// transaction directory will be created.
    #[arg(long, value_name = "DIR")]
    consent_retirement_quarantine_root: Option<std::path::PathBuf>,

    /// Superseded complete consent ledger to include in the retirement plan.
    /// Repeat only when multiple independently named complete-ledger copies are
    /// intentionally being retired.
    #[arg(long, value_name = "FILE")]
    consent_retirement_complete_ledger_candidate: Vec<std::path::PathBuf>,

    /// Superseded compaction-preflight bundle candidate. Repeat as needed.
    #[arg(long, value_name = "FILE")]
    consent_retirement_compaction_bundle_candidate: Vec<std::path::PathBuf>,

    /// Superseded compacted snapshot candidate. Repeat as needed.
    #[arg(long, value_name = "FILE")]
    consent_retirement_compacted_snapshot_candidate: Vec<std::path::PathBuf>,

    /// Maximum validity of a newly exported retirement plan.
    #[arg(long, default_value_t = 3600)]
    consent_retirement_plan_lifetime_secs: u64,

    /// Signed retirement plan input for approval, quarantine, recovery, or
    /// receipt verification.
    #[arg(long, value_name = "FILE")]
    consent_retirement_plan_input: Option<std::path::PathBuf>,

    /// Ledger Ed25519 public key used by independent retirement or purge
    /// approval, recovery, and receipt-verification operations. These
    /// operations do not require access to the ledger private key.
    #[arg(long, value_name = "HEX")]
    consent_retirement_ledger_public_key_hex: Option<String>,

    /// Add one independent retention-key approval to the approval bundle and
    /// exit. The key must already exist; this operation never generates it.
    #[arg(long)]
    sign_consent_retirement_plan: bool,

    /// Existing 32-byte Ed25519 witness seed used only by the one-shot
    /// retirement approval operation.
    #[arg(long, value_name = "FILE")]
    consent_retirement_witness_key: Option<std::path::PathBuf>,

    /// Retirement approval bundle input/output. The signing operation creates
    /// or appends to it; quarantine and recovery treat it as read-only.
    #[arg(long, value_name = "FILE")]
    consent_retirement_approval_bundle: Option<std::path::PathBuf>,

    /// Trusted independent retirement witness public key, as 64 hex
    /// characters. Repeat to configure the accepted trust set.
    #[arg(long, value_name = "HEX")]
    trusted_consent_retirement_witness_key_hex: Vec<String>,

    /// Minimum number of distinct trusted retirement approvals required.
    #[arg(long)]
    trusted_consent_retirement_witness_quorum: Option<usize>,

    /// Execute the signed plan by moving exact verified bytes into quarantine.
    /// No unlink is performed; a signed receipt and crash journal are written.
    #[arg(long)]
    quarantine_consent_retirement: bool,

    /// Recover one interrupted quarantine transaction. A valid signed receipt
    /// finalizes commit; otherwise moved files are restored from the journal.
    #[arg(long, value_name = "FILE")]
    recover_consent_retirement_journal: Option<std::path::PathBuf>,

    /// Verify a signed quarantine receipt and rehash every quarantined file.
    #[arg(long, value_name = "FILE")]
    verify_consent_retirement_receipt: Option<std::path::PathBuf>,

    /// Export a short-lived ledger-signed purge plan for exact aged
    /// quarantine bytes. This operation does not unlink anything.
    #[arg(long, value_name = "FILE")]
    export_consent_purge_plan: Option<std::path::PathBuf>,

    /// Existing private directory that will retain the complete rollback
    /// package after quarantine bytes are removed.
    #[arg(long, value_name = "DIR")]
    consent_purge_rollback_root: Option<std::path::PathBuf>,

    /// Minimum age of the signed quarantine receipt before a purge plan may be
    /// issued. The protocol minimum is 24 hours.
    #[arg(long, default_value_t = 7 * 24 * 60 * 60)]
    consent_purge_min_quarantine_age_secs: u64,

    /// Maximum validity of a newly exported purge plan.
    #[arg(long, default_value_t = 3600)]
    consent_purge_plan_lifetime_secs: u64,

    /// Original signed retirement plan that created the quarantine receipt.
    #[arg(long, value_name = "FILE")]
    consent_purge_retirement_plan_input: Option<std::path::PathBuf>,

    /// Original independent retirement approval bundle.
    #[arg(long, value_name = "FILE")]
    consent_purge_retirement_approval_bundle: Option<std::path::PathBuf>,

    /// Signed quarantine receipt whose exact files are eligible for purge.
    #[arg(long, value_name = "FILE")]
    consent_purge_quarantine_receipt: Option<std::path::PathBuf>,

    /// Signed purge plan input for approval, execution, recovery, or receipt
    /// verification.
    #[arg(long, value_name = "FILE")]
    consent_purge_plan_input: Option<std::path::PathBuf>,

    /// Add one independent purge-key approval and exit. This operation does not
    /// access the ledger private key.
    #[arg(long)]
    sign_consent_purge_plan: bool,

    /// Existing 32-byte Ed25519 seed used only for one purge approval.
    #[arg(long, value_name = "FILE")]
    consent_purge_witness_key: Option<std::path::PathBuf>,

    /// Purge approval bundle input/output.
    #[arg(long, value_name = "FILE")]
    consent_purge_approval_bundle: Option<std::path::PathBuf>,

    /// Trusted independent purge witness public key, as 64 hex characters.
    #[arg(long, value_name = "HEX")]
    trusted_consent_purge_witness_key_hex: Vec<String>,

    /// Minimum number of distinct trusted purge approvals required.
    #[arg(long)]
    trusted_consent_purge_witness_quorum: Option<usize>,

    /// Create and fsync a complete rollback package, then remove the exact
    /// quarantine files under a crash-audited journal.
    #[arg(long)]
    execute_consent_purge: bool,

    /// Recover an interrupted purge. Without a valid signed receipt, missing
    /// quarantine files are restored from the retained rollback package.
    #[arg(long, value_name = "FILE")]
    recover_consent_purge_journal: Option<std::path::PathBuf>,

    /// Verify a signed purge receipt, the retained rollback package, and the
    /// absence of every purged quarantine file.
    #[arg(long, value_name = "FILE")]
    verify_consent_purge_receipt: Option<std::path::PathBuf>,

    /// Export a ledger-signed obligation to retain the exact purge rollback
    /// package and its recovery metadata through a fixed deadline.
    #[arg(long, value_name = "FILE")]
    export_consent_purge_retention_certificate: Option<std::path::PathBuf>,

    /// Retention period beginning at purge completion. The protocol minimum is
    /// 24 hours; the operational default is 30 days.
    #[arg(long, default_value_t = 30 * 24 * 60 * 60)]
    consent_purge_retention_secs: u64,

    /// Signed purge receipt used to create the retention certificate.
    #[arg(long, value_name = "FILE")]
    consent_purge_receipt_input: Option<std::path::PathBuf>,

    /// Ledger-signed purge-retention certificate input.
    #[arg(long, value_name = "FILE")]
    consent_purge_retention_certificate_input: Option<std::path::PathBuf>,

    /// Add one independent observation to the retention-witness bundle.
    #[arg(long)]
    sign_consent_purge_retention_certificate: bool,

    /// Existing 32-byte Ed25519 seed used only to witness a retention
    /// certificate. The key must be distinct from ledger and purge witnesses.
    #[arg(long, value_name = "FILE")]
    consent_purge_retention_witness_key: Option<std::path::PathBuf>,

    /// Retention-witness bundle input/output.
    #[arg(long, value_name = "FILE")]
    consent_purge_retention_witness_bundle: Option<std::path::PathBuf>,

    /// Trusted independent retention-witness public key. Repeat to configure
    /// the accepted trust set.
    #[arg(long, value_name = "HEX")]
    trusted_consent_purge_retention_witness_key_hex: Vec<String>,

    /// Minimum number of distinct trusted retention witnesses required.
    #[arg(long)]
    trusted_consent_purge_retention_witness_quorum: Option<usize>,

    /// Export one compact ledger-signed anchor joining the retention
    /// certificate, witness quorum, and exact protected-file inventory.
    #[arg(long, value_name = "FILE")]
    export_consent_purge_retention_anchor: Option<std::path::PathBuf>,

    /// Verify an externally retained purge-retention anchor and rehash every
    /// protected rollback-package file.
    #[arg(long, value_name = "FILE")]
    verify_consent_purge_retention_anchor: Option<std::path::PathBuf>,

    /// Existing path that a future cleanup proposal wants to select. Repeat
    /// during anchor verification to prove every candidate is disjoint from
    /// the protected rollback package and all of its parent aliases.
    #[arg(
        long,
        value_name = "PATH",
        requires = "verify_consent_purge_retention_anchor"
    )]
    consent_purge_retention_candidate_check: Vec<std::path::PathBuf>,

    /// Existing retention anchor used as the immutable base for renewal,
    /// custody, or final-destruction readiness operations.
    #[arg(long, value_name = "FILE")]
    consent_purge_retention_anchor_input: Option<std::path::PathBuf>,

    /// Versioned monotonic retention-renewal chain input/output.
    #[arg(long, value_name = "FILE")]
    consent_purge_retention_renewal_chain: Option<std::path::PathBuf>,

    /// Append one ledger-signed retention renewal and exit.
    #[arg(long, value_name = "FILE")]
    export_consent_purge_retention_renewal: Option<std::path::PathBuf>,

    /// Additional seconds beyond the current effective retention deadline.
    #[arg(long, default_value_t = 30 * 24 * 60 * 60)]
    consent_purge_retention_renewal_secs: u64,

    /// Add one independently signed custody attestation and exit.
    #[arg(long)]
    sign_consent_purge_custody: bool,

    /// Existing 32-byte Ed25519 seed for one custody attestation.
    #[arg(long, value_name = "FILE")]
    consent_purge_custody_key: Option<std::path::PathBuf>,

    /// Custody bundle input/output.
    #[arg(long, value_name = "FILE")]
    consent_purge_custody_bundle: Option<std::path::PathBuf>,

    /// Custody assertion class: offline-media, remote-vault, or
    /// hardware-protected. This is an assertion by the custodian, not hardware
    /// attestation performed by Xenia.
    #[arg(long, value_name = "CLASS")]
    consent_purge_custody_class: Option<String>,

    /// Opaque custodian locator whose domain-separated digest is signed.
    #[arg(long, value_name = "LOCATOR")]
    consent_purge_custody_locator: Option<String>,

    /// Stable non-zero 128-bit replica identifier as 32 hex characters.
    #[arg(long, value_name = "HEX")]
    consent_purge_custody_replica_id_hex: Option<String>,

    /// Custodian availability interval beginning at observation time.
    #[arg(long, default_value_t = 90 * 24 * 60 * 60)]
    consent_purge_custody_available_secs: u64,

    /// Trusted independent custody public key. Repeat to configure the trust
    /// set used by final-destruction planning.
    #[arg(long, value_name = "HEX")]
    trusted_consent_purge_custody_key_hex: Vec<String>,

    /// Minimum distinct trusted custody attestations required.
    #[arg(long)]
    trusted_consent_purge_custody_quorum: Option<usize>,

    /// Export a short-lived ledger-signed plan covering the complete protected
    /// rollback inventory. This operation does not delete anything.
    #[arg(long, value_name = "FILE")]
    export_consent_final_destruction_plan: Option<std::path::PathBuf>,

    /// Maximum validity of a newly exported final-destruction plan.
    #[arg(long, default_value_t = 3600)]
    consent_final_destruction_plan_lifetime_secs: u64,

    /// Signed final-destruction plan input.
    #[arg(long, value_name = "FILE")]
    consent_final_destruction_plan_input: Option<std::path::PathBuf>,

    /// Add one independent final-destruction approval and exit.
    #[arg(long)]
    sign_consent_final_destruction_plan: bool,

    /// Existing 32-byte Ed25519 seed used only for final-destruction approval.
    #[arg(long, value_name = "FILE")]
    consent_final_destruction_witness_key: Option<std::path::PathBuf>,

    /// Final-destruction approval bundle input/output.
    #[arg(long, value_name = "FILE")]
    consent_final_destruction_approval_bundle: Option<std::path::PathBuf>,

    /// Trusted independent final-destruction witness public key.
    #[arg(long, value_name = "HEX")]
    trusted_consent_final_destruction_witness_key_hex: Vec<String>,

    /// Minimum distinct final-destruction approvals required.
    #[arg(long)]
    trusted_consent_final_destruction_witness_quorum: Option<usize>,

    /// Export a ledger-signed readiness artifact after all checks pass. This
    /// operation remains authorization-only and performs no deletion.
    #[arg(long, value_name = "FILE")]
    export_consent_final_destruction_readiness: Option<std::path::PathBuf>,

    /// Verify a retained final-destruction readiness artifact using only public
    /// keys and prerequisite evidence.
    #[arg(long, value_name = "FILE")]
    verify_consent_final_destruction_readiness: Option<std::path::PathBuf>,

    /// Independently retained signed checkpoint that the current consent
    /// ledger must contain as an exact prefix. Store this outside the daemon
    /// state directory or backup set being restored; otherwise an attacker can
    /// roll back the ledger and its local checkpoint together.
    #[arg(long, value_name = "FILE")]
    trusted_consent_ledger_checkpoint: Option<std::path::PathBuf>,

    /// Dual-signed old-key/new-key transition authorizing the currently loaded
    /// ledger as a fresh successor epoch to
    /// `--trusted-consent-ledger-checkpoint`. Without this artifact, retained
    /// checkpoints must be exact prefixes under the current ledger key.
    #[arg(
        long,
        value_name = "FILE",
        requires = "trusted_consent_ledger_checkpoint",
        conflicts_with = "trusted_consent_ledger_witness_bundle"
    )]
    trusted_consent_ledger_key_transition: Option<std::path::PathBuf>,

    /// Independently countersigned checkpoint bundle. The embedded checkpoint
    /// must be an exact prefix of the current ledger and satisfy the configured
    /// distinct trusted-witness quorum.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "trusted_consent_ledger_checkpoint"
    )]
    trusted_consent_ledger_witness_bundle: Option<std::path::PathBuf>,

    /// Trusted Ed25519 checkpoint-witness public key, encoded as 64 lowercase
    /// or uppercase hexadecimal characters. Repeat once per independent
    /// witness key.
    #[arg(
        long,
        value_name = "HEX",
        requires = "trusted_consent_ledger_witness_bundle"
    )]
    trusted_consent_ledger_witness_key_hex: Vec<String>,

    /// Minimum number of distinct trusted countersignatures required in the
    /// retained witness bundle. Defaults to one when a bundle is supplied.
    #[arg(
        long,
        value_name = "N",
        requires = "trusted_consent_ledger_witness_bundle"
    )]
    trusted_consent_ledger_witness_quorum: Option<usize>,

    /// Optional maximum age, in seconds, for a direct retained checkpoint or
    /// witnessed checkpoint. Key-transition anchors are historical by design
    /// and cannot be combined with this freshness SLA.
    #[arg(long, value_name = "SECONDS")]
    trusted_consent_ledger_checkpoint_max_age_secs: Option<u64>,

    /// Maximum positive clock skew accepted for retained checkpoint timestamps.
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    trusted_consent_ledger_checkpoint_max_future_skew_secs: u64,

    /// Atomically create or advance an independently stored consent-ledger
    /// checkpoint and exit. An existing checkpoint is overwritten only when
    /// the current verified ledger contains it as an exact prefix.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "export_consent_ledger_archive_segment"
    )]
    advance_consent_ledger_checkpoint: Option<std::path::PathBuf>,

    /// Export a bounded, verifiable JSON archive segment and exit. This does
    /// not truncate the live ledger. Compaction preflight bundles can now bind
    /// replay/recovery state, but live pruning remains intentionally disabled.
    #[arg(
        long,
        value_name = "FILE",
        requires = "consent_ledger_archive_base_checkpoint",
        conflicts_with = "advance_consent_ledger_checkpoint"
    )]
    export_consent_ledger_archive_segment: Option<std::path::PathBuf>,

    /// Signed checkpoint immediately before the first entry to include in
    /// `--export-consent-ledger-archive-segment`.
    #[arg(
        long,
        value_name = "FILE",
        requires = "export_consent_ledger_archive_segment"
    )]
    consent_ledger_archive_base_checkpoint: Option<std::path::PathBuf>,

    /// Export a non-destructive compaction preflight bundle and exit. The
    /// bundle embeds one or more verified archive segments, a deterministic
    /// replay/recovery summary, and a ledger-signed manifest binding both to
    /// the current live ledger head. No live entries are deleted.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = [
            "advance_consent_ledger_checkpoint",
            "export_consent_ledger_archive_segment",
            "verify_consent_ledger_compaction_bundle"
        ]
    )]
    export_consent_ledger_compaction_bundle: Option<std::path::PathBuf>,

    /// Verifiable archive segment to include in the compaction preflight
    /// bundle. Repeat in chronological order. The first segment must begin at
    /// genesis and the archived prefix must contain only completed ceremonies.
    #[arg(
        long,
        value_name = "FILE",
        requires = "export_consent_ledger_compaction_bundle"
    )]
    consent_ledger_compaction_archive_segment: Vec<std::path::PathBuf>,

    /// Verify an existing compaction preflight bundle against the complete
    /// current consent ledger and exit. This is a read-only verification gate.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = [
            "advance_consent_ledger_checkpoint",
            "export_consent_ledger_archive_segment",
            "export_consent_ledger_compaction_bundle"
        ]
    )]
    verify_consent_ledger_compaction_bundle: Option<std::path::PathBuf>,

    /// Export a minimal, non-destructive compacted restore snapshot and exit.
    /// The snapshot contains the authenticated recovery summary and only the
    /// live suffix after the archived boundary; the detailed archive remains a
    /// separate cold-storage artifact.
    #[arg(
        long,
        value_name = "FILE",
        requires = "consent_ledger_compaction_bundle_input",
        conflicts_with_all = [
            "advance_consent_ledger_checkpoint",
            "export_consent_ledger_archive_segment",
            "export_consent_ledger_compaction_bundle",
            "verify_consent_ledger_compaction_bundle",
            "verify_consent_ledger_compacted_snapshot"
        ]
    )]
    export_consent_ledger_compacted_snapshot: Option<std::path::PathBuf>,

    /// Previously verified compaction preflight bundle used to derive
    /// `--export-consent-ledger-compacted-snapshot`.
    #[arg(
        long,
        value_name = "FILE",
        requires = "export_consent_ledger_compacted_snapshot"
    )]
    consent_ledger_compaction_bundle_input: Option<std::path::PathBuf>,

    /// Verify a compacted restore snapshot against its detailed archive
    /// segments and exit. No live ledger file is replaced.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = [
            "advance_consent_ledger_checkpoint",
            "export_consent_ledger_archive_segment",
            "export_consent_ledger_compaction_bundle",
            "verify_consent_ledger_compaction_bundle",
            "export_consent_ledger_compacted_snapshot"
        ]
    )]
    verify_consent_ledger_compacted_snapshot: Option<std::path::PathBuf>,

    /// Detailed archive segment required to verify a compacted restore
    /// snapshot. Repeat in chronological order from genesis.
    #[arg(
        long,
        value_name = "FILE",
        requires = "verify_consent_ledger_compacted_snapshot"
    )]
    consent_ledger_compacted_snapshot_archive_segment: Vec<std::path::PathBuf>,

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
    /// `windows` injects via Win32 `SendInput` (requires the
    /// `windows-sendinput` build feature; Windows only). `macos`
    /// injects via CoreGraphics `CGEvent` (requires the
    /// `macos-cgevent` build feature; macOS only, and triggers the
    /// OS's own Accessibility permission prompt on first real use).
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

    /// Write logs to this file, in addition to stdout. If unset AND
    /// stdout isn't a terminal (e.g. launched by double-clicking the
    /// binary on Windows rather than from a console), falls back to
    /// `xenia-peer.log` next to the executable -- otherwise nothing
    /// durable would capture a crash or early error. Explicit stdout
    /// logging still happens either way; this only adds a file.
    #[arg(long)]
    log_file: Option<std::path::PathBuf>,
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
    #[cfg(all(feature = "windows-sendinput", target_os = "windows"))]
    Windows,
    #[cfg(all(feature = "macos-cgevent", target_os = "macos"))]
    Macos,
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
    fn transport_profile(&self) -> xenia_peer_core::transport::TransportProfileV1 {
        match self {
            AnyTransport::Tcp(t) => t.transport_profile(),
            AnyTransport::Ws(t) => t.transport_profile(),
            AnyTransport::Quic { transport, .. } => transport.transport_profile(),
        }
    }

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
        self.transport_profile().kind
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
            let _ = tokio::time::timeout(Duration::from_millis(GRACEFUL_CLOSE_TIMEOUT_MS), send.closed()).await;
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
    clipboard: ClipboardMode,
) -> Result<RawFrame, Box<dyn std::error::Error>> {
    xenia_peer_core::RawCapabilities {
        frame_id,
        timestamp_ms: now_ms(),
        audio: Some(audio),
        video_format,
        telemetry_enabled: telemetry_level != TelemetryLevel::Off,
        input_control_enabled: input_backend != InputBackendChoice::Noop,
        clipboard_enabled: clipboard != ClipboardMode::Off,
        input_event_schema_version: xenia_peer_core::frame::INPUT_EVENT_SCHEMA_VERSION,
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
        #[cfg(all(feature = "windows-sendinput", target_os = "windows"))]
        InputBackendChoice::Windows => {
            match xenia_inject::WindowsInjector::new(screen_width, screen_height) {
                Ok(injector) => Box::new(injector),
                Err(err) => {
                    warn!(
                        error = %err,
                        "WindowsInjector construction failed; input events will be discarded"
                    );
                    Box::new(NoopInjector)
                }
            }
        }
        #[cfg(all(feature = "macos-cgevent", target_os = "macos"))]
        InputBackendChoice::Macos => {
            match xenia_inject::MacosInjector::new(screen_width, screen_height) {
                Ok(injector) => Box::new(injector),
                Err(err) => {
                    warn!(
                        error = %err,
                        "MacosInjector construction failed; input events will be discarded"
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

/// Build this session's canonical, stable-format scope description --
/// digest-bound (`scope_digest`) into the signed consent-action transcript,
/// so this exact string (not operator/console free text -- the daemon is
/// the only thing that ever constructs it) is what the operator-agent's
/// broad-grant confirmation classifier (`scope_indicates_broad_grant`,
/// `xenia-operator-agent`) parses. Every field's wording is deliberately
/// fixed-format (`"label: value"`, `;`-joined) rather than free prose, so
/// that parsing is a stable keyword check, not fragile string-sniffing.
///
/// Previously covered only display/telemetry/audio -- silently omitting
/// input injection, clipboard, and file-transfer even though
/// `configured_permission_set` grants them. A confirmation dialog (or any
/// other operator-facing scope description) is only as trustworthy as the
/// text it shows; this was incomplete regardless of whether anything reads
/// it. Reuses `configured_permission_set` as the single source of truth for
/// which tiers this session's CLI config actually grants, rather than a
/// second, possibly-drifting description of the same flags.
fn m1_consent_scope(args: &Args) -> String {
    let telemetry = match args.telemetry_level {
        TelemetryLevel::Off => "telemetry: off",
        TelemetryLevel::Basic => "telemetry: basic host performance",
        TelemetryLevel::System => "telemetry: system identity and performance",
    };
    let audio = match args.audio {
        AudioMode::Off => "audio: off",
        AudioMode::Sine | AudioMode::Noise => "audio: synthetic test signal",
        AudioMode::Capture => "audio: host device capture",
    };
    let granted = configured_permission_set(args);
    let input = if granted.inject_input {
        "input: viewer may inject"
    } else {
        "input: off"
    };
    let clipboard = match (granted.read_host_clipboard, granted.write_host_clipboard) {
        (false, false) => "clipboard: off",
        (true, false) => "clipboard: host-to-viewer disclosure",
        (false, true) => "clipboard: viewer-to-host apply",
        (true, true) => "clipboard: bidirectional",
    };
    let file_transfer = match (
        granted.send_file_to_viewer,
        granted.receive_file_from_viewer,
    ) {
        (false, false) => "file-transfer: off",
        (true, false) => "file-transfer: host-to-viewer send",
        (false, true) => "file-transfer: viewer-to-host receive",
        (true, true) => "file-transfer: bidirectional",
    };
    format!("display: screen stream; {telemetry}; {audio}; {input}; {clipboard}; {file_transfer}")
}

/// Load an Ed25519 signing key from `path`, or generate and persist a fresh
/// one on first use. Uses `xenia_secure_file::load_or_create_secure_file`
/// for atomic, owner-only (`0600`) creation with no write-then-chmod window,
/// and TOCTOU-safe reads (parent directory and leaf file both opened
/// `O_NOFOLLOW`, checked owned by this process's uid, re-tightened to `0600`
/// on every access) -- see that crate's module doc comment for the full
/// reasoning. Was previously hand-rolled independently here; unified per
/// `docs/roadmap/POST_RC1_HARDENING_PLAN.md` Track 4.
fn load_or_create_signing_key(
    path: &std::path::Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let key_bytes = xenia_secure_file::load_or_create_secure_file(path, || {
        SigningKey::generate(&mut rand::thread_rng())
            .to_bytes()
            .to_vec()
    })?;
    Ok(SigningKey::from_bytes(
        &key_bytes.try_into().map_err(|_| "Invalid key length")?,
    ))
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
    let bytes = xenia_secure_file::load_or_create_secure_file(path, || {
        rand::random::<[u8; 32]>().to_vec()
    })?;
    bytes
        .try_into()
        .map_err(|_| "Invalid ML-DSA seed length".into())
}

/// Load the host's persistent signing identity from `path`, or generate and
/// persist a fresh one (0600) on first use. The file is a 64-byte blob:
/// 32-byte Ed25519 secret followed by a 32-byte ML-DSA-65 seed. Reconstructed
/// deterministically so the host's public identity (and fingerprint) is stable
/// across restarts -- the prerequisite for a viewer pinning it.
fn load_or_create_host_identity(
    path: &std::path::Path,
) -> Result<HandshakeManager, Box<dyn std::error::Error>> {
    let blob = xenia_secure_file::load_or_create_secure_file(path, || {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob
    })?;
    if blob.len() != 64 {
        return Err("host identity file must be exactly 64 bytes".into());
    }
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
    let blob = xenia_secure_file::load_or_create_secure_file(path, || {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob
    })?;
    if blob.len() != 64 {
        return Err("host identity file must be exactly 64 bytes".into());
    }
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

/// Derive the consent tiers to grant from the operator's configured flags.
///
/// A single Approve should authorize only what the operator actually turned
/// on: frame streaming is the daemon's core purpose and always granted, but
/// input injection, clipboard, and file transfer are each unlocked only when
/// their backing flag is enabled -- and clipboard/file-transfer are each
/// unlocked per-direction, not as one combined flag, so e.g. `--send-file`
/// alone does not also silently authorize accepting viewer-offered files.
/// This keeps an approval from silently authorizing capabilities the daemon
/// isn't even wired to use.
fn configured_permission_set(args: &Args) -> M1PermissionSet {
    M1PermissionSet {
        stream_frame: true,
        stream_telemetry: args.telemetry_level != TelemetryLevel::Off,
        stream_audio: args.audio != AudioMode::Off,
        inject_input: args.input_backend != InputBackendChoice::Noop,
        read_host_clipboard: args.clipboard != ClipboardMode::Off,
        write_host_clipboard: args.clipboard == ClipboardMode::Bidirectional,
        send_file_to_viewer: args.send_file.is_some(),
        receive_file_from_viewer: args.recv_file_dir.is_some(),
    }
}

/// A decoded consent-socket decision: the action to apply, plus the operator
/// attribution when it came in authenticated (drives the Phase 4 audit entry).
struct DecodedConsent {
    action: crate::operator_auth::ConsentAction,
    authorized: Option<crate::operator_auth::AuthorizedConsentAction>,
}

/// Decode a consent-socket message into a decision. With operator auth off,
/// this is the legacy plain-text `Approve`/`Deny`/`Revoke`. With it on, the
/// message must be a signed `AuthenticatedConsentAction` from an enrolled
/// operator whose role permits the action -- anything else is refused (logged
/// and dropped), so an unauthenticated socket can no longer decide consent.
fn decode_consent_decision(
    text: &str,
    require_operator_auth: bool,
    auth_state: &crate::operator_http::OperatorAuthState,
    session_id: &[u8; 16],
    scope_digest: &[u8; 32],
    revocations: &crate::operator_revocations::OperatorRevocations,
) -> Option<DecodedConsent> {
    if !require_operator_auth {
        let action = match text {
            "Approve" => crate::operator_auth::ConsentAction::Approve,
            "Deny" => crate::operator_auth::ConsentAction::Deny,
            "Revoke" => crate::operator_auth::ConsentAction::Revoke,
            other => {
                info!(text = other, "ignoring unrecognized consent message");
                return None;
            }
        };
        return Some(DecodedConsent {
            action,
            authorized: None,
        });
    }

    let request = match crate::operator_http::parse_authenticated_consent_action(text) {
        Ok(request) => request,
        Err(err) => {
            warn!(error = %err, "malformed authenticated consent action; refused");
            return None;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match crate::operator_auth::authorize_consent_action(
        &auth_state.policy,
        &auth_state.daemon_key.verifying_key(),
        &auth_state.daemon_ml_dsa.public_key_bytes(),
        now,
        session_id,
        scope_digest,
        &request,
    ) {
        Ok(authorized) => {
            // A token is dead the moment its operator is revoked, even if the
            // token itself is still unexpired and correctly signed. This closes
            // the plaintext-consent path (the sealed channel already refuses a
            // revoked operator at the handshake).
            if revocations.is_revoked(&authorized.operator_id) {
                warn!(operator = %authorized.operator_id, "consent action refused: operator revoked");
                return None;
            }
            info!(
                operator = %authorized.operator_id,
                role = ?authorized.role,
                action = ?authorized.action,
                "authenticated consent action authorized"
            );
            Some(DecodedConsent {
                action: authorized.action,
                authorized: Some(authorized),
            })
        }
        Err(err) => {
            warn!(error = %err, "consent action refused by operator auth");
            None
        }
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
            let Some(kind) = synthetic_audio_kind(mode) else {
                return Err("synthetic audio mode did not resolve to a source kind".into());
            };
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

/// Candidate log-file paths to try opening, in priority order.
///
/// An explicit `--log-file` is never substituted -- a path the user asked
/// for that fails to open is a configuration error worth surfacing, not
/// something to silently relocate. Otherwise, if stdout is a terminal, no
/// candidates at all (unchanged pre-existing stdout-only behavior). If
/// stdout isn't a terminal (the double-click-launch case, where nothing
/// would otherwise capture a crash or early error): first, next to the
/// running executable (the common per-user/unzipped-install case); then
/// the OS temp dir, which is a fallback and not the first choice only
/// because it's a shared, less discoverable location.
///
/// The temp-dir fallback exists because "next to the executable" alone
/// silently defeats this feature's whole purpose in a real, common
/// deployment shape: installed to a location the running process can't
/// write to (an unelevated install under `Program Files`, a distro
/// package's `/usr/bin`, this project's own Nix store build, any
/// immutable-filesystem deployment). Found by hand 2026-07-31 via a real
/// CI failure, not hypothesized: `checks.network-vm` runs `xenia-peer`
/// straight from a read-only `/nix/store` path, and the single-fallback
/// version of this function degraded all the way to stdout-only there --
/// exactly the "nothing captures it" scenario `--log-file` exists to
/// prevent, and no-terminal-attached to boot, so stdout output would have
/// gone nowhere either.
fn log_file_candidates(
    explicit: Option<&std::path::Path>,
    stdout_is_terminal: bool,
    exe_dir: Option<&std::path::Path>,
    temp_dir: &std::path::Path,
    file_name: &str,
) -> Vec<std::path::PathBuf> {
    if let Some(p) = explicit {
        return vec![p.to_path_buf()];
    }
    if stdout_is_terminal {
        return Vec::new();
    }
    [
        exe_dir.map(|dir| dir.join(file_name)),
        Some(temp_dir.join(file_name)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Set up tracing, always to stdout and optionally also to a file. See
/// [`log_file_candidates`] for the fallback chain `explicit = None`
/// resolves to.
///
/// Returns the non-blocking writer's flush guard; the caller must hold it
/// for the whole process lifetime (dropping it early stops the file
/// writer from flushing).
fn init_tracing(
    explicit: Option<&std::path::Path>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use std::io::IsTerminal;
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    let candidates = log_file_candidates(
        explicit,
        std::io::stdout().is_terminal(),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .as_deref(),
        &std::env::temp_dir(),
        "xenia-peer.log",
    );

    let mut failed = Vec::new();
    let mut opened = None;
    for path in candidates {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => {
                opened = Some(file);
                break;
            }
            Err(err) => failed.push(format!("{} ({err})", path.display())),
        }
    }

    let Some(file) = opened else {
        if !failed.is_empty() {
            eprintln!(
                "warning: could not open a log file, tried: {}; logging to stdout only",
                failed.join("; ")
            );
        }
        tracing_subscriber::fmt::init();
        return None;
    };
    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    tracing_subscriber::fmt()
        .with_writer(std::io::stdout.and(non_blocking))
        .init();
    Some(guard)
}

#[cfg(test)]
mod log_file_candidate_tests {
    use super::*;

    #[test]
    fn explicit_path_is_the_only_candidate_regardless_of_terminal_or_dirs() {
        let explicit = std::path::Path::new("/explicit/path.log");
        for stdout_is_terminal in [true, false] {
            let got = log_file_candidates(
                Some(explicit),
                stdout_is_terminal,
                Some(std::path::Path::new("/exe/dir")),
                std::path::Path::new("/tmp"),
                "xenia-peer.log",
            );
            assert_eq!(got, vec![explicit.to_path_buf()]);
        }
    }

    #[test]
    fn terminal_attached_with_no_explicit_path_yields_no_candidates() {
        let got = log_file_candidates(
            None,
            true,
            Some(std::path::Path::new("/exe/dir")),
            std::path::Path::new("/tmp"),
            "xenia-peer.log",
        );
        assert!(
            got.is_empty(),
            "a terminal-attached run must stay stdout-only"
        );
    }

    #[test]
    fn no_terminal_tries_exe_dir_then_temp_dir_in_order() {
        let got = log_file_candidates(
            None,
            false,
            Some(std::path::Path::new("/exe/dir")),
            std::path::Path::new("/tmp"),
            "xenia-peer.log",
        );
        assert_eq!(
            got,
            vec![
                std::path::PathBuf::from("/exe/dir/xenia-peer.log"),
                std::path::PathBuf::from("/tmp/xenia-peer.log"),
            ],
            "exe-dir candidate must be tried before the temp-dir fallback"
        );
    }

    #[test]
    fn no_terminal_and_no_exe_dir_still_falls_back_to_temp_dir() {
        // current_exe()/its parent can fail to resolve in principle -- the
        // temp-dir fallback must not depend on it succeeding.
        let got = log_file_candidates(
            None,
            false,
            None,
            std::path::Path::new("/tmp"),
            "xenia-peer.log",
        );
        assert_eq!(got, vec![std::path::PathBuf::from("/tmp/xenia-peer.log")]);
    }
}

// Consent-ledger maintenance ceremony helpers (Phase 2 of the PR #99
// re-derivation: witness-policy parsing, key-separation guards, artifact
// readers, and the existing-signing-key loader the ceremony operations
// below use -- unlike the daemon's own load_or_create_signing_key, this
// fails if the key is absent rather than generating one, since a
// ceremony must use an operator-provided identity, never a freshly
// minted one.
fn parse_ed25519_public_key_hex(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim()).map_err(|err| err.to_string())?;
    bytes.try_into().map_err(|_| {
        "Ed25519 public key must be exactly 32 bytes (64 hexadecimal characters)".to_string()
    })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn read_consent_archive_segments(
    paths: &[std::path::PathBuf],
    label: &str,
) -> Result<Vec<xenia_ledger::LedgerArchiveSegment>, Box<dyn std::error::Error>> {
    if paths.is_empty() {
        return Err(format!("{label} requires at least one archive segment").into());
    }
    if paths.len() > xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS {
        return Err(format!(
            "{label} has {} archive segments; maximum is {}",
            paths.len(),
            xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
        )
        .into());
    }
    let mut segments = Vec::with_capacity(paths.len());
    let mut aggregate_bytes = 0u64;
    for path in paths {
        let remaining =
            consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES.saturating_sub(aggregate_bytes);
        let (segment, bytes) = audit_ledger_store::read_bounded_json_with_size(
            path, remaining, label,
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("failed to read {label} {}: {err}", path.display()).into()
        })?;
        aggregate_bytes =
            aggregate_bytes
                .checked_add(bytes)
                .ok_or_else(|| -> Box<dyn std::error::Error> {
                    format!("{label} aggregate byte count overflow").into()
                })?;
        if aggregate_bytes > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
            return Err(format!(
                "{label} inputs exceed {} bytes",
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
            )
            .into());
        }
        segments.push(segment);
    }
    Ok(segments)
}

fn persist_json_owner_only<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
    maximum_bytes: u64,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!(
            "serialized {label} is {} bytes; maximum is {maximum_bytes}",
            bytes.len()
        )
        .into());
    }
    audit_ledger_store::persist_owner_only_atomic(path, &bytes)
        .map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })
}

struct ConsentRetirementEvidence {
    active: consent_compaction::ConsentCompactedActiveStateV1,
    pin: consent_compaction::ConsentCompactedStatePinV1,
    certificate: consent_compaction::ConsentCompactionGcCertificateV1,
    archive_segments: Vec<xenia_ledger::LedgerArchiveSegment>,
    protected_paths: Vec<std::path::PathBuf>,
}

fn load_consent_retirement_evidence(
    args: &Args,
    signing_key: &SigningKey,
) -> Result<ConsentRetirementEvidence, Box<dyn std::error::Error>> {
    let state_path = args
        .consent_ledger_compacted_state
        .as_deref()
        .ok_or("consent retirement requires --consent-ledger-compacted-state")?;
    let pin_path = args
        .trusted_consent_ledger_compacted_state_pin
        .as_deref()
        .ok_or("consent retirement requires --trusted-consent-ledger-compacted-state-pin")?;
    let certificate_path = args
        .consent_retirement_gc_certificate
        .as_deref()
        .ok_or("consent retirement requires --consent-retirement-gc-certificate")?;
    let (active, _) =
        crate::consent_ledger_persistence::load_compacted_active_state(state_path, signing_key)?;
    let pin: consent_compaction::ConsentCompactedStatePinV1 =
        audit_ledger_store::read_bounded_json(
            pin_path,
            audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
            "consent retirement retained compacted-state pin",
        )?;
    let certificate: consent_compaction::ConsentCompactionGcCertificateV1 =
        audit_ledger_store::read_bounded_json(
            certificate_path,
            audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
            "consent retirement GC certificate",
        )?;
    let archive_segments = read_consent_archive_segments(
        &args.consent_ledger_gc_archive_segment,
        "consent retirement cold archive",
    )?;
    certificate.verify(
        &active,
        &pin,
        &archive_segments,
        &signing_key.verifying_key(),
    )?;
    let mut protected_paths = vec![
        std::fs::canonicalize(state_path)?,
        std::fs::canonicalize(pin_path)?,
        std::fs::canonicalize(certificate_path)?,
        std::fs::canonicalize(&args.operator_key_path)?,
    ];
    for path in &args.consent_ledger_gc_archive_segment {
        protected_paths.push(std::fs::canonicalize(path)?);
    }
    Ok(ConsentRetirementEvidence {
        active,
        pin,
        certificate,
        archive_segments,
        protected_paths,
    })
}

fn load_existing_signing_key(
    path: &std::path::Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("required signing key does not exist: {}", path.display()).into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "required signing key must be a regular non-symlink file: {}",
            path.display()
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let bytes = std::fs::read(path)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        format!(
            "signing key {} must contain exactly 32 bytes",
            path.display()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn retirement_ledger_verifying_key(
    args: &Args,
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error>> {
    let value = args
        .consent_retirement_ledger_public_key_hex
        .as_deref()
        .ok_or("operation requires --consent-retirement-ledger-public-key-hex")?;
    let bytes = parse_ed25519_public_key_hex(value)
        .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "consent retirement ledger public key is not a valid Ed25519 key".into())
}

/// Trusted witness public keys and the minimum quorum of them required,
/// parsed from CLI args for one of the purge/retention/retirement ceremonies.
type WitnessPolicy = (Vec<[u8; 32]>, usize);

fn parse_retirement_witness_policy(
    args: &Args,
) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    if args.trusted_consent_retirement_witness_key_hex.is_empty() {
        return Err("retirement operation requires at least one --trusted-consent-retirement-witness-key-hex".into());
    }
    let keys = args
        .trusted_consent_retirement_witness_key_hex
        .iter()
        .map(|value| parse_ed25519_public_key_hex(value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("invalid trusted retirement witness key: {err}").into()
        })?;
    for key in &keys {
        ed25519_dalek::VerifyingKey::from_bytes(key).map_err(
            |_| -> Box<dyn std::error::Error> {
                "trusted retirement witness key is not a valid Ed25519 key".into()
            },
        )?;
    }
    if keys.len() > consent_retirement::MAX_RETIREMENT_APPROVALS {
        return Err(format!(
            "retirement witness trust set has {} keys; maximum is {}",
            keys.len(),
            consent_retirement::MAX_RETIREMENT_APPROVALS
        )
        .into());
    }
    let distinct = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != keys.len() {
        return Err("retirement witness trust set contains a duplicate key".into());
    }
    let quorum = args.trusted_consent_retirement_witness_quorum.unwrap_or(1);
    if quorum == 0 || quorum > keys.len() {
        return Err(format!(
            "retirement witness quorum {quorum} must be between 1 and {}",
            keys.len()
        )
        .into());
    }
    Ok((keys, quorum))
}

fn read_retirement_plan(
    path: &std::path::Path,
) -> Result<consent_retirement::ConsentRetirementPlanV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
        "consent retirement plan",
    )?)
}

fn read_retirement_approvals(
    path: &std::path::Path,
) -> Result<consent_retirement::ConsentRetirementApprovalBundleV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
        "consent retirement approval bundle",
    )?)
}

fn read_retirement_receipt(
    path: &std::path::Path,
) -> Result<consent_retirement::ConsentRetirementQuarantineReceiptV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
        "consent retirement quarantine receipt",
    )?)
}

fn read_purge_plan(
    path: &std::path::Path,
) -> Result<consent_purge::ConsentPurgePlanV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge::MAX_PURGE_TRANSACTION_BYTES,
        "consent purge plan",
    )?)
}

fn read_purge_approvals(
    path: &std::path::Path,
) -> Result<consent_purge::ConsentPurgeApprovalBundleV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge::MAX_PURGE_TRANSACTION_BYTES,
        "consent purge approval bundle",
    )?)
}

fn read_purge_receipt(
    path: &std::path::Path,
) -> Result<consent_purge::ConsentPurgeReceiptV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge::MAX_PURGE_TRANSACTION_BYTES,
        "consent purge receipt",
    )?)
}

fn read_purge_rollback_package(
    plan: &consent_purge::ConsentPurgePlanV1,
) -> Result<consent_purge::ConsentPurgeRollbackPackageV1, Box<dyn std::error::Error>> {
    let path = consent_purge::purge_transaction_directory(plan).join("rollback-package.json");
    Ok(audit_ledger_store::read_bounded_json(
        &path,
        consent_purge::MAX_PURGE_TRANSACTION_BYTES,
        "consent purge rollback package",
    )?)
}

fn read_purge_retention_certificate(
    path: &std::path::Path,
) -> Result<consent_purge_retention::ConsentPurgeRetentionCertificateV1, Box<dyn std::error::Error>>
{
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
        "consent purge retention certificate",
    )?)
}

fn read_purge_retention_witnesses(
    path: &std::path::Path,
) -> Result<consent_purge_retention::ConsentPurgeRetentionWitnessBundleV1, Box<dyn std::error::Error>>
{
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
        "consent purge retention witness bundle",
    )?)
}

fn read_purge_retention_anchor(
    path: &std::path::Path,
) -> Result<consent_purge_retention::ConsentPurgeRetentionAnchorV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
        "consent purge retention anchor",
    )?)
}

fn read_purge_retention_renewal_chain(
    path: &std::path::Path,
) -> Result<consent_purge_retention::ConsentPurgeRetentionRenewalChainV1, Box<dyn std::error::Error>>
{
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
        "consent purge retention renewal chain",
    )?)
}

fn read_purge_custody_bundle(
    path: &std::path::Path,
) -> Result<consent_purge_custody::ConsentPurgeCustodyBundleV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
        "consent purge custody bundle",
    )?)
}

fn read_final_destruction_plan(
    path: &std::path::Path,
) -> Result<consent_final_destruction::ConsentFinalDestructionPlanV1, Box<dyn std::error::Error>> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
        "consent final destruction plan",
    )?)
}

fn read_final_destruction_approvals(
    path: &std::path::Path,
) -> Result<
    consent_final_destruction::ConsentFinalDestructionApprovalBundleV1,
    Box<dyn std::error::Error>,
> {
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
        "consent final destruction approval bundle",
    )?)
}

fn read_final_destruction_readiness(
    path: &std::path::Path,
) -> Result<consent_final_destruction::ConsentFinalDestructionReadinessV1, Box<dyn std::error::Error>>
{
    Ok(audit_ledger_store::read_bounded_json(
        path,
        consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
        "consent final destruction readiness",
    )?)
}

fn parse_purge_retention_witness_policy(
    args: &Args,
) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    if args
        .trusted_consent_purge_retention_witness_key_hex
        .is_empty()
    {
        return Err("retention operation requires at least one --trusted-consent-purge-retention-witness-key-hex".into());
    }
    let keys = args
        .trusted_consent_purge_retention_witness_key_hex
        .iter()
        .map(|value| parse_ed25519_public_key_hex(value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("invalid trusted purge-retention witness key: {err}").into()
        })?;
    for key in &keys {
        ed25519_dalek::VerifyingKey::from_bytes(key).map_err(
            |_| -> Box<dyn std::error::Error> {
                "trusted purge-retention witness key is not a valid Ed25519 key".into()
            },
        )?;
    }
    if keys.len() > consent_purge_retention::MAX_PURGE_RETENTION_WITNESSES {
        return Err(format!(
            "purge-retention witness trust set has {} keys; maximum is {}",
            keys.len(),
            consent_purge_retention::MAX_PURGE_RETENTION_WITNESSES
        )
        .into());
    }
    let distinct = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != keys.len() {
        return Err("purge-retention witness trust set contains a duplicate key".into());
    }
    let quorum = args
        .trusted_consent_purge_retention_witness_quorum
        .unwrap_or(1);
    if quorum == 0 || quorum > keys.len() {
        return Err(format!(
            "purge-retention witness quorum {quorum} must be between 1 and {}",
            keys.len()
        )
        .into());
    }
    Ok((keys, quorum))
}

fn ensure_purge_retention_witness_separation(
    retention_keys: &[[u8; 32]],
    ledger_key: &[u8; 32],
    purge_approvals: &consent_purge::ConsentPurgeApprovalBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let purge_keys = purge_approvals
        .approvals
        .iter()
        .map(|approval| approval.witness_public_key)
        .collect::<std::collections::BTreeSet<_>>();
    if retention_keys.iter().any(|key| key == ledger_key) {
        return Err(
            "trusted purge-retention witness keys must be distinct from the ledger key".into(),
        );
    }
    if retention_keys.iter().any(|key| purge_keys.contains(key)) {
        return Err(
            "trusted purge-retention witness keys must be distinct from purge approval keys".into(),
        );
    }
    Ok(())
}

fn parse_distinct_trusted_key_policy(
    values: &[String],
    configured_quorum: Option<usize>,
    maximum: usize,
    label: &str,
) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    if values.is_empty() {
        return Err(format!("{label} requires at least one trusted public key").into());
    }
    let keys = values
        .iter()
        .map(|value| parse_ed25519_public_key_hex(value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("invalid {label} public key: {err}").into()
        })?;
    if keys.len() > maximum {
        return Err(format!("{label} has {} keys; maximum is {maximum}", keys.len()).into());
    }
    for key in &keys {
        ed25519_dalek::VerifyingKey::from_bytes(key)
            .map_err(|_| format!("{label} contains a malformed Ed25519 public key"))?;
    }
    let distinct = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != keys.len() {
        return Err(format!("{label} contains a duplicate key").into());
    }
    let quorum = configured_quorum.unwrap_or(1);
    if quorum == 0 || quorum > keys.len() {
        return Err(format!(
            "{label} quorum {quorum} must be between 1 and {}",
            keys.len()
        )
        .into());
    }
    Ok((keys, quorum))
}

fn parse_purge_custody_policy(args: &Args) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    parse_distinct_trusted_key_policy(
        &args.trusted_consent_purge_custody_key_hex,
        args.trusted_consent_purge_custody_quorum,
        consent_purge_custody::MAX_PURGE_CUSTODY_ATTESTATIONS,
        "purge custody policy",
    )
}

fn parse_final_destruction_policy(
    args: &Args,
) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    parse_distinct_trusted_key_policy(
        &args.trusted_consent_final_destruction_witness_key_hex,
        args.trusted_consent_final_destruction_witness_quorum,
        consent_final_destruction::MAX_FINAL_DESTRUCTION_APPROVALS,
        "final-destruction witness policy",
    )
}

fn parse_custody_class(
    value: &str,
) -> Result<consent_purge_custody::ConsentPurgeCustodyClassV1, Box<dyn std::error::Error>> {
    match value {
        "offline-media" => Ok(consent_purge_custody::ConsentPurgeCustodyClassV1::OfflineMedia),
        "remote-vault" => Ok(consent_purge_custody::ConsentPurgeCustodyClassV1::RemoteVault),
        "hardware-protected" => {
            Ok(consent_purge_custody::ConsentPurgeCustodyClassV1::HardwareProtected)
        }
        _ => Err("custody class must be offline-media, remote-vault, or hardware-protected".into()),
    }
}

fn parse_replica_id_hex(value: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let decoded = hex::decode(value)?;
    let replica_id: [u8; 16] = decoded
        .try_into()
        .map_err(|_| "custody replica id must contain exactly 16 bytes")?;
    if replica_id == [0u8; 16] {
        return Err("custody replica id cannot be all zeroes".into());
    }
    Ok(replica_id)
}

struct VerifiedRetentionContext {
    certificate: consent_purge_retention::ConsentPurgeRetentionCertificateV1,
    anchor: consent_purge_retention::ConsentPurgeRetentionAnchorV1,
    renewal_chain: consent_purge_retention::ConsentPurgeRetentionRenewalChainV1,
    subject: consent_purge_retention::ConsentPurgeRetentionSubjectV1,
    retention_witnesses: consent_purge_retention::ConsentPurgeRetentionWitnessBundleV1,
    purge_approvals: consent_purge::ConsentPurgeApprovalBundleV1,
    certificate_path: std::path::PathBuf,
    anchor_path: std::path::PathBuf,
    retention_witness_path: std::path::PathBuf,
    purge_approval_path: std::path::PathBuf,
    renewal_path: Option<std::path::PathBuf>,
}

impl VerifiedRetentionContext {
    fn protect_output(
        &self,
        output_path: &std::path::Path,
        additional_inputs: &[&std::path::Path],
        label: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut protected_inputs = vec![
            self.certificate_path.as_path(),
            self.anchor_path.as_path(),
            self.retention_witness_path.as_path(),
            self.purge_approval_path.as_path(),
        ];
        if let Some(path) = self.renewal_path.as_deref() {
            protected_inputs.push(path);
        }
        protected_inputs.extend_from_slice(additional_inputs);
        consent_artifact_paths::ensure_output_disjoint_from_inputs(
            output_path,
            &protected_inputs,
            Some(std::path::Path::new(&self.subject.package_directory)),
            label,
        )
    }
}

fn verified_retention_context(
    args: &Args,
    ledger_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<VerifiedRetentionContext, Box<dyn std::error::Error>> {
    let certificate_path = args
        .consent_purge_retention_certificate_input
        .as_deref()
        .ok_or("operation requires --consent-purge-retention-certificate-input")?;
    let anchor_path = args
        .consent_purge_retention_anchor_input
        .as_deref()
        .ok_or("operation requires --consent-purge-retention-anchor-input")?;
    let witness_bundle_path = args
        .consent_purge_retention_witness_bundle
        .as_deref()
        .ok_or("operation requires --consent-purge-retention-witness-bundle")?;
    let purge_approval_path = args
        .consent_purge_approval_bundle
        .as_deref()
        .ok_or("operation requires --consent-purge-approval-bundle")?;
    let certificate = read_purge_retention_certificate(certificate_path)?;
    let anchor = read_purge_retention_anchor(anchor_path)?;
    let retention_witnesses = read_purge_retention_witnesses(witness_bundle_path)?;
    let purge_approvals = read_purge_approvals(purge_approval_path)?;
    let (trusted_retention_keys, retention_quorum) = parse_purge_retention_witness_policy(args)?;
    ensure_purge_retention_witness_separation(
        &trusted_retention_keys,
        &ledger_public_key.to_bytes(),
        &purge_approvals,
    )?;
    anchor.verify(
        &certificate,
        &retention_witnesses,
        &trusted_retention_keys,
        retention_quorum,
        ledger_public_key,
        unix_now_secs(),
        consent_purge_retention::MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
    )?;
    let renewal_path = args.consent_purge_retention_renewal_chain.clone();
    let renewal_chain = if let Some(path) = renewal_path.as_deref() {
        read_purge_retention_renewal_chain(path)?
    } else {
        consent_purge_retention::ConsentPurgeRetentionRenewalChainV1::new(&certificate)?
    };
    renewal_chain.verify(&certificate, &anchor, ledger_public_key, unix_now_secs())?;
    let subject = consent_purge_retention::verify_retention_subject(
        &certificate,
        &anchor,
        &renewal_chain.renewals,
        ledger_public_key,
        unix_now_secs(),
    )?;
    Ok(VerifiedRetentionContext {
        certificate,
        anchor,
        renewal_chain,
        subject,
        retention_witnesses,
        purge_approvals,
        certificate_path: certificate_path.to_path_buf(),
        anchor_path: anchor_path.to_path_buf(),
        retention_witness_path: witness_bundle_path.to_path_buf(),
        purge_approval_path: purge_approval_path.to_path_buf(),
        renewal_path,
    })
}

fn ensure_custody_key_separation(
    custody_keys: &[[u8; 32]],
    ledger_key: &[u8; 32],
    retention_witnesses: &consent_purge_retention::ConsentPurgeRetentionWitnessBundleV1,
    purge_approvals: &consent_purge::ConsentPurgeApprovalBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let excluded = retention_witnesses
        .witnesses
        .iter()
        .map(|witness| witness.witness_public_key)
        .chain(
            purge_approvals
                .approvals
                .iter()
                .map(|approval| approval.witness_public_key),
        )
        .collect::<std::collections::BTreeSet<_>>();
    if custody_keys.iter().any(|key| key == ledger_key) {
        return Err("custody keys must be distinct from the ledger key".into());
    }
    if custody_keys.iter().any(|key| excluded.contains(key)) {
        return Err("custody keys must be distinct from purge and retention witness keys".into());
    }
    Ok(())
}

fn ensure_final_destruction_key_separation(
    destruction_keys: &[[u8; 32]],
    ledger_key: &[u8; 32],
    custody_bundle: &consent_purge_custody::ConsentPurgeCustodyBundleV1,
    retention_witnesses: &consent_purge_retention::ConsentPurgeRetentionWitnessBundleV1,
    purge_approvals: &consent_purge::ConsentPurgeApprovalBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let excluded = custody_bundle
        .attestations
        .iter()
        .map(|attestation| attestation.custodian_public_key)
        .chain(
            retention_witnesses
                .witnesses
                .iter()
                .map(|witness| witness.witness_public_key),
        )
        .chain(
            purge_approvals
                .approvals
                .iter()
                .map(|approval| approval.witness_public_key),
        )
        .collect::<std::collections::BTreeSet<_>>();
    if destruction_keys.iter().any(|key| key == ledger_key) {
        return Err("final-destruction witnesses must be distinct from the ledger key".into());
    }
    if destruction_keys.iter().any(|key| excluded.contains(key)) {
        return Err(
            "final-destruction witnesses must be distinct from purge, retention, and custody keys"
                .into(),
        );
    }
    Ok(())
}

fn parse_purge_witness_policy(args: &Args) -> Result<WitnessPolicy, Box<dyn std::error::Error>> {
    if args.trusted_consent_purge_witness_key_hex.is_empty() {
        return Err(
            "purge operation requires at least one --trusted-consent-purge-witness-key-hex".into(),
        );
    }
    let keys = args
        .trusted_consent_purge_witness_key_hex
        .iter()
        .map(|value| parse_ed25519_public_key_hex(value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("invalid trusted purge witness key: {err}").into()
        })?;
    for key in &keys {
        ed25519_dalek::VerifyingKey::from_bytes(key).map_err(
            |_| -> Box<dyn std::error::Error> {
                "trusted purge witness key is not a valid Ed25519 key".into()
            },
        )?;
    }
    if keys.len() > consent_purge::MAX_PURGE_APPROVALS {
        return Err(format!(
            "purge witness trust set has {} keys; maximum is {}",
            keys.len(),
            consent_purge::MAX_PURGE_APPROVALS
        )
        .into());
    }
    let distinct = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != keys.len() {
        return Err("purge witness trust set contains a duplicate key".into());
    }
    let quorum = args.trusted_consent_purge_witness_quorum.unwrap_or(1);
    if quorum == 0 || quorum > keys.len() {
        return Err(format!(
            "purge witness quorum {quorum} must be between 1 and {}",
            keys.len()
        )
        .into());
    }
    Ok((keys, quorum))
}

fn ensure_purge_witness_separation(
    purge_keys: &[[u8; 32]],
    ledger_key: &[u8; 32],
    retirement_approvals: &consent_retirement::ConsentRetirementApprovalBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let retirement_keys = retirement_approvals
        .approvals
        .iter()
        .map(|approval| approval.witness_public_key)
        .collect::<std::collections::BTreeSet<_>>();
    if purge_keys.iter().any(|key| key == ledger_key) {
        return Err("trusted purge witness keys must be distinct from the ledger key".into());
    }
    if purge_keys.iter().any(|key| retirement_keys.contains(key)) {
        return Err(
            "trusted purge witness keys must be distinct from retirement approval keys".into(),
        );
    }
    Ok(())
}

fn ensure_retirement_candidates_are_unprotected(
    plan: &consent_retirement::ConsentRetirementPlanV1,
    protected_paths: &[std::path::PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let quarantine_root = std::path::Path::new(&plan.quarantine_root);
    for candidate in &plan.candidates {
        let canonical = std::fs::canonicalize(&candidate.canonical_path)?;
        if protected_paths
            .iter()
            .any(|protected| protected == &canonical)
        {
            return Err(format!(
                "retirement candidate aliases a protected artifact: {}",
                canonical.display()
            )
            .into());
        }
        if canonical.starts_with(quarantine_root) {
            return Err(format!(
                "retirement candidate is already inside the quarantine root: {}",
                canonical.display()
            )
            .into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Held for main()'s whole lifetime -- dropping it early would stop the
    // non-blocking file writer from flushing. `_` alone would drop it
    // immediately after this statement.
    let _log_guard = init_tracing(args.log_file.as_deref());

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

    // The session listener had no exposure guard at all until 2026-07-28,
    // only the operator surface above did. Unlike that surface this one is
    // reachable pre-authentication by design (a viewer has to connect before
    // it can handshake), so the warning is about availability rather than
    // forgery: --handshake-timeout-secs is what keeps an unauthenticated peer
    // from parking the single session slot. See THREAT_MODEL.md §Availability.
    if !crate::operator_exposure::is_loopback_listen_addr(&args.listen) {
        tracing::warn!(
            listen = %args.listen,
            handshake_timeout_secs = args.handshake_timeout_secs,
            "session listener bound to a NON-loopback address — any host that can reach it \
             can occupy the accept path until the handshake deadline expires. Restrict it at \
             the network layer if this host isn't meant to accept viewers from anywhere."
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

    // Consent-ledger maintenance ceremony dispatch (Phase 2 of the PR #99
    // re-derivation): a mutually-exclusive one-shot operation selected by
    // consent_maintenance::validate_one_shot_selection, covering five
    // families (retirement/purge/purge-retention/purge-custody/final-
    // destruction). Deliberately NOT wiring the sixth family from PR #99
    // (ledger-maintenance: activate/advance-pin/gc-certificate/checkpoint/
    // archive-segment/compaction-bundle/compacted-snapshot ops) here -- those
    // operate on the live daemon's already-loaded ledger and signing key
    // rather than purely on operator-supplied files, a different and more
    // invasive integration surface than the other five, and deserve their
    // own dedicated pass rather than being rushed in alongside these.
    // Every branch below returns before the daemon's own signing-key load
    // (just below) or normal startup ever runs.
    // --- preamble ---
    let selected_one_shot = consent_maintenance::validate_one_shot_selection(&args)?;
    let selected_family = selected_one_shot.map(consent_maintenance::OneShotOperation::family);
    let retirement_operation_requested =
        selected_family == Some(consent_maintenance::OperationFamily::Retirement);
    let purge_operation_requested =
        selected_family == Some(consent_maintenance::OperationFamily::Purge);
    let purge_retention_operation_requested =
        selected_family == Some(consent_maintenance::OperationFamily::PurgeRetention);
    let purge_custody_operation_requested =
        selected_family == Some(consent_maintenance::OperationFamily::PurgeCustody);
    let final_destruction_operation_requested =
        selected_family == Some(consent_maintenance::OperationFamily::FinalDestruction);

    // --- retirement_sign ---
    if args.sign_consent_retirement_plan {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let plan_path = args
            .consent_retirement_plan_input
            .as_deref()
            .ok_or("--sign-consent-retirement-plan requires --consent-retirement-plan-input")?;
        let approval_path = args.consent_retirement_approval_bundle.as_deref().ok_or(
            "--sign-consent-retirement-plan requires --consent-retirement-approval-bundle",
        )?;
        let witness_key_path = args
            .consent_retirement_witness_key
            .as_deref()
            .ok_or("--sign-consent-retirement-plan requires --consent-retirement-witness-key")?;
        let plan = read_retirement_plan(plan_path)?;
        plan.verify_authority_signature_and_window(&ledger_public_key, unix_now_secs())?;
        let witness_key = load_existing_signing_key(witness_key_path)?;
        if witness_key.verifying_key() == ledger_public_key {
            return Err(
                "retirement witness key must be distinct from the ledger signing key".into(),
            );
        }
        let mut approvals = if approval_path.exists() {
            let existing = read_retirement_approvals(approval_path)?;
            if !existing.approvals.is_empty() {
                let observed_keys = existing
                    .approvals
                    .iter()
                    .map(|approval| approval.witness_public_key)
                    .collect::<Vec<_>>();
                existing.verify_quorum(&plan, &observed_keys, observed_keys.len())?;
            }
            existing
        } else {
            consent_retirement::ConsentRetirementApprovalBundleV1::new(&plan)?
        };
        approvals.sign_with(&plan, &witness_key, unix_now_secs())?;
        let normalized_output = consent_artifact_paths::normalized_output_path(approval_path)?;
        if normalized_output == consent_artifact_paths::normalized_output_path(plan_path)?
            || normalized_output == std::fs::canonicalize(witness_key_path)?
            || normalized_output.starts_with(std::path::Path::new(&plan.quarantine_root))
            || plan.candidates.iter().any(|candidate| {
                std::path::Path::new(&candidate.canonical_path) == normalized_output.as_path()
            })
        {
            return Err("retirement approval output aliases a protected input or candidate".into());
        }
        persist_json_owner_only(
            approval_path,
            &approvals,
            consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
            "consent retirement approval bundle",
        )?;
        println!("consent retirement approval added");
        println!("path: {}", approval_path.display());
        println!(
            "witness public key: {}",
            hex::encode(witness_key.verifying_key().to_bytes())
        );
        println!("approval count: {}", approvals.approvals.len());
        println!("the ledger private key was not accessed");
        println!("no artifact was moved or deleted");
        return Ok(());
    }

    // --- retirement_recover ---
    if let Some(journal_path) = args.recover_consent_retirement_journal.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let plan_path = args.consent_retirement_plan_input.as_deref().ok_or(
            "--recover-consent-retirement-journal requires --consent-retirement-plan-input",
        )?;
        let approval_path = args.consent_retirement_approval_bundle.as_deref().ok_or(
            "--recover-consent-retirement-journal requires --consent-retirement-approval-bundle",
        )?;
        let plan = read_retirement_plan(plan_path)?;
        let approvals = read_retirement_approvals(approval_path)?;
        let (trusted_witness_keys, quorum) = parse_retirement_witness_policy(&args)?;
        if trusted_witness_keys
            .iter()
            .any(|key| *key == ledger_public_key.to_bytes())
        {
            return Err(
                "trusted retirement witness keys must be distinct from the ledger key".into(),
            );
        }
        let outcome = consent_retirement::recover_retirement_transaction(
            journal_path,
            &plan,
            &approvals,
            &trusted_witness_keys,
            quorum,
            &ledger_public_key,
            unix_now_secs(),
        )?;
        let outcome_label = match outcome {
            consent_retirement::ConsentRetirementRecoveryOutcomeV1::FinalizedCommitted => {
                "finalized committed transaction"
            }
            consent_retirement::ConsentRetirementRecoveryOutcomeV1::RolledBack => {
                "rolled back incomplete transaction"
            }
            consent_retirement::ConsentRetirementRecoveryOutcomeV1::AlreadyCommitted => {
                "transaction already committed"
            }
            consent_retirement::ConsentRetirementRecoveryOutcomeV1::AlreadyRolledBack => {
                "transaction already rolled back"
            }
        };
        println!("consent retirement recovery: {outcome_label}");
        println!("journal: {}", journal_path.display());
        println!("the ledger private key was not accessed");
        println!("no artifact was unlinked");
        return Ok(());
    }

    // --- retirement_verify ---
    if let Some(receipt_path) = args.verify_consent_retirement_receipt.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let plan_path = args.consent_retirement_plan_input.as_deref().ok_or(
            "--verify-consent-retirement-receipt requires --consent-retirement-plan-input",
        )?;
        let approval_path = args.consent_retirement_approval_bundle.as_deref().ok_or(
            "--verify-consent-retirement-receipt requires --consent-retirement-approval-bundle",
        )?;
        let plan = read_retirement_plan(plan_path)?;
        let approvals = read_retirement_approvals(approval_path)?;
        let (trusted_witness_keys, quorum) = parse_retirement_witness_policy(&args)?;
        if trusted_witness_keys
            .iter()
            .any(|key| *key == ledger_public_key.to_bytes())
        {
            return Err(
                "trusted retirement witness keys must be distinct from the ledger key".into(),
            );
        }
        plan.verify_authority_signature(&ledger_public_key)?;
        approvals.verify_quorum(&plan, &trusted_witness_keys, quorum)?;
        let receipt: consent_retirement::ConsentRetirementQuarantineReceiptV1 =
            audit_ledger_store::read_bounded_json(
                receipt_path,
                consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
                "consent retirement quarantine receipt",
            )?;
        receipt.verify(&plan, &approvals, &ledger_public_key)?;
        consent_retirement::verify_quarantined_receipt_files(&receipt)?;
        println!("consent retirement quarantine receipt verified");
        println!("path: {}", receipt_path.display());
        println!("artifacts: {}", receipt.entries.len());
        println!("the ledger private key was not accessed");
        println!("no artifact was unlinked");
        return Ok(());
    }

    // --- purge_sign ---
    if args.sign_consent_purge_plan {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--sign-consent-purge-plan requires --consent-purge-plan-input")?;
        let approval_path = args
            .consent_purge_approval_bundle
            .as_deref()
            .ok_or("--sign-consent-purge-plan requires --consent-purge-approval-bundle")?;
        let witness_key_path = args
            .consent_purge_witness_key
            .as_deref()
            .ok_or("--sign-consent-purge-plan requires --consent-purge-witness-key")?;
        let retirement_plan_path = args
            .consent_purge_retirement_plan_input
            .as_deref()
            .ok_or("--sign-consent-purge-plan requires --consent-purge-retirement-plan-input")?;
        let retirement_approval_path = args
            .consent_purge_retirement_approval_bundle
            .as_deref()
            .ok_or(
                "--sign-consent-purge-plan requires --consent-purge-retirement-approval-bundle",
            )?;
        let quarantine_receipt_path = args
            .consent_purge_quarantine_receipt
            .as_deref()
            .ok_or("--sign-consent-purge-plan requires --consent-purge-quarantine-receipt")?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let retirement_plan = read_retirement_plan(retirement_plan_path)?;
        let retirement_approvals = read_retirement_approvals(retirement_approval_path)?;
        let quarantine_receipt = read_retirement_receipt(quarantine_receipt_path)?;
        purge_plan.verify_authority_signature_and_window(&ledger_public_key, unix_now_secs())?;
        consent_purge::verify_purge_prerequisite_identity(
            &purge_plan,
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            &ledger_public_key,
        )?;
        let witness_key = load_existing_signing_key(witness_key_path)?;
        if witness_key.verifying_key() == ledger_public_key
            || retirement_approvals.approvals.iter().any(|approval| {
                approval.witness_public_key == witness_key.verifying_key().to_bytes()
            })
        {
            return Err(
                "purge witness key must be distinct from the ledger and retirement witness keys"
                    .into(),
            );
        }
        let mut approvals = if approval_path.exists() {
            let existing = read_purge_approvals(approval_path)?;
            if !existing.approvals.is_empty() {
                let observed = existing
                    .approvals
                    .iter()
                    .map(|approval| approval.witness_public_key)
                    .collect::<Vec<_>>();
                existing.verify_quorum(&purge_plan, &observed, observed.len())?;
            }
            existing
        } else {
            consent_purge::ConsentPurgeApprovalBundleV1::new(&purge_plan)?
        };
        approvals.sign_with(&purge_plan, &witness_key, unix_now_secs())?;
        let normalized_output = consent_artifact_paths::normalized_output_path(approval_path)?;
        if normalized_output == consent_artifact_paths::normalized_output_path(purge_plan_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(retirement_plan_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(retirement_approval_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(quarantine_receipt_path)?
            || normalized_output == std::fs::canonicalize(witness_key_path)?
            || normalized_output.starts_with(std::path::Path::new(&purge_plan.rollback_root))
            || normalized_output.starts_with(std::path::Path::new(
                &purge_plan.quarantine_transaction_directory,
            ))
            || purge_plan.candidates.iter().any(|candidate| {
                std::path::Path::new(&candidate.quarantine_path) == normalized_output.as_path()
                    || std::path::Path::new(&candidate.rollback_path) == normalized_output.as_path()
            })
        {
            return Err("purge approval output aliases a protected input or artifact".into());
        }
        persist_json_owner_only(
            approval_path,
            &approvals,
            consent_purge::MAX_PURGE_TRANSACTION_BYTES,
            "consent purge approval bundle",
        )?;
        println!("consent purge approval added");
        println!("path: {}", approval_path.display());
        println!(
            "witness public key: {}",
            hex::encode(witness_key.verifying_key().to_bytes())
        );
        println!("approval count: {}", approvals.approvals.len());
        println!("the ledger private key was not accessed");
        println!("no artifact was removed");
        return Ok(());
    }

    // --- purge_recover ---
    if let Some(journal_path) = args.recover_consent_purge_journal.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--recover-consent-purge-journal requires --consent-purge-plan-input")?;
        let purge_approval_path = args
            .consent_purge_approval_bundle
            .as_deref()
            .ok_or("--recover-consent-purge-journal requires --consent-purge-approval-bundle")?;
        let retirement_plan_path = args.consent_purge_retirement_plan_input.as_deref().ok_or(
            "--recover-consent-purge-journal requires --consent-purge-retirement-plan-input",
        )?;
        let retirement_approval_path = args
            .consent_purge_retirement_approval_bundle
            .as_deref()
            .ok_or("--recover-consent-purge-journal requires --consent-purge-retirement-approval-bundle")?;
        let quarantine_receipt_path = args
            .consent_purge_quarantine_receipt
            .as_deref()
            .ok_or("--recover-consent-purge-journal requires --consent-purge-quarantine-receipt")?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let retirement_plan = read_retirement_plan(retirement_plan_path)?;
        let retirement_approvals = read_retirement_approvals(retirement_approval_path)?;
        let quarantine_receipt = read_retirement_receipt(quarantine_receipt_path)?;
        let (trusted_purge_keys, purge_quorum) = parse_purge_witness_policy(&args)?;
        ensure_purge_witness_separation(
            &trusted_purge_keys,
            &ledger_public_key.to_bytes(),
            &retirement_approvals,
        )?;
        let outcome = consent_purge::recover_consent_purge(
            journal_path,
            &purge_plan,
            &purge_approvals,
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            &trusted_purge_keys,
            purge_quorum,
            &ledger_public_key,
            unix_now_secs(),
        )?;
        let label = match outcome {
            consent_purge::ConsentPurgeRecoveryOutcomeV1::FinalizedCommitted => {
                "finalized committed purge"
            }
            consent_purge::ConsentPurgeRecoveryOutcomeV1::RolledBack => {
                "restored incomplete purge from rollback package"
            }
            consent_purge::ConsentPurgeRecoveryOutcomeV1::AlreadyCommitted => {
                "purge already committed"
            }
            consent_purge::ConsentPurgeRecoveryOutcomeV1::AlreadyRolledBack => {
                "purge already rolled back"
            }
        };
        println!("consent purge recovery: {label}");
        println!("journal: {}", journal_path.display());
        println!("the ledger private key was not accessed");
        println!("the rollback package was retained");
        return Ok(());
    }

    // --- purge_verify ---
    if let Some(receipt_path) = args.verify_consent_purge_receipt.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--verify-consent-purge-receipt requires --consent-purge-plan-input")?;
        let purge_approval_path = args
            .consent_purge_approval_bundle
            .as_deref()
            .ok_or("--verify-consent-purge-receipt requires --consent-purge-approval-bundle")?;
        let retirement_plan_path = args.consent_purge_retirement_plan_input.as_deref().ok_or(
            "--verify-consent-purge-receipt requires --consent-purge-retirement-plan-input",
        )?;
        let retirement_approval_path = args
            .consent_purge_retirement_approval_bundle
            .as_deref()
            .ok_or("--verify-consent-purge-receipt requires --consent-purge-retirement-approval-bundle")?;
        let quarantine_receipt_path = args
            .consent_purge_quarantine_receipt
            .as_deref()
            .ok_or("--verify-consent-purge-receipt requires --consent-purge-quarantine-receipt")?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let retirement_plan = read_retirement_plan(retirement_plan_path)?;
        let retirement_approvals = read_retirement_approvals(retirement_approval_path)?;
        let quarantine_receipt = read_retirement_receipt(quarantine_receipt_path)?;
        let (trusted_purge_keys, purge_quorum) = parse_purge_witness_policy(&args)?;
        ensure_purge_witness_separation(
            &trusted_purge_keys,
            &ledger_public_key.to_bytes(),
            &retirement_approvals,
        )?;
        purge_plan.verify_authority_signature(&ledger_public_key)?;
        consent_purge::verify_purge_prerequisite_identity(
            &purge_plan,
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            &ledger_public_key,
        )?;
        purge_approvals.verify_quorum(&purge_plan, &trusted_purge_keys, purge_quorum)?;
        let rollback_package = read_purge_rollback_package(&purge_plan)?;
        rollback_package.verify(&purge_plan, &purge_approvals, &ledger_public_key)?;
        let receipt: consent_purge::ConsentPurgeReceiptV1 = audit_ledger_store::read_bounded_json(
            receipt_path,
            consent_purge::MAX_PURGE_TRANSACTION_BYTES,
            "consent purge receipt",
        )?;
        receipt.verify(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &ledger_public_key,
        )?;
        consent_purge::verify_purge_receipt_files(&receipt)?;
        println!("consent purge receipt and rollback package verified");
        println!("path: {}", receipt_path.display());
        println!(
            "artifacts removed from quarantine: {}",
            receipt.entries.len()
        );
        println!("the ledger private key was not accessed");
        println!("the rollback package remains intact");
        return Ok(());
    }

    // --- purge_retention_sign ---
    if args.sign_consent_purge_retention_certificate {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let certificate_path = args
            .consent_purge_retention_certificate_input
            .as_deref()
            .ok_or("--sign-consent-purge-retention-certificate requires --consent-purge-retention-certificate-input")?;
        let witness_key_path = args
            .consent_purge_retention_witness_key
            .as_deref()
            .ok_or("--sign-consent-purge-retention-certificate requires --consent-purge-retention-witness-key")?;
        let witness_bundle_path = args
            .consent_purge_retention_witness_bundle
            .as_deref()
            .ok_or("--sign-consent-purge-retention-certificate requires --consent-purge-retention-witness-bundle")?;
        let purge_plan_path = args.consent_purge_plan_input.as_deref().ok_or(
            "--sign-consent-purge-retention-certificate requires --consent-purge-plan-input",
        )?;
        let purge_approval_path = args.consent_purge_approval_bundle.as_deref().ok_or(
            "--sign-consent-purge-retention-certificate requires --consent-purge-approval-bundle",
        )?;
        let purge_receipt_path = args.consent_purge_receipt_input.as_deref().ok_or(
            "--sign-consent-purge-retention-certificate requires --consent-purge-receipt-input",
        )?;
        let certificate = read_purge_retention_certificate(certificate_path)?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let rollback_package = read_purge_rollback_package(&purge_plan)?;
        let purge_receipt = read_purge_receipt(purge_receipt_path)?;
        certificate.verify(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &purge_receipt,
            &ledger_public_key,
        )?;
        let witness_key = load_existing_signing_key(witness_key_path)?;
        let witness_public = witness_key.verifying_key().to_bytes();
        ensure_purge_retention_witness_separation(
            &[witness_public],
            &ledger_public_key.to_bytes(),
            &purge_approvals,
        )?;
        let mut bundle = if witness_bundle_path.exists() {
            let existing = read_purge_retention_witnesses(witness_bundle_path)?;
            if !existing.witnesses.is_empty() {
                let observed = existing
                    .witnesses
                    .iter()
                    .map(|witness| witness.witness_public_key)
                    .collect::<Vec<_>>();
                existing.verify_quorum(
                    &certificate,
                    &observed,
                    observed.len(),
                    unix_now_secs(),
                    consent_purge_retention::MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
                )?;
            }
            existing
        } else {
            consent_purge_retention::ConsentPurgeRetentionWitnessBundleV1::new(&certificate)?
        };
        bundle.sign_with(&certificate, &witness_key, unix_now_secs())?;
        let output = consent_artifact_paths::normalized_output_path(witness_bundle_path)?;
        if output == consent_artifact_paths::normalized_output_path(certificate_path)?
            || output == consent_artifact_paths::normalized_output_path(purge_plan_path)?
            || output == consent_artifact_paths::normalized_output_path(purge_approval_path)?
            || output == consent_artifact_paths::normalized_output_path(purge_receipt_path)?
            || output == std::fs::canonicalize(witness_key_path)?
            || output.starts_with(std::path::Path::new(&certificate.package_directory))
        {
            return Err(
                "retention-witness output aliases protected evidence or key material".into(),
            );
        }
        persist_json_owner_only(
            witness_bundle_path,
            &bundle,
            consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
            "consent purge retention witness bundle",
        )?;
        println!("consent purge retention witness added");
        println!("path: {}", witness_bundle_path.display());
        println!("witness public key: {}", hex::encode(witness_public));
        println!("witness count: {}", bundle.witnesses.len());
        println!("the ledger private key was not accessed");
        return Ok(());
    }

    // --- purge_retention_verify_anchor ---
    if let Some(anchor_path) = args.verify_consent_purge_retention_anchor.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let certificate_path = args
            .consent_purge_retention_certificate_input
            .as_deref()
            .ok_or("--verify-consent-purge-retention-anchor requires --consent-purge-retention-certificate-input")?;
        let witness_bundle_path = args
            .consent_purge_retention_witness_bundle
            .as_deref()
            .ok_or("--verify-consent-purge-retention-anchor requires --consent-purge-retention-witness-bundle")?;
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--verify-consent-purge-retention-anchor requires --consent-purge-plan-input")?;
        let purge_approval_path = args.consent_purge_approval_bundle.as_deref().ok_or(
            "--verify-consent-purge-retention-anchor requires --consent-purge-approval-bundle",
        )?;
        let purge_receipt_path = args.consent_purge_receipt_input.as_deref().ok_or(
            "--verify-consent-purge-retention-anchor requires --consent-purge-receipt-input",
        )?;
        let certificate = read_purge_retention_certificate(certificate_path)?;
        let witnesses = read_purge_retention_witnesses(witness_bundle_path)?;
        let anchor = read_purge_retention_anchor(anchor_path)?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let rollback_package = read_purge_rollback_package(&purge_plan)?;
        let purge_receipt = read_purge_receipt(purge_receipt_path)?;
        certificate.verify(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &purge_receipt,
            &ledger_public_key,
        )?;
        let (trusted_keys, quorum) = parse_purge_retention_witness_policy(&args)?;
        ensure_purge_retention_witness_separation(
            &trusted_keys,
            &ledger_public_key.to_bytes(),
            &purge_approvals,
        )?;
        anchor.verify(
            &certificate,
            &witnesses,
            &trusted_keys,
            quorum,
            &ledger_public_key,
            unix_now_secs(),
            consent_purge_retention::MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
        )?;
        consent_purge_retention::verify_candidate_paths_disjoint(
            &certificate,
            &args.consent_purge_retention_candidate_check,
        )?;
        println!("consent purge retention anchor verified");
        println!("path: {}", anchor_path.display());
        println!(
            "protected artifacts: {}",
            certificate.protected_artifacts.len()
        );
        println!(
            "retain until unix seconds: {}",
            certificate.retain_until_unix_secs
        );
        println!("the ledger private key was not accessed");
        return Ok(());
    }

    // --- purge_custody_sign ---
    if args.sign_consent_purge_custody {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let retention = verified_retention_context(&args, &ledger_public_key)?;
        let subject = &retention.subject;
        let custody_key_path = args
            .consent_purge_custody_key
            .as_deref()
            .ok_or("--sign-consent-purge-custody requires --consent-purge-custody-key")?;
        let custody_bundle_path = args
            .consent_purge_custody_bundle
            .as_deref()
            .ok_or("--sign-consent-purge-custody requires --consent-purge-custody-bundle")?;
        let custody_class = parse_custody_class(
            args.consent_purge_custody_class
                .as_deref()
                .ok_or("--sign-consent-purge-custody requires --consent-purge-custody-class")?,
        )?;
        let locator = args
            .consent_purge_custody_locator
            .as_deref()
            .ok_or("--sign-consent-purge-custody requires --consent-purge-custody-locator")?;
        let replica_id =
            parse_replica_id_hex(args.consent_purge_custody_replica_id_hex.as_deref().ok_or(
                "--sign-consent-purge-custody requires --consent-purge-custody-replica-id-hex",
            )?)?;
        let custody_key = load_existing_signing_key(custody_key_path)?;
        let custody_public = custody_key.verifying_key().to_bytes();
        ensure_custody_key_separation(
            &[custody_public],
            &ledger_public_key.to_bytes(),
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        let observed_at = unix_now_secs();
        let available_until = observed_at
            .checked_add(args.consent_purge_custody_available_secs)
            .ok_or("custody availability deadline overflow")?;
        let attestation = consent_purge_custody::ConsentPurgeCustodyAttestationV1::sign(
            subject,
            custody_class,
            locator,
            replica_id,
            &custody_key,
            observed_at,
            available_until,
        )?;
        let mut bundle = if custody_bundle_path.exists() {
            let existing = read_purge_custody_bundle(custody_bundle_path)?;
            if !existing.attestations.is_empty() {
                let observed = existing
                    .attestations
                    .iter()
                    .map(|entry| entry.custodian_public_key)
                    .collect::<Vec<_>>();
                ensure_custody_key_separation(
                    &observed,
                    &ledger_public_key.to_bytes(),
                    &retention.retention_witnesses,
                    &retention.purge_approvals,
                )?;
                existing.verify_quorum(
                    subject,
                    &observed,
                    observed.len(),
                    observed_at,
                    consent_purge_custody::MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
                    subject.retain_until_unix_secs,
                )?;
            }
            existing
        } else {
            consent_purge_custody::ConsentPurgeCustodyBundleV1::new(subject)
        };
        bundle.add(subject, attestation)?;
        retention.protect_output(custody_bundle_path, &[custody_key_path], "custody bundle")?;
        persist_json_owner_only(
            custody_bundle_path,
            &bundle,
            consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
            "consent purge custody bundle",
        )?;
        println!("consent purge custody attestation added");
        println!("path: {}", custody_bundle_path.display());
        println!("custodian public key: {}", hex::encode(custody_public));
        println!("replica id: {}", hex::encode(replica_id));
        println!("attestation count: {}", bundle.attestations.len());
        println!("the ledger private key was not accessed");
        println!("no hardware or geographic independence claim was inferred");
        return Ok(());
    }

    // --- final_destruction_sign ---
    if args.sign_consent_final_destruction_plan {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let retention = verified_retention_context(&args, &ledger_public_key)?;
        let plan_path = args.consent_final_destruction_plan_input.as_deref().ok_or(
            "--sign-consent-final-destruction-plan requires --consent-final-destruction-plan-input",
        )?;
        let approval_path = args
            .consent_final_destruction_approval_bundle
            .as_deref()
            .ok_or("--sign-consent-final-destruction-plan requires --consent-final-destruction-approval-bundle")?;
        let witness_key_path = args
            .consent_final_destruction_witness_key
            .as_deref()
            .ok_or("--sign-consent-final-destruction-plan requires --consent-final-destruction-witness-key")?;
        let custody_bundle_path = args.consent_purge_custody_bundle.as_deref().ok_or(
            "--sign-consent-final-destruction-plan requires --consent-purge-custody-bundle",
        )?;
        let plan = read_final_destruction_plan(plan_path)?;
        let custody_bundle = read_purge_custody_bundle(custody_bundle_path)?;
        let (custody_keys, custody_quorum) = parse_purge_custody_policy(&args)?;
        ensure_custody_key_separation(
            &custody_keys,
            &ledger_public_key.to_bytes(),
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        plan.verify(
            &retention.certificate,
            &retention.subject,
            &custody_bundle,
            &custody_keys,
            custody_quorum,
            &ledger_public_key,
            unix_now_secs(),
        )?;
        let witness_key = load_existing_signing_key(witness_key_path)?;
        let witness_public = witness_key.verifying_key().to_bytes();
        ensure_final_destruction_key_separation(
            &[witness_public],
            &ledger_public_key.to_bytes(),
            &custody_bundle,
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        let mut approvals = if approval_path.exists() {
            let existing = read_final_destruction_approvals(approval_path)?;
            if !existing.approvals.is_empty() {
                let observed = existing
                    .approvals
                    .iter()
                    .map(|approval| approval.witness_public_key)
                    .collect::<Vec<_>>();
                ensure_final_destruction_key_separation(
                    &observed,
                    &ledger_public_key.to_bytes(),
                    &custody_bundle,
                    &retention.retention_witnesses,
                    &retention.purge_approvals,
                )?;
                existing.verify_quorum(&plan, &observed, observed.len())?;
            }
            existing
        } else {
            consent_final_destruction::ConsentFinalDestructionApprovalBundleV1::new(&plan)?
        };
        approvals.sign_with(&plan, &witness_key, unix_now_secs())?;
        retention.protect_output(
            approval_path,
            &[plan_path, custody_bundle_path, witness_key_path],
            "final-destruction approval",
        )?;
        persist_json_owner_only(
            approval_path,
            &approvals,
            consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
            "consent final destruction approval bundle",
        )?;
        println!("final-destruction approval added");
        println!("path: {}", approval_path.display());
        println!("witness public key: {}", hex::encode(witness_public));
        println!("approval count: {}", approvals.approvals.len());
        println!("the ledger private key was not accessed");
        println!("no artifact was removed");
        return Ok(());
    }

    // --- final_destruction_verify_readiness ---
    if let Some(readiness_path) = args.verify_consent_final_destruction_readiness.as_deref() {
        let ledger_public_key = retirement_ledger_verifying_key(&args)?;
        let retention = verified_retention_context(&args, &ledger_public_key)?;
        let plan_path = args
            .consent_final_destruction_plan_input
            .as_deref()
            .ok_or("--verify-consent-final-destruction-readiness requires --consent-final-destruction-plan-input")?;
        let approval_path = args
            .consent_final_destruction_approval_bundle
            .as_deref()
            .ok_or("--verify-consent-final-destruction-readiness requires --consent-final-destruction-approval-bundle")?;
        let custody_bundle_path = args.consent_purge_custody_bundle.as_deref().ok_or(
            "--verify-consent-final-destruction-readiness requires --consent-purge-custody-bundle",
        )?;
        let plan = read_final_destruction_plan(plan_path)?;
        let approvals = read_final_destruction_approvals(approval_path)?;
        let custody_bundle = read_purge_custody_bundle(custody_bundle_path)?;
        let readiness = read_final_destruction_readiness(readiness_path)?;
        let (custody_keys, custody_quorum) = parse_purge_custody_policy(&args)?;
        ensure_custody_key_separation(
            &custody_keys,
            &ledger_public_key.to_bytes(),
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        plan.verify(
            &retention.certificate,
            &retention.subject,
            &custody_bundle,
            &custody_keys,
            custody_quorum,
            &ledger_public_key,
            readiness.ready_at_unix_secs,
        )?;
        let (destruction_keys, destruction_quorum) = parse_final_destruction_policy(&args)?;
        ensure_final_destruction_key_separation(
            &destruction_keys,
            &ledger_public_key.to_bytes(),
            &custody_bundle,
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        readiness.verify(
            &plan,
            &approvals,
            &custody_bundle,
            &destruction_keys,
            destruction_quorum,
            &ledger_public_key,
        )?;
        if readiness.ready_at_unix_secs
            > unix_now_secs()
                .saturating_add(consent_final_destruction::MAX_FINAL_DESTRUCTION_FUTURE_SKEW_SECS)
        {
            return Err("final-destruction readiness timestamp is too far in the future".into());
        }
        println!("final-destruction readiness verified");
        println!("path: {}", readiness_path.display());
        println!("candidates: {}", readiness.candidate_count);
        println!(
            "readiness blake3: {}",
            hex::encode(
                consent_final_destruction::consent_final_destruction_readiness_fingerprint(
                    &readiness,
                )?
            )
        );
        println!("the ledger private key was not accessed");
        println!("no artifact was removed");
        return Ok(());
    }

    // --- signing_key_select ---
    let signing_key = if retirement_operation_requested
        || args.export_consent_purge_plan.is_some()
        || args.execute_consent_purge
        || args.export_consent_purge_retention_certificate.is_some()
        || args.export_consent_purge_retention_anchor.is_some()
        || args.export_consent_purge_retention_renewal.is_some()
        || args.export_consent_final_destruction_plan.is_some()
        || args.export_consent_final_destruction_readiness.is_some()
    {
        load_existing_signing_key(&args.operator_key_path)?
    } else {
        load_or_create_signing_key(&args.operator_key_path)?
    };

    // --- purge_retention_export_renewal ---
    if let Some(output_path) = args.export_consent_purge_retention_renewal.as_deref() {
        let mut retention = verified_retention_context(&args, &signing_key.verifying_key())?;
        let current_deadline = retention.renewal_chain.verify(
            &retention.certificate,
            &retention.anchor,
            &signing_key.verifying_key(),
            unix_now_secs(),
        )?;
        let renewed_deadline = current_deadline
            .checked_add(args.consent_purge_retention_renewal_secs)
            .ok_or("retention renewal deadline overflow")?;
        retention.renewal_chain.append(
            &retention.certificate,
            &retention.anchor,
            &signing_key,
            unix_now_secs(),
            renewed_deadline,
        )?;
        retention.protect_output(
            output_path,
            &[args.operator_key_path.as_path()],
            "retention renewal",
        )?;
        persist_json_owner_only(
            output_path,
            &retention.renewal_chain,
            consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
            "consent purge retention renewal chain",
        )?;
        println!("consent purge retention renewal exported");
        println!("path: {}", output_path.display());
        println!("renewal count: {}", retention.renewal_chain.renewals.len());
        println!("retain until unix seconds: {renewed_deadline}");
        println!("no expired obligation was revived");
        println!("no artifact was removed");
        return Ok(());
    }

    // --- final_destruction_export_plan ---
    if let Some(output_path) = args.export_consent_final_destruction_plan.as_deref() {
        let retention = verified_retention_context(&args, &signing_key.verifying_key())?;
        let custody_bundle_path = args.consent_purge_custody_bundle.as_deref().ok_or(
            "--export-consent-final-destruction-plan requires --consent-purge-custody-bundle",
        )?;
        let custody_bundle = read_purge_custody_bundle(custody_bundle_path)?;
        let (custody_keys, custody_quorum) = parse_purge_custody_policy(&args)?;
        ensure_custody_key_separation(
            &custody_keys,
            &signing_key.verifying_key().to_bytes(),
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        let issued_at = unix_now_secs();
        let expires_at = issued_at
            .checked_add(args.consent_final_destruction_plan_lifetime_secs)
            .ok_or("final-destruction plan expiry overflow")?;
        let plan = consent_final_destruction::ConsentFinalDestructionPlanV1::sign(
            &retention.certificate,
            &retention.subject,
            &custody_bundle,
            &custody_keys,
            custody_quorum,
            &signing_key,
            issued_at,
            expires_at,
        )?;
        retention.protect_output(
            output_path,
            &[custody_bundle_path, args.operator_key_path.as_path()],
            "final-destruction plan",
        )?;
        persist_json_owner_only(
            output_path,
            &plan,
            consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
            "consent final destruction plan",
        )?;
        println!("final-destruction readiness plan exported");
        println!("path: {}", output_path.display());
        println!("destruction id: {}", hex::encode(plan.destruction_id));
        println!("candidates: {}", plan.candidates.len());
        println!("expires at unix seconds: {}", plan.expires_at_unix_secs);
        println!("no artifact was removed");
        return Ok(());
    }

    // --- final_destruction_export_readiness ---
    if let Some(output_path) = args.export_consent_final_destruction_readiness.as_deref() {
        let retention = verified_retention_context(&args, &signing_key.verifying_key())?;
        let plan_path = args
            .consent_final_destruction_plan_input
            .as_deref()
            .ok_or("--export-consent-final-destruction-readiness requires --consent-final-destruction-plan-input")?;
        let approval_path = args
            .consent_final_destruction_approval_bundle
            .as_deref()
            .ok_or("--export-consent-final-destruction-readiness requires --consent-final-destruction-approval-bundle")?;
        let custody_bundle_path = args.consent_purge_custody_bundle.as_deref().ok_or(
            "--export-consent-final-destruction-readiness requires --consent-purge-custody-bundle",
        )?;
        let plan = read_final_destruction_plan(plan_path)?;
        let approvals = read_final_destruction_approvals(approval_path)?;
        let custody_bundle = read_purge_custody_bundle(custody_bundle_path)?;
        let (custody_keys, custody_quorum) = parse_purge_custody_policy(&args)?;
        ensure_custody_key_separation(
            &custody_keys,
            &signing_key.verifying_key().to_bytes(),
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        plan.verify(
            &retention.certificate,
            &retention.subject,
            &custody_bundle,
            &custody_keys,
            custody_quorum,
            &signing_key.verifying_key(),
            unix_now_secs(),
        )?;
        let (destruction_keys, destruction_quorum) = parse_final_destruction_policy(&args)?;
        ensure_final_destruction_key_separation(
            &destruction_keys,
            &signing_key.verifying_key().to_bytes(),
            &custody_bundle,
            &retention.retention_witnesses,
            &retention.purge_approvals,
        )?;
        let readiness = consent_final_destruction::ConsentFinalDestructionReadinessV1::sign(
            &plan,
            &approvals,
            &custody_bundle,
            &destruction_keys,
            destruction_quorum,
            &signing_key,
            unix_now_secs(),
        )?;
        retention.protect_output(
            output_path,
            &[
                plan_path,
                approval_path,
                custody_bundle_path,
                args.operator_key_path.as_path(),
            ],
            "final-destruction readiness",
        )?;
        persist_json_owner_only(
            output_path,
            &readiness,
            consent_final_destruction::MAX_FINAL_DESTRUCTION_BYTES,
            "consent final destruction readiness",
        )?;
        println!("final-destruction readiness exported");
        println!("path: {}", output_path.display());
        println!("candidates: {}", readiness.candidate_count);
        println!(
            "expires at unix seconds: {}",
            readiness.expires_at_unix_secs
        );
        println!("this artifact authorizes no implicit cleanup implementation");
        println!("no artifact was removed");
        return Ok(());
    }

    // --- retirement_export_plan ---
    if let Some(output_path) = args.export_consent_retirement_plan.as_deref() {
        let evidence = load_consent_retirement_evidence(&args, &signing_key)?;
        let quarantine_root_path = args.consent_retirement_quarantine_root.as_deref().ok_or(
            "--export-consent-retirement-plan requires --consent-retirement-quarantine-root",
        )?;
        let quarantine_root = consent_retirement::canonical_quarantine_root(quarantine_root_path)?;
        let mut candidates = Vec::new();
        for path in &args.consent_retirement_complete_ledger_candidate {
            candidates.push(consent_retirement::observe_retirement_artifact(
                consent_retirement::ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
                path,
            )?);
        }
        for path in &args.consent_retirement_compaction_bundle_candidate {
            candidates.push(consent_retirement::observe_retirement_artifact(
                consent_retirement::ConsentRetirementArtifactRoleV1::SupersededCompactionBundle,
                path,
            )?);
        }
        for path in &args.consent_retirement_compacted_snapshot_candidate {
            candidates.push(consent_retirement::observe_retirement_artifact(
                consent_retirement::ConsentRetirementArtifactRoleV1::SupersededCompactedSnapshot,
                path,
            )?);
        }
        if candidates.is_empty() {
            return Err("retirement plan requires at least one candidate artifact".into());
        }
        let issued_at = unix_now_secs();
        let expires_at = issued_at
            .checked_add(args.consent_retirement_plan_lifetime_secs)
            .ok_or("consent retirement plan expiry overflow")?;
        let plan = consent_retirement::ConsentRetirementPlanV1::sign(
            &evidence.active,
            &evidence.pin,
            &evidence.certificate,
            &evidence.archive_segments,
            quarantine_root,
            candidates,
            &signing_key,
            issued_at,
            expires_at,
        )?;
        ensure_retirement_candidates_are_unprotected(&plan, &evidence.protected_paths)?;
        let normalized_output = consent_artifact_paths::normalized_output_path(output_path)?;
        if evidence
            .protected_paths
            .iter()
            .any(|protected| protected == &normalized_output)
            || plan.candidates.iter().any(|candidate| {
                std::path::Path::new(&candidate.canonical_path) == normalized_output.as_path()
            })
            || normalized_output.starts_with(std::path::Path::new(&plan.quarantine_root))
        {
            return Err(
                "retirement plan output aliases protected, candidate, or quarantine storage".into(),
            );
        }
        persist_json_owner_only(
            output_path,
            &plan,
            consent_retirement::MAX_RETIREMENT_TRANSACTION_BYTES,
            "consent retirement plan",
        )?;
        println!("consent retirement plan exported");
        println!("path: {}", output_path.display());
        println!("plan id: {}", hex::encode(plan.plan_id));
        println!("candidates: {}", plan.candidates.len());
        println!("expires at unix seconds: {}", plan.expires_at_unix_secs);
        println!("no artifact was moved or deleted");
        return Ok(());
    }

    // --- retirement_quarantine ---
    if args.quarantine_consent_retirement {
        let evidence = load_consent_retirement_evidence(&args, &signing_key)?;
        let plan_path = args
            .consent_retirement_plan_input
            .as_deref()
            .ok_or("--quarantine-consent-retirement requires --consent-retirement-plan-input")?;
        let approval_path = args.consent_retirement_approval_bundle.as_deref().ok_or(
            "--quarantine-consent-retirement requires --consent-retirement-approval-bundle",
        )?;
        let plan = read_retirement_plan(plan_path)?;
        let approvals = read_retirement_approvals(approval_path)?;
        let (trusted_witness_keys, quorum) = parse_retirement_witness_policy(&args)?;
        if trusted_witness_keys
            .iter()
            .any(|key| *key == signing_key.verifying_key().to_bytes())
        {
            return Err(
                "trusted retirement witness keys must be distinct from the ledger key".into(),
            );
        }
        plan.verify(
            &evidence.active,
            &evidence.pin,
            &evidence.certificate,
            &evidence.archive_segments,
            &signing_key.verifying_key(),
            unix_now_secs(),
        )?;
        ensure_retirement_candidates_are_unprotected(&plan, &evidence.protected_paths)?;
        let receipt = consent_retirement::execute_retirement_quarantine(
            &plan,
            &approvals,
            &evidence.active,
            &evidence.pin,
            &evidence.certificate,
            &evidence.archive_segments,
            &trusted_witness_keys,
            quorum,
            &signing_key,
            unix_now_secs(),
        )?;
        println!("consent artifacts moved into reversible quarantine");
        println!("transaction: {}", receipt.transaction_directory);
        println!("artifacts: {}", receipt.entries.len());
        println!(
            "receipt blake3: {}",
            hex::encode(consent_retirement::consent_retirement_receipt_fingerprint(
                &receipt
            )?)
        );
        println!("no artifact was unlinked");
        return Ok(());
    }

    // --- purge_retention_export_certificate ---
    if let Some(output_path) = args.export_consent_purge_retention_certificate.as_deref() {
        let purge_plan_path = args.consent_purge_plan_input.as_deref().ok_or(
            "--export-consent-purge-retention-certificate requires --consent-purge-plan-input",
        )?;
        let purge_approval_path = args.consent_purge_approval_bundle.as_deref().ok_or(
            "--export-consent-purge-retention-certificate requires --consent-purge-approval-bundle",
        )?;
        let purge_receipt_path = args.consent_purge_receipt_input.as_deref().ok_or(
            "--export-consent-purge-retention-certificate requires --consent-purge-receipt-input",
        )?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let rollback_package_path =
            consent_purge::purge_transaction_directory(&purge_plan).join("rollback-package.json");
        let rollback_package: consent_purge::ConsentPurgeRollbackPackageV1 =
            audit_ledger_store::read_bounded_json(
                &rollback_package_path,
                consent_purge::MAX_PURGE_TRANSACTION_BYTES,
                "consent purge rollback package",
            )?;
        let purge_receipt = read_purge_receipt(purge_receipt_path)?;
        let retain_until = purge_receipt
            .completed_at_unix_secs
            .checked_add(args.consent_purge_retention_secs)
            .ok_or("consent purge retention deadline overflow")?;
        let certificate = consent_purge_retention::ConsentPurgeRetentionCertificateV1::sign(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &purge_receipt,
            &signing_key,
            unix_now_secs(),
            retain_until,
        )?;
        let normalized_output = consent_artifact_paths::normalized_output_path(output_path)?;
        if normalized_output == consent_artifact_paths::normalized_output_path(purge_plan_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(purge_approval_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(purge_receipt_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(&rollback_package_path)?
            || normalized_output == std::fs::canonicalize(&args.operator_key_path)?
            || normalized_output.starts_with(std::path::Path::new(&certificate.package_directory))
        {
            return Err(
                "retention-certificate output aliases protected evidence or key material".into(),
            );
        }
        persist_json_owner_only(
            output_path,
            &certificate,
            consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
            "consent purge retention certificate",
        )?;
        println!("consent purge retention certificate exported");
        println!("path: {}", output_path.display());
        println!(
            "protected artifacts: {}",
            certificate.protected_artifacts.len()
        );
        println!(
            "retain until unix seconds: {}",
            certificate.retain_until_unix_secs
        );
        println!("no artifact was removed");
        return Ok(());
    }

    // --- purge_retention_export_anchor ---
    if let Some(output_path) = args.export_consent_purge_retention_anchor.as_deref() {
        let certificate_path = args
            .consent_purge_retention_certificate_input
            .as_deref()
            .ok_or("--export-consent-purge-retention-anchor requires --consent-purge-retention-certificate-input")?;
        let witness_bundle_path = args
            .consent_purge_retention_witness_bundle
            .as_deref()
            .ok_or("--export-consent-purge-retention-anchor requires --consent-purge-retention-witness-bundle")?;
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--export-consent-purge-retention-anchor requires --consent-purge-plan-input")?;
        let purge_approval_path = args.consent_purge_approval_bundle.as_deref().ok_or(
            "--export-consent-purge-retention-anchor requires --consent-purge-approval-bundle",
        )?;
        let purge_receipt_path = args.consent_purge_receipt_input.as_deref().ok_or(
            "--export-consent-purge-retention-anchor requires --consent-purge-receipt-input",
        )?;
        let certificate = read_purge_retention_certificate(certificate_path)?;
        let witnesses = read_purge_retention_witnesses(witness_bundle_path)?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let rollback_package = read_purge_rollback_package(&purge_plan)?;
        let purge_receipt = read_purge_receipt(purge_receipt_path)?;
        certificate.verify(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &purge_receipt,
            &signing_key.verifying_key(),
        )?;
        let (trusted_keys, quorum) = parse_purge_retention_witness_policy(&args)?;
        ensure_purge_retention_witness_separation(
            &trusted_keys,
            &signing_key.verifying_key().to_bytes(),
            &purge_approvals,
        )?;
        let anchor = consent_purge_retention::ConsentPurgeRetentionAnchorV1::sign(
            &certificate,
            &witnesses,
            &trusted_keys,
            quorum,
            &signing_key,
            unix_now_secs(),
            consent_purge_retention::MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
        )?;
        let normalized_output = consent_artifact_paths::normalized_output_path(output_path)?;
        if normalized_output == consent_artifact_paths::normalized_output_path(certificate_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(witness_bundle_path)?
            || normalized_output == consent_artifact_paths::normalized_output_path(purge_plan_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(purge_approval_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(purge_receipt_path)?
            || normalized_output == std::fs::canonicalize(&args.operator_key_path)?
            || normalized_output.starts_with(std::path::Path::new(&certificate.package_directory))
        {
            return Err(
                "retention-anchor output aliases protected evidence or key material".into(),
            );
        }
        persist_json_owner_only(
            output_path,
            &anchor,
            consent_purge_retention::MAX_PURGE_RETENTION_BYTES,
            "consent purge retention anchor",
        )?;
        println!("consent purge retention anchor exported");
        println!("path: {}", output_path.display());
        println!(
            "anchor blake3: {}",
            hex::encode(
                consent_purge_retention::consent_purge_retention_anchor_fingerprint(&anchor)?
            )
        );
        println!(
            "retain until unix seconds: {}",
            anchor.retain_until_unix_secs
        );
        println!("no artifact was removed");
        return Ok(());
    }

    // --- purge_export_plan ---
    if let Some(output_path) = args.export_consent_purge_plan.as_deref() {
        let retirement_plan_path = args
            .consent_purge_retirement_plan_input
            .as_deref()
            .ok_or("--export-consent-purge-plan requires --consent-purge-retirement-plan-input")?;
        let retirement_approval_path = args
            .consent_purge_retirement_approval_bundle
            .as_deref()
            .ok_or(
                "--export-consent-purge-plan requires --consent-purge-retirement-approval-bundle",
            )?;
        let quarantine_receipt_path = args
            .consent_purge_quarantine_receipt
            .as_deref()
            .ok_or("--export-consent-purge-plan requires --consent-purge-quarantine-receipt")?;
        let rollback_root_path = args
            .consent_purge_rollback_root
            .as_deref()
            .ok_or("--export-consent-purge-plan requires --consent-purge-rollback-root")?;
        let retirement_plan = read_retirement_plan(retirement_plan_path)?;
        let retirement_approvals = read_retirement_approvals(retirement_approval_path)?;
        let quarantine_receipt = read_retirement_receipt(quarantine_receipt_path)?;
        let rollback_root = consent_purge::canonical_private_root(rollback_root_path)?;
        let issued_at = unix_now_secs();
        let expires_at = issued_at
            .checked_add(args.consent_purge_plan_lifetime_secs)
            .ok_or("consent purge plan expiry overflow")?;
        let purge_plan = consent_purge::ConsentPurgePlanV1::sign(
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            rollback_root,
            args.consent_purge_min_quarantine_age_secs,
            &signing_key,
            issued_at,
            expires_at,
        )?;
        let normalized_output = consent_artifact_paths::normalized_output_path(output_path)?;
        if normalized_output
            == consent_artifact_paths::normalized_output_path(retirement_plan_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(retirement_approval_path)?
            || normalized_output
                == consent_artifact_paths::normalized_output_path(quarantine_receipt_path)?
            || normalized_output == std::fs::canonicalize(&args.operator_key_path)?
            || normalized_output.starts_with(std::path::Path::new(&purge_plan.rollback_root))
            || normalized_output.starts_with(std::path::Path::new(
                &purge_plan.quarantine_transaction_directory,
            ))
            || purge_plan.candidates.iter().any(|candidate| {
                std::path::Path::new(&candidate.quarantine_path) == normalized_output.as_path()
                    || std::path::Path::new(&candidate.rollback_path) == normalized_output.as_path()
            })
        {
            return Err("purge plan output aliases a prerequisite or protected artifact".into());
        }
        persist_json_owner_only(
            output_path,
            &purge_plan,
            consent_purge::MAX_PURGE_TRANSACTION_BYTES,
            "consent purge plan",
        )?;
        println!("consent purge plan exported");
        println!("path: {}", output_path.display());
        println!("purge id: {}", hex::encode(purge_plan.purge_id));
        println!("candidates: {}", purge_plan.candidates.len());
        println!("rollback root: {}", purge_plan.rollback_root);
        println!(
            "expires at unix seconds: {}",
            purge_plan.expires_at_unix_secs
        );
        println!("no artifact was removed");
        return Ok(());
    }

    // --- purge_execute ---
    if args.execute_consent_purge {
        let purge_plan_path = args
            .consent_purge_plan_input
            .as_deref()
            .ok_or("--execute-consent-purge requires --consent-purge-plan-input")?;
        let purge_approval_path = args
            .consent_purge_approval_bundle
            .as_deref()
            .ok_or("--execute-consent-purge requires --consent-purge-approval-bundle")?;
        let retirement_plan_path = args
            .consent_purge_retirement_plan_input
            .as_deref()
            .ok_or("--execute-consent-purge requires --consent-purge-retirement-plan-input")?;
        let retirement_approval_path = args
            .consent_purge_retirement_approval_bundle
            .as_deref()
            .ok_or("--execute-consent-purge requires --consent-purge-retirement-approval-bundle")?;
        let quarantine_receipt_path = args
            .consent_purge_quarantine_receipt
            .as_deref()
            .ok_or("--execute-consent-purge requires --consent-purge-quarantine-receipt")?;
        let purge_plan = read_purge_plan(purge_plan_path)?;
        let purge_approvals = read_purge_approvals(purge_approval_path)?;
        let retirement_plan = read_retirement_plan(retirement_plan_path)?;
        let retirement_approvals = read_retirement_approvals(retirement_approval_path)?;
        let quarantine_receipt = read_retirement_receipt(quarantine_receipt_path)?;
        let (trusted_purge_keys, purge_quorum) = parse_purge_witness_policy(&args)?;
        ensure_purge_witness_separation(
            &trusted_purge_keys,
            &signing_key.verifying_key().to_bytes(),
            &retirement_approvals,
        )?;
        let receipt = consent_purge::execute_consent_purge(
            &purge_plan,
            &purge_approvals,
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            &trusted_purge_keys,
            purge_quorum,
            &signing_key,
            unix_now_secs(),
        )?;
        println!("consent quarantine artifacts removed after rollback packaging");
        println!("transaction: {}", receipt.transaction_directory);
        println!("artifacts: {}", receipt.entries.len());
        println!(
            "rollback package retained: {}",
            receipt.transaction_directory
        );
        return Ok(());
    }

    // --- mutual_exclusion_guards ---
    let retirement_auxiliary_args_present = args.consent_retirement_gc_certificate.is_some()
        || args.consent_retirement_quarantine_root.is_some()
        || !args.consent_retirement_complete_ledger_candidate.is_empty()
        || !args
            .consent_retirement_compaction_bundle_candidate
            .is_empty()
        || !args
            .consent_retirement_compacted_snapshot_candidate
            .is_empty()
        || args.consent_retirement_plan_input.is_some()
        || args.consent_retirement_ledger_public_key_hex.is_some()
        || args.consent_retirement_witness_key.is_some()
        || args.consent_retirement_approval_bundle.is_some()
        || !args.trusted_consent_retirement_witness_key_hex.is_empty()
        || args.trusted_consent_retirement_witness_quorum.is_some();
    if !retirement_operation_requested
        && !purge_operation_requested
        && !purge_retention_operation_requested
        && !purge_custody_operation_requested
        && !final_destruction_operation_requested
        && retirement_auxiliary_args_present
    {
        return Err("consent-retirement arguments require an explicit retirement operation".into());
    }

    let purge_auxiliary_args_present = args.consent_purge_rollback_root.is_some()
        || args.consent_purge_retirement_plan_input.is_some()
        || args.consent_purge_retirement_approval_bundle.is_some()
        || args.consent_purge_quarantine_receipt.is_some()
        || args.consent_purge_plan_input.is_some()
        || args.consent_purge_witness_key.is_some()
        || args.consent_purge_approval_bundle.is_some()
        || !args.trusted_consent_purge_witness_key_hex.is_empty()
        || args.trusted_consent_purge_witness_quorum.is_some();
    if !purge_operation_requested
        && !purge_retention_operation_requested
        && !purge_custody_operation_requested
        && !final_destruction_operation_requested
        && purge_auxiliary_args_present
    {
        return Err("consent-purge arguments require an explicit purge operation".into());
    }

    let purge_retention_auxiliary_args_present = args.consent_purge_receipt_input.is_some()
        || args.consent_purge_retention_certificate_input.is_some()
        || args.consent_purge_retention_witness_key.is_some()
        || args.consent_purge_retention_witness_bundle.is_some()
        || !args
            .trusted_consent_purge_retention_witness_key_hex
            .is_empty()
        || args
            .trusted_consent_purge_retention_witness_quorum
            .is_some()
        || !args.consent_purge_retention_candidate_check.is_empty()
        || args.consent_purge_retention_anchor_input.is_some()
        || args.consent_purge_retention_renewal_chain.is_some();
    if !purge_retention_operation_requested
        && !purge_custody_operation_requested
        && !final_destruction_operation_requested
        && purge_retention_auxiliary_args_present
    {
        return Err(
            "consent-purge-retention arguments require an explicit retention operation".into(),
        );
    }

    let purge_custody_auxiliary_args_present = args.consent_purge_custody_key.is_some()
        || args.consent_purge_custody_bundle.is_some()
        || args.consent_purge_custody_class.is_some()
        || args.consent_purge_custody_locator.is_some()
        || args.consent_purge_custody_replica_id_hex.is_some()
        || !args.trusted_consent_purge_custody_key_hex.is_empty()
        || args.trusted_consent_purge_custody_quorum.is_some();
    if !purge_custody_operation_requested
        && !final_destruction_operation_requested
        && purge_custody_auxiliary_args_present
    {
        return Err("consent-purge-custody arguments require an explicit custody or final-destruction operation".into());
    }

    let final_destruction_auxiliary_args_present =
        args.consent_final_destruction_plan_input.is_some()
            || args.consent_final_destruction_witness_key.is_some()
            || args.consent_final_destruction_approval_bundle.is_some()
            || !args
                .trusted_consent_final_destruction_witness_key_hex
                .is_empty()
            || args
                .trusted_consent_final_destruction_witness_quorum
                .is_some();
    if !final_destruction_operation_requested && final_destruction_auxiliary_args_present {
        return Err("final-destruction arguments require an explicit readiness operation".into());
    }

    // --- ledger_maintenance_file_only (Phase 4) ---
    // The four consent-ledger maintenance operations that operate purely on
    // operator-supplied files plus `signing_key` -- no dependency on the
    // daemon's own live `--consent-ledger-path` ledger, so (like every
    // other one-shot operation above) they can run and exit before the
    // daemon ever loads it. See docs/packaging or the Phase 4 PR
    // description for the full family breakdown; the remaining five
    // ledger-maintenance operations that genuinely need the live ledger
    // are wired further below, right after it loads.
    if let Some(output_path) = args.activate_consent_ledger_compacted_state.as_deref() {
        let Some(snapshot_path) = args.consent_ledger_activation_snapshot.as_deref() else {
            return Err(
                "--activate-consent-ledger-compacted-state requires \
                 --consent-ledger-activation-snapshot"
                    .into(),
            );
        };
        if args.consent_ledger_activation_archive_segment.is_empty() {
            return Err(
                "--activate-consent-ledger-compacted-state requires at least one \
                 --consent-ledger-activation-archive-segment"
                    .into(),
            );
        }
        if args.consent_ledger_activation_archive_segment.len()
            > xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
        {
            return Err(format!(
                "compacted-state activation has {} archive segments; maximum is {}",
                args.consent_ledger_activation_archive_segment.len(),
                xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
            )
            .into());
        }
        let snapshot: consent_compaction::ConsentCompactedSnapshotV1 =
            audit_ledger_store::read_bounded_json(
                snapshot_path,
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES,
                "consent compacted snapshot",
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read activation snapshot {}: {err}",
                    snapshot_path.display()
                )
                .into()
            })?;
        let mut archive_segments =
            Vec::with_capacity(args.consent_ledger_activation_archive_segment.len());
        let mut aggregate_bytes = 0u64;
        for path in &args.consent_ledger_activation_archive_segment {
            let (segment, bytes) = audit_ledger_store::read_bounded_json_with_size(
                path,
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES,
                "consent ledger activation archive segment",
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read activation archive segment {}: {err}",
                    path.display()
                )
                .into()
            })?;
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes)
                .ok_or("activation archive input byte count overflow")?;
            if aggregate_bytes > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
                return Err(format!(
                    "activation archive inputs exceed {} bytes",
                    consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
                )
                .into());
            }
            archive_segments.push(segment);
        }
        // Disclosed asymmetry (Phase 4): this writes a real, verified
        // compacted active-state file, but current main()'s normal daemon
        // startup below still only ever calls
        // `audit_ledger_store::load_verified`, which constructs a plain
        // `Chain::from_entries` -- it has never been taught to read back
        // `Chain::from_checkpoint_suffix`-shaped (anchored-suffix) state.
        // Manually pointing `--consent-ledger-path` at this operation's
        // output will NOT round-trip through a normal daemon restart yet.
        // Teaching startup that mode is the deliberately deferred, separate
        // piece of this family (the daemon-startup persister-mode switch +
        // continuity checks) -- not done here.
        let active = consent_compaction::ConsentCompactedActiveStateV1::activate(
            snapshot,
            &archive_segments,
            &signing_key,
            unix_now_secs(),
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("consent compacted-state activation failed: {err}").into()
        })?;
        crate::consent_ledger_persistence::persist_compacted_active_state_atomic(
            output_path,
            &active,
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "failed to persist activated compacted consent state {}: {err}",
                output_path.display()
            )
            .into()
        })?;
        println!("consent-ledger compacted active state created");
        println!("path: {}", output_path.display());
        println!(
            "archived entries: {}",
            active
                .activation_snapshot
                .recovery_summary
                .archived_entry_count
        );
        println!("resident suffix entries: {}", active.resident_entries.len());
        println!("total entries: {}", active.current_checkpoint.entry_count);
        println!("active generation: {}", active.generation);
        println!(
            "ledger epoch blake3: {}",
            hex::encode(active.cutover_receipt.ledger_epoch_id)
        );
        println!("state blake3: {}", hex::encode(active.state_digest));
        println!(
            "note: current daemon startup cannot yet read this back via --consent-ledger-path"
        );
        return Ok(());
    }

    if let Some(pin_path) = args.advance_consent_ledger_compacted_state_pin.as_deref() {
        let Some(state_path) = args.consent_ledger_compacted_state.as_deref() else {
            return Err(
                "--advance-consent-ledger-compacted-state-pin requires \
                 --consent-ledger-compacted-state"
                    .into(),
            );
        };
        if pin_path == state_path {
            return Err("compacted-state pin path must differ from the active-state path".into());
        }
        let (active, _) = crate::consent_ledger_persistence::load_compacted_active_state(
            state_path,
            &signing_key,
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "failed to load compacted state {} for pin advancement: {err}",
                state_path.display()
            )
            .into()
        })?;
        if pin_path.exists() {
            let retained: consent_compaction::ConsentCompactedStatePinV1 =
                audit_ledger_store::read_bounded_json(
                    pin_path,
                    audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
                    "retained compacted-state pin",
                )?;
            retained
                .verify_against_state(&active, &signing_key.verifying_key())
                .map_err(|err| -> Box<dyn std::error::Error> {
                    format!(
                        "current compacted state does not extend retained pin {}: {err}",
                        pin_path.display()
                    )
                    .into()
                })?;
        }
        let pin = consent_compaction::ConsentCompactedStatePinV1::sign_for_state(
            &active,
            &signing_key,
            unix_now_secs(),
        )?;
        persist_json_owner_only(
            pin_path,
            &pin,
            audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
            "compacted-state pin",
        )?;
        println!("compacted-state pin advanced");
        println!("path: {}", pin_path.display());
        println!("generation: {}", pin.generation);
        println!("entries: {}", pin.checkpoint.entry_count);
        println!(
            "pin blake3: {}",
            hex::encode(consent_compaction::consent_compacted_state_pin_fingerprint(
                &pin
            )?)
        );
        return Ok(());
    }

    if args
        .export_consent_ledger_compaction_gc_certificate
        .is_some()
        || args
            .verify_consent_ledger_compaction_gc_certificate
            .is_some()
    {
        let Some(state_path) = args.consent_ledger_compacted_state.as_deref() else {
            return Err(
                "consent-ledger GC certification requires --consent-ledger-compacted-state"
                    .into(),
            );
        };
        let Some(pin_path) = args.trusted_consent_ledger_compacted_state_pin.as_deref() else {
            return Err(
                "consent-ledger GC certification requires \
                 --trusted-consent-ledger-compacted-state-pin"
                    .into(),
            );
        };
        let (active, _) = crate::consent_ledger_persistence::load_compacted_active_state(
            state_path,
            &signing_key,
        )?;
        let pin: consent_compaction::ConsentCompactedStatePinV1 =
            audit_ledger_store::read_bounded_json(
                pin_path,
                audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
                "trusted compacted-state pin",
            )?;
        let archive_segments = read_consent_archive_segments(
            &args.consent_ledger_gc_archive_segment,
            "consent-ledger GC archive",
        )?;

        if let Some(output_path) = args
            .export_consent_ledger_compaction_gc_certificate
            .as_deref()
        {
            if output_path == state_path
                || output_path == pin_path
                || args
                    .consent_ledger_gc_archive_segment
                    .iter()
                    .any(|path| path == output_path)
            {
                return Err(
                    "GC certificate output must not overwrite active state, retained pin, or cold archive"
                        .into(),
                );
            }
            let certificate = consent_compaction::ConsentCompactionGcCertificateV1::sign_for_state(
                &active,
                &pin,
                &archive_segments,
                &signing_key,
                unix_now_secs(),
            )?;
            persist_json_owner_only(
                output_path,
                &certificate,
                audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
                "compaction GC certificate",
            )?;
            println!("consent-ledger GC readiness certificate exported");
            println!("path: {}", output_path.display());
            println!(
                "archive through entries: {}",
                certificate.archive_through_checkpoint.entry_count
            );
            println!(
                "active entries: {}",
                certificate.current_checkpoint.entry_count
            );
            println!("no live or archived artifact was deleted");
            return Ok(());
        }

        let Some(certificate_path) = args
            .verify_consent_ledger_compaction_gc_certificate
            .as_deref()
        else {
            return Err("GC certificate verification mode requires a certificate path".into());
        };
        let certificate: consent_compaction::ConsentCompactionGcCertificateV1 =
            audit_ledger_store::read_bounded_json(
                certificate_path,
                audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
                "compaction GC certificate",
            )?;
        certificate.verify(
            &active,
            &pin,
            &archive_segments,
            &signing_key.verifying_key(),
        )?;
        println!("consent-ledger GC readiness certificate verified");
        println!("path: {}", certificate_path.display());
        println!("no live or archived artifact was deleted");
        return Ok(());
    }

    if let Some(snapshot_path) = args.verify_consent_ledger_compacted_snapshot.as_deref() {
        if args
            .consent_ledger_compacted_snapshot_archive_segment
            .is_empty()
        {
            return Err(concat!(
                "--verify-consent-ledger-compacted-snapshot requires at least one ",
                "--consent-ledger-compacted-snapshot-archive-segment"
            )
            .into());
        }
        if args.consent_ledger_compacted_snapshot_archive_segment.len()
            > xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
        {
            return Err(format!(
                "compacted snapshot has {} archive segments; maximum is {}",
                args.consent_ledger_compacted_snapshot_archive_segment.len(),
                xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
            )
            .into());
        }
        let snapshot = audit_ledger_store::read_bounded_json::<
            consent_compaction::ConsentCompactedSnapshotV1,
        >(
            snapshot_path,
            consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES,
            "consent compacted restore snapshot",
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "failed to read --verify-consent-ledger-compacted-snapshot {}: {err}",
                snapshot_path.display()
            )
            .into()
        })?;
        let mut archive_segments =
            Vec::with_capacity(args.consent_ledger_compacted_snapshot_archive_segment.len());
        let mut archive_input_bytes = 0u64;
        for path in &args.consent_ledger_compacted_snapshot_archive_segment {
            let remaining_input_bytes = consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
                .saturating_sub(archive_input_bytes);
            let per_file_limit =
                audit_ledger_store::MAX_AUDIT_LEDGER_BYTES.min(remaining_input_bytes);
            let (segment, input_bytes) = audit_ledger_store::read_bounded_json_with_size::<
                xenia_ledger::LedgerArchiveSegment,
            >(
                path, per_file_limit, "consent ledger archive segment"
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read compacted snapshot archive segment {}: {err}",
                    path.display()
                )
                .into()
            })?;
            archive_input_bytes = archive_input_bytes
                .checked_add(input_bytes)
                .ok_or("compacted snapshot archive input byte count overflow")?;
            if archive_input_bytes > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
                return Err(format!(
                    "compacted snapshot archive inputs exceed {} bytes",
                    consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
                )
                .into());
            }
            archive_segments.push(segment);
        }
        let restored = snapshot
            .restore_state(&archive_segments, &signing_key)
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "consent compacted snapshot {} failed restore verification: {err}",
                    snapshot_path.display()
                )
                .into()
            })?;
        println!("consent-ledger compacted restore snapshot verified");
        println!("path: {}", snapshot_path.display());
        println!(
            "archived entries represented by summary: {}",
            snapshot.recovery_summary.archived_entry_count
        );
        println!("resident suffix entries: {}", snapshot.suffix_entries.len());
        println!(
            "current entries: {}",
            snapshot.manifest.current_checkpoint.entry_count
        );
        println!("snapshot blake3: {}", hex::encode(snapshot.snapshot_digest));
        println!("restored total entries: {}", restored.chain.entry_count());
        println!(
            "restored resident entries: {}",
            restored.chain.resident_len()
        );
        println!(
            "restored archived replay action ids: {}",
            restored.archived_replay_action_count()
        );
        println!(
            "restored archived terminal sessions: {}",
            restored.archived_terminal_session_count()
        );
        return Ok(());
    }

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
    //
    // Daemon-startup compacted-state persister mode: `--consent-ledger
    // -compacted-state` swaps both halves of ledger persistence for the
    // whole rest of the process, not just this load -- `ledger_persister`
    // is threaded into `ConsentServer`/`SealedConsentDeps` below and is
    // what every live consent decision actually persists through (see
    // `consent_server::apply_consent_decision`). This mirrors PR #99's own
    // design (its `main.rs` staged the same choice through a `(Chain,
    // SharedConsentLedgerPersister, ..., bool)` tuple), adapted to this
    // codebase's simpler runtime: current `main` has no `ConsentDecisionService`
    // /`consent_authority.rs` indirection, so there are no historical replay/
    // terminal-session indexes to thread through here -- `into_parts()`'s
    // archived-index halves are intentionally dropped.
    let (ledger, ledger_persister): (
        xenia_ledger::Chain,
        consent_ledger_persistence::SharedConsentLedgerPersister,
    ) = if let Some(path) = args.consent_ledger_compacted_state.as_deref() {
        let (active, restored) =
            consent_ledger_persistence::load_compacted_active_state(path, &signing_key).map_err(
                |err| -> Box<dyn std::error::Error> {
                    format!(
                        "failed to load --consent-ledger-compacted-state {}: {err}",
                        path.display()
                    )
                    .into()
                },
            )?;
        if let Some(pin_path) = args.trusted_consent_ledger_compacted_state_pin.as_deref() {
            let pin: consent_compaction::ConsentCompactedStatePinV1 =
                audit_ledger_store::read_bounded_json(
                    pin_path,
                    audit_ledger_store::MAX_CONTINUITY_ARTIFACT_BYTES,
                    "trusted compacted-state pin",
                )
                .map_err(|err| -> Box<dyn std::error::Error> {
                    format!(
                        "failed to load --trusted-consent-ledger-compacted-state-pin {}: {err}",
                        pin_path.display()
                    )
                    .into()
                })?;
            pin.verify_against_state(&active, &signing_key.verifying_key())
                .map_err(|err| -> Box<dyn std::error::Error> {
                    format!(
                        "current compacted consent-ledger state does not satisfy \
                             --trusted-consent-ledger-compacted-state-pin {}: {err}",
                        pin_path.display()
                    )
                    .into()
                })?;
        }
        let (chain, _archived_replay_action_ids, _archived_terminal_sessions) =
            restored.into_parts();
        info!(
            path = %path.display(),
            entries = chain.len(),
            "compacted consent ledger loaded and verified"
        );
        let persister: consent_ledger_persistence::SharedConsentLedgerPersister =
            std::sync::Arc::new(
                consent_ledger_persistence::CompactedConsentLedgerPersister::new(
                    path.to_path_buf(),
                    active,
                ),
            );
        (chain, persister)
    } else {
        let ledger = audit_ledger_store::load_verified(&args.consent_ledger_path, &signing_key)
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to load --consent-ledger-path {}: {err}",
                    args.consent_ledger_path.display()
                )
                .into()
            })?;
        info!(
            path = %args.consent_ledger_path.display(),
            entries = ledger.len(),
            "consent ledger loaded and verified"
        );
        let persister: consent_ledger_persistence::SharedConsentLedgerPersister =
            std::sync::Arc::new(
                consent_ledger_persistence::CompleteConsentLedgerPersister::new(
                    args.consent_ledger_path.clone(),
                ),
            );
        (ledger, persister)
    };
    let compacted_state_loaded = args.consent_ledger_compacted_state.is_some();

    // --- ledger_continuity (Phase B) ---
    // Independent-checkpoint continuity verification and the two
    // compacted-mode mutual-exclusion guards PR #99 paired with the
    // daemon-startup persister-mode switch (Phase A). Adapted rather than
    // ported verbatim -- PR #99 threaded these through its
    // `ConsentDecisionService`/`consent_authority.rs` refactor, which
    // doesn't exist on current `main`; nothing here needs it, since these
    // checks only read `ledger`/`compacted_state_loaded`/`args`. Runs
    // unconditionally (whether or not a one-shot maintenance operation is
    // also requested below) and fails closed via `?` -- a startup with a
    // continuity anchor configured that the current ledger doesn't satisfy
    // must never silently proceed.
    if compacted_state_loaded && args.trusted_consent_ledger_key_transition.is_some() {
        return Err(
            "--trusted-consent-ledger-key-transition is not yet supported with an activated \
             compacted ledger; retain the complete successor epoch or use a same-key \
             checkpoint/witness anchor"
                .into(),
        );
    }
    let complete_ledger_operation_requested = args.export_consent_ledger_archive_segment.is_some()
        || args.export_consent_ledger_compaction_bundle.is_some()
        || args.verify_consent_ledger_compaction_bundle.is_some()
        || args.export_consent_ledger_compacted_snapshot.is_some();
    if compacted_state_loaded && complete_ledger_operation_requested {
        return Err(
            "archive and compaction-preflight operations currently require a complete \
             genesis-based consent ledger; activated compacted state supports normal append, \
             checkpoint, witness, and runtime paths only"
                .into(),
        );
    }
    let checkpoint_freshness = xenia_ledger::CheckpointFreshnessPolicy {
        max_age_secs: args.trusted_consent_ledger_checkpoint_max_age_secs,
        max_future_skew_secs: args.trusted_consent_ledger_checkpoint_max_future_skew_secs,
    };
    let continuity_anchor_configured = args.trusted_consent_ledger_checkpoint.is_some()
        || args.trusted_consent_ledger_witness_bundle.is_some();
    if args
        .trusted_consent_ledger_checkpoint_max_age_secs
        .is_some()
        && !continuity_anchor_configured
    {
        return Err(
            "--trusted-consent-ledger-checkpoint-max-age-secs requires a retained checkpoint or \
             witness bundle"
                .into(),
        );
    }
    if args
        .trusted_consent_ledger_checkpoint_max_age_secs
        .is_some()
        && args.trusted_consent_ledger_key_transition.is_some()
    {
        return Err(
            "--trusted-consent-ledger-checkpoint-max-age-secs cannot be used with a historical \
             key-transition anchor"
                .into(),
        );
    }
    if let Some(bundle_path) = args.trusted_consent_ledger_witness_bundle.as_deref() {
        if args.trusted_consent_ledger_witness_key_hex.is_empty() {
            return Err(
                "--trusted-consent-ledger-witness-bundle requires at least one \
                 --trusted-consent-ledger-witness-key-hex"
                    .into(),
            );
        }
        let trusted_witness_keys = args
            .trusted_consent_ledger_witness_key_hex
            .iter()
            .map(|value| parse_ed25519_public_key_hex(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!("invalid trusted checkpoint witness key: {err}").into()
            })?;
        let quorum = args.trusted_consent_ledger_witness_quorum.unwrap_or(1);
        if quorum == 0 {
            return Err("checkpoint witness quorum must be greater than zero".into());
        }
        if quorum > trusted_witness_keys.len() {
            return Err(format!(
                "checkpoint witness quorum {quorum} exceeds {} configured trusted witness keys",
                trusted_witness_keys.len()
            )
            .into());
        }
        let bundle = audit_ledger_store::verify_retained_witness_bundle(
            bundle_path,
            &ledger,
            &signing_key.verifying_key(),
            &trusted_witness_keys,
            quorum,
            unix_now_secs(),
            checkpoint_freshness,
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "current consent ledger does not satisfy --trusted-consent-ledger-witness-bundle \
                 {}: {err}",
                bundle_path.display()
            )
            .into()
        })?;
        info!(
            bundle = %bundle_path.display(),
            retained_entries = bundle.checkpoint.entry_count,
            current_entries = ledger.len(),
            witness_quorum = quorum,
            "witnessed consent-ledger checkpoint verified"
        );
    } else if let Some(checkpoint_path) = args.trusted_consent_ledger_checkpoint.as_deref() {
        if let Some(transition_path) = args.trusted_consent_ledger_key_transition.as_deref() {
            let transition = audit_ledger_store::verify_retained_key_successor(
                checkpoint_path,
                transition_path,
                &ledger,
                &signing_key.verifying_key(),
                unix_now_secs(),
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "current consent ledger is not an authorized successor of checkpoint {} via \
                     transition {}: {err}",
                    checkpoint_path.display(),
                    transition_path.display()
                )
                .into()
            })?;
            info!(
                checkpoint = %checkpoint_path.display(),
                transition = %transition_path.display(),
                previous_entries = transition.previous_checkpoint.entry_count,
                current_entries = ledger.len(),
                "dual-signed consent-ledger key succession verified"
            );
        } else {
            let checkpoint = audit_ledger_store::verify_retained_checkpoint_with_policy(
                checkpoint_path,
                &ledger,
                &signing_key.verifying_key(),
                unix_now_secs(),
                checkpoint_freshness,
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "current consent ledger does not extend --trusted-consent-ledger-checkpoint \
                     {}: {err}",
                    checkpoint_path.display()
                )
                .into()
            })?;
            info!(
                checkpoint = %checkpoint_path.display(),
                retained_entries = checkpoint.entry_count,
                current_entries = ledger.len(),
                "retained consent-ledger checkpoint verified as an exact prefix"
            );
        }
    }

    // --- ledger_maintenance_live_ledger (Phase 4) ---
    // The remaining five ledger-maintenance operations, which genuinely
    // need a reference to the daemon's own live, just-loaded `ledger` --
    // unlike every operation above (including the four ledger-maintenance
    // ones just above), these can only run after this point. Still exit
    // before any listener binds, same one-shot contract as everything else.
    if let Some(checkpoint_path) = args.advance_consent_ledger_checkpoint.as_deref() {
        let checkpoint = audit_ledger_store::advance_retained_checkpoint(
            checkpoint_path,
            &ledger,
            &signing_key.verifying_key(),
            unix_now_secs(),
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "failed to advance --advance-consent-ledger-checkpoint {}: {err}",
                checkpoint_path.display()
            )
            .into()
        })?;
        println!("consent-ledger checkpoint advanced");
        println!("path: {}", checkpoint_path.display());
        println!("entries: {}", checkpoint.entry_count);
        println!("head blake3: {}", hex::encode(checkpoint.head_hash));
        return Ok(());
    }

    if let Some(output_path) = args.export_consent_ledger_archive_segment.as_deref() {
        let Some(base_path) = args.consent_ledger_archive_base_checkpoint.as_deref() else {
            return Err(
                "--export-consent-ledger-archive-segment requires \
                 --consent-ledger-archive-base-checkpoint"
                    .into(),
            );
        };
        let segment = audit_ledger_store::export_archive_segment_atomic(
            output_path,
            base_path,
            &ledger,
            unix_now_secs(),
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!(
                "failed to export consent ledger archive segment {}: {err}",
                output_path.display()
            )
            .into()
        })?;
        println!("consent-ledger archive segment exported");
        println!("path: {}", output_path.display());
        println!("base entries: {}", segment.base_checkpoint.entry_count);
        println!(
            "terminal entries: {}",
            segment.terminal_checkpoint.entry_count
        );
        println!("segment entries: {}", segment.entries.len());
        println!("segment blake3: {}", hex::encode(segment.segment_digest));
        return Ok(());
    }

    if let Some(output_path) = args.export_consent_ledger_compaction_bundle.as_deref() {
        if args.consent_ledger_compaction_archive_segment.is_empty() {
            return Err(concat!(
                "--export-consent-ledger-compaction-bundle requires at least one ",
                "--consent-ledger-compaction-archive-segment"
            )
            .into());
        }
        if args.consent_ledger_compaction_archive_segment.len()
            > xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
        {
            return Err(format!(
                "compaction bundle has {} archive segments; maximum is {}",
                args.consent_ledger_compaction_archive_segment.len(),
                xenia_ledger::MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS
            )
            .into());
        }
        let mut archive_segments =
            Vec::with_capacity(args.consent_ledger_compaction_archive_segment.len());
        let mut archive_input_bytes = 0u64;
        for path in &args.consent_ledger_compaction_archive_segment {
            let remaining_input_bytes = consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
                .saturating_sub(archive_input_bytes);
            let per_file_limit =
                audit_ledger_store::MAX_AUDIT_LEDGER_BYTES.min(remaining_input_bytes);
            let (segment, input_bytes) = audit_ledger_store::read_bounded_json_with_size::<
                xenia_ledger::LedgerArchiveSegment,
            >(
                path, per_file_limit, "consent ledger archive segment"
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read compaction archive segment {}: {err}",
                    path.display()
                )
                .into()
            })?;
            archive_input_bytes = archive_input_bytes
                .checked_add(input_bytes)
                .ok_or("compaction archive input byte count overflow")?;
            if archive_input_bytes > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
                return Err(format!(
                    "compaction archive inputs exceed {} bytes",
                    consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
                )
                .into());
            }
            archive_segments.push(segment);
        }
        let bundle = consent_compaction::ConsentCompactionBundleV1::build(
            &ledger,
            archive_segments,
            unix_now_secs(),
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("consent ledger compaction preflight failed: {err}").into()
        })?;
        let mut bytes = serde_json::to_vec_pretty(&bundle)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
            return Err(format!(
                "serialized compaction bundle is {} bytes; maximum is {}",
                bytes.len(),
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
            )
            .into());
        }
        audit_ledger_store::persist_owner_only_atomic(output_path, &bytes).map_err(
            |err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to persist consent ledger compaction bundle {}: {err}",
                    output_path.display()
                )
                .into()
            },
        )?;
        println!("consent-ledger compaction preflight bundle exported");
        println!("path: {}", output_path.display());
        println!(
            "archived entries: {}",
            bundle.recovery_summary.archived_entry_count
        );
        println!(
            "replay action ids: {}",
            bundle.recovery_summary.replay_action_ids.len()
        );
        println!(
            "completed sessions: {}",
            bundle.recovery_summary.sessions.len()
        );
        println!(
            "archive sequence blake3: {}",
            hex::encode(bundle.recovery_summary.archive_sequence_digest)
        );
        println!(
            "recovery summary blake3: {}",
            hex::encode(bundle.recovery_summary.summary_digest)
        );
        println!(
            "live entries: {}",
            bundle.manifest.current_checkpoint.entry_count
        );
        println!("no live ledger entries were deleted");
        return Ok(());
    }

    if let Some(bundle_path) = args.verify_consent_ledger_compaction_bundle.as_deref() {
        let bundle =
            audit_ledger_store::read_bounded_json::<consent_compaction::ConsentCompactionBundleV1>(
                bundle_path,
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES,
                "consent ledger compaction bundle",
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read --verify-consent-ledger-compaction-bundle {}: {err}",
                    bundle_path.display()
                )
                .into()
            })?;
        let entries = ledger.iter().cloned().collect::<Vec<_>>();
        // `anchor` is `None` here, not a placeholder: this operation is
        // still guarded to only run against a complete, genesis-based
        // `--consent-ledger-path` chain (see the `complete_ledger_operation_requested`
        // guard above), so `entries` really is absolute from true genesis.
        // See `consent_compaction::local_suffix_start`'s doc comment for why
        // this parameter exists at all.
        bundle
            .verify_against_live_ledger(&entries, &signing_key.verifying_key(), None)
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "consent ledger compaction bundle {} failed verification: {err}",
                    bundle_path.display()
                )
                .into()
            })?;
        println!("consent-ledger compaction preflight bundle verified");
        println!("path: {}", bundle_path.display());
        println!(
            "archived entries: {}",
            bundle.recovery_summary.archived_entry_count
        );
        println!(
            "current entries: {}",
            bundle.manifest.current_checkpoint.entry_count
        );
        println!(
            "replay action ids: {}",
            bundle.recovery_summary.replay_action_ids.len()
        );
        println!(
            "completed sessions: {}",
            bundle.recovery_summary.sessions.len()
        );
        return Ok(());
    }

    if let Some(output_path) = args.export_consent_ledger_compacted_snapshot.as_deref() {
        let Some(bundle_path) = args.consent_ledger_compaction_bundle_input.as_deref() else {
            return Err(
                "--export-consent-ledger-compacted-snapshot requires \
                 --consent-ledger-compaction-bundle-input"
                    .into(),
            );
        };
        let bundle =
            audit_ledger_store::read_bounded_json::<consent_compaction::ConsentCompactionBundleV1>(
                bundle_path,
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES,
                "consent ledger compaction bundle",
            )
            .map_err(|err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to read --consent-ledger-compaction-bundle-input {}: {err}",
                    bundle_path.display()
                )
                .into()
            })?;
        let entries = ledger.iter().cloned().collect::<Vec<_>>();
        // See the identical comment on the verify-compaction-bundle branch
        // above: this operation is guarded to complete-chain-only, so
        // `anchor: None` reflects real current behavior, not a stub.
        let snapshot = consent_compaction::ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &signing_key.verifying_key(),
            None,
        )
        .map_err(|err| -> Box<dyn std::error::Error> {
            format!("consent compacted snapshot export failed: {err}").into()
        })?;
        let mut bytes = serde_json::to_vec_pretty(&snapshot)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES {
            return Err(format!(
                "serialized compacted snapshot is {} bytes; maximum is {}",
                bytes.len(),
                consent_compaction::MAX_CONSENT_COMPACTION_BUNDLE_BYTES
            )
            .into());
        }
        audit_ledger_store::persist_owner_only_atomic(output_path, &bytes).map_err(
            |err| -> Box<dyn std::error::Error> {
                format!(
                    "failed to persist compacted consent snapshot {}: {err}",
                    output_path.display()
                )
                .into()
            },
        )?;
        println!("consent-ledger compacted restore snapshot exported");
        println!("path: {}", output_path.display());
        println!(
            "archived entries represented by summary: {}",
            snapshot.recovery_summary.archived_entry_count
        );
        println!("resident suffix entries: {}", snapshot.suffix_entries.len());
        println!(
            "current entries: {}",
            snapshot.manifest.current_checkpoint.entry_count
        );
        println!("snapshot blake3: {}", hex::encode(snapshot.snapshot_digest));
        println!("no live ledger entries were deleted or replaced");
        return Ok(());
    }

    // Everything above this point can exit without ever binding a socket;
    // only now are we actually committing to serving. Moved here (from
    // its previous position before the ledger-maintenance one-shot checks
    // above) so it stays true -- otherwise a one-shot ledger-maintenance
    // invocation would misleadingly log "daemon listening" moments before
    // exiting without binding anything, unlike every other one-shot
    // operation in this file.
    info!(addr = %args.listen, "xenia-peer daemon listening");

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

    // The host identity is persistent and must be loaded exactly once, not
    // per accept attempt -- it is the fingerprint operators pin out of band.
    let mut mgr = load_or_create_host_identity(&args.host_identity_key_path)?;
    info!(
        fingerprint = %hex::encode(mgr.identity_fingerprint()),
        path = %args.host_identity_key_path.display(),
        "host signing identity loaded; share this fingerprint out-of-band for viewer pinning"
    );

    // Accept a peer and complete its handshake, retrying until one succeeds.
    //
    // Both halves of this loop are load-bearing for availability, and neither
    // is sufficient alone (THREAT_MODEL.md §Availability):
    //
    //   * the deadline stops a peer that connects and never sends its
    //     handshake response from parking us forever -- `read_exact` under
    //     `recv_envelope` has no deadline of its own;
    //   * the retry stops that peer from consuming the daemon's single
    //     session slot. With a deadline but no retry, a stalled peer would
    //     just convert a silent hang into an exit, which is still a denial of
    //     service an attacker can trigger at will with one idle socket.
    //
    // Per-session state (`session`, `capabilities`, and the context hash that
    // binds them into the transcript) is rebuilt on each attempt so a failed
    // peer cannot leave partially-advanced state behind for the next one.
    // Re-entering `accept_transport` rebinds the listener, which is safe:
    // mio sets SO_REUSEADDR on every TcpListener bind.
    let handshake_deadline = Duration::from_secs(args.handshake_timeout_secs.max(1));
    let (
        mut transport,
        negotiated_transport,
        mut session,
        frame_format,
        capabilities,
        negotiated_context_hash,
        handshake,
    ) = loop {
        let mut transport = accept_transport(&args, audio_advertisement.clone()).await?;
        let negotiated_transport = transport.negotiated_transport();
        let transport_profile = transport.transport_profile();
        let pre_session_profile = transport.pre_session_profile();
        let availability_profile = transport.availability_profile();
        let mut session = LaneSession::with_fixture(source_id, args.epoch);
        let frame_format = codec_to_frame_format(args.codec);
        let capabilities = session_capabilities_frame(
            session.next_frame_id(),
            audio_advertisement.clone(),
            frame_format,
            args.telemetry_level,
            args.input_backend,
            args.clipboard,
        )?;
        let negotiated_context_hash = negotiated_session_context_hash_with_profiles(
            &transport_profile,
            &pre_session_profile,
            &availability_profile,
            xenia_peer_core::RawCapabilities::from_frame(&capabilities)?,
        )?;

        match tokio::time::timeout(
            handshake_deadline,
            perform_host_handshake_with_transcript_and_context(
                &mut transport,
                &mut mgr,
                "viewer",
                Some(negotiated_context_hash),
            ),
        )
        .await
        {
            Ok(Ok(handshake)) => {
                break (
                    transport,
                    negotiated_transport,
                    session,
                    frame_format,
                    capabilities,
                    negotiated_context_hash,
                    handshake,
                );
            }
            Ok(Err(err)) => {
                warn!(
                    error = %err,
                    "peer failed the handshake; dropping it and accepting the next one"
                );
            }
            Err(_) => {
                warn!(
                    timeout_secs = args.handshake_timeout_secs,
                    "peer did not complete the handshake before the deadline; dropping it \
                     and accepting the next one"
                );
            }
        }
    };
    info!("Handshake successful, session key established and transcript hash computed");

    // Consent Ceremony: the real decision arrives over --consent-port as a
    // plain "Approve" / "Deny" text message — the same convention already
    // spoken by apps/sovereign-admin's ConsentModal (a browser-based
    // operator console). The request itself is broadcast on --admin-port
    // (below, once m1_runtime.offer() succeeds) so a connected ConsentModal
    // has something real to show instead of an empty prompt.
    info!("Waiting for consent request...");

    let (consent_decision_tx, consent_decision_rx) = tokio::sync::oneshot::channel::<bool>();

    // Set by the consent socket when the operator sends a later "Revoke" on
    // the still-open connection (after an initial "Approve"). The main send
    // loop polls this each tick, calls `M1RuntimeSession::revoke()` to record
    // the boundary in the consent ledger and flip every gate fail-closed,
    // then stops streaming -- so an operator can end a live session without
    // killing the process. See the send loop's revocation check below.
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_for_consent = Arc::clone(&revoked);

    // When --require-operator-auth is set, consent decisions must be signed,
    // role-authorized operator actions (see decode_consent_decision). The
    // per-action signature binds to this session id, and each authenticated
    // decision is attributed in the ledger (Phase 4).
    let require_operator_auth = args.require_operator_auth;
    let consent_auth_state = operator_auth_state.clone();
    let consent_session_id = *session_id.as_bytes();
    let consent_session_uuid = session_id;
    let consent_ledger = shared_ledger.clone();
    let consent_ledger_persister = ledger_persister.clone();
    // Computed here (a pure function of the daemon's own CLI config, not
    // handshake/runtime state) rather than down at the `m1_scope` binding
    // below, so both consent-server branches immediately below can bind
    // their per-action signatures to this session's actual offered scope --
    // never trusting anything relayed back through the console/agent
    // round-trip for that binding. Reused verbatim (not recomputed) for the
    // M1 consent-scope offer/broadcast below, so there's exactly one source
    // of truth for what this session's scope string is.
    let m1_scope = m1_consent_scope(&args);
    let consent_scope_digest = xenia_operator_proto::scope_digest(&m1_scope);

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
                    require_operator_auth,
                    auth_state: consent_auth_state,
                    session_id: consent_session_id,
                    scope_digest: consent_scope_digest,
                    session_uuid: consent_session_uuid,
                    ledger: consent_ledger,
                    ledger_persister: consent_ledger_persister,
                    revoked: revoked_for_consent,
                    revocations: revocations.clone(),
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
                        consent_decision_tx,
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
                    require_operator_auth,
                    auth_state: consent_auth_state,
                    session_id: consent_session_id,
                    scope_digest: consent_scope_digest,
                    session_uuid: consent_session_uuid,
                    ledger: consent_ledger,
                    ledger_persister: consent_ledger_persister,
                    grant_tx: consent_decision_tx,
                    revoked: revoked_for_consent,
                    revocations: revocations.clone(),
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
    // `m1_scope` was already computed above (before the consent-server
    // branches, so their per-action signature binding could use it) -- reuse
    // it here rather than recomputing, so there's one source of truth.
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
        // Broadcast the consent request as JSON carrying the session_id, so an
        // authenticated operator console can bind its per-action signature to
        // this exact session (see the console's
        // operator_session::build_consent_request + consent_action_transcript).
        // `scope` is the human-readable description for display. A legacy
        // plaintext console just shows the text and still sends
        // "Approve"/"Deny", which a daemon without --require-operator-auth
        // accepts -- so this shape change is backward compatible.
        let consent_prompt = serde_json::json!({
            "session_id": hex::encode(session_id.as_bytes()),
            "scope": m1_scope_for_log,
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
                let granted = configured_permission_set(&args);
                m1_runtime.grant_consent_scoped(granted)?;
                info!(
                    inject_input = granted.inject_input,
                    read_host_clipboard = granted.read_host_clipboard,
                    write_host_clipboard = granted.write_host_clipboard,
                    send_file_to_viewer = granted.send_file_to_viewer,
                    receive_file_from_viewer = granted.receive_file_from_viewer,
                    "M1 consent granted; only the operator-enabled tiers unlocked"
                );
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
        m1_runtime.lock().await.allow_file_send_flow()?;
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
                        if let Err(err) = m1_runtime.allow_host_clipboard_write_flow() {
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
                if input.payload.len() > xenia_inject::MAX_BINCODE_INPUT_EVENT_BYTES {
                    warn!(
                        bytes = input.payload.len(),
                        max_bytes = xenia_inject::MAX_BINCODE_INPUT_EVENT_BYTES,
                        "input event payload exceeds application parser ceiling"
                    );
                    continue;
                }
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

        ticker.tick().await;

        // Mid-session revocation: if the operator sent "Revoke" on the
        // consent socket, record it in the consent ledger (which flips the
        // M1 state to Revoked so every frame/input/clipboard/file gate now
        // fails closed) and stop streaming with a graceful close.
        if revoked.load(Ordering::SeqCst) {
            if let Err(err) = m1_runtime.lock().await.revoke() {
                warn!(error = %err, "failed to record consent revocation");
            }
            info!("session revoked by operator; stopping frame flow");
            break;
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
                    m1_runtime.lock().await.allow_telemetry_flow()?;
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
                m1_runtime.lock().await.allow_audio_flow()?;
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
                m1_runtime.lock().await.preflight_frame_flow()?;
                m1_runtime.lock().await.allow_host_clipboard_read_flow()?;
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
        let Some(encoder) = encoder.as_mut() else {
            return Err("video encoder was unavailable after capture initialization".into());
        };

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
        let mut args = Args::parse_from(["xenia-peer"]);
        args.telemetry_level = TelemetryLevel::Basic;
        args.audio = AudioMode::Off;
        assert_eq!(
            m1_consent_scope(&args),
            "display: screen stream; telemetry: basic host performance; audio: off; \
             input: off; clipboard: off; file-transfer: off"
        );
    }

    #[test]
    fn m1_scope_names_real_audio_capture_explicitly() {
        let mut args = Args::parse_from(["xenia-peer"]);
        args.telemetry_level = TelemetryLevel::System;
        args.audio = AudioMode::Capture;
        assert_eq!(
            m1_consent_scope(&args),
            "display: screen stream; telemetry: system identity and performance; \
             audio: host device capture; input: off; clipboard: off; file-transfer: off"
        );
    }

    #[test]
    fn m1_scope_names_input_clipboard_and_file_transfer_when_enabled() {
        let mut args = Args::parse_from(["xenia-peer"]);
        args.telemetry_level = TelemetryLevel::Off;
        args.input_backend = InputBackendChoice::Log;
        args.clipboard = ClipboardMode::Bidirectional;
        args.recv_file_dir = Some(std::path::PathBuf::from("/tmp/inbox"));
        args.send_file = Some(std::path::PathBuf::from("/tmp/report.pdf"));
        assert_eq!(
            m1_consent_scope(&args),
            "display: screen stream; telemetry: off; audio: off; \
             input: viewer may inject; clipboard: bidirectional; \
             file-transfer: bidirectional"
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

    #[test]
    fn view_only_daemon_grants_only_frame_streaming() {
        let args = args_with(InputBackendChoice::Noop, ClipboardMode::Off, None, None);
        let granted = configured_permission_set(&args);
        assert!(granted.stream_frame);
        assert!(!granted.inject_input);
        assert!(!granted.read_host_clipboard);
        assert!(!granted.write_host_clipboard);
        assert!(!granted.send_file_to_viewer);
        assert!(!granted.receive_file_from_viewer);
    }

    #[test]
    fn each_enabled_capability_unlocks_exactly_its_own_tier() {
        let input = args_with(InputBackendChoice::Log, ClipboardMode::Off, None, None);
        assert!(configured_permission_set(&input).inject_input);
        assert!(!configured_permission_set(&input).read_host_clipboard);
        assert!(!configured_permission_set(&input).write_host_clipboard);

        let clip = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Bidirectional,
            None,
            None,
        );
        assert!(configured_permission_set(&clip).read_host_clipboard);
        assert!(configured_permission_set(&clip).write_host_clipboard);
        assert!(!configured_permission_set(&clip).inject_input);

        // Host-to-viewer clipboard discloses to the viewer but is not a
        // host-write grant: an operator who only enabled one-way disclosure
        // must not also silently authorize the viewer writing to the host
        // clipboard.
        let clip_one_way = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::HostToViewer,
            None,
            None,
        );
        assert!(configured_permission_set(&clip_one_way).read_host_clipboard);
        assert!(!configured_permission_set(&clip_one_way).write_host_clipboard);

        // --recv-file-dir authorizes receiving viewer-offered files, but
        // must not also silently authorize sending host files to the viewer.
        let recv = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Off,
            Some(std::path::PathBuf::from("/tmp/inbox")),
            None,
        );
        assert!(configured_permission_set(&recv).receive_file_from_viewer);
        assert!(!configured_permission_set(&recv).send_file_to_viewer);

        // --send-file is the symmetric case: authorizes sending, not
        // receiving.
        let send = args_with(
            InputBackendChoice::Noop,
            ClipboardMode::Off,
            None,
            Some(std::path::PathBuf::from("/tmp/report.pdf")),
        );
        assert!(configured_permission_set(&send).send_file_to_viewer);
        assert!(!configured_permission_set(&send).receive_file_from_viewer);
    }
}
