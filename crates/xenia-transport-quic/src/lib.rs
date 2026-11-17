// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-transport-quic
//!
//! Iroh QUIC implementation of the
//! [`xenia_peer_core::transport::Transport`] trait.
//!
//! Xenia envelopes are already end-to-end sealed by `xenia-wire`. This crate
//! uses Iroh for endpoint identity, multiplexing, and QUIC stream semantics;
//! the application payload remains transport-independent.
//!
//! **NAT traversal is opt-in.** [`bind_xenia_endpoint`] defaults to direct-only
//! mode and requires already-reachable addresses. Operators may select
//! `public-relay` or `custom-relay` through `XENIA_IROH_RELAY_MODE`; custom
//! mode additionally requires `XENIA_IROH_RELAY_URLS`. See
//! `docs/transport/RELAY_PATH_POLICY.md`.
//!
//! Relay use improves reachability but creates a metadata-observation point:
//! the selected relay can observe endpoint IDs, timing, packet sizes and
//! traffic volume. It forwards encrypted Iroh packets and cannot decode
//! Xenia's end-to-end sealed application envelopes.
//!
//! The transport currently wraps one long-lived bidirectional QUIC stream.
//! Inside that stream it uses the same 4-byte big-endian envelope length prefix
//! as TCP, so callers get identical envelope boundary behavior across TCP,
//! WebSocket, and QUIC.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::time::{Duration, Instant};
use std::{collections::BTreeSet, env, io};

use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, RelayUrl,
    endpoint::{Connection, PathEvent, PathId, PathStats, RecvStream, SendStream, presets},
};
use thiserror::Error;
use tracing::debug;
use xenia_peer_core::transport::{
    MAX_ENVELOPE_BYTES, NetworkPathProfileV1, QUIC_CONNECT_TIMEOUT_MS, QUIC_PROTOCOL_ID,
    QUIC_STREAM_OPEN_TIMEOUT_MS, RECEIVE_ENVELOPE_TIMEOUT_MS, RecvEnvelope, SEND_STALL_TIMEOUT_MS,
    SendEnvelope, Transport, TransportError, TransportKind, TransportProfileV1,
};

/// Re-export of the Iroh crate for endpoint ownership in callers.
pub use iroh;

/// ALPN used by the Xenia QUIC transport.
pub const XENIA_QUIC_ALPN: &[u8] = QUIC_PROTOCOL_ID.as_bytes();

const STREAM_PREFACE: &[u8; 8] = b"XENIAQ0\0";
const ADDR_PREFIX: &str = "iroh:";

/// Errors specific to the Iroh QUIC transport.
#[derive(Debug, Error)]
pub enum QuicError {
    /// Endpoint connection attempt failed.
    #[error("iroh connect: {0}")]
    Connect(String),

    /// Incoming connection accept failed.
    #[error("iroh accept: {0}")]
    Accept(String),

    /// QUIC stream open/accept failed.
    #[error("iroh stream: {0}")]
    Stream(String),

    /// QUIC stream read/write failed.
    #[error("iroh I/O: {0}")]
    Io(String),

    /// Endpoint closed before a connection arrived.
    #[error("iroh endpoint closed before accepting a connection")]
    EndpointClosed,

    /// Endpoint address string could not be encoded or decoded.
    #[error("iroh address: {0}")]
    Address(String),
}

impl From<QuicError> for TransportError {
    fn from(value: QuicError) -> Self {
        match value {
            QuicError::EndpointClosed => TransportError::UnexpectedEof,
            other => TransportError::Io(io::Error::other(other.to_string())),
        }
    }
}

/// Environment variable selecting the Iroh relay policy for both Xenia peers.
pub const IROH_RELAY_MODE_ENV: &str = "XENIA_IROH_RELAY_MODE";
/// Environment variable containing comma-separated HTTPS relay URLs for custom mode.
pub const IROH_RELAY_URLS_ENV: &str = "XENIA_IROH_RELAY_URLS";

/// Operator-selected network path policy for Iroh endpoint establishment.
///
/// Direct-only is deliberately the default. Enabling a public or custom relay
/// allows NAT traversal and relay fallback, but also exposes connection
/// metadata to the selected relay operator. Xenia application envelopes remain
/// end-to-end sealed independently of the Iroh relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayPolicy {
    /// No relay use. Requires an already-reachable direct address.
    DirectOnly,
    /// Use Iroh's default public relay map.
    PublicRelay,
    /// Use exactly the supplied operator-managed HTTPS relay URLs.
    Custom(Vec<RelayUrl>),
}

impl RelayPolicy {
    /// Parse the environment-variable contract. Missing mode defaults to
    /// direct-only; custom mode requires at least one HTTPS relay URL.
    pub fn from_env() -> Result<Self, TransportError> {
        let mode = env::var(IROH_RELAY_MODE_ENV).unwrap_or_else(|_| "direct-only".to_string());
        let urls = env::var(IROH_RELAY_URLS_ENV).ok();
        Self::parse(&mode, urls.as_deref())
    }

    /// Parse a mode and optional comma-separated relay list without reading
    /// process environment. Exposed for deterministic configuration tests.
    pub fn parse(mode: &str, urls: Option<&str>) -> Result<Self, TransportError> {
        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "direct-only" | "disabled" => Ok(Self::DirectOnly),
            "public" | "public-relay" => Ok(Self::PublicRelay),
            "custom" | "custom-relay" => {
                let raw = urls.ok_or_else(|| {
                    relay_config_error(format!(
                        "{IROH_RELAY_URLS_ENV} is required when {IROH_RELAY_MODE_ENV}=custom"
                    ))
                })?;
                let mut unique = BTreeSet::new();
                let mut relays = Vec::new();
                for candidate in raw.split(',') {
                    let candidate = candidate.trim();
                    if candidate.is_empty() {
                        return Err(relay_config_error(
                            "custom relay list contains an empty URL".to_string(),
                        ));
                    }
                    if !candidate
                        .get(..8)
                        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
                    {
                        return Err(relay_config_error(format!(
                            "custom relay URL must use HTTPS: {candidate}"
                        )));
                    }
                    let relay = candidate.parse::<RelayUrl>().map_err(|error| {
                        relay_config_error(format!(
                            "custom relay URL is invalid ({candidate}): {error}"
                        ))
                    })?;
                    let canonical = relay.to_string();
                    if !unique.insert(canonical.clone()) {
                        return Err(relay_config_error(format!(
                            "custom relay URL is duplicated: {canonical}"
                        )));
                    }
                    relays.push(relay);
                }
                if relays.is_empty() {
                    return Err(relay_config_error(
                        "custom relay mode requires at least one relay URL".to_string(),
                    ));
                }
                Ok(Self::Custom(relays))
            }
            other => Err(relay_config_error(format!(
                "unsupported {IROH_RELAY_MODE_ENV} value '{other}'; use direct-only, public-relay, or custom"
            ))),
        }
    }

    fn to_iroh_mode(&self) -> RelayMode {
        match self {
            Self::DirectOnly => RelayMode::Disabled,
            Self::PublicRelay => RelayMode::Default,
            Self::Custom(relays) => RelayMode::custom(relays.clone()),
        }
    }

    /// Produce the privacy-preserving path profile that the host and viewer
    /// bind into the authenticated negotiated-session context.
    pub fn network_path_profile(&self) -> Result<NetworkPathProfileV1, TransportError> {
        match self {
            Self::DirectOnly => Ok(NetworkPathProfileV1::current(TransportKind::Quic)),
            Self::PublicRelay => Ok(NetworkPathProfileV1::public_relay()),
            Self::Custom(relays) => {
                let canonical_urls = relays.iter().map(ToString::to_string).collect::<Vec<_>>();
                NetworkPathProfileV1::custom_relay_urls(&canonical_urls)
                    .map_err(|error| relay_config_error(error.to_string()))
            }
        }
    }

    /// Stable, non-secret name for operator logs and support diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DirectOnly => "direct-only",
            Self::PublicRelay => "public-relay",
            Self::Custom(_) => "custom-relay",
        }
    }
}

fn relay_config_error(message: String) -> TransportError {
    TransportError::from(QuicError::Address(message))
}

/// Bind an Iroh endpoint configured for the Xenia QUIC ALPN.
///
/// This uses Iroh's minimal preset. Relay behavior is selected explicitly
/// through `XENIA_IROH_RELAY_MODE`; the default remains direct-only. The
/// resulting [`Endpoint::addr`] contains direct and, when opted in, relay
/// addresses appropriate to the configured policy.
pub async fn bind_xenia_endpoint() -> Result<Endpoint, TransportError> {
    let policy = RelayPolicy::from_env()?;
    bind_xenia_endpoint_with_policy(policy).await
}

/// Bind an Iroh endpoint with an explicit Xenia relay policy.
///
/// The minimal preset preserves Xenia's TLS configuration and avoids
/// implicitly enabling address-lookup services. Relay behavior is selected
/// separately and is therefore reviewable at the call site.
pub async fn bind_xenia_endpoint_with_policy(
    policy: RelayPolicy,
) -> Result<Endpoint, TransportError> {
    let relay_mode = policy.to_iroh_mode();
    tracing::info!(relay_policy = policy.label(), "binding Xenia Iroh endpoint");
    Endpoint::builder(presets::Minimal)
        .relay_mode(relay_mode)
        .alpns(vec![XENIA_QUIC_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| TransportError::from(QuicError::Accept(e.to_string())))
}

/// Encode an Iroh endpoint address into a copyable CLI token.
pub fn encode_endpoint_addr(addr: &EndpointAddr) -> Result<String, TransportError> {
    let json = serde_json::to_vec(addr)
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))?;
    Ok(format!("{ADDR_PREFIX}{}", bs58::encode(json).into_string()))
}

/// Decode an endpoint address previously returned by [`encode_endpoint_addr`].
pub fn decode_endpoint_addr(s: &str) -> Result<EndpointAddr, TransportError> {
    let encoded = s.strip_prefix(ADDR_PREFIX).unwrap_or(s);
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))
}

/// Schema identifier for redacted Iroh path-event observations.
pub const QUIC_PATH_EVENT_SCHEMA_V1: &str = "xenia-quic-path-event/v1";

/// Redacted event category from Iroh's connection path monitor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicPathEventKind {
    /// A new path became available to the connection.
    Opened,
    /// A previously available path closed.
    Closed,
    /// The connection selected a path for transmitting application data.
    Selected,
    /// The Iroh path-event subscriber missed one or more events.
    Lagged,
    /// A future Iroh event variant was observed but is not yet mapped.
    Unknown,
}

/// Coarse route classification. No IP address, port, relay URL, or hostname is
/// retained in this type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicRouteClass {
    /// Direct IP-based path.
    DirectIp,
    /// Iroh relay path.
    Relay,
    /// Iroh custom transport path.
    Custom,
    /// Unknown or not classifiable from the public event.
    Unknown,
}

/// Redacted statistics for one QUIC transmission path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuicPathStats {
    /// Round-trip time estimate in microseconds.
    pub rtt_us: u64,
    /// Congestion window in bytes.
    pub congestion_window_bytes: u64,
    /// Congestion events observed on this path.
    pub congestion_events: u64,
    /// Packets lost on this path.
    pub lost_packets: u64,
    /// Bytes lost on this path.
    pub lost_bytes: u64,
    /// Current path MTU in bytes.
    pub current_mtu_bytes: u16,
}

/// One path in a reconciled open-path snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuicPathSnapshot {
    /// Ephemeral Iroh path identifier, not a socket address.
    pub path_id: String,
    /// Redacted route class.
    pub route_class: QuicRouteClass,
    /// Whether Iroh currently selects this path for application data.
    pub selected_for_transmit: bool,
    /// Current statistics when Iroh provides them.
    pub stats: Option<QuicPathStats>,
}

/// Redacted path event with a local observer clock and explicit history status.
///
/// `observer_monotonic_us` is elapsed time since this subscription started.
/// It must not be compared with timestamps from another process or endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuicPathEvent {
    /// Versioned event schema.
    pub schema_version: String,
    /// Sequence number local to this subscription, starting at one.
    pub observer_sequence: u64,
    /// Monotonic microseconds since this subscription started.
    pub observer_monotonic_us: u64,
    /// Event category.
    pub event_kind: QuicPathEventKind,
    /// Ephemeral Iroh path identifier when the event applies to one path.
    pub path_id: Option<String>,
    /// Redacted route classification when available.
    pub route_class: Option<QuicRouteClass>,
    /// Current selected status when known.
    pub selected_for_transmit: Option<bool>,
    /// Number of events missed when the stream reports a lag.
    pub missed_events: Option<u64>,
    /// Path statistics when available.
    pub stats: Option<QuicPathStats>,
    /// Current open-path snapshot attached to a lag event for reconciliation.
    pub reconciled_paths: Option<Vec<QuicPathSnapshot>>,
    /// True only while no event-history gap has been observed by this subscriber.
    /// A reconciled snapshot repairs current-state knowledge, not lost history.
    pub history_complete: bool,
}

fn route_class_from_flags(is_relay: bool, is_ip: bool, is_custom: bool) -> QuicRouteClass {
    if is_relay {
        QuicRouteClass::Relay
    } else if is_ip {
        QuicRouteClass::DirectIp
    } else if is_custom {
        QuicRouteClass::Custom
    } else {
        QuicRouteClass::Unknown
    }
}

fn classify_transport_addr(addr: &iroh::TransportAddr) -> QuicRouteClass {
    route_class_from_flags(addr.is_relay(), addr.is_ip(), addr.is_custom())
}

fn duration_micros_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn summarize_path_stats(stats: &PathStats) -> QuicPathStats {
    QuicPathStats {
        rtt_us: duration_micros_u64(stats.rtt),
        congestion_window_bytes: stats.cwnd,
        congestion_events: stats.congestion_events,
        lost_packets: stats.lost_packets,
        lost_bytes: stats.lost_bytes,
        current_mtu_bytes: stats.current_mtu,
    }
}

fn snapshot_one_path(connection: &Connection, id: PathId) -> Option<QuicPathSnapshot> {
    let paths = connection.paths();
    paths.get(id).map(|path| QuicPathSnapshot {
        path_id: id.to_string(),
        route_class: classify_transport_addr(path.remote_addr()),
        selected_for_transmit: path.is_selected(),
        stats: Some(summarize_path_stats(&path.stats())),
    })
}

fn snapshot_open_paths(connection: &Connection) -> Vec<QuicPathSnapshot> {
    let paths = connection.paths();
    paths
        .iter()
        .map(|path| QuicPathSnapshot {
            path_id: path.id().to_string(),
            route_class: classify_transport_addr(path.remote_addr()),
            selected_for_transmit: path.is_selected(),
            stats: Some(summarize_path_stats(&path.stats())),
        })
        .collect()
}

fn make_path_event(
    observer_sequence: u64,
    observer_monotonic_us: u64,
    event_kind: QuicPathEventKind,
    path_id: Option<String>,
    route_class: Option<QuicRouteClass>,
    selected_for_transmit: Option<bool>,
    missed_events: Option<u64>,
    stats: Option<QuicPathStats>,
    reconciled_paths: Option<Vec<QuicPathSnapshot>>,
    history_complete: bool,
) -> QuicPathEvent {
    QuicPathEvent {
        schema_version: QUIC_PATH_EVENT_SCHEMA_V1.to_string(),
        observer_sequence,
        observer_monotonic_us,
        event_kind,
        path_id,
        route_class,
        selected_for_transmit,
        missed_events,
        stats,
        reconciled_paths,
        history_complete,
    }
}

/// Iroh QUIC transport over one bidirectional stream.
pub struct QuicTransport {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl QuicTransport {
    /// Wrap an already-opened bidirectional stream.
    pub fn new(conn: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self { conn, send, recv }
    }

    /// Connect to an Iroh endpoint address and open the transport stream.
    pub async fn connect(
        endpoint: &Endpoint,
        addr: impl Into<EndpointAddr>,
    ) -> Result<Self, TransportError> {
        let conn = tokio::time::timeout(
            Duration::from_millis(QUIC_CONNECT_TIMEOUT_MS),
            endpoint.connect(addr, XENIA_QUIC_ALPN),
        )
        .await
        .map_err(|_| TransportError::TimedOut {
            operation: "quic_connect",
            timeout_ms: QUIC_CONNECT_TIMEOUT_MS,
        })?
        .map_err(|e| TransportError::from(QuicError::Connect(e.to_string())))?;
        Self::open(conn).await
    }

    /// Accept one incoming Iroh connection and its first bidirectional stream.
    pub async fn accept_one(endpoint: &Endpoint) -> Result<Self, TransportError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::from(QuicError::EndpointClosed))?;
        let conn = tokio::time::timeout(Duration::from_millis(QUIC_CONNECT_TIMEOUT_MS), incoming)
            .await
            .map_err(|_| TransportError::TimedOut {
                operation: "quic_accept_connection",
                timeout_ms: QUIC_CONNECT_TIMEOUT_MS,
            })?
            .map_err(|e| TransportError::from(QuicError::Accept(e.to_string())))?;
        Self::accept_stream(conn).await
    }

    /// Open a new bidirectional stream on an established connection.
    pub async fn open(conn: Connection) -> Result<Self, TransportError> {
        tokio::time::timeout(
            Duration::from_millis(QUIC_STREAM_OPEN_TIMEOUT_MS),
            async move {
                let (mut send, recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| TransportError::from(QuicError::Stream(e.to_string())))?;
                send.write_all(STREAM_PREFACE)
                    .await
                    .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
                debug!("iroh quic stream opened");
                Ok(Self::new(conn, send, recv))
            },
        )
        .await
        .map_err(|_| TransportError::TimedOut {
            operation: "quic_open_stream",
            timeout_ms: QUIC_STREAM_OPEN_TIMEOUT_MS,
        })?
    }

    /// Accept the next bidirectional stream on an established connection.
    pub async fn accept_stream(conn: Connection) -> Result<Self, TransportError> {
        tokio::time::timeout(
            Duration::from_millis(QUIC_STREAM_OPEN_TIMEOUT_MS),
            async move {
                let (send, recv) = conn
                    .accept_bi()
                    .await
                    .map_err(|e| TransportError::from(QuicError::Stream(e.to_string())))?;
                Self::accept_stream_pair(conn, send, recv).await
            },
        )
        .await
        .map_err(|_| TransportError::TimedOut {
            operation: "quic_accept_stream",
            timeout_ms: QUIC_STREAM_OPEN_TIMEOUT_MS,
        })?
    }

    /// Gracefully finish the sending side of the transport stream.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))
    }

    /// Subscribe to redacted Iroh path events.
    ///
    /// The returned stream owns an additional connection handle and must be
    /// dropped when monitoring is no longer required. Raw transport addresses
    /// are classified but never retained or formatted. If Iroh reports a
    /// lagged subscriber, the event includes a fresh open-path snapshot while
    /// `history_complete` remains false to preserve the fact that history was
    /// lost.
    pub fn path_events(&self) -> impl Stream<Item = QuicPathEvent> + Send + 'static {
        let connection = self.conn.clone();
        let started = Instant::now();
        let mut observer_sequence = 0_u64;
        let mut history_complete = true;

        self.conn.path_events().map(move |event| {
            observer_sequence = observer_sequence.saturating_add(1);
            let observed_us = duration_micros_u64(started.elapsed());

            match event {
                PathEvent::Opened {
                    id,
                    remote_addr,
                    ..
                } => {
                    let snapshot = snapshot_one_path(&connection, id);
                    make_path_event(
                        observer_sequence,
                        observed_us,
                        QuicPathEventKind::Opened,
                        Some(id.to_string()),
                        Some(classify_transport_addr(&remote_addr)),
                        snapshot.as_ref().map(|path| path.selected_for_transmit),
                        None,
                        snapshot.and_then(|path| path.stats),
                        None,
                        history_complete,
                    )
                }
                PathEvent::Closed {
                    id,
                    remote_addr,
                    last_stats,
                    ..
                } => make_path_event(
                    observer_sequence,
                    observed_us,
                    QuicPathEventKind::Closed,
                    Some(id.to_string()),
                    Some(classify_transport_addr(&remote_addr)),
                    Some(false),
                    None,
                    Some(summarize_path_stats(&last_stats)),
                    None,
                    history_complete,
                ),
                PathEvent::Selected {
                    id,
                    remote_addr,
                    ..
                } => {
                    let snapshot = snapshot_one_path(&connection, id);
                    make_path_event(
                        observer_sequence,
                        observed_us,
                        QuicPathEventKind::Selected,
                        Some(id.to_string()),
                        Some(classify_transport_addr(&remote_addr)),
                        Some(true),
                        None,
                        snapshot.and_then(|path| path.stats),
                        None,
                        history_complete,
                    )
                }
                PathEvent::Lagged { missed, .. } => {
                    history_complete = false;
                    make_path_event(
                        observer_sequence,
                        observed_us,
                        QuicPathEventKind::Lagged,
                        None,
                        None,
                        None,
                        Some(missed),
                        None,
                        Some(snapshot_open_paths(&connection)),
                        history_complete,
                    )
                }
                _ => make_path_event(
                    observer_sequence,
                    observed_us,
                    QuicPathEventKind::Unknown,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    history_complete,
                ),
            }
        })
    }

    /// Wait until the peer closes the underlying QUIC connection.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }

    /// Split into independently-owned send/recv halves — Iroh's
    /// `SendStream`/`RecvStream` are already separate fields
    /// internally, so this just repackages them. See
    /// [`xenia_peer_core::transport::Transport`]'s doc comment for why
    /// this exists. The connection handle (needed for `finish`/`closed`
    /// during teardown) stays with the send half.
    pub fn split(self) -> (QuicSendHalf, QuicRecvHalf) {
        (
            QuicSendHalf {
                conn: self.conn,
                send: self.send,
            },
            QuicRecvHalf { recv: self.recv },
        )
    }

    async fn accept_stream_pair(
        conn: Connection,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Self, TransportError> {
        let mut preface = [0u8; STREAM_PREFACE.len()];
        recv.read_exact(&mut preface).await.map_err(|e| {
            let msg = e.to_string();
            if is_stream_eof(&msg) {
                TransportError::UnexpectedEof
            } else {
                TransportError::from(QuicError::Io(msg))
            }
        })?;
        if &preface != STREAM_PREFACE {
            return Err(TransportError::from(QuicError::Stream(
                "invalid stream preface".to_string(),
            )));
        }

        debug!("iroh quic stream accepted");
        Ok(Self::new(conn, send, recv))
    }
}

fn is_stream_eof(msg: &str) -> bool {
    msg.contains("end of stream") || msg.contains("closed") || msg.contains("reset")
}

/// Write one length-prefixed envelope to a QUIC send stream. Shared by
/// [`QuicTransport`] and [`QuicSendHalf`].
async fn write_envelope_with_timeout(
    send: &mut SendStream,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), TransportError> {
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::EnvelopeTooLarge(u32::MAX))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }

    tokio::time::timeout(timeout, async {
        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
        send.write_all(bytes)
            .await
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
        Ok(())
    })
    .await
    .map_err(|_| TransportError::TimedOut {
        operation: "send_envelope",
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
    })?
}

async fn write_envelope(send: &mut SendStream, bytes: &[u8]) -> Result<(), TransportError> {
    write_envelope_with_timeout(send, bytes, Duration::from_millis(SEND_STALL_TIMEOUT_MS)).await
}

async fn read_envelope_with_timeout(
    recv: &mut RecvStream,
    timeout: Duration,
) -> Result<Vec<u8>, TransportError> {
    tokio::time::timeout(timeout, async {
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.map_err(|e| {
            let msg = e.to_string();
            if is_stream_eof(&msg) {
                TransportError::UnexpectedEof
            } else {
                TransportError::from(QuicError::Io(msg))
            }
        })?;

        let len = u32::from_be_bytes(len_buf);
        if len > MAX_ENVELOPE_BYTES {
            return Err(TransportError::EnvelopeTooLarge(len));
        }

        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf).await.map_err(|e| {
            let msg = e.to_string();
            if is_stream_eof(&msg) {
                TransportError::UnexpectedEof
            } else {
                TransportError::from(QuicError::Io(msg))
            }
        })?;
        Ok(buf)
    })
    .await
    .map_err(|_| TransportError::TimedOut {
        operation: "recv_envelope",
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
    })?
}

async fn read_envelope(recv: &mut RecvStream) -> Result<Vec<u8>, TransportError> {
    read_envelope_with_timeout(recv, Duration::from_millis(RECEIVE_ENVELOPE_TIMEOUT_MS)).await
}

impl Transport for QuicTransport {
    fn transport_profile(&self) -> TransportProfileV1 {
        TransportProfileV1::current(TransportKind::Quic)
    }

    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.send, bytes).await
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.recv).await
    }
}

/// Send-only half of a split [`QuicTransport`]. Also carries the
/// `Connection` handle so callers can still `finish`/`closed` during
/// teardown after splitting.
pub struct QuicSendHalf {
    conn: Connection,
    send: SendStream,
}

impl QuicSendHalf {
    /// Gracefully finish the sending side of the stream.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))
    }

    /// Wait until the peer closes the underlying QUIC connection.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }
}

impl SendEnvelope for QuicSendHalf {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.send, bytes).await
    }
}

/// Receive-only half of a split [`QuicTransport`].
pub struct QuicRecvHalf {
    recv: RecvStream,
}

impl RecvEnvelope for QuicRecvHalf {
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.recv).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_classification_is_coarse_and_never_needs_raw_address_text() {
        assert_eq!(
            route_class_from_flags(true, false, false),
            QuicRouteClass::Relay
        );
        assert_eq!(
            route_class_from_flags(false, true, false),
            QuicRouteClass::DirectIp
        );
        assert_eq!(
            route_class_from_flags(false, false, true),
            QuicRouteClass::Custom
        );
        assert_eq!(
            route_class_from_flags(false, false, false),
            QuicRouteClass::Unknown
        );
    }

    #[test]
    fn redacted_path_event_serialization_contains_no_address_fields() {
        let event = make_path_event(
            1,
            2_500,
            QuicPathEventKind::Selected,
            Some("path-0".to_string()),
            Some(QuicRouteClass::Relay),
            Some(true),
            None,
            Some(QuicPathStats {
                rtt_us: 12_000,
                congestion_window_bytes: 65_536,
                congestion_events: 2,
                lost_packets: 3,
                lost_bytes: 3_600,
                current_mtu_bytes: 1_200,
            }),
            None,
            true,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("path-0"));
        assert!(json.contains("relay"));
        assert!(!json.contains("remote_addr"));
        assert!(!json.contains("local_addr"));
        assert!(!json.contains("relay.example"));
        assert!(!json.contains("10.0.0.1"));
    }

    #[test]
    fn lagged_path_event_carries_a_reconciliation_snapshot_and_marks_history_incomplete() {
        let event = make_path_event(
            9,
            91_000,
            QuicPathEventKind::Lagged,
            None,
            None,
            None,
            Some(7),
            None,
            Some(vec![QuicPathSnapshot {
                path_id: "path-1".to_string(),
                route_class: QuicRouteClass::DirectIp,
                selected_for_transmit: true,
                stats: None,
            }]),
            false,
        );
        assert_eq!(event.missed_events, Some(7));
        assert!(!event.history_complete);
        assert_eq!(event.reconciled_paths.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn relay_policy_defaults_to_direct_only() {
        assert_eq!(
            RelayPolicy::parse("", None).unwrap(),
            RelayPolicy::DirectOnly
        );
        assert_eq!(
            RelayPolicy::parse("direct-only", None).unwrap(),
            RelayPolicy::DirectOnly
        );
        assert_eq!(
            RelayPolicy::parse("disabled", None).unwrap(),
            RelayPolicy::DirectOnly
        );
    }

    #[test]
    fn relay_policy_supports_explicit_public_relay() {
        let policy = RelayPolicy::parse("public-relay", None).unwrap();
        assert_eq!(policy.label(), "public-relay");
        assert!(matches!(policy.to_iroh_mode(), RelayMode::Default));
    }

    #[test]
    fn relay_policy_accepts_unique_https_custom_relays() {
        let policy = RelayPolicy::parse(
            "custom",
            Some("https://relay-a.example.test, https://relay-b.example.test"),
        )
        .unwrap();
        assert_eq!(policy.label(), "custom-relay");
        assert!(matches!(policy, RelayPolicy::Custom(ref relays) if relays.len() == 2));
    }

    #[test]
    fn relay_policy_network_profile_binds_mode_and_custom_url_set() {
        assert_eq!(
            RelayPolicy::DirectOnly.network_path_profile().unwrap(),
            NetworkPathProfileV1::current(TransportKind::Quic)
        );
        assert_eq!(
            RelayPolicy::PublicRelay.network_path_profile().unwrap(),
            NetworkPathProfileV1::public_relay()
        );

        let first = RelayPolicy::parse(
            "custom",
            Some("https://relay-a.example.test,https://relay-b.example.test"),
        )
        .unwrap()
        .network_path_profile()
        .unwrap();
        let reversed = RelayPolicy::parse(
            "custom",
            Some("https://relay-b.example.test,https://relay-a.example.test"),
        )
        .unwrap()
        .network_path_profile()
        .unwrap();
        assert_ne!(first, reversed);
        assert_eq!(
            first.relay_mode,
            xenia_peer_core::transport::NetworkRelayModeV1::Custom
        );
        assert!(!format!("{first:?}").contains("relay-a.example.test"));
    }

    #[test]
    fn relay_policy_rejects_empty_duplicate_invalid_and_unsupported_configuration() {
        assert!(RelayPolicy::parse("custom", None).is_err());
        assert!(RelayPolicy::parse("custom", Some("")).is_err());
        assert!(RelayPolicy::parse("custom", Some("https://relay.example.test,")).is_err());
        assert!(
            RelayPolicy::parse(
                "custom",
                Some("https://relay.example.test, https://relay.example.test")
            )
            .is_err()
        );
        assert!(RelayPolicy::parse("custom", Some("http://relay.example.test")).is_err());
        assert!(RelayPolicy::parse("custom", Some("not-a-url")).is_err());
        assert!(RelayPolicy::parse("automatic-magic", None).is_err());
    }

    #[test]
    fn wire_constants_are_stable() {
        // These are on the wire; a change silently breaks interop with peers
        // running an older build.
        assert_eq!(XENIA_QUIC_ALPN, b"xenia/transport/quic/0");
        assert_eq!(STREAM_PREFACE, b"XENIAQ0\0");
        assert_eq!(STREAM_PREFACE.len(), 8);
    }

    #[test]
    fn quic_availability_deadlines_match_authenticated_profile() {
        let profile = xenia_peer_core::transport::TransportAvailabilityProfileV1::current(
            TransportKind::Quic,
        );
        assert_eq!(profile.send_stall_timeout_ms, SEND_STALL_TIMEOUT_MS);
        assert_eq!(
            profile.receive_envelope_timeout_ms,
            RECEIVE_ENVELOPE_TIMEOUT_MS
        );
        assert!(!profile.carrier_keepalive_resets_application_idle);
    }

    #[test]
    fn decode_endpoint_addr_rejects_garbage() {
        // Non-base58 characters (0, O, I, l are not in the alphabet).
        assert!(decode_endpoint_addr("iroh:0OIl").is_err());
        // Empty.
        assert!(decode_endpoint_addr("").is_err());
        // Valid base58 whose decoded bytes are not an EndpointAddr JSON.
        let token = format!("iroh:{}", bs58::encode(b"not endpoint json").into_string());
        assert!(decode_endpoint_addr(&token).is_err());
    }

    #[test]
    fn decode_endpoint_addr_tolerates_a_missing_prefix() {
        // The prefix is stripped when present and ignored when absent; either
        // way an un-decodable body errors rather than panicking.
        let body = bs58::encode(b"still not json").into_string();
        assert!(decode_endpoint_addr(&body).is_err());
        assert!(decode_endpoint_addr(&format!("iroh:{body}")).is_err());
    }

    #[test]
    fn is_stream_eof_classifies_teardown_messages() {
        assert!(is_stream_eof("the connection was closed"));
        assert!(is_stream_eof("stream reset by peer"));
        assert!(is_stream_eof("reached end of stream"));
        assert!(!is_stream_eof("permission denied"));
        assert!(!is_stream_eof("timed out"));
    }

    #[test]
    fn quic_error_maps_to_the_uniform_transport_error() {
        // EndpointClosed is the graceful-shutdown signal -> UnexpectedEof.
        assert!(matches!(
            TransportError::from(QuicError::EndpointClosed),
            TransportError::UnexpectedEof
        ));
        // Everything else collapses to Io so the trait contract stays uniform.
        assert!(matches!(
            TransportError::from(QuicError::Connect("x".into())),
            TransportError::Io(_)
        ));
        assert!(matches!(
            TransportError::from(QuicError::Stream("y".into())),
            TransportError::Io(_)
        ));
    }
}
