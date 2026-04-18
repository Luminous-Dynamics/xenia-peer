// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `xenia-viewer` — native client that connects to an `xenia-peer`
//! daemon and watches the shared session.
//!
//! **Pre-alpha M0 scaffold.** This binary currently:
//!
//! - Connects over TCP to an `xenia-peer` daemon.
//! - Installs the same fixture session key as the daemon (dev only).
//! - Sends a handful of synthetic `RawInput` envelopes as a liveness
//!   probe.
//! - Does **not** render frames. Does **not** decode video. No GUI.
//!
//! Roadmap:
//!
//! | Milestone | What lands here |
//! |-----------|-----------------|
//! | **M0** (now) | CLI that proves the transport + wire. |
//! | M1 | Receive encoded frames from the daemon, decode via `ffmpeg-next`, dump to stdout or a file. |
//! | M2 | Consent ceremony: show the prompt to the user. |
//! | M3 | Iroh QUIC client; WebSocket fallback. |
//! | M4 | `egui` GUI (primary) → `Tauri` for productization. |
//!
//! See `docs/ADR-001-m0-architecture.md` for the three strategic
//! decisions shaping this layout.

use clap::Parser;
use tracing::{info, warn};
use xenia_peer_core::transport::{TcpTransport, Transport};
use xenia_peer_core::{Session, SessionRole};

/// Dev fixture key. MUST match the daemon's value. M2 replaces with
/// handshake-derived key.
const FIXTURE_KEY: [u8; 32] = *b"xenia-peer-m0-stub-fixture-key!!";

#[derive(Parser, Debug)]
#[command(
    name = "xenia-viewer",
    version,
    about = "Native viewer for Xenia sessions"
)]
struct Args {
    /// Address of the xenia-peer daemon to connect to.
    #[arg(long, default_value = "127.0.0.1:4747")]
    connect: String,

    /// Fixed source_id (hex, 16 chars). MUST match the daemon's
    /// `--source-id-hex`.
    #[arg(long, default_value = "7878656e69617068")]
    source_id_hex: String,

    /// Fixed epoch. MUST match the daemon's `--epoch`.
    #[arg(long, default_value_t = 0x01)]
    epoch: u8,

    /// Number of synthetic input probes to send. M1 replaces with
    /// real mouse/keyboard capture.
    #[arg(long, default_value_t = 5)]
    probe_count: u64,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let source_id = parse_source_id(&args.source_id_hex)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    info!(peer = %args.connect, "connecting to xenia-peer daemon");
    warn!("M0 scaffold: fixture key in use; no frame decode; no GUI. See ADR-001.");

    let mut transport = TcpTransport::connect(&args.connect).await?;
    let mut session = Session::with_fixture(SessionRole::Viewer, source_id, args.epoch);
    session.install_key(FIXTURE_KEY);

    for i in 0..args.probe_count {
        let payload = format!(r#"{{"probe":{i},"m0":"hello"}}"#).into_bytes();
        let payload_len = payload.len();
        let envelope = session.seal_input_event(payload)?;
        transport.send_envelope(&envelope).await?;
        info!(seq = i, bytes = payload_len, "input probe sent");
    }

    info!(sent = args.probe_count, "viewer exiting");
    Ok(())
}
