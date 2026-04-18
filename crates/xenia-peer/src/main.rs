// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `xenia-peer` — headless daemon that hosts a Xenia session.
//!
//! **Pre-alpha M0 scaffold.** This binary currently:
//!
//! - Listens on a TCP port for a single incoming viewer connection.
//! - Installs a fixture session key (dev only; M2 replaces with
//!   ML-KEM-768 handshake).
//! - Receives `RawInput` envelopes and logs their sequence + payload
//!   size.
//! - Does **not** capture the screen. Does **not** encode video.
//!   Those land in M1.
//!
//! Real-world deployment will not resemble this scaffold — the point
//! is to prove the transport + session state-machine + consent gate
//! work end-to-end before wiring in the heavy OS plumbing.
//!
//! Roadmap:
//!
//! | Milestone | What lands here |
//! |-----------|-----------------|
//! | **M0** (now) | TCP listener + per-envelope logging. |
//! | M1 | Wayland capture (`wlr-screencopy` on wlroots compositors, `xdg-desktop-portal` on GNOME/KDE); H.264 encode via `ffmpeg-next`. |
//! | M2 | Consent ceremony flow (UI prompt on the host). |
//! | M3 | Iroh QUIC primary transport; WebSocket fallback. |
//! | M4 | Productization: systemd unit, sandboxing, log rotation. |
//!
//! See `docs/ADR-001-m0-architecture.md` for the three strategic
//! decisions that shaped this layout (monorepo, Wayland-exclusive,
//! AGPL-for-binaries).

use clap::Parser;
use tokio::net::TcpListener;
use tracing::{info, warn};
use xenia_peer_core::transport::{TcpTransport, Transport};
use xenia_peer_core::{Session, SessionRole};

/// Dev fixture key. M2 replaces with handshake-derived session key.
const FIXTURE_KEY: [u8; 32] = *b"xenia-peer-m0-stub-fixture-key!!";

#[derive(Parser, Debug)]
#[command(name = "xenia-peer", version, about = "Host daemon for Xenia sessions")]
struct Args {
    /// Address to listen on for incoming viewer connections.
    #[arg(long, default_value = "127.0.0.1:4747")]
    listen: String,

    /// Fixed source_id for the session (hex; exactly 16 chars). Dev
    /// fixture; production sessions randomize per-session.
    #[arg(long, default_value = "7878656e69617068")]
    source_id_hex: String,

    /// Fixed epoch byte.
    #[arg(long, default_value_t = 0x01)]
    epoch: u8,

    /// Exit after receiving this many input envelopes. 0 = run
    /// indefinitely. Useful for M0 smoke tests.
    #[arg(long, default_value_t = 0)]
    max_inputs: u64,
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

    let listener = TcpListener::bind(&args.listen).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, "xenia-peer daemon listening");
    warn!("M0 scaffold: fixture key in use; no screen capture; no consent UI. See ADR-001.");

    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true).ok();
    info!(peer = %peer, "viewer connected");
    let mut transport = TcpTransport::new(stream);

    let mut session = Session::with_fixture(SessionRole::Host, source_id, args.epoch);
    session.install_key(FIXTURE_KEY);

    let mut received: u64 = 0;
    loop {
        if args.max_inputs != 0 && received >= args.max_inputs {
            info!(received, "reached --max-inputs, exiting");
            break;
        }
        let envelope = match transport.recv_envelope().await {
            Ok(e) => e,
            Err(err) => {
                info!(error = %err, "viewer disconnected or transport closed");
                break;
            }
        };
        match session.open_input(&envelope) {
            Ok(input) => {
                received += 1;
                info!(
                    seq = input.sequence,
                    bytes = input.payload.len(),
                    total_received = received,
                    "input received"
                );
            }
            Err(err) => {
                warn!(error = %err, "failed to open input envelope");
            }
        }
    }

    info!(received, "daemon exiting");
    Ok(())
}
