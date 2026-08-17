// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Phase-0 cross-compile/plumbing proof for the Xenia Android app.
//!
//! Calls `xenia_mobile_ffi::engine::ViewerEngine` directly (the safe
//! Rust core, no JNI/C-ABI involved) against a real running
//! `xenia-peer` daemon, to prove the handshake + receive/decode loop
//! works when cross-compiled to `aarch64-linux-android` and run for
//! real on-device via `adb shell`. No Kotlin/Gradle/JNI needed for
//! this proof -- see the project plan's Phase 0/Phase 1 split.
//!
//! Usage: `xenia_mobile_smoke <host:port> [passthrough|hdc|h264] [send-file <path>]`
//!
//! `send-file <path>` is a debugging aid added while diagnosing a real
//! hang hit only on-device (Android) with no visible Rust-side logs --
//! this exercises the exact same `engine::ViewerEngine::send_file`
//! path with full `RUST_LOG=info` visibility on the host, so a bug in
//! `handle_file_transfer_command`/`handle_file_transfer_message` can
//! be reproduced and iterated on without an APK rebuild/install cycle.

use std::time::Duration;

use xenia_mobile_ffi::engine::{MobileCodec, SessionState, ViewerEngine};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let host_port = args.next().unwrap_or_else(|| "127.0.0.1:7900".to_string());
    let codec = match args.next().as_deref() {
        Some("hdc") => MobileCodec::Hdc,
        Some("h264") => MobileCodec::H264,
        _ => MobileCodec::Passthrough,
    };
    let send_file_path = match args.next().as_deref() {
        Some("send-file") => args.next(),
        _ => None,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    println!("xenia_mobile_smoke: connecting to {host_port} ({codec:?})");
    // No file-transfer receive dir for this smoke proof -- it only
    // exercises connect/handshake/frame plumbing (and, with
    // `send-file`, the outgoing send path).
    let engine = ViewerEngine::connect(rt.handle(), host_port, codec, None, None, 100 * 1024 * 1024);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut last_state = None;
    let mut frames_seen = 0u32;
    let mut file_sent = false;
    loop {
        let state = engine.state();
        if Some(state) != last_state {
            println!("state: {state:?}");
            last_state = Some(state);
        }
        if state == SessionState::Error {
            println!("error: {}", engine.last_error().unwrap_or_default());
            std::process::exit(1);
        }
        if state == SessionState::Disconnected {
            println!("disconnected after {frames_seen} frame(s)");
            break;
        }

        if state == SessionState::Connected
            && !file_sent
            && let Some(path) = &send_file_path
        {
            let data = std::fs::read(path).expect("failed to read send-file path");
            let name = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("test-file")
                .to_string();
            println!("sending file: {name} ({} bytes)", data.len());
            match engine.send_file(name, data) {
                Ok(()) => file_sent = true,
                Err(err) => {
                    eprintln!("failed to enqueue file transfer: {err:?}");
                    std::process::exit(1);
                }
            }
        }

        while let Some(event) = engine.poll_file_transfer_event() {
            println!("file-transfer event: {event:?}");
        }

        if let Some(frame) = engine.poll_frame() {
            frames_seen += 1;
            println!(
                "frame {frames_seen}: {}x{} ({} bytes, pts={}ms)",
                frame.width,
                frame.height,
                frame.rgba.len(),
                frame.pts_ms
            );
            if send_file_path.is_none() && frames_seen >= 5 {
                println!("PASS: received {frames_seen} real decoded frames, exiting");
                std::process::exit(0);
            }
        }
        if std::time::Instant::now() > deadline {
            println!("TIMEOUT after 30s (last state: {last_state:?}, frames_seen: {frames_seen})");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
