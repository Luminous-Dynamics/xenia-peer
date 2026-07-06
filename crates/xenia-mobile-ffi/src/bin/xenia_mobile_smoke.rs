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
//! Usage: `xenia_mobile_smoke <host:port> [passthrough|hdc]`

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
        _ => MobileCodec::Passthrough,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    println!("xenia_mobile_smoke: connecting to {host_port} ({codec:?})");
    let engine = ViewerEngine::connect(rt.handle(), host_port, codec);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut last_state = None;
    let mut frames_seen = 0u32;
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
        if let Some(frame) = engine.poll_frame() {
            frames_seen += 1;
            println!(
                "frame {frames_seen}: {}x{} ({} bytes, pts={}ms)",
                frame.width,
                frame.height,
                frame.rgba.len(),
                frame.pts_ms
            );
            if frames_seen >= 5 {
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
