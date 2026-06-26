// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// capture-bench — W0 scap real-hardware validation harness.
//
// Runs a timed capture session against `ScapCapture`, reports effective
// FPS, first-frame latency, MB/s, try_recv Empty polls, and errors.
// Pass criteria (matching ADR 0001 §Pending validation): >= 15 fps
// sustained over 30s at native resolution, zero errors, BGRA→RGBA
// conversion producing non-zero alpha.
//
// Usage:
//
//   cargo run -p xenia-capture --features scap-backend --example capture_bench
//
// Env overrides:
//
//   FRAMES=N            target frame count (default 300)
//   DURATION_SECS=N     max wall-clock duration (default 30)
//   FPS=N               requested capture fps (default 30)
//   DUMP_FRAME=path     dump first captured frame as raw RGBA to this path
//
// Platform notes (ADR 0001 §Known upstream issues):
// - macOS will trigger the TCC Screen Recording prompt on first run.
//   That's expected; the reported first_frame_latency includes prompt
//   time.
// - Linux requires a Wayland compositor with PipeWire + xdg-desktop-
//   portal. The portal picker appears during start_capture() inside
//   the worker thread.
// - Windows Capturer is !Send upstream (scap #145); we construct it
//   inside the worker, so this should be transparent here.

use std::env;
use std::time::{Duration, Instant};

use xenia_capture::{ScapCapture, ScapOptions, ScapResolution, ScreenCapture};

fn main() {
    let frames_target: usize = env::var("FRAMES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let duration_target = Duration::from_secs(
        env::var("DURATION_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30),
    );
    let fps: u32 = env::var("FPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let dump_path = env::var("DUMP_FRAME").ok();

    println!("xenia-capture bench — W0 scap validation harness");
    println!("  target frames:    {frames_target}");
    println!("  target duration:  {:?}", duration_target);
    println!("  requested fps:    {fps}");
    println!();

    if !ScapCapture::is_available() {
        eprintln!("scap not available on this host (platform unsupported or");
        eprintln!("screen-recording permission not granted).");
        eprintln!();
        eprintln!("macOS: grant 'Screen Recording' in System Settings →");
        eprintln!("       Privacy & Security → Screen Recording, then re-run.");
        eprintln!("Linux: ensure xdg-desktop-portal + a backend (gnome / kde /");
        eprintln!("       wlr) are installed, and you are inside a Wayland session.");
        eprintln!("Windows: WGC requires Windows 10 1903+ and a desktop session.");
        std::process::exit(2);
    }

    let mut cap = match ScapCapture::with_options(ScapOptions {
        fps,
        show_cursor: true,
        resolution: ScapResolution::Native,
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ScapCapture::with_options failed: {e}");
            std::process::exit(3);
        }
    };
    println!("  backend:          {}", cap.backend_name());
    println!();

    let mut frames = 0usize;
    let mut errors = 0usize;
    let mut empty_polls = 0usize;
    let mut first_frame_at: Option<Duration> = None;
    let mut last_bytes = 0usize;
    let mut last_w = 0u32;
    let mut last_h = 0u32;
    let mut dumped = false;

    let start = Instant::now();
    while start.elapsed() < duration_target && frames < frames_target {
        match cap.capture() {
            Ok(Some(frame)) => {
                if first_frame_at.is_none() {
                    first_frame_at = Some(start.elapsed());
                }
                frames += 1;
                let Some(pixels) = frame.pixels() else {
                    eprintln!("  warning: capture returned non-pixel frame; skipping dump");
                    continue;
                };
                last_bytes = pixels.len();
                last_w = frame.width;
                last_h = frame.height;

                if !dumped {
                    if let Some(ref path) = dump_path {
                        if let Err(e) = std::fs::write(path, pixels) {
                            eprintln!("  warning: DUMP_FRAME write failed: {e}");
                        } else {
                            println!("  wrote first-frame RGBA to {path} ({last_bytes} bytes)");
                        }
                    }
                    dumped = true;
                }
            }
            Ok(None) => {
                empty_polls += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                errors += 1;
                eprintln!("  capture error #{errors}: {e}");
                if errors > 10 {
                    eprintln!("  too many errors — bailing");
                    break;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let effective_fps = if elapsed.as_secs_f64() > 0.0 {
        frames as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let mbps = if elapsed.as_secs_f64() > 0.0 && last_bytes > 0 {
        (frames as f64 * last_bytes as f64) / elapsed.as_secs_f64() / 1_000_000.0
    } else {
        0.0
    };

    println!();
    println!("Results");
    println!("  frames:             {frames}");
    println!("  elapsed:            {:?}", elapsed);
    println!("  effective fps:      {effective_fps:.2}");
    println!("  frame dims:         {last_w} x {last_h}");
    println!("  bytes/frame:        {last_bytes}");
    println!("  throughput:         {mbps:.1} MB/s");
    println!(
        "  first-frame lat:    {:?}",
        first_frame_at.unwrap_or_default()
    );
    println!("  empty polls:        {empty_polls}");
    println!("  errors:             {errors}");
    println!();

    let pass = effective_fps >= 15.0 && last_bytes > 0 && errors == 0 && frames > 0;
    if pass {
        println!("VERDICT: PASS (>= 15 fps, no errors, non-zero frame data)");
        std::process::exit(0);
    } else {
        println!("VERDICT: FAIL");
        if effective_fps < 15.0 {
            println!("  - effective_fps {effective_fps:.2} < 15.0 target");
        }
        if last_bytes == 0 {
            println!("  - no frames captured");
        }
        if errors > 0 {
            println!("  - {errors} capture errors occurred");
        }
        std::process::exit(1);
    }
}
