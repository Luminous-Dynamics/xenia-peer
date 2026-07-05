// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Standalone HDC codec throughput measurement.
//!
//! Isolates `HdcEncoder::encode()`'s own CPU cost from the rest of a
//! real capture pipeline (scrcpy/ADB, HEVC decode, network transport),
//! which is a much larger and more variable source of latency. Useful
//! for telling "the codec itself is slow" apart from "the machine/host
//! pipeline around it is contended" -- the live phone-capture test
//! (T3.4, ROADMAP.md) found HDC starving to 0-1 real frames per 15-25s
//! window at 1008x2244, but that test ran on a heavily-contended shared
//! machine (12+ concurrent Claude sessions), so it couldn't distinguish
//! "HDC is inherently too slow at this resolution" from "the whole box
//! was starved that run."
//!
//! Usage: `cargo run --example hdc_throughput --features hdc [--release] -- [width] [height] [frames]`
//! Defaults to 1008x2244 (the real Pixel 8 Pro resolution from the
//! T3.4 live test) and 60 frames.

#[cfg(feature = "hdc")]
fn main() {
    use std::time::Instant;
    use xenia_video::hdc::HdcEncoder;
    use xenia_video::{EncodeParams, Encoder, PixelFormat};

    let args: Vec<String> = std::env::args().collect();
    let width: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1008);
    let height: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2244);
    let frames: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);

    let params = EncodeParams {
        width,
        height,
        pixel_format: PixelFormat::Rgba,
        target_fps: 30,
        bitrate_kbps: 1000,
    };
    let mut enc = HdcEncoder::new(params);

    // Synthetic frames with real per-frame motion (a moving diagonal
    // gradient), so change detection has real work to do every frame
    // instead of trivially skipping every tile after the keyframe --
    // that would understate cost relative to a real, moving phone
    // screen.
    let frame_size = (width as usize) * (height as usize) * 4;
    let make_frame = |seed: u8| -> Vec<u8> {
        let mut p = vec![0u8; frame_size];
        for y in 0..height as usize {
            for x in 0..width as usize {
                let i = (y * width as usize + x) * 4;
                p[i] = (x as u8).wrapping_add(seed);
                p[i + 1] = (y as u8).wrapping_add(seed);
                p[i + 2] = seed.wrapping_mul(3);
                p[i + 3] = 255;
            }
        }
        p
    };

    println!("HDC throughput: {width}x{height}, {frames} frames (synthetic per-frame motion)");

    let mut durations_ms = Vec::with_capacity(frames);
    for i in 0..frames {
        let frame = make_frame(i as u8);
        let pts_ms = (i as u64) * 33;
        let start = Instant::now();
        let packets = enc.encode(&frame, pts_ms).expect("encode");
        let elapsed = start.elapsed();
        durations_ms.push(elapsed.as_secs_f64() * 1000.0);
        let total_bytes: usize = packets.iter().map(|p| p.bytes.len()).sum();
        println!(
            "frame {i:3}: {:7.2} ms  ({} bytes, keyframe={})",
            elapsed.as_secs_f64() * 1000.0,
            total_bytes,
            packets.first().map(|p| p.is_keyframe).unwrap_or(false)
        );
    }

    let total: f64 = durations_ms.iter().sum();
    let mean = total / durations_ms.len() as f64;
    let max = durations_ms.iter().cloned().fold(0.0, f64::max);
    let min = durations_ms.iter().cloned().fold(f64::MAX, f64::min);
    println!("---");
    println!(
        "mean: {mean:.2} ms/frame ({:.1} fps)  min: {min:.2} ms  max: {max:.2} ms",
        1000.0 / mean
    );
}

#[cfg(not(feature = "hdc"))]
fn main() {
    eprintln!("build with --features hdc to run this example");
}
