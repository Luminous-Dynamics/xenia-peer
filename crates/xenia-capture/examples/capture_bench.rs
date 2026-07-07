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
// DURATION_SECS measures steady-state throughput starting from the first
// successfully captured frame, not total process runtime — setup (portal
// negotiation, and on Linux occasional retries past a known upstream D-Bus
// race, see scap_backend.rs's MAX_BUILD_ATTEMPTS) can legitimately take a
// while and must not eat into the fps measurement window. A separate
// internal 90s setup_timeout bounds the pre-first-frame wait so a truly
// broken backend still terminates.
//
// On Linux this also opens a small always-repainting XWayland window for
// the run's duration: PipeWire's ScreenCast is damage-driven and only
// pushes frames when the screen visibly changes, so a static desktop
// under-reports fps regardless of how fast the pipeline actually is (see
// mycelix-sovereign/docs/capture-validation-runbook.md, 2026-07-02
// KDE-Wayland results). No manual mouse movement should be needed anymore.
//
// Usage:
//
//   cargo run -p xenia-capture --features scap-backend --example capture_bench
//
// Env overrides:
//
//   FRAMES=N            target frame count (default 300)
//   DURATION_SECS=N     steady-state measurement window, from first frame (default 30)
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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use xenia_capture::{ScapCapture, ScapOptions, ScapResolution, ScreenCapture};

/// PipeWire's ScreenCast implementations are damage-driven: they only push
/// a new frame when on-screen content visibly changes. Against a static,
/// idle desktop this harness under-reports fps regardless of how fast the
/// capture pipeline actually is (see mycelix-sovereign's
/// capture-validation-runbook.md, 2026-07-02 KDE-Wayland results). Rather
/// than depend on a human moving the mouse during every future run, open a
/// small override-redirect XWayland window and repaint it continuously for
/// the benchmark's duration — that's real, guaranteed compositor damage on
/// any desktop with XWayland (effectively universal on Linux desktops),
/// independent of whether the compositor renders the cursor as part of the
/// captured buffer or a separate hardware overlay.
///
/// Best-effort: if no X11/XWayland connection is available (e.g. a pure
/// Wayland-only session with Xwayland disabled), this prints a warning and
/// the benchmark proceeds without synthetic activity — same as before this
/// harness existed.
struct ActivityGenerator {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ActivityGenerator {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("xenia-capture-bench-activity".into())
            .spawn(move || {
                if let Err(e) = run_activity_window(&stop_for_thread) {
                    eprintln!(
                        "  warning: on-screen activity generator unavailable ({e}); \
                         fps measurement may under-report on an idle desktop. \
                         Move the mouse / interact with a window during the run \
                         for a meaningful number."
                    );
                }
            })
            .expect("failed to spawn activity generator thread");
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for ActivityGenerator {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_activity_window(stop: &AtomicBool) -> Result<(), Box<dyn std::error::Error>> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        ChangeWindowAttributesAux, ConnectionExt, CreateWindowAux, WindowClass,
    };

    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let win_id = conn.generate_id()?;

    conn.create_window(
        screen.root_depth,
        win_id,
        screen.root,
        0,
        0,
        64,
        64,
        0,
        WindowClass::INPUT_OUTPUT,
        screen.root_visual,
        &CreateWindowAux::new()
            .background_pixel(screen.black_pixel)
            .override_redirect(1),
    )?;
    conn.map_window(win_id)?;
    conn.flush()?;

    let mut toggle = false;
    while !stop.load(Ordering::Relaxed) {
        toggle = !toggle;
        let color = if toggle {
            screen.black_pixel
        } else {
            screen.white_pixel
        };
        conn.change_window_attributes(
            win_id,
            &ChangeWindowAttributesAux::new().background_pixel(color),
        )?;
        conn.clear_area(false, win_id, 0, 0, 64, 64)?;
        conn.flush()?;
        std::thread::sleep(Duration::from_millis(33));
    }

    conn.destroy_window(win_id)?;
    conn.flush()?;
    Ok(())
}

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

    // Kept alive for the whole benchmark; see ActivityGenerator's doc
    // comment for why this exists.
    let _activity = ActivityGenerator::start();

    let mut frames = 0usize;
    let mut errors = 0usize;
    let mut empty_polls = 0usize;
    let mut first_frame_at: Option<Duration> = None;
    let mut steady_state_start: Option<Instant> = None;
    let mut last_bytes = 0usize;
    let mut last_w = 0u32;
    let mut last_h = 0u32;
    let mut dumped = false;

    // Setup can legitimately take a while: the backend may retry past a
    // known upstream D-Bus race (scap_backend.rs's MAX_BUILD_ATTEMPTS), and
    // each failed attempt burns close to scap's own ~10s internal timeout
    // before giving up and retrying. That dead time must not eat into the
    // fps measurement window, or a flaky-but-eventually-successful setup
    // makes a perfectly fine capture pipeline look slow. `duration_target`
    // is the steady-state measurement window, counted from the first
    // successfully captured frame; `setup_timeout` bounds the pre-first-
    // frame wait so a truly broken backend still terminates.
    let setup_timeout = Duration::from_secs(90);

    let start = Instant::now();
    loop {
        let past_deadline = match steady_state_start {
            Some(steady_start) => steady_start.elapsed() >= duration_target,
            None => start.elapsed() >= setup_timeout,
        };
        if past_deadline || frames >= frames_target {
            break;
        }
        match cap.capture() {
            Ok(Some(frame)) => {
                if first_frame_at.is_none() {
                    first_frame_at = Some(start.elapsed());
                    steady_state_start = Some(Instant::now());
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

    let total_elapsed = start.elapsed();
    // Steady-state window: from first successful frame, not process start —
    // see the setup_timeout comment above for why. Falls back to total
    // elapsed if no frame ever arrived (so a zero-frame run reports 0 fps
    // via the total wall clock rather than dividing by nothing).
    let steady_elapsed = steady_state_start
        .map(|s| s.elapsed())
        .unwrap_or(total_elapsed);
    let effective_fps = if steady_elapsed.as_secs_f64() > 0.0 {
        frames as f64 / steady_elapsed.as_secs_f64()
    } else {
        0.0
    };
    let mbps = if steady_elapsed.as_secs_f64() > 0.0 && last_bytes > 0 {
        (frames as f64 * last_bytes as f64) / steady_elapsed.as_secs_f64() / 1_000_000.0
    } else {
        0.0
    };

    println!();
    println!("Results");
    println!("  frames:             {frames}");
    println!("  total elapsed:      {:?}", total_elapsed);
    println!("  steady-state:       {:?}", steady_elapsed);
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
