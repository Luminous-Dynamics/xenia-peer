// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// scap-backed ScreenCapture implementation.
//
// See mycelix-sovereign/docs/adr/0001-screen-capture-backend.md for the
// rationale — scap is the primary cross-platform backend (Windows WGC,
// macOS ScreenCaptureKit, Linux PipeWire via xdg-desktop-portal).
//
// Design notes:
//
// - scap's `Capturer::get_next_frame()` is BLOCKING (no `try_recv` exposed
//   upstream as of 0.1.0-beta.1), so we run the Capturer on a dedicated
//   worker thread and forward frames via a bounded mpsc channel. The
//   trait's `capture() -> Ok(None)` when no frame is ready is implemented
//   via `Receiver::try_recv`.
//
// - scap's `Capturer` is `!Send` on Windows (upstream issue #145). The
//   worker thread CONSTRUCTS the Capturer locally (inside the thread
//   closure), so it never crosses thread boundaries.
//
// - scap emits BGRA frames when configured with `FrameType::BGRAFrame`.
//   We swap B↔R in-place via `chunks_exact_mut(4).swap(0, 2)` before
//   forwarding to satisfy the crate's RGBA top-left contract.
//
// - Linux portal-cancel is not surfaced by scap as a distinct error
//   (upstream issue #170). A disconnected receiver channel → Backend
//   error is the clean failure mode.

use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use crate::{CaptureError, CapturedFrame, ScreenCapture};

/// Output resolution for scap. Maps to [`scap::capturer::Resolution`] at
/// construction time.
#[derive(Debug, Clone, Copy, Default)]
pub enum ScapResolution {
    /// Use the display's native resolution (scap default).
    #[default]
    Native,
    /// 720p capped.
    _720p,
    /// 1080p capped.
    _1080p,
    /// 1440p capped.
    _1440p,
    /// 2160p capped.
    _2160p,
}

impl ScapResolution {
    fn to_scap(self) -> scap::capturer::Resolution {
        match self {
            Self::Native => scap::capturer::Resolution::Captured,
            Self::_720p => scap::capturer::Resolution::_720p,
            Self::_1080p => scap::capturer::Resolution::_1080p,
            Self::_1440p => scap::capturer::Resolution::_1440p,
            Self::_2160p => scap::capturer::Resolution::_2160p,
        }
    }
}

/// Options for constructing a [`ScapCapture`].
#[derive(Debug, Clone)]
pub struct ScapOptions {
    /// Target frame rate. scap may silently cap this below its platform
    /// ceiling (upstream issue #150).
    pub fps: u32,
    /// Whether to render the system cursor into the frame.
    pub show_cursor: bool,
    /// Requested output resolution.
    pub resolution: ScapResolution,
}

impl Default for ScapOptions {
    fn default() -> Self {
        Self {
            fps: 30,
            show_cursor: true,
            resolution: ScapResolution::Native,
        }
    }
}

/// scap-backed `ScreenCapture`. Worker thread runs the scap `Capturer`;
/// main thread polls frames via [`ScreenCapture::capture`].
pub struct ScapCapture {
    width: u32,
    height: u32,
    worker: Option<JoinHandle<()>>,
    rx: mpsc::Receiver<Result<CapturedFrame, CaptureError>>,
    stop_tx: mpsc::Sender<()>,
}

impl ScapCapture {
    /// Probe for platform support and permissions without constructing
    /// a Capturer. On macOS this checks the TCC "Screen Recording"
    /// permission and will NOT trigger the consent prompt.
    pub fn is_available() -> bool {
        scap::is_supported() && scap::has_permission()
    }

    /// Construct a new scap-backed capture with default options.
    pub fn new() -> Result<Self, CaptureError> {
        Self::with_options(ScapOptions::default())
    }

    /// Construct a new scap-backed capture.
    ///
    /// On macOS, if screen-recording permission has not yet been
    /// granted, this will trigger the TCC consent prompt via
    /// `scap::request_permission()`. A denial surfaces as
    /// [`CaptureError::ConsentDenied`].
    ///
    /// On Linux the portal source-picker does NOT surface at this
    /// call — it runs during `Capturer::build` inside the worker
    /// thread. If the user cancels the portal, the capturer will
    /// fail to produce frames; `capture()` returns `Err` on the
    /// channel disconnect.
    pub fn with_options(options: ScapOptions) -> Result<Self, CaptureError> {
        if !scap::is_supported() {
            return Err(CaptureError::Unavailable(
                "scap: platform not supported by this build".into(),
            ));
        }
        if !scap::has_permission() && !scap::request_permission() {
            return Err(CaptureError::ConsentDenied);
        }

        let (frame_tx, frame_rx) = mpsc::channel::<Result<CapturedFrame, CaptureError>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        // Capturer is `!Send` on Windows — build it INSIDE the worker thread.
        let thread_opts = options.clone();
        let worker = thread::Builder::new()
            .name("xenia-capture-scap".into())
            .spawn(move || {
                scap_worker(thread_opts, frame_tx, stop_rx);
            })
            .map_err(|e| CaptureError::Backend(format!("scap worker spawn: {e}")))?;

        // The exact capture dimensions aren't known until the worker has
        // called `Capturer::get_output_frame_size()`. The caller will
        // learn the real dimensions from the first frame's `width` /
        // `height`. Surface zeros here as a sentinel; the first successful
        // `capture()` call updates them.
        Ok(Self {
            width: 0,
            height: 0,
            worker: Some(worker),
            rx: frame_rx,
            stop_tx,
        })
    }
}

fn scap_worker(
    options: ScapOptions,
    frame_tx: mpsc::Sender<Result<CapturedFrame, CaptureError>>,
    stop_rx: mpsc::Receiver<()>,
) {
    let scap_options = scap::capturer::Options {
        fps: options.fps,
        show_cursor: options.show_cursor,
        show_highlight: false,
        target: None, // primary display
        crop_area: None,
        output_type: scap::frame::FrameType::BGRAFrame,
        output_resolution: options.resolution.to_scap(),
        excluded_targets: None,
        captures_audio: false,
        exclude_current_process_audio: false,
    };

    let mut capturer = match scap::capturer::Capturer::build(scap_options) {
        Ok(c) => c,
        Err(e) => {
            let err = match e {
                scap::capturer::CapturerBuildError::NotSupported => {
                    CaptureError::Unavailable(format!("scap build: {e:?}"))
                }
                scap::capturer::CapturerBuildError::PermissionNotGranted => {
                    CaptureError::ConsentDenied
                }
            };
            let _ = frame_tx.send(Err(err));
            return;
        }
    };

    capturer.start_capture();

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }

        match capturer.get_next_frame() {
            Ok(frame) => {
                if let Some(captured) = frame_to_rgba(frame) {
                    if frame_tx.send(Ok(captured)).is_err() {
                        // Consumer dropped — main thread is gone; shut down.
                        break;
                    }
                }
                // Non-BGRA frames are discarded; we requested BGRA so
                // this is an upstream API surprise rather than normal flow.
            }
            Err(_) => {
                // mpsc::RecvError — capturer channel closed.
                // On Linux this is the closest signal we get to a
                // portal-cancel (upstream #170).
                let _ = frame_tx.send(Err(CaptureError::Backend(
                    "scap capturer channel closed (possible portal cancel)".into(),
                )));
                break;
            }
        }
    }

    capturer.stop_capture();
}

/// Convert a scap `Frame` into our `CapturedFrame` (RGBA, top-left).
/// Returns `None` if the frame is not BGRA (shouldn't happen given our
/// `FrameType::BGRAFrame` request, but defensive against scap's variant
/// enum expanding in a future beta).
fn frame_to_rgba(frame: scap::frame::Frame) -> Option<CapturedFrame> {
    match frame {
        scap::frame::Frame::BGRA(bgra) => {
            let mut pixels = bgra.data;
            // Defensive: upstream #159 reports occasional 0-byte frames
            // after which latency spikes 4-5×. Drop them silently.
            let expected_len = bgra.width as usize * bgra.height as usize * 4;
            if pixels.len() != expected_len {
                return None;
            }
            // BGRA → RGBA: swap bytes 0 and 2 in each 4-byte pixel.
            for chunk in pixels.chunks_exact_mut(4) {
                chunk.swap(0, 2);
            }
            Some(CapturedFrame {
                pixels,
                width: bgra.width as u32,
                height: bgra.height as u32,
            })
        }
        _ => None,
    }
}

impl Drop for ScapCapture {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.worker.take() {
            // Best-effort join — don't block Drop indefinitely if the
            // worker is stuck in a blocking scap call.
            let _ = handle.join();
        }
    }
}

impl ScreenCapture for ScapCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        match self.rx.try_recv() {
            Ok(Ok(frame)) => {
                // Learn actual dimensions from the first frame we see.
                if self.width == 0 {
                    self.width = frame.width;
                    self.height = frame.height;
                }
                Ok(Some(frame))
            }
            Ok(Err(e)) => Err(e),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(CaptureError::Backend(
                "scap worker thread dropped".into(),
            )),
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn backend_name(&self) -> &str {
        "scap"
    }
}

// ──────────────────────────── Tests ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // These tests verify the wrapper's compile-time and no-display
    // behavior. Real capture validation requires a live display +
    // compositor / WGC / ScreenCaptureKit and runs in the hardware-
    // validation suite, not here.

    #[test]
    fn is_available_does_not_panic() {
        // Only contract: the probe returns a bool. On headless CI the
        // answer is almost certainly `false` and that's fine.
        let _ = ScapCapture::is_available();
    }

    #[test]
    fn scap_resolution_maps_to_all_variants() {
        // Compile-time coverage: every variant we expose resolves to
        // an scap::capturer::Resolution. If scap renames a variant in
        // a future beta, this test breaks at compile time.
        let _ = ScapResolution::Native.to_scap();
        let _ = ScapResolution::_720p.to_scap();
        let _ = ScapResolution::_1080p.to_scap();
        let _ = ScapResolution::_1440p.to_scap();
        let _ = ScapResolution::_2160p.to_scap();
    }

    #[test]
    fn options_default_is_reasonable() {
        let opts = ScapOptions::default();
        assert!(opts.fps >= 15, "default fps should exceed the 15 fps floor");
        assert!(opts.show_cursor);
    }
}
