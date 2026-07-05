// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wraps [`crate::scrcpy::stream::ScrcpyCaptureStream`] as a
//! [`xenia_capture::ScreenCapture`] backend -- the new glue that lets a
//! `xenia-peer` daemon stream a real Android phone's screen the same way
//! it streams a desktop's.

use std::path::PathBuf;
use std::time::Duration;

use xenia_capture::{CaptureError, CapturedFrame, FrameData, MonitorDescriptor, ScreenCapture};

use crate::scrcpy::stream::{ScrcpyCaptureStream, StreamError};
use crate::scrcpy::ScrcpyOptions;

/// Path to the vendored scrcpy-server JAR this crate ships, resolved
/// relative to the crate's own source location so callers don't need to
/// know xenia-peer's repo layout.
pub fn vendored_jar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vendor")
        .join(crate::scrcpy::VENDORED_JAR_NAME)
}

/// A real Android device, captured via `scrcpy-server` over ADB.
///
/// Unlike the desktop backends (`TestCapture`, `ScapCapture`), width/height
/// aren't known until the device's video header arrives during `launch` --
/// there's no equivalent of a `--width`/`--height` CLI default to fall
/// back on beforehand.
pub struct ScrcpyScreenCapture {
    stream: ScrcpyCaptureStream,
    width: u32,
    height: u32,
}

impl ScrcpyScreenCapture {
    /// Launch scrcpy-server on `serial` and complete the handshake
    /// (JAR push, reverse tunnel, device-meta + video-header read).
    /// Blocks for up to 5 seconds waiting for the device to connect
    /// (see `ScrcpyCaptureStream::launch`'s doc comment).
    pub fn launch(serial: &str, tcp_port: u16) -> Result<Self, CaptureError> {
        let jar = vendored_jar_path();
        let opts = ScrcpyOptions::cybernetic_defaults(serial, tcp_port);
        let stream = ScrcpyCaptureStream::launch(&jar, &opts)
            .map_err(|e| CaptureError::Backend(format!("scrcpy launch: {e}")))?;
        let header = stream.video_header();
        Ok(Self {
            width: header.width,
            height: header.height,
            stream,
        })
    }

    /// As [`Self::launch`] but with an explicit per-frame read timeout --
    /// see `ScrcpyCaptureStream::launch_with_timeout`'s doc comment for
    /// why the default (500ms) can be too tight on a slower link.
    pub fn launch_with_timeout(
        serial: &str,
        tcp_port: u16,
        read_timeout: Duration,
    ) -> Result<Self, CaptureError> {
        let jar = vendored_jar_path();
        let opts = ScrcpyOptions::cybernetic_defaults(serial, tcp_port);
        let stream = ScrcpyCaptureStream::launch_with_timeout(&jar, &opts, read_timeout)
            .map_err(|e| CaptureError::Backend(format!("scrcpy launch: {e}")))?;
        let header = stream.video_header();
        Ok(Self {
            width: header.width,
            height: header.height,
            stream,
        })
    }
}

impl ScreenCapture for ScrcpyScreenCapture {
    fn capture(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        match self.stream.next_frame() {
            Ok(Some(frame)) => {
                // scrcpy's dynamic-resolution support means dimensions
                // can change mid-stream (e.g. phone rotation) -- keep
                // our cached width/height in sync so `width()`/`height()`
                // stay accurate for callers that check them separately
                // from the frame itself (matches ScapCapture's contract).
                self.width = frame.width;
                self.height = frame.height;
                Ok(Some(CapturedFrame {
                    width: frame.width,
                    height: frame.height,
                    data: FrameData::Pixels(frame.rgba),
                }))
            }
            Ok(None) => Ok(None),
            Err(StreamError::Io(e)) => Err(CaptureError::Backend(format!("scrcpy I/O: {e}"))),
            Err(e) => Err(CaptureError::Backend(format!("scrcpy: {e}"))),
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn enumerate_monitors(&self) -> Vec<MonitorDescriptor> {
        vec![MonitorDescriptor {
            index: 0,
            name: self.stream.device_meta().name.clone(),
            width: self.width,
            height: self.height,
            is_primary: true,
            x_offset: 0,
            y_offset: 0,
        }]
    }

    fn backend_name(&self) -> &str {
        "scrcpy"
    }
}
