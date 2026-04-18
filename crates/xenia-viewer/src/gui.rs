// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! egui-based GUI for `xenia-viewer`.
//!
//! **M4 scaffold.** A minimal `eframe::App` that pulls the latest
//! decoded RGBA frame from a shared slot, uploads it to an egui
//! texture, and renders it at 1:1 in the central panel. Status bar
//! shows codec + transport + frames-received + last-frame byte
//! size.
//!
//! The receive/decode pipeline runs on a background tokio runtime
//! and writes each decoded frame into the shared slot; egui polls
//! the slot each `update()` call and replaces its texture if a new
//! frame is present. A single-slot Mutex is correct here even
//! though it drops intermediate frames on slow repaint — a viewer
//! that falls behind should display the most recent screen, not a
//! queued stale one.
//!
//! Input capture (mouse / keyboard → `RawInput` back to the
//! daemon) is NOT wired yet; that's M2.

use std::sync::{Arc, Mutex};

use eframe::egui;

/// A single decoded frame ready for display. `rgba` length MUST
/// equal `width * height * 4`.
pub struct FrameSlot {
    /// Latest frame, replaced on every arrival. `None` until the
    /// first frame lands.
    pub latest: Mutex<Option<FrameData>>,
}

/// Decoded RGBA frame shared between the receive task and the
/// egui render loop.
pub struct FrameData {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Tightly packed RGBA8 bytes. Length = `width * height * 4`.
    pub rgba: Vec<u8>,
    /// Sequence number of this frame in the stream.
    pub seq: u64,
    /// Payload size of the corresponding sealed envelope (before
    /// decode). Displayed in the status bar so the user can eyeball
    /// codec efficiency.
    pub wire_bytes: usize,
}

impl FrameSlot {
    /// Empty slot — no frame yet.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            latest: Mutex::new(None),
        })
    }

    /// Replace the slot with a new frame. Always overwrites; we
    /// deliberately drop any un-rendered prior frame because the
    /// user wants the latest screen, not a stale one.
    pub fn put(&self, frame: FrameData) {
        if let Ok(mut g) = self.latest.lock() {
            *g = Some(frame);
        }
    }

    /// Take the current frame out of the slot (if any). The egui
    /// render loop calls this; once taken the slot is empty until
    /// the next `put`.
    pub fn take(&self) -> Option<FrameData> {
        self.latest.lock().ok().and_then(|mut g| g.take())
    }
}

impl Default for FrameSlot {
    fn default() -> Self {
        Self {
            latest: Mutex::new(None),
        }
    }
}

/// Parameters baked into the GUI once at startup.
pub struct ViewerConfig {
    /// Human-readable codec label shown in the status bar.
    pub codec: String,
    /// Human-readable transport label shown in the status bar.
    pub transport: String,
    /// Remote daemon address (for the title bar).
    pub peer_addr: String,
}

/// eframe::App implementing the viewer window.
pub struct ViewerApp {
    slot: Arc<FrameSlot>,
    texture: Option<egui::TextureHandle>,
    config: ViewerConfig,
    frames_received: u64,
    last_wire_bytes: usize,
    last_frame_seq: u64,
    // Simple rolling fps: timestamp of last ~30 frames.
    recent_frame_instants: std::collections::VecDeque<std::time::Instant>,
}

impl ViewerApp {
    /// Construct the app. Owns the shared `FrameSlot` so the
    /// background receive task can `put` into it by cloning the
    /// `Arc`.
    pub fn new(slot: Arc<FrameSlot>, config: ViewerConfig) -> Self {
        Self {
            slot,
            texture: None,
            config,
            frames_received: 0,
            last_wire_bytes: 0,
            last_frame_seq: 0,
            recent_frame_instants: std::collections::VecDeque::with_capacity(64),
        }
    }

    fn fps(&self) -> f32 {
        if self.recent_frame_instants.len() < 2 {
            return 0.0;
        }
        let first = self.recent_frame_instants.front().unwrap();
        let last = self.recent_frame_instants.back().unwrap();
        let span = last.duration_since(*first).as_secs_f32();
        if span <= 0.0 {
            return 0.0;
        }
        (self.recent_frame_instants.len() as f32 - 1.0) / span
    }
}

impl eframe::App for ViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(frame) = self.slot.take() {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [frame.width as usize, frame.height as usize],
                &frame.rgba,
            );
            self.texture =
                Some(ctx.load_texture("xenia-frame", image, egui::TextureOptions::NEAREST));
            self.frames_received += 1;
            self.last_wire_bytes = frame.wire_bytes;
            self.last_frame_seq = frame.seq;

            let now = std::time::Instant::now();
            self.recent_frame_instants.push_back(now);
            while self.recent_frame_instants.len() > 32 {
                self.recent_frame_instants.pop_front();
            }
        }

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("peer: {}", self.config.peer_addr));
                ui.separator();
                ui.label(format!("codec: {}", self.config.codec));
                ui.separator();
                ui.label(format!("transport: {}", self.config.transport));
                ui.separator();
                ui.label(format!("frames: {}", self.frames_received));
                ui.separator();
                ui.label(format!("last wire: {} B", self.last_wire_bytes));
                ui.separator();
                ui.label(format!("fps: {:.1}", self.fps()));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(tex) = &self.texture {
                ui.add(
                    egui::Image::new(tex)
                        .fit_to_exact_size(tex.size_vec2())
                        .maintain_aspect_ratio(true),
                );
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Waiting for first frame…")
                            .size(18.0)
                            .italics(),
                    );
                });
            }
        });

        // Keep the UI live so newly arriving frames show up without
        // requiring user input to trigger a repaint. Throttling is
        // fine for a remote-viewer at ~60fps target.
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}
