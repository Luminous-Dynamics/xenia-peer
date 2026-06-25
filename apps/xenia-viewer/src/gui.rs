// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! egui-based GUI for `xenia-viewer`.
//!
//! **M4 scaffold.** A minimal `eframe::App` that pulls the latest
//! decoded RGBA frame from a shared slot, uploads it to an egui
//! texture, and renders it at 1:1 in the central panel. Status bar
//! shows codec + transport + frames-received + last-frame byte size,
//! plus the latest host telemetry values.
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
    /// Latest host telemetry batch.
    pub telemetry: Mutex<Option<TelemetryData>>,
    /// Latest audio timing/jitter state.
    pub audio: Mutex<Option<AudioData>>,
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

/// Latest host telemetry values shared between receive task and GUI.
#[derive(Clone, Debug, Default)]
pub struct TelemetryData {
    /// Producing backend name.
    pub backend: String,
    /// CPU usage percentage.
    pub cpu_percent: Option<f64>,
    /// Total host memory in bytes.
    pub memory_total_bytes: Option<u64>,
    /// Used host memory in bytes.
    pub memory_used_bytes: Option<u64>,
    /// Hostname when policy allows it.
    pub host_name: Option<String>,
    /// OS version when policy allows it.
    pub os_version: Option<String>,
    /// Number of samples in the last batch.
    pub samples: usize,
    /// Last telemetry timestamp.
    pub timestamp_ms: u64,
}

/// Latest audio timing state shared between receive task and GUI.
#[derive(Clone, Debug, Default)]
pub struct AudioData {
    /// Audio frames received by the viewer.
    pub frames_received: u64,
    /// Last received sequence.
    pub last_sequence: u64,
    /// Last accepted stream id.
    pub stream_id: u32,
    /// Sample rate in Hz.
    pub sample_rate_hz: u32,
    /// Channel count.
    pub channels: u16,
    /// Frame duration in milliseconds.
    pub frame_duration_ms: u16,
    /// Last capture timestamp.
    pub capture_timestamp_ms: u64,
    /// Duplicate frames detected by jitter buffer.
    pub duplicates: u64,
    /// Late frames detected by jitter buffer.
    pub late: u64,
    /// Missing sequence gaps detected by jitter buffer.
    pub gaps: u64,
    /// Underruns reported by jitter buffer.
    pub underruns: u64,
}

impl FrameSlot {
    /// Empty slot — no frame yet.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            latest: Mutex::new(None),
            telemetry: Mutex::new(None),
            audio: Mutex::new(None),
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

    /// Replace the latest telemetry batch.
    pub fn put_telemetry(&self, telemetry: TelemetryData) {
        if let Ok(mut g) = self.telemetry.lock() {
            *g = Some(telemetry);
        }
    }

    /// Read the latest telemetry batch without clearing it.
    pub fn telemetry(&self) -> Option<TelemetryData> {
        self.telemetry.lock().ok().and_then(|g| g.clone())
    }

    /// Replace the latest audio state.
    pub fn put_audio(&self, audio: AudioData) {
        if let Ok(mut g) = self.audio.lock() {
            *g = Some(audio);
        }
    }

    /// Read the latest audio state without clearing it.
    pub fn audio(&self) -> Option<AudioData> {
        self.audio.lock().ok().and_then(|g| g.clone())
    }
}

impl Default for FrameSlot {
    fn default() -> Self {
        Self {
            latest: Mutex::new(None),
            telemetry: Mutex::new(None),
            audio: Mutex::new(None),
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
    last_telemetry: Option<TelemetryData>,
    last_audio: Option<AudioData>,
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
            last_telemetry: None,
            last_audio: None,
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

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
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
        if let Some(telemetry) = self.slot.telemetry() {
            self.last_telemetry = Some(telemetry);
        }
        if let Some(audio) = self.slot.audio() {
            self.last_audio = Some(audio);
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
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    if let Some(tex) = &self.texture {
                        ui.add(
                            egui::Image::new(tex)
                                .fit_to_exact_size(tex.size_vec2())
                                .maintain_aspect_ratio(true),
                        );
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                egui::RichText::new("Waiting for first frame...")
                                    .size(18.0)
                                    .italics(),
                            );
                        });
                    }
                });

                ui.separator();

                ui.vertical(|ui| {
                    ui.heading("Host");
                    if let Some(telemetry) = &self.last_telemetry {
                        ui.label(format!("telemetry: {}", telemetry.backend));
                        if let Some(cpu) = telemetry.cpu_percent {
                            ui.label(format!("cpu: {:.1}%", cpu));
                        }
                        if let (Some(used), Some(total)) =
                            (telemetry.memory_used_bytes, telemetry.memory_total_bytes)
                        {
                            ui.label(format!(
                                "memory: {} / {}",
                                format_bytes(used),
                                format_bytes(total)
                            ));
                        }
                        if let Some(host) = &telemetry.host_name {
                            ui.label(format!("host: {host}"));
                        }
                        if let Some(os) = &telemetry.os_version {
                            ui.label(format!("os: {os}"));
                        }
                        ui.label(format!("samples: {}", telemetry.samples));
                        ui.label(format!(
                            "age: {} ms",
                            now_ms().saturating_sub(telemetry.timestamp_ms)
                        ));
                    } else {
                        ui.label(
                            egui::RichText::new("Waiting for telemetry...")
                                .size(14.0)
                                .italics(),
                        );
                    }
                });

                ui.separator();

                ui.vertical(|ui| {
                    ui.heading("Audio");
                    if let Some(audio) = &self.last_audio {
                        ui.label(format!("stream: {}", audio.stream_id));
                        ui.label(format!("frames: {}", audio.frames_received));
                        ui.label(format!("last seq: {}", audio.last_sequence));
                        ui.label(format!(
                            "format: {} Hz / {} ch / {} ms",
                            audio.sample_rate_hz, audio.channels, audio.frame_duration_ms
                        ));
                        ui.label(format!(
                            "age: {} ms",
                            now_ms().saturating_sub(audio.capture_timestamp_ms)
                        ));
                        ui.label(format!("gaps: {}", audio.gaps));
                        ui.label(format!("duplicates: {}", audio.duplicates));
                        ui.label(format!("late: {}", audio.late));
                        ui.label(format!("underruns: {}", audio.underruns));
                    } else {
                        ui.label(egui::RichText::new("Audio lane idle").size(14.0).italics());
                    }
                });
            });
        });

        // Keep the UI live so newly arriving frames show up without
        // requiring user input to trigger a repaint. Throttling is
        // fine for a remote-viewer at ~60fps target.
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}
