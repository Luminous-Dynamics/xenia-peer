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
//! daemon): pointer motion/buttons and a common-subset keymap are
//! wired below via `egui::Context::input`. Captured [`InputEvent`]s
//! go out over an unbounded channel to the network task, which seals
//! and sends them concurrently with the frame-receive loop (see
//! `gui_receive_loop` in `main.rs`). Coordinates are normalized
//! against the last-rendered image rect, not the whole window, so
//! pointer activity over the status bar / side panels is ignored.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use eframe::egui;
use xenia_inject::InputEvent;
use xenia_peer_core::RawAudio;

use crate::AudioPlaybackSink;

/// Map a subset of `egui::Key` to Linux evdev keycodes (matching the
/// convention `xenia-inject`'s backends expect — see
/// `xenia-inject/examples/inject_bench.rs`'s `KEY_A = 30` comment).
/// Covers letters, digits, and the keys most useful for real usability
/// testing; not an exhaustive mapping of every `egui::Key` variant.
fn egui_key_to_evdev(key: egui::Key) -> Option<u32> {
    use egui::Key;
    Some(match key {
        Key::A => 30,
        Key::B => 48,
        Key::C => 46,
        Key::D => 32,
        Key::E => 18,
        Key::F => 33,
        Key::G => 34,
        Key::H => 35,
        Key::I => 23,
        Key::J => 36,
        Key::K => 37,
        Key::L => 38,
        Key::M => 50,
        Key::N => 49,
        Key::O => 24,
        Key::P => 25,
        Key::Q => 16,
        Key::R => 19,
        Key::S => 31,
        Key::T => 20,
        Key::U => 22,
        Key::V => 47,
        Key::W => 17,
        Key::X => 45,
        Key::Y => 21,
        Key::Z => 44,
        Key::Num0 => 11,
        Key::Num1 => 2,
        Key::Num2 => 3,
        Key::Num3 => 4,
        Key::Num4 => 5,
        Key::Num5 => 6,
        Key::Num6 => 7,
        Key::Num7 => 8,
        Key::Num8 => 9,
        Key::Num9 => 10,
        Key::Space => 57,
        Key::Enter => 28,
        Key::Escape => 1,
        Key::Backspace => 14,
        Key::Tab => 15,
        Key::ArrowUp => 103,
        Key::ArrowDown => 108,
        Key::ArrowLeft => 105,
        Key::ArrowRight => 106,
        Key::Home => 102,
        Key::End => 107,
        Key::PageUp => 104,
        Key::PageDown => 109,
        Key::Insert => 110,
        Key::Delete => 111,
        Key::Minus => 12,
        Key::Equals => 13,
        Key::Semicolon => 39,
        Key::Quote => 40,
        Key::Backtick => 41,
        Key::Backslash => 43,
        Key::Comma => 51,
        Key::Period => 52,
        Key::Slash => 53,
        Key::OpenBracket => 26,
        Key::CloseBracket => 27,
        Key::F1 => 59,
        Key::F2 => 60,
        Key::F3 => 61,
        Key::F4 => 62,
        Key::F5 => 63,
        Key::F6 => 64,
        Key::F7 => 65,
        Key::F8 => 66,
        Key::F9 => 67,
        Key::F10 => 68,
        Key::F11 => 87,
        Key::F12 => 88,
        _ => return None,
    })
}

/// Bit 0 = Shift, 1 = Ctrl, 2 = Alt, 3 = Meta/Super/Cmd. Matches the
/// convention documented on `xenia_inject::InputEvent::Key.modifiers`.
fn modifiers_bitmask(m: &egui::Modifiers) -> u8 {
    let mut bits = 0u8;
    if m.shift {
        bits |= 1 << 0;
    }
    if m.ctrl {
        bits |= 1 << 1;
    }
    if m.alt {
        bits |= 1 << 2;
    }
    if m.mac_cmd || m.command {
        bits |= 1 << 3;
    }
    bits
}

/// xenia-inject's pointer-button convention (0 = left, 1 = middle,
/// 2 = right) does not match egui's `PointerButton` discriminants
/// (Primary=0/left, Secondary=1/right, Middle=2) -- remap explicitly
/// rather than casting.
fn pointer_button_id(button: egui::PointerButton) -> u8 {
    match button {
        egui::PointerButton::Primary => 0,
        egui::PointerButton::Middle => 1,
        egui::PointerButton::Secondary => 2,
        _ => 3,
    }
}

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
    /// Video presentation/capture timestamp in milliseconds.
    pub timestamp_ms: u64,
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
    /// Audio frames decoded by the viewer.
    pub frames_decoded: u64,
    /// Audio frames inserted into the jitter buffer.
    pub frames_inserted: u64,
    /// Audio frames emitted from the jitter buffer.
    pub frames_emitted: u64,
    /// Audio frames accepted by the playback sink.
    pub frames_played: u64,
    /// Audio samples accepted by the playback sink.
    pub samples_played: u64,
    /// Audio frames rejected by the playback sink policy.
    pub playback_rejected: u64,
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
    /// Buffered frames dropped by jitter buffer depth policy.
    pub dropped: u64,
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
    audio_rx: Option<mpsc::Receiver<RawAudio>>,
    audio_sink: Box<dyn AudioPlaybackSink>,
    frames_received: u64,
    last_wire_bytes: usize,
    last_frame_seq: u64,
    last_video_timestamp_ms: u64,
    last_telemetry: Option<TelemetryData>,
    last_audio: Option<AudioData>,
    // Simple rolling fps: timestamp of last ~30 frames.
    recent_frame_instants: std::collections::VecDeque<std::time::Instant>,
    // Input capture (mouse / keyboard -> daemon). `None` means input
    // is disabled client-side (no channel was wired up).
    input_tx: Option<tokio::sync::mpsc::UnboundedSender<InputEvent>>,
    // On-screen rect of the last-rendered frame image, used to
    // normalize pointer coordinates and to ignore pointer activity
    // over the status bar / side panels.
    image_rect: Option<egui::Rect>,
    last_pointer_pos: Option<egui::Pos2>,
}

impl ViewerApp {
    /// Construct the app. Owns the shared `FrameSlot` so the
    /// background receive task can `put` into it by cloning the
    /// `Arc`.
    pub fn new(
        slot: Arc<FrameSlot>,
        config: ViewerConfig,
        audio_rx: Option<mpsc::Receiver<RawAudio>>,
        audio_sink: Box<dyn AudioPlaybackSink>,
        input_tx: Option<tokio::sync::mpsc::UnboundedSender<InputEvent>>,
    ) -> Self {
        Self {
            slot,
            texture: None,
            config,
            audio_rx,
            audio_sink,
            frames_received: 0,
            last_wire_bytes: 0,
            last_frame_seq: 0,
            last_video_timestamp_ms: 0,
            last_telemetry: None,
            last_audio: None,
            recent_frame_instants: std::collections::VecDeque::with_capacity(64),
            input_tx,
            image_rect: None,
            last_pointer_pos: None,
        }
    }

    /// Normalize a screen-space position against the last-rendered
    /// image rect. `None` if there's no image yet or the position
    /// falls outside it (pointer over a side panel / status bar).
    fn normalize_in_image(&self, pos: egui::Pos2) -> Option<(f32, f32)> {
        let rect = self.image_rect?;
        if !rect.contains(pos) {
            return None;
        }
        let size = rect.size();
        if size.x <= 0.0 || size.y <= 0.0 {
            return None;
        }
        let x = ((pos.x - rect.min.x) / size.x).clamp(0.0, 1.0);
        let y = ((pos.y - rect.min.y) / size.y).clamp(0.0, 1.0);
        Some((x, y))
    }

    /// Send one captured input event to the network task, if input
    /// capture is wired up. Silently drops on a closed channel (the
    /// network side already ended; the GUI keeps rendering
    /// independently until the window closes).
    fn send_input(&self, event: InputEvent) {
        if let Some(tx) = &self.input_tx {
            let _ = tx.send(event);
        }
    }

    /// Poll `ctx` for pointer motion/buttons and keyboard events this
    /// frame, translate to `InputEvent`s, and forward them.
    fn capture_input(&mut self, ctx: &egui::Context) {
        if self.input_tx.is_none() {
            return;
        }

        let (pointer_pos, button_events, key_events) = ctx.input(|i| {
            let pos = i.pointer.interact_pos();
            let buttons = [
                egui::PointerButton::Primary,
                egui::PointerButton::Secondary,
                egui::PointerButton::Middle,
            ]
            .into_iter()
            .filter_map(|button| {
                if i.pointer.button_pressed(button) {
                    Some((button, true))
                } else if i.pointer.button_released(button) {
                    Some((button, false))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
            let keys = i
                .events
                .iter()
                .filter_map(|event| match event {
                    egui::Event::Key {
                        key,
                        pressed,
                        repeat: false,
                        modifiers,
                        ..
                    } => Some((*key, *pressed, *modifiers)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (pos, buttons, keys)
        });

        if let Some(pos) = pointer_pos
            && self.last_pointer_pos != Some(pos)
        {
            self.last_pointer_pos = Some(pos);
            if let Some((x, y)) = self.normalize_in_image(pos) {
                self.send_input(InputEvent::Pointer {
                    x,
                    y,
                    button: 0,
                    pressed: false,
                });
            }
        }

        for (button, pressed) in button_events {
            let Some(pos) = pointer_pos else { continue };
            let Some((x, y)) = self.normalize_in_image(pos) else {
                continue;
            };
            self.send_input(InputEvent::Pointer {
                x,
                y,
                button: pointer_button_id(button),
                pressed,
            });
        }

        for (key, pressed, modifiers) in key_events {
            let Some(code) = egui_key_to_evdev(key) else {
                continue;
            };
            self.send_input(InputEvent::Key {
                code,
                pressed,
                modifiers: modifiers_bitmask(&modifiers),
            });
        }
    }

    fn drain_audio_playback(&mut self) {
        let Some(rx) = &self.audio_rx else {
            return;
        };
        while let Ok(frame) = rx.try_recv() {
            self.audio_sink.submit(&frame);
        }
        let playback = self.audio_sink.stats();
        if let Some(audio) = &mut self.last_audio {
            audio.frames_played = playback.frames_played;
            audio.samples_played = playback.samples_played;
            audio.playback_rejected = audio.playback_rejected.max(playback.rejected);
        }
    }

    fn fps(&self) -> f32 {
        if self.recent_frame_instants.len() < 2 {
            return 0.0;
        }
        let (Some(first), Some(last)) = (
            self.recent_frame_instants.front(),
            self.recent_frame_instants.back(),
        ) else {
            return 0.0;
        };
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
            self.last_video_timestamp_ms = frame.timestamp_ms;

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
        self.drain_audio_playback();

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
                        let response = ui.add(
                            egui::Image::new(tex)
                                .fit_to_exact_size(tex.size_vec2())
                                .maintain_aspect_ratio(true),
                        );
                        self.image_rect = Some(response.rect);
                    } else {
                        self.image_rect = None;
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
                        ui.label(format!("decoded: {}", audio.frames_decoded));
                        ui.label(format!("inserted: {}", audio.frames_inserted));
                        ui.label(format!("emitted: {}", audio.frames_emitted));
                        ui.label(format!("played: {}", audio.frames_played));
                        ui.label(format!("played samples: {}", audio.samples_played));
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
                        ui.label(format!("dropped: {}", audio.dropped));
                        ui.label(format!("playback rejected: {}", audio.playback_rejected));
                        ui.label(format!("underruns: {}", audio.underruns));
                        if self.last_video_timestamp_ms != 0 {
                            let drift_ms = audio.capture_timestamp_ms as i128
                                - self.last_video_timestamp_ms as i128;
                            ui.label(format!("a/v drift: {drift_ms:+} ms"));
                        }
                    } else {
                        ui.label(egui::RichText::new("Audio lane idle").size(14.0).italics());
                    }
                });
            });
        });

        // Capture after rendering so `self.image_rect` reflects
        // exactly what's on screen this frame.
        self.capture_input(ctx);

        // Keep the UI live so newly arriving frames show up without
        // requiring user input to trigger a repaint. Throttling is
        // fine for a remote-viewer at ~60fps target.
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_map_has_no_duplicate_evdev_codes() {
        // All egui::Key variants (not just the mapped subset) --
        // catches copy-paste collisions like accidentally mapping two
        // different keys to the same evdev code.
        let mut seen = std::collections::HashSet::new();
        for key in egui::Key::ALL {
            if let Some(code) = egui_key_to_evdev(*key) {
                assert!(
                    seen.insert(code),
                    "evdev code {code} mapped from more than one egui::Key (last: {key:?})"
                );
            }
        }
    }

    #[test]
    fn key_map_matches_known_evdev_codes() {
        assert_eq!(egui_key_to_evdev(egui::Key::A), Some(30));
        assert_eq!(egui_key_to_evdev(egui::Key::Space), Some(57));
        assert_eq!(egui_key_to_evdev(egui::Key::Enter), Some(28));
        assert_eq!(egui_key_to_evdev(egui::Key::Escape), Some(1));
        assert_eq!(egui_key_to_evdev(egui::Key::Period), Some(52));
        assert_eq!(egui_key_to_evdev(egui::Key::Num0), Some(11));
        assert_eq!(egui_key_to_evdev(egui::Key::F1), Some(59));
    }

    #[test]
    fn pointer_button_mapping_matches_xenia_inject_convention() {
        // xenia-inject: 0 = left, 1 = middle, 2 = right.
        assert_eq!(pointer_button_id(egui::PointerButton::Primary), 0);
        assert_eq!(pointer_button_id(egui::PointerButton::Middle), 1);
        assert_eq!(pointer_button_id(egui::PointerButton::Secondary), 2);
    }

    #[test]
    fn modifiers_bitmask_combines_flags() {
        let mut m = egui::Modifiers::default();
        assert_eq!(modifiers_bitmask(&m), 0);
        m.shift = true;
        assert_eq!(modifiers_bitmask(&m), 0b0001);
        m.ctrl = true;
        assert_eq!(modifiers_bitmask(&m), 0b0011);
        m.alt = true;
        assert_eq!(modifiers_bitmask(&m), 0b0111);
        m.command = true;
        assert_eq!(modifiers_bitmask(&m), 0b1111);
    }

    #[test]
    fn normalize_in_image_clamps_and_rejects_outside_rect() {
        let mut app = ViewerApp::new(
            FrameSlot::new(),
            ViewerConfig {
                codec: "test".into(),
                transport: "test".into(),
                peer_addr: "test".into(),
            },
            None,
            Box::new(crate::NullAudioSink::default()),
            None,
        );
        assert_eq!(app.normalize_in_image(egui::pos2(5.0, 5.0)), None);

        app.image_rect = Some(egui::Rect::from_min_size(
            egui::pos2(10.0, 10.0),
            egui::vec2(100.0, 50.0),
        ));
        assert_eq!(
            app.normalize_in_image(egui::pos2(60.0, 35.0)),
            Some((0.5, 0.5))
        );
        assert_eq!(app.normalize_in_image(egui::pos2(5.0, 5.0)), None);
    }
}
