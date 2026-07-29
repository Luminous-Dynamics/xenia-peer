// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `org.freedesktop.portal.RemoteDesktop` input-injection backend for
//! GNOME/KDE (any compositor with a `xdg-desktop-portal` RemoteDesktop
//! implementation).
//!
//! Uses `ashpd` (high-level async bindings) rather than hand-rolling raw
//! D-Bus calls the way `xenia-capture`'s `scap` dependency does for
//! `ScreenCast` — `scap`'s `handle_req_response` (in its `portal.rs`)
//! registers the D-Bus signal match *after* sending the method call, a
//! real, confirmed request/response race (a fast portal reply can be
//! silently missed). `ashpd` is a mature, actively-maintained crate built
//! specifically to avoid this class of bug.
//!
//! `InputInjector`'s trait methods are synchronous but the portal API is
//! async-only, so this mirrors `xenia-capture::ScapCapture`'s worker-
//! thread architecture (`crates/xenia-capture/src/scap_backend.rs`): a
//! dedicated OS thread owns a small current-thread `tokio` runtime and
//! the portal session; the sync trait methods send events to it over an
//! `mpsc` channel.
//!
//! ## Pointer coordinates
//!
//! The portal's `NotifyPointerMotion` is relative-only
//! (`NotifyPointerMotionAbsolute` requires an associated ScreenCast
//! stream node ID this crate doesn't have, since it doesn't pair with
//! `xenia-capture`). The worker tracks the last denormalized pointer
//! position and sends the delta each call.

use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ashpd::desktop::remote_desktop::{DeviceType, RemoteDesktop};
use ashpd::desktop::{PersistMode, Session};
use ashpd::enumflags2::BitFlags;
use ashpd::WindowIdentifier;

use crate::{evdev_button_code, InjectError, InputInjector};

/// Linux evdev button code for `NotifyPointerButton` (the portal's
/// documented convention). Delegates to the crate-wide canonical
/// mapping (`lib.rs::evdev_button_code`) -- this function used to have
/// its own formula-based implementation that disagreed with
/// `UinputInjector`'s explicit match on button 3 (`BTN_EXTRA` instead
/// of `BTN_SIDE`); see that function's doc comment for how it was
/// found. Kept as a thin wrapper (rather than inlining the call at
/// each site) so this module's two call sites don't need to know the
/// shared function lives in the crate root.
fn evdev_button(button: u8) -> i32 {
    evdev_button_code(button) as i32
}

fn key_state(pressed: bool) -> ashpd::desktop::remote_desktop::KeyState {
    if pressed {
        ashpd::desktop::remote_desktop::KeyState::Pressed
    } else {
        ashpd::desktop::remote_desktop::KeyState::Released
    }
}

/// Denormalize a `[0.0, 1.0]` coordinate into pixels against `extent`
/// (screen width or height). Pure, so it's unit-testable without a
/// live portal session -- pulled out of `XdgPortalInjector::denorm_x`/
/// `denorm_y` (which just forward to this with `self.screen_width`/
/// `self.screen_height`) for exactly that reason.
fn denorm(v: f32, extent: u32) -> f64 {
    f64::from(v.clamp(0.0, 1.0) * extent as f32)
}

/// One event dispatched to the portal worker thread. Pointer/touch
/// coordinates arrive already denormalized to pixels (the sync
/// `InputInjector` side does the `[0.0, 1.0]` → pixel conversion, matching
/// `LoggingInjector`'s convention) so the worker only ever deals in f64
/// pixel space.
enum Command {
    Pointer {
        x: f64,
        y: f64,
        button: u8,
        pressed: bool,
    },
    Key {
        code: u32,
        pressed: bool,
    },
    Touch {
        index: u8,
        x: f64,
        y: f64,
        phase: u8,
    },
    Shutdown,
}

/// `org.freedesktop.portal.RemoteDesktop`-backed injector.
pub struct XdgPortalInjector {
    screen_width: u32,
    screen_height: u32,
    tx: mpsc::Sender<Command>,
    worker: Option<JoinHandle<()>>,
}

impl XdgPortalInjector {
    /// Create the portal session and request keyboard + pointer + touch
    /// device access. Blocks until the session is ready (including the
    /// operator clicking through the RemoteDesktop consent dialog) or
    /// `timeout` elapses.
    ///
    /// # Errors
    ///
    /// [`InjectError::Unavailable`] if the portal isn't reachable at all
    /// (no `xdg-desktop-portal`, or no RemoteDesktop backend), the
    /// operator declines the dialog, or the timeout is reached first —
    /// `ashpd::Error` doesn't distinguish these cases at the type level,
    /// so all surface as `Unavailable` with the portal's message.
    pub fn new(
        screen_width: u32,
        screen_height: u32,
        timeout: Duration,
    ) -> Result<Self, InjectError> {
        let (tx, rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();

        let worker = thread::Builder::new()
            .name("xenia-inject-portal".into())
            .spawn(move || portal_worker(rx, ready_tx))
            .map_err(|e| InjectError::Backend(format!("portal worker spawn: {e}")))?;

        match ready_rx.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(Self {
                screen_width,
                screen_height,
                tx,
                worker: Some(worker),
            }),
            Ok(Err(msg)) => Err(InjectError::Unavailable(msg)),
            Err(_) => Err(InjectError::Unavailable(format!(
                "RemoteDesktop portal session did not become ready within {timeout:?}"
            ))),
        }
    }

    fn denorm_x(&self, x: f32) -> f64 {
        denorm(x, self.screen_width)
    }

    fn denorm_y(&self, y: f32) -> f64 {
        denorm(y, self.screen_height)
    }

    fn send(&self, cmd: Command) -> Result<(), InjectError> {
        self.tx
            .send(cmd)
            .map_err(|_| InjectError::Backend("portal worker thread gone".into()))
    }
}

impl Drop for XdgPortalInjector {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl InputInjector for XdgPortalInjector {
    fn inject_pointer(
        &mut self,
        x: f32,
        y: f32,
        button: u8,
        pressed: bool,
    ) -> Result<(), InjectError> {
        self.send(Command::Pointer {
            x: self.denorm_x(x),
            y: self.denorm_y(y),
            button,
            pressed,
        })
    }

    fn inject_key(&mut self, code: u32, pressed: bool, _modifiers: u8) -> Result<(), InjectError> {
        self.send(Command::Key { code, pressed })
    }

    fn inject_touch(
        &mut self,
        index: u8,
        x: f32,
        y: f32,
        phase: u8,
        _pressure: f32,
    ) -> Result<(), InjectError> {
        self.send(Command::Touch {
            index,
            x: self.denorm_x(x),
            y: self.denorm_y(y),
            phase,
        })
    }

    fn backend_name(&self) -> &str {
        "xdg-portal"
    }
}

fn portal_worker(rx: mpsc::Receiver<Command>, ready_tx: mpsc::Sender<Result<(), String>>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("tokio runtime build failed: {e}")));
            return;
        }
    };

    rt.block_on(async move {
        let (proxy, session) = match setup_session().await {
            Ok(pair) => pair,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));

        // Last denormalized pointer position, per touch-index last position —
        // NotifyPointerMotion is relative-only (see module doc comment).
        let mut last_pointer: Option<(f64, f64)> = None;

        while let Ok(cmd) = rx.recv() {
            match cmd {
                Command::Shutdown => break,
                Command::Pointer {
                    x,
                    y,
                    button,
                    pressed,
                } => {
                    let (dx, dy) = match last_pointer {
                        Some((lx, ly)) => (x - lx, y - ly),
                        None => (0.0, 0.0),
                    };
                    last_pointer = Some((x, y));
                    if dx != 0.0 || dy != 0.0 {
                        let _ = proxy.notify_pointer_motion(&session, dx, dy).await;
                    }
                    let _ = proxy
                        .notify_pointer_button(&session, evdev_button(button), key_state(pressed))
                        .await;
                }
                Command::Key { code, pressed } => {
                    let _ = proxy
                        .notify_keyboard_keycode(
                            &session,
                            i32::try_from(code).unwrap_or(i32::MAX),
                            key_state(pressed),
                        )
                        .await;
                }
                Command::Touch { index, x, y, phase } => {
                    let slot = u32::from(index);
                    // Portal spec: down/motion carry (stream, slot, x, y);
                    // stream is a ScreenCast node id this injector doesn't
                    // have (no paired capture session) -- 0 is the
                    // documented sentinel for "no associated stream".
                    let stream = 0u32;
                    let result = match phase {
                        0 => proxy.notify_touch_down(&session, stream, slot, x, y).await,
                        1 => {
                            proxy
                                .notify_touch_motion(&session, stream, slot, x, y)
                                .await
                        }
                        _ => proxy.notify_touch_up(&session, slot).await,
                    };
                    let _ = result;
                }
            }
        }
    });
}

async fn setup_session() -> Result<
    (
        RemoteDesktop<'static>,
        Session<'static, RemoteDesktop<'static>>,
    ),
    String,
> {
    let proxy = RemoteDesktop::new()
        .await
        .map_err(|e| format!("RemoteDesktop portal unavailable: {e}"))?;
    let session = proxy
        .create_session()
        .await
        .map_err(|e| format!("create_session failed: {e}"))?;
    let devices: BitFlags<DeviceType> =
        DeviceType::Keyboard | DeviceType::Pointer | DeviceType::Touchscreen;
    proxy
        .select_devices(&session, devices, None, PersistMode::DoNot)
        .await
        .map_err(|e| format!("select_devices request failed: {e}"))?
        .response()
        .map_err(|e| format!("select_devices rejected: {e}"))?;
    proxy
        .start(&session, &WindowIdentifier::default())
        .await
        .map_err(|e| format!("start request failed: {e}"))?
        .response()
        .map_err(|e| format!("start rejected (operator may have declined the dialog): {e}"))?;
    Ok((proxy, session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evdev_button_matches_known_codes() {
        assert_eq!(evdev_button(0), 0x110); // BTN_LEFT
        assert_eq!(evdev_button(1), 0x112); // BTN_MIDDLE
        assert_eq!(evdev_button(2), 0x111); // BTN_RIGHT
    }

    #[test]
    fn evdev_button_aux_buttons_saturate_at_extra() {
        // button 3 -> BTN_SIDE (0x113); 4 and beyond saturate at
        // BTN_EXTRA (0x114) rather than incrementing further -- matches
        // UinputInjector's original (correct) design, which this
        // function now delegates to. It used to increment sequentially
        // instead (BTN_MIDDLE + n - 1), putting button 3 at BTN_EXTRA
        // and disagreeing with uinput's explicit match; see
        // evdev_button_code's doc comment in lib.rs.
        assert_eq!(evdev_button(3), 0x113);
        assert_eq!(evdev_button(4), 0x114);
        assert_eq!(evdev_button(5), 0x114);
        assert_eq!(evdev_button(255), 0x114);
    }

    #[test]
    fn key_state_maps_pressed_and_released() {
        use ashpd::desktop::remote_desktop::KeyState;
        assert_eq!(key_state(true), KeyState::Pressed);
        assert_eq!(key_state(false), KeyState::Released);
    }

    #[test]
    fn denorm_scales_by_extent() {
        assert_eq!(denorm(0.5, 1920), 960.0);
        assert_eq!(denorm(0.0, 1080), 0.0);
        assert_eq!(denorm(1.0, 1080), 1080.0);
    }

    #[test]
    fn denorm_clamps_out_of_range_inputs() {
        assert_eq!(denorm(-1.0, 1000), 0.0);
        assert_eq!(denorm(2.0, 1000), 1000.0);
    }
}
