// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Phone-as-source screen capture: drives a real Android device's
//! scrcpy-server over ADB and decodes its video stream into
//! [`xenia_capture::ScreenCapture`] frames. This unblocks the
//! phone→desktop leg of the three-way test matrix (see xenia-peer's
//! ROADMAP.md, T3.4) -- the other two legs (desktop↔desktop and
//! desktop→phone-browser) already work.
//!
//! `scrcpy` is the protocol/decode layer, ported from
//! `symthaea-phone-embodiment`'s hardware-verified scrcpy client (same
//! AGPL-3.0-or-later license) -- see that module's doc comment. `capture`
//! is the new glue wrapping it as a `ScreenCapture` backend.

#[cfg(feature = "hevc")]
pub mod capture;
pub mod scrcpy;

#[cfg(feature = "hevc")]
pub use capture::ScrcpyScreenCapture;
