// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Fuzz target: `xenia-peer-core`'s attacker-controlled decode surface,
//! with the same arbitrary bytes tried against each entry point in turn.
//!
//! These are the five decode paths a peer reaches before -- or as part
//! of -- authentication:
//! - `HandshakeMessage` (bincode): the **pre-auth** handshake message
//!   enum (`HostHello`/`ViewerResponse`/`HostFinalize`). The single
//!   highest-value target here -- this is parsed before either side has
//!   authenticated the other at all.
//! - `RawFrame::from_bin` (bincode via `Sealable`): the outer envelope
//!   for every frame on the wire (video/telemetry/rekey/clipboard/audio
//!   all ride inside it via `pixel_format`).
//! - `RawInput::from_bin` (bincode via `Sealable`): viewer-to-daemon
//!   input events -- the reverse-path envelope.
//! - `TransportAdvertisement::decode` (magic-prefixed bincode): the
//!   transport-negotiation payload sent before the handshake completes.
//! - `RawCapabilities` (bincode): fuzzed directly against the same
//!   bytes `RawCapabilities::from_frame` would decode from
//!   `RawFrame.pixels` -- exercising the inner-payload decode step
//!   without needing the fuzzer to separately produce a well-formed
//!   `RawFrame` envelope around it.
//!
//! Goal: no panic on any byte sequence, for any of them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_peer_core::advertisement::TransportAdvertisement;
use xenia_peer_core::frame::{RawCapabilities, RawFrame, RawInput};
use xenia_peer_core::handshake::HandshakeMessage;
use xenia_wire::Sealable;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<HandshakeMessage>(data);
    let _ = RawFrame::from_bin(data);
    let _ = RawInput::from_bin(data);
    let _ = TransportAdvertisement::decode(data);
    let _ = bincode::deserialize::<RawCapabilities>(data);
});
