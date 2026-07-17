// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Fuzz target: `serde_json::from_slice` over every `xenia-operator-agent`
//! `/v1/*` request DTO, with the same arbitrary bytes tried against each
//! type in turn. These are exactly what axum's `Json<T>` extractor
//! deserializes from a browser-origin (or, for `/v1/sign/*`, potentially
//! MITM-relayed daemon-evidence-bearing) HTTP body -- untrusted input by
//! construction. Goal: no panic on any byte sequence, for any of them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_operator_agent_proto::{
    HandshakeBeginRequest, HandshakeFinishRequest, SignChallengeRequest, SignConsentActionRequest,
    SignRevokeRequest,
};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SignChallengeRequest>(data);
    let _ = serde_json::from_slice::<SignConsentActionRequest>(data);
    let _ = serde_json::from_slice::<SignRevokeRequest>(data);
    let _ = serde_json::from_slice::<HandshakeBeginRequest>(data);
    let _ = serde_json::from_slice::<HandshakeFinishRequest>(data);
});
