// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical hybrid-key lineage for Xenia generic authenticated subjects.
//!
//! This crate verifies an append-only sequence of key-epoch transitions from an
//! externally pinned genesis. It separates ordinary rotation from compromise
//! recovery and never treats key history as trusted time, current authorization,
//! or evidence truth.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use xenia_auth::{
    AuthenticationAdapterError, AuthenticationVerifierRegistryV1,
    Ed25519AuthenticationVerifier, MlDsa65AuthenticationVerifier,
    SubjectAuthenticationVerificationError, verify_authentication,
};
use xenia_auth_protocol::{
    AuthenticationContextId, AuthenticationProtocolError, AuthenticationSuiteId,
    SubjectAuthentication, SubjectAuthenticationVerifier, authenticated_subject_digest,
};

/// Frozen generic-authentication profile consumed by this lineage protocol.
pub const GENERIC_AUTH_PROFILE_V1_SHA256: [u8; 32] = [
    0xe8, 0xb6, 0xac, 0x90, 0x02, 0x8c, 0x30, 0x64, 0x88, 0x0b, 0xfb, 0x6b, 0x59, 0xac, 0x7f, 0xbd,
    0x1a, 0x1d, 0xb0, 0x41, 0x82, 0xbd, 0x38, 0x41, 0xe6, 0x56, 0xbb, 0xa2, 0x73, 0x6d, 0x2b, 0x90,
];

const TRANSITION_SUBJECT_DOMAIN_V1: &[u8] = b"XENIA:HistoricalKeyTransition:v1\0";

include!("model.rs");
include!("verify.rs");
include!("canonical.rs");

#[cfg(test)]
mod tests;
