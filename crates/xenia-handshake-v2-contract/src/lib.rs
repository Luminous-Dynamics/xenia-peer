// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Hardened public facade for Xenia's candidate dynamically negotiated V2 handshake contract.
//!
//! The frozen wire/transcript implementation remains byte-for-byte preserved in
//! a private module so existing cross-language vectors remain meaningful. The
//! public transcript APIs add two fail-closed invariants the frozen core did not
//! express directly:
//!
//! 1. the V5 commitment in `ViewerResponseV2` must equal the value recomputed
//!    from the canonical host offer, canonical viewer offer, deterministic
//!    selection/binding, and the host's V4 context;
//! 2. the V5 commitment carried by `HostFinalizeV2` must exactly equal that
//!    already viewer-authenticated V5.
//!
//! This prevents callers from signing or accepting transcript bytes for one
//! negotiated context while carrying a different V5 in either handshake phase.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod frozen;

use xenia_negotiation::{NegotiatedContextError, negotiate_capabilities};
use xenia_negotiation_codec::{NegotiationCodecError, decode_capability_offer};

pub use frozen::{
    HANDSHAKE_POLICY_PROFILE, HANDSHAKE_SIGNATURE_CONTEXT_V2, HANDSHAKE_TRANSCRIPT_SCHEMA_V2,
    HostFinalizeV2, HostHelloV2, KDF_SUITE_LABEL, KEM_SUITE_LABEL, MAX_HANDSHAKE_ENVELOPE_BYTES,
    MAX_V2_CAPABILITY_OFFER_BYTES, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN,
    ML_KEM_768_PK_LEN, NEGOTIATED_SESSION_CONTEXT_V5_DOMAIN, TRANSCRIPT_SIGNATURE_SUITE_LABEL,
    V2ContractError, ViewerResponseV2, compose_v5_context, decode_host_finalize_v2,
    decode_host_hello_v2, decode_viewer_response_v2, encode_host_finalize_v2,
    encode_host_hello_v2, encode_viewer_response_v2,
};

/// Failure while constructing an authenticated negotiated V2 signature transcript.
#[derive(Debug, thiserror::Error)]
pub enum HostFinalizeTranscriptError {
    /// The frozen V2 wire/transcript contract rejected an input.
    #[error(transparent)]
    Contract(#[from] V2ContractError),
    /// Canonical offer bytes could not be decoded at the hardened binding layer.
    #[error(transparent)]
    OfferCodec(#[from] NegotiationCodecError),
    /// Deterministic capability negotiation failed.
    #[error(transparent)]
    Negotiation(#[from] NegotiatedContextError),
    /// The V5 supplied by the viewer differs from the value recomputed from the
    /// exact canonical offers and host V4 context.
    #[error("viewer-response V5 context does not match deterministic negotiation")]
    ViewerV5ContextMismatch,
    /// The V5 commitment carried by host-finalize differs from the V5 already
    /// authenticated by the viewer response.
    #[error("host-finalize V5 context does not match viewer-response V5 context")]
    FinalV5ContextMismatch,
}

/// Build the exact bytes both viewer signature algorithms sign in V2.
///
/// Before returning any transcript bytes, this facade validates the frozen
/// canonical message contract and independently recomputes the negotiated V5
/// from the host's canonical offer, the viewer's canonical offer, deterministic
/// capability selection/binding, and the host's V4 context. A caller therefore
/// cannot sign an arbitrary non-zero V5 and rely on a later layer to remember
/// the negotiation check.
///
/// Valid-message bytes are identical to the frozen cross-language contract.
pub fn viewer_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
) -> Result<Vec<u8>, HostFinalizeTranscriptError> {
    validated_viewer_transcript_v2(hello_bytes, response)
}

/// Build the exact bytes both host-finalize signature algorithms sign in V2.
///
/// `final_v5_context_hash` must be the value carried by the actual
/// [`HostFinalizeV2`] being signed or verified. The function first enforces the
/// viewer-side deterministic V5 recomputation, then rejects an all-zero finalize
/// commitment and requires exact equality with `response.final_v5_context_hash`.
/// Only after those checks does it return the frozen host transcript bytes.
///
/// This makes both V5 relationships explicit without changing the valid-message
/// byte contract or frozen cross-language digest vectors.
pub fn host_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
    final_v5_context_hash: &[u8; 32],
) -> Result<Vec<u8>, HostFinalizeTranscriptError> {
    let _ = validated_viewer_transcript_v2(hello_bytes, response)?;
    if final_v5_context_hash.iter().all(|byte| *byte == 0) {
        return Err(V2ContractError::ZeroContextHash.into());
    }
    if final_v5_context_hash != &response.final_v5_context_hash {
        return Err(HostFinalizeTranscriptError::FinalV5ContextMismatch);
    }
    frozen::host_signature_transcript_v2(hello_bytes, response).map_err(Into::into)
}

fn validated_viewer_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
) -> Result<Vec<u8>, HostFinalizeTranscriptError> {
    // Run the frozen transport/canonicality checks first. This enforces the
    // 16 KiB envelope / 8 KiB offer limits before semantic recomputation.
    let transcript = frozen::viewer_signature_transcript_v2(hello_bytes, response)?;
    let hello = frozen::decode_host_hello_v2(hello_bytes)?;
    let host_offer = decode_capability_offer(&hello.host_offer)?;
    let viewer_offer = decode_capability_offer(&response.viewer_offer)?;
    let negotiation = negotiate_capabilities(&host_offer, &viewer_offer)?;
    let expected_v5 = frozen::compose_v5_context(
        &hello.base_v4_context_hash,
        &negotiation.binding_hash(),
    );
    if response.final_v5_context_hash != expected_v5 {
        return Err(HostFinalizeTranscriptError::ViewerV5ContextMismatch);
    }
    Ok(transcript)
}
