// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Hardened public facade for Xenia's candidate dynamically negotiated V2 handshake contract.
//!
//! The frozen wire/transcript implementation remains byte-for-byte preserved in
//! a private module so existing cross-language vectors remain meaningful. The
//! public host-finalize transcript API adds one fail-closed invariant that the
//! frozen core did not express: the V5 commitment carried by `HostFinalizeV2`
//! must exactly equal the V5 commitment authenticated in `ViewerResponseV2`.
//! This prevents a caller from verifying host signatures over one V5 context
//! while accepting a finalize message that advertises another.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod frozen;

pub use frozen::{
    HANDSHAKE_POLICY_PROFILE, HANDSHAKE_SIGNATURE_CONTEXT_V2, HANDSHAKE_TRANSCRIPT_SCHEMA_V2,
    HostFinalizeV2, HostHelloV2, KDF_SUITE_LABEL, KEM_SUITE_LABEL, MAX_HANDSHAKE_ENVELOPE_BYTES,
    MAX_V2_CAPABILITY_OFFER_BYTES, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN,
    ML_KEM_768_PK_LEN, NEGOTIATED_SESSION_CONTEXT_V5_DOMAIN, TRANSCRIPT_SIGNATURE_SUITE_LABEL,
    V2ContractError, ViewerResponseV2, compose_v5_context, decode_host_finalize_v2,
    decode_host_hello_v2, decode_viewer_response_v2, encode_host_finalize_v2,
    encode_host_hello_v2, encode_viewer_response_v2, viewer_signature_transcript_v2,
};

/// Failure while constructing the authenticated host-finalize V2 transcript.
#[derive(Debug, thiserror::Error)]
pub enum HostFinalizeTranscriptError {
    /// The frozen V2 wire/transcript contract rejected an input.
    #[error(transparent)]
    Contract(#[from] V2ContractError),
    /// The V5 commitment carried by host-finalize differs from the V5 already
    /// authenticated by the viewer response.
    #[error("host-finalize V5 context does not match viewer-response V5 context")]
    FinalV5ContextMismatch,
}

/// Build the exact bytes both host-finalize signature algorithms sign in V2.
///
/// `final_v5_context_hash` must be the value carried by the actual
/// [`HostFinalizeV2`] being signed or verified. The function first validates the
/// frozen viewer transcript, then rejects an all-zero finalize commitment and
/// requires exact equality with `response.final_v5_context_hash`. Only after
/// those checks does it return the frozen host transcript bytes.
///
/// This makes the relationship between the signed transcript and the finalize
/// message explicit without changing the valid-message byte contract or frozen
/// cross-language digest vectors.
pub fn host_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
    final_v5_context_hash: &[u8; 32],
) -> Result<Vec<u8>, HostFinalizeTranscriptError> {
    let transcript = frozen::host_signature_transcript_v2(hello_bytes, response)?;
    if final_v5_context_hash.iter().all(|byte| *byte == 0) {
        return Err(V2ContractError::ZeroContextHash.into());
    }
    if final_v5_context_hash != &response.final_v5_context_hash {
        return Err(HostFinalizeTranscriptError::FinalV5ContextMismatch);
    }
    Ok(transcript)
}
