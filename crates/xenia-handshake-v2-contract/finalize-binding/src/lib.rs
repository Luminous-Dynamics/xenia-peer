// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Fail-closed V5 binding for Xenia's candidate `HostFinalizeV2` phase.
//!
//! The parent V2 contract already binds the viewer-signed V5 into the host
//! signature transcript. This successor contract closes one remaining API
//! ambiguity: the V5 carried by `HostFinalizeV2` must be the exact same value
//! before host signatures are created or accepted.
//!
//! Valid transcript bytes deliberately remain unchanged. Only previously
//! ambiguous finalize-context substitutions become invalid.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use xenia_handshake_v2_contract::{
    HostFinalizeV2, V2ContractError, ViewerResponseV2, host_signature_transcript_v2,
};

/// Build the host-finalize signature transcript while explicitly binding the
/// V5 value that will be carried by `HostFinalizeV2`.
///
/// The supplied finalize V5 must equal the V5 already authenticated by the
/// viewer response. Because the parent transcript already appends that response
/// V5, equality makes the resulting signed bytes also bind the exact finalize
/// field without changing the frozen valid transcript encoding.
pub fn host_signature_transcript_for_finalize_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
    finalize_v5_context_hash: &[u8; 32],
) -> Result<Vec<u8>, FinalizeBindingError> {
    require_matching_finalize_context(response, finalize_v5_context_hash)?;
    host_signature_transcript_v2(hello_bytes, response).map_err(FinalizeBindingError::Contract)
}

/// Validate the V5 carried by a received `HostFinalizeV2` before host
/// signatures are accepted.
pub fn validate_host_finalize_v2(
    response: &ViewerResponseV2,
    finalize: &HostFinalizeV2,
) -> Result<(), FinalizeBindingError> {
    require_matching_finalize_context(response, &finalize.final_v5_context_hash)
}

fn require_matching_finalize_context(
    response: &ViewerResponseV2,
    finalize_v5_context_hash: &[u8; 32],
) -> Result<(), FinalizeBindingError> {
    if finalize_v5_context_hash != &response.final_v5_context_hash {
        return Err(FinalizeBindingError::FinalizeContextMismatch);
    }
    Ok(())
}

/// Failure while binding the host-finalize message to the viewer-signed V5.
#[derive(Debug, thiserror::Error)]
pub enum FinalizeBindingError {
    /// The finalize message attempted to carry a different V5 commitment from
    /// the one already signed by the viewer.
    #[error("HostFinalizeV2 V5 does not match the viewer-signed V5")]
    FinalizeContextMismatch,
    /// The underlying canonical V2 transcript contract rejected its inputs.
    #[error(transparent)]
    Contract(#[from] V2ContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake_v2_contract::{
        HostHelloV2, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN,
        ML_KEM_768_PK_LEN, encode_host_hello_v2,
    };
    use xenia_negotiation::{CapabilityOfferV1, causal_authority_draft04_offer_entry};
    use xenia_negotiation_codec::encode_capability_offer;

    fn authority_offer() -> Vec<u8> {
        encode_capability_offer(
            &CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap(),
        )
    }

    fn host() -> HostHelloV2 {
        HostHelloV2 {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x22; ML_DSA_65_PK_LEN],
            kem_pk: [0x33; ML_KEM_768_PK_LEN],
            nonce: [0x44; 32],
            base_v4_context_hash: [0x55; 32],
            host_offer: authority_offer(),
        }
    }

    fn response() -> ViewerResponseV2 {
        ViewerResponseV2 {
            ed25519_pk: [0x66; 32],
            ml_dsa_pk: [0x77; ML_DSA_65_PK_LEN],
            kem_ct: [0x88; ML_KEM_768_CT_LEN],
            nonce: [0x99; 32],
            viewer_offer: authority_offer(),
            final_v5_context_hash: [0xaa; 32],
            signature: [0xbb; 64],
            ml_dsa_signature: [0xcc; ML_DSA_65_SIG_LEN],
        }
    }

    #[test]
    fn valid_binding_preserves_frozen_host_transcript_bytes() {
        let hello = encode_host_hello_v2(&host()).unwrap();
        let response = response();
        let baseline = host_signature_transcript_v2(&hello, &response).unwrap();
        let bound = host_signature_transcript_for_finalize_v2(
            &hello,
            &response,
            &response.final_v5_context_hash,
        )
        .unwrap();
        assert_eq!(bound, baseline);
    }

    #[test]
    fn mutated_finalize_v5_fails_before_signature_acceptance() {
        let hello = encode_host_hello_v2(&host()).unwrap();
        let response = response();
        let mut substituted = response.final_v5_context_hash;
        substituted[0] ^= 0x80;

        assert!(matches!(
            host_signature_transcript_for_finalize_v2(&hello, &response, &substituted),
            Err(FinalizeBindingError::FinalizeContextMismatch)
        ));
    }

    #[test]
    fn received_finalize_message_must_match_viewer_signed_v5() {
        let response = response();
        let mut finalize = HostFinalizeV2 {
            final_v5_context_hash: response.final_v5_context_hash,
            signature: [0xdd; 64],
            ml_dsa_signature: [0xee; ML_DSA_65_SIG_LEN],
        };
        validate_host_finalize_v2(&response, &finalize).unwrap();

        finalize.final_v5_context_hash[31] ^= 1;
        assert!(matches!(
            validate_host_finalize_v2(&response, &finalize),
            Err(FinalizeBindingError::FinalizeContextMismatch)
        ));
    }
}
