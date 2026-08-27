// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Non-production contract for Xenia's candidate dynamically negotiated V2 handshake.
//!
//! This crate freezes wire shape, hostile-input bounds, V5 composition, and the
//! signature preimages before those semantics are allowed to drive production
//! ML-KEM/session state. It deliberately does **not** perform cryptography or I/O.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use xenia_negotiation_codec::decode_capability_offer;

/// Existing Xenia unauthenticated handshake-envelope ceiling.
pub const MAX_HANDSHAKE_ENVELOPE_BYTES: usize = 16 * 1024;
/// V2 transport-specific cap for either peer's canonical capability offer.
pub const MAX_V2_CAPABILITY_OFFER_BYTES: usize = 8 * 1024;

/// ML-KEM-768 public-key length (FIPS 203).
pub const ML_KEM_768_PK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// ML-DSA-65 public-key length (FIPS 204).
pub const ML_DSA_65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length (FIPS 204).
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// V2 signature-context label. V1 remains unchanged for legacy messages.
pub const HANDSHAKE_SIGNATURE_CONTEXT_V2: &[u8] = b"xenia-handshake-signature-v2";
/// V2 transcript schema label.
pub const HANDSHAKE_TRANSCRIPT_SCHEMA_V2: &[u8] = b"xenia-handshake-transcript-v2";
/// Current hybrid transcript-authentication policy copied into the signed context.
pub const HANDSHAKE_POLICY_PROFILE: &[u8] = b"hybrid-pq-transcript-v1";
/// Current KEM suite label copied into the signed context.
pub const KEM_SUITE_LABEL: &[u8] = b"ml-kem-768-fips203";
/// Current transcript-signature suite label copied into the signed context.
pub const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &[u8] = b"ed25519-rfc8032+ml-dsa-65-fips204";
/// Current KDF suite label copied into the signed context.
pub const KDF_SUITE_LABEL: &[u8] = b"hkdf-sha256";
/// Domain for V4 + negotiation-binding composition.
pub const NEGOTIATED_SESSION_CONTEXT_V5_DOMAIN: &[u8] =
    b"xenia.negotiated-session-context.v5\0";

/// Candidate host hello for dynamic V2 negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHelloV2 {
    /// Host Ed25519 verifying key.
    pub ed25519_pk: [u8; 32],
    /// Host ML-DSA-65 verifying key.
    pub ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    /// Host ML-KEM-768 encapsulation key.
    pub kem_pk: [u8; ML_KEM_768_PK_LEN],
    /// Fresh host nonce.
    pub nonce: [u8; 32],
    /// Existing authenticated-session V4 context commitment.
    pub base_v4_context_hash: [u8; 32],
    /// Exact canonical host capability-offer bytes.
    pub host_offer: Vec<u8>,
}

/// Candidate viewer response for dynamic V2 negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerResponseV2 {
    /// Viewer Ed25519 verifying key.
    pub ed25519_pk: [u8; 32],
    /// Viewer ML-DSA-65 verifying key.
    pub ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    /// ML-KEM-768 ciphertext.
    pub kem_ct: [u8; ML_KEM_768_CT_LEN],
    /// Fresh viewer nonce.
    pub nonce: [u8; 32],
    /// Exact canonical viewer capability-offer bytes.
    pub viewer_offer: Vec<u8>,
    /// V5 context independently recomputed from V4 + deterministic negotiation.
    pub final_v5_context_hash: [u8; 32],
    /// Viewer Ed25519 signature over [`viewer_signature_transcript_v2`].
    pub signature: [u8; 64],
    /// Viewer ML-DSA-65 signature over the identical transcript.
    pub ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Candidate host-finalize message for dynamic V2 negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFinalizeV2 {
    /// Host's independently recomputed V5 context.
    pub final_v5_context_hash: [u8; 32],
    /// Host Ed25519 signature over [`host_signature_transcript_v2`].
    pub signature: [u8; 64],
    /// Host ML-DSA-65 signature over the identical transcript.
    pub ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

// The first three variants reserve the exact legacy HandshakeMessage indices.
// Their payload shape does not affect serialization of variants 3/4/5. This
// probe therefore freezes the V2 discriminants without duplicating legacy
// message implementation into the staged contract crate.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum HandshakeMessageV2Contract {
    ReservedLegacyHostHello,
    ReservedLegacyViewerResponse,
    ReservedLegacyHostFinalize,
    HostHelloV2 {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_768_PK_LEN],
        nonce: [u8; 32],
        base_v4_context_hash: [u8; 32],
        host_offer: Vec<u8>,
    },
    ViewerResponseV2 {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_768_CT_LEN],
        nonce: [u8; 32],
        viewer_offer: Vec<u8>,
        final_v5_context_hash: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
    HostFinalizeV2 {
        final_v5_context_hash: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
}

/// Encode a canonical HostHelloV2 using the frozen future enum discriminant.
pub fn encode_host_hello_v2(message: &HostHelloV2) -> Result<Vec<u8>, V2ContractError> {
    validate_context_hash(&message.base_v4_context_hash)?;
    validate_offer(&message.host_offer)?;
    let bytes = bincode::serialize(&HandshakeMessageV2Contract::HostHelloV2 {
        ed25519_pk: message.ed25519_pk,
        ml_dsa_pk: message.ml_dsa_pk,
        kem_pk: message.kem_pk,
        nonce: message.nonce,
        base_v4_context_hash: message.base_v4_context_hash,
        host_offer: message.host_offer.clone(),
    })?;
    validate_envelope_size(bytes.len())?;
    Ok(bytes)
}

/// Decode and revalidate a HostHelloV2 from untrusted handshake bytes.
pub fn decode_host_hello_v2(bytes: &[u8]) -> Result<HostHelloV2, V2ContractError> {
    validate_envelope_size(bytes.len())?;
    let decoded: HandshakeMessageV2Contract = bincode::deserialize(bytes)?;
    let HandshakeMessageV2Contract::HostHelloV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_pk,
        nonce,
        base_v4_context_hash,
        host_offer,
    } = decoded
    else {
        return Err(V2ContractError::WrongMessageVariant);
    };
    validate_context_hash(&base_v4_context_hash)?;
    validate_offer(&host_offer)?;
    let message = HostHelloV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_pk,
        nonce,
        base_v4_context_hash,
        host_offer,
    };
    if encode_host_hello_v2(&message)? != bytes {
        return Err(V2ContractError::NonCanonicalMessageEncoding);
    }
    Ok(message)
}

/// Encode a canonical ViewerResponseV2 using the frozen future enum discriminant.
pub fn encode_viewer_response_v2(
    message: &ViewerResponseV2,
) -> Result<Vec<u8>, V2ContractError> {
    validate_context_hash(&message.final_v5_context_hash)?;
    validate_offer(&message.viewer_offer)?;
    let bytes = bincode::serialize(&HandshakeMessageV2Contract::ViewerResponseV2 {
        ed25519_pk: message.ed25519_pk,
        ml_dsa_pk: message.ml_dsa_pk,
        kem_ct: message.kem_ct,
        nonce: message.nonce,
        viewer_offer: message.viewer_offer.clone(),
        final_v5_context_hash: message.final_v5_context_hash,
        signature: message.signature,
        ml_dsa_signature: message.ml_dsa_signature,
    })?;
    validate_envelope_size(bytes.len())?;
    Ok(bytes)
}

/// Decode and revalidate a ViewerResponseV2 from untrusted handshake bytes.
pub fn decode_viewer_response_v2(bytes: &[u8]) -> Result<ViewerResponseV2, V2ContractError> {
    validate_envelope_size(bytes.len())?;
    let decoded: HandshakeMessageV2Contract = bincode::deserialize(bytes)?;
    let HandshakeMessageV2Contract::ViewerResponseV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_ct,
        nonce,
        viewer_offer,
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    } = decoded
    else {
        return Err(V2ContractError::WrongMessageVariant);
    };
    validate_context_hash(&final_v5_context_hash)?;
    validate_offer(&viewer_offer)?;
    let message = ViewerResponseV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_ct,
        nonce,
        viewer_offer,
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    };
    if encode_viewer_response_v2(&message)? != bytes {
        return Err(V2ContractError::NonCanonicalMessageEncoding);
    }
    Ok(message)
}

/// Encode a canonical HostFinalizeV2 using the frozen future enum discriminant.
pub fn encode_host_finalize_v2(message: &HostFinalizeV2) -> Result<Vec<u8>, V2ContractError> {
    validate_context_hash(&message.final_v5_context_hash)?;
    let bytes = bincode::serialize(&HandshakeMessageV2Contract::HostFinalizeV2 {
        final_v5_context_hash: message.final_v5_context_hash,
        signature: message.signature,
        ml_dsa_signature: message.ml_dsa_signature,
    })?;
    validate_envelope_size(bytes.len())?;
    Ok(bytes)
}

/// Decode and revalidate a HostFinalizeV2 from untrusted handshake bytes.
pub fn decode_host_finalize_v2(bytes: &[u8]) -> Result<HostFinalizeV2, V2ContractError> {
    validate_envelope_size(bytes.len())?;
    let decoded: HandshakeMessageV2Contract = bincode::deserialize(bytes)?;
    let HandshakeMessageV2Contract::HostFinalizeV2 {
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    } = decoded
    else {
        return Err(V2ContractError::WrongMessageVariant);
    };
    validate_context_hash(&final_v5_context_hash)?;
    let message = HostFinalizeV2 {
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    };
    if encode_host_finalize_v2(&message)? != bytes {
        return Err(V2ContractError::NonCanonicalMessageEncoding);
    }
    Ok(message)
}

/// Compose the frozen V5 session-context commitment from existing V4 context
/// and the authenticated deterministic negotiation binding.
pub fn compose_v5_context(
    base_v4_context_hash: &[u8; 32],
    negotiation_binding_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATED_SESSION_CONTEXT_V5_DOMAIN);
    hasher.update(base_v4_context_hash);
    hasher.update(negotiation_binding_hash);
    hasher.finalize().into()
}

/// Build the exact bytes both viewer signature algorithms sign in V2.
///
/// The HostHelloV2 bytes transitively bind host identity/KEM material, the base
/// V4 context, and the exact canonical host offer. The response phase then adds
/// viewer identity/KEM material, the exact viewer offer, and independently
/// recomputed V5. Neither signature field is included in its own preimage.
pub fn viewer_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
) -> Result<Vec<u8>, V2ContractError> {
    // Require the hello to be exact canonical V2 bytes before allowing it into
    // a signature transcript.
    let _ = decode_host_hello_v2(hello_bytes)?;
    validate_offer(&response.viewer_offer)?;
    validate_context_hash(&response.final_v5_context_hash)?;

    let mut transcript = signature_context_prefix_v2()?;
    append_len_prefixed(&mut transcript, b"viewer-response-v2")?;
    append_len_prefixed(&mut transcript, hello_bytes)?;
    append_len_prefixed(&mut transcript, &response.ed25519_pk)?;
    append_len_prefixed(&mut transcript, &response.ml_dsa_pk)?;
    append_len_prefixed(&mut transcript, &response.kem_ct)?;
    append_len_prefixed(&mut transcript, &response.nonce)?;
    append_len_prefixed(&mut transcript, &response.viewer_offer)?;
    append_len_prefixed(&mut transcript, &response.final_v5_context_hash)?;
    Ok(transcript)
}

/// Build the exact bytes both host-finalize signature algorithms sign in V2.
///
/// This extends the viewer transcript with both viewer signatures and V5,
/// preserving v1's rule that host-finalize authenticates the viewer's complete
/// signed response rather than merely repeating host state.
pub fn host_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2,
) -> Result<Vec<u8>, V2ContractError> {
    let mut transcript = viewer_signature_transcript_v2(hello_bytes, response)?;
    append_len_prefixed(&mut transcript, b"host-finalize-v2")?;
    append_len_prefixed(&mut transcript, &response.signature)?;
    append_len_prefixed(&mut transcript, &response.ml_dsa_signature)?;
    append_len_prefixed(&mut transcript, &response.final_v5_context_hash)?;
    Ok(transcript)
}

fn signature_context_prefix_v2() -> Result<Vec<u8>, V2ContractError> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, HANDSHAKE_SIGNATURE_CONTEXT_V2)?;
    append_len_prefixed(&mut out, HANDSHAKE_TRANSCRIPT_SCHEMA_V2)?;
    append_len_prefixed(&mut out, HANDSHAKE_POLICY_PROFILE)?;
    append_len_prefixed(&mut out, KEM_SUITE_LABEL)?;
    append_len_prefixed(&mut out, TRANSCRIPT_SIGNATURE_SUITE_LABEL)?;
    append_len_prefixed(&mut out, KDF_SUITE_LABEL)?;
    Ok(out)
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), V2ContractError> {
    let len = u32::try_from(bytes.len()).map_err(|_| V2ContractError::TranscriptComponentTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_offer(bytes: &[u8]) -> Result<(), V2ContractError> {
    if bytes.len() > MAX_V2_CAPABILITY_OFFER_BYTES {
        return Err(V2ContractError::OfferTooLarge {
            actual: bytes.len(),
            maximum: MAX_V2_CAPABILITY_OFFER_BYTES,
        });
    }
    decode_capability_offer(bytes).map_err(V2ContractError::OfferCodec)?;
    Ok(())
}

fn validate_context_hash(hash: &[u8; 32]) -> Result<(), V2ContractError> {
    if hash.iter().all(|byte| *byte == 0) {
        return Err(V2ContractError::ZeroContextHash);
    }
    Ok(())
}

fn validate_envelope_size(len: usize) -> Result<(), V2ContractError> {
    if len > MAX_HANDSHAKE_ENVELOPE_BYTES {
        return Err(V2ContractError::EnvelopeTooLarge {
            actual: len,
            maximum: MAX_HANDSHAKE_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

/// Candidate V2 wire/transcript contract failure.
#[derive(Debug, thiserror::Error)]
pub enum V2ContractError {
    /// Bincode message encoding/decoding failed.
    #[error("invalid V2 handshake bincode: {0}")]
    Bincode(#[from] bincode::Error),
    /// Canonical capability-offer parsing failed.
    #[error("invalid canonical V2 capability offer: {0}")]
    OfferCodec(#[source] xenia_negotiation_codec::NegotiationCodecError),
    /// A peer offer exceeds the V2 transport-specific bound.
    #[error("V2 capability offer too large ({actual} > {maximum} bytes)")]
    OfferTooLarge {
        /// Observed bytes.
        actual: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// The serialized handshake message exceeds the global unauthenticated ceiling.
    #[error("V2 handshake envelope too large ({actual} > {maximum} bytes)")]
    EnvelopeTooLarge {
        /// Observed bytes.
        actual: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// The caller attempted to decode one V2 phase as another.
    #[error("unexpected V2 handshake message variant")]
    WrongMessageVariant,
    /// Parsed bytes are not exactly the canonical bincode emitted by this contract.
    #[error("V2 handshake message is not canonically encoded")]
    NonCanonicalMessageEncoding,
    /// V4/V5 context commitment is the all-zero sentinel.
    #[error("V2 context hash must not be all zero")]
    ZeroContextHash,
    /// A signature-transcript component cannot fit the u32 big-endian length prefix.
    #[error("V2 signature transcript component exceeds u32 length bound")]
    TranscriptComponentTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_negotiation::{
        CapabilityOfferV1, causal_authority_draft04_offer_entry,
    };
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
    fn v2_discriminants_and_fixed_size_budget_are_frozen() {
        let host = host();
        let response = response();
        let finalize = HostFinalizeV2 {
            final_v5_context_hash: [0xaa; 32],
            signature: [0xdd; 64],
            ml_dsa_signature: [0xee; ML_DSA_65_SIG_LEN],
        };
        let host_bytes = encode_host_hello_v2(&host).unwrap();
        let response_bytes = encode_viewer_response_v2(&response).unwrap();
        let finalize_bytes = encode_host_finalize_v2(&finalize).unwrap();

        assert_eq!(&host_bytes[..4], &3u32.to_le_bytes());
        assert_eq!(&response_bytes[..4], &4u32.to_le_bytes());
        assert_eq!(&finalize_bytes[..4], &5u32.to_le_bytes());
        assert_eq!(host_bytes.len(), 3244 + host.host_offer.len());
        assert_eq!(response_bytes.len(), 6521 + response.viewer_offer.len());
        assert_eq!(finalize_bytes.len(), 3409);
        assert!(response_bytes.len() <= MAX_HANDSHAKE_ENVELOPE_BYTES);
    }

    #[test]
    fn every_v2_phase_round_trips_canonically() {
        let host = host();
        let response = response();
        let finalize = HostFinalizeV2 {
            final_v5_context_hash: [0xaa; 32],
            signature: [0xdd; 64],
            ml_dsa_signature: [0xee; ML_DSA_65_SIG_LEN],
        };
        assert_eq!(decode_host_hello_v2(&encode_host_hello_v2(&host).unwrap()).unwrap(), host);
        assert_eq!(
            decode_viewer_response_v2(&encode_viewer_response_v2(&response).unwrap()).unwrap(),
            response
        );
        assert_eq!(
            decode_host_finalize_v2(&encode_host_finalize_v2(&finalize).unwrap()).unwrap(),
            finalize
        );
    }

    #[test]
    fn wrong_phase_and_noncanonical_offer_fail_closed() {
        let host_bytes = encode_host_hello_v2(&host()).unwrap();
        assert!(matches!(
            decode_viewer_response_v2(&host_bytes),
            Err(V2ContractError::WrongMessageVariant)
        ));

        let mut host = host();
        host.host_offer.push(0xa5);
        assert!(matches!(
            encode_host_hello_v2(&host),
            Err(V2ContractError::OfferCodec(_))
        ));
    }

    #[test]
    fn transport_specific_offer_and_global_envelope_bounds_fail_closed() {
        let mut host = host();
        host.host_offer = vec![0u8; MAX_V2_CAPABILITY_OFFER_BYTES + 1];
        assert!(matches!(
            encode_host_hello_v2(&host),
            Err(V2ContractError::OfferTooLarge { .. })
        ));

        assert!(matches!(
            decode_host_hello_v2(&vec![0u8; MAX_HANDSHAKE_ENVELOPE_BYTES + 1]),
            Err(V2ContractError::EnvelopeTooLarge { .. })
        ));
    }

    #[test]
    fn v5_composition_matches_frozen_cross_language_vector() {
        let mut base = [0u8; 32];
        for (index, byte) in base.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let binding = [
            0x32, 0x0f, 0x93, 0x74, 0xb3, 0xdb, 0x96, 0x1e, 0xd1, 0x69, 0xaa, 0xc8, 0x6d,
            0x2c, 0x3e, 0x6c, 0x2c, 0x36, 0xea, 0x88, 0x5f, 0x14, 0x3b, 0x2d, 0xd9, 0x91,
            0xc8, 0xee, 0x75, 0xf3, 0xc5, 0x7b,
        ];
        assert_eq!(
            compose_v5_context(&base, &binding),
            [
                0x9f, 0x59, 0xef, 0xa7, 0xef, 0x09, 0x59, 0xfa, 0xf5, 0x7c, 0x24, 0x90, 0xeb,
                0x43, 0x8d, 0x55, 0x37, 0xe1, 0x48, 0x5f, 0x4b, 0xf4, 0xf2, 0x84, 0x1c, 0xc0,
                0xdf, 0x76, 0xa6, 0x47, 0xf5, 0x84,
            ]
        );
    }

    #[test]
    fn signature_transcripts_bind_offer_v5_and_viewer_signatures() {
        let hello = encode_host_hello_v2(&host()).unwrap();
        let response = response();
        let viewer = viewer_signature_transcript_v2(&hello, &response).unwrap();
        let host_final = host_signature_transcript_v2(&hello, &response).unwrap();
        assert_ne!(viewer, host_final);

        let mut changed_v5 = response.clone();
        changed_v5.final_v5_context_hash[0] ^= 1;
        assert_ne!(
            viewer,
            viewer_signature_transcript_v2(&hello, &changed_v5).unwrap()
        );

        let mut changed_signature = response.clone();
        changed_signature.signature[0] ^= 1;
        assert_eq!(
            viewer,
            viewer_signature_transcript_v2(&hello, &changed_signature).unwrap()
        );
        assert_ne!(
            host_final,
            host_signature_transcript_v2(&hello, &changed_signature).unwrap()
        );
    }

    #[test]
    fn all_zero_context_hashes_are_rejected_before_signing() {
        let mut host = host();
        host.base_v4_context_hash = [0; 32];
        assert!(matches!(
            encode_host_hello_v2(&host),
            Err(V2ContractError::ZeroContextHash)
        ));

        let hello = encode_host_hello_v2(&super::tests::host()).unwrap();
        let mut response = response();
        response.final_v5_context_hash = [0; 32];
        assert!(matches!(
            viewer_signature_transcript_v2(&hello, &response),
            Err(V2ContractError::ZeroContextHash)
        ));
    }
}
