// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Concrete, resource-bounded codecs for `xenia-zk-protocol` envelopes.
//!
//! The protocol crate deliberately owns no wire format. This crate is the narrow
//! integration boundary where untrusted bytes become a `ProofEnvelopeV3`.
//!
//! Security rules:
//! - the raw frame ceiling is enforced before JSON or binary parsing;
//! - the canonical binary decoder checks every declared length against both the
//!   local policy and the remaining frame **before** allocating a `Vec`;
//! - the binary codec rejects trailing bytes and has one representation per
//!   parsed envelope;
//! - JSON is transport syntax only. Signatures authenticate the protocol's
//!   canonical digest, never the original JSON bytes;
//! - protocol types reject unknown JSON object fields via `deny_unknown_fields`.

use thiserror::Error;
use xenia_zk_protocol::{
    AuthenticationSuiteId, ParameterSetId, ProofAuthentication, ProofEnvelopeV3, ProofSystemId,
    ProtocolError, StatementId, VerifierId,
    policy::{
        BoundedEnvelopeFrame, EnvelopePolicy, EnvelopeValidationError,
        bound_envelope_frame_before_deserialization,
    },
};

pub const BINARY_ENVELOPE_MAGIC_V1: &[u8; 8] = b"XZKENV01";

#[derive(Debug, Error)]
pub enum JsonEnvelopeCodecError {
    #[error("frame rejected before JSON decoding: {0}")]
    Frame(#[from] EnvelopeValidationError),
    #[error("JSON proof envelope rejected: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BinaryEnvelopeCodecError {
    #[error("frame rejected before binary decoding: {0}")]
    Frame(#[from] EnvelopeValidationError),
    #[error("binary proof envelope has an invalid magic/version tag")]
    InvalidMagic,
    #[error("binary proof envelope is truncated")]
    Truncated,
    #[error("binary proof envelope has trailing bytes: {0}")]
    TrailingBytes(usize),
    #[error("binary proof envelope field {field} exceeds limit: {actual} > {limit}")]
    LengthLimit {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("binary proof envelope declared {declared} bytes for {field}, only {remaining} remain")]
    LengthExceedsFrame {
        field: &'static str,
        declared: usize,
        remaining: usize,
    },
    #[error("binary proof envelope statement text is not UTF-8")]
    InvalidUtf8,
    #[error("binary proof envelope protocol value rejected: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Decode JSON only after enforcing the raw-frame ceiling.
///
/// JSON bytes themselves are not a signed/canonical representation. The parsed
/// envelope's protocol digest is the authentication boundary.
pub fn decode_json_envelope_bounded(
    encoded: &[u8],
    policy: &EnvelopePolicy,
) -> Result<ProofEnvelopeV3, JsonEnvelopeCodecError> {
    let bounded = bound_envelope_frame_before_deserialization(encoded, policy)?;
    Ok(serde_json::from_slice(bounded.as_bytes())?)
}

/// Encode an envelope to compact JSON transport syntax.
pub fn encode_json_envelope(envelope: &ProofEnvelopeV3) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(envelope)
}

/// Encode the canonical Xenia binary envelope representation.
///
/// This performs the same resource-length checks the decoder enforces, avoiding
/// generation of frames local policy would reject before parsing.
pub fn encode_binary_envelope_v1(
    envelope: &ProofEnvelopeV3,
    policy: &EnvelopePolicy,
) -> Result<Vec<u8>, BinaryEnvelopeCodecError> {
    envelope.statement.validate()?;
    check_len(
        "proof",
        envelope.proof.len(),
        policy.max_proof_bytes.min(u32::MAX as usize),
    )?;
    check_len(
        "authentication",
        envelope.authentication.len(),
        policy.max_authentication_entries.min(u16::MAX as usize),
    )?;
    for auth in &envelope.authentication {
        check_len(
            "signature",
            auth.signature.len(),
            policy.max_signature_bytes.min(u32::MAX as usize),
        )?;
    }

    let mut out = Vec::with_capacity(
        BINARY_ENVELOPE_MAGIC_V1
            .len()
            .saturating_add(envelope.proof.len())
            .saturating_add(
                envelope
                    .authentication
                    .iter()
                    .map(|auth| auth.signature.len())
                    .sum::<usize>(),
            )
            .saturating_add(256),
    );
    out.extend_from_slice(BINARY_ENVELOPE_MAGIC_V1);
    out.extend_from_slice(&envelope.protocol_version.to_le_bytes());
    push_text(&mut out, envelope.statement.ecosystem());
    push_text(&mut out, envelope.statement.application());
    push_text(&mut out, envelope.statement.purpose());
    out.extend_from_slice(&envelope.statement.version().to_le_bytes());
    out.extend_from_slice(&envelope.proof_system.wire_id().to_le_bytes());
    out.extend_from_slice(&envelope.verifier_id.0);
    out.extend_from_slice(&envelope.parameter_set_id.0);
    out.extend_from_slice(&envelope.timestamp_unix_seconds.to_le_bytes());
    out.extend_from_slice(&envelope.nonce);
    out.extend_from_slice(&envelope.public_inputs_hash);
    push_bytes_u32(&mut out, &envelope.proof);
    out.extend_from_slice(&envelope.extensions_digest);
    out.extend_from_slice(&(envelope.authentication.len() as u16).to_le_bytes());
    for auth in &envelope.authentication {
        out.extend_from_slice(&auth.suite.wire_id().to_le_bytes());
        out.extend_from_slice(&auth.signer_key_id);
        push_bytes_u32(&mut out, &auth.signature);
    }

    check_len(
        "encoded-envelope",
        out.len(),
        policy.max_encoded_envelope_bytes,
    )?;
    Ok(out)
}

/// Decode the canonical binary representation with allocation-safe length checks.
pub fn decode_binary_envelope_v1(
    encoded: &[u8],
    policy: &EnvelopePolicy,
) -> Result<ProofEnvelopeV3, BinaryEnvelopeCodecError> {
    let bounded = bound_envelope_frame_before_deserialization(encoded, policy)?;
    decode_binary_bounded(bounded, policy)
}

fn decode_binary_bounded(
    bounded: BoundedEnvelopeFrame<'_>,
    policy: &EnvelopePolicy,
) -> Result<ProofEnvelopeV3, BinaryEnvelopeCodecError> {
    let mut cursor = Cursor::new(bounded.as_bytes());
    if cursor.take(BINARY_ENVELOPE_MAGIC_V1.len())? != BINARY_ENVELOPE_MAGIC_V1 {
        return Err(BinaryEnvelopeCodecError::InvalidMagic);
    }

    let protocol_version = cursor.u32()?;
    let ecosystem = cursor.text_u8()?;
    let application = cursor.text_u8()?;
    let purpose = cursor.text_u8()?;
    let statement_version = cursor.u32()?;
    let statement = StatementId::try_new(ecosystem, application, purpose, statement_version)?;
    let proof_system = ProofSystemId::try_from(cursor.u16()?)?;
    let verifier_id = VerifierId(cursor.array32()?);
    let parameter_set_id = ParameterSetId(cursor.array32()?);
    let timestamp_unix_seconds = cursor.u64()?;
    let nonce = cursor.array32()?;
    let public_inputs_hash = cursor.array32()?;
    let proof = cursor.bytes_u32_bounded("proof", policy.max_proof_bytes.min(u32::MAX as usize))?;
    let extensions_digest = cursor.array32()?;

    let authentication_count = usize::from(cursor.u16()?);
    check_len(
        "authentication",
        authentication_count,
        policy.max_authentication_entries.min(u16::MAX as usize),
    )?;
    // An authentication record has at least suite(2) + key-id(32) + length(4).
    // Checking the minimum representation before Vec allocation prevents a large
    // count from reserving memory when the frame cannot possibly contain it.
    let min_auth_bytes =
        authentication_count
            .checked_mul(38)
            .ok_or(BinaryEnvelopeCodecError::LengthLimit {
                field: "authentication",
                actual: authentication_count,
                limit: policy.max_authentication_entries,
            })?;
    if min_auth_bytes > cursor.remaining() {
        return Err(BinaryEnvelopeCodecError::LengthExceedsFrame {
            field: "authentication",
            declared: min_auth_bytes,
            remaining: cursor.remaining(),
        });
    }

    let mut authentication = Vec::with_capacity(authentication_count);
    for _ in 0..authentication_count {
        let suite = AuthenticationSuiteId::try_from(cursor.u16()?)?;
        let signer_key_id = cursor.array32()?;
        let signature = cursor.bytes_u32_bounded(
            "signature",
            policy.max_signature_bytes.min(u32::MAX as usize),
        )?;
        authentication.push(ProofAuthentication {
            suite,
            signer_key_id,
            signature,
        });
    }

    if cursor.remaining() != 0 {
        return Err(BinaryEnvelopeCodecError::TrailingBytes(cursor.remaining()));
    }

    Ok(ProofEnvelopeV3 {
        protocol_version,
        statement,
        proof_system,
        verifier_id,
        parameter_set_id,
        timestamp_unix_seconds,
        nonce,
        public_inputs_hash,
        proof,
        extensions_digest,
        authentication,
    })
}

fn check_len(
    field: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), BinaryEnvelopeCodecError> {
    if actual > limit {
        Err(BinaryEnvelopeCodecError::LengthLimit {
            field,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    debug_assert!(text.len() <= u8::MAX as usize);
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
}

fn push_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u32::MAX as usize);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], BinaryEnvelopeCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(BinaryEnvelopeCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BinaryEnvelopeCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, BinaryEnvelopeCodecError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| BinaryEnvelopeCodecError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, BinaryEnvelopeCodecError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| BinaryEnvelopeCodecError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, BinaryEnvelopeCodecError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| BinaryEnvelopeCodecError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], BinaryEnvelopeCodecError> {
        self.take(32)?
            .try_into()
            .map_err(|_| BinaryEnvelopeCodecError::Truncated)
    }

    fn text_u8(&mut self) -> Result<String, BinaryEnvelopeCodecError> {
        let length = usize::from(
            *self
                .take(1)?
                .first()
                .ok_or(BinaryEnvelopeCodecError::Truncated)?,
        );
        let raw = self.take(length)?;
        let text = std::str::from_utf8(raw).map_err(|_| BinaryEnvelopeCodecError::InvalidUtf8)?;
        Ok(text.to_owned())
    }

    fn bytes_u32_bounded(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> Result<Vec<u8>, BinaryEnvelopeCodecError> {
        let declared =
            usize::try_from(self.u32()?).map_err(|_| BinaryEnvelopeCodecError::LengthLimit {
                field,
                actual: usize::MAX,
                limit,
            })?;
        check_len(field, declared, limit)?;
        if declared > self.remaining() {
            return Err(BinaryEnvelopeCodecError::LengthExceedsFrame {
                field,
                declared,
                remaining: self.remaining(),
            });
        }
        Ok(self.take(declared)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_zk_protocol::{
        AuthenticationSuiteId, ParameterSetId, ProofAuthentication, ProofSystemId, StatementId,
        VerifierId, empty_extensions_digest,
    };

    fn envelope() -> ProofEnvelopeV3 {
        let mut envelope = ProofEnvelopeV3::new_unsigned(
            StatementId::try_new("XENIA", "Access", "RangeCredential", 3).unwrap(),
            ProofSystemId::WINTERFELL,
            VerifierId([0x11; 32]),
            ParameterSetId([0x22; 32]),
            1_800_000_000,
            [0x33; 32],
            [0x44; 32],
            vec![0x55; 64],
            empty_extensions_digest(),
        );
        envelope.authentication.push(ProofAuthentication {
            suite: AuthenticationSuiteId::ML_DSA_65_FIPS204,
            signer_key_id: [0x66; 32],
            signature: vec![0x77; 96],
        });
        envelope
    }

    #[test]
    fn canonical_binary_round_trip_is_exact() {
        let policy = EnvelopePolicy::default();
        let expected = envelope();
        let encoded = encode_binary_envelope_v1(&expected, &policy).unwrap();
        let decoded = decode_binary_envelope_v1(&encoded, &policy).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            encode_binary_envelope_v1(&decoded, &policy).unwrap(),
            encoded
        );
    }

    #[test]
    fn binary_decoder_rejects_every_truncation_and_trailing_byte() {
        let policy = EnvelopePolicy::default();
        let encoded = encode_binary_envelope_v1(&envelope(), &policy).unwrap();
        for end in 0..encoded.len() {
            assert!(decode_binary_envelope_v1(&encoded[..end], &policy).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_binary_envelope_v1(&trailing, &policy).unwrap_err(),
            BinaryEnvelopeCodecError::TrailingBytes(1)
        );
    }

    #[test]
    fn binary_declared_lengths_are_bounded_before_allocation() {
        let mut policy = EnvelopePolicy::default();
        policy.max_proof_bytes = 32;
        let encoded = encode_binary_envelope_v1(&envelope(), &EnvelopePolicy::default()).unwrap();
        assert!(matches!(
            decode_binary_envelope_v1(&encoded, &policy),
            Err(BinaryEnvelopeCodecError::LengthLimit { field: "proof", .. })
        ));
    }

    #[test]
    fn json_unknown_fields_fail_closed() {
        let policy = EnvelopePolicy::default();
        let encoded = encode_json_envelope(&envelope()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["unexpected_security_field"] = serde_json::json!(true);
        let mutated = serde_json::to_vec(&value).unwrap();
        assert!(decode_json_envelope_bounded(&mutated, &policy).is_err());
    }

    #[test]
    fn json_duplicate_fields_fail_closed() {
        let policy = EnvelopePolicy::default();
        let encoded = String::from_utf8(encode_json_envelope(&envelope()).unwrap()).unwrap();
        let mutated = encoded.replacen(
            "\"protocol_version\":3",
            "\"protocol_version\":3,\"protocol_version\":3",
            1,
        );
        assert!(decode_json_envelope_bounded(mutated.as_bytes(), &policy).is_err());
    }

    #[test]
    fn oversized_frame_never_reaches_json_or_binary_parser() {
        let policy = EnvelopePolicy {
            max_encoded_envelope_bytes: 4,
            ..EnvelopePolicy::default()
        };
        assert!(matches!(
            decode_json_envelope_bounded(b"{malformed but oversized}", &policy),
            Err(JsonEnvelopeCodecError::Frame(
                EnvelopeValidationError::EncodedEnvelopeTooLarge { .. }
            ))
        ));
        assert!(matches!(
            decode_binary_envelope_v1(b"malformed but oversized", &policy),
            Err(BinaryEnvelopeCodecError::Frame(
                EnvelopeValidationError::EncodedEnvelopeTooLarge { .. }
            ))
        ));
    }
}
