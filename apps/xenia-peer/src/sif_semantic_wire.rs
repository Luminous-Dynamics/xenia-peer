// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed application-layer bridge between SIF ledger semantics and the dedicated
//! protected-file AEAD carrier.
//!
//! `xenia-peer-core` deliberately carries only bounded opaque semantic bytes so the
//! permissively licensed carrier does not depend on the AGPL ledger. This module is
//! the narrow join: concrete Offer/Response/Chunk/Complete values are validated,
//! encoded with one fixed canonical grammar, tagged with the matching encrypted wire
//! class, and sealed through the dedicated directional SIF channel.
//!
//! Generic Serde/bincode decoding is intentionally not used here. Even when an outer
//! envelope is small, attacker-controlled collection/string length prefixes can cause
//! a decoder to reserve much larger allocations before semantic validation runs. The
//! codec below parses fixed-width lengths first, checks protocol ceilings, requires an
//! exact byte count with no trailing representation, and only then allocates/copies
//! bounded display-name, Reject-reason, or Chunk bytes.

use thiserror::Error;
use uuid::Uuid;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    MAX_SIF_PROTECTED_FILE_CHUNK_BYTES, MAX_SIF_PROTECTED_FILE_NAME_BYTES,
    MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES, SifProtectedFileChunk,
    SifProtectedFileComplete, SifProtectedFileOffer, SifProtectedFileOfferDecision,
    SifProtectedFileOfferResponse, SifProtectedFileProtocolError,
};
use xenia_peer_core::{
    SifProtectedFileWireChannel, SifProtectedFileWireError, SifProtectedFileWireKind,
    SifProtectedFileWirePayload, SifProtectedFileWireRole,
};

/// Stable canonical application-layer codec carried inside SIF wire wrapper v1.
pub const SIF_SEMANTIC_WIRE_CODEC_VERSION: u8 = 1;

const OFFER_FIXED_BYTES: usize = 1 + 16 + 8 + 32 + 32 + 8 + 32 + 2;
const RESPONSE_FIXED_BYTES: usize = 1 + 32 + 1 + 2;
const CHUNK_FIXED_BYTES: usize = 1 + 32 + 8 + 4;
const COMPLETE_FIXED_BYTES: usize = 1 + 32;

/// Typed SIF semantic channel over the dedicated peer-core protected-file carrier.
pub struct SifProtectedFileSemanticChannel {
    wire: SifProtectedFileWireChannel,
}

impl SifProtectedFileSemanticChannel {
    /// Create a channel with fresh wire-session source metadata for `role`.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            wire: SifProtectedFileWireChannel::new(role),
        }
    }

    /// Create a deterministic channel for interoperability and qualification tests.
    ///
    /// Production callers should prefer [`Self::new`] or explicitly reuse authenticated
    /// enclosing-session source metadata according to the deployment integration.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            wire: SifProtectedFileWireChannel::with_fixture(role, source_id, epoch),
        }
    }

    /// Endpoint role fixed for the underlying directional SIF carrier.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.wire.role()
    }

    /// Install an explicit negotiated control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.wire.install_control_key(key);
    }

    /// Install the initial transcript-derived control key.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.wire.install_schedule(schedule);
    }

    /// Install the control key for a negotiated rekey epoch.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.wire.install_rekey_keys(keys);
    }

    /// Advance previous-key grace expiry on the underlying SIF channel.
    pub fn tick(&mut self) {
        self.wire.tick();
    }

    /// Validate, canonically encode, and seal one exact release-bound Offer.
    pub fn seal_offer(
        &mut self,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        offer.validate()?;
        self.seal_semantic(SifProtectedFileWireKind::Offer, encode_offer(offer)?)
    }

    /// Open and validate one exact release-bound Offer.
    pub fn open_offer(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifProtectedFileOffer, SifSemanticWireError> {
        let bytes = self.open_semantic(envelope, SifProtectedFileWireKind::Offer)?;
        decode_offer(&bytes)
    }

    /// Validate an Accept/Reject against `offer`, then seal it as a Response.
    pub fn seal_response_for_offer(
        &mut self,
        response: &SifProtectedFileOfferResponse,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        response.validate_against_offer(offer)?;
        self.seal_semantic(
            SifProtectedFileWireKind::Response,
            encode_response(response)?,
        )
    }

    /// Open a Response and require exact binding to `offer`.
    pub fn open_response_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileOfferResponse, SifSemanticWireError> {
        let bytes = self.open_semantic(envelope, SifProtectedFileWireKind::Response)?;
        decode_response(&bytes, offer)
    }

    /// Validate one content Chunk against `offer`, then seal it as a Chunk.
    pub fn seal_chunk_for_offer(
        &mut self,
        chunk: &SifProtectedFileChunk,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        chunk.validate_against_offer(offer)?;
        self.seal_semantic(SifProtectedFileWireKind::Chunk, encode_chunk(chunk)?)
    }

    /// Open a Chunk and require exact binding and byte-range validity against `offer`.
    pub fn open_chunk_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileChunk, SifSemanticWireError> {
        let bytes = self.open_semantic(envelope, SifProtectedFileWireKind::Chunk)?;
        decode_chunk(&bytes, offer)
    }

    /// Validate a completion marker against `offer`, then seal it as Complete.
    pub fn seal_complete_for_offer(
        &mut self,
        complete: &SifProtectedFileComplete,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        complete.validate_against_offer(offer)?;
        self.seal_semantic(
            SifProtectedFileWireKind::Complete,
            encode_complete(complete),
        )
    }

    /// Open a Complete marker and require exact binding to `offer`.
    pub fn open_complete_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileComplete, SifSemanticWireError> {
        let bytes = self.open_semantic(envelope, SifProtectedFileWireKind::Complete)?;
        decode_complete(&bytes, offer)
    }

    fn seal_semantic(
        &mut self,
        kind: SifProtectedFileWireKind,
        semantic_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        let payload = SifProtectedFileWirePayload::new(kind, semantic_bytes)?;
        Ok(self.wire.seal(&payload)?)
    }

    fn open_semantic(
        &mut self,
        envelope: &[u8],
        expected_kind: SifProtectedFileWireKind,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        let payload = self.wire.open(envelope)?;
        if payload.kind() != expected_kind {
            return Err(SifSemanticWireError::UnexpectedSemanticKind {
                expected: expected_kind,
                found: payload.kind(),
            });
        }
        Ok(payload.into_semantic_bytes())
    }
}

fn encode_offer(offer: &SifProtectedFileOffer) -> Result<Vec<u8>, SifSemanticWireError> {
    offer.validate()?;
    let name = offer.display_name().as_bytes();
    let name_len = u16::try_from(name.len())
        .map_err(|_| malformed("offer.display_name length cannot fit u16"))?;
    let mut out = Vec::with_capacity(OFFER_FIXED_BYTES + name.len());
    out.push(SIF_SEMANTIC_WIRE_CODEC_VERSION);
    out.extend_from_slice(offer.release_id().as_bytes());
    out.extend_from_slice(&offer.transfer_id().to_be_bytes());
    out.extend_from_slice(&offer.sender_release_entry_hash());
    out.extend_from_slice(&offer.result_digest());
    out.extend_from_slice(&offer.size().to_be_bytes());
    out.extend_from_slice(&offer.content_blake3());
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name);
    Ok(out)
}

fn decode_offer(bytes: &[u8]) -> Result<SifProtectedFileOffer, SifSemanticWireError> {
    let mut reader = SemanticReader::new(bytes);
    reader.require_version()?;
    let release_id = Uuid::from_bytes(reader.array::<16>("offer.release_id")?);
    let transfer_id = reader.u64("offer.transfer_id")?;
    let sender_release_entry_hash = reader.array::<32>("offer.sender_release_entry_hash")?;
    let result_digest = reader.array::<32>("offer.result_digest")?;
    let size = reader.u64("offer.size")?;
    let content_blake3 = reader.array::<32>("offer.content_blake3")?;
    let name_len = usize::from(reader.u16("offer.display_name_len")?);
    if name_len == 0 || name_len > MAX_SIF_PROTECTED_FILE_NAME_BYTES {
        return Err(malformed("offer.display_name length outside protocol bound"));
    }
    let name_bytes = reader.slice(name_len, "offer.display_name")?;
    reader.finish()?;
    let display_name = std::str::from_utf8(name_bytes)
        .map_err(|_| malformed("offer.display_name is not UTF-8"))?;
    Ok(SifProtectedFileOffer::new(
        release_id,
        transfer_id,
        sender_release_entry_hash,
        result_digest,
        display_name.to_owned(),
        size,
        content_blake3,
    )?)
}

fn encode_response(
    response: &SifProtectedFileOfferResponse,
) -> Result<Vec<u8>, SifSemanticWireError> {
    let reason = response.reason().unwrap_or("").as_bytes();
    let reason_len = u16::try_from(reason.len())
        .map_err(|_| malformed("response.reason length cannot fit u16"))?;
    let mut out = Vec::with_capacity(RESPONSE_FIXED_BYTES + reason.len());
    out.push(SIF_SEMANTIC_WIRE_CODEC_VERSION);
    out.extend_from_slice(&response.offer_digest());
    out.push(match response.decision() {
        SifProtectedFileOfferDecision::Accept => 0,
        SifProtectedFileOfferDecision::Reject => 1,
    });
    out.extend_from_slice(&reason_len.to_be_bytes());
    out.extend_from_slice(reason);
    Ok(out)
}

fn decode_response(
    bytes: &[u8],
    offer: &SifProtectedFileOffer,
) -> Result<SifProtectedFileOfferResponse, SifSemanticWireError> {
    let mut reader = SemanticReader::new(bytes);
    reader.require_version()?;
    let offer_digest = reader.array::<32>("response.offer_digest")?;
    require_offer_digest(offer_digest, offer)?;
    let decision = reader.u8("response.decision")?;
    let reason_len = usize::from(reader.u16("response.reason_len")?);
    if reason_len > MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES {
        return Err(malformed("response.reason length outside protocol bound"));
    }
    let reason_bytes = reader.slice(reason_len, "response.reason")?;
    reader.finish()?;

    match decision {
        0 if reason_len == 0 => Ok(SifProtectedFileOfferResponse::accept(offer)?),
        0 => Err(malformed("Accept response carried a Reject reason")),
        1 if reason_len == 0 => Err(malformed("Reject response omitted reason")),
        1 => {
            let reason = std::str::from_utf8(reason_bytes)
                .map_err(|_| malformed("response.reason is not UTF-8"))?;
            Ok(SifProtectedFileOfferResponse::reject(
                offer,
                reason.to_owned(),
            )?)
        }
        _ => Err(malformed("response.decision tag is unknown")),
    }
}

fn encode_chunk(chunk: &SifProtectedFileChunk) -> Result<Vec<u8>, SifSemanticWireError> {
    let data_len = u32::try_from(chunk.data().len())
        .map_err(|_| malformed("chunk.data length cannot fit u32"))?;
    let mut out = Vec::with_capacity(CHUNK_FIXED_BYTES + chunk.data().len());
    out.push(SIF_SEMANTIC_WIRE_CODEC_VERSION);
    out.extend_from_slice(&chunk.offer_digest());
    out.extend_from_slice(&chunk.offset().to_be_bytes());
    out.extend_from_slice(&data_len.to_be_bytes());
    out.extend_from_slice(chunk.data());
    Ok(out)
}

fn decode_chunk(
    bytes: &[u8],
    offer: &SifProtectedFileOffer,
) -> Result<SifProtectedFileChunk, SifSemanticWireError> {
    let mut reader = SemanticReader::new(bytes);
    reader.require_version()?;
    let offer_digest = reader.array::<32>("chunk.offer_digest")?;
    require_offer_digest(offer_digest, offer)?;
    let offset = reader.u64("chunk.offset")?;
    let data_len = usize::try_from(reader.u32("chunk.data_len")?)
        .map_err(|_| malformed("chunk.data length cannot fit usize"))?;
    if data_len == 0 || data_len > MAX_SIF_PROTECTED_FILE_CHUNK_BYTES {
        return Err(malformed("chunk.data length outside protocol bound"));
    }
    let data = reader.slice(data_len, "chunk.data")?;
    reader.finish()?;
    Ok(SifProtectedFileChunk::new(offer, offset, data.to_vec())?)
}

fn encode_complete(complete: &SifProtectedFileComplete) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMPLETE_FIXED_BYTES);
    out.push(SIF_SEMANTIC_WIRE_CODEC_VERSION);
    out.extend_from_slice(&complete.offer_digest());
    out
}

fn decode_complete(
    bytes: &[u8],
    offer: &SifProtectedFileOffer,
) -> Result<SifProtectedFileComplete, SifSemanticWireError> {
    let mut reader = SemanticReader::new(bytes);
    reader.require_version()?;
    let offer_digest = reader.array::<32>("complete.offer_digest")?;
    reader.finish()?;
    require_offer_digest(offer_digest, offer)?;
    Ok(SifProtectedFileComplete::new(offer)?)
}

fn require_offer_digest(
    found: [u8; 32],
    offer: &SifProtectedFileOffer,
) -> Result<(), SifSemanticWireError> {
    if found != offer.offer_digest()? {
        return Err(SifProtectedFileProtocolError::OfferDigestMismatch.into());
    }
    Ok(())
}

fn malformed(reason: &'static str) -> SifSemanticWireError {
    SifSemanticWireError::MalformedSemantic { reason }
}

struct SemanticReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SemanticReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn require_version(&mut self) -> Result<(), SifSemanticWireError> {
        if self.u8("codec.version")? != SIF_SEMANTIC_WIRE_CODEC_VERSION {
            return Err(malformed("unsupported SIF semantic wire codec version"));
        }
        Ok(())
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, SifSemanticWireError> {
        Ok(self.slice(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, SifSemanticWireError> {
        Ok(u16::from_be_bytes(self.array::<2>(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SifSemanticWireError> {
        Ok(u32::from_be_bytes(self.array::<4>(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SifSemanticWireError> {
        Ok(u64::from_be_bytes(self.array::<8>(field)?))
    }

    fn array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SifSemanticWireError> {
        let bytes = self.slice(N, field)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn slice(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], SifSemanticWireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| malformed("semantic field length overflow"))?;
        if end > self.bytes.len() {
            return Err(SifSemanticWireError::TruncatedSemantic { field });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(self) -> Result<(), SifSemanticWireError> {
        if self.offset != self.bytes.len() {
            return Err(malformed("semantic payload has trailing bytes"));
        }
        Ok(())
    }
}

/// Fail-closed semantic↔wire adapter errors.
#[derive(Debug, Error)]
pub enum SifSemanticWireError {
    /// Dedicated SIF AEAD carrier rejected or failed the envelope.
    #[error(transparent)]
    Wire(#[from] SifProtectedFileWireError),
    /// Concrete ledger object failed SIF protocol validation.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Encrypted coarse class did not match the typed API the caller invoked.
    #[error("unexpected SIF semantic wire kind: expected {expected:?}, found {found:?}")]
    UnexpectedSemanticKind {
        /// Message class required by the typed receive method.
        expected: SifProtectedFileWireKind,
        /// Authenticated encrypted class carried by the peer.
        found: SifProtectedFileWireKind,
    },
    /// Semantic field ended before its declared fixed/bounded length.
    #[error("truncated SIF semantic field: {field}")]
    TruncatedSemantic {
        /// Field being read when authenticated bytes ended.
        field: &'static str,
    },
    /// Canonical semantic grammar was violated.
    #[error("malformed SIF semantic payload: {reason}")]
    MalformedSemantic {
        /// Stable local diagnostic explaining the rejected representation.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sif_receive_runtime::{SifReceiveRuntime, SifReceiveRuntimeTerminal};
    use std::path::PathBuf;
    use xenia_ledger::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, SessionTranscriptBinding, SifDeliveryDisposition,
        SignatureSuite, sif_file_result_digest,
    };

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn pair() -> (
        SifProtectedFileSemanticChannel,
        SifProtectedFileSemanticChannel,
    ) {
        let mut host = SifProtectedFileSemanticChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = SifProtectedFileSemanticChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    fn offer_for(payload: &[u8], release: u128) -> SifProtectedFileOffer {
        let content_hash = *blake3::hash(payload).as_bytes();
        let result_digest =
            sif_file_result_digest("evidence.bin", payload.len() as u64, content_hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(release),
            7,
            [0x22; 32],
            result_digest,
            "evidence.bin",
            payload.len() as u64,
            content_hash,
        )
        .unwrap()
    }

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-sif-semantic-wire-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn offer_response_chunk_complete_roundtrip_preserves_exact_semantics() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload, 1);
        let (mut host, mut viewer) = pair();

        let received_offer = viewer.open_offer(&host.seal_offer(&offer).unwrap()).unwrap();
        assert_eq!(received_offer, offer);

        let response = SifProtectedFileOfferResponse::accept(&received_offer).unwrap();
        let sealed_response = viewer
            .seal_response_for_offer(&response, &received_offer)
            .unwrap();
        assert_eq!(
            host.open_response_for_offer(&sealed_response, &offer).unwrap(),
            response
        );

        let chunk = SifProtectedFileChunk::new(&offer, 0, payload.to_vec()).unwrap();
        let sealed_chunk = host.seal_chunk_for_offer(&chunk, &offer).unwrap();
        assert_eq!(
            viewer
                .open_chunk_for_offer(&sealed_chunk, &received_offer)
                .unwrap(),
            chunk
        );

        let complete = SifProtectedFileComplete::new(&offer).unwrap();
        let sealed_complete = host.seal_complete_for_offer(&complete, &offer).unwrap();
        assert_eq!(
            viewer
                .open_complete_for_offer(&sealed_complete, &received_offer)
                .unwrap(),
            complete
        );
    }

    #[test]
    fn response_cannot_be_sealed_against_a_different_offer() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload, 1);
        let other_offer = offer_for(payload, 2);
        let response = SifProtectedFileOfferResponse::accept(&offer).unwrap();
        let (mut host, _) = pair();
        assert!(matches!(
            host.seal_response_for_offer(&response, &other_offer),
            Err(SifSemanticWireError::Protocol(
                SifProtectedFileProtocolError::ReleaseIdMismatch
            ))
        ));
    }

    #[test]
    fn encrypted_message_class_must_match_typed_receive_api() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload, 1);
        let (mut host, mut viewer) = pair();
        let wrong_class = SifProtectedFileWirePayload::new(
            SifProtectedFileWireKind::Chunk,
            encode_offer(&offer).unwrap(),
        )
        .unwrap();
        let envelope = host.wire.seal(&wrong_class).unwrap();
        assert!(matches!(
            viewer.open_offer(&envelope),
            Err(SifSemanticWireError::UnexpectedSemanticKind {
                expected: SifProtectedFileWireKind::Offer,
                found: SifProtectedFileWireKind::Chunk,
            })
        ));
    }

    #[test]
    fn inner_chunk_length_bomb_is_rejected_before_data_allocation() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload, 1);
        let (mut host, mut viewer) = pair();
        let mut forged = Vec::with_capacity(CHUNK_FIXED_BYTES);
        forged.push(SIF_SEMANTIC_WIRE_CODEC_VERSION);
        forged.extend_from_slice(&offer.offer_digest().unwrap());
        forged.extend_from_slice(&0u64.to_be_bytes());
        forged.extend_from_slice(&u32::MAX.to_be_bytes());
        let wrapper =
            SifProtectedFileWirePayload::new(SifProtectedFileWireKind::Chunk, forged).unwrap();
        let envelope = host.wire.seal(&wrapper).unwrap();
        assert!(matches!(
            viewer.open_chunk_for_offer(&envelope, &offer),
            Err(SifSemanticWireError::MalformedSemantic { .. })
        ));
    }

    #[test]
    fn semantic_codec_rejects_trailing_authenticated_representation() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload, 1);
        let (mut host, mut viewer) = pair();
        let mut forged = encode_offer(&offer).unwrap();
        forged.push(0);
        let wrapper =
            SifProtectedFileWirePayload::new(SifProtectedFileWireKind::Offer, forged).unwrap();
        let envelope = host.wire.seal(&wrapper).unwrap();
        assert!(matches!(
            viewer.open_offer(&envelope),
            Err(SifSemanticWireError::MalformedSemantic { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn full_semantic_wire_and_durable_custody_chain_reaches_positive_receipt() {
        let payload = b"abcdefghijklmnop";
        let offer = offer_for(payload, 1);
        let (mut host, mut viewer) = pair();

        let received_offer = viewer.open_offer(&host.seal_offer(&offer).unwrap()).unwrap();
        let accept = SifProtectedFileOfferResponse::accept(&received_offer).unwrap();
        let accept_envelope = viewer
            .seal_response_for_offer(&accept, &received_offer)
            .unwrap();
        host.open_response_for_offer(&accept_envelope, &offer)
            .unwrap();

        let dir = temp_dir();
        let final_path = dir.join(received_offer.display_name());
        let mut runtime = SifReceiveRuntime::begin(received_offer.clone(), &dir).unwrap();

        for (offset, bytes) in [(0u64, &payload[..6]), (6u64, &payload[6..])] {
            let chunk = SifProtectedFileChunk::new(&offer, offset, bytes.to_vec()).unwrap();
            let envelope = host.seal_chunk_for_offer(&chunk, &offer).unwrap();
            let received = viewer
                .open_chunk_for_offer(&envelope, &received_offer)
                .unwrap();
            runtime = runtime.accept_chunk(&received).unwrap();
        }

        let complete = SifProtectedFileComplete::new(&offer).unwrap();
        let complete_envelope = host.seal_complete_for_offer(&complete, &offer).unwrap();
        let received_complete = viewer
            .open_complete_for_offer(&complete_envelope, &received_offer)
            .unwrap();
        let terminal = runtime.finish_with_complete(&received_complete).unwrap();
        let durable = match terminal {
            SifReceiveRuntimeTerminal::DurableVerified(durable) => durable,
            other => panic!("expected durable verified custody, got {other:?}"),
        };
        assert_eq!(std::fs::read(&final_path).unwrap(), payload);

        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let binding = durable
            .into_delivery_receipt_binding(
                session,
                SignatureSuite::Ed25519Rfc8032,
                &[0x55; 32],
                1_780_000_000_400,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        assert_eq!(binding.disposition(), SifDeliveryDisposition::PersistedVerified);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
