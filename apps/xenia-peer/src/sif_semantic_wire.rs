// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed application-layer bridge between SIF ledger semantics and the dedicated
//! protected-file AEAD carrier.
//!
//! `xenia-peer-core` deliberately carries only bounded opaque semantic bytes so the
//! permissively licensed carrier does not depend on the AGPL ledger. This module is
//! the narrow join: concrete Offer/Response/Chunk/Complete values are validated,
//! canonically bincode-encoded, tagged with the matching encrypted wire class, and
//! sealed through the dedicated directional SIF channel.
//!
//! On receive, the carrier first enforces the dedicated `0x33`/`0x34` AEAD domain.
//! This bridge then requires the encrypted message class expected by the caller,
//! deserializes exactly that concrete ledger type, requires canonical byte-for-byte
//! re-encoding, and finally validates the semantic object against the exact Offer.

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    SifProtectedFileChunk, SifProtectedFileComplete, SifProtectedFileOffer,
    SifProtectedFileOfferResponse, SifProtectedFileProtocolError,
};
use xenia_peer_core::{
    SifProtectedFileWireChannel, SifProtectedFileWireError, SifProtectedFileWireKind,
    SifProtectedFileWirePayload, SifProtectedFileWireRole,
};

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
        self.seal_typed(SifProtectedFileWireKind::Offer, offer)
    }

    /// Open and validate one exact release-bound Offer.
    pub fn open_offer(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifProtectedFileOffer, SifSemanticWireError> {
        let offer = self.open_typed(envelope, SifProtectedFileWireKind::Offer)?;
        offer.validate()?;
        Ok(offer)
    }

    /// Validate an Accept/Reject against `offer`, then seal it as a Response.
    pub fn seal_response_for_offer(
        &mut self,
        response: &SifProtectedFileOfferResponse,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        response.validate_against_offer(offer)?;
        self.seal_typed(SifProtectedFileWireKind::Response, response)
    }

    /// Open a Response and require exact binding to `offer`.
    pub fn open_response_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileOfferResponse, SifSemanticWireError> {
        let response = self.open_typed(envelope, SifProtectedFileWireKind::Response)?;
        response.validate_against_offer(offer)?;
        Ok(response)
    }

    /// Validate one content Chunk against `offer`, then seal it as a Chunk.
    pub fn seal_chunk_for_offer(
        &mut self,
        chunk: &SifProtectedFileChunk,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        chunk.validate_against_offer(offer)?;
        self.seal_typed(SifProtectedFileWireKind::Chunk, chunk)
    }

    /// Open a Chunk and require exact binding and byte-range validity against `offer`.
    pub fn open_chunk_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileChunk, SifSemanticWireError> {
        let chunk = self.open_typed(envelope, SifProtectedFileWireKind::Chunk)?;
        chunk.validate_against_offer(offer)?;
        Ok(chunk)
    }

    /// Validate a completion marker against `offer`, then seal it as Complete.
    pub fn seal_complete_for_offer(
        &mut self,
        complete: &SifProtectedFileComplete,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        complete.validate_against_offer(offer)?;
        self.seal_typed(SifProtectedFileWireKind::Complete, complete)
    }

    /// Open a Complete marker and require exact binding to `offer`.
    pub fn open_complete_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileComplete, SifSemanticWireError> {
        let complete = self.open_typed(envelope, SifProtectedFileWireKind::Complete)?;
        complete.validate_against_offer(offer)?;
        Ok(complete)
    }

    fn seal_typed<T: Serialize>(
        &mut self,
        kind: SifProtectedFileWireKind,
        value: &T,
    ) -> Result<Vec<u8>, SifSemanticWireError> {
        let semantic_bytes = canonical_encode(value)?;
        let payload = SifProtectedFileWirePayload::new(kind, semantic_bytes)?;
        Ok(self.wire.seal(&payload)?)
    }

    fn open_typed<T: Serialize + DeserializeOwned>(
        &mut self,
        envelope: &[u8],
        expected_kind: SifProtectedFileWireKind,
    ) -> Result<T, SifSemanticWireError> {
        let payload = self.wire.open(envelope)?;
        if payload.kind() != expected_kind {
            return Err(SifSemanticWireError::UnexpectedSemanticKind {
                expected: expected_kind,
                found: payload.kind(),
            });
        }
        canonical_decode(payload.semantic_bytes())
    }
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, SifSemanticWireError> {
    bincode::serialize(value).map_err(|error| SifSemanticWireError::Codec {
        operation: "encode",
        message: error.to_string(),
    })
}

fn canonical_decode<T: Serialize + DeserializeOwned>(
    semantic_bytes: &[u8],
) -> Result<T, SifSemanticWireError> {
    let value: T = bincode::deserialize(semantic_bytes).map_err(|error| {
        SifSemanticWireError::Codec {
            operation: "decode",
            message: error.to_string(),
        }
    })?;
    let canonical = canonical_encode(&value)?;
    if canonical != semantic_bytes {
        return Err(SifSemanticWireError::NonCanonicalSemanticEncoding);
    }
    Ok(value)
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
    /// Bincode could not encode/decode the concrete semantic object.
    #[error("SIF semantic {operation} failed: {message}")]
    Codec {
        /// Serialization phase that failed.
        operation: &'static str,
        /// Non-portable diagnostic detail retained for local logs.
        message: String,
    },
    /// Encrypted coarse class did not match the typed API the caller invoked.
    #[error("unexpected SIF semantic wire kind: expected {expected:?}, found {found:?}")]
    UnexpectedSemanticKind {
        /// Message class required by the typed receive method.
        expected: SifProtectedFileWireKind,
        /// Authenticated encrypted class carried by the peer.
        found: SifProtectedFileWireKind,
    },
    /// Authenticated semantic bytes were decodable but not the canonical local encoding.
    #[error("SIF semantic payload used a non-canonical encoding")]
    NonCanonicalSemanticEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sif_receive_runtime::{SifReceiveRuntime, SifReceiveRuntimeTerminal};
    use std::path::PathBuf;
    use uuid::Uuid;
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

        let sealed_offer = host.seal_offer(&offer).unwrap();
        let received_offer = viewer.open_offer(&sealed_offer).unwrap();
        assert_eq!(received_offer, offer);

        let response = SifProtectedFileOfferResponse::accept(&received_offer).unwrap();
        let sealed_response = viewer
            .seal_response_for_offer(&response, &received_offer)
            .unwrap();
        let received_response = host
            .open_response_for_offer(&sealed_response, &offer)
            .unwrap();
        assert_eq!(received_response, response);

        let chunk = SifProtectedFileChunk::new(&offer, 0, payload.to_vec()).unwrap();
        let sealed_chunk = host.seal_chunk_for_offer(&chunk, &offer).unwrap();
        let received_chunk = viewer
            .open_chunk_for_offer(&sealed_chunk, &received_offer)
            .unwrap();
        assert_eq!(received_chunk, chunk);

        let complete = SifProtectedFileComplete::new(&offer).unwrap();
        let sealed_complete = host.seal_complete_for_offer(&complete, &offer).unwrap();
        let received_complete = viewer
            .open_complete_for_offer(&sealed_complete, &received_offer)
            .unwrap();
        assert_eq!(received_complete, complete);
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
        let semantic_bytes = bincode::serialize(&offer).unwrap();
        let wrong_class = SifProtectedFileWirePayload::new(
            SifProtectedFileWireKind::Chunk,
            semantic_bytes,
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

        for (offset, bytes) in [(0u64, &payload[..6]), (6u64, &payload[6..])]
        {
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
