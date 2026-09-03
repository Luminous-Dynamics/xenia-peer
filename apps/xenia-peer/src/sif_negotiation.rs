// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated exact-profile negotiation gate for SIF protected-file transfer.
//!
//! The unauthenticated transport advertisement is deliberately not authority to enable
//! protected transfer. Instead both peers exchange an exact compiled SIF profile
//! fingerprint under the transcript-derived control key using the dedicated capability
//! AEAD domain (`0x35`/`0x36`). Only a successful move-only transition from
//! [`PendingSifProtectedFileChannel`] to [`NegotiatedSifProtectedFileChannel`] exposes
//! Offer/Response/Chunk/Complete APIs.
//!
//! Capability traffic and protected evidence traffic use separate directional nonce
//! domains. The pending capability carrier is dropped on successful negotiation; the
//! protected transfer carrier (`0x33`/`0x34`) retains an independent sequence/replay
//! lifecycle. A negotiation failure has no automatic path to legacy file transfer.

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_ledger::{
    MAX_SIF_PROTECTED_FILE_CHUNK_BYTES, MAX_SIF_PROTECTED_FILE_NAME_BYTES,
    MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES, SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM,
    SIF_DELIVERY_RECEIPT_SCHEMA, SIF_FILE_RESULT_PROFILE, SIF_PROTECTED_FILE_CHUNK_SCHEMA,
    SIF_PROTECTED_FILE_COMPLETE_SCHEMA, SIF_PROTECTED_FILE_OFFER_DIGEST_ALGORITHM,
    SIF_PROTECTED_FILE_OFFER_SCHEMA, SIF_PROTECTED_FILE_PROTOCOL_SCHEMA,
    SIF_PROTECTED_FILE_RESPONSE_SCHEMA, SifProtectedFileChunk, SifProtectedFileComplete,
    SifProtectedFileOffer, SifProtectedFileOfferResponse,
};
use xenia_peer_core::{
    MAX_SIF_CAPABILITY_SEMANTIC_BYTES, MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES,
    MAX_SIF_PROTECTED_FILE_COMPLETE_BYTES, MAX_SIF_PROTECTED_FILE_OFFER_BYTES,
    MAX_SIF_PROTECTED_FILE_RESPONSE_BYTES, PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST,
    PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
    PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER, SIF_CAPABILITY_WIRE_SCHEMA_VERSION,
    SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION, SifCapabilityWireError,
    SifProtectedFileCapabilityWireChannel, SifProtectedFileCapabilityWirePayload,
    SifProtectedFileWireRole,
};

use crate::sif_semantic_wire::{
    SIF_SEMANTIC_WIRE_CODEC_VERSION, SifProtectedFileSemanticChannel, SifSemanticWireError,
};

/// Canonical fixed capability-message codec version.
pub const SIF_CAPABILITY_CODEC_VERSION: u8 = 1;
/// Exact byte length of the v1 capability message: version + profile digest.
pub const SIF_CAPABILITY_MESSAGE_BYTES: usize = 1 + 32;

const SIF_CAPABILITY_PROFILE_DOMAIN: &[u8] = b"xenia:sif-protected-file:capability-profile:v1";

/// Return the exact compiled protected-file profile fingerprint negotiated by this build.
///
/// This is deliberately stricter than a feature boolean. Any change to a bound schema,
/// codec version, payload-domain allocation, cryptographic commitment label, or protocol
/// ceiling changes the digest and therefore prevents silent cross-profile operation.
pub fn current_sif_protected_file_profile_digest() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SIF_CAPABILITY_PROFILE_DOMAIN);
    push_label(&mut hasher, SIF_PROTECTED_FILE_PROTOCOL_SCHEMA);
    push_label(&mut hasher, SIF_PROTECTED_FILE_OFFER_SCHEMA);
    push_label(&mut hasher, SIF_PROTECTED_FILE_RESPONSE_SCHEMA);
    push_label(&mut hasher, SIF_PROTECTED_FILE_CHUNK_SCHEMA);
    push_label(&mut hasher, SIF_PROTECTED_FILE_COMPLETE_SCHEMA);
    push_label(&mut hasher, SIF_PROTECTED_FILE_OFFER_DIGEST_ALGORITHM);
    push_label(&mut hasher, SIF_FILE_RESULT_PROFILE);
    push_label(&mut hasher, SIF_DELIVERY_RECEIPT_SCHEMA);
    push_label(&mut hasher, SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM);
    push_u8(&mut hasher, SIF_SEMANTIC_WIRE_CODEC_VERSION);
    push_u16(&mut hasher, SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION);
    push_u16(&mut hasher, SIF_CAPABILITY_WIRE_SCHEMA_VERSION);
    push_u8(&mut hasher, SIF_CAPABILITY_CODEC_VERSION);
    push_u8(&mut hasher, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
    push_u8(&mut hasher, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER);
    push_u8(&mut hasher, PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST);
    push_u8(&mut hasher, PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_NAME_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_CHUNK_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_OFFER_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_RESPONSE_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES);
    push_usize(&mut hasher, MAX_SIF_PROTECTED_FILE_COMPLETE_BYTES);
    push_usize(&mut hasher, MAX_SIF_CAPABILITY_SEMANTIC_BYTES);
    *hasher.finalize().as_bytes()
}

fn push_label(hasher: &mut blake3::Hasher, label: &str) {
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
}

fn push_u8(hasher: &mut blake3::Hasher, value: u8) {
    hasher.update(&[value]);
}

fn push_u16(hasher: &mut blake3::Hasher, value: u16) {
    hasher.update(&value.to_be_bytes());
}

fn push_usize(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(&(value as u64).to_be_bytes());
}

fn encode_current_capability() -> Vec<u8> {
    let mut out = Vec::with_capacity(SIF_CAPABILITY_MESSAGE_BYTES);
    out.push(SIF_CAPABILITY_CODEC_VERSION);
    out.extend_from_slice(&current_sif_protected_file_profile_digest());
    out
}

fn decode_capability(bytes: &[u8]) -> Result<[u8; 32], SifNegotiationError> {
    if bytes.len() != SIF_CAPABILITY_MESSAGE_BYTES {
        return Err(SifNegotiationError::MalformedCapabilityLength {
            expected: SIF_CAPABILITY_MESSAGE_BYTES,
            found: bytes.len(),
        });
    }
    if bytes[0] != SIF_CAPABILITY_CODEC_VERSION {
        return Err(SifNegotiationError::UnsupportedCapabilityCodec {
            found: bytes[0],
        });
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[1..]);
    Ok(digest)
}

/// Pre-negotiation SIF channel.
///
/// This type intentionally exposes no protected Offer/Chunk API. The local exact
/// capability must first be successfully sealed, then a peer capability must be opened
/// and match exactly. `accept_peer_capability` consumes `self`, so any mismatch or
/// malformed peer message destroys this pending attempt rather than returning a
/// partially negotiated channel.
pub struct PendingSifProtectedFileChannel {
    capability: SifProtectedFileCapabilityWireChannel,
    semantic: SifProtectedFileSemanticChannel,
    local_capability_emitted: bool,
}

impl PendingSifProtectedFileChannel {
    /// Create pending capability and protected-transfer channels for `role`.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            capability: SifProtectedFileCapabilityWireChannel::new(role),
            semantic: SifProtectedFileSemanticChannel::new(role),
            local_capability_emitted: false,
        }
    }

    /// Create deterministic pending channels for qualification tests.
    ///
    /// Both subchannels deliberately use the same fixture source metadata here. Their
    /// disjoint payload types prove that capability and transfer nonce domains remain
    /// distinct even under otherwise identical source/key/epoch/sequence inputs.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            capability: SifProtectedFileCapabilityWireChannel::with_fixture(role, source_id, epoch),
            semantic: SifProtectedFileSemanticChannel::with_fixture(role, source_id, epoch),
            local_capability_emitted: false,
        }
    }

    /// Endpoint role fixed for both pending subchannels.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.semantic.role()
    }

    /// Install one explicit initial control key into both disjoint SIF domains.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.capability.install_control_key(key);
        self.semantic.install_control_key(key);
    }

    /// Install the initial transcript-derived control key into both SIF domains.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.capability.install_schedule(schedule);
        self.semantic.install_schedule(schedule);
    }

    /// Advance previous-key grace expiry while negotiation is pending.
    pub fn tick(&mut self) {
        self.capability.tick();
        self.semantic.tick();
    }

    /// Seal this build's exact protected-file capability profile.
    ///
    /// The local-emitted flag changes only after a successful authenticated seal. A
    /// caller therefore cannot negotiate a peer profile without first committing its
    /// own exact profile to the wire.
    pub fn seal_local_capability(&mut self) -> Result<Vec<u8>, SifNegotiationError> {
        let payload = SifProtectedFileCapabilityWirePayload::new(encode_current_capability())?;
        let envelope = self.capability.seal(&payload)?;
        self.local_capability_emitted = true;
        Ok(envelope)
    }

    /// Consume pending state and accept one exact peer capability profile.
    ///
    /// There is deliberately no legacy fallback return state. Failure means this SIF
    /// protected-transfer attempt did not negotiate and cannot emit protected evidence.
    pub fn accept_peer_capability(
        mut self,
        envelope: &[u8],
    ) -> Result<NegotiatedSifProtectedFileChannel, SifNegotiationError> {
        if !self.local_capability_emitted {
            return Err(SifNegotiationError::LocalCapabilityNotEmitted);
        }
        let payload = self.capability.open(envelope)?;
        let peer_digest = decode_capability(payload.semantic_bytes())?;
        let expected = current_sif_protected_file_profile_digest();
        if peer_digest != expected {
            return Err(SifNegotiationError::CapabilityProfileMismatch {
                expected,
                found: peer_digest,
            });
        }
        Ok(NegotiatedSifProtectedFileChannel {
            semantic: self.semantic,
            profile_digest: expected,
        })
    }
}

/// Capability-authenticated SIF protected-transfer channel.
///
/// This is the public state that exposes protected semantic traffic. Construction is
/// private and only reachable through an exact authenticated capability match.
pub struct NegotiatedSifProtectedFileChannel {
    semantic: SifProtectedFileSemanticChannel,
    profile_digest: [u8; 32],
}

impl NegotiatedSifProtectedFileChannel {
    /// Endpoint role fixed for this negotiated protected-transfer channel.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.semantic.role()
    }

    /// Exact compiled profile fingerprint authenticated during negotiation.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    /// Install the control key for a negotiated rekey epoch.
    ///
    /// Capability negotiation is not repeated automatically: the semantic profile is a
    /// compile/session contract, while cryptographic key epochs rotate underneath it.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.semantic.install_rekey_keys(keys);
    }

    /// Advance previous-key grace expiry on protected transfer traffic.
    pub fn tick(&mut self) {
        self.semantic.tick();
    }

    /// Seal one validated release-bound Offer.
    pub fn seal_offer(
        &mut self,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifNegotiationError> {
        Ok(self.semantic.seal_offer(offer)?)
    }

    /// Open and validate one release-bound Offer.
    pub fn open_offer(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifProtectedFileOffer, SifNegotiationError> {
        Ok(self.semantic.open_offer(envelope)?)
    }

    /// Seal one exact Offer-bound Accept/Reject response.
    pub fn seal_response_for_offer(
        &mut self,
        response: &SifProtectedFileOfferResponse,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifNegotiationError> {
        Ok(self.semantic.seal_response_for_offer(response, offer)?)
    }

    /// Open one response and require exact binding to `offer`.
    pub fn open_response_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileOfferResponse, SifNegotiationError> {
        Ok(self.semantic.open_response_for_offer(envelope, offer)?)
    }

    /// Seal one exact Offer-bound content Chunk.
    pub fn seal_chunk_for_offer(
        &mut self,
        chunk: &SifProtectedFileChunk,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifNegotiationError> {
        Ok(self.semantic.seal_chunk_for_offer(chunk, offer)?)
    }

    /// Open one content Chunk and require exact binding to `offer`.
    pub fn open_chunk_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileChunk, SifNegotiationError> {
        Ok(self.semantic.open_chunk_for_offer(envelope, offer)?)
    }

    /// Seal one exact Offer-bound completion marker.
    pub fn seal_complete_for_offer(
        &mut self,
        complete: &SifProtectedFileComplete,
        offer: &SifProtectedFileOffer,
    ) -> Result<Vec<u8>, SifNegotiationError> {
        Ok(self.semantic.seal_complete_for_offer(complete, offer)?)
    }

    /// Open one completion marker and require exact binding to `offer`.
    pub fn open_complete_for_offer(
        &mut self,
        envelope: &[u8],
        offer: &SifProtectedFileOffer,
    ) -> Result<SifProtectedFileComplete, SifNegotiationError> {
        Ok(self.semantic.open_complete_for_offer(envelope, offer)?)
    }
}

/// Fail-closed authenticated SIF capability-negotiation errors.
#[derive(Debug, Error)]
pub enum SifNegotiationError {
    /// Dedicated capability AEAD carrier rejected or failed the message.
    #[error(transparent)]
    CapabilityWire(#[from] SifCapabilityWireError),
    /// Protected semantic carrier/codec rejected or failed a post-negotiation message.
    #[error(transparent)]
    Semantic(#[from] SifSemanticWireError),
    /// Peer capability cannot be accepted until this endpoint emitted its own profile.
    #[error("local SIF capability must be emitted before accepting peer capability")]
    LocalCapabilityNotEmitted,
    /// Capability message had the wrong exact fixed length.
    #[error("malformed SIF capability length: expected {expected}, found {found}")]
    MalformedCapabilityLength {
        /// Required exact v1 length.
        expected: usize,
        /// Authenticated peer length.
        found: usize,
    },
    /// Capability codec version is unsupported.
    #[error("unsupported SIF capability codec version {found}")]
    UnsupportedCapabilityCodec {
        /// Authenticated codec version received.
        found: u8,
    },
    /// Peer authenticated a different compiled protected-file security profile.
    #[error("SIF protected-file capability profile mismatch")]
    CapabilityProfileMismatch {
        /// Exact local profile required for this build.
        expected: [u8; 32],
        /// Exact authenticated peer profile.
        found: [u8; 32],
    },
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

    fn pending_pair() -> (
        PendingSifProtectedFileChannel,
        PendingSifProtectedFileChannel,
    ) {
        let mut host = PendingSifProtectedFileChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = PendingSifProtectedFileChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    fn negotiate_pair() -> (
        NegotiatedSifProtectedFileChannel,
        NegotiatedSifProtectedFileChannel,
    ) {
        let (mut host, mut viewer) = pending_pair();
        let host_cap = host.seal_local_capability().unwrap();
        let viewer_cap = viewer.seal_local_capability().unwrap();
        let host = host.accept_peer_capability(&viewer_cap).unwrap();
        let viewer = viewer.accept_peer_capability(&host_cap).unwrap();
        (host, viewer)
    }

    fn offer_for(payload: &[u8]) -> SifProtectedFileOffer {
        let content_hash = *blake3::hash(payload).as_bytes();
        let result_digest =
            sif_file_result_digest("evidence.bin", payload.len() as u64, content_hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(1),
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
            "xenia-sif-negotiation-{}-{}",
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
    fn exact_profile_negotiation_unlocks_protected_offer_api() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let (mut host, mut viewer) = negotiate_pair();
        assert_eq!(
            host.profile_digest(),
            current_sif_protected_file_profile_digest()
        );
        let envelope = host.seal_offer(&offer).unwrap();
        assert_eq!(viewer.open_offer(&envelope).unwrap(), offer);
    }

    #[test]
    fn peer_capability_cannot_be_accepted_before_local_profile_is_emitted() {
        let (mut host, viewer) = pending_pair();
        let host_cap = host.seal_local_capability().unwrap();
        assert!(matches!(
            viewer.accept_peer_capability(&host_cap),
            Err(SifNegotiationError::LocalCapabilityNotEmitted)
        ));
    }

    #[test]
    fn authenticated_profile_mismatch_consumes_pending_attempt() {
        let (mut host, mut viewer) = pending_pair();
        let _viewer_cap = viewer.seal_local_capability().unwrap();
        let _host_cap = host.seal_local_capability().unwrap();

        let mut forged_bytes = encode_current_capability();
        forged_bytes[1] ^= 0x80;
        let forged = SifProtectedFileCapabilityWirePayload::new(forged_bytes).unwrap();
        let envelope = host.capability.seal(&forged).unwrap();
        assert!(matches!(
            viewer.accept_peer_capability(&envelope),
            Err(SifNegotiationError::CapabilityProfileMismatch { .. })
        ));
    }

    #[test]
    fn capability_profile_digest_is_nonzero_and_stable_within_build() {
        let first = current_sif_protected_file_profile_digest();
        let second = current_sif_protected_file_profile_digest();
        assert_ne!(first, [0u8; 32]);
        assert_eq!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn negotiated_profile_gates_full_wire_to_durable_custody_chain() {
        let payload = b"abcdefghijklmnop";
        let offer = offer_for(payload);
        let (mut host, mut viewer) = negotiate_pair();

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
                1_780_000_000_500,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        assert_eq!(binding.disposition(), SifDeliveryDisposition::PersistedVerified);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
