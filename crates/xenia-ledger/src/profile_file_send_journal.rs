// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash/retry-safe write-ahead accounting for SIF protected file sends.
//!
//! A successful [`SifProtectedFileSendState::prepare_chunk`] transition is persisted
//! before the returned capability may be handed to a carrier. Recovery therefore
//! treats a prepared-but-unconfirmed chunk as **possibly disclosed** rather than
//! silently assuming that an interrupted send emitted no bytes.
//!
//! Novel chunks are strictly contiguous and only one prepared chunk may be outstanding.
//! Exact recovery of that outstanding chunk is idempotent; any same-range substitution
//! fails closed. Carrier confirmation is a separate durable transition. This module
//! deliberately does not claim receiver acknowledgement or application egress
//! confinement; transport integration must carry the returned idempotency token and
//! prevent alternate byte-supply paths before those stronger claims are made.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::chain::Chain;
use crate::protected_file_protocol::{
    SifProtectedFileChunk, SifProtectedFileOffer, SifProtectedFileProtocolError,
};
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for signed write-ahead protected-file send entries.
pub const SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA: &str = "xenia-sif-protected-file-send-entry-v1";
/// Commitment algorithm used by the send journal.
pub const SIF_PROTECTED_FILE_SEND_COMMITMENT_ALGORITHM: &str = "blake3-256";

const SEND_ENTRY_DOMAIN: &[u8] = b"xenia:sif-protected-file:send-entry:v1";
const CHUNK_DIGEST_DOMAIN: &[u8] = b"xenia:sif-protected-file:send-chunk-digest:v1";
const IDEMPOTENCY_TOKEN_DOMAIN: &[u8] = b"xenia:sif-protected-file:send-idempotency:v1";

/// One write-ahead or carrier-confirmed transition for a protected file chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SifProtectedFileSendEvent {
    /// Exact chunk identity became durable before any carrier write was allowed.
    Prepared {
        /// Monotonic content-chunk sequence within this Offer.
        chunk_sequence: u64,
        /// Exact file offset of the prepared chunk.
        offset: u64,
        /// Exact prepared content length.
        len: u64,
        /// Domain-separated digest of Offer, sequence, range and exact content.
        chunk_digest: [u8; 32],
        /// Stable retry identity derived from the complete prepared identity.
        idempotency_token: [u8; 32],
    },
    /// The carrier reported success for one exact previously prepared chunk.
    CarrierConfirmed {
        /// Sequence of the exact prepared chunk.
        chunk_sequence: u64,
        /// Signed journal entry hash that durably prepared the chunk.
        prepare_entry_hash: [u8; 32],
    },
}

/// One signed, hash-chained write-ahead send-journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileSendEntry {
    schema: String,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    event: SifProtectedFileSendEvent,
    entry_hash: [u8; 32],
    signature: SignatureEnvelope,
}

impl SifProtectedFileSendEntry {
    /// Monotonic signed-journal sequence.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Release governed by this entry.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Session-local protected transfer identifier.
    pub const fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    /// Exact protected Offer digest governed by this entry.
    pub const fn offer_digest(&self) -> [u8; 32] {
        self.offer_digest
    }

    /// Signed write-ahead event.
    pub fn event(&self) -> &SifProtectedFileSendEvent {
        &self.event
    }

    /// Domain-separated signed entry hash.
    pub const fn entry_hash(&self) -> [u8; 32] {
        self.entry_hash
    }
}

/// Durable send-journal frontier used as a compare-and-swap token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileSendFrontier {
    /// Number of durable signed entries.
    pub entry_count: u64,
    /// Last signed entry hash, or all-zero for an empty journal.
    pub head_hash: [u8; 32],
}

impl SifProtectedFileSendFrontier {
    /// Empty-journal frontier.
    pub const GENESIS: Self = Self {
        entry_count: 0,
        head_hash: [0u8; 32],
    };
}

/// Atomic persistence contract for write-ahead protected-file send transitions.
pub trait SifProtectedFileSendStore {
    /// Store-specific failure.
    type Error;

    /// Persist `next_entries` only if durable state still equals `expected`.
    fn compare_and_swap(
        &mut self,
        expected: SifProtectedFileSendFrontier,
        next_entries: &[SifProtectedFileSendEntry],
    ) -> Result<(), Self::Error>;
}

/// Whether prepare created new authority or recovered the exact outstanding chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifProtectedFilePrepareDisposition {
    /// A new `Prepared` entry was atomically persisted.
    New,
    /// The exact durable outstanding chunk was recovered without re-appending.
    Retry,
}

/// Whether carrier confirmation created a new entry or observed an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifProtectedFileConfirmDisposition {
    /// A new `CarrierConfirmed` entry was atomically persisted.
    New,
    /// The exact chunk was already durably carrier-confirmed.
    AlreadyConfirmed,
}

/// Capability proving that one exact chunk identity is already durable.
///
/// This type is intentionally non-`Clone`. Future transport typestate should consume
/// or borrow it rather than accepting caller-authored chunks independently.
#[derive(Debug)]
pub struct PreparedSifProtectedFileChunk {
    chunk: SifProtectedFileChunk,
    chunk_sequence: u64,
    chunk_digest: [u8; 32],
    idempotency_token: [u8; 32],
    prepare_entry_hash: [u8; 32],
    disposition: SifProtectedFilePrepareDisposition,
}

impl PreparedSifProtectedFileChunk {
    /// Exact protected Chunk whose identity is durably prepared.
    pub fn chunk(&self) -> &SifProtectedFileChunk {
        &self.chunk
    }

    /// Monotonic content-chunk sequence.
    pub const fn chunk_sequence(&self) -> u64 {
        self.chunk_sequence
    }

    /// Exact domain-separated chunk digest.
    pub const fn chunk_digest(&self) -> [u8; 32] {
        self.chunk_digest
    }

    /// Stable idempotency token for crash-safe transport retry integration.
    pub const fn idempotency_token(&self) -> [u8; 32] {
        self.idempotency_token
    }

    /// Signed journal hash proving the write-ahead prepare became durable.
    pub const fn prepare_entry_hash(&self) -> [u8; 32] {
        self.prepare_entry_hash
    }

    /// Whether this capability came from a new prepare or exact recovery retry.
    pub const fn disposition(&self) -> SifProtectedFilePrepareDisposition {
        self.disposition
    }
}

#[derive(Debug, Clone, Copy)]
struct PreparedRecord {
    chunk_sequence: u64,
    offset: u64,
    len: u64,
    chunk_digest: [u8; 32],
    idempotency_token: [u8; 32],
    prepare_entry_hash: [u8; 32],
    confirmed: bool,
}

#[derive(Debug, Default)]
struct SendIndex {
    prepared: Vec<PreparedRecord>,
    possible_frontier: u64,
    confirmed_frontier: u64,
}

/// CAS-backed write-ahead state for one exact protected Offer.
///
/// `possibly_disclosed_unique_bytes` advances when `Prepared` becomes durable, before
/// carrier I/O. `confirmed_unique_bytes` advances only after durable carrier success.
/// At most one unconfirmed prepared chunk may exist.
#[derive(Debug)]
pub struct SifProtectedFileSendState {
    offer: SifProtectedFileOffer,
    offer_digest: [u8; 32],
    ledger_public_key: [u8; 32],
    entries: Vec<SifProtectedFileSendEntry>,
}

impl SifProtectedFileSendState {
    /// Create an empty send journal bound to an exact protected Offer and ledger signer.
    pub fn new(
        offer: SifProtectedFileOffer,
        chain: &Chain,
    ) -> Result<Self, SifProtectedFileSendError> {
        offer.validate()?;
        let offer_digest = offer.offer_digest()?;
        Ok(Self {
            offer,
            offer_digest,
            ledger_public_key: chain.signing_key.verifying_key().to_bytes(),
            entries: Vec::new(),
        })
    }

    /// Verify and rehydrate persisted entries for one exact protected Offer.
    pub fn from_verified_entries(
        offer: SifProtectedFileOffer,
        entries: Vec<SifProtectedFileSendEntry>,
        ledger_public_key: &[u8],
    ) -> Result<Self, SifProtectedFileSendError> {
        offer.validate()?;
        let ledger_public_key: [u8; 32] = ledger_public_key.try_into().map_err(|_| {
            SifProtectedFileSendError::BadLedgerPublicKeyLength {
                found: ledger_public_key.len(),
            }
        })?;
        verify_sif_protected_file_send_entries(&entries, &offer, &ledger_public_key)?;
        Ok(Self {
            offer_digest: offer.offer_digest()?,
            offer,
            ledger_public_key,
            entries,
        })
    }

    /// Exact protected Offer governed by this journal.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Current durable CAS frontier.
    pub fn frontier(&self) -> SifProtectedFileSendFrontier {
        SifProtectedFileSendFrontier {
            entry_count: self.entries.len() as u64,
            head_hash: self
                .entries
                .last()
                .map(SifProtectedFileSendEntry::entry_hash)
                .unwrap_or([0u8; 32]),
        }
    }

    /// Signed entries for persistence, audit and crash recovery.
    pub fn entries(&self) -> &[SifProtectedFileSendEntry] {
        &self.entries
    }

    /// Consume the state into its serializable signed entries.
    pub fn into_entries(self) -> Vec<SifProtectedFileSendEntry> {
        self.entries
    }

    /// Unique content bytes durably prepared before carrier I/O.
    ///
    /// On recovery this is the conservative upper bound on bytes that may have escaped.
    pub fn possibly_disclosed_unique_bytes(&self) -> Result<u64, SifProtectedFileSendError> {
        Ok(self.index()?.possible_frontier)
    }

    /// Unique content bytes whose carrier send was durably confirmed successful.
    pub fn confirmed_unique_bytes(&self) -> Result<u64, SifProtectedFileSendError> {
        Ok(self.index()?.confirmed_frontier)
    }

    /// Persist one exact write-ahead chunk identity before carrier I/O.
    ///
    /// Novel chunks must begin exactly at the possible-disclosure frontier, and no new
    /// chunk may be prepared while another remains unconfirmed. Re-presenting the exact
    /// outstanding chunk returns an idempotent retry capability without a second entry.
    pub fn prepare_chunk<S: SifProtectedFileSendStore>(
        &mut self,
        chain: &Chain,
        chunk: SifProtectedFileChunk,
        store: &mut S,
    ) -> Result<PreparedSifProtectedFileChunk, TransactionalSifProtectedFileSendError<S::Error>> {
        self.require_same_signer(chain)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        chunk
            .validate_against_offer(&self.offer)
            .map_err(SifProtectedFileSendError::Protocol)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;

        let index = self
            .index()
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        let offset = chunk.offset();
        let len = u64::try_from(chunk.data().len())
            .map_err(|_| SifProtectedFileSendError::ChunkLengthOverflow)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;

        if offset < index.possible_frontier {
            let prepared = index
                .prepared
                .iter()
                .find(|record| record.offset == offset)
                .ok_or(SifProtectedFileSendError::NonExactPreparedOverlap)
                .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
            let chunk_digest = sif_protected_file_send_chunk_digest(
                self.offer_digest,
                prepared.chunk_sequence,
                offset,
                chunk.data(),
            );
            let token = sif_protected_file_send_idempotency_token(
                self.offer_digest,
                prepared.chunk_sequence,
                offset,
                len,
                chunk_digest,
            );
            if prepared.len != len
                || prepared.chunk_digest != chunk_digest
                || prepared.idempotency_token != token
            {
                return Err(TransactionalSifProtectedFileSendError::Protocol(
                    SifProtectedFileSendError::PreparedChunkIdentityMismatch,
                ));
            }
            if prepared.confirmed {
                return Err(TransactionalSifProtectedFileSendError::Protocol(
                    SifProtectedFileSendError::ChunkAlreadyConfirmed,
                ));
            }
            return Ok(PreparedSifProtectedFileChunk {
                chunk,
                chunk_sequence: prepared.chunk_sequence,
                chunk_digest,
                idempotency_token: token,
                prepare_entry_hash: prepared.prepare_entry_hash,
                disposition: SifProtectedFilePrepareDisposition::Retry,
            });
        }

        if offset > index.possible_frontier {
            return Err(TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::PreparedChunkGap {
                    expected: index.possible_frontier,
                    found: offset,
                },
            ));
        }
        if index.prepared.len() as u64 != confirmed_count(&index) {
            return Err(TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::UnconfirmedChunkOutstanding,
            ));
        }

        let chunk_sequence = index.prepared.len() as u64;
        let chunk_digest = sif_protected_file_send_chunk_digest(
            self.offer_digest,
            chunk_sequence,
            offset,
            chunk.data(),
        );
        let idempotency_token = sif_protected_file_send_idempotency_token(
            self.offer_digest,
            chunk_sequence,
            offset,
            len,
            chunk_digest,
        );
        let expected = self.frontier();
        let entry = build_send_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            expected.head_hash,
            self.offer.release_id(),
            self.offer.transfer_id(),
            self.offer_digest,
            SifProtectedFileSendEvent::Prepared {
                chunk_sequence,
                offset,
                len,
                chunk_digest,
                idempotency_token,
            },
        );
        let prepare_entry_hash = entry.entry_hash;
        self.entries.push(entry);
        if let Err(error) = store.compare_and_swap(expected, &self.entries) {
            self.entries.pop();
            return Err(TransactionalSifProtectedFileSendError::Persist(error));
        }
        Ok(PreparedSifProtectedFileChunk {
            chunk,
            chunk_sequence,
            chunk_digest,
            idempotency_token,
            prepare_entry_hash,
            disposition: SifProtectedFilePrepareDisposition::New,
        })
    }

    /// Atomically record carrier success for one exact durably prepared chunk.
    ///
    /// This is carrier confirmation, not receiver acknowledgement. Re-confirming an
    /// exact already-confirmed capability is idempotent and appends no second entry.
    pub fn confirm_carrier_success<S: SifProtectedFileSendStore>(
        &mut self,
        chain: &Chain,
        prepared: &PreparedSifProtectedFileChunk,
        store: &mut S,
    ) -> Result<SifProtectedFileConfirmDisposition, TransactionalSifProtectedFileSendError<S::Error>>
    {
        self.require_same_signer(chain)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        prepared
            .chunk
            .validate_against_offer(&self.offer)
            .map_err(SifProtectedFileSendError::Protocol)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        let index = self
            .index()
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        let record = index
            .prepared
            .get(prepared.chunk_sequence as usize)
            .ok_or(SifProtectedFileSendError::ConfirmationWithoutPrepare)
            .map_err(TransactionalSifProtectedFileSendError::Protocol)?;
        if record.prepare_entry_hash != prepared.prepare_entry_hash
            || record.chunk_digest != prepared.chunk_digest
            || record.idempotency_token != prepared.idempotency_token
            || record.offset != prepared.chunk.offset()
            || record.len != prepared.chunk.data().len() as u64
        {
            return Err(TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::PreparedAuthorizationMismatch,
            ));
        }
        if record.confirmed {
            return Ok(SifProtectedFileConfirmDisposition::AlreadyConfirmed);
        }
        let next_confirm = confirmed_count(&index);
        if prepared.chunk_sequence != next_confirm {
            return Err(TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::ConfirmationOutOfOrder {
                    expected: next_confirm,
                    found: prepared.chunk_sequence,
                },
            ));
        }

        let expected = self.frontier();
        let entry = build_send_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            expected.head_hash,
            self.offer.release_id(),
            self.offer.transfer_id(),
            self.offer_digest,
            SifProtectedFileSendEvent::CarrierConfirmed {
                chunk_sequence: prepared.chunk_sequence,
                prepare_entry_hash: prepared.prepare_entry_hash,
            },
        );
        self.entries.push(entry);
        if let Err(error) = store.compare_and_swap(expected, &self.entries) {
            self.entries.pop();
            return Err(TransactionalSifProtectedFileSendError::Persist(error));
        }
        Ok(SifProtectedFileConfirmDisposition::New)
    }

    fn index(&self) -> Result<SendIndex, SifProtectedFileSendError> {
        build_send_index(&self.entries, &self.offer, self.offer_digest)
    }

    fn require_same_signer(&self, chain: &Chain) -> Result<(), SifProtectedFileSendError> {
        if chain.signing_key.verifying_key().as_bytes() != &self.ledger_public_key {
            return Err(SifProtectedFileSendError::LedgerSignerChanged);
        }
        Ok(())
    }
}

/// Verify a persisted send journal and all write-ahead transitions offline.
pub fn verify_sif_protected_file_send_entries(
    entries: &[SifProtectedFileSendEntry],
    offer: &SifProtectedFileOffer,
    ledger_public_key: &[u8],
) -> Result<(), SifProtectedFileSendError> {
    offer.validate()?;
    let offer_digest = offer.offer_digest()?;
    let backend = Ed25519EvidenceSignatureBackend;
    let mut previous = [0u8; 32];

    for (position, entry) in entries.iter().enumerate() {
        if entry.schema != SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA {
            return Err(SifProtectedFileSendError::UnsupportedEntrySchema);
        }
        if entry.seq != position as u64 || entry.prev_hash != previous {
            return Err(SifProtectedFileSendError::JournalChainMismatch);
        }
        if entry.release_id != offer.release_id()
            || entry.transfer_id != offer.transfer_id()
            || entry.offer_digest != offer_digest
        {
            return Err(SifProtectedFileSendError::OfferBindingMismatch);
        }
        let expected = send_entry_hash(
            entry.seq,
            entry.prev_hash,
            entry.release_id,
            entry.transfer_id,
            entry.offer_digest,
            &entry.event,
        );
        if entry.entry_hash != expected {
            return Err(SifProtectedFileSendError::JournalHashMismatch);
        }
        let suite = entry.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(SifProtectedFileSendError::UnsupportedSignatureSuite { suite });
        }
        backend.verify_signature(
            ledger_public_key,
            &entry.entry_hash,
            &entry.signature.signature,
        )?;
        previous = entry.entry_hash;
    }

    build_send_index(entries, offer, offer_digest)?;
    Ok(())
}

/// Derive the exact domain-separated digest for one prepared chunk identity.
pub fn sif_protected_file_send_chunk_digest(
    offer_digest: [u8; 32],
    chunk_sequence: u64,
    offset: u64,
    data: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHUNK_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(&offer_digest);
    hasher.update(&chunk_sequence.to_be_bytes());
    hasher.update(&offset.to_be_bytes());
    hasher.update(&(data.len() as u64).to_be_bytes());
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Derive the stable retry token for one exact already-prepared identity.
pub fn sif_protected_file_send_idempotency_token(
    offer_digest: [u8; 32],
    chunk_sequence: u64,
    offset: u64,
    len: u64,
    chunk_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDEMPOTENCY_TOKEN_DOMAIN);
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(&offer_digest);
    hasher.update(&chunk_sequence.to_be_bytes());
    hasher.update(&offset.to_be_bytes());
    hasher.update(&len.to_be_bytes());
    hasher.update(&chunk_digest);
    *hasher.finalize().as_bytes()
}

fn build_send_index(
    entries: &[SifProtectedFileSendEntry],
    offer: &SifProtectedFileOffer,
    offer_digest: [u8; 32],
) -> Result<SendIndex, SifProtectedFileSendError> {
    let mut index = SendIndex::default();
    for entry in entries {
        if entry.release_id != offer.release_id()
            || entry.transfer_id != offer.transfer_id()
            || entry.offer_digest != offer_digest
        {
            return Err(SifProtectedFileSendError::OfferBindingMismatch);
        }
        match entry.event {
            SifProtectedFileSendEvent::Prepared {
                chunk_sequence,
                offset,
                len,
                chunk_digest,
                idempotency_token,
            } => {
                if len == 0 {
                    return Err(SifProtectedFileSendError::ZeroPreparedChunk);
                }
                if chunk_sequence != index.prepared.len() as u64 {
                    return Err(SifProtectedFileSendError::PreparedSequenceMismatch);
                }
                if confirmed_count(&index) != index.prepared.len() as u64 {
                    return Err(SifProtectedFileSendError::UnconfirmedChunkOutstanding);
                }
                if offset != index.possible_frontier {
                    return Err(SifProtectedFileSendError::PreparedChunkGap {
                        expected: index.possible_frontier,
                        found: offset,
                    });
                }
                let end = offset
                    .checked_add(len)
                    .ok_or(SifProtectedFileSendError::ChunkRangeOverflow)?;
                if end > offer.size() {
                    return Err(SifProtectedFileSendError::PreparedBeyondOffer {
                        end,
                        size: offer.size(),
                    });
                }
                require_nonzero("chunk_digest", &chunk_digest)?;
                require_nonzero("idempotency_token", &idempotency_token)?;
                index.prepared.push(PreparedRecord {
                    chunk_sequence,
                    offset,
                    len,
                    chunk_digest,
                    idempotency_token,
                    prepare_entry_hash: entry.entry_hash,
                    confirmed: false,
                });
                index.possible_frontier = end;
            }
            SifProtectedFileSendEvent::CarrierConfirmed {
                chunk_sequence,
                prepare_entry_hash,
            } => {
                let expected_sequence = confirmed_count(&index);
                if chunk_sequence != expected_sequence {
                    return Err(SifProtectedFileSendError::ConfirmationOutOfOrder {
                        expected: expected_sequence,
                        found: chunk_sequence,
                    });
                }
                let record = index
                    .prepared
                    .get_mut(chunk_sequence as usize)
                    .ok_or(SifProtectedFileSendError::ConfirmationWithoutPrepare)?;
                if record.prepare_entry_hash != prepare_entry_hash {
                    return Err(SifProtectedFileSendError::PreparedAuthorizationMismatch);
                }
                record.confirmed = true;
                index.confirmed_frontier = record
                    .offset
                    .checked_add(record.len)
                    .ok_or(SifProtectedFileSendError::ChunkRangeOverflow)?;
            }
        }
    }
    Ok(index)
}

fn confirmed_count(index: &SendIndex) -> u64 {
    index
        .prepared
        .iter()
        .take_while(|record| record.confirmed)
        .count() as u64
}

fn build_send_entry(
    signing_key: &ed25519_dalek::SigningKey,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    event: SifProtectedFileSendEvent,
) -> SifProtectedFileSendEntry {
    let entry_hash = send_entry_hash(
        seq,
        prev_hash,
        release_id,
        transfer_id,
        offer_digest,
        &event,
    );
    let signature = signing_key.sign(&entry_hash).to_bytes();
    SifProtectedFileSendEntry {
        schema: SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA.to_string(),
        seq,
        prev_hash,
        release_id,
        transfer_id,
        offer_digest,
        event,
        entry_hash,
        signature: SignatureEnvelope::ed25519(signature),
    }
}

fn send_entry_hash(
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    event: &SifProtectedFileSendEvent,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_ENTRY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_SEND_ENTRY_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_SEND_COMMITMENT_ALGORITHM.as_bytes());
    hasher.update(&[0]);
    hasher.update(&seq.to_be_bytes());
    hasher.update(&prev_hash);
    hasher.update(release_id.as_bytes());
    hasher.update(&transfer_id.to_be_bytes());
    hasher.update(&offer_digest);
    match event {
        SifProtectedFileSendEvent::Prepared {
            chunk_sequence,
            offset,
            len,
            chunk_digest,
            idempotency_token,
        } => {
            hasher.update(&[0]);
            hasher.update(&chunk_sequence.to_be_bytes());
            hasher.update(&offset.to_be_bytes());
            hasher.update(&len.to_be_bytes());
            hasher.update(chunk_digest);
            hasher.update(idempotency_token);
        }
        SifProtectedFileSendEvent::CarrierConfirmed {
            chunk_sequence,
            prepare_entry_hash,
        } => {
            hasher.update(&[1]);
            hasher.update(&chunk_sequence.to_be_bytes());
            hasher.update(prepare_entry_hash);
        }
    }
    *hasher.finalize().as_bytes()
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), SifProtectedFileSendError> {
    if *digest == [0u8; 32] {
        return Err(SifProtectedFileSendError::ZeroCommitment { field });
    }
    Ok(())
}

/// Protocol or persisted-journal failure for protected-file write-ahead sends.
#[derive(Debug, Error)]
pub enum SifProtectedFileSendError {
    /// Protected-file semantic validation failed.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Signature envelope was malformed.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// Rehydration received a ledger public key with the wrong length.
    #[error("protected-file send ledger public key must be 32 bytes, found {found}")]
    BadLedgerPublicKeyLength {
        /// Actual supplied public-key length.
        found: usize,
    },
    /// The signer changed after this send journal was created or rehydrated.
    #[error("protected-file send journal ledger signer changed")]
    LedgerSignerChanged,
    /// Persisted entry schema is unsupported.
    #[error("unsupported protected-file send entry schema")]
    UnsupportedEntrySchema,
    /// Entry signature suite is unsupported by this journal profile.
    #[error("unsupported protected-file send signature suite: {suite:?}")]
    UnsupportedSignatureSuite {
        /// Suite carried by the rejected entry.
        suite: SignatureSuite,
    },
    /// Persisted entry belongs to a different release/transfer/Offer.
    #[error("protected-file send journal Offer binding mismatch")]
    OfferBindingMismatch,
    /// Signed hash-chain sequence or predecessor is invalid.
    #[error("protected-file send journal chain mismatch")]
    JournalChainMismatch,
    /// Persisted entry hash does not match canonical entry content.
    #[error("protected-file send journal hash mismatch")]
    JournalHashMismatch,
    /// Required digest/token used an all-zero placeholder.
    #[error("protected-file send commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Invalid commitment field.
        field: &'static str,
    },
    /// Chunk content length could not be represented as `u64`.
    #[error("protected-file send chunk length overflow")]
    ChunkLengthOverflow,
    /// Prepared range end overflowed.
    #[error("protected-file send chunk range overflow")]
    ChunkRangeOverflow,
    /// Persisted Prepared event used a zero-length range.
    #[error("protected-file send prepared chunk must not be empty")]
    ZeroPreparedChunk,
    /// Persisted prepared sequence is not canonical and contiguous.
    #[error("protected-file send prepared chunk sequence mismatch")]
    PreparedSequenceMismatch,
    /// A new prepared range left a gap in the possible-disclosure frontier.
    #[error("protected-file send prepared chunk offset {found} does not equal frontier {expected}")]
    PreparedChunkGap {
        /// Expected next contiguous offset.
        expected: u64,
        /// Supplied chunk offset.
        found: u64,
    },
    /// A retry overlapped prepared bytes without naming an exact old boundary.
    #[error("protected-file send retry is not an exact prepared range")]
    NonExactPreparedOverlap,
    /// A retry changed content, length or idempotency identity.
    #[error("protected-file send retry changed the prepared chunk identity")]
    PreparedChunkIdentityMismatch,
    /// Caller attempted to re-prepare a chunk already carrier-confirmed.
    #[error("protected-file send chunk is already carrier-confirmed")]
    ChunkAlreadyConfirmed,
    /// A second novel chunk was prepared before the prior chunk was confirmed.
    #[error("protected-file send has an unconfirmed prepared chunk outstanding")]
    UnconfirmedChunkOutstanding,
    /// Prepared range exceeds the exact Offer length.
    #[error("protected-file send prepared end {end} exceeds Offer size {size}")]
    PreparedBeyondOffer {
        /// Exclusive prepared range end.
        end: u64,
        /// Exact Offer size.
        size: u64,
    },
    /// Carrier confirmation named no prepared chunk.
    #[error("protected-file send carrier confirmation has no matching prepare")]
    ConfirmationWithoutPrepare,
    /// Carrier confirmation did not match the exact durable prepare capability.
    #[error("protected-file send prepared authorization mismatch")]
    PreparedAuthorizationMismatch,
    /// Carrier confirmations were not recorded in contiguous content order.
    #[error("protected-file send confirmation sequence {found} does not equal next {expected}")]
    ConfirmationOutOfOrder {
        /// Expected next confirmation sequence.
        expected: u64,
        /// Supplied confirmation sequence.
        found: u64,
    },
}

/// Protocol/persistence failure while atomically advancing the send journal.
#[derive(Debug)]
pub enum TransactionalSifProtectedFileSendError<E> {
    /// Semantic, cryptographic or lifecycle validation failed.
    Protocol(SifProtectedFileSendError),
    /// Atomic durable persistence failed; the in-memory append was rolled back.
    Persist(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StoreError {
        Stale,
    }

    #[derive(Debug, Default)]
    struct MemoryStore {
        entries: Vec<SifProtectedFileSendEntry>,
    }

    impl SifProtectedFileSendStore for MemoryStore {
        type Error = StoreError;

        fn compare_and_swap(
            &mut self,
            expected: SifProtectedFileSendFrontier,
            next_entries: &[SifProtectedFileSendEntry],
        ) -> Result<(), Self::Error> {
            let actual = SifProtectedFileSendFrontier {
                entry_count: self.entries.len() as u64,
                head_hash: self
                    .entries
                    .last()
                    .map(SifProtectedFileSendEntry::entry_hash)
                    .unwrap_or([0u8; 32]),
            };
            if actual != expected {
                return Err(StoreError::Stale);
            }
            self.entries = next_entries.to_vec();
            Ok(())
        }
    }

    fn fixture() -> (Chain, SifProtectedFileOffer, SifProtectedFileSendState, MemoryStore) {
        let chain = Chain::new(SigningKey::from_bytes(&[7u8; 32]));
        let content_blake3 = [9u8; 32];
        let result_digest = crate::sif_file_result_digest("report.bin", 8, content_blake3).unwrap();
        let offer = SifProtectedFileOffer::new(
            Uuid::from_u128(1),
            11,
            [3u8; 32],
            result_digest,
            "report.bin",
            8,
            content_blake3,
        )
        .unwrap();
        let state = SifProtectedFileSendState::new(offer.clone(), &chain).unwrap();
        (chain, offer, state, MemoryStore::default())
    }

    fn chunk(offer: &SifProtectedFileOffer, offset: u64, data: &[u8]) -> SifProtectedFileChunk {
        SifProtectedFileChunk::new(offer, offset, data.to_vec()).unwrap()
    }

    #[test]
    fn prepare_is_write_ahead_and_exact_retry_does_not_double_account() {
        let (chain, offer, mut state, mut store) = fixture();
        let first = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        assert_eq!(first.disposition(), SifProtectedFilePrepareDisposition::New);
        assert_eq!(state.possibly_disclosed_unique_bytes().unwrap(), 4);
        assert_eq!(state.confirmed_unique_bytes().unwrap(), 0);
        assert_eq!(store.entries.len(), 1);

        let retry = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        assert_eq!(retry.disposition(), SifProtectedFilePrepareDisposition::Retry);
        assert_eq!(retry.idempotency_token(), first.idempotency_token());
        assert_eq!(retry.prepare_entry_hash(), first.prepare_entry_hash());
        assert_eq!(state.possibly_disclosed_unique_bytes().unwrap(), 4);
        assert_eq!(store.entries.len(), 1);
    }

    #[test]
    fn substitution_gap_and_second_outstanding_chunk_fail_closed() {
        let (chain, offer, mut state, mut store) = fixture();
        let gap = state
            .prepare_chunk(&chain, chunk(&offer, 4, b"efgh"), &mut store)
            .unwrap_err();
        assert!(matches!(
            gap,
            TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::PreparedChunkGap { .. }
            )
        ));

        state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        let substitution = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abce"), &mut store)
            .unwrap_err();
        assert!(matches!(
            substitution,
            TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::PreparedChunkIdentityMismatch
            )
        ));
        let outstanding = state
            .prepare_chunk(&chain, chunk(&offer, 4, b"efgh"), &mut store)
            .unwrap_err();
        assert!(matches!(
            outstanding,
            TransactionalSifProtectedFileSendError::Protocol(
                SifProtectedFileSendError::UnconfirmedChunkOutstanding
            )
        ));
    }

    #[test]
    fn confirmation_is_separate_and_idempotent() {
        let (chain, offer, mut state, mut store) = fixture();
        let prepared = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        assert_eq!(
            state
                .confirm_carrier_success(&chain, &prepared, &mut store)
                .unwrap(),
            SifProtectedFileConfirmDisposition::New
        );
        assert_eq!(state.confirmed_unique_bytes().unwrap(), 4);
        assert_eq!(state.possibly_disclosed_unique_bytes().unwrap(), 4);
        assert_eq!(
            state
                .confirm_carrier_success(&chain, &prepared, &mut store)
                .unwrap(),
            SifProtectedFileConfirmDisposition::AlreadyConfirmed
        );
        assert_eq!(store.entries.len(), 2);
    }

    #[test]
    fn crash_recovery_preserves_possible_but_unconfirmed_disclosure() {
        let (chain, offer, mut state, mut store) = fixture();
        let prepared = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        let persisted = store.entries.clone();
        drop(state);

        let mut recovered = SifProtectedFileSendState::from_verified_entries(
            offer.clone(),
            persisted,
            chain.signing_key.verifying_key().as_bytes(),
        )
        .unwrap();
        assert_eq!(recovered.possibly_disclosed_unique_bytes().unwrap(), 4);
        assert_eq!(recovered.confirmed_unique_bytes().unwrap(), 0);
        let retry = recovered
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        assert_eq!(retry.idempotency_token(), prepared.idempotency_token());
        assert_eq!(retry.prepare_entry_hash(), prepared.prepare_entry_hash());
    }

    #[test]
    fn next_chunk_requires_prior_confirmation() {
        let (chain, offer, mut state, mut store) = fixture();
        let first = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap();
        state
            .confirm_carrier_success(&chain, &first, &mut store)
            .unwrap();
        let second = state
            .prepare_chunk(&chain, chunk(&offer, 4, b"efgh"), &mut store)
            .unwrap();
        assert_eq!(second.chunk_sequence(), 1);
        assert_eq!(state.possibly_disclosed_unique_bytes().unwrap(), 8);
        assert_eq!(state.confirmed_unique_bytes().unwrap(), 4);
    }

    #[test]
    fn stale_store_rolls_back_prepare() {
        let (chain, offer, mut state, mut store) = fixture();
        store.entries.push(build_send_entry(
            &chain.signing_key,
            0,
            [0u8; 32],
            offer.release_id(),
            offer.transfer_id(),
            offer.offer_digest().unwrap(),
            SifProtectedFileSendEvent::Prepared {
                chunk_sequence: 0,
                offset: 0,
                len: 1,
                chunk_digest: [1u8; 32],
                idempotency_token: [2u8; 32],
            },
        ));
        let error = state
            .prepare_chunk(&chain, chunk(&offer, 0, b"abcd"), &mut store)
            .unwrap_err();
        assert!(matches!(
            error,
            TransactionalSifProtectedFileSendError::Persist(StoreError::Stale)
        ));
        assert_eq!(state.frontier(), SifProtectedFileSendFrontier::GENESIS);
    }
}
