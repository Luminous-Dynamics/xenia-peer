// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable, fail-closed single-use issuance state for Xenia Symthaea authority receipts.
//!
//! The journal stores an exact request-binding digest and opaque retained receipt
//! bytes. It does not decide whether a request is authorized.
//!
//! Lifecycle:
//! - absent -> Reserved
//! - Reserved -> IssuedAndRetained
//! - Reserved -> Aborted
//!
//! A durable Reserved entry left behind after a crash is surfaced as
//! DeliveryUnknown and can never be reused automatically. A durable issued
//! receipt is explicitly idempotent: the same nonce plus binding returns the
//! retained bytes rather than minting a second receipt.
//!
//! The journal is single-owner: one daemon process should own a given path.
//! In-process clones share one mutex. The on-disk format is a checksummed,
//! append-only write-ahead journal; malformed or truncated state fails closed
//! rather than being repaired or truncated.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use thiserror::Error;

/// Current durable issuance-journal format version.
pub const ISSUANCE_JOURNAL_VERSION_V1: u16 = 1;
/// Domain separator for all v1 journal records.
pub const ISSUANCE_JOURNAL_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-issuance-journal-v1\0";
/// Maximum retained signed-receipt byte length.
pub const MAX_RETAINED_RECEIPT_BYTES_V1: usize = 1024 * 1024;
/// Maximum number of permanently remembered issuance nonces.
pub const MAX_ISSUANCE_ENTRIES_V1: usize = 1_000_000;

const NONCE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const CHECKSUM_LEN: usize = 32;
const FIXED_PREFIX_LEN: usize =
    ISSUANCE_JOURNAL_DOMAIN_V1.len() + 2 + 1 + NONCE_LEN + DIGEST_LEN + 4;

/// Outcome of reserving a request nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// The nonce was durably reserved for this exact binding and may proceed.
    Reserved,
    /// The exact nonce and binding already produced a durable receipt.
    AlreadyIssued {
        /// Exact previously retained signed-receipt bytes.
        receipt: Vec<u8>,
    },
    /// A durable reservation exists but no terminal issuance outcome is known.
    DeliveryUnknown,
    /// The nonce was durably marked aborted and is permanently unusable.
    Aborted,
}

/// Fail-closed errors from the durable issuance boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IssuanceJournalError {
    /// The journal path does not exist when opening an existing journal.
    #[error("issuance journal is missing")]
    JournalMissing,
    /// A new journal was requested over an existing path.
    #[error("issuance journal already exists")]
    JournalAlreadyExists,
    /// Journal bytes do not match the fixed v1 framing.
    #[error("issuance journal is malformed")]
    MalformedJournal,
    /// A record checksum does not match its exact bytes.
    #[error("issuance journal checksum mismatch")]
    ChecksumMismatch,
    /// Journal record format version is unsupported.
    #[error("unsupported issuance journal version {0}")]
    UnsupportedVersion(u16),
    /// The request nonce was all zero.
    #[error("issuance request nonce must not be all zero")]
    ZeroNonce,
    /// The request-binding digest was all zero.
    #[error("issuance request binding digest must not be all zero")]
    ZeroBindingDigest,
    /// A retained receipt exceeded the frozen v1 bound.
    #[error("retained signed receipt exceeds the v1 size bound")]
    ReceiptTooLarge,
    /// The journal has reached its permanent v1 nonce-retention bound.
    #[error("issuance journal nonce capacity exhausted")]
    CapacityExhausted,
    /// The nonce was already used for a different request binding.
    #[error("issuance request nonce is bound to different request material")]
    NonceBindingMismatch,
    /// A state transition was attempted from a terminal or absent state.
    #[error("invalid issuance journal state transition")]
    InvalidTransition,
    /// The journal file could not be durably read or written.
    #[error("issuance journal I/O failure: {0}")]
    Io(String),
    /// The caller attempted to mark a reservation with the wrong binding.
    #[error("issuance reservation binding does not match")]
    ReservationBindingMismatch,
    /// Another process already owns the journal's exclusive writer lock.
    #[error("issuance journal is already owned by another process")]
    JournalBusy,
    /// The configured journal parent is not a trusted private storage root.
    #[error("issuance journal storage root is not trusted")]
    StorageRootUntrusted,
    /// The journal path no longer resolves to the object owned by this instance.
    #[error("issuance journal storage object identity changed")]
    StorageIdentityMismatch,
    /// The journal storage identity could not be established or rechecked.
    #[error("issuance journal storage identity failure: {0}")]
    StorageIdentityUnavailable(String),
    /// A prior storage-identity failure permanently poisoned this journal owner.
    #[error("issuance journal storage identity is poisoned")]
    StorageIdentityPoisoned,
    /// A prior write failed after the journal may have been partially changed.
    #[error("issuance journal is poisoned after a persistence failure")]
    JournalPoisoned,
}

/// Durable exclusive owner of the issuance journal.
///
/// Clones share the same in-process state lock and the same OS file handle.
/// The handle holds the exclusive journal lock for the lifetime of the
/// journal, so a second daemon process cannot admit the same journal path.
///
/// All durable appends use this already-locked handle. Reopening the path for
/// individual writes would defeat the ownership theorem because filesystem
/// locks are attached to file handles, not to the path string.
#[derive(Clone, Debug)]
pub struct IssuanceJournal {
    file: Arc<File>,
    path: PathBuf,
    identity: FileIdentity,
    storage_identity_poisoned: Arc<AtomicBool>,
    state: Arc<Mutex<JournalState>>,
}

#[derive(Debug, Default)]
struct JournalState {
    entries: BTreeMap<[u8; NONCE_LEN], JournalEntry>,
    poisoned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalEntry {
    binding_digest: [u8; DIGEST_LEN],
    state: JournalEntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum JournalEntryState {
    Reserved,
    Issued { receipt: Vec<u8> },
    Aborted,
}

impl IssuanceJournal {
    /// Create a new empty journal. Existing files are never silently reused.
    pub fn bootstrap_new(path: impl AsRef<Path>) -> Result<Self, IssuanceJournalError> {
        let path = path.as_ref().to_path_buf();
        validate_storage_root(&path)?;
        let mut options = secure_open_options();
        options.read(true).append(true).create_new(true);
        let file = options
            .open(&path)
            .map_err(|error| match error.kind() {
                ErrorKind::AlreadyExists => IssuanceJournalError::JournalAlreadyExists,
                _ => IssuanceJournalError::Io(error.to_string()),
            })?;

        acquire_exclusive_lock(&file)?;
        sync_parent_directory(&path)?;
        let canonical_path = canonicalize_journal_path(&path)?;
        validate_storage_root(&canonical_path)?;
        let identity = capture_identity(&file)?;
        ensure_path_identity(&canonical_path, &identity)?;
        Ok(Self {
            file: Arc::new(file),
            path: canonical_path,
            identity,
            storage_identity_poisoned: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(JournalState::default())),
        })
    }

    /// Open and fully validate an existing journal.
    ///
    /// Every record is replayed in order. Any malformed, truncated, unknown,
    /// or impossible transition fails closed.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, IssuanceJournalError> {
        let path = path.as_ref().to_path_buf();
        validate_storage_root(&path)?;
        let canonical_path = canonicalize_journal_path(&path)?;
        validate_storage_root(&canonical_path)?;
        let mut options = secure_open_options();
        options.read(true).append(true);
        let mut file = options.open(&path).map_err(|error| match error.kind() {
            ErrorKind::NotFound => IssuanceJournalError::JournalMissing,
            _ => IssuanceJournalError::Io(error.to_string()),
        })?;

        acquire_exclusive_lock(&file)?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| IssuanceJournalError::Io(error.to_string()))?;

        let identity = capture_identity(&file)?;
        ensure_path_identity(&canonical_path, &identity)?;
        let state = decode_journal(&bytes)?;
        Ok(Self {
            file: Arc::new(file),
            path: canonical_path,
            identity,
            storage_identity_poisoned: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Reserve one nonzero request nonce for one exact request-binding digest.
    ///
    /// The reservation is fsync'd before Reserved is returned. If the process
    /// crashes after this point but before a terminal outcome is durable,
    /// restart observes DeliveryUnknown and refuses to mint another receipt.
    pub fn reserve(
        &self,
        nonce: [u8; NONCE_LEN],
        binding_digest: [u8; DIGEST_LEN],
    ) -> Result<ReserveOutcome, IssuanceJournalError> {
        validate_nonce_and_binding(&nonce, &binding_digest)?;
        self.ensure_storage_identity()?;

        let mut state = self.lock_state()?;
        ensure_healthy(&state)?;

        if let Some(entry) = state.entries.get(&nonce) {
            if entry.binding_digest != binding_digest {
                return Err(IssuanceJournalError::NonceBindingMismatch);
            }
            return Ok(match &entry.state {
                JournalEntryState::Reserved => ReserveOutcome::DeliveryUnknown,
                JournalEntryState::Issued { receipt } => ReserveOutcome::AlreadyIssued {
                    receipt: receipt.clone(),
                },
                JournalEntryState::Aborted => ReserveOutcome::Aborted,
            });
        }

        if state.entries.len() >= MAX_ISSUANCE_ENTRIES_V1 {
            return Err(IssuanceJournalError::CapacityExhausted);
        }

        let record = encode_record(
            JournalRecordState::Reserved,
            nonce,
            binding_digest,
            &[],
        )?;
        self.ensure_storage_identity()?;
        if let Err(error) = append_and_sync(&self.file, &record) {
            state.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.ensure_storage_identity() {
            state.poisoned = true;
            return Err(error);
        }
        state.entries.insert(
            nonce,
            JournalEntry {
                binding_digest,
                state: JournalEntryState::Reserved,
            },
        );
        Ok(ReserveOutcome::Reserved)
    }

    /// Durably record the exact opaque signed-receipt bytes for a reserved nonce.
    ///
    /// This is the explicit v1 idempotency point. Once it succeeds, the same
    /// nonce and binding can return these exact bytes after a restart.
    pub fn record_issued(
        &self,
        nonce: [u8; NONCE_LEN],
        binding_digest: [u8; DIGEST_LEN],
        receipt: &[u8],
    ) -> Result<(), IssuanceJournalError> {
        validate_nonce_and_binding(&nonce, &binding_digest)?;
        self.ensure_storage_identity()?;
        if receipt.is_empty() {
            return Err(IssuanceJournalError::MalformedJournal);
        }
        if receipt.len() > MAX_RETAINED_RECEIPT_BYTES_V1 {
            return Err(IssuanceJournalError::ReceiptTooLarge);
        }

        let mut state = self.lock_state()?;
        ensure_healthy(&state)?;

        let entry = state
            .entries
            .get(&nonce)
            .ok_or(IssuanceJournalError::InvalidTransition)?;
        if entry.binding_digest != binding_digest {
            return Err(IssuanceJournalError::ReservationBindingMismatch);
        }
        if !matches!(entry.state, JournalEntryState::Reserved) {
            return Err(IssuanceJournalError::InvalidTransition);
        }

        let record = encode_record(
            JournalRecordState::Issued,
            nonce,
            binding_digest,
            receipt,
        )?;
        self.ensure_storage_identity()?;
        if let Err(error) = append_and_sync(&self.file, &record) {
            state.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.ensure_storage_identity() {
            state.poisoned = true;
            return Err(error);
        }

        if let Some(entry) = state.entries.get_mut(&nonce) {
            entry.state = JournalEntryState::Issued {
                receipt: receipt.to_vec(),
            };
        }
        Ok(())
    }

    /// Durably mark a reserved nonce aborted. The nonce remains terminal and
    /// can never be reused for a later positive issuance.
    pub fn record_aborted(
        &self,
        nonce: [u8; NONCE_LEN],
        binding_digest: [u8; DIGEST_LEN],
    ) -> Result<(), IssuanceJournalError> {
        validate_nonce_and_binding(&nonce, &binding_digest)?;
        self.ensure_storage_identity()?;

        let mut state = self.lock_state()?;
        ensure_healthy(&state)?;

        let entry = state
            .entries
            .get(&nonce)
            .ok_or(IssuanceJournalError::InvalidTransition)?;
        if entry.binding_digest != binding_digest {
            return Err(IssuanceJournalError::ReservationBindingMismatch);
        }
        if !matches!(entry.state, JournalEntryState::Reserved) {
            return Err(IssuanceJournalError::InvalidTransition);
        }

        let record =
            encode_record(JournalRecordState::Aborted, nonce, binding_digest, &[])?;
        self.ensure_storage_identity()?;
        if let Err(error) = append_and_sync(&self.file, &record) {
            state.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.ensure_storage_identity() {
            state.poisoned = true;
            return Err(error);
        }

        if let Some(entry) = state.entries.get_mut(&nonce) {
            entry.state = JournalEntryState::Aborted;
        }
        Ok(())
    }

    /// Return the current durable state for one nonce, if present.
    pub fn reserve_status(
        &self,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Option<ReserveOutcome>, IssuanceJournalError> {
        if *nonce == [0; NONCE_LEN] {
            return Err(IssuanceJournalError::ZeroNonce);
        }
        self.ensure_storage_identity()?;
        let state = self.lock_state()?;
        ensure_healthy(&state)?;
        Ok(state.entries.get(nonce).map(|entry| match &entry.state {
            JournalEntryState::Reserved => ReserveOutcome::DeliveryUnknown,
            JournalEntryState::Issued { receipt } => ReserveOutcome::AlreadyIssued {
                receipt: receipt.clone(),
            },
            JournalEntryState::Aborted => ReserveOutcome::Aborted,
        }))
    }

    /// Number of permanently retained request nonces.
    pub fn len(&self) -> Result<usize, IssuanceJournalError> {
        self.ensure_storage_identity()?;
        let state = self.lock_state()?;
        ensure_healthy(&state)?;
        Ok(state.entries.len())
    }

    /// Whether no request nonce has yet been recorded.
    pub fn is_empty(&self) -> Result<bool, IssuanceJournalError> {
        Ok(self.len()? == 0)
    }

    fn ensure_storage_identity(&self) -> Result<(), IssuanceJournalError> {
        if self
            .storage_identity_poisoned
            .load(Ordering::Acquire)
        {
            return Err(IssuanceJournalError::StorageIdentityPoisoned);
        }

        match ensure_path_identity(&self.path, &self.identity) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.storage_identity_poisoned.store(true, Ordering::Release);
                Err(error)
            }
        }
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, JournalState>, IssuanceJournalError> {
        self.state
            .lock()
            .map_err(|_| IssuanceJournalError::Io("issuance journal lock poisoned".into()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalRecordState {
    Reserved = 1,
    Issued = 2,
    Aborted = 3,
}

fn ensure_healthy(state: &JournalState) -> Result<(), IssuanceJournalError> {
    if state.poisoned {
        Err(IssuanceJournalError::JournalPoisoned)
    } else {
        Ok(())
    }
}

fn validate_nonce_and_binding(
    nonce: &[u8; NONCE_LEN],
    binding_digest: &[u8; DIGEST_LEN],
) -> Result<(), IssuanceJournalError> {
    if *nonce == [0; NONCE_LEN] {
        return Err(IssuanceJournalError::ZeroNonce);
    }
    if *binding_digest == [0; DIGEST_LEN] {
        return Err(IssuanceJournalError::ZeroBindingDigest);
    }
    Ok(())
}

fn encode_record(
    state: JournalRecordState,
    nonce: [u8; NONCE_LEN],
    binding_digest: [u8; DIGEST_LEN],
    receipt: &[u8],
) -> Result<Vec<u8>, IssuanceJournalError> {
    if receipt.len() > MAX_RETAINED_RECEIPT_BYTES_V1 {
        return Err(IssuanceJournalError::ReceiptTooLarge);
    }
    if state != JournalRecordState::Issued && !receipt.is_empty() {
        return Err(IssuanceJournalError::MalformedJournal);
    }

    let receipt_len =
        u32::try_from(receipt.len()).map_err(|_| IssuanceJournalError::ReceiptTooLarge)?;

    let mut out = Vec::with_capacity(FIXED_PREFIX_LEN + receipt.len() + CHECKSUM_LEN);
    out.extend_from_slice(ISSUANCE_JOURNAL_DOMAIN_V1);
    out.extend_from_slice(&ISSUANCE_JOURNAL_VERSION_V1.to_be_bytes());
    out.push(state as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&binding_digest);
    out.extend_from_slice(&receipt_len.to_be_bytes());
    out.extend_from_slice(receipt);
    let checksum: [u8; CHECKSUM_LEN] = Sha256::digest(&out).into();
    out.extend_from_slice(&checksum);
    Ok(out)
}

fn decode_journal(bytes: &[u8]) -> Result<JournalState, IssuanceJournalError> {
    let mut state = JournalState::default();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if bytes.len() - offset < FIXED_PREFIX_LEN + CHECKSUM_LEN {
            return Err(IssuanceJournalError::MalformedJournal);
        }

        let prefix_end = offset + FIXED_PREFIX_LEN;
        if !bytes[offset..prefix_end].starts_with(ISSUANCE_JOURNAL_DOMAIN_V1) {
            return Err(IssuanceJournalError::MalformedJournal);
        }

        let mut cursor = offset + ISSUANCE_JOURNAL_DOMAIN_V1.len();
        let version = u16::from_be_bytes(
            bytes[cursor..cursor + 2]
                .try_into()
                .map_err(|_| IssuanceJournalError::MalformedJournal)?,
        );
        cursor += 2;
        if version != ISSUANCE_JOURNAL_VERSION_V1 {
            return Err(IssuanceJournalError::UnsupportedVersion(version));
        }

        let record_state = match bytes[cursor] {
            1 => JournalRecordState::Reserved,
            2 => JournalRecordState::Issued,
            3 => JournalRecordState::Aborted,
            _ => return Err(IssuanceJournalError::MalformedJournal),
        };
        cursor += 1;

        let nonce: [u8; NONCE_LEN] = bytes[cursor..cursor + NONCE_LEN]
            .try_into()
            .map_err(|_| IssuanceJournalError::MalformedJournal)?;
        cursor += NONCE_LEN;
        let binding_digest: [u8; DIGEST_LEN] =
            bytes[cursor..cursor + DIGEST_LEN]
                .try_into()
                .map_err(|_| IssuanceJournalError::MalformedJournal)?;
        cursor += DIGEST_LEN;

        validate_nonce_and_binding(&nonce, &binding_digest)?;

        let receipt_len = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| IssuanceJournalError::MalformedJournal)?,
        ) as usize;
        cursor += 4;
        if receipt_len > MAX_RETAINED_RECEIPT_BYTES_V1 {
            return Err(IssuanceJournalError::ReceiptTooLarge);
        }
        if record_state != JournalRecordState::Issued && receipt_len != 0 {
            return Err(IssuanceJournalError::MalformedJournal);
        }

        let receipt_end = cursor
            .checked_add(receipt_len)
            .ok_or(IssuanceJournalError::MalformedJournal)?;
        let checksum_end = receipt_end
            .checked_add(CHECKSUM_LEN)
            .ok_or(IssuanceJournalError::MalformedJournal)?;
        if checksum_end > bytes.len() {
            return Err(IssuanceJournalError::MalformedJournal);
        }

        let expected_checksum: [u8; CHECKSUM_LEN] =
            Sha256::digest(&bytes[offset..receipt_end]).into();
        if bytes[receipt_end..checksum_end] != expected_checksum {
            return Err(IssuanceJournalError::ChecksumMismatch);
        }

        apply_record(
            &mut state,
            nonce,
            binding_digest,
            record_state,
            bytes[cursor..receipt_end].to_vec(),
        )?;
        offset = checksum_end;
    }

    Ok(state)
}

fn apply_record(
    state: &mut JournalState,
    nonce: [u8; NONCE_LEN],
    binding_digest: [u8; DIGEST_LEN],
    record_state: JournalRecordState,
    receipt: Vec<u8>,
) -> Result<(), IssuanceJournalError> {
    if let Some(existing) = state.entries.get(&nonce) {
        if existing.binding_digest != binding_digest {
            return Err(IssuanceJournalError::NonceBindingMismatch);
        }
        match (&existing.state, record_state) {
            (JournalEntryState::Reserved, JournalRecordState::Issued) => {}
            (JournalEntryState::Reserved, JournalRecordState::Aborted) => {}
            _ => return Err(IssuanceJournalError::InvalidTransition),
        }
    } else {
        if state.entries.len() >= MAX_ISSUANCE_ENTRIES_V1 {
            return Err(IssuanceJournalError::CapacityExhausted);
        }
        if record_state != JournalRecordState::Reserved {
            return Err(IssuanceJournalError::InvalidTransition);
        }
    }

    let next_state = match record_state {
        JournalRecordState::Reserved => JournalEntryState::Reserved,
        JournalRecordState::Issued => {
            if receipt.is_empty() {
                return Err(IssuanceJournalError::MalformedJournal);
            }
            JournalEntryState::Issued { receipt }
        }
        JournalRecordState::Aborted => {
            if !receipt.is_empty() {
                return Err(IssuanceJournalError::MalformedJournal);
            }
            JournalEntryState::Aborted
        }
    };

    state.entries.insert(
        nonce,
        JournalEntry {
            binding_digest,
            state: next_state,
        },
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_index: u64,
}

fn canonicalize_journal_path(path: &Path) -> Result<PathBuf, IssuanceJournalError> {
    fs::canonicalize(path)
        .map_err(|error| IssuanceJournalError::StorageIdentityUnavailable(error.to_string()))
}

fn validate_storage_root(path: &Path) -> Result<(), IssuanceJournalError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| IssuanceJournalError::StorageIdentityUnavailable(error.to_string()))?;
    if !metadata.is_dir() {
        return Err(IssuanceJournalError::StorageRootUntrusted);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(IssuanceJournalError::StorageRootUntrusted);
        }
    }

    Ok(())
}

fn capture_identity(file: &File) -> Result<FileIdentity, IssuanceJournalError> {
    let metadata = file
        .metadata()
        .map_err(|error| IssuanceJournalError::StorageIdentityUnavailable(error.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    #[cfg(windows)]
    {
        let info = winapi_util::file::information(file)
            .map_err(|error| IssuanceJournalError::StorageIdentityUnavailable(error.to_string()))?;
        Ok(FileIdentity {
            volume_serial: info.volume_serial_number(),
            file_index: info.file_index(),
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(IssuanceJournalError::StorageIdentityUnavailable(
            "stable storage-object identity is unsupported on this target".into(),
        ))
    }
}

fn ensure_path_identity(
    path: &Path,
    expected: &FileIdentity,
) -> Result<(), IssuanceJournalError> {
    let file = File::open(path)
        .map_err(|error| IssuanceJournalError::StorageIdentityUnavailable(error.to_string()))?;
    let current = capture_identity(&file)?;
    if current == *expected {
        Ok(())
    } else {
        Err(IssuanceJournalError::StorageIdentityMismatch)
    }
}

fn acquire_exclusive_lock(file: &File) -> Result<(), IssuanceJournalError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(IssuanceJournalError::JournalBusy),
        Err(TryLockError::Error(error)) => {
            Err(IssuanceJournalError::Io(error.to_string()))
        }
    }
}

fn append_and_sync(file: &File, record: &[u8]) -> Result<(), IssuanceJournalError> {
    file.write_all(record)
        .map_err(|error| IssuanceJournalError::Io(error.to_string()))?;
    file.sync_all()
        .map_err(|error| IssuanceJournalError::Io(error.to_string()))?;
    Ok(())
}

fn secure_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn sync_parent_directory(path: &Path) -> Result<(), IssuanceJournalError> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| IssuanceJournalError::Io("invalid journal path".into()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| IssuanceJournalError::Io(error.to_string()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("issuance-journal-v1.bin")
    }

    fn nonce(byte: u8) -> [u8; NONCE_LEN] {
        [byte; NONCE_LEN]
    }

    fn binding(byte: u8) -> [u8; DIGEST_LEN] {
        [byte; DIGEST_LEN]
    }

    #[test]
    fn bootstrap_is_explicit_and_restart_preserves_terminal_state() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();

        assert_eq!(
            journal.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Reserved
        );
        journal.record_aborted(nonce(1), binding(2)).unwrap();
        drop(journal);

        let reopened = IssuanceJournal::open_existing(path(&dir)).unwrap();
        assert_eq!(
            reopened.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Aborted
        );
        assert_eq!(reopened.len().unwrap(), 1);
    }

    #[test]
    fn issued_receipt_is_explicitly_idempotent_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        let receipt = b"signed-receipt-v1";
        assert_eq!(
            journal.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Reserved
        );
        journal.record_issued(nonce(1), binding(2), receipt).unwrap();
        drop(journal);

        let reopened = IssuanceJournal::open_existing(path(&dir)).unwrap();
        assert_eq!(
            reopened.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::AlreadyIssued {
                receipt: receipt.to_vec()
            }
        );
    }

    #[test]
    fn unresolved_reservation_is_delivery_unknown_and_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        assert_eq!(
            journal.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Reserved
        );
        drop(journal);

        let reopened = IssuanceJournal::open_existing(path(&dir)).unwrap();
        assert_eq!(
            reopened.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::DeliveryUnknown
        );
        assert_eq!(
            reopened.record_issued(nonce(1), binding(2), b"late").unwrap_err(),
            IssuanceJournalError::InvalidTransition
        );
    }

    #[test]
    fn nonce_cannot_be_transplanted_to_different_binding() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        assert_eq!(
            journal.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Reserved
        );
        assert_eq!(
            journal.reserve(nonce(1), binding(3)).unwrap_err(),
            IssuanceJournalError::NonceBindingMismatch
        );
    }

    #[test]
    fn aborted_is_terminal_and_signer_failure_can_be_made_non_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        journal.reserve(nonce(1), binding(2)).unwrap();
        journal.record_aborted(nonce(1), binding(2)).unwrap();

        assert_eq!(
            journal.reserve(nonce(1), binding(2)).unwrap(),
            ReserveOutcome::Aborted
        );
        assert_eq!(
            journal.record_issued(nonce(1), binding(2), b"receipt").unwrap_err(),
            IssuanceJournalError::InvalidTransition
        );
    }

    #[test]
    fn zero_sentinels_and_oversized_receipts_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        assert_eq!(
            journal.reserve([0; NONCE_LEN], binding(2)).unwrap_err(),
            IssuanceJournalError::ZeroNonce
        );
        assert_eq!(
            journal.reserve(nonce(1), [0; DIGEST_LEN]).unwrap_err(),
            IssuanceJournalError::ZeroBindingDigest
        );
        let oversized = vec![0xAA; MAX_RETAINED_RECEIPT_BYTES_V1 + 1];
        journal.reserve(nonce(1), binding(2)).unwrap();
        assert_eq!(
            journal
                .record_issued(nonce(1), binding(2), &oversized)
                .unwrap_err(),
            IssuanceJournalError::ReceiptTooLarge
        );
    }

    #[test]
    fn corruption_checksum_and_truncation_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        journal.reserve(nonce(1), binding(2)).unwrap();
        drop(journal);

        let mut bytes = std::fs::read(path(&dir)).unwrap();
        bytes[bytes.len() - 1] ^= 1;
        std::fs::write(path(&dir), &bytes).unwrap();
        assert_eq!(
            IssuanceJournal::open_existing(path(&dir)).unwrap_err(),
            IssuanceJournalError::ChecksumMismatch
        );

        let clean_path = dir.path().join("clean.bin");
        let clean = IssuanceJournal::bootstrap_new(&clean_path).unwrap();
        clean.reserve(nonce(3), binding(4)).unwrap();
        drop(clean);
        let mut bytes = std::fs::read(&clean_path).unwrap();
        bytes.pop();
        std::fs::write(&clean_path, bytes).unwrap();
        assert_eq!(
            IssuanceJournal::open_existing(&clean_path).unwrap_err(),
            IssuanceJournalError::MalformedJournal
        );
    }

    #[test]
    fn unsupported_version_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        journal.reserve(nonce(1), binding(2)).unwrap();
        drop(journal);

        let mut bytes = std::fs::read(path(&dir)).unwrap();
        let version_offset = ISSUANCE_JOURNAL_DOMAIN_V1.len();
        bytes[version_offset..version_offset + 2].copy_from_slice(&99u16.to_be_bytes());
        std::fs::write(path(&dir), &bytes).unwrap();

        assert_eq!(
            IssuanceJournal::open_existing(path(&dir)).unwrap_err(),
            IssuanceJournalError::UnsupportedVersion(99)
        );
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_creates_private_journal_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let journal_path = path(&dir);
        IssuanceJournal::bootstrap_new(&journal_path).unwrap();
        let mode = std::fs::metadata(journal_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn second_process_owner_is_rejected_before_state_admission() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();
        journal.reserve(nonce(1), binding(2)).unwrap();

        assert_eq!(
            IssuanceJournal::open_existing(path(&dir)).unwrap_err(),
            IssuanceJournalError::JournalBusy
        );
        assert_eq!(journal.len().unwrap(), 1);
    }



    #[test]
    fn repeated_durable_writes_preserve_storage_identity() {
        let dir = tempfile::tempdir().unwrap();
        let journal = IssuanceJournal::bootstrap_new(path(&dir)).unwrap();

        journal.reserve(nonce(7), binding(8)).unwrap();
        journal.record_issued(nonce(7), binding(8), b"stable-receipt").unwrap();

        assert_eq!(
            journal.reserve(nonce(7), binding(8)).unwrap(),
            ReserveOutcome::AlreadyIssued {
                receipt: b"stable-receipt".to_vec()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_replacement_fails_closed_for_live_owner() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = path(&dir);
        let journal = IssuanceJournal::bootstrap_new(&journal_path).unwrap();
        journal.reserve(nonce(1), binding(2)).unwrap();

        let moved_path = dir.path().join("moved.bin");
        std::fs::rename(&journal_path, &moved_path).unwrap();
        std::fs::write(&journal_path, b"replacement").unwrap();

        assert_eq!(
            journal.reserve(nonce(3), binding(4)).unwrap_err(),
            IssuanceJournalError::StorageIdentityMismatch
        );

        std::fs::remove_file(&journal_path).unwrap();
        std::fs::rename(&moved_path, &journal_path).unwrap();

        assert_eq!(
            journal.len().unwrap_err(),
            IssuanceJournalError::StorageIdentityPoisoned
        );
    }

    #[cfg(unix)]
    #[test]
    fn writable_storage_root_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(dir.path(), permissions).unwrap();

        assert_eq!(
            IssuanceJournal::bootstrap_new(path(&dir)).unwrap_err(),
            IssuanceJournalError::StorageRootUntrusted
        );
    }


    #[test]
    fn concurrent_clones_serialize_reservations() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let journal = Arc::new(IssuanceJournal::bootstrap_new(path(&dir)).unwrap());
        let a = journal.clone();
        let b = journal.clone();

        let left = thread::spawn(move || a.reserve(nonce(9), binding(9)).unwrap());
        let right = thread::spawn(move || b.reserve(nonce(9), binding(9)).unwrap());
        let mut outcomes = vec![left.join().unwrap(), right.join().unwrap()];
        outcomes.sort_by_key(|outcome| match outcome {
            ReserveOutcome::Reserved => 0,
            ReserveOutcome::DeliveryUnknown => 1,
            ReserveOutcome::AlreadyIssued { .. } => 2,
            ReserveOutcome::Aborted => 3,
        });
        assert_eq!(outcomes[0], ReserveOutcome::Reserved);
        assert_eq!(outcomes[1], ReserveOutcome::DeliveryUnknown);
    }
}
