// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash-recovery journal for exact effectuation attempts.
//!
//! The journal makes lifecycle intent durable, but it does not make an external
//! OS/backend call transactional. Every state change is length-prefixed,
//! validated, written, and followed by sync_data. Recovery fails closed on a
//! truncated or malformed record instead of silently discarding an uncertain
//! suffix.
//!
//! The journal records only exact attempt/receipt material. It cannot be
//! deserialized into authority and it does not decide the external outcome.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    FINALITY_ATTEMPT_SCHEMA, FINALITY_RECEIPT_SCHEMA, FinalityAttemptError,
    FinalityAttemptStateV1, FinalityAttemptV1, FinalityOutcomeV1, FinalityReceiptV1,
};

/// Stable schema for the journal stream.
pub const FINALITY_JOURNAL_SCHEMA: &str = "xenia-finality-journal-v2";

const MAX_JOURNAL_RECORD_BYTES: u32 = 64 * 1024;
const JOURNAL_MAGIC: &[u8; 8] = b"XNFJ0002";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FinalityJournalRecordV1 {
    Attempt(FinalityAttemptV1),
    Receipt(FinalityReceiptV1),
}

/// Single-owner append-only finality journal.
///
/// Opening atomically claims a sibling `.lock` directory. A live process therefore
/// refuses a second owner, including a second process that has independently
/// reconstructed an empty in-memory fence. A stale lock is intentionally not
/// guessed about: operators must reconcile/remove it after establishing that
/// the prior owner is gone.
pub struct FinalityJournalV1 {
    path: PathBuf,
    file: File,
    _lock: FinalityJournalLockV1,
    initialized: bool,
    latest: BTreeMap<[u8; 16], FinalityAttemptV1>,
    receipts: BTreeMap<[u8; 16], FinalityReceiptV1>,
    consumed_handles: BTreeMap<[u8; 32], [u8; 16]>,
    occupied_actions: BTreeMap<[u8; 32], [u8; 16]>,
}

struct FinalityJournalLockV1 {
    dir: PathBuf,
    owner: PathBuf,
}

impl Drop for FinalityJournalLockV1 {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.owner);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Errors raised while opening, validating, or appending the durable finality journal.
#[derive(Debug, Error)]
pub enum FinalityJournalError {
    /// Filesystem access failed.
    #[error("finality journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A length-delimited record could not be decoded completely.
    #[error("finality journal record is malformed")]
    MalformedRecord,
    /// A record exceeded the parser's hard size ceiling.
    #[error("finality journal record exceeds parser ceiling")]
    RecordTooLarge,
    /// A stored attempt or receipt used an unsupported schema.
    #[error("unsupported finality journal schema")]
    UnsupportedJournalSchema,
    #[error("finality attempt is invalid: {0}")]
    Attempt(#[from] FinalityAttemptError),
    /// An attempt identifier was reused with different exact act/sink identity.
    #[error("finality attempt identity changed for an existing attempt")]
    AttemptIdentityMismatch,
    /// A stored lifecycle state did not follow the previous durable state.
    #[error("invalid finality journal lifecycle transition")]
    InvalidLifecycleTransition,
    /// A receipt did not match the exact latest attempt material.
    #[error("finality receipt does not match the exact attempt")]
    ReceiptMismatch,
    /// A receipt outcome did not match the corresponding terminal state.
    #[error("finality receipt outcome does not match the attempt state")]
    ReceiptOutcomeMismatch,
    /// Another live journal owner already holds the sibling lock.
    #[error("finality journal is already owned by another process")]
    JournalAlreadyOwned,
    /// A different attempt already occupies the same semantic action key.
    #[error("exact action is already durably in flight or closed")]
    ActionAlreadyFenced {
        /// Semantic action identity protected by the fence.
        action_key_digest: [u8; 32],
        /// Attempt currently occupying the action key.
        existing_attempt_id: [u8; 16],
    },
    /// An already-consumed exact handle was presented under a different attempt.
    #[error("exact execution handle was already durably consumed by another attempt")]
    HandleAlreadyConsumed {
        /// Exact handle identity that was already consumed.
        handle_digest: [u8; 32],
        /// Attempt that durably consumed the handle first.
        existing_attempt_id: [u8; 16],
    },
}

impl FinalityJournalV1 {
    /// Open or create the journal and replay every existing record.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FinalityJournalError> {
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path_for(&path);
        std::fs::create_dir(&lock_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                FinalityJournalError::JournalAlreadyOwned
            } else {
                FinalityJournalError::Io(error)
            }
        })?;

        let owner_path = lock_path.join("owner");
        let mut lock = FinalityJournalLockV1 {
            dir: lock_path,
            owner: owner_path,
        };
        let mut owner_file = File::create(&lock.owner)?;
        let mut owner = format!("pid={}", std::process::id());
        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            owner.push_str(&format!(" opened_at_unix_s={}", now.as_secs()));
        }
        owner_file.write_all(owner.as_bytes())?;
        owner_file.sync_all()?;

        let mut reader = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let (initialized, record_bytes) = split_journal_header(&bytes)?;
        let (latest, receipts) = replay_journal_bytes(record_bytes)?;
        let consumed_handles = consumed_handle_index(&latest)?;
        let occupied_actions = occupied_action_index(&latest)?;

        Ok(Self {
            path,
            file: reader,
            _lock: lock,
            initialized,
            latest,
            receipts,
            consumed_handles,
            occupied_actions,
        })
    }

    /// Return the filesystem path owned by this journal.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the latest durable lifecycle state for an exact attempt identifier.
    pub fn latest_attempt(&self, attempt_id: [u8; 16]) -> Option<&FinalityAttemptV1> {
        self.latest.get(&attempt_id)
    }

    /// Durably append a lifecycle state after enforcing exact identity and single-use handle fencing.
    pub fn append_attempt(
        &mut self,
        attempt: &FinalityAttemptV1,
    ) -> Result<(), FinalityJournalError> {
        attempt.validate()?;

        if let Some(existing_attempt_id) = self.consumed_handles.get(&attempt.handle_digest) {
            if existing_attempt_id != &attempt.attempt_id {
                return Err(FinalityJournalError::HandleAlreadyConsumed {
                    handle_digest: attempt.handle_digest,
                    existing_attempt_id: *existing_attempt_id,
                });
            }
        }

        if let Some(existing_attempt_id) = self.occupied_actions.get(&attempt.action_key_digest) {
            if existing_attempt_id != &attempt.attempt_id {
                return Err(FinalityJournalError::ActionAlreadyFenced {
                    action_key_digest: attempt.action_key_digest,
                    existing_attempt_id: *existing_attempt_id,
                });
            }
        }

        if let Some(previous) = self.latest.get(&attempt.attempt_id) {
            if previous.handle_digest != attempt.handle_digest
                || previous.action_key_digest != attempt.action_key_digest
                || previous.act_digest != attempt.act_digest
                || previous.sink_digest != attempt.sink_digest
            {
                return Err(FinalityJournalError::AttemptIdentityMismatch);
            }
            if !valid_lifecycle_transition(previous.state, attempt.state) {
                return Err(FinalityJournalError::InvalidLifecycleTransition);
            }
        }

        self.append_record(&FinalityJournalRecordV1::Attempt(attempt.clone()))?;
        if !matches!(attempt.state, FinalityAttemptStateV1::Prepared) {
            self.consumed_handles.insert(attempt.handle_digest, attempt.attempt_id);
        }
        match attempt.state {
            FinalityAttemptStateV1::EffectuationStarted
            | FinalityAttemptStateV1::Committed
            | FinalityAttemptStateV1::Indeterminate => {
                self.occupied_actions.insert(attempt.action_key_digest, attempt.attempt_id);
            }
            FinalityAttemptStateV1::Prepared => {}
            FinalityAttemptStateV1::Denied => {
                self.occupied_actions.remove(&attempt.action_key_digest);
            }
        }
        self.latest.insert(attempt.attempt_id, attempt.clone());
        Ok(())
    }

    /// Durably append a receipt that exactly matches the current terminal/indeterminate state.
    pub fn append_receipt(
        &mut self,
        receipt: &FinalityReceiptV1,
    ) -> Result<(), FinalityJournalError> {
        receipt.validate()?;
        let Some(attempt) = self.latest.get(&receipt.attempt_id) else {
            return Err(FinalityJournalError::ReceiptMismatch);
        };

        if receipt.handle_digest != attempt.handle_digest
            || receipt.action_key_digest != attempt.action_key_digest
            || receipt.act_digest != attempt.act_digest
            || receipt.sink_digest != attempt.sink_digest
            || receipt.attempt_digest != attempt.digest()
        {
            return Err(FinalityJournalError::ReceiptMismatch);
        }

        let expected_outcome = match attempt.state {
            FinalityAttemptStateV1::Committed => FinalityOutcomeV1::Committed,
            FinalityAttemptStateV1::Denied => FinalityOutcomeV1::Denied,
            FinalityAttemptStateV1::Indeterminate => FinalityOutcomeV1::Indeterminate,
            FinalityAttemptStateV1::Prepared | FinalityAttemptStateV1::EffectuationStarted => {
                return Err(FinalityJournalError::ReceiptOutcomeMismatch)
            }
        };

        if receipt.outcome != expected_outcome {
            return Err(FinalityJournalError::ReceiptOutcomeMismatch);
        }

        if let Some(existing) = self.receipts.get(&receipt.attempt_id) {
            if existing == receipt {
                return Ok(());
            }
            return Err(FinalityJournalError::ReceiptMismatch);
        }

        self.append_record(&FinalityJournalRecordV1::Receipt(receipt.clone()))?;
        self.receipts.insert(receipt.attempt_id, receipt.clone());
        Ok(())
    }

    /// Return the durable receipt for an exact attempt, when one has been recorded.
    pub fn latest_receipt(&self, attempt_id: [u8; 16]) -> Option<&FinalityReceiptV1> {
        self.receipts.get(&attempt_id)
    }

    /// Return the number of distinct attempts present in the journal index.
    pub fn len(&self) -> usize {
        self.latest.len()
    }

    /// Return true when the journal contains no attempts.
    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    fn append_record(
        &mut self,
        record: &FinalityJournalRecordV1,
    ) -> Result<(), FinalityJournalError> {
        let encoded =
            bincode::serialize(record).map_err(|_| FinalityJournalError::MalformedRecord)?;
        if encoded.len() > MAX_JOURNAL_RECORD_BYTES as usize {
            return Err(FinalityJournalError::RecordTooLarge);
        }

        if !self.initialized {
            self.file.write_all(JOURNAL_MAGIC)?;
            self.file.sync_data()?;
            self.initialized = true;
        }

        self.file.write_all(&(encoded.len() as u32).to_be_bytes())?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        Ok(())
    }
}

fn split_journal_header(bytes: &[u8]) -> Result<(bool, &[u8]), FinalityJournalError> {
    if bytes.is_empty() {
        return Ok((false, bytes));
    }
    if bytes.len() < JOURNAL_MAGIC.len() || &bytes[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(FinalityJournalError::UnsupportedJournalSchema);
    }
    Ok((true, &bytes[JOURNAL_MAGIC.len()..]))
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn replay_journal_bytes(
    bytes: &[u8],
) -> Result<(
    BTreeMap<[u8; 16], FinalityAttemptV1>,
    BTreeMap<[u8; 16], FinalityReceiptV1>,
), FinalityJournalError> {
    let mut cursor = 0usize;
    let mut latest = BTreeMap::new();
    let mut receipts = BTreeMap::new();

    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            return Err(FinalityJournalError::MalformedRecord);
        }

        let len = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| FinalityJournalError::MalformedRecord)?,
        ) as usize;
        cursor += 4;

        if len > MAX_JOURNAL_RECORD_BYTES as usize {
            return Err(FinalityJournalError::RecordTooLarge);
        }
        if bytes.len() - cursor < len {
            return Err(FinalityJournalError::MalformedRecord);
        }

        let record: FinalityJournalRecordV1 = bincode::deserialize(&bytes[cursor..cursor + len])
            .map_err(|_| FinalityJournalError::MalformedRecord)?;
        cursor += len;

        match record {
            FinalityJournalRecordV1::Attempt(attempt) => {
                if attempt.schema != FINALITY_ATTEMPT_SCHEMA {
                    return Err(FinalityJournalError::UnsupportedJournalSchema);
                }
                attempt.validate()?;

                if let Some(existing_attempt_id) = consumed_handles.get(&attempt.handle_digest) {
                    if existing_attempt_id != &attempt.attempt_id {
                        return Err(FinalityJournalError::HandleAlreadyConsumed {
                            handle_digest: attempt.handle_digest,
                            existing_attempt_id: *existing_attempt_id,
                        });
                    }
                }
                if let Some(existing_attempt_id) = occupied_actions.get(&attempt.action_key_digest) {
                    if existing_attempt_id != &attempt.attempt_id {
                        return Err(FinalityJournalError::ActionAlreadyFenced {
                            action_key_digest: attempt.action_key_digest,
                            existing_attempt_id: *existing_attempt_id,
                        });
                    }
                }

                if let Some(previous) = latest.get(&attempt.attempt_id) {
                    if previous.handle_digest != attempt.handle_digest
                        || previous.action_key_digest != attempt.action_key_digest
                        || previous.act_digest != attempt.act_digest
                        || previous.sink_digest != attempt.sink_digest
                    {
                        return Err(FinalityJournalError::AttemptIdentityMismatch);
                    }
                    if !valid_lifecycle_transition(previous.state, attempt.state) {
                        return Err(FinalityJournalError::InvalidLifecycleTransition);
                    }
                }

                let attempt_id = attempt.attempt_id;
                let handle_digest = attempt.handle_digest;
                let action_key_digest = attempt.action_key_digest;

                if !matches!(attempt.state, FinalityAttemptStateV1::Prepared) {
                    consumed_handles.insert(handle_digest, attempt_id);
                }

                match attempt.state {
                    FinalityAttemptStateV1::EffectuationStarted
                    | FinalityAttemptStateV1::Committed
                    | FinalityAttemptStateV1::Indeterminate => {
                        occupied_actions.insert(action_key_digest, attempt_id);
                    }
                    FinalityAttemptStateV1::Prepared => {}
                    FinalityAttemptStateV1::Denied => {
                        occupied_actions.remove(&action_key_digest);
                    }
                }

                latest.insert(attempt_id, attempt);
            }
            FinalityJournalRecordV1::Receipt(receipt) => {
                if receipt.schema != FINALITY_RECEIPT_SCHEMA {
                    return Err(FinalityJournalError::UnsupportedJournalSchema);
                }
                receipt.validate()?;
                let Some(attempt) = latest.get(&receipt.attempt_id) else {
                    return Err(FinalityJournalError::ReceiptMismatch);
                };

                if receipt.handle_digest != attempt.handle_digest
                    || receipt.action_key_digest != attempt.action_key_digest
                    || receipt.act_digest != attempt.act_digest
                    || receipt.sink_digest != attempt.sink_digest
                    || receipt.attempt_digest != attempt.digest()
                {
                    return Err(FinalityJournalError::ReceiptMismatch);
                }

                let expected_outcome = match attempt.state {
                    FinalityAttemptStateV1::Committed => FinalityOutcomeV1::Committed,
                    FinalityAttemptStateV1::Denied => FinalityOutcomeV1::Denied,
                    FinalityAttemptStateV1::Indeterminate => FinalityOutcomeV1::Indeterminate,
                    FinalityAttemptStateV1::Prepared
                    | FinalityAttemptStateV1::EffectuationStarted => {
                        return Err(FinalityJournalError::ReceiptOutcomeMismatch)
                    }
                };

                if receipt.outcome != expected_outcome {
                    return Err(FinalityJournalError::ReceiptOutcomeMismatch);
                }

                if let Some(existing) = receipts.get(&receipt.attempt_id) {
                    if existing != &receipt {
                        return Err(FinalityJournalError::ReceiptMismatch);
                    }
                } else {
                    receipts.insert(receipt.attempt_id, receipt);
                }
            }
        }
    }

    Ok((latest, receipts, consumed_handles, occupied_actions))
}

fn valid_lifecycle_transition(
    from: FinalityAttemptStateV1,
    to: FinalityAttemptStateV1,
) -> bool {
    matches!(
        (from, to),
        (
            FinalityAttemptStateV1::Prepared,
            FinalityAttemptStateV1::EffectuationStarted
        ) | (
            FinalityAttemptStateV1::EffectuationStarted,
            FinalityAttemptStateV1::Committed
        ) | (
            FinalityAttemptStateV1::EffectuationStarted,
            FinalityAttemptStateV1::Denied
        ) | (
            FinalityAttemptStateV1::EffectuationStarted,
            FinalityAttemptStateV1::Indeterminate
        ) | (
            FinalityAttemptStateV1::Indeterminate,
            FinalityAttemptStateV1::Committed
        ) | (
            FinalityAttemptStateV1::Indeterminate,
            FinalityAttemptStateV1::Denied
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn attempt() -> FinalityAttemptV1 {
        FinalityAttemptV1::prepare([1; 16], [2; 32], [9; 32], [3; 32], [4; 32]).unwrap()
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("xenia-finality-journal-{}-{}", tag, std::process::id()))
    }

    #[test]
    fn journal_requires_its_own_file_header() {
        let path = temp_path("header");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));

        fs::write(&path, b"not-xenia-journal").unwrap();
        assert!(matches!(
            FinalityJournalV1::open(&path),
            Err(FinalityJournalError::UnsupportedJournalSchema)
        ));

        fs::write(&path, JOURNAL_MAGIC).unwrap();
        let journal = FinalityJournalV1::open(&path).unwrap();
        assert!(journal.is_empty());

        drop(journal);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));
    }

    #[test]
    fn second_owner_is_rejected_while_first_owner_is_live() {
        let path = temp_path("ownership");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));

        let journal = FinalityJournalV1::open(&path).unwrap();
        assert!(matches!(
            FinalityJournalV1::open(&path),
            Err(FinalityJournalError::JournalAlreadyOwned)
        ));

        drop(journal);

        let reopened = FinalityJournalV1::open(&path).unwrap();
        drop(reopened);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));
    }

    #[test]
    fn failed_open_releases_lock_for_retry() {
        let path = temp_path("failed-open-lock");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));

        fs::write(&path, [0xAA, 0xBB, 0xCC]).unwrap();

        assert!(matches!(
            FinalityJournalV1::open(&path),
            Err(FinalityJournalError::UnsupportedJournalSchema)
        ));
        assert!(matches!(
            FinalityJournalV1::open(&path),
            Err(FinalityJournalError::UnsupportedJournalSchema)
        ));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));
    }

    #[test]
    fn journal_round_trips_indeterminate_without_reopening_execution() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        {
            let mut journal = FinalityJournalV1::open(&path).unwrap();
            let mut current = attempt();
            journal.append_attempt(&current).unwrap();
            current.mark_effectuation_started().unwrap();
            journal.append_attempt(&current).unwrap();
            let receipt = current.mark_indeterminate().unwrap();
            journal.append_attempt(&current).unwrap();
            journal.append_receipt(&receipt).unwrap();
        }

        let journal = FinalityJournalV1::open(&path).unwrap();
        let recovered = journal.latest_attempt([1; 16]).unwrap();
        assert_eq!(recovered.state(), FinalityAttemptStateV1::Indeterminate);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn journal_rejects_identity_substitution() {
        let path = temp_path("identity");
        let _ = fs::remove_file(&path);

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let current = attempt();
        journal.append_attempt(&current).unwrap();

        let mut substituted = current.clone();
        substituted.act_digest = [9; 32];
        assert!(matches!(
            journal.append_attempt(&substituted),
            Err(FinalityJournalError::AttemptIdentityMismatch)
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn journal_rejects_fresh_authority_for_same_action_key() {
        let path = temp_path("same-action");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let mut first =
            FinalityAttemptV1::prepare([21; 16], [22; 32], [23; 32], [24; 32], [25; 32]).unwrap();
        journal.append_attempt(&first).unwrap();
        first.mark_effectuation_started().unwrap();
        journal.append_attempt(&first).unwrap();

        let fresh_authority =
            FinalityAttemptV1::prepare([26; 16], [27; 32], [23; 32], [24; 32], [25; 32]).unwrap();
        assert!(matches!(
            journal.append_attempt(&fresh_authority),
            Err(FinalityJournalError::ActionAlreadyFenced { .. })
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn denied_outcome_releases_action_fence_but_not_native_handle() {
        let path = temp_path("release");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let mut first =
            FinalityAttemptV1::prepare([31; 16], [32; 32], [33; 32], [34; 32], [35; 32]).unwrap();
        journal.append_attempt(&first).unwrap();
        first.mark_effectuation_started().unwrap();
        journal.append_attempt(&first).unwrap();
        first.deny().unwrap();
        journal.append_attempt(&first).unwrap();

        let mut second =
            FinalityAttemptV1::prepare([36; 16], [37; 32], [33; 32], [34; 32], [35; 32]).unwrap();
        journal.append_attempt(&second).unwrap();
        second.mark_effectuation_started().unwrap();
        journal.append_attempt(&second).unwrap();

        let reused_original_handle =
            FinalityAttemptV1::prepare([38; 16], [32; 32], [33; 32], [34; 32], [35; 32]).unwrap();
        assert!(matches!(
            journal.append_attempt(&reused_original_handle),
            Err(FinalityJournalError::HandleAlreadyConsumed { .. })
        ));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path_for(&path));
    }

    #[test]
    fn journal_rejects_reused_handle_before_preparation_is_visible() {
        let path = temp_path("early-handle-reuse");
        let _ = fs::remove_file(&path);

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let mut first = attempt();
        first.mark_effectuation_started().unwrap();
        journal.append_attempt(&first).unwrap();

        let second =
            FinalityAttemptV1::prepare([9; 16], [2; 32], [9; 32], [3; 32], [4; 32]).unwrap();
        assert!(matches!(
            journal.append_attempt(&second),
            Err(FinalityJournalError::HandleAlreadyConsumed { .. })
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn journal_fences_handle_reuse_across_distinct_attempt_ids() {
        let path = temp_path("handle-reuse");
        let _ = fs::remove_file(&path);

        {
            let mut journal = FinalityJournalV1::open(&path).unwrap();
            let mut first = attempt();
            first.mark_effectuation_started().unwrap();
            journal.append_attempt(&first).unwrap();

            let mut second =
                FinalityAttemptV1::prepare([9; 16], [2; 32], [3; 32], [4; 32]).unwrap();
            second.mark_effectuation_started().unwrap();

            assert!(matches!(
                journal.append_attempt(&second),
                Err(FinalityJournalError::HandleAlreadyConsumed { .. })
            ));
        }

        assert!(matches!(
            FinalityJournalV1::open(&path).unwrap().latest_attempt([1; 16]).unwrap().state(),
            FinalityAttemptStateV1::EffectuationStarted
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn truncated_tail_fails_closed() {
        let path = temp_path("truncated");
        let _ = fs::remove_file(&path);

        {
            let mut journal = FinalityJournalV1::open(&path).unwrap();
            journal.append_attempt(&attempt()).unwrap();
        }

        let mut bytes = fs::read(&path).unwrap();
        bytes.pop();
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            FinalityJournalV1::open(&path),
            Err(FinalityJournalError::MalformedRecord)
        ));

        let _ = fs::remove_file(&path);
    }
}
