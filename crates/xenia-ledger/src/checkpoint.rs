// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::entry::LedgerEntry;
use crate::errors::VerifyError;
use crate::hash::compute_entry_hash;
use crate::verify::Verifier;

/// Stable schema label for [`LedgerCheckpoint`].
pub const LEDGER_CHECKPOINT_SCHEMA: &str = "xenia-ledger-checkpoint-v1";

/// A public commitment to the current state of a [`crate::Chain`] -- safe to
/// expose without any authentication, unlike the ledger's actual entries.
///
/// A checkpoint reveals only how many entries exist, the current chain
/// head hash, the ledger's verifying key, and a timestamp, all signed by
/// the same Ed25519 key that signs every ledger entry. It deliberately
/// carries none of [`crate::ConsentEventRecord`]'s contents (session/request IDs,
/// scope strings, timing of individual events) -- those can reveal
/// operational metadata (session relationships, revocation activity,
/// incident-response patterns) even when nothing is "secret" in the
/// cryptographic sense. A third party who periodically retains checkpoints
/// can later detect the ledger being rewritten or truncated (a checkpoint
/// whose `entry_count`/`head_hash` don't extend monotonically and
/// consistently from an earlier one they hold) without ever seeing ledger
/// contents, and without trusting whichever daemon serves the checkpoint at
/// query time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpoint {
    /// Must equal [`LEDGER_CHECKPOINT_SCHEMA`].
    pub schema: String,
    /// Number of entries in the chain when this checkpoint was produced
    /// (0 for an empty chain).
    pub entry_count: u64,
    /// [`crate::Chain::last_hash`] at the time this checkpoint was produced --
    /// `[0; 32]` for an empty chain.
    pub head_hash: [u8; 32],
    /// The ledger's Ed25519 verifying key. Lets a holder of an earlier
    /// checkpoint confirm a later one is still signed by the same
    /// authority (a changed key here, at the same or a related endpoint,
    /// is exactly as significant as a changed sealed-channel host
    /// fingerprint -- see `xenia-operator-agent`'s `host_trust` module).
    pub ledger_public_key: [u8; 32],
    /// Unix seconds this checkpoint was produced.
    pub timestamp_unix_secs: u64,
    /// Ed25519 signature over [`checkpoint_message`] for this checkpoint's
    /// own fields.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// The domain-separated message a [`LedgerCheckpoint`]'s signature covers.
/// Length-prefixing every variable-length field and fixing the order of
/// fixed-length ones prevents two different checkpoints from ever hashing
/// to the same message.
pub fn checkpoint_message(
    entry_count: u64,
    head_hash: &[u8; 32],
    ledger_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64 + LEDGER_CHECKPOINT_SCHEMA.len());
    message.extend_from_slice(b"xenia:ledger-checkpoint:v1");
    message.push(0);
    message.extend_from_slice(LEDGER_CHECKPOINT_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(&entry_count.to_be_bytes());
    message.extend_from_slice(head_hash);
    message.extend_from_slice(ledger_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

/// Compute a stable BLAKE3 fingerprint over every signed field of a checkpoint.
///
/// This is used by higher-level continuity artifacts such as key-transition
/// certificates and witness countersignatures. Including the checkpoint
/// signature binds the exact signed object, not merely an equivalent set of
/// unsigned fields.
pub fn checkpoint_fingerprint(
    checkpoint: &LedgerCheckpoint,
) -> Result<[u8; 32], CheckpointError> {
    Verifier::verify_checkpoint(checkpoint)?;
    let mut bytes = checkpoint_message(
        checkpoint.entry_count,
        &checkpoint.head_hash,
        &checkpoint.ledger_public_key,
        checkpoint.timestamp_unix_secs,
    );
    bytes.extend_from_slice(&checkpoint.signature);
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Host-local freshness policy for retained public checkpoints.
///
/// Signature and prefix verification prove authenticity and continuity. This
/// policy additionally lets deployments require that their independent
/// retention process is still alive and reject checkpoints implausibly far in
/// the future. A `None` maximum age preserves historical checkpoints without
/// imposing a freshness SLA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointFreshnessPolicy {
    /// Maximum accepted checkpoint age in seconds, or `None` for no age limit.
    pub max_age_secs: Option<u64>,
    /// Maximum accepted positive clock skew in seconds.
    pub max_future_skew_secs: u64,
}

impl Default for CheckpointFreshnessPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: None,
            max_future_skew_secs: 300,
        }
    }
}

/// Why a [`LedgerCheckpoint`] failed to verify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    /// The checkpoint's `schema` field is not [`LEDGER_CHECKPOINT_SCHEMA`].
    #[error("unsupported ledger checkpoint schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the checkpoint.
        schema: String,
    },
    /// The checkpoint's embedded public key is not a valid Ed25519 key.
    #[error("ledger checkpoint has a malformed public key")]
    BadPublicKey,
    /// The checkpoint's signature does not verify against its own fields
    /// and embedded public key.
    #[error("ledger checkpoint signature is invalid")]
    BadSignature,
}

impl Verifier {
    /// Verify a [`LedgerCheckpoint`]'s signature against its own embedded
    /// public key and fields.
    ///
    /// This only confirms internal self-consistency (the signature really
    /// is over these exact fields, under this exact key) -- it does *not*
    /// by itself confirm the embedded public key is the one a caller
    /// already trusts for a given ledger/endpoint. A caller holding an
    /// earlier checkpoint (or any other independently-obtained copy of the
    /// ledger's public key) should additionally compare
    /// `ledger_public_key` against that -- the same trust-on-first-use
    /// discipline `xenia-operator-agent`'s `host_trust` module applies to
    /// the sealed-channel host identity.
    pub fn verify_checkpoint(checkpoint: &LedgerCheckpoint) -> Result<(), CheckpointError> {
        if checkpoint.schema != LEDGER_CHECKPOINT_SCHEMA {
            return Err(CheckpointError::UnsupportedSchema {
                schema: checkpoint.schema.clone(),
            });
        }
        let public_key = VerifyingKey::from_bytes(&checkpoint.ledger_public_key)
            .map_err(|_| CheckpointError::BadPublicKey)?;
        let message = checkpoint_message(
            checkpoint.entry_count,
            &checkpoint.head_hash,
            &checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        );
        let signature = Signature::from_bytes(&checkpoint.signature);
        public_key
            .verify(&message, &signature)
            .map_err(|_| CheckpointError::BadSignature)
    }
}

/// Why two valid signed checkpoints or a checkpoint and ledger entries failed
/// Xenia's continuity rules.
///
/// A monotonic checkpoint comparison can detect rollback, key substitution,
/// timestamp regression, and a fork at an already-observed height. It cannot,
/// by itself, prove that a higher checkpoint extends an earlier one: that
/// stronger claim requires the intervening signed entries and is enforced by
/// [`Verifier::verify_checkpoint_extension`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointContinuityError {
    /// One of the signed checkpoints was internally invalid.
    #[error("ledger checkpoint failed signature/schema verification: {0}")]
    InvalidCheckpoint(#[from] CheckpointError),
    /// The candidate checkpoint used a different ledger key.
    #[error("ledger checkpoint key changed")]
    LedgerKeyChanged,
    /// The candidate checkpoint moved backward in wall-clock time.
    #[error("ledger checkpoint timestamp regressed from {previous} to {candidate}")]
    TimestampRegressed {
        /// Earlier retained timestamp.
        previous: u64,
        /// Candidate timestamp.
        candidate: u64,
    },
    /// The candidate checkpoint declared fewer entries than the retained one.
    #[error("ledger checkpoint entry count regressed from {previous} to {candidate}")]
    EntryCountRegressed {
        /// Earlier retained entry count.
        previous: u64,
        /// Candidate entry count.
        candidate: u64,
    },
    /// Two checkpoints at the same height committed to different heads.
    #[error("ledger checkpoint fork detected at entry count {entry_count}")]
    ForkAtSameHeight {
        /// Conflicting checkpoint height.
        entry_count: u64,
    },
    /// The checkpoint key did not match the caller's trusted ledger key.
    #[error("ledger checkpoint public key does not match the trusted ledger key")]
    TrustedKeyMismatch,
    /// The retained checkpoint is ahead of the supplied ledger.
    #[error("checkpoint entry count {checkpoint} exceeds ledger length {ledger}")]
    CheckpointAheadOfLedger {
        /// Retained checkpoint count.
        checkpoint: u64,
        /// Supplied ledger length.
        ledger: u64,
    },
    /// The supplied ledger did not contain the checkpoint's committed head at
    /// the checkpoint's declared height.
    #[error("ledger does not contain the retained checkpoint head at entry count {entry_count}")]
    PrefixHeadMismatch {
        /// Checkpoint height that failed to match.
        entry_count: u64,
    },
    /// The candidate checkpoint's count did not equal the retained count plus
    /// the number of supplied suffix entries.
    #[error(
        "checkpoint extension length mismatch: previous={previous}, suffix={suffix}, candidate={candidate}"
    )]
    ExtensionLengthMismatch {
        /// Retained checkpoint count.
        previous: u64,
        /// Number of supplied suffix entries.
        suffix: u64,
        /// Candidate checkpoint count.
        candidate: u64,
    },
    /// A suffix entry used the wrong absolute sequence number.
    #[error("checkpoint extension entry {index} has sequence {found}, expected {expected}")]
    SuffixOutOfOrder {
        /// Index inside the supplied suffix.
        index: usize,
        /// Expected absolute sequence number.
        expected: u64,
        /// Found sequence number.
        found: u64,
    },
    /// A suffix entry did not link to the retained checkpoint or previous
    /// suffix entry.
    #[error("checkpoint extension has a broken hash link at sequence {seq}")]
    SuffixBrokenLink {
        /// Sequence number with the invalid previous hash.
        seq: u64,
    },
    /// A suffix entry's content hash did not recompute.
    #[error("checkpoint extension entry hash mismatch at sequence {seq}")]
    SuffixEntryHashMismatch {
        /// Sequence number with the invalid hash.
        seq: u64,
    },
    /// A suffix entry signature was invalid.
    #[error("checkpoint extension signature invalid at sequence {seq}")]
    SuffixBadSignature {
        /// Sequence number with the invalid signature.
        seq: u64,
    },
    /// The verified suffix did not terminate at the candidate checkpoint head.
    #[error("checkpoint extension suffix does not terminate at the candidate head")]
    CandidateHeadMismatch,
    /// A retained checkpoint timestamp was implausibly far in the future.
    #[error(
        "ledger checkpoint timestamp {checkpoint} exceeds now {now} plus allowed future skew {maximum_skew}"
    )]
    CheckpointFromFuture {
        /// Signed checkpoint timestamp.
        checkpoint: u64,
        /// Verifier wall-clock timestamp.
        now: u64,
        /// Configured positive clock-skew allowance.
        maximum_skew: u64,
    },
    /// A retained checkpoint was older than the deployment's freshness SLA.
    #[error(
        "ledger checkpoint age {age} seconds exceeds maximum accepted age {maximum_age}"
    )]
    CheckpointTooOld {
        /// Observed age in seconds.
        age: u64,
        /// Configured maximum age.
        maximum_age: u64,
    },
    /// Full-chain verification failed while checking a retained checkpoint
    /// against a supplied ledger.
    #[error("ledger failed verification while checking checkpoint continuity: {0}")]
    Ledger(#[from] VerifyError),
}

impl Verifier {
    /// Verify a checkpoint's signature plus host-local freshness policy.
    pub fn verify_checkpoint_freshness(
        checkpoint: &LedgerCheckpoint,
        now_unix_secs: u64,
        policy: CheckpointFreshnessPolicy,
    ) -> Result<(), CheckpointContinuityError> {
        Self::verify_checkpoint(checkpoint)?;
        if checkpoint.timestamp_unix_secs
            > now_unix_secs.saturating_add(policy.max_future_skew_secs)
        {
            return Err(CheckpointContinuityError::CheckpointFromFuture {
                checkpoint: checkpoint.timestamp_unix_secs,
                now: now_unix_secs,
                maximum_skew: policy.max_future_skew_secs,
            });
        }
        if let Some(maximum_age) = policy.max_age_secs {
            let age = now_unix_secs.saturating_sub(checkpoint.timestamp_unix_secs);
            if age > maximum_age {
                return Err(CheckpointContinuityError::CheckpointTooOld {
                    age,
                    maximum_age,
                });
            }
        }
        Ok(())
    }

    /// Check the facts that two independently valid signed checkpoints can
    /// establish without any ledger entries.
    ///
    /// This detects rollback, key substitution, timestamp regression, and a
    /// conflicting head at the same height. A larger entry count is only a
    /// monotonic claim; use [`Verifier::verify_checkpoint_extension`] with the
    /// intervening entries to prove actual append-only extension.
    pub fn verify_checkpoint_monotonic(
        previous: &LedgerCheckpoint,
        candidate: &LedgerCheckpoint,
    ) -> Result<(), CheckpointContinuityError> {
        Self::verify_checkpoint(previous)?;
        Self::verify_checkpoint(candidate)?;
        if previous.ledger_public_key != candidate.ledger_public_key {
            return Err(CheckpointContinuityError::LedgerKeyChanged);
        }
        if candidate.timestamp_unix_secs < previous.timestamp_unix_secs {
            return Err(CheckpointContinuityError::TimestampRegressed {
                previous: previous.timestamp_unix_secs,
                candidate: candidate.timestamp_unix_secs,
            });
        }
        if candidate.entry_count < previous.entry_count {
            return Err(CheckpointContinuityError::EntryCountRegressed {
                previous: previous.entry_count,
                candidate: candidate.entry_count,
            });
        }
        if candidate.entry_count == previous.entry_count
            && candidate.head_hash != previous.head_hash
        {
            return Err(CheckpointContinuityError::ForkAtSameHeight {
                entry_count: candidate.entry_count,
            });
        }
        Ok(())
    }

    /// Verify that `entries` is a complete, valid ledger under `public_key` and
    /// contains the retained checkpoint as an exact prefix.
    ///
    /// This is the restore/startup gate: a complete older state directory
    /// cannot be accepted when an independently retained checkpoint commits to
    /// a later prefix.
    pub fn verify_checkpoint_prefix(
        checkpoint: &LedgerCheckpoint,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), CheckpointContinuityError> {
        Self::verify_checkpoint(checkpoint)?;
        if checkpoint.ledger_public_key != public_key.to_bytes() {
            return Err(CheckpointContinuityError::TrustedKeyMismatch);
        }
        Self::verify_chain(entries, public_key)?;
        let ledger_len = entries.len() as u64;
        if checkpoint.entry_count > ledger_len {
            return Err(CheckpointContinuityError::CheckpointAheadOfLedger {
                checkpoint: checkpoint.entry_count,
                ledger: ledger_len,
            });
        }
        let observed_head = if checkpoint.entry_count == 0 {
            [0u8; 32]
        } else {
            let checkpoint_index = usize::try_from(checkpoint.entry_count - 1)
                .expect("checkpoint count is bounded by the supplied ledger length");
            entries[checkpoint_index].entry_hash
        };
        if observed_head != checkpoint.head_hash {
            return Err(CheckpointContinuityError::PrefixHeadMismatch {
                entry_count: checkpoint.entry_count,
            });
        }
        Ok(())
    }

    /// Prove that `candidate` extends `previous` using every signed ledger entry
    /// between their heights.
    ///
    /// The suffix must begin at `previous.entry_count`, link from
    /// `previous.head_hash`, contain exactly the number of entries implied by
    /// the candidate checkpoint, and terminate at `candidate.head_hash`.
    pub fn verify_checkpoint_extension(
        previous: &LedgerCheckpoint,
        candidate: &LedgerCheckpoint,
        suffix: &[LedgerEntry],
    ) -> Result<(), CheckpointContinuityError> {
        Self::verify_checkpoint_monotonic(previous, candidate)?;
        let expected_len = candidate.entry_count - previous.entry_count;
        if suffix.len() as u64 != expected_len {
            return Err(CheckpointContinuityError::ExtensionLengthMismatch {
                previous: previous.entry_count,
                suffix: suffix.len() as u64,
                candidate: candidate.entry_count,
            });
        }
        let public_key = VerifyingKey::from_bytes(&candidate.ledger_public_key)
            .map_err(|_| CheckpointError::BadPublicKey)?;
        let mut expected_prev = previous.head_hash;
        for (index, entry) in suffix.iter().enumerate() {
            let expected_seq = previous.entry_count + index as u64;
            if entry.seq != expected_seq {
                return Err(CheckpointContinuityError::SuffixOutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }
            if entry.prev_hash != expected_prev {
                return Err(CheckpointContinuityError::SuffixBrokenLink { seq: entry.seq });
            }
            let recomputed = compute_entry_hash(
                entry.seq,
                &entry.prev_hash,
                &entry.timestamp,
                &entry.event,
            )
            .map_err(|_| CheckpointContinuityError::SuffixEntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(CheckpointContinuityError::SuffixEntryHashMismatch { seq: entry.seq });
            }
            let signature = Signature::from_bytes(&entry.signature);
            public_key
                .verify(&entry.entry_hash, &signature)
                .map_err(|_| CheckpointContinuityError::SuffixBadSignature { seq: entry.seq })?;
            expected_prev = entry.entry_hash;
        }
        if expected_prev != candidate.head_hash {
            return Err(CheckpointContinuityError::CandidateHeadMismatch);
        }
        Ok(())
    }
}
