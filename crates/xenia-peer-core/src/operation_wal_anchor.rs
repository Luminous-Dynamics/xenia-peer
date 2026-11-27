// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Independently witnessed operation-WAL checkpoints and sequence leases.
//!
//! A local hash chain detects edits to retained records, but cannot detect
//! replacement with an older, internally valid prefix unless a newer head is
//! retained outside the WAL's storage and signing failure domain.
//!
//! This module defines a protocol/reference model. It does not implement a
//! network witness service or hardware-backed monotonic storage. Production
//! implementations of OperationWalWitnessStore must provide durable,
//! linearizable compare-and-advance semantics and retain their own state.
//!
//! A witness MUST verify the supplied extension proof from its previously
//! retained checkpoint to the candidate head before countersigning it. A
//! signature over a candidate head alone is not proof of append-only
//! continuity.
//!
//! Sequence leases amortize witness round trips for high-rate traffic. A lease
//! reserves a bounded, non-overlapping range, bound to the authenticated
//! session, authority epoch, and a fresh process-boot fingerprint. After a
//! process restart, the unused remainder of the prior lease is burned. The
//! next lease begins after the entire previously reserved range. The boot
//! fingerprint must be newly generated for every process lifetime and must
//! never be restored from the WAL.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::operation_wal_merkle::{
    OperationWalMerkleConsistencyProof, operation_wal_merkle_root,
    verify_operation_wal_consistency_proof,
};

/// Schema for independently witnessed operation-WAL checkpoints.
pub const OPERATION_WAL_CHECKPOINT_SCHEMA: &str = "xenia-operation-wal-checkpoint-v2";
/// Schema for process-bound operation-sequence leases.
pub const OPERATION_SEQUENCE_LEASE_SCHEMA: &str = "xenia-operation-sequence-lease-v1";
/// Maximum independent witness signatures accepted in one bundle.
pub const MAX_OPERATION_WAL_WITNESSES: usize = 64;
/// Maximum number of operation identities reserved by one lease.
pub const MAX_OPERATION_SEQUENCE_LEASE_SPAN: u64 = 1_048_576;

/// Public commitment to one exact durable operation-WAL head.
///
/// witness_sequence is maintained by the independent witness store. It is
/// distinct from wal_sequence, which is maintained by the local WAL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationWalCheckpoint {
    /// Must equal OPERATION_WAL_CHECKPOINT_SCHEMA.
    pub schema: String,
    /// Authenticated Xenia session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Monotonic clock-domain identity used by the local WAL.
    pub clock_domain: u64,
    /// Local durable WAL sequence committed by this checkpoint.
    pub wal_sequence: u64,
    /// Exact local WAL hash-chain head at wal_sequence.
    pub wal_head_hash: [u8; 32],
    /// Number of record hashes committed by the Merkle root; equals wal_sequence.
    pub wal_merkle_tree_size: u64,
    /// RFC 9162-style SHA-256 Merkle root over the ordered WAL record hashes.
    pub wal_merkle_root: [u8; 32],
    /// Monotonic generation maintained by the independent witness store.
    pub witness_sequence: u64,
    /// Fingerprint of the immediately preceding witnessed checkpoint.
    /// The first checkpoint uses [0; 32].
    pub previous_checkpoint_fingerprint: [u8; 32],
    /// Unix seconds when the checkpoint proposal was created.
    pub timestamp_unix_secs: u64,
}

impl OperationWalCheckpoint {
    /// Propose the immediate successor of an independently retained checkpoint.
    ///
    /// The witness store must still compare-and-advance its retained head
    /// atomically before signing or persisting this candidate.
    pub fn next(
        previous: Option<&Self>,
        session_fingerprint: [u8; 32],
        clock_domain: u64,
        wal_sequence: u64,
        wal_head_hash: [u8; 32],
        wal_merkle_tree_size: u64,
        wal_merkle_root: [u8; 32],
        timestamp_unix_secs: u64,
    ) -> Result<Self, OperationWalAnchorError> {
        let (witness_sequence, previous_checkpoint_fingerprint) = match previous {
            Some(previous) => {
                validate_checkpoint(previous)?;
                if previous.session_fingerprint != session_fingerprint {
                    return Err(OperationWalAnchorError::SessionMismatch);
                }
                if previous.clock_domain != clock_domain {
                    return Err(OperationWalAnchorError::ClockDomainMismatch);
                }
                if timestamp_unix_secs < previous.timestamp_unix_secs {
                    return Err(OperationWalAnchorError::TimestampRegressed);
                }
                (
                    previous.witness_sequence.checked_add(1)
                        .ok_or(OperationWalAnchorError::SequenceExhausted)?,
                    operation_wal_checkpoint_fingerprint(previous)?,
                )
            }
            None => (1, [0; 32]),
        };
        let candidate = Self {
            schema: OPERATION_WAL_CHECKPOINT_SCHEMA.to_string(),
            session_fingerprint,
            clock_domain,
            wal_sequence,
            wal_head_hash,
            wal_merkle_tree_size,
            wal_merkle_root,
            witness_sequence,
            previous_checkpoint_fingerprint,
            timestamp_unix_secs,
        };
        validate_checkpoint(&candidate)?;
        if let Some(previous) = previous {
            verify_checkpoint_successor(previous, &candidate)?;
        } else if wal_sequence == 0 && wal_head_hash != [0; 32] {
            return Err(OperationWalAnchorError::GenesisHeadMismatch);
        }
        Ok(candidate)
    }
}

/// Payload-redacted hash-link record used to prove a WAL head extension.
///
/// The witness checks sequence continuity and previous-hash edges. The local
/// WAL verifier must separately recompute each record_hash from its canonical
/// serialized record body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationWalHeadRecord {
    /// Absolute sequence number of this WAL record.
    pub sequence: u64,
    /// Hash of the immediately preceding WAL record.
    pub previous_hash: [u8; 32],
    /// Hash of this complete WAL record.
    pub record_hash: [u8; 32],
}

/// Proof that a candidate WAL head follows a previously witnessed WAL head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationWalHeadExtension {
    /// Sequence at the previously witnessed head.
    pub base_sequence: u64,
    /// Hash at the previously witnessed head.
    pub base_head_hash: [u8; 32],
    /// Ordered payload-redacted hash-link records.
    pub records: Vec<OperationWalHeadRecord>,
}

impl OperationWalHeadExtension {
    /// Verify exact sequence and hash-link continuity to the candidate head.
    pub fn verify(
        &self,
        previous: Option<&OperationWalCheckpoint>,
        candidate: &OperationWalCheckpoint,
    ) -> Result<(), OperationWalAnchorError> {
        validate_checkpoint(candidate)?;
        let (base_sequence, base_head_hash) = match previous {
            Some(previous) => {
                verify_checkpoint_successor(previous, candidate)?;
                (previous.wal_sequence, previous.wal_head_hash)
            }
            None => {
                if candidate.witness_sequence != 1
                    || candidate.previous_checkpoint_fingerprint != [0; 32]
                {
                    return Err(OperationWalAnchorError::PreviousCheckpointMismatch);
                }
                (0, [0; 32])
            }
        };
        if self.base_sequence != base_sequence || self.base_head_hash != base_head_hash {
            return Err(OperationWalAnchorError::ExtensionBaseMismatch);
        }
        let expected_count = candidate.wal_sequence.checked_sub(base_sequence)
            .ok_or(OperationWalAnchorError::WalSequenceRegressed {
                previous: base_sequence,
                candidate: candidate.wal_sequence,
            })?;
        if u64::try_from(self.records.len()).ok() != Some(expected_count) {
            return Err(OperationWalAnchorError::ExtensionLengthMismatch {
                expected: expected_count,
                observed: self.records.len(),
            });
        }
        let mut sequence = base_sequence;
        let mut head_hash = base_head_hash;
        for (index, record) in self.records.iter().enumerate() {
            sequence = sequence.checked_add(1)
                .ok_or(OperationWalAnchorError::SequenceExhausted)?;
            if record.sequence != sequence {
                return Err(OperationWalAnchorError::ExtensionSequenceMismatch {
                    index,
                    expected: sequence,
                    observed: record.sequence,
                });
            }
            if record.previous_hash != head_hash {
                return Err(OperationWalAnchorError::ExtensionBrokenLink {
                    sequence: record.sequence,
                });
            }
            head_hash = record.record_hash;
        }
        if sequence != candidate.wal_sequence || head_hash != candidate.wal_head_hash {
            return Err(OperationWalAnchorError::ExtensionHeadMismatch);
        }
        Ok(())
    }

    /// Compute a domain-separated digest of this payload-free extension proof.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"XENIA-OPERATION-WAL-HEAD-EXTENSION-V1\0");
        hasher.update(&self.base_sequence.to_be_bytes());
        hasher.update(&self.base_head_hash);
        hasher.update(&(self.records.len() as u64).to_be_bytes());
        for record in &self.records {
            hasher.update(&record.sequence.to_be_bytes());
            hasher.update(&record.previous_hash);
            hasher.update(&record.record_hash);
        }
        *hasher.finalize().as_bytes()
    }
}


/// Proof mode presented to an independent checkpoint witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationWalCheckpointExtension {
    /// Linear record-by-record hash-chain proof, retained for small/debug cases.
    ///
    /// This mode is rejected when the WAL sequence grows. Growing checkpoints
    /// must use the compact Merkle consistency proof.
    LinearHashChain(OperationWalHeadExtension),
    /// Compact RFC 9162 consistency proof over ordered WAL record hashes.
    MerkleConsistency(OperationWalMerkleConsistencyProof),
}

impl OperationWalCheckpointExtension {
    /// Verify that this proof extends the previous witnessed checkpoint.
    pub fn verify(
        &self,
        previous: Option<&OperationWalCheckpoint>,
        candidate: &OperationWalCheckpoint,
    ) -> Result<(), OperationWalAnchorError> {
        match self {
            Self::LinearHashChain(extension) => {
                if let Some(previous) = previous {
                    if candidate.wal_sequence > previous.wal_sequence {
                        return Err(OperationWalAnchorError::MerkleConsistencyRequired);
                    }
                } else if candidate.wal_sequence > 0 {
                    return Err(OperationWalAnchorError::MerkleConsistencyRequired);
                }
                extension.verify(previous, candidate)
            }
            Self::MerkleConsistency(proof) => {
                validate_checkpoint(candidate)?;
                if let Some(previous) = previous {
                    verify_checkpoint_successor(previous, candidate)?;
                } else if candidate.witness_sequence != 1
                    || candidate.previous_checkpoint_fingerprint != [0; 32]
                {
                    return Err(OperationWalAnchorError::PreviousCheckpointMismatch);
                }
                verify_operation_wal_consistency_proof(
                    previous.map(|value| value.wal_merkle_tree_size).unwrap_or(0),
                    previous
                        .map(|value| value.wal_merkle_root)
                        .unwrap_or_else(|| operation_wal_merkle_root(&[])),
                    candidate.wal_merkle_tree_size,
                    candidate.wal_merkle_root,
                    proof,
                )
                .map_err(|_| OperationWalAnchorError::MerkleProofRejected)
            }
        }
    }
}

/// Independent Ed25519 witness signature over an exact checkpoint or lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationWalWitnessSignature {
    /// Witness Ed25519 public key.
    pub witness_public_key: [u8; 32],
    /// Fingerprint of the exact checkpoint or lease statement.
    pub statement_digest: [u8; 32],
    /// Unix seconds when the witness observed the statement.
    pub observed_at_unix_secs: u64,
    /// Ed25519 signature over operation_wal_witness_message.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl OperationWalWitnessSignature {
    /// Countersign a statement with a key held by an independent witness.
    pub fn sign(
        signing_key: &SigningKey,
        statement_digest: [u8; 32],
        observed_at_unix_secs: u64,
    ) -> Self {
        let witness_public_key = signing_key.verifying_key().to_bytes();
        let message = operation_wal_witness_message(
            &statement_digest,
            &witness_public_key,
            observed_at_unix_secs,
        );
        Self {
            witness_public_key,
            statement_digest,
            observed_at_unix_secs,
            signature: signing_key.sign(&message).to_bytes(),
        }
    }
}

/// One checkpoint plus independent witness countersignatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationWalWitnessBundle {
    /// Exact WAL checkpoint observed by the witnesses.
    pub checkpoint: OperationWalCheckpoint,
    /// Distinct witness signatures.
    pub witnesses: Vec<OperationWalWitnessSignature>,
}

impl OperationWalWitnessBundle {
    /// Start a witness bundle for a schema-valid checkpoint proposal.
    pub fn new(checkpoint: OperationWalCheckpoint) -> Result<Self, OperationWalAnchorError> {
        validate_checkpoint(&checkpoint)?;
        Ok(Self { checkpoint, witnesses: Vec::new() })
    }

    /// Add one witness signature, rejecting duplicate keys and stale timestamps.
    pub fn sign_with(
        &mut self,
        signing_key: &SigningKey,
        observed_at_unix_secs: u64,
    ) -> Result<(), OperationWalAnchorError> {
        if observed_at_unix_secs < self.checkpoint.timestamp_unix_secs {
            return Err(OperationWalAnchorError::WitnessPredatesStatement);
        }
        if self.witnesses.len() >= MAX_OPERATION_WAL_WITNESSES {
            return Err(OperationWalAnchorError::TooManyWitnesses);
        }
        let public_key = signing_key.verifying_key().to_bytes();
        if self.witnesses.iter().any(|w| w.witness_public_key == public_key) {
            return Err(OperationWalAnchorError::DuplicateWitness);
        }
        let digest = operation_wal_checkpoint_fingerprint(&self.checkpoint)?;
        self.witnesses.push(OperationWalWitnessSignature::sign(
            signing_key, digest, observed_at_unix_secs,
        ));
        Ok(())
    }
}

/// Caller-pinned witness trust policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationWalWitnessPolicy {
    /// Exact trusted Ed25519 witness public keys.
    pub trusted_witness_keys: Vec<[u8; 32]>,
    /// Minimum number of distinct trusted signatures.
    pub minimum_quorum: usize,
}

impl OperationWalWitnessPolicy {
    /// Validate that the configured trust set and quorum are meaningful.
    pub fn validate(&self) -> Result<(), OperationWalAnchorError> {
        let trusted = self.trusted_witness_keys.iter().copied().collect::<BTreeSet<_>>();
        if self.minimum_quorum == 0 || trusted.len() != self.trusted_witness_keys.len()
            || trusted.len() > MAX_OPERATION_WAL_WITNESSES
            || self.minimum_quorum > trusted.len()
        {
            return Err(OperationWalAnchorError::InvalidWitnessPolicy);
        }
        Ok(())
    }
}

/// Freshness constraints for a witnessed checkpoint or sequence lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationWalAnchorFreshnessPolicy {
    /// Maximum statement age in seconds, or None for no age limit.
    pub max_age_secs: Option<u64>,
    /// Maximum positive clock skew in seconds.
    pub max_future_skew_secs: u64,
}

impl Default for OperationWalAnchorFreshnessPolicy {
    fn default() -> Self {
        Self { max_age_secs: None, max_future_skew_secs: 300 }
    }
}

/// A monotonic, process-bound reservation of operation sequence numbers.
///
/// Unused sequence numbers in a lease are burned when a process exits. The
/// next process obtains a new lease after the entire prior range, preventing
/// reuse of identities for effects that may have happened but whose WAL
/// terminal record was lost in a crash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSequenceLease {
    /// Must equal OPERATION_SEQUENCE_LEASE_SCHEMA.
    pub schema: String,
    /// Authenticated Xenia session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Authority/rekey epoch for which the lease is valid.
    pub authority_epoch: u64,
    /// Monotonic lease generation within the session.
    pub lease_generation: u64,
    /// First sequence in the reserved range, inclusive.
    pub first_operation_sequence: u64,
    /// Last sequence in the reserved range, inclusive.
    pub last_operation_sequence: u64,
    /// Fingerprint of the previous lease, or zero for genesis.
    pub previous_lease_fingerprint: [u8; 32],
    /// Fresh per-process boot fingerprint; never restored from the WAL.
    pub owner_boot_fingerprint: [u8; 32],
    /// Unix seconds when the lease was issued.
    pub issued_at_unix_secs: u64,
    /// Unix seconds when the lease expires.
    pub expires_at_unix_secs: u64,
}

impl OperationSequenceLease {
    /// Propose the next non-overlapping range after a prior lease.
    pub fn next(
        previous: Option<&Self>,
        session_fingerprint: [u8; 32],
        authority_epoch: u64,
        owner_boot_fingerprint: [u8; 32],
        operation_count: u64,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> Result<Self, OperationWalAnchorError> {
        if operation_count == 0 || operation_count > MAX_OPERATION_SEQUENCE_LEASE_SPAN {
            return Err(OperationWalAnchorError::InvalidLeaseSpan);
        }
        if expires_at_unix_secs <= issued_at_unix_secs {
            return Err(OperationWalAnchorError::InvalidLeaseLifetime);
        }
        let (generation, first, previous_fingerprint) = match previous {
            Some(previous) => {
                validate_lease(previous)?;
                if previous.session_fingerprint != session_fingerprint {
                    return Err(OperationWalAnchorError::SessionMismatch);
                }
                if authority_epoch < previous.authority_epoch {
                    return Err(OperationWalAnchorError::AuthorityEpochRegressed);
                }
                (
                    previous.lease_generation.checked_add(1)
                        .ok_or(OperationWalAnchorError::SequenceExhausted)?,
                    previous.last_operation_sequence.checked_add(1)
                        .ok_or(OperationWalAnchorError::SequenceExhausted)?,
                    operation_sequence_lease_fingerprint(previous)?,
                )
            }
            None => (1, 1, [0; 32]),
        };
        let last = first.checked_add(operation_count - 1)
            .ok_or(OperationWalAnchorError::SequenceExhausted)?;
        let candidate = Self {
            schema: OPERATION_SEQUENCE_LEASE_SCHEMA.to_string(),
            session_fingerprint,
            authority_epoch,
            lease_generation: generation,
            first_operation_sequence: first,
            last_operation_sequence: last,
            previous_lease_fingerprint: previous_fingerprint,
            owner_boot_fingerprint,
            issued_at_unix_secs,
            expires_at_unix_secs,
        };
        if let Some(previous) = previous {
            verify_sequence_lease_successor(previous, &candidate)?;
        }
        Ok(candidate)
    }

    /// Whether an operation sequence is inside this lease.
    pub fn contains(&self, sequence: u64) -> bool {
        (self.first_operation_sequence..=self.last_operation_sequence).contains(&sequence)
    }
}

/// A process-bound lease plus independent witness signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSequenceLeaseBundle {
    /// Exact lease observed by the witnesses.
    pub lease: OperationSequenceLease,
    /// Distinct witness signatures.
    pub witnesses: Vec<OperationWalWitnessSignature>,
}

/// Opaque lease verified once against the independent witness quorum.
///
/// Hold this token in the active session runtime. Its private field prevents
/// callers from manufacturing a verified lease. Per-operation admission uses
/// the constant-time range check in contains(), not repeated Ed25519 verifies.
#[derive(Debug)]
pub struct VerifiedOperationSequenceLease {
    lease: OperationSequenceLease,
    monotonic_expiry: Instant,
}

impl VerifiedOperationSequenceLease {
    /// Whether an operation sequence belongs to the verified reserved range.
    pub fn contains(&self, operation_sequence: u64) -> bool {
        Instant::now() <= self.monotonic_expiry && self.lease.contains(operation_sequence)
    }

    /// Require that an operation sequence belongs to this unexpired lease.
    pub fn validate_sequence(
        &self,
        operation_sequence: u64,
    ) -> Result<(), OperationWalAnchorError> {
        if self.contains(operation_sequence) {
            Ok(())
        } else {
            Err(OperationWalAnchorError::OperationSequenceOutsideLease)
        }
    }

    /// First sequence in the verified lease, inclusive.
    pub fn first_operation_sequence(&self) -> u64 {
        self.lease.first_operation_sequence
    }

    /// Last sequence in the verified lease, inclusive.
    pub fn last_operation_sequence(&self) -> u64 {
        self.lease.last_operation_sequence
    }

    /// Authority epoch bound to the verified lease.
    pub fn authority_epoch(&self) -> u64 {
        self.lease.authority_epoch
    }

    /// Process boot fingerprint bound to the verified lease.
    pub fn owner_boot_fingerprint(&self) -> [u8; 32] {
        self.lease.owner_boot_fingerprint
    }
}


/// Fail-closed errors returned by the checkpoint/lease protocol.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationWalAnchorError {
    /// Unknown checkpoint or lease schema.
    #[error("unsupported operation-WAL anchor schema")]
    UnsupportedSchema,
    /// Checkpoint belongs to another session.
    #[error("operation-WAL anchor session mismatch")]
    SessionMismatch,
    /// Checkpoint belongs to another clock domain.
    #[error("operation-WAL anchor clock-domain mismatch")]
    ClockDomainMismatch,
    /// Checkpoint timestamp regressed.
    #[error("operation-WAL checkpoint timestamp regressed")]
    TimestampRegressed,
    /// Candidate did not name the exact prior checkpoint.
    #[error("operation-WAL checkpoint previous fingerprint mismatch")]
    PreviousCheckpointMismatch,
    /// Independent witness generation did not increment by exactly one.
    #[error("operation-WAL witness generation is not the immediate successor")]
    NonMonotonicWitnessSequence,
    /// WAL sequence regressed.
    #[error("operation-WAL sequence regressed")]
    WalSequenceRegressed {
        /// Prior independently witnessed WAL sequence.
        previous: u64,
        /// Candidate WAL sequence.
        candidate: u64,
    },
    /// Two heads at the same WAL sequence differ.
    #[error("operation-WAL fork detected at one sequence")]
    WalFork {
        /// Conflicting WAL sequence.
        sequence: u64,
    },
    /// Genesis sequence/head combination is invalid.
    #[error("operation-WAL genesis head must use sequence zero and zero hash")]
    GenesisHeadMismatch,
    /// Extension proof does not start at prior witnessed head.
    #[error("operation-WAL extension base mismatch")]
    ExtensionBaseMismatch,
    /// Extension record count does not match sequence gap.
    #[error("operation-WAL extension length mismatch")]
    ExtensionLengthMismatch {
        /// Number of records required by the WAL sequence gap.
        expected: u64,
        /// Number of records present in the supplied extension.
        observed: usize,
    },
    /// Extension record sequence is out of order.
    #[error("operation-WAL extension sequence mismatch")]
    ExtensionSequenceMismatch {
        /// Position of the malformed extension record.
        index: usize,
        /// Expected absolute sequence number.
        expected: u64,
        /// Observed absolute sequence number.
        observed: u64,
    },
    /// Previous hash does not match prior record.
    #[error("operation-WAL extension has broken previous-hash link")]
    ExtensionBrokenLink {
        /// WAL sequence whose previous-hash link failed.
        sequence: u64,
    },
    /// Final extension hash differs from candidate head.
    #[error("operation-WAL extension head mismatch")]
    ExtensionHeadMismatch,
    /// Candidate local WAL is behind the witnessed checkpoint.
    #[error("local operation-WAL rollback detected")]
    LocalWalRollback {
        /// Latest independently witnessed sequence.
        checkpoint: u64,
        /// Sequence present in the local WAL.
        local: u64,
    },
    /// Candidate local WAL is ahead but its suffix is not externally witnessed.
    #[error("local operation-WAL contains an unanchored suffix")]
    UnanchoredWalSuffix {
        /// Latest independently witnessed sequence.
        checkpoint: u64,
        /// Newer local sequence not yet externally witnessed.
        local: u64,
    },
    /// Local head hash differs at the witnessed sequence.
    #[error("local operation-WAL head does not match checkpoint")]
    LocalWalHeadMismatch,
    /// Merkle leaf count does not equal the durable WAL sequence.
    #[error("operation-WAL Merkle tree size differs from WAL sequence")]
    MerkleTreeSizeMismatch,
    /// Empty WAL checkpoint has a non-empty Merkle root.
    #[error("operation-WAL genesis Merkle root mismatch")]
    GenesisMerkleRootMismatch,
    /// A growing checkpoint did not supply a compact Merkle proof.
    #[error("growing operation-WAL checkpoint requires Merkle consistency proof")]
    MerkleConsistencyRequired,
    /// Compact Merkle consistency verification failed.
    #[error("operation-WAL Merkle consistency proof rejected")]
    MerkleProofRejected,
    /// Invalid witness trust set or zero/impossible quorum.
    #[error("invalid operation-WAL witness policy")]
    InvalidWitnessPolicy,
    /// A witness public key was malformed.
    #[error("malformed operation-WAL witness public key")]
    BadWitnessPublicKey,
    /// A supplied authority epoch differs from the lease epoch.
    #[error("operation sequence lease authority epoch mismatch")]
    AuthorityEpochMismatch,
    /// A witness was not present in the caller-pinned trust set.
    #[error("untrusted operation-WAL witness")]
    UntrustedWitness,
    /// Witness signature does not verify.
    #[error("bad operation-WAL witness signature")]
    BadWitnessSignature,
    /// Witness statement digest differs from bundle statement.
    #[error("operation-WAL witness signed another statement")]
    StatementDigestMismatch,
    /// Duplicate witness key in bundle.
    #[error("duplicate operation-WAL witness")]
    DuplicateWitness,
    /// Witness timestamp predates checkpoint/lease.
    #[error("operation-WAL witness predates statement")]
    WitnessPredatesStatement,
    /// Witness set does not meet quorum.
    #[error("operation-WAL witness quorum not met")]
    QuorumNotMet {
        /// Number of distinct valid signatures from trusted keys.
        verified: usize,
        /// Minimum trusted witness quorum required by policy.
        required: usize,
    },
    /// More than the explicit witness limit was supplied.
    #[error("too many operation-WAL witnesses")]
    TooManyWitnesses,
    /// Statement timestamp is too far in the future.
    #[error("operation-WAL anchor is from the future")]
    AnchorFromFuture,
    /// Statement exceeds configured age limit.
    #[error("operation-WAL anchor is too old")]
    AnchorTooOld,
    /// Sequence arithmetic overflowed.
    #[error("operation-WAL sequence exhausted")]
    SequenceExhausted,
    /// Empty, inverted or too-large lease range.
    #[error("invalid operation sequence lease span")]
    InvalidLeaseSpan,
    /// Lease expiry does not follow issuance.
    #[error("invalid operation sequence lease lifetime")]
    InvalidLeaseLifetime,
    /// Lease does not immediately follow previous generation/range.
    #[error("operation sequence lease is not a strict successor")]
    NonMonotonicLease,
    /// Lease range overlaps/reuses an earlier range.
    #[error("operation sequence lease range reused")]
    LeaseRangeReuse,
    /// Authority epoch moved backwards.
    #[error("operation sequence lease authority epoch regressed")]
    AuthorityEpochRegressed,
    /// Current process boot fingerprint differs from the lease owner.
    #[error("operation sequence lease belongs to another process boot")]
    BootFingerprintMismatch,
    /// Process boot identity must be fresh and nonzero.
    #[error("operation sequence lease boot fingerprint is invalid")]
    InvalidBootFingerprint,
    /// Lease timestamp/expiry is invalid at current time.
    #[error("operation sequence lease is expired or not yet valid")]
    LeaseExpired,
    /// Requested operation identity lies outside the reserved lease.
    #[error("operation sequence is outside witnessed lease")]
    OperationSequenceOutsideLease,
}

/// Durably retained checkpoint and sequence lease authority.
///
/// Implementations MUST retain their state outside the local WAL's failure
/// domain. A sidecar in the same directory is not an independent anchor.
/// Checkpoint compare-and-advance MUST atomically compare the expected prior
/// fingerprint, verify the provided extension, and persist the candidate
/// before returning signatures. Lease compare-and-advance MUST atomically
/// reserve a non-overlapping range and persist its high-water mark before
/// returning signatures. Unknown outcomes must be read back before retry.
pub trait OperationWalWitnessStore: Send + Sync {
    /// Read the latest witnessed checkpoint for this session and clock domain.
    fn latest_checkpoint(
        &self,
        session_fingerprint: [u8; 32],
        clock_domain: u64,
    ) -> Result<Option<OperationWalWitnessBundle>, OperationWalWitnessStoreError>;

    /// Atomically verify and advance a checkpoint head.
    fn compare_and_advance_checkpoint(
        &self,
        expected_previous_fingerprint: Option<[u8; 32]>,
        candidate: OperationWalCheckpoint,
        extension: OperationWalCheckpointExtension,
    ) -> Result<OperationWalWitnessBundle, OperationWalWitnessStoreError>;

    /// Read the last witnessed sequence lease for this session.
    fn latest_sequence_lease(
        &self,
        session_fingerprint: [u8; 32],
    ) -> Result<Option<OperationSequenceLeaseBundle>, OperationWalWitnessStoreError>;

    /// Atomically reserve and witness a non-overlapping sequence lease.
    fn compare_and_advance_sequence_lease(
        &self,
        expected_previous_fingerprint: Option<[u8; 32]>,
        candidate: OperationSequenceLease,
    ) -> Result<OperationSequenceLeaseBundle, OperationWalWitnessStoreError>;
}

/// Independent-witness service failure; never treat an error as a safe retry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationWalWitnessStoreError {
    /// Witness store is unavailable.
    #[error("operation-WAL witness store unavailable")]
    Unavailable,
    /// Another caller advanced the retained head.
    #[error("operation-WAL witness expected head is stale")]
    StaleExpectedHead,
    /// Candidate or extension was rejected.
    #[error("operation-WAL witness candidate rejected")]
    CandidateRejected,
    /// Request may have committed; read witness state before retrying.
    #[error("operation-WAL witness outcome unknown; reconcile before retry")]
    UnknownOutcome,
}

/// Stable fingerprint of all fields in one WAL checkpoint.
pub fn operation_wal_checkpoint_fingerprint(
    checkpoint: &OperationWalCheckpoint,
) -> Result<[u8; 32], OperationWalAnchorError> {
    validate_checkpoint(checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-OPERATION-WAL-CHECKPOINT-V2\0");
    hasher.update(&checkpoint.session_fingerprint);
    hasher.update(&checkpoint.clock_domain.to_be_bytes());
    hasher.update(&checkpoint.wal_sequence.to_be_bytes());
    hasher.update(&checkpoint.wal_head_hash);
    hasher.update(&checkpoint.wal_merkle_tree_size.to_be_bytes());
    hasher.update(&checkpoint.wal_merkle_root);
    hasher.update(&checkpoint.witness_sequence.to_be_bytes());
    hasher.update(&checkpoint.previous_checkpoint_fingerprint);
    hasher.update(&checkpoint.timestamp_unix_secs.to_be_bytes());
    Ok(*hasher.finalize().as_bytes())
}

/// Stable fingerprint of all fields in one sequence lease.
pub fn operation_sequence_lease_fingerprint(
    lease: &OperationSequenceLease,
) -> Result<[u8; 32], OperationWalAnchorError> {
    validate_lease(lease)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-OPERATION-SEQUENCE-LEASE-V1\0");
    hasher.update(&lease.session_fingerprint);
    hasher.update(&lease.authority_epoch.to_be_bytes());
    hasher.update(&lease.lease_generation.to_be_bytes());
    hasher.update(&lease.first_operation_sequence.to_be_bytes());
    hasher.update(&lease.last_operation_sequence.to_be_bytes());
    hasher.update(&lease.previous_lease_fingerprint);
    hasher.update(&lease.owner_boot_fingerprint);
    hasher.update(&lease.issued_at_unix_secs.to_be_bytes());
    hasher.update(&lease.expires_at_unix_secs.to_be_bytes());
    Ok(*hasher.finalize().as_bytes())
}

/// Domain-separated witness signature message.
pub fn operation_wal_witness_message(
    statement_digest: &[u8; 32],
    witness_public_key: &[u8; 32],
    observed_at_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(112);
    message.extend_from_slice(b"XENIA-OPERATION-WAL-WITNESS-V1\0");
    message.extend_from_slice(statement_digest);
    message.extend_from_slice(witness_public_key);
    message.extend_from_slice(&observed_at_unix_secs.to_be_bytes());
    message
}

/// Verify exact immediate-successor semantics for two checkpoints.
pub fn verify_checkpoint_successor(
    previous: &OperationWalCheckpoint,
    candidate: &OperationWalCheckpoint,
) -> Result<(), OperationWalAnchorError> {
    validate_checkpoint(previous)?;
    validate_checkpoint(candidate)?;
    if previous.session_fingerprint != candidate.session_fingerprint {
        return Err(OperationWalAnchorError::SessionMismatch);
    }
    if previous.clock_domain != candidate.clock_domain {
        return Err(OperationWalAnchorError::ClockDomainMismatch);
    }
    if candidate.witness_sequence != previous.witness_sequence.checked_add(1)
        .ok_or(OperationWalAnchorError::SequenceExhausted)?
    {
        return Err(OperationWalAnchorError::NonMonotonicWitnessSequence);
    }
    if candidate.previous_checkpoint_fingerprint
        != operation_wal_checkpoint_fingerprint(previous)?
    {
        return Err(OperationWalAnchorError::PreviousCheckpointMismatch);
    }
    if candidate.wal_sequence < previous.wal_sequence {
        return Err(OperationWalAnchorError::WalSequenceRegressed {
            previous: previous.wal_sequence,
            candidate: candidate.wal_sequence,
        });
    }
    if candidate.wal_sequence == previous.wal_sequence
        && (candidate.wal_head_hash != previous.wal_head_hash
            || candidate.wal_merkle_root != previous.wal_merkle_root)
    {
        return Err(OperationWalAnchorError::WalFork { sequence: candidate.wal_sequence });
    }
    if candidate.timestamp_unix_secs < previous.timestamp_unix_secs {
        return Err(OperationWalAnchorError::TimestampRegressed);
    }
    Ok(())
}

/// Verify a payload-free extension proof from the prior witnessed head.
pub fn verify_checkpoint_extension(
    previous: Option<&OperationWalCheckpoint>,
    candidate: &OperationWalCheckpoint,
    extension: &OperationWalHeadExtension,
) -> Result<(), OperationWalAnchorError> {
    extension.verify(previous, candidate)
}

/// Require the local WAL to equal the most recently witnessed head exactly.
///
/// A local WAL behind the checkpoint is a rollback. A local WAL ahead of the
/// checkpoint has an unanchored suffix and cannot authorize new privileged
/// mutations until that suffix is witnessed.
pub fn verify_local_wal_head(
    checkpoint: &OperationWalCheckpoint,
    local_sequence: u64,
    local_head_hash: [u8; 32],
    local_merkle_root: [u8; 32],
) -> Result<(), OperationWalAnchorError> {
    validate_checkpoint(checkpoint)?;
    if local_sequence < checkpoint.wal_sequence {
        return Err(OperationWalAnchorError::LocalWalRollback {
            checkpoint: checkpoint.wal_sequence,
            local: local_sequence,
        });
    }
    if local_sequence > checkpoint.wal_sequence {
        return Err(OperationWalAnchorError::UnanchoredWalSuffix {
            checkpoint: checkpoint.wal_sequence,
            local: local_sequence,
        });
    }
    if local_head_hash != checkpoint.wal_head_hash
        || local_merkle_root != checkpoint.wal_merkle_root
    {
        return Err(OperationWalAnchorError::LocalWalHeadMismatch);
    }
    Ok(())
}

/// Verify that every witness signature comes from a caller-pinned key and
/// signs the exact checkpoint, requiring a nonzero quorum.
pub fn verify_checkpoint_witness_quorum(
    bundle: &OperationWalWitnessBundle,
    policy: &OperationWalWitnessPolicy,
) -> Result<(), OperationWalAnchorError> {
    policy.validate()?;
    let digest = operation_wal_checkpoint_fingerprint(&bundle.checkpoint)?;
    verify_witness_signatures(
        digest,
        bundle.checkpoint.timestamp_unix_secs,
        &bundle.witnesses,
        policy,
    )
}

/// Verify the independent witness quorum over a sequence lease.
pub fn verify_sequence_lease_witness_quorum(
    bundle: &OperationSequenceLeaseBundle,
    policy: &OperationWalWitnessPolicy,
) -> Result<(), OperationWalAnchorError> {
    policy.validate()?;
    let digest = operation_sequence_lease_fingerprint(&bundle.lease)?;
    verify_witness_signatures(digest, bundle.lease.issued_at_unix_secs, &bundle.witnesses, policy)
}

fn verify_witness_signatures(
    statement_digest: [u8; 32],
    statement_timestamp: u64,
    signatures: &[OperationWalWitnessSignature],
    policy: &OperationWalWitnessPolicy,
) -> Result<(), OperationWalAnchorError> {
    if signatures.len() > MAX_OPERATION_WAL_WITNESSES {
        return Err(OperationWalAnchorError::TooManyWitnesses);
    }
    let trusted = policy.trusted_witness_keys.iter().copied().collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for witness in signatures {
        if witness.statement_digest != statement_digest {
            return Err(OperationWalAnchorError::StatementDigestMismatch);
        }
        if witness.observed_at_unix_secs < statement_timestamp {
            return Err(OperationWalAnchorError::WitnessPredatesStatement);
        }
        if !observed.insert(witness.witness_public_key) {
            return Err(OperationWalAnchorError::DuplicateWitness);
        }
        if !trusted.contains(&witness.witness_public_key) {
            return Err(OperationWalAnchorError::UntrustedWitness);
        }
        let key = VerifyingKey::from_bytes(&witness.witness_public_key)
            .map_err(|_| OperationWalAnchorError::BadWitnessPublicKey)?;
        let message = operation_wal_witness_message(
            &statement_digest,
            &witness.witness_public_key,
            witness.observed_at_unix_secs,
        );
        key.verify(&message, &Signature::from_bytes(&witness.signature))
            .map_err(|_| OperationWalAnchorError::BadWitnessSignature)?;
    }
    if observed.len() < policy.minimum_quorum {
        return Err(OperationWalAnchorError::QuorumNotMet {
            verified: observed.len(),
            required: policy.minimum_quorum,
        });
    }
    Ok(())
}

/// Verify checkpoint or lease freshness against a deployment-specific SLA.
pub fn verify_anchor_freshness(
    statement_timestamp: u64,
    now_unix_secs: u64,
    policy: OperationWalAnchorFreshnessPolicy,
) -> Result<(), OperationWalAnchorError> {
    if statement_timestamp > now_unix_secs.saturating_add(policy.max_future_skew_secs) {
        return Err(OperationWalAnchorError::AnchorFromFuture);
    }
    if let Some(max_age) = policy.max_age_secs {
        if now_unix_secs.saturating_sub(statement_timestamp) > max_age {
            return Err(OperationWalAnchorError::AnchorTooOld);
        }
    }
    Ok(())
}

/// Verify that a sequence lease is the immediate, non-overlapping successor.
pub fn verify_sequence_lease_successor(
    previous: &OperationSequenceLease,
    candidate: &OperationSequenceLease,
) -> Result<(), OperationWalAnchorError> {
    validate_lease(previous)?;
    validate_lease(candidate)?;
    if previous.session_fingerprint != candidate.session_fingerprint {
        return Err(OperationWalAnchorError::SessionMismatch);
    }
    if candidate.authority_epoch < previous.authority_epoch {
        return Err(OperationWalAnchorError::AuthorityEpochRegressed);
    }
    if candidate.lease_generation != previous.lease_generation.checked_add(1)
        .ok_or(OperationWalAnchorError::SequenceExhausted)?
    {
        return Err(OperationWalAnchorError::NonMonotonicLease);
    }
    if candidate.previous_lease_fingerprint != operation_sequence_lease_fingerprint(previous)? {
        return Err(OperationWalAnchorError::LeaseRangeReuse);
    }
    let expected_first = previous.last_operation_sequence.checked_add(1)
        .ok_or(OperationWalAnchorError::SequenceExhausted)?;
    if candidate.first_operation_sequence != expected_first
        || candidate.last_operation_sequence < candidate.first_operation_sequence
    {
        return Err(OperationWalAnchorError::LeaseRangeReuse);
    }
    if candidate.issued_at_unix_secs < previous.issued_at_unix_secs {
        return Err(OperationWalAnchorError::InvalidLeaseLifetime);
    }
    Ok(())
}

/// Verify a witnessed lease for one operation in the current process/session.
/// Verify a lease once for the active process/session and return an opaque token.
///
/// Runtime send paths should call this when acquiring/renewing a lease, then
/// use VerifiedOperationSequenceLease::contains for each operation. This
/// avoids running the witness-signature quorum on every frame.
pub fn verify_sequence_lease_for_use(
    bundle: &OperationSequenceLeaseBundle,
    policy: &OperationWalWitnessPolicy,
    freshness: OperationWalAnchorFreshnessPolicy,
    now_unix_secs: u64,
    session_fingerprint: [u8; 32],
    authority_epoch: u64,
    owner_boot_fingerprint: [u8; 32],
) -> Result<VerifiedOperationSequenceLease, OperationWalAnchorError> {
    verify_sequence_lease_witness_quorum(bundle, policy)?;
    let lease = &bundle.lease;
    if lease.session_fingerprint != session_fingerprint {
        return Err(OperationWalAnchorError::SessionMismatch);
    }
    if lease.authority_epoch != authority_epoch {
        return Err(OperationWalAnchorError::AuthorityEpochMismatch);
    }
    if lease.owner_boot_fingerprint != owner_boot_fingerprint {
        return Err(OperationWalAnchorError::BootFingerprintMismatch);
    }
    verify_anchor_freshness(lease.issued_at_unix_secs, now_unix_secs, freshness)?;
    if now_unix_secs < lease.issued_at_unix_secs || now_unix_secs > lease.expires_at_unix_secs {
        return Err(OperationWalAnchorError::LeaseExpired);
    }
    let remaining_secs = lease.expires_at_unix_secs.saturating_sub(now_unix_secs);
    let monotonic_expiry = Instant::now()
        .checked_add(Duration::from_secs(remaining_secs))
        .ok_or(OperationWalAnchorError::LeaseExpired)?;
    Ok(VerifiedOperationSequenceLease { lease: lease.clone(), monotonic_expiry })
}

fn validate_checkpoint(checkpoint: &OperationWalCheckpoint) -> Result<(), OperationWalAnchorError> {
    if checkpoint.schema != OPERATION_WAL_CHECKPOINT_SCHEMA {
        return Err(OperationWalAnchorError::UnsupportedSchema);
    }
    if checkpoint.witness_sequence == 0 {
        return Err(OperationWalAnchorError::NonMonotonicWitnessSequence);
    }
    if checkpoint.wal_merkle_tree_size != checkpoint.wal_sequence {
        return Err(OperationWalAnchorError::MerkleTreeSizeMismatch);
    }
    if checkpoint.wal_merkle_tree_size == 0
        && checkpoint.wal_merkle_root != operation_wal_merkle_root(&[])
    {
        return Err(OperationWalAnchorError::GenesisMerkleRootMismatch);
    }
    if (checkpoint.witness_sequence == 1)
        != (checkpoint.previous_checkpoint_fingerprint == [0; 32])
    {
        return Err(OperationWalAnchorError::PreviousCheckpointMismatch);
    }
    if checkpoint.wal_sequence == 0 && checkpoint.wal_head_hash != [0; 32] {
        return Err(OperationWalAnchorError::GenesisHeadMismatch);
    }
    Ok(())
}

fn validate_lease(lease: &OperationSequenceLease) -> Result<(), OperationWalAnchorError> {
    if lease.schema != OPERATION_SEQUENCE_LEASE_SCHEMA {
        return Err(OperationWalAnchorError::UnsupportedSchema);
    }
    let span = lease.last_operation_sequence.checked_sub(lease.first_operation_sequence)
        .and_then(|v| v.checked_add(1))
        .ok_or(OperationWalAnchorError::InvalidLeaseSpan)?;
    if lease.first_operation_sequence == 0 || span == 0
        || span > MAX_OPERATION_SEQUENCE_LEASE_SPAN
    {
        return Err(OperationWalAnchorError::InvalidLeaseSpan);
    }
    if lease.expires_at_unix_secs <= lease.issued_at_unix_secs {
        return Err(OperationWalAnchorError::InvalidLeaseLifetime);
    }
    if (lease.lease_generation == 1) != (lease.previous_lease_fingerprint == [0; 32]) {
        return Err(OperationWalAnchorError::LeaseRangeReuse);
    }
    if lease.owner_boot_fingerprint == [0; 32] {
        return Err(OperationWalAnchorError::InvalidBootFingerprint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn witness_policy() -> OperationWalWitnessPolicy {
        OperationWalWitnessPolicy {
            trusted_witness_keys: vec![
                signing_key(1).verifying_key().to_bytes(),
                signing_key(2).verifying_key().to_bytes(),
                signing_key(3).verifying_key().to_bytes(),
            ],
            minimum_quorum: 2,
        }
    }

    fn checkpoint(
        previous: Option<&OperationWalCheckpoint>,
        wal_sequence: u64,
        wal_head_hash: [u8; 32],
        timestamp: u64,
    ) -> OperationWalCheckpoint {
        let record_hashes: Vec<[u8; 32]> = (0..wal_sequence)
            .map(|sequence| [(sequence as u8).wrapping_add(1); 32])
            .collect();
        let merkle_root = operation_wal_merkle_root(&record_hashes);
        OperationWalCheckpoint::next(
            previous,
            [7; 32],
            11,
            wal_sequence,
            wal_head_hash,
            wal_sequence,
            merkle_root,
            timestamp,
        )
        .unwrap_or_else(|error| panic!("checkpoint construction failed: {error:?}"))
    }

    fn merkle_extension(
        record_hashes: &[[u8; 32]],
        old_tree_size: u64,
    ) -> OperationWalCheckpointExtension {
        OperationWalCheckpointExtension::MerkleConsistency(
            crate::operation_wal_merkle::generate_operation_wal_consistency_proof(
                record_hashes,
                old_tree_size,
            )
            .unwrap_or_else(|error| panic!("Merkle proof generation failed: {error:?}")),
        )
    }

    fn witnessed_checkpoint(checkpoint: OperationWalCheckpoint) -> OperationWalWitnessBundle {
        let mut bundle = OperationWalWitnessBundle::new(checkpoint)
            .unwrap_or_else(|error| panic!("bundle creation failed: {error:?}"));
        bundle.sign_with(&signing_key(1), bundle.checkpoint.timestamp_unix_secs + 1)
            .unwrap_or_else(|error| panic!("witness one failed: {error:?}"));
        bundle.sign_with(&signing_key(2), bundle.checkpoint.timestamp_unix_secs + 2)
            .unwrap_or_else(|error| panic!("witness two failed: {error:?}"));
        bundle
    }


    /// Deterministic in-memory reference implementation for CAS protocol tests.
    ///
    /// This is not a production independent witness store. It deliberately
    /// keeps the same atomic mutex around compare/validate/persist so the
    /// tests can exercise single-winner semantics and crash-response readback.
    struct MemoryWitnessStore {
        checkpoints: std::sync::Mutex<
            std::collections::HashMap<([u8; 32], u64), OperationWalWitnessBundle>,
        >,
        leases: std::sync::Mutex<
            std::collections::HashMap<[u8; 32], OperationSequenceLeaseBundle>,
        >,
        keys: [SigningKey; 2],
    }

    impl MemoryWitnessStore {
        fn new() -> Self {
            Self {
                checkpoints: std::sync::Mutex::new(std::collections::HashMap::new()),
                leases: std::sync::Mutex::new(std::collections::HashMap::new()),
                keys: [signing_key(1), signing_key(2)],
            }
        }

        fn sign_checkpoint(
            &self,
            checkpoint: OperationWalCheckpoint,
        ) -> Result<OperationWalWitnessBundle, OperationWalWitnessStoreError> {
            let mut bundle = OperationWalWitnessBundle::new(checkpoint)
                .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            for key in &self.keys {
                bundle
                    .sign_with(key, bundle.checkpoint.timestamp_unix_secs)
                    .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            }
            Ok(bundle)
        }

        fn sign_lease(
            &self,
            lease: OperationSequenceLease,
        ) -> Result<OperationSequenceLeaseBundle, OperationWalWitnessStoreError> {
            let mut bundle = OperationSequenceLeaseBundle::new(lease)
                .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            for key in &self.keys {
                bundle
                    .sign_with(key, bundle.lease.issued_at_unix_secs)
                    .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            }
            Ok(bundle)
        }
    }

    impl OperationWalWitnessStore for MemoryWitnessStore {
        fn latest_checkpoint(
            &self,
            session_fingerprint: [u8; 32],
            clock_domain: u64,
        ) -> Result<Option<OperationWalWitnessBundle>, OperationWalWitnessStoreError> {
            self.checkpoints
                .lock()
                .map_err(|_| OperationWalWitnessStoreError::Unavailable)
                .map(|state| state.get(&(session_fingerprint, clock_domain)).cloned())
        }

        fn compare_and_advance_checkpoint(
            &self,
            expected_previous_fingerprint: Option<[u8; 32]>,
            candidate: OperationWalCheckpoint,
            extension: OperationWalCheckpointExtension,
        ) -> Result<OperationWalWitnessBundle, OperationWalWitnessStoreError> {
            let key = (candidate.session_fingerprint, candidate.clock_domain);
            let mut state = self
                .checkpoints
                .lock()
                .map_err(|_| OperationWalWitnessStoreError::Unavailable)?;
            let previous = state.get(&key).cloned();
            let actual_previous_fingerprint = previous
                .as_ref()
                .map(|bundle| operation_wal_checkpoint_fingerprint(&bundle.checkpoint))
                .transpose()
                .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            if actual_previous_fingerprint != expected_previous_fingerprint {
                return Err(OperationWalWitnessStoreError::StaleExpectedHead);
            }
            extension
                .verify(previous.as_ref().map(|bundle| &bundle.checkpoint), &candidate)
                .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            let bundle = self.sign_checkpoint(candidate)?;
            state.insert(key, bundle.clone());
            Ok(bundle)
        }

        fn latest_sequence_lease(
            &self,
            session_fingerprint: [u8; 32],
        ) -> Result<Option<OperationSequenceLeaseBundle>, OperationWalWitnessStoreError> {
            self.leases
                .lock()
                .map_err(|_| OperationWalWitnessStoreError::Unavailable)
                .map(|state| state.get(&session_fingerprint).cloned())
        }

        fn compare_and_advance_sequence_lease(
            &self,
            expected_previous_fingerprint: Option<[u8; 32]>,
            candidate: OperationSequenceLease,
        ) -> Result<OperationSequenceLeaseBundle, OperationWalWitnessStoreError> {
            let session = candidate.session_fingerprint;
            let mut state = self
                .leases
                .lock()
                .map_err(|_| OperationWalWitnessStoreError::Unavailable)?;
            let previous = state.get(&session).cloned();
            let actual_previous_fingerprint = previous
                .as_ref()
                .map(|bundle| operation_sequence_lease_fingerprint(&bundle.lease))
                .transpose()
                .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            if actual_previous_fingerprint != expected_previous_fingerprint {
                return Err(OperationWalWitnessStoreError::StaleExpectedHead);
            }
            if let Some(previous) = previous.as_ref() {
                verify_sequence_lease_successor(&previous.lease, &candidate)
                    .map_err(|_| OperationWalWitnessStoreError::CandidateRejected)?;
            } else if candidate.lease_generation != 1
                || candidate.previous_lease_fingerprint != [0; 32]
                || candidate.first_operation_sequence != 1
            {
                return Err(OperationWalWitnessStoreError::CandidateRejected);
            }
            let bundle = self.sign_lease(candidate)?;
            state.insert(session, bundle.clone());
            Ok(bundle)
        }
    }

    #[test]
    fn checkpoint_quorum_verifies_and_rejects_an_untrusted_witness() {
        let bundle = witnessed_checkpoint(checkpoint(None, 0, [0; 32], 100));
        assert!(verify_checkpoint_witness_quorum(&bundle, &witness_policy()).is_ok());

        let mut bad = bundle.clone();
        bad.witnesses[0].witness_public_key = signing_key(9).verifying_key().to_bytes();
        assert_eq!(
            verify_checkpoint_witness_quorum(&bad, &witness_policy()),
            Err(OperationWalAnchorError::UntrustedWitness)
        );
    }

    #[test]
    fn checkpoint_successor_rejects_fork_rollback_and_wrong_parent() {
        let first = checkpoint(None, 3, [3; 32], 100);
        let second = checkpoint(Some(&first), 5, [5; 32], 101);
        assert!(verify_checkpoint_successor(&first, &second).is_ok());

        let fork = checkpoint(Some(&first), 3, [8; 32], 101);
        assert!(matches!(
            verify_checkpoint_successor(&first, &fork),
            Err(OperationWalAnchorError::WalFork { sequence: 3 })
        ));
        let rollback = checkpoint(Some(&first), 2, [2; 32], 101);
        assert!(matches!(
            verify_checkpoint_successor(&first, &rollback),
            Err(OperationWalAnchorError::WalSequenceRegressed { .. })
        ));
        let mut wrong_parent = second.clone();
        wrong_parent.previous_checkpoint_fingerprint = [99; 32];
        assert_eq!(
            verify_checkpoint_successor(&first, &wrong_parent),
            Err(OperationWalAnchorError::PreviousCheckpointMismatch)
        );
    }

    #[test]
    fn extension_proof_checks_every_link_and_terminal_head() {
        let first = checkpoint(None, 2, [2; 32], 100);
        let candidate = checkpoint(Some(&first), 4, [4; 32], 101);
        let extension = OperationWalHeadExtension {
            base_sequence: 2,
            base_head_hash: [2; 32],
            records: vec![
                OperationWalHeadRecord { sequence: 3, previous_hash: [2; 32], record_hash: [3; 32] },
                OperationWalHeadRecord { sequence: 4, previous_hash: [3; 32], record_hash: [4; 32] },
            ],
        };
        assert!(verify_checkpoint_extension(Some(&first), &candidate, &extension).is_ok());
        let mut broken = extension;
        broken.records[1].previous_hash = [88; 32];
        assert_eq!(
            verify_checkpoint_extension(Some(&first), &candidate, &broken),
            Err(OperationWalAnchorError::ExtensionBrokenLink { sequence: 4 })
        );
    }

    #[test]
    fn local_head_must_equal_latest_witnessed_checkpoint() {
        let checkpoint = checkpoint(None, 10, [10; 32], 100);
        assert!(verify_local_wal_head(
            &checkpoint, 10, [10; 32], checkpoint.wal_merkle_root
        ).is_ok());
        assert!(matches!(
            verify_local_wal_head(&checkpoint, 9, [9; 32], checkpoint.wal_merkle_root),
            Err(OperationWalAnchorError::LocalWalRollback { .. })
        ));
        assert_eq!(
            verify_local_wal_head(&checkpoint, 10, [9; 32], checkpoint.wal_merkle_root),
            Err(OperationWalAnchorError::LocalWalHeadMismatch)
        );
        assert_eq!(
            verify_local_wal_head(&checkpoint, 10, [10; 32], [99; 32]),
            Err(OperationWalAnchorError::LocalWalHeadMismatch)
        );
        assert!(matches!(
            verify_local_wal_head(&checkpoint, 11, [11; 32], checkpoint.wal_merkle_root),
            Err(OperationWalAnchorError::UnanchoredWalSuffix { .. })
        ));
    }

    #[test]
    fn sequence_leases_are_monotonic_and_process_bound() {
        let first = OperationSequenceLease::next(
            None, [7; 32], 4, [10; 32], 10_000, 100, 200,
        ).unwrap_or_else(|error| panic!("first lease failed: {error:?}"));
        assert_eq!(first.first_operation_sequence, 1);
        assert_eq!(first.last_operation_sequence, 10_000);

        let second = OperationSequenceLease::next(
            Some(&first), [7; 32], 5, [11; 32], 10_000, 201, 301,
        ).unwrap_or_else(|error| panic!("second lease failed: {error:?}"));
        assert_eq!(second.first_operation_sequence, 10_001);
        assert_eq!(second.last_operation_sequence, 20_000);
        assert!(verify_sequence_lease_successor(&first, &second).is_ok());

        let mut bundle = OperationSequenceLeaseBundle::new(first)
            .unwrap_or_else(|error| panic!("lease bundle failed: {error:?}"));
        bundle.sign_with(&signing_key(1), 101)
            .unwrap_or_else(|error| panic!("lease witness one failed: {error:?}"));
        bundle.sign_with(&signing_key(2), 102)
            .unwrap_or_else(|error| panic!("lease witness two failed: {error:?}"));
        let policy = witness_policy();
        let verified = verify_sequence_lease_for_use(
            &bundle,
            &policy,
            OperationWalAnchorFreshnessPolicy::default(),
            150,
            [7; 32],
            4,
            [10; 32],
        ).unwrap_or_else(|error| panic!("lease verification failed: {error:?}"));
        assert!(verified.contains(9_999));
        assert!(!verified.contains(10_001));
        assert_eq!(verified.first_operation_sequence(), 1);
        assert_eq!(verified.last_operation_sequence(), 10_000);
        assert_eq!(
            verify_sequence_lease_for_use(
                &bundle,
                &policy,
                OperationWalAnchorFreshnessPolicy::default(),
                150,
                [7; 32],
                4,
                [99; 32],
            ).err(),
            Some(OperationWalAnchorError::BootFingerprintMismatch)
        );
    }

    #[test]
    fn witness_store_atomically_advances_checkpoint_and_supports_readback() {
        let store = MemoryWitnessStore::new();
        let first = checkpoint(None, 2, [2; 32], 100);
        let first_extension = merkle_extension(&[[1; 32], [2; 32]], 0);
        let first_bundle = store
            .compare_and_advance_checkpoint(None, first, first_extension)
            .unwrap_or_else(|error| panic!("first checkpoint advance failed: {error:?}"));
        assert!(verify_checkpoint_witness_quorum(&first_bundle, &witness_policy()).is_ok());

        let second = checkpoint(Some(&first_bundle.checkpoint), 4, [4; 32], 101);
        let second_extension = merkle_extension(&[[1; 32], [2; 32], [3; 32], [4; 32]], 2);
        let expected = operation_wal_checkpoint_fingerprint(&first_bundle.checkpoint)
            .unwrap_or_else(|error| panic!("checkpoint fingerprint failed: {error:?}"));
        let second_bundle = store
            .compare_and_advance_checkpoint(Some(expected), second, second_extension)
            .unwrap_or_else(|error| panic!("second checkpoint advance failed: {error:?}"));
        assert_eq!(second_bundle.checkpoint.witness_sequence, 2);

        let retained = store
            .latest_checkpoint([7; 32], 11)
            .unwrap_or_else(|error| panic!("checkpoint readback failed: {error:?}"))
            .unwrap_or_else(|| panic!("latest checkpoint missing"));
        assert_eq!(retained, second_bundle);
        assert!(verify_checkpoint_witness_quorum(&retained, &witness_policy()).is_ok());
    }

    #[test]
    fn witness_store_rejects_broken_extension_without_mutating_head() {
        let store = MemoryWitnessStore::new();
        let candidate = checkpoint(None, 2, [2; 32], 100);
        let mut broken = merkle_extension(&[[1; 32], [2; 32]], 0);
        if let OperationWalCheckpointExtension::MerkleConsistency(proof) = &mut broken {
            proof.nodes[0][0] ^= 1;
        }
        assert_eq!(
            store.compare_and_advance_checkpoint(None, candidate, broken),
            Err(OperationWalWitnessStoreError::CandidateRejected)
        );
        assert!(
            store.latest_checkpoint([7; 32], 11)
                .unwrap_or_else(|error| panic!("checkpoint readback failed: {error:?}"))
                .is_none(),
            "invalid extension must not advance witness state"
        );
    }

    #[test]
    fn concurrent_checkpoint_compare_and_advance_has_one_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = Arc::new(MemoryWitnessStore::new());
        let candidate = checkpoint(None, 2, [2; 32], 100);
        let extension = merkle_extension(&[[1; 32], [2; 32]], 0);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_store = Arc::clone(&store);
            let worker_barrier = Arc::clone(&barrier);
            let worker_candidate = candidate.clone();
            let worker_extension = extension.clone();
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                worker_store.compare_and_advance_checkpoint(
                    None,
                    worker_candidate,
                    worker_extension,
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or_else(|_| panic!("witness worker panicked")))
            .collect();
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let stale = results
            .iter()
            .filter(|result| {
                result.as_ref().err() == Some(&OperationWalWitnessStoreError::StaleExpectedHead)
            })
            .count();
        assert_eq!(successes, 1);
        assert_eq!(stale, 1);
        let retained = store
            .latest_checkpoint([7; 32], 11)
            .unwrap_or_else(|error| panic!("checkpoint readback failed: {error:?}"));
        assert!(retained.is_some());
    }

    #[test]
    fn witness_store_reserves_nonoverlapping_leases_and_readback_resolves_lost_reply() {
        let store = MemoryWitnessStore::new();
        let first = OperationSequenceLease::next(
            None, [7; 32], 4, [10; 32], 100, 100, 200,
        ).unwrap_or_else(|error| panic!("first lease proposal failed: {error:?}"));
        let first_bundle = store
            .compare_and_advance_sequence_lease(None, first)
            .unwrap_or_else(|error| panic!("first lease advance failed: {error:?}"));
        assert!(verify_sequence_lease_witness_quorum(&first_bundle, &witness_policy()).is_ok());

        let previous_fingerprint = operation_sequence_lease_fingerprint(&first_bundle.lease)
            .unwrap_or_else(|error| panic!("lease fingerprint failed: {error:?}"));
        let second = OperationSequenceLease::next(
            Some(&first_bundle.lease), [7; 32], 5, [11; 32], 100, 201, 301,
        ).unwrap_or_else(|error| panic!("second lease proposal failed: {error:?}"));

        // Simulate a caller that lost the successful response: read back the
        // independently retained lease instead of issuing a different range.
        let _response_lost_after_commit = store
            .compare_and_advance_sequence_lease(Some(previous_fingerprint), second)
            .unwrap_or_else(|error| panic!("second lease advance failed: {error:?}"));
        let retained = store
            .latest_sequence_lease([7; 32])
            .unwrap_or_else(|error| panic!("lease readback failed: {error:?}"))
            .unwrap_or_else(|| panic!("latest lease missing"));
        assert_eq!(retained.lease.lease_generation, 2);
        assert_eq!(retained.lease.previous_lease_fingerprint, previous_fingerprint);
        assert_eq!(retained.lease.first_operation_sequence, 101);
        assert_eq!(retained.lease.last_operation_sequence, 200);
        assert_eq!(
            store.compare_and_advance_sequence_lease(None, retained.lease.clone()),
            Err(OperationWalWitnessStoreError::StaleExpectedHead)
        );
    }

    #[test]
    fn concurrent_sequence_lease_reservations_have_one_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = Arc::new(MemoryWitnessStore::new());
        let candidate = OperationSequenceLease::next(
            None,
            [7; 32],
            4,
            [10; 32],
            100,
            100,
            200,
        ).unwrap_or_else(|error| panic!("lease proposal failed: {error:?}"));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_store = Arc::clone(&store);
            let worker_barrier = Arc::clone(&barrier);
            let worker_candidate = candidate.clone();
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                worker_store.compare_and_advance_sequence_lease(None, worker_candidate)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or_else(|_| panic!("lease worker panicked")))
            .collect();
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let stale = results
            .iter()
            .filter(|result| {
                result.as_ref().err() == Some(&OperationWalWitnessStoreError::StaleExpectedHead)
            })
            .count();
        assert_eq!(successes, 1);
        assert_eq!(stale, 1);

        let retained = store
            .latest_sequence_lease([7; 32])
            .unwrap_or_else(|error| panic!("lease readback failed: {error:?}"))
            .unwrap_or_else(|| panic!("reserved lease missing"));
        assert_eq!(retained.lease.first_operation_sequence, 1);
        assert_eq!(retained.lease.last_operation_sequence, 100);
    }

    #[test]
    fn invalid_lease_ranges_and_freshness_fail_closed() {
        assert_eq!(
            OperationSequenceLease::next(None, [7; 32], 1, [1; 32], 0, 10, 20),
            Err(OperationWalAnchorError::InvalidLeaseSpan)
        );
        assert_eq!(
            OperationSequenceLease::next(None, [7; 32], 1, [1; 32], 10, 20, 20),
            Err(OperationWalAnchorError::InvalidLeaseLifetime)
        );
        let policy = OperationWalAnchorFreshnessPolicy {
            max_age_secs: Some(30),
            max_future_skew_secs: 2,
        };
        assert_eq!(
            verify_anchor_freshness(10, 100, policy),
            Err(OperationWalAnchorError::AnchorTooOld)
        );
        assert_eq!(
            verify_anchor_freshness(105, 100, policy),
            Err(OperationWalAnchorError::AnchorFromFuture)
        );
    }
    #[test]
    fn verified_sequence_lease_expires_on_monotonic_deadline() {
        let lease = OperationSequenceLease::next(
            None, [7; 32], 4, [10; 32], 100, 100, 200,
        )
        .unwrap_or_else(|error| panic!("lease failed: {error:?}"));
        let expired = VerifiedOperationSequenceLease {
            lease,
            monotonic_expiry: Instant::now() - Duration::from_secs(1),
        };
        assert!(!expired.contains(1));
        assert_eq!(
            expired.validate_sequence(1),
            Err(OperationWalAnchorError::OperationSequenceOutsideLease)
        );
    }

}
