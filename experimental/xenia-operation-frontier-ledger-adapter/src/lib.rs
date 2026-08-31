// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authority-owning verification for operation-frontier ledger witnesses.
//!
//! The permissive witness crate proves only witness syntax/signature/lineage. This adapter owns
//! the actual trust decision by requiring a real Xenia ledger checkpoint, a caller-retained
//! trusted ledger key, the signed ledger entries being recovered, and retained operation-store
//! frontiers. Only their composition yields [`VerifiedOperationFrontierWitnessV1`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::VerifyingKey;
use thiserror::Error;
use xenia_ledger::{
    CheckpointContinuityError, CheckpointError, CheckpointFreshnessPolicy, LedgerCheckpoint,
    LedgerEntry, Verifier, checkpoint_fingerprint,
};
use xenia_operation_frontier_ledger_witness::{
    FrontierLedgerWitnessError, LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessV1,
};
use xenia_operation_store_frontier::{
    OperationStoreFrontierError, OperationStoreFrontierV1, verify_anchor_lineage,
};

/// Successful composition of one signed witness with authenticated ledger/frontier history.
///
/// Fields are intentionally private and the type is not serializable. Possessing serialized
/// witness bytes is therefore not equivalent to possessing a successful recovery verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOperationFrontierWitnessV1 {
    witness_digest: [u8; 32],
    checkpoint_fingerprint: [u8; 32],
    frontier_digest: [u8; 32],
    witness_sequence: u64,
    ledger_entry_count: u64,
}

impl VerifiedOperationFrontierWitnessV1 {
    /// Digest of the exact signed witness that passed the composition gate.
    pub const fn witness_digest(self) -> [u8; 32] {
        self.witness_digest
    }

    /// Fingerprint of the exact real ledger checkpoint that passed the gate.
    pub const fn checkpoint_fingerprint(self) -> [u8; 32] {
        self.checkpoint_fingerprint
    }

    /// Exact externally witnessed operation-frontier digest.
    pub const fn frontier_digest(self) -> [u8; 32] {
        self.frontier_digest
    }

    /// Monotonic sequence of the verified witness lineage.
    pub const fn witness_sequence(self) -> u64 {
        self.witness_sequence
    }

    /// Ledger entry count committed by the verified checkpoint.
    pub const fn ledger_entry_count(self) -> u64 {
        self.ledger_entry_count
    }
}

/// Verify one externally retained witness against real local ledger and operation-frontier state.
///
/// This gate proves all of the following together:
///
/// 1. `checkpoint` has a valid Xenia checkpoint signature and satisfies freshness policy;
/// 2. the checkpoint public key equals `trusted_ledger_public_key`;
/// 3. `ledger_entries` is a valid signed ledger and contains that checkpoint as an exact prefix;
/// 4. the witness signature validates under the checkpoint key;
/// 5. the witness checkpoint binding exactly equals the real checkpoint facts/fingerprint;
/// 6. the witness frontier anchor is an exact ancestor of `local_frontiers`.
///
/// It does not clear recovery state or authorize any external effect.
pub fn verify_operation_frontier_witness_v1(
    witness: &OperationFrontierLedgerWitnessV1,
    checkpoint: &LedgerCheckpoint,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
) -> Result<VerifiedOperationFrontierWitnessV1, OperationFrontierWitnessAdapterError> {
    verify_operation_frontier_witness_with_policy(
        witness,
        checkpoint,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )
}

/// Verify an exact successor pair using one current signed ledger and retained frontier history.
///
/// The previous checkpoint is treated as historical evidence and therefore has no maximum-age
/// requirement, while future-skew checks remain active. The candidate checkpoint uses the full
/// supplied freshness policy. Both checkpoints must be exact prefixes of the same signed ledger,
/// so a higher-height fork cannot pass merely because it carries a valid signature.
pub fn verify_operation_frontier_witness_successor_v1(
    previous_witness: &OperationFrontierLedgerWitnessV1,
    previous_checkpoint: &LedgerCheckpoint,
    candidate_witness: &OperationFrontierLedgerWitnessV1,
    candidate_checkpoint: &LedgerCheckpoint,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
) -> Result<VerifiedOperationFrontierWitnessV1, OperationFrontierWitnessAdapterError> {
    let historical_policy = CheckpointFreshnessPolicy {
        max_age_secs: None,
        max_future_skew_secs: freshness_policy.max_future_skew_secs,
    };
    verify_operation_frontier_witness_with_policy(
        previous_witness,
        previous_checkpoint,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        historical_policy,
    )?;
    let verified_candidate = verify_operation_frontier_witness_with_policy(
        candidate_witness,
        candidate_checkpoint,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )?;
    candidate_witness.validate_successor(previous_witness)?;
    Ok(verified_candidate)
}

fn verify_operation_frontier_witness_with_policy(
    witness: &OperationFrontierLedgerWitnessV1,
    checkpoint: &LedgerCheckpoint,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
) -> Result<VerifiedOperationFrontierWitnessV1, OperationFrontierWitnessAdapterError> {
    let trusted_key = VerifyingKey::from_bytes(&trusted_ledger_public_key)
        .map_err(|_| OperationFrontierWitnessAdapterError::MalformedTrustedLedgerKey)?;

    Verifier::verify_checkpoint_freshness(checkpoint, now_unix_secs, freshness_policy)?;
    Verifier::verify_checkpoint_prefix(checkpoint, ledger_entries, &trusted_key)?;

    let fingerprint = checkpoint_fingerprint(checkpoint)?;
    let expected_binding = LedgerCheckpointBindingV1::new(
        fingerprint,
        checkpoint.entry_count,
        checkpoint.head_hash,
        checkpoint.ledger_public_key,
        checkpoint.timestamp_unix_secs,
    )?;

    witness.validate()?;
    if witness.payload.ledger_checkpoint != expected_binding {
        return Err(OperationFrontierWitnessAdapterError::CheckpointBindingMismatch);
    }

    verify_anchor_lineage(&witness.payload.frontier_anchor, local_frontiers)?;

    Ok(VerifiedOperationFrontierWitnessV1 {
        witness_digest: witness.witness_digest()?,
        checkpoint_fingerprint: fingerprint,
        frontier_digest: witness.payload.frontier_anchor.frontier_digest,
        witness_sequence: witness.payload.witness_sequence,
        ledger_entry_count: checkpoint.entry_count,
    })
}

/// Fail-closed errors from the authority-owning witness composition gate.
#[derive(Debug, Error)]
pub enum OperationFrontierWitnessAdapterError {
    /// Caller-provided trusted ledger key bytes were not a valid Ed25519 public key.
    #[error("trusted ledger public key is malformed")]
    MalformedTrustedLedgerKey,
    /// Ledger checkpoint signature/fingerprint validation failed.
    #[error("ledger checkpoint rejected witness composition: {0}")]
    Checkpoint(#[from] CheckpointError),
    /// Checkpoint freshness, trusted-key, prefix, or ledger-chain continuity failed.
    #[error("ledger checkpoint continuity rejected witness composition: {0}")]
    CheckpointContinuity(#[from] CheckpointContinuityError),
    /// Witness syntax/signature/lineage validation failed.
    #[error("frontier witness rejected composition: {0}")]
    Witness(#[from] FrontierLedgerWitnessError),
    /// Signed witness named checkpoint facts different from the independently verified checkpoint.
    #[error("frontier witness checkpoint binding does not match the real verified checkpoint")]
    CheckpointBindingMismatch,
    /// Operation frontier ancestry did not contain the exact externally witnessed anchor.
    #[error("operation frontier ancestry rejected witness composition: {0}")]
    Frontier(#[from] OperationStoreFrontierError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind};
    use xenia_operation_frontier_ledger_witness::{
        OperationFrontierLedgerWitnessPayloadV1, OperationFrontierLedgerWitnessV1,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn ledger_with_one_entry(signing_key: SigningKey) -> Chain {
        let mut chain = Chain::new(signing_key);
        chain
            .append(ConsentEventRecord {
                source_id: [1u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(2),
                kind: ConsentKind::Approval,
                scope: "operation-frontier-witness-test".to_string(),
            })
            .unwrap();
        chain
    }

    fn frontier(
        sequence: u64,
        previous: [u8; 32],
        recorded_at_ms: u64,
    ) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [7u8; 16],
            0,
            sequence,
            [8u8; 32],
            previous,
            recorded_at_ms,
            &[],
            &[],
        )
        .unwrap()
    }

    fn witness_for(
        signing_key: &SigningKey,
        checkpoint: &LedgerCheckpoint,
        frontier: &OperationStoreFrontierV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
        witnessed_at_ms: u64,
    ) -> OperationFrontierLedgerWitnessV1 {
        let binding = LedgerCheckpointBindingV1::new(
            checkpoint_fingerprint(checkpoint).unwrap(),
            checkpoint.entry_count,
            checkpoint.head_hash,
            checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        )
        .unwrap();
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            frontier.anchor(witnessed_at_ms).unwrap(),
            binding,
            witness_sequence,
            previous_witness_digest,
            witnessed_at_ms,
        )
        .unwrap();
        OperationFrontierLedgerWitnessV1::sign_ed25519(payload, signing_key).unwrap()
    }

    fn entries(chain: &Chain) -> Vec<LedgerEntry> {
        chain.iter().cloned().collect()
    }

    fn policy() -> CheckpointFreshnessPolicy {
        CheckpointFreshnessPolicy {
            max_age_secs: Some(1_000),
            max_future_skew_secs: 10,
        }
    }

    #[test]
    fn real_checkpoint_ledger_prefix_and_frontier_ancestry_compose() {
        let signing_key = key(3);
        let chain = ledger_with_one_entry(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let witness = witness_for(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);

        let verified = verify_operation_frontier_witness_v1(
            &witness,
            &checkpoint,
            &entries(&chain),
            signing_key.verifying_key().to_bytes(),
            std::slice::from_ref(&f0),
            100,
            policy(),
        )
        .unwrap();

        assert_eq!(verified.frontier_digest(), f0.frontier_digest().unwrap());
        assert_eq!(verified.ledger_entry_count(), 1);
    }

    #[test]
    fn trusted_key_substitution_fails_before_frontier_acceptance() {
        let signing_key = key(3);
        let wrong_key = key(4);
        let chain = ledger_with_one_entry(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let witness = witness_for(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);

        assert!(verify_operation_frontier_witness_v1(
            &witness,
            &checkpoint,
            &entries(&chain),
            wrong_key.verifying_key().to_bytes(),
            std::slice::from_ref(&f0),
            100,
            policy(),
        )
        .is_err());
    }

    #[test]
    fn signed_but_forged_checkpoint_binding_fails() {
        let signing_key = key(3);
        let chain = ledger_with_one_entry(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let mut binding = LedgerCheckpointBindingV1::new(
            checkpoint_fingerprint(&checkpoint).unwrap(),
            checkpoint.entry_count,
            checkpoint.head_hash,
            checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        )
        .unwrap();
        binding.checkpoint_fingerprint = [99u8; 32];
        let witness = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                f0.anchor(100_000).unwrap(),
                binding,
                0,
                [0u8; 32],
                100_000,
            )
            .unwrap(),
            &signing_key,
        )
        .unwrap();

        assert!(matches!(
            verify_operation_frontier_witness_v1(
                &witness,
                &checkpoint,
                &entries(&chain),
                signing_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                100,
                policy(),
            ),
            Err(OperationFrontierWitnessAdapterError::CheckpointBindingMismatch)
        ));
    }

    #[test]
    fn local_store_rollback_behind_witness_fails() {
        let signing_key = key(3);
        let chain = ledger_with_one_entry(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 101_000);
        let witness = witness_for(&signing_key, &checkpoint, &f1, 0, [0u8; 32], 101_000);

        assert!(matches!(
            verify_operation_frontier_witness_v1(
                &witness,
                &checkpoint,
                &entries(&chain),
                signing_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                101,
                policy(),
            ),
            Err(OperationFrontierWitnessAdapterError::Frontier(_))
        ));
    }

    #[test]
    fn validly_signed_ledger_fork_is_not_a_prefix_of_recovered_ledger() {
        let signing_key = key(3);
        let original = ledger_with_one_entry(signing_key.clone());
        let original_entries = entries(&original);

        let mut fork = Chain::new(signing_key.clone());
        fork.append(ConsentEventRecord {
            source_id: [2u8; 32],
            session_id: Uuid::from_u128(3),
            request_id: Uuid::from_u128(4),
            kind: ConsentKind::Denial,
            scope: "fork".to_string(),
        })
        .unwrap();
        let fork_checkpoint = fork.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let fork_witness = witness_for(&signing_key, &fork_checkpoint, &f0, 0, [0u8; 32], 100_000);

        assert!(matches!(
            verify_operation_frontier_witness_v1(
                &fork_witness,
                &fork_checkpoint,
                &original_entries,
                signing_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                100,
                policy(),
            ),
            Err(OperationFrontierWitnessAdapterError::CheckpointContinuity(_))
        ));
    }
}
