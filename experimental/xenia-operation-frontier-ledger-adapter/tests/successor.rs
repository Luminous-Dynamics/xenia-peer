// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{
    Chain, CheckpointFreshnessPolicy, ConsentEventRecord, ConsentKind, LedgerCheckpoint,
    checkpoint_fingerprint,
};
use xenia_operation_frontier_ledger_adapter::verify_operation_frontier_witness_successor_v1;
use xenia_operation_frontier_ledger_witness::{
    LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
    OperationFrontierLedgerWitnessV1,
};
use xenia_operation_store_frontier::OperationStoreFrontierV1;

fn frontier(sequence: u64, previous: [u8; 32], recorded_at_ms: u64) -> OperationStoreFrontierV1 {
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
    key: &SigningKey,
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
    OperationFrontierLedgerWitnessV1::sign_ed25519(
        OperationFrontierLedgerWitnessPayloadV1::new(
            frontier.anchor(witnessed_at_ms).unwrap(),
            binding,
            witness_sequence,
            previous_witness_digest,
            witnessed_at_ms,
        )
        .unwrap(),
        key,
    )
    .unwrap()
}

#[test]
fn historical_checkpoint_may_age_out_while_fresh_candidate_still_verifies() {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let mut chain = Chain::new(key.clone());
    chain
        .append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            kind: ConsentKind::Approval,
            scope: "witness-successor-old".to_string(),
        })
        .unwrap();
    let previous_checkpoint = chain.sign_checkpoint(10);

    chain
        .append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(3),
            kind: ConsentKind::Revocation,
            scope: "witness-successor-new".to_string(),
        })
        .unwrap();
    let candidate_checkpoint = chain.sign_checkpoint(100);
    let entries = chain.iter().cloned().collect::<Vec<_>>();

    let f0 = frontier(0, [0u8; 32], 10_000);
    let previous_witness = witness_for(&key, &previous_checkpoint, &f0, 0, [0u8; 32], 10_000);
    let f1 = frontier(1, f0.frontier_digest().unwrap(), 100_000);
    let candidate_witness = witness_for(
        &key,
        &candidate_checkpoint,
        &f1,
        1,
        previous_witness.witness_digest().unwrap(),
        100_000,
    );

    // At now=100, the old checkpoint age is 90 seconds and would fail this candidate SLA.
    // Successor verification intentionally treats it as historical evidence while applying the
    // 20-second maximum age to the current candidate checkpoint.
    let policy = CheckpointFreshnessPolicy {
        max_age_secs: Some(20),
        max_future_skew_secs: 5,
    };
    let verified = verify_operation_frontier_witness_successor_v1(
        &previous_witness,
        &previous_checkpoint,
        &candidate_witness,
        &candidate_checkpoint,
        &entries,
        key.verifying_key().to_bytes(),
        &[f0, f1],
        100,
        policy,
    )
    .unwrap();

    assert_eq!(verified.witness_sequence(), 1);
    assert_eq!(verified.ledger_entry_count(), 2);
}
