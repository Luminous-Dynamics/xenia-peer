use xenia_operation_store_frontier::{
    AdmissionFrontierEntryV1, OperationStoreFrontierError, OperationStoreFrontierV1,
    ReceiptHeadFrontierEntryV1, validate_frontier_chain, verify_anchor_lineage,
};

fn empty_frontier() -> OperationStoreFrontierV1 {
    OperationStoreFrontierV1::from_state(
        [1u8; 16],
        0,
        0,
        [2u8; 32],
        [0u8; 32],
        100,
        &[],
        &[],
    )
    .unwrap()
}

fn one_admission(previous: &OperationStoreFrontierV1) -> OperationStoreFrontierV1 {
    let admissions = [AdmissionFrontierEntryV1 {
        admission_sequence: 10,
        operation_id: [3u8; 16],
        admission_digest: [4u8; 32],
    }];
    let heads = [ReceiptHeadFrontierEntryV1 {
        operation_id: [3u8; 16],
        event_index: None,
        event_digest: [0u8; 32],
    }];
    OperationStoreFrontierV1::from_state(
        previous.store_id,
        previous.generation,
        previous.checkpoint_sequence + 1,
        previous.store_schema_digest,
        previous.frontier_digest().unwrap(),
        previous.recorded_at_unix_ms + 1,
        &admissions,
        &heads,
    )
    .unwrap()
}

#[test]
fn empty_store_has_a_nonzero_deterministic_frontier() {
    let first = empty_frontier();
    let second = empty_frontier();
    assert_eq!(first.frontier_digest().unwrap(), second.frontier_digest().unwrap());
    assert_ne!(first.frontier_digest().unwrap(), [0u8; 32]);
    assert_eq!(first.admission_count, 0);
    assert_eq!(first.highest_admission_sequence, None);
}

#[test]
fn newer_chain_can_prove_ancestry_to_empty_store_anchor() {
    let genesis = empty_frontier();
    let anchor = genesis.anchor(100).unwrap();
    let next = one_admission(&genesis);
    assert!(verify_anchor_lineage(&anchor, &[genesis, next]).is_ok());
}

#[test]
fn schema_change_inside_generation_is_rejected() {
    let genesis = empty_frontier();
    let mut next = one_admission(&genesis);
    next.store_schema_digest = [99u8; 32];
    assert!(matches!(
        next.validate_successor(&genesis),
        Err(OperationStoreFrontierError::StoreSchemaChangedWithinGeneration)
    ));
}

#[test]
fn generation_change_is_not_an_implicit_successor() {
    let genesis = empty_frontier();
    let mut next = one_admission(&genesis);
    next.generation += 1;
    assert!(matches!(
        next.validate_successor(&genesis),
        Err(OperationStoreFrontierError::GenerationMismatch)
    ));
}

#[test]
fn admission_count_cannot_regress() {
    let genesis = empty_frontier();
    let admitted = one_admission(&genesis);
    let rolled_back = OperationStoreFrontierV1::from_state(
        admitted.store_id,
        admitted.generation,
        admitted.checkpoint_sequence + 1,
        admitted.store_schema_digest,
        admitted.frontier_digest().unwrap(),
        admitted.recorded_at_unix_ms + 1,
        &[],
        &[],
    )
    .unwrap();
    assert!(matches!(
        rolled_back.validate_successor(&admitted),
        Err(OperationStoreFrontierError::AdmissionCountRegression)
    ));
}

#[test]
fn frontier_chain_rejects_skipped_checkpoint_sequence() {
    let genesis = empty_frontier();
    let mut next = one_admission(&genesis);
    next.checkpoint_sequence += 1;
    assert!(matches!(
        validate_frontier_chain(&[genesis, next]),
        Err(OperationStoreFrontierError::CheckpointSequenceMismatch)
    ));
}

#[test]
fn external_anchor_for_other_generation_cannot_authorize_local_state() {
    let genesis = empty_frontier();
    let mut anchor = genesis.anchor(100).unwrap();
    anchor.generation = 1;
    assert!(matches!(
        verify_anchor_lineage(&anchor, &[genesis]),
        Err(OperationStoreFrontierError::GenerationMismatch)
    ));
}
