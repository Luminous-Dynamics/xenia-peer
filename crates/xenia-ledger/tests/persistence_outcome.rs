// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::panic::{AssertUnwindSafe, catch_unwind};

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{
    Chain, ConsentEventRecord, ConsentKind, LedgerError, PersistenceDisposition,
    PersistenceReconciliationOutcome, TransactionalAppendOutcome,
};

fn chain() -> Chain {
    Chain::new(SigningKey::from_bytes(&[7; 32]))
}

fn event(request: u8) -> ConsentEventRecord {
    ConsentEventRecord {
        source_id: [0x11; 32],
        session_id: Uuid::from_bytes([0x22; 16]),
        request_id: Uuid::from_bytes([request; 16]),
        kind: ConsentKind::Approval,
        scope: "qualification fixture".to_string(),
    }
}

#[test]
fn ambiguous_persistence_latches_chain_until_confirmed() {
    let mut chain = chain();
    let outcome = chain
        .append_transactional_outcome(event(1), |_| {
            PersistenceDisposition::OutcomeUnknown("ack lost")
        })
        .unwrap();
    let pending = match outcome {
        TransactionalAppendOutcome::OutcomeUnknown { pending, .. } => pending,
        other => panic!("unexpected outcome: {other:?}"),
    };

    assert_eq!(pending.seq, 0);
    assert_eq!(chain.entry_count(), 1);
    assert_eq!(chain.pending_persistence_frontier(), Some(pending));
    assert!(matches!(
        chain.append(event(2)),
        Err(LedgerError::UncertainPersistencePending { seq: 0 })
    ));

    let reconciled = chain
        .reconcile_pending_persistence(|_, exact| {
            assert_eq!(exact, pending);
            PersistenceDisposition::<&'static str>::Persisted
        })
        .unwrap();
    assert!(matches!(
        reconciled,
        PersistenceReconciliationOutcome::Persisted(_)
    ));
    assert!(!chain.has_uncertain_persistence());
    assert_eq!(chain.append(event(2)).unwrap().seq, 1);
}

#[test]
fn proven_non_persistence_rolls_back_and_reuses_sequence_safely() {
    let mut chain = chain();
    let outcome = chain
        .append_transactional_outcome(event(1), |_| {
            PersistenceDisposition::ProvenNotPersisted("rename never happened")
        })
        .unwrap();

    let reverted = match outcome {
        TransactionalAppendOutcome::ProvenNotPersisted { reverted_entry, .. } => reverted_entry,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(reverted.seq, 0);
    assert_eq!(chain.entry_count(), 0);
    assert!(!chain.has_uncertain_persistence());
    assert_eq!(chain.append(event(2)).unwrap().seq, 0);
}

#[test]
fn unknown_then_proven_not_persisted_releases_only_exact_candidate() {
    let mut chain = chain();
    let pending = match chain
        .append_transactional_outcome(event(1), |_| {
            PersistenceDisposition::OutcomeUnknown("fsync acknowledgement lost")
        })
        .unwrap()
    {
        TransactionalAppendOutcome::OutcomeUnknown { pending, .. } => pending,
        other => panic!("unexpected outcome: {other:?}"),
    };

    let reconciled = chain
        .reconcile_pending_persistence(|_, exact| {
            assert_eq!(exact, pending);
            PersistenceDisposition::ProvenNotPersisted("durable store proves absent")
        })
        .unwrap();
    let reverted = match reconciled {
        PersistenceReconciliationOutcome::ProvenNotPersisted { reverted_entry, .. } => {
            reverted_entry
        }
        other => panic!("unexpected reconciliation: {other:?}"),
    };
    assert_eq!(reverted.entry_hash, pending.entry_hash);
    assert_eq!(chain.entry_count(), 0);
    assert_eq!(chain.append(event(2)).unwrap().seq, 0);
}

#[test]
fn caught_persistence_panic_leaves_chain_fail_closed() {
    let mut chain = chain();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = chain.append_transactional_outcome(event(1), |_| -> PersistenceDisposition<()> {
            panic!("simulated crash after external commit boundary");
        });
    }));
    assert!(result.is_err());

    let pending = chain
        .pending_persistence_frontier()
        .expect("candidate must remain latched after caught unwind");
    assert_eq!(pending.seq, 0);
    assert!(matches!(
        chain.append(event(2)),
        Err(LedgerError::UncertainPersistencePending { seq: 0 })
    ));
}
