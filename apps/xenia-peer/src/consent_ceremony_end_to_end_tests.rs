// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A real end-to-end test driving the full consent-ledger maintenance
//! operator sequence -- compaction -> retirement/quarantine -> purge ->
//! purge-retention -> purge-custody -> final-destruction -- through the
//! same `pub(crate)` ceremony functions `main.rs`'s CLI dispatch calls.
//!
//! No such test existed even in the original, unported PR #99: rich
//! fixture-level unit coverage exists per module, but nothing drove the
//! whole chain in one place. This closes that gap.
//!
//! Not a subprocess/CLI-spawn test: this crate is a binary, and every
//! ceremony type/function here is `pub(crate)`, not part of any exported
//! library API a separate `tests/` integration binary could link against
//! -- the same reason every other module in this port puts its tests in an
//! inline `#[cfg(test)] mod`. Calling the functions directly *is* the real
//! integration surface: `main.rs`'s dispatch branches are thin wrappers
//! that parse CLI args and call exactly these functions, so this test
//! exercises the same code path Phase 2 hand-verified via the compiled
//! binary, without the process-spawn overhead.
//!
//! Every ceremony function takes its `now_unix_secs`/`issued_at_unix_secs`
//! as an explicit parameter rather than reading the wall clock internally
//! -- confirmed by reading every `sign`/`execute`/`verify_quorum` call site
//! in this port. That's what makes a real, fast, single-process test of a
//! protocol with a 24-hour minimum-quarantine-age floor
//! (`consent_purge::MIN_PURGE_QUARANTINE_AGE_SECS`) possible without
//! faking the OS clock: the whole timeline below is synthetic u64 seconds
//! chosen to satisfy every window/expiry check for real, the same pattern
//! already used by e.g. `consent_purge::tests::fixture()`
//! (`issued_at_unix_secs: 20 + MIN_PURGE_QUARANTINE_AGE_SECS`).

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerArchiveSegment};

    use crate::consent_compaction::{
        ConsentCompactedActiveStateV1, ConsentCompactedSnapshotV1, ConsentCompactedStatePinV1,
        ConsentCompactionBundleV1, ConsentCompactionGcCertificateV1,
    };
    use crate::consent_final_destruction::{
        ConsentFinalDestructionApprovalBundleV1, ConsentFinalDestructionPlanV1,
        ConsentFinalDestructionReadinessV1,
    };
    use crate::consent_purge::{
        self, ConsentPurgeApprovalBundleV1, ConsentPurgePlanV1, ConsentPurgeRollbackPackageV1,
    };
    use crate::consent_purge_custody::{
        ConsentPurgeCustodyAttestationV1, ConsentPurgeCustodyBundleV1, ConsentPurgeCustodyClassV1,
    };
    use crate::consent_purge_retention::{
        ConsentPurgeRetentionAnchorV1, ConsentPurgeRetentionCertificateV1,
        ConsentPurgeRetentionWitnessBundleV1, verify_retention_subject,
    };
    use crate::consent_retirement::{
        self, ConsentRetirementApprovalBundleV1, ConsentRetirementArtifactRoleV1,
        ConsentRetirementPlanV1,
    };
    use ed25519_dalek::SigningKey as LedgerSigningKey;

    fn owner_only_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn event(kind: ConsentKind, session: u128, request: u128) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0x99; 32],
            session_id: Uuid::from_u128(session),
            request_id: Uuid::from_u128(request),
            kind,
            scope: "e2e".into(),
        }
    }

    /// Mirrors `consent_retirement::tests::prerequisites()` -- builds a
    /// real compaction chain -> archive -> bundle -> snapshot -> active
    /// state -> pin -> GC certificate, all for real, from scratch.
    fn compaction_prerequisites() -> (
        LedgerSigningKey,
        ConsentCompactedActiveStateV1,
        ConsentCompactedStatePinV1,
        ConsentCompactionGcCertificateV1,
        Vec<LedgerArchiveSegment>,
    ) {
        let key = LedgerSigningKey::from_bytes(&[0x77; 32]);
        let mut complete = Chain::new(key.clone());
        let genesis = complete.sign_checkpoint(100);
        complete.append(event(ConsentKind::Denial, 1, 2)).unwrap();
        let archive = vec![LedgerArchiveSegment::from_chain(&complete, genesis, 101).unwrap()];
        let bundle = ConsentCompactionBundleV1::build(&complete, archive.clone(), 102).unwrap();
        let entries = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &archive, &key, 103).unwrap();
        let pin = ConsentCompactedStatePinV1::sign_for_state(&active, &key, 104).unwrap();
        let certificate =
            ConsentCompactionGcCertificateV1::sign_for_state(&active, &pin, &archive, &key, 105)
                .unwrap();
        (key, active, pin, certificate, archive)
    }

    /// Phase A hand-verification, kept as permanent coverage: drives two
    /// real consent decisions through the actual `apply_consent_decision`
    /// (the same function `ConsentServer`/`SealedConsentDeps` call in
    /// production) against a real `CompactedConsentLedgerPersister` -- the
    /// exact function/persister pairing the daemon-startup compacted-mode
    /// switch wires up -- and reloads the on-disk file after each to
    /// confirm it genuinely advances. This is what caught a real bug: the
    /// persister used to silently stop advancing `generation` after the
    /// first real append (fixed in `consent_ledger_persistence.rs`, see
    /// that file's own regression test for the isolated repro).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compacted_boot_mode_persists_two_real_consent_decisions_through_apply_consent_decision()
     {
        let (key, active, _pin, _cert, _archive) = compaction_prerequisites();
        let workdir = tempfile::tempdir().unwrap();
        let path = workdir.path().join("compacted-state.json");
        crate::consent_ledger_persistence::persist_compacted_active_state_atomic(&path, &active)
            .unwrap();
        let (loaded_active, restored) =
            crate::consent_ledger_persistence::load_compacted_active_state(&path, &key).unwrap();
        let initial_entry_count = restored.chain.entry_count();
        let initial_generation = loaded_active.generation;

        let persister = crate::consent_ledger_persistence::CompactedConsentLedgerPersister::new(
            path.clone(),
            loaded_active,
        );
        let ledger = tokio::sync::Mutex::new(restored.chain);
        let authorized = crate::operator_auth::AuthorizedConsentAction {
            action: crate::operator_auth::ConsentAction::Approve,
            operator_id: "e2e-operator".to_string(),
            role: crate::operator::OperatorRole::Admin,
            ed25519_pubkey: [0x22; 32],
        };
        let session_uuid = uuid::Uuid::from_u128(999);

        for expected_generation in [initial_generation + 1, initial_generation + 2] {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let mut tx = Some(tx);
            let revoked = std::sync::atomic::AtomicBool::new(false);
            let outcome = crate::consent_server::apply_consent_decision(
                crate::DecodedConsent {
                    action: crate::operator_auth::ConsentAction::Approve,
                    authorized: Some(authorized.clone()),
                },
                &mut tx,
                &revoked,
                &ledger,
                &persister,
                session_uuid,
            )
            .await;
            assert!(matches!(
                outcome,
                crate::consent_server::ConsentFollowup::KeepServing
            ));
            assert!(rx.await.unwrap(), "grant must resolve true on Approve");

            let (reloaded_active, reloaded_restored) =
                crate::consent_ledger_persistence::load_compacted_active_state(&path, &key)
                    .unwrap();
            assert_eq!(
                reloaded_restored.chain.entry_count(),
                ledger.lock().await.entry_count(),
                "the on-disk compacted state must match the live in-memory chain after every append"
            );
            assert_eq!(
                reloaded_active.generation, expected_generation,
                "generation must advance on every real append, not just the first"
            );
        }

        assert_eq!(
            ledger.lock().await.entry_count(),
            initial_entry_count + 2,
            "both decisions must have actually appended"
        );
    }

    /// Drives the full operator sequence for real: every step calls the
    /// same `pub(crate)` function `main.rs`'s CLI dispatch calls, with a
    /// synthetic but internally consistent timeline (see module doc).
    #[test]
    fn full_consent_ledger_maintenance_ceremony_end_to_end() {
        let (key, active, pin, gc_certificate, archive) = compaction_prerequisites();

        // ---- Retirement: real file, real quarantine move ----
        let workdir = tempfile::tempdir().unwrap();
        let candidate_path = workdir.path().join("consent.ledger");
        fs::write(&candidate_path, b"superseded-ledger-bytes-for-e2e-test").unwrap();
        let quarantine_root = workdir.path().join("quarantine");
        owner_only_dir(&quarantine_root);
        let artifact = consent_retirement::observe_retirement_artifact(
            ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            &candidate_path,
        )
        .unwrap();
        let retirement_plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &gc_certificate,
            &archive,
            fs::canonicalize(&quarantine_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![artifact],
            &key,
            106,
            3_706,
        )
        .unwrap();
        let retirement_witness = LedgerSigningKey::from_bytes(&[0x78; 32]);
        let mut retirement_approvals =
            ConsentRetirementApprovalBundleV1::new(&retirement_plan).unwrap();
        retirement_approvals
            .sign_with(&retirement_plan, &retirement_witness, 107)
            .unwrap();
        let quarantine_receipt = consent_retirement::execute_retirement_quarantine(
            &retirement_plan,
            &retirement_approvals,
            &active,
            &pin,
            &gc_certificate,
            &archive,
            &[retirement_witness.verifying_key().to_bytes()],
            1,
            &key,
            108,
        )
        .unwrap();
        assert!(
            !candidate_path.exists(),
            "quarantine must have moved the original artifact"
        );
        assert!(
            Path::new(&quarantine_receipt.entries[0].quarantine_path).exists(),
            "quarantine must have created a real file at the quarantine path"
        );

        // ---- Purge: real deletion of the (already-quarantined) copy,
        // only after the real 24h floor, satisfied synthetically ----
        let rollback_root = workdir.path().join("rollback");
        owner_only_dir(&rollback_root);
        let purge_issued_at = quarantine_receipt.completed_at_unix_secs
            + consent_purge::MIN_PURGE_QUARANTINE_AGE_SECS;
        let purge_plan = ConsentPurgePlanV1::sign(
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            fs::canonicalize(&rollback_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            consent_purge::MIN_PURGE_QUARANTINE_AGE_SECS,
            &key,
            purge_issued_at,
            purge_issued_at + 3_600,
        )
        .unwrap();
        let purge_witness = LedgerSigningKey::from_bytes(&[0x79; 32]);
        let mut purge_approvals = ConsentPurgeApprovalBundleV1::new(&purge_plan).unwrap();
        purge_approvals
            .sign_with(&purge_plan, &purge_witness, purge_issued_at + 1)
            .unwrap();
        let purge_receipt = consent_purge::execute_consent_purge(
            &purge_plan,
            &purge_approvals,
            &retirement_plan,
            &retirement_approvals,
            &quarantine_receipt,
            &[purge_witness.verifying_key().to_bytes()],
            1,
            &key,
            purge_issued_at + 2,
        )
        .unwrap();
        assert!(
            !Path::new(&quarantine_receipt.entries[0].quarantine_path).exists(),
            "purge must have deleted the quarantined copy"
        );
        let rollback_package: ConsentPurgeRollbackPackageV1 = {
            let path =
                Path::new(&purge_receipt.transaction_directory).join("rollback-package.json");
            let bytes = fs::read(&path).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert!(
            Path::new(&purge_receipt.entries[0].artifact.rollback_path).exists(),
            "the independently-verified rollback copy must survive the purge"
        );

        // ---- Purge-retention: certificate, witness quorum, anchor ----
        let retention_issued_at = purge_issued_at + 100;
        let retain_until = retention_issued_at + 100_000;
        let retention_certificate = ConsentPurgeRetentionCertificateV1::sign(
            &purge_plan,
            &purge_approvals,
            &rollback_package,
            &purge_receipt,
            &key,
            retention_issued_at,
            retain_until,
        )
        .unwrap();
        let retention_witness = LedgerSigningKey::from_bytes(&[0x80; 32]);
        let mut retention_witnesses =
            ConsentPurgeRetentionWitnessBundleV1::new(&retention_certificate).unwrap();
        retention_witnesses
            .sign_with(
                &retention_certificate,
                &retention_witness,
                retention_issued_at + 1,
            )
            .unwrap();
        let anchor = ConsentPurgeRetentionAnchorV1::sign(
            &retention_certificate,
            &retention_witnesses,
            &[retention_witness.verifying_key().to_bytes()],
            1,
            &key,
            retention_issued_at + 2,
            300,
        )
        .unwrap();
        let subject = verify_retention_subject(
            &retention_certificate,
            &anchor,
            &[],
            &key.verifying_key(),
            retention_issued_at + 3,
        )
        .unwrap();
        assert_eq!(subject.retain_until_unix_secs, retain_until);

        // ---- Purge-custody: an independent custodian attests it holds
        // the rollback package, available well past the retention window
        // and the final-destruction plan's own expiry below ----
        let custody_key = LedgerSigningKey::from_bytes(&[0x81; 32]);
        let custody_available_until = retain_until + 10_000;
        let custody_attestation = ConsentPurgeCustodyAttestationV1::sign(
            &subject,
            ConsentPurgeCustodyClassV1::RemoteVault,
            "vault://independent-custodian/e2e-test",
            [0xAA; 16],
            &custody_key,
            retention_issued_at + 4,
            custody_available_until,
        )
        .unwrap();
        let mut custody_bundle = ConsentPurgeCustodyBundleV1::new(&subject);
        custody_bundle.add(&subject, custody_attestation).unwrap();

        // ---- Final destruction: authorization-only ceremony. Confirms,
        // for real, that reaching "readiness" authorizes nothing more than
        // a signed certificate -- see item 4 of the Phase 3 review for the
        // static call-graph proof that no deletion is reachable from here. ----
        let destruction_issued_at = retain_until;
        let destruction_expires_at = destruction_issued_at + 1_000;
        let destruction_plan = ConsentFinalDestructionPlanV1::sign(
            &retention_certificate,
            &subject,
            &custody_bundle,
            &[custody_key.verifying_key().to_bytes()],
            1,
            &key,
            destruction_issued_at,
            destruction_expires_at,
        )
        .unwrap();
        let destruction_witness = LedgerSigningKey::from_bytes(&[0x82; 32]);
        let mut destruction_approvals =
            ConsentFinalDestructionApprovalBundleV1::new(&destruction_plan).unwrap();
        destruction_approvals
            .sign_with(
                &destruction_plan,
                &destruction_witness,
                destruction_issued_at + 1,
            )
            .unwrap();
        let readiness = ConsentFinalDestructionReadinessV1::sign(
            &destruction_plan,
            &destruction_approvals,
            &custody_bundle,
            &[destruction_witness.verifying_key().to_bytes()],
            1,
            &key,
            destruction_issued_at + 2,
        )
        .unwrap();
        readiness
            .verify(
                &destruction_plan,
                &destruction_approvals,
                &custody_bundle,
                &[destruction_witness.verifying_key().to_bytes()],
                1,
                &key.verifying_key(),
            )
            .unwrap();

        // The whole point of the disclosure this test exists to confirm:
        // reaching a verified readiness certificate is where the chain
        // ends. Nothing below this line exists to call, because nothing
        // in consent_final_destruction.rs (or its read-only callees) ever
        // deletes anything -- see the module's own doc comment and item 4
        // of the Phase 3 adversarial review.
    }
}
