//! Typed selection for `xenia-peer` one-shot maintenance commands.
//!
//! `xenia-peer` intentionally exposes many read-only verification and explicit
//! lifecycle operations through the daemon binary.  The dispatcher in
//! `main.rs` returns after the first matching branch, so accepting two operation
//! flags in one invocation would otherwise make the later flag silently inert.
//! This module enumerates every one-shot branch in one place and refuses an
//! ambiguous invocation before keys are loaded or files are changed.

use crate::Args;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationFamily {
    Evidence,
    Retirement,
    Purge,
    PurgeRetention,
    PurgeCustody,
    FinalDestruction,
    LedgerMaintenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OneShotOperation {
    M1RuntimeSmoke,
    VerifyEvidenceBundle,
    VerifySealedEvidenceBundle,
    AuditEvidenceReport,
    AuditSealedEvidenceReport,
    SignRetirementPlan,
    RecoverRetirementJournal,
    VerifyRetirementReceipt,
    ExportRetirementPlan,
    QuarantineRetirement,
    SignPurgePlan,
    RecoverPurgeJournal,
    VerifyPurgeReceipt,
    ExportPurgePlan,
    ExecutePurge,
    SignRetentionCertificate,
    VerifyRetentionAnchor,
    ExportRetentionCertificate,
    ExportRetentionAnchor,
    ExportRetentionRenewal,
    SignCustodyAssertion,
    SignFinalDestructionPlan,
    VerifyFinalDestructionReadiness,
    ExportFinalDestructionPlan,
    ExportFinalDestructionReadiness,
    ActivateCompactedState,
    AdvanceCompactedStatePin,
    ExportCompactionGcCertificate,
    VerifyCompactionGcCertificate,
    AdvanceLedgerCheckpoint,
    ExportLedgerArchiveSegment,
    ExportCompactionBundle,
    VerifyCompactionBundle,
    ExportCompactedSnapshot,
    VerifyCompactedSnapshot,
}

impl OneShotOperation {
    pub(crate) const fn family(self) -> OperationFamily {
        match self {
            Self::M1RuntimeSmoke
            | Self::VerifyEvidenceBundle
            | Self::VerifySealedEvidenceBundle
            | Self::AuditEvidenceReport
            | Self::AuditSealedEvidenceReport => OperationFamily::Evidence,
            Self::SignRetirementPlan
            | Self::RecoverRetirementJournal
            | Self::VerifyRetirementReceipt
            | Self::ExportRetirementPlan
            | Self::QuarantineRetirement => OperationFamily::Retirement,
            Self::SignPurgePlan
            | Self::RecoverPurgeJournal
            | Self::VerifyPurgeReceipt
            | Self::ExportPurgePlan
            | Self::ExecutePurge => OperationFamily::Purge,
            Self::SignRetentionCertificate
            | Self::VerifyRetentionAnchor
            | Self::ExportRetentionCertificate
            | Self::ExportRetentionAnchor
            | Self::ExportRetentionRenewal => OperationFamily::PurgeRetention,
            Self::SignCustodyAssertion => OperationFamily::PurgeCustody,
            Self::SignFinalDestructionPlan
            | Self::VerifyFinalDestructionReadiness
            | Self::ExportFinalDestructionPlan
            | Self::ExportFinalDestructionReadiness => OperationFamily::FinalDestruction,
            Self::ActivateCompactedState
            | Self::AdvanceCompactedStatePin
            | Self::ExportCompactionGcCertificate
            | Self::VerifyCompactionGcCertificate
            | Self::AdvanceLedgerCheckpoint
            | Self::ExportLedgerArchiveSegment
            | Self::ExportCompactionBundle
            | Self::VerifyCompactionBundle
            | Self::ExportCompactedSnapshot
            | Self::VerifyCompactedSnapshot => OperationFamily::LedgerMaintenance,
        }
    }

    pub(crate) const fn flag(self) -> &'static str {
        match self {
            Self::M1RuntimeSmoke => "--m1-runtime-smoke",
            Self::VerifyEvidenceBundle => "--verify-evidence-bundle",
            Self::VerifySealedEvidenceBundle => "--verify-sealed-evidence-bundle",
            Self::AuditEvidenceReport => "--audit-evidence-report",
            Self::AuditSealedEvidenceReport => "--audit-sealed-evidence-report",
            Self::SignRetirementPlan => "--sign-consent-retirement-plan",
            Self::RecoverRetirementJournal => "--recover-consent-retirement-journal",
            Self::VerifyRetirementReceipt => "--verify-consent-retirement-receipt",
            Self::ExportRetirementPlan => "--export-consent-retirement-plan",
            Self::QuarantineRetirement => "--quarantine-consent-retirement",
            Self::SignPurgePlan => "--sign-consent-purge-plan",
            Self::RecoverPurgeJournal => "--recover-consent-purge-journal",
            Self::VerifyPurgeReceipt => "--verify-consent-purge-receipt",
            Self::ExportPurgePlan => "--export-consent-purge-plan",
            Self::ExecutePurge => "--execute-consent-purge",
            Self::SignRetentionCertificate => "--sign-consent-purge-retention-certificate",
            Self::VerifyRetentionAnchor => "--verify-consent-purge-retention-anchor",
            Self::ExportRetentionCertificate => "--export-consent-purge-retention-certificate",
            Self::ExportRetentionAnchor => "--export-consent-purge-retention-anchor",
            Self::ExportRetentionRenewal => "--export-consent-purge-retention-renewal",
            Self::SignCustodyAssertion => "--sign-consent-purge-custody",
            Self::SignFinalDestructionPlan => "--sign-consent-final-destruction-plan",
            Self::VerifyFinalDestructionReadiness => {
                "--verify-consent-final-destruction-readiness"
            }
            Self::ExportFinalDestructionPlan => "--export-consent-final-destruction-plan",
            Self::ExportFinalDestructionReadiness => {
                "--export-consent-final-destruction-readiness"
            }
            Self::ActivateCompactedState => "--activate-consent-ledger-compacted-state",
            Self::AdvanceCompactedStatePin => "--advance-consent-ledger-compacted-state-pin",
            Self::ExportCompactionGcCertificate => {
                "--export-consent-ledger-compaction-gc-certificate"
            }
            Self::VerifyCompactionGcCertificate => {
                "--verify-consent-ledger-compaction-gc-certificate"
            }
            Self::AdvanceLedgerCheckpoint => "--advance-consent-ledger-checkpoint",
            Self::ExportLedgerArchiveSegment => "--export-consent-ledger-archive-segment",
            Self::ExportCompactionBundle => "--export-consent-ledger-compaction-bundle",
            Self::VerifyCompactionBundle => "--verify-consent-ledger-compaction-bundle",
            Self::ExportCompactedSnapshot => "--export-consent-ledger-compacted-snapshot",
            Self::VerifyCompactedSnapshot => "--verify-consent-ledger-compacted-snapshot",
        }
    }
}

fn push_if(operations: &mut Vec<OneShotOperation>, condition: bool, operation: OneShotOperation) {
    if condition {
        operations.push(operation);
    }
}

pub(crate) fn selected_one_shot_operations(args: &Args) -> Vec<OneShotOperation> {
    let mut operations = Vec::new();

    push_if(&mut operations, args.m1_runtime_smoke, OneShotOperation::M1RuntimeSmoke);
    push_if(
        &mut operations,
        args.verify_evidence_bundle.is_some(),
        OneShotOperation::VerifyEvidenceBundle,
    );
    push_if(
        &mut operations,
        args.verify_sealed_evidence_bundle.is_some(),
        OneShotOperation::VerifySealedEvidenceBundle,
    );
    push_if(
        &mut operations,
        args.audit_evidence_report.is_some(),
        OneShotOperation::AuditEvidenceReport,
    );
    push_if(
        &mut operations,
        args.audit_sealed_evidence_report.is_some(),
        OneShotOperation::AuditSealedEvidenceReport,
    );

    push_if(
        &mut operations,
        args.sign_consent_retirement_plan,
        OneShotOperation::SignRetirementPlan,
    );
    push_if(
        &mut operations,
        args.recover_consent_retirement_journal.is_some(),
        OneShotOperation::RecoverRetirementJournal,
    );
    push_if(
        &mut operations,
        args.verify_consent_retirement_receipt.is_some(),
        OneShotOperation::VerifyRetirementReceipt,
    );
    push_if(
        &mut operations,
        args.export_consent_retirement_plan.is_some(),
        OneShotOperation::ExportRetirementPlan,
    );
    push_if(
        &mut operations,
        args.quarantine_consent_retirement,
        OneShotOperation::QuarantineRetirement,
    );

    push_if(
        &mut operations,
        args.sign_consent_purge_plan,
        OneShotOperation::SignPurgePlan,
    );
    push_if(
        &mut operations,
        args.recover_consent_purge_journal.is_some(),
        OneShotOperation::RecoverPurgeJournal,
    );
    push_if(
        &mut operations,
        args.verify_consent_purge_receipt.is_some(),
        OneShotOperation::VerifyPurgeReceipt,
    );
    push_if(
        &mut operations,
        args.export_consent_purge_plan.is_some(),
        OneShotOperation::ExportPurgePlan,
    );
    push_if(
        &mut operations,
        args.execute_consent_purge,
        OneShotOperation::ExecutePurge,
    );

    push_if(
        &mut operations,
        args.sign_consent_purge_retention_certificate,
        OneShotOperation::SignRetentionCertificate,
    );
    push_if(
        &mut operations,
        args.verify_consent_purge_retention_anchor.is_some(),
        OneShotOperation::VerifyRetentionAnchor,
    );
    push_if(
        &mut operations,
        args.export_consent_purge_retention_certificate.is_some(),
        OneShotOperation::ExportRetentionCertificate,
    );
    push_if(
        &mut operations,
        args.export_consent_purge_retention_anchor.is_some(),
        OneShotOperation::ExportRetentionAnchor,
    );
    push_if(
        &mut operations,
        args.export_consent_purge_retention_renewal.is_some(),
        OneShotOperation::ExportRetentionRenewal,
    );
    push_if(
        &mut operations,
        args.sign_consent_purge_custody,
        OneShotOperation::SignCustodyAssertion,
    );

    push_if(
        &mut operations,
        args.sign_consent_final_destruction_plan,
        OneShotOperation::SignFinalDestructionPlan,
    );
    push_if(
        &mut operations,
        args.verify_consent_final_destruction_readiness.is_some(),
        OneShotOperation::VerifyFinalDestructionReadiness,
    );
    push_if(
        &mut operations,
        args.export_consent_final_destruction_plan.is_some(),
        OneShotOperation::ExportFinalDestructionPlan,
    );
    push_if(
        &mut operations,
        args.export_consent_final_destruction_readiness.is_some(),
        OneShotOperation::ExportFinalDestructionReadiness,
    );

    push_if(
        &mut operations,
        args.activate_consent_ledger_compacted_state.is_some(),
        OneShotOperation::ActivateCompactedState,
    );
    push_if(
        &mut operations,
        args.advance_consent_ledger_compacted_state_pin.is_some(),
        OneShotOperation::AdvanceCompactedStatePin,
    );
    push_if(
        &mut operations,
        args.export_consent_ledger_compaction_gc_certificate.is_some(),
        OneShotOperation::ExportCompactionGcCertificate,
    );
    push_if(
        &mut operations,
        args.verify_consent_ledger_compaction_gc_certificate.is_some(),
        OneShotOperation::VerifyCompactionGcCertificate,
    );
    push_if(
        &mut operations,
        args.advance_consent_ledger_checkpoint.is_some(),
        OneShotOperation::AdvanceLedgerCheckpoint,
    );
    push_if(
        &mut operations,
        args.export_consent_ledger_archive_segment.is_some(),
        OneShotOperation::ExportLedgerArchiveSegment,
    );
    push_if(
        &mut operations,
        args.export_consent_ledger_compaction_bundle.is_some(),
        OneShotOperation::ExportCompactionBundle,
    );
    push_if(
        &mut operations,
        args.verify_consent_ledger_compaction_bundle.is_some(),
        OneShotOperation::VerifyCompactionBundle,
    );
    push_if(
        &mut operations,
        args.export_consent_ledger_compacted_snapshot.is_some(),
        OneShotOperation::ExportCompactedSnapshot,
    );
    push_if(
        &mut operations,
        args.verify_consent_ledger_compacted_snapshot.is_some(),
        OneShotOperation::VerifyCompactedSnapshot,
    );

    operations
}

pub(crate) fn validate_one_shot_selection(
    args: &Args,
) -> Result<Option<OneShotOperation>, Box<dyn std::error::Error>> {
    let operations = selected_one_shot_operations(args);
    match operations.as_slice() {
        [] => Ok(None),
        [operation] => Ok(Some(*operation)),
        _ => {
            let flags = operations
                .iter()
                .map(|operation| operation.flag())
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "select exactly one one-shot operation per invocation; conflicting flags: {flags}"
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(extra: &[&str]) -> Args {
        let mut argv = vec!["xenia-peer"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).expect("test arguments should parse")
    }

    #[test]
    fn accepts_one_operation() {
        let args = parse(&["--m1-runtime-smoke"]);
        assert_eq!(
            validate_one_shot_selection(&args).unwrap(),
            Some(OneShotOperation::M1RuntimeSmoke)
        );
    }

    #[test]
    fn rejects_cross_family_operations_before_dispatch() {
        let args = parse(&[
            "--sign-consent-purge-custody",
            "--advance-consent-ledger-checkpoint",
            "/tmp/checkpoint.json",
        ]);
        let error = validate_one_shot_selection(&args).unwrap_err().to_string();
        assert!(error.contains("--sign-consent-purge-custody"));
        assert!(error.contains("--advance-consent-ledger-checkpoint"));
    }

    #[test]
    fn rejects_verification_and_lifecycle_operations() {
        let args = parse(&[
            "--verify-evidence-bundle",
            "/tmp/evidence",
            "--sign-consent-purge-custody",
        ]);
        let error = validate_one_shot_selection(&args).unwrap_err().to_string();
        assert!(error.contains("--verify-evidence-bundle"));
        assert!(error.contains("--sign-consent-purge-custody"));
    }

    #[test]
    fn normal_daemon_start_has_no_one_shot_operation() {
        let args = parse(&[]);
        assert_eq!(validate_one_shot_selection(&args).unwrap(), None);
    }
}
