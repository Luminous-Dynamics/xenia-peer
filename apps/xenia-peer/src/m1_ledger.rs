// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! M1 session lifecycle to ledger adapter.
//!
//! This module deliberately lives in the daemon app because it bridges the
//! permissive `xenia-peer-core` session policy layer to the AGPL
//! `xenia-ledger` accountability layer.
//!
//! It is loss-aware: not every M1 audit event is a consent-boundary event.
//! Frame/input/exec operation authorization events should become richer audit
//! records in their owning runtime; they should not be squeezed into misleading
//! consent kinds today.

#![allow(dead_code)] // M1 adapter lands before runtime wiring in the next PR.

use uuid::Uuid;
use xenia_ledger::{ConsentEventRecord, ConsentKind};
use xenia_peer_core::M1AuditEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M1LedgerSkipReason {
    NotConsentBoundary,
    NormalTerminalEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M1LedgerDisposition {
    Record(ConsentKind),
    Skip(M1LedgerSkipReason),
}

pub(crate) fn disposition_for_m1_event(event: M1AuditEvent) -> M1LedgerDisposition {
    match event {
        M1AuditEvent::SessionOffered => M1LedgerDisposition::Record(ConsentKind::Request),
        M1AuditEvent::ConsentGranted => M1LedgerDisposition::Record(ConsentKind::Approval),
        M1AuditEvent::ConsentDenied => M1LedgerDisposition::Record(ConsentKind::Denial),
        M1AuditEvent::ConsentRevoked => M1LedgerDisposition::Record(ConsentKind::Revocation),
        M1AuditEvent::SessionFailed => M1LedgerDisposition::Record(ConsentKind::Violation),
        M1AuditEvent::FrameStreamed
        | M1AuditEvent::TelemetryStreamed
        | M1AuditEvent::AudioStreamed
        | M1AuditEvent::InputInjected
        | M1AuditEvent::HostClipboardRead
        | M1AuditEvent::HostClipboardWritten
        | M1AuditEvent::FileSentToViewer
        | M1AuditEvent::FileReceivedFromViewer
        | M1AuditEvent::CommandExecutionAuthorized
        | M1AuditEvent::InteractiveTerminalAuthorized => {
            M1LedgerDisposition::Skip(M1LedgerSkipReason::NotConsentBoundary)
        }
        M1AuditEvent::SessionEnded => {
            M1LedgerDisposition::Skip(M1LedgerSkipReason::NormalTerminalEvent)
        }
    }
}

pub(crate) fn consent_record_for_m1_event(
    source_id: [u8; 32],
    session_id: Uuid,
    request_id: Uuid,
    scope: impl Into<String>,
    event: M1AuditEvent,
) -> Option<ConsentEventRecord> {
    match disposition_for_m1_event(event) {
        M1LedgerDisposition::Record(kind) => Some(ConsentEventRecord {
            source_id,
            session_id,
            request_id,
            kind,
            scope: scope.into(),
        }),
        M1LedgerDisposition::Skip(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_boundary_events_map_to_consent_kinds() {
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::SessionOffered),
            M1LedgerDisposition::Record(ConsentKind::Request)
        );
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::ConsentGranted),
            M1LedgerDisposition::Record(ConsentKind::Approval)
        );
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::ConsentDenied),
            M1LedgerDisposition::Record(ConsentKind::Denial)
        );
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::ConsentRevoked),
            M1LedgerDisposition::Record(ConsentKind::Revocation)
        );
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::SessionFailed),
            M1LedgerDisposition::Record(ConsentKind::Violation)
        );
    }

    #[test]
    fn operation_events_are_not_misrepresented_as_consent_events() {
        for event in [
            M1AuditEvent::FrameStreamed,
            M1AuditEvent::InputInjected,
            M1AuditEvent::CommandExecutionAuthorized,
            M1AuditEvent::InteractiveTerminalAuthorized,
        ] {
            assert_eq!(
                disposition_for_m1_event(event),
                M1LedgerDisposition::Skip(M1LedgerSkipReason::NotConsentBoundary)
            );
        }
    }

    #[test]
    fn normal_session_end_is_not_a_revocation() {
        assert_eq!(
            disposition_for_m1_event(M1AuditEvent::SessionEnded),
            M1LedgerDisposition::Skip(M1LedgerSkipReason::NormalTerminalEvent)
        );
    }

    #[test]
    fn consent_record_preserves_identity_and_scope() {
        let source_id = [0xAB; 32];
        let session_id = Uuid::from_bytes([1; 16]);
        let request_id = Uuid::from_bytes([2; 16]);

        let record = consent_record_for_m1_event(
            source_id,
            session_id,
            request_id,
            "view screen",
            M1AuditEvent::ConsentGranted,
        )
        .expect("consent grant should produce a ledger record");

        assert_eq!(record.source_id, source_id);
        assert_eq!(record.session_id, session_id);
        assert_eq!(record.request_id, request_id);
        assert_eq!(record.kind, ConsentKind::Approval);
        assert_eq!(record.scope, "view screen");
    }

    #[test]
    fn skipped_events_do_not_produce_consent_records() {
        let record = consent_record_for_m1_event(
            [0xAB; 32],
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            "view screen",
            M1AuditEvent::FrameStreamed,
        );

        assert!(record.is_none());
    }

    #[test]
    fn m1_lifecycle_builds_verifiable_ledger_transcript() {
        use ed25519_dalek::SigningKey;
        use xenia_ledger::{Chain, Verifier};
        use xenia_peer_core::M1SessionMachine;

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut chain = Chain::new(signing_key);

        let source_id = [0xAB; 32];
        let session_id = Uuid::from_bytes([1; 16]);
        let request_id = Uuid::from_bytes([2; 16]);
        let scope = "view screen";

        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();
        session.stream_frame().unwrap();
        session.inject_input().unwrap();
        session.revoke().unwrap();

        let appended = session
            .audit()
            .iter()
            .filter_map(|event| {
                consent_record_for_m1_event(source_id, session_id, request_id, scope, *event)
            })
            .map(|record| chain.append(record).map(|_| ()))
            .collect::<Result<Vec<_>, _>>()
            .expect("M1 consent-boundary events should append to the ledger");

        assert_eq!(appended.len(), 3);

        let entries = chain.into_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Approval);
        assert_eq!(entries[2].event.kind, ConsentKind::Revocation);
        assert_eq!(entries[0].event.stable_name(), "consent.requested");
        assert_eq!(entries[1].event.stable_name(), "consent.granted");
        assert_eq!(entries[2].event.stable_name(), "consent.revoked");

        Verifier::verify_chain(&entries, &verifying_key)
            .expect("M1 ledger transcript should verify");
    }

    #[test]
    fn m1_frame_and_input_events_are_absent_from_consent_transcript() {
        use ed25519_dalek::SigningKey;
        use xenia_ledger::Chain;
        use xenia_peer_core::M1SessionMachine;

        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let mut chain = Chain::new(signing_key);

        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();
        session.stream_frame().unwrap();
        session.inject_input().unwrap();
        session.revoke().unwrap();

        for event in session.audit() {
            if let Some(record) = consent_record_for_m1_event(
                [0xAB; 32],
                Uuid::from_bytes([1; 16]),
                Uuid::from_bytes([2; 16]),
                "view screen",
                *event,
            ) {
                chain.append(record).unwrap();
            }
        }

        let stable_names = chain
            .into_entries()
            .into_iter()
            .map(|entry| entry.event.stable_name())
            .collect::<Vec<_>>();

        assert_eq!(
            stable_names,
            vec!["consent.requested", "consent.granted", "consent.revoked"]
        );
        assert!(!stable_names.contains(&"frame.streamed"));
        assert!(!stable_names.contains(&"input.injected"));
    }
}
