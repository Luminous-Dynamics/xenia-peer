// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-local M1 runtime skeleton.
//!
//! This module wires the deterministic M1 session state machine to the
//! consent ledger without adding networking, capture, GUI, or real input
//! injection. It is the first app-layer runtime bridge:
//!
//! session transition -> audit event -> consent-boundary ledger record.
//!
//! Frame and input operation events remain state-machine audit events, but
//! they are deliberately not represented as consent ledger entries yet.

#![allow(dead_code)] // Skeleton lands before daemon CLI/runtime integration.

use std::error::Error;
use std::fmt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use uuid::Uuid;
use xenia_ledger::{
    CURRENT_EVIDENCE_CRYPTO_MANIFEST, Chain, ConsentKind, EvidenceBundleVerifyError, LedgerEntry,
    LedgerEntryExport, LedgerError, SessionTranscriptBinding, Verifier, VerifyError,
};
use xenia_peer_core::{M1Permission, M1SessionError, M1SessionMachine, M1SessionState};

use crate::m1_ledger::consent_record_for_m1_event;

#[derive(Debug)]
pub(crate) enum M1RuntimeError {
    Session(M1SessionError),
    Ledger(LedgerError),
    Verify(VerifyError),
    EvidenceBundle(EvidenceBundleVerifyError),
    MissingTranscriptBinding,
    PersistIo(std::io::Error),
    PersistCodec(bincode::Error),
}

impl fmt::Display for M1RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(err) => write!(f, "M1 session error: {err}"),
            Self::Ledger(err) => write!(f, "M1 ledger error: {err}"),
            Self::Verify(err) => write!(f, "M1 ledger verification error: {err}"),
            Self::EvidenceBundle(err) => write!(f, "M1 transcript-bound evidence error: {err}"),
            Self::MissingTranscriptBinding => write!(
                f,
                "M1 session has no canonical handshake transcript hash bound"
            ),
            Self::PersistIo(err) => write!(f, "M1 ledger persistence I/O error: {err}"),
            Self::PersistCodec(err) => write!(f, "M1 ledger persistence codec error: {err}"),
        }
    }
}

impl Error for M1RuntimeError {}

impl From<M1SessionError> for M1RuntimeError {
    fn from(err: M1SessionError) -> Self {
        Self::Session(err)
    }
}

impl From<LedgerError> for M1RuntimeError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<VerifyError> for M1RuntimeError {
    fn from(err: VerifyError) -> Self {
        Self::Verify(err)
    }
}

impl From<EvidenceBundleVerifyError> for M1RuntimeError {
    fn from(err: EvidenceBundleVerifyError) -> Self {
        Self::EvidenceBundle(err)
    }
}

impl From<std::io::Error> for M1RuntimeError {
    fn from(err: std::io::Error) -> Self {
        Self::PersistIo(err)
    }
}

impl From<bincode::Error> for M1RuntimeError {
    fn from(err: bincode::Error) -> Self {
        Self::PersistCodec(err)
    }
}

pub(crate) struct M1RuntimeSession {
    session: M1SessionMachine,
    chain: Chain,
    source_id: [u8; 32],
    session_id: Uuid,
    request_id: Uuid,
    scope: String,
    session_transcript_hash: Option<[u8; 32]>,
    next_audit_index: usize,
}

impl M1RuntimeSession {
    pub(crate) fn new(
        signing_key: SigningKey,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Self {
        Self::from_chain(
            Chain::new(signing_key),
            source_id,
            session_id,
            request_id,
            scope,
        )
    }

    pub(crate) fn from_chain(
        chain: Chain,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            session: M1SessionMachine::new(),
            chain,
            source_id,
            session_id,
            request_id,
            scope: scope.into(),
            session_transcript_hash: None,
            next_audit_index: 0,
        }
    }

    pub(crate) fn from_persisted_entries(
        signing_key: SigningKey,
        entries: Vec<LedgerEntry>,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Result<Self, M1RuntimeError> {
        let mut runtime = Self::from_chain(
            Chain::from_entries(entries, signing_key),
            source_id,
            session_id,
            request_id,
            scope,
        );
        runtime.replay_persisted_consent_state()?;
        Ok(runtime)
    }

    pub(crate) fn state(&self) -> M1SessionState {
        self.session.state()
    }

    pub(crate) fn entries(&self) -> Vec<LedgerEntry> {
        self.chain.iter().cloned().collect()
    }

    pub(crate) fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.chain.export_entries()
    }

    pub(crate) fn bind_session_transcript_hash(&mut self, transcript_hash: [u8; 32]) {
        self.session_transcript_hash = Some(transcript_hash);
    }

    pub(crate) fn session_transcript_binding(&self) -> Option<SessionTranscriptBinding> {
        self.session_transcript_hash.map(|hash| {
            SessionTranscriptBinding::from_hash(
                self.session_id,
                hash,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
            )
        })
    }

    pub(crate) fn verify_transcript_bound_export(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), M1RuntimeError> {
        let Some(binding) = self.session_transcript_binding() else {
            return Err(M1RuntimeError::MissingTranscriptBinding);
        };
        let entries = self.export_entries();
        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &entries,
            public_key,
        )?;
        Ok(())
    }

    pub(crate) fn ledger_len(&self) -> usize {
        self.chain.len()
    }

    pub(crate) fn stable_names(&self) -> Vec<&'static str> {
        self.chain
            .iter()
            .map(|entry| entry.event.stable_name())
            .collect()
    }

    pub(crate) fn persist_entries_bincode(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), M1RuntimeError> {
        let bytes = bincode::serialize(&self.entries())?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub(crate) fn load_entries_bincode(
        path: impl AsRef<Path>,
    ) -> Result<Vec<LedgerEntry>, M1RuntimeError> {
        let bytes = std::fs::read(path)?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub(crate) fn verify_entries(
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), M1RuntimeError> {
        Verifier::verify_chain(entries, public_key)?;
        Ok(())
    }

    fn replay_persisted_consent_state(&mut self) -> Result<(), M1RuntimeError> {
        let entries = self.entries();

        for entry in entries {
            match entry.event.kind {
                ConsentKind::Request => self.session.offer()?,
                ConsentKind::Approval => self.session.grant_consent()?,
                ConsentKind::Denial => self.session.deny_consent()?,
                ConsentKind::Revocation => self.session.revoke()?,
                ConsentKind::Violation => self.session.fail()?,
                ConsentKind::AthenaTriage => {}
            }
        }

        self.next_audit_index = self.session.audit().len();
        Ok(())
    }

    pub(crate) fn offer(&mut self) -> Result<(), M1RuntimeError> {
        self.session.offer()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn grant_consent(&mut self) -> Result<(), M1RuntimeError> {
        self.session.grant_consent()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn deny_consent(&mut self) -> Result<(), M1RuntimeError> {
        self.session.deny_consent()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn stream_frame(&mut self) -> Result<(), M1RuntimeError> {
        self.session.stream_frame()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn inject_input(&mut self) -> Result<(), M1RuntimeError> {
        self.session.inject_input()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn allow_frame_flow(&mut self) -> Result<(), M1RuntimeError> {
        self.stream_frame()
    }

    pub(crate) fn preflight_frame_flow(&self) -> Result<(), M1RuntimeError> {
        if self.session.state() == M1SessionState::Active {
            Ok(())
        } else {
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: self.session.state(),
                permission: M1Permission::StreamFrame,
            }))
        }
    }

    pub(crate) fn allow_input_flow(&mut self) -> Result<(), M1RuntimeError> {
        self.inject_input()
    }

    pub(crate) fn revoke(&mut self) -> Result<(), M1RuntimeError> {
        self.session.revoke()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn end(&mut self) -> Result<(), M1RuntimeError> {
        self.session.end()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn fail(&mut self) -> Result<(), M1RuntimeError> {
        self.session.fail()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn verify(&self, public_key: &VerifyingKey) -> Result<(), M1RuntimeError> {
        let entries = self.entries();
        Verifier::verify_chain(&entries, public_key)?;
        Ok(())
    }

    fn flush_new_audit_events(&mut self) -> Result<(), M1RuntimeError> {
        let events = self.session.audit()[self.next_audit_index..].to_vec();

        for event in events {
            if let Some(record) = consent_record_for_m1_event(
                self.source_id,
                self.session_id,
                self.request_id,
                self.scope.clone(),
                event,
            ) {
                self.chain.append(record)?;
            }
        }

        self.next_audit_index = self.session.audit().len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_ledger::ConsentKind;
    use xenia_peer_core::M1Permission;

    fn runtime(seed: u8) -> (M1RuntimeSession, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();

        let runtime = M1RuntimeSession::new(
            signing_key,
            [0xAB; 32],
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            "view screen",
        );

        (runtime, verifying_key)
    }

    #[test]
    fn runtime_lifecycle_appends_only_consent_boundaries() {
        let (mut runtime, verifying_key) = runtime(11);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.stream_frame().unwrap();
        runtime.inject_input().unwrap();
        runtime.revoke().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Revoked);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Approval);
        assert_eq!(entries[2].event.kind, ConsentKind::Revocation);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn runtime_exports_transcript_bound_evidence() {
        let (mut runtime, verifying_key) = runtime(21);
        runtime.bind_session_transcript_hash([0x5A; 32]);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let binding = runtime.session_transcript_binding().unwrap();
        assert_eq!(binding.session_id, Uuid::from_bytes([1; 16]));
        assert_eq!(binding.transcript_hash, [0x5A; 32]);
        assert_eq!(runtime.export_entries().len(), 3);
        runtime
            .verify_transcript_bound_export(&verifying_key)
            .expect("transcript-bound export should verify");
    }

    #[test]
    fn runtime_without_transcript_hash_cannot_verify_transcript_bound_export() {
        let (mut runtime, verifying_key) = runtime(22);
        runtime.offer().unwrap();

        assert!(matches!(
            runtime.verify_transcript_bound_export(&verifying_key),
            Err(M1RuntimeError::MissingTranscriptBinding)
        ));
    }

    #[test]
    fn stream_and_input_do_not_append_consent_entries() {
        let (mut runtime, verifying_key) = runtime(12);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();

        let before_ops = runtime.entries().len();
        runtime.stream_frame().unwrap();
        runtime.inject_input().unwrap();
        let after_ops = runtime.entries().len();

        assert_eq!(before_ops, 2);
        assert_eq!(after_ops, 2);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn denied_session_records_denial_and_blocks_privileged_flow() {
        let (mut runtime, verifying_key) = runtime(13);

        runtime.offer().unwrap();
        runtime.deny_consent().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Denied);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Denial);

        assert!(matches!(
            runtime.stream_frame(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Denied,
                permission: M1Permission::StreamFrame,
            }))
        ));

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn preflight_frame_flow_is_non_auditing_and_fails_closed() {
        let (mut runtime, _) = runtime(18);

        runtime.offer().unwrap();
        let before = runtime.ledger_len();
        assert!(matches!(
            runtime.preflight_frame_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::StreamFrame,
            }))
        ));
        assert_eq!(runtime.ledger_len(), before);

        runtime.grant_consent().unwrap();
        let before = runtime.ledger_len();
        runtime.preflight_frame_flow().unwrap();
        assert_eq!(runtime.ledger_len(), before);
    }

    #[test]
    fn normal_end_is_not_written_as_consent_revocation() {
        let (mut runtime, verifying_key) = runtime(14);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.end().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Ended);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Approval);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn failed_session_records_protocol_violation() {
        let (mut runtime, verifying_key) = runtime(15);

        runtime.offer().unwrap();
        runtime.fail().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Failed);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Violation);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn revoked_session_blocks_privileged_flow() {
        let (mut runtime, verifying_key) = runtime(16);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Revoked);
        assert_eq!(
            runtime.stable_names(),
            vec!["consent.requested", "consent.granted", "consent.revoked"]
        );
        assert!(matches!(
            runtime.allow_frame_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::StreamFrame,
            }))
        ));
        assert!(matches!(
            runtime.allow_input_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::InjectInput,
            }))
        ));

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn runtime_transcript_persists_and_reloads() {
        let (mut runtime, verifying_key) = runtime(17);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let path = std::env::temp_dir().join(format!(
            "xenia-m1-runtime-transcript-{}-{}.bin",
            std::process::id(),
            17
        ));

        runtime.persist_entries_bincode(&path).unwrap();
        let reloaded = M1RuntimeSession::load_entries_bincode(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(reloaded, runtime.entries());
        M1RuntimeSession::verify_entries(&reloaded, &verifying_key).unwrap();
    }

    #[test]
    fn rehydrated_runtime_continues_hash_chain() {
        let signing_key = SigningKey::from_bytes(&[18; 32]);
        let verifying_key = signing_key.verifying_key();
        let source_id = [0xAB; 32];
        let session_id = Uuid::from_bytes([1; 16]);
        let request_id = Uuid::from_bytes([2; 16]);

        let mut runtime = M1RuntimeSession::new(
            signing_key.clone(),
            source_id,
            session_id,
            request_id,
            "view screen",
        );
        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        let persisted = runtime.entries();

        let mut rehydrated = M1RuntimeSession::from_persisted_entries(
            signing_key,
            persisted,
            source_id,
            session_id,
            request_id,
            "view screen",
        )
        .unwrap();
        rehydrated.revoke().unwrap();

        let entries = rehydrated.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].event.kind, ConsentKind::Revocation);
        M1RuntimeSession::verify_entries(&entries, &verifying_key).unwrap();
    }
}
