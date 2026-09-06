// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::SigningKey;
use xenia_ledger::{
    AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION, AgentCapabilityConsentIntentV1,
    AgentCheckpointAnchorV1, AgentConsentAuthorityError, Chain, ConsentEventRecord, ConsentKind,
    DurableLedgerAppendOutcomeV1, DurableLedgerFrontierV1, Ed25519EvidenceSignatureBackend,
    EvidencePublicKeyBinding, PersistenceDisposition, SessionTranscriptBinding, SignatureSuite,
    TranscriptSignatureSuiteV1, verify_durable_consent_bound_agent_capability_attestation_v1,
};

const PERSISTENCE_POLICY: [u8; 32] = [0xD1; 32];
const SIGNING_SEED: [u8; 32] = [3; 32];

fn intent() -> AgentCapabilityConsentIntentV1 {
    AgentCapabilityConsentIntentV1 {
        schema_version: AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION,
        requester_source_id: [0x11; 32],
        authorization_id: [0x21; 16],
        session_id: [0x22; 16],
        session_transcript_hash: [0x33; 32],
        session_signature_suite: TranscriptSignatureSuiteV1::Ed25519Rfc8032,
        capability_digest: [0x44; 32],
        executor_workload_digest: [0x55; 32],
        authority_epoch: 9,
        issued_at_unix_s: 100,
        expires_at_unix_s: 200,
        nonce: [0x66; 16],
        prior_checkpoint: Some(AgentCheckpointAnchorV1 {
            sequence: 3,
            digest: [0x77; 32],
        }),
        consent_presentation_digest: [0x88; 32],
    }
}

fn session() -> SessionTranscriptBinding {
    SessionTranscriptBinding::from_hash(
        uuid::Uuid::from_bytes([0x22; 16]),
        [0x33; 32],
        SignatureSuite::Ed25519Rfc8032,
    )
}

fn approval_for(intent: AgentCapabilityConsentIntentV1) -> ConsentEventRecord {
    let mut event = intent.request_record().unwrap();
    event.kind = ConsentKind::Approval;
    event
}

fn append_durable(chain: &mut Chain, event: ConsentEventRecord) -> DurableLedgerFrontierV1 {
    match chain
        .append_transactional_outcome_durable_v1(event, PERSISTENCE_POLICY, |_, _| {
            PersistenceDisposition::Persisted
        })
        .unwrap()
    {
        DurableLedgerAppendOutcomeV1::Persisted {
            durable_frontier, ..
        } => durable_frontier,
        _ => panic!("expected persisted durable append"),
    }
}

#[test]
fn public_request_approval_durability_and_verification_path_is_closed_world() {
    let intent = intent();
    let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut chain = Chain::new(signing_key);

    let _request_frontier = append_durable(&mut chain, intent.request_record().unwrap());
    let durable_frontier = append_durable(&mut chain, approval_for(intent));
    let attestation = chain
        .attest_agent_capability_consent_bound_durable_v1(
            intent,
            &session(),
            &durable_frontier,
            PERSISTENCE_POLICY,
        )
        .unwrap();

    let key_binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
    verify_durable_consent_bound_agent_capability_attestation_v1(
        &attestation,
        &session(),
        &key_binding,
        &Ed25519EvidenceSignatureBackend,
        120,
        intent.capability_digest,
        intent.executor_workload_digest,
        intent.authority_epoch,
        intent.prior_checkpoint,
        PERSISTENCE_POLICY,
    )
    .unwrap();

    assert_eq!(attestation.consent.request_entry_seq, 0);
    assert_eq!(attestation.consent.approval_entry_seq, 1);
    assert_eq!(attestation.inner.authorization.ledger_entry_count, 2);
}

#[test]
fn compacted_prefix_cannot_mint_consent_bound_authority_without_history_proof() {
    let intent = intent();
    let mut complete = Chain::new(SigningKey::from_bytes(&SIGNING_SEED));
    let _request_frontier = append_durable(&mut complete, intent.request_record().unwrap());
    let _approval_frontier = append_durable(&mut complete, approval_for(intent));
    let checkpoint = complete.sign_checkpoint(150);

    let compacted = Chain::from_checkpoint_suffix(
        checkpoint,
        Vec::new(),
        SigningKey::from_bytes(&SIGNING_SEED),
    );
    let durable_frontier = compacted
        .verify_restored_durable_frontier_v1(PERSISTENCE_POLICY, |_, _| Ok(()))
        .unwrap();

    assert!(matches!(
        compacted.attest_agent_capability_consent_bound_durable_v1(
            intent,
            &session(),
            &durable_frontier,
            PERSISTENCE_POLICY,
        ),
        Err(AgentConsentAuthorityError::CompactedConsentHistory)
    ));
}
