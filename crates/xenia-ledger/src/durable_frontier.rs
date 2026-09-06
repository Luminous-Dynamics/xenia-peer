// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opaque proof that the current in-memory Xenia ledger frontier has passed a
//! reviewed durable-storage verification boundary.
//!
//! The witness is intentionally process-local and non-serializable. It prevents
//! higher-level issuance APIs from accidentally treating `Chain::append` or a
//! merely non-ambiguous in-memory frontier as proof of persistence.

use thiserror::Error;

use crate::{
    AgentCapabilityAttestationError, AgentCapabilityAttestationV1, AgentCapabilityAuthorizationV1,
    Chain, LedgerEntry, LedgerError, PendingPersistenceFrontier, PersistenceDisposition,
    PersistenceReconciliationOutcome, SessionTranscriptBinding, SignedWitnessFrontierObservationV1,
    TransactionalAppendOutcome, WitnessFrontierAnchorAppendOutcomeV1, WitnessFrontierAnchorError,
    WitnessFrontierAnchorStore, WitnessFrontierAnchorTargetV1, XeniaWitnessFrontierSourcePolicyV1,
};

/// Schema version for [`DurableLedgerFrontierClaimV1`].
pub const DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION: u16 = 1;
/// Domain separator for a privacy-minimized durable-frontier commitment.
pub const DURABLE_LEDGER_FRONTIER_DOMAIN: &[u8] = b"xenia.durable-ledger-frontier.v1\0";

const ZERO32: [u8; 32] = [0; 32];

/// Exact frontier that a persistence adapter must prove is durably recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableLedgerFrontierClaimV1 {
    /// Must equal [`DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Total authenticated Xenia ledger entry count.
    pub entry_count: u64,
    /// Exact Xenia ledger head hash.
    pub head_hash: [u8; 32],
    /// Exact ledger authority public key for this chain.
    pub ledger_public_key: [u8; 32],
    /// Commitment to the reviewed persistence/restore policy that established durability.
    pub persistence_policy_digest: [u8; 32],
}

impl DurableLedgerFrontierClaimV1 {
    /// Validate the fixed structural contract.
    pub fn validate(self) -> Result<(), DurableLedgerFrontierError> {
        if self.schema_version != DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION
            || self.entry_count == 0
            || self.head_hash == ZERO32
            || self.ledger_public_key == ZERO32
            || self.persistence_policy_digest == ZERO32
        {
            return Err(DurableLedgerFrontierError::MalformedClaim);
        }
        Ok(())
    }

    /// Stable BLAKE3 commitment to the complete claim.
    pub fn digest(self) -> Result<[u8; 32], DurableLedgerFrontierError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(DURABLE_LEDGER_FRONTIER_DOMAIN);
        hasher.update(&self.schema_version.to_be_bytes());
        hasher.update(&self.entry_count.to_be_bytes());
        hasher.update(&self.head_hash);
        hasher.update(&self.ledger_public_key);
        hasher.update(&self.persistence_policy_digest);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Process-local capability proving one exact Xenia ledger frontier passed a
/// durable-storage verification boundary.
///
/// There is deliberately no public constructor, serde implementation or raw
/// field exposure. Higher-level code receives this only from the reviewed
/// methods in this module and must present it back to a durable issuance API.
#[derive(Debug)]
pub struct DurableLedgerFrontierV1 {
    claim: DurableLedgerFrontierClaimV1,
}

impl DurableLedgerFrontierV1 {
    /// Privacy-minimized commitment to the exact durable frontier and policy.
    pub fn digest(&self) -> [u8; 32] {
        self.claim
            .digest()
            .expect("private durable frontier is constructed only after validation")
    }

    /// Durable authenticated entry count.
    pub fn entry_count(&self) -> u64 {
        self.claim.entry_count
    }

    /// Durable authenticated chain head.
    pub fn head_hash(&self) -> [u8; 32] {
        self.claim.head_hash
    }

    /// Persistence-policy commitment under which the token was established.
    pub fn persistence_policy_digest(&self) -> [u8; 32] {
        self.claim.persistence_policy_digest
    }

    fn verify_against_chain(
        &self,
        chain: &Chain,
        expected_persistence_policy_digest: [u8; 32],
    ) -> Result<(), DurableLedgerFrontierError> {
        self.claim.validate()?;
        if expected_persistence_policy_digest == ZERO32
            || self.claim.persistence_policy_digest != expected_persistence_policy_digest
        {
            return Err(DurableLedgerFrontierError::PersistencePolicyMismatch);
        }
        if chain.has_uncertain_persistence() {
            return Err(DurableLedgerFrontierError::PersistenceUncertain);
        }
        let current = durable_claim_for_chain(chain, self.claim.persistence_policy_digest)?;
        if current != self.claim {
            return Err(DurableLedgerFrontierError::ChainFrontierMismatch);
        }
        Ok(())
    }
}

/// Outcome-aware append result that mints a durable frontier witness only when
/// the persistence backend says the exact candidate was durably committed.
#[derive(Debug)]
pub enum DurableLedgerAppendOutcomeV1 {
    /// Candidate persisted and the returned token binds the resulting exact frontier.
    Persisted {
        /// Exact ledger entry that became durable.
        entry: LedgerEntry,
        /// Opaque durable-frontier token.
        durable_frontier: DurableLedgerFrontierV1,
    },
    /// Persistence was proven absent; no durable token exists for the reverted candidate.
    ProvenNotPersisted {
        /// Privacy-minimized backend diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact candidate safely removed from memory.
        reverted_entry: LedgerEntry,
    },
    /// Persistence may have happened; no durable token is issued until reconciliation.
    OutcomeUnknown {
        /// Privacy-minimized backend diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact ambiguous frontier retained by #287.
        pending: PendingPersistenceFrontier,
    },
}

/// Reconciliation result. A durable token appears only after ambiguous
/// persistence is explicitly established as committed.
#[derive(Debug)]
pub enum DurableLedgerReconciliationOutcomeV1 {
    /// Candidate is durably present and can now authorize durable-only issuance.
    Persisted {
        /// Exact ledger entry confirmed durable.
        entry: LedgerEntry,
        /// Opaque durable-frontier token.
        durable_frontier: DurableLedgerFrontierV1,
    },
    /// Candidate is definitively absent and was removed.
    ProvenNotPersisted {
        /// Privacy-minimized backend diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact candidate removed after reconciliation.
        reverted_entry: LedgerEntry,
    },
    /// Persistence remains unresolved; no token exists.
    OutcomeUnknown {
        /// Privacy-minimized backend diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact ambiguous frontier retained by #287.
        pending: PendingPersistenceFrontier,
    },
}

impl Chain {
    /// Verify that an already-restored chain exactly matches an authoritative
    /// durable-storage view, then mint an opaque frontier witness.
    ///
    /// `verify` is the restore adapter's reviewed trust boundary. It receives
    /// both the restored chain and the exact durability claim so one callback can
    /// establish durable recoverability and perform the appropriate Xenia
    /// cryptographic restore-integrity verification before returning success.
    /// An error mints no token.
    pub fn verify_restored_durable_frontier_v1(
        &self,
        persistence_policy_digest: [u8; 32],
        verify: impl FnOnce(&Self, &DurableLedgerFrontierClaimV1) -> Result<(), [u8; 32]>,
    ) -> Result<DurableLedgerFrontierV1, DurableLedgerFrontierError> {
        if self.has_uncertain_persistence() {
            return Err(DurableLedgerFrontierError::PersistenceUncertain);
        }
        let before = durable_claim_for_chain(self, persistence_policy_digest)?;
        if let Err(diagnostic_digest) = verify(self, &before) {
            return Err(DurableLedgerFrontierError::PersistenceVerificationRejected(
                nonzero_diagnostic(diagnostic_digest, b"restore-verifier-rejected"),
            ));
        }
        let after = durable_claim_for_chain(self, persistence_policy_digest)?;
        if before != after {
            return Err(DurableLedgerFrontierError::ChainFrontierMismatch);
        }
        Ok(DurableLedgerFrontierV1 { claim: after })
    }

    /// Outcome-aware append that returns an opaque durable token only after the
    /// exact candidate frontier is confirmed persisted.
    pub fn append_transactional_outcome_durable_v1(
        &mut self,
        event: crate::ConsentEventRecord,
        persistence_policy_digest: [u8; 32],
        persist: impl FnOnce(&Self, &DurableLedgerFrontierClaimV1) -> PersistenceDisposition<[u8; 32]>,
    ) -> Result<DurableLedgerAppendOutcomeV1, DurableLedgerFrontierError> {
        validate_policy_digest(persistence_policy_digest)?;
        let outcome = self.append_transactional_outcome(event, |chain| {
            let claim = durable_claim_for_chain_allow_pending(chain, persistence_policy_digest)
                .expect("outcome-aware append has already established a valid candidate frontier");
            persist(chain, &claim)
        })?;
        match outcome {
            TransactionalAppendOutcome::Persisted(entry) => {
                let claim = durable_claim_for_chain(self, persistence_policy_digest)?;
                Ok(DurableLedgerAppendOutcomeV1::Persisted {
                    entry,
                    durable_frontier: DurableLedgerFrontierV1 { claim },
                })
            }
            TransactionalAppendOutcome::ProvenNotPersisted {
                error,
                reverted_entry,
            } => Ok(DurableLedgerAppendOutcomeV1::ProvenNotPersisted {
                diagnostic_digest: nonzero_diagnostic(error, b"append-proven-not-persisted"),
                reverted_entry,
            }),
            TransactionalAppendOutcome::OutcomeUnknown { error, pending } => {
                Ok(DurableLedgerAppendOutcomeV1::OutcomeUnknown {
                    diagnostic_digest: nonzero_diagnostic(error, b"append-outcome-unknown"),
                    pending,
                })
            }
        }
    }

    /// Reconcile an exact #287 ambiguous candidate and mint a durable token only
    /// if the persistence adapter proves that candidate is durably present.
    pub fn reconcile_pending_persistence_durable_v1(
        &mut self,
        persistence_policy_digest: [u8; 32],
        reconcile: impl FnOnce(
            &Self,
            PendingPersistenceFrontier,
            &DurableLedgerFrontierClaimV1,
        ) -> PersistenceDisposition<[u8; 32]>,
    ) -> Result<DurableLedgerReconciliationOutcomeV1, DurableLedgerFrontierError> {
        validate_policy_digest(persistence_policy_digest)?;
        let outcome = self.reconcile_pending_persistence(|chain, pending| {
            let claim = durable_claim_for_chain_allow_pending(chain, persistence_policy_digest)
                .expect("pending reconciliation has a structurally valid candidate frontier");
            reconcile(chain, pending, &claim)
        })?;
        match outcome {
            PersistenceReconciliationOutcome::Persisted(entry) => {
                let claim = durable_claim_for_chain(self, persistence_policy_digest)?;
                Ok(DurableLedgerReconciliationOutcomeV1::Persisted {
                    entry,
                    durable_frontier: DurableLedgerFrontierV1 { claim },
                })
            }
            PersistenceReconciliationOutcome::ProvenNotPersisted {
                error,
                reverted_entry,
            } => Ok(DurableLedgerReconciliationOutcomeV1::ProvenNotPersisted {
                diagnostic_digest: nonzero_diagnostic(error, b"reconcile-proven-not-persisted"),
                reverted_entry,
            }),
            PersistenceReconciliationOutcome::OutcomeUnknown { error, pending } => {
                Ok(DurableLedgerReconciliationOutcomeV1::OutcomeUnknown {
                    diagnostic_digest: nonzero_diagnostic(error, b"reconcile-outcome-unknown"),
                    pending,
                })
            }
        }
    }

    /// Durable-only bounded-agent authorization issuance.
    ///
    /// The token must match this exact current chain and the integration's
    /// expected persistence-policy commitment before #232's signer is entered.
    pub fn attest_agent_capability_authorization_durable_v1(
        &self,
        authorization: AgentCapabilityAuthorizationV1,
        session_binding: &SessionTranscriptBinding,
        durable_frontier: &DurableLedgerFrontierV1,
        expected_persistence_policy_digest: [u8; 32],
    ) -> Result<AgentCapabilityAttestationV1, DurableLedgerFrontierError> {
        durable_frontier.verify_against_chain(self, expected_persistence_policy_digest)?;
        self.attest_agent_capability_authorization(authorization, session_binding)
            .map_err(DurableLedgerFrontierError::AgentAuthority)
    }

    /// Durable-only witness-anchor append. The durable consent frontier remains
    /// a separate prerequisite from the anchor store's own CAS durability.
    #[allow(clippy::too_many_arguments)]
    pub fn append_witness_frontier_anchor_durable_v1<S: WitnessFrontierAnchorStore>(
        &self,
        target: WitnessFrontierAnchorTargetV1,
        source_policy: XeniaWitnessFrontierSourcePolicyV1,
        issued_at_unix_s: u64,
        anchor_store: &mut S,
        durable_frontier: &DurableLedgerFrontierV1,
        expected_persistence_policy_digest: [u8; 32],
    ) -> Result<WitnessFrontierAnchorAppendOutcomeV1, DurableLedgerFrontierError> {
        durable_frontier.verify_against_chain(self, expected_persistence_policy_digest)?;
        self.append_witness_frontier_anchor_v1(
            target,
            source_policy,
            issued_at_unix_s,
            anchor_store,
        )
        .map_err(DurableLedgerFrontierError::WitnessAnchor)
    }

    /// Durable-only fresh observation of the current witness anchor.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_witness_frontier_durable_v1<S: WitnessFrontierAnchorStore>(
        &self,
        witness_id: [u8; 16],
        challenge: [u8; 32],
        source_policy: XeniaWitnessFrontierSourcePolicyV1,
        observed_at_unix_s: u64,
        anchor_store: &mut S,
        durable_frontier: &DurableLedgerFrontierV1,
        expected_persistence_policy_digest: [u8; 32],
    ) -> Result<SignedWitnessFrontierObservationV1, DurableLedgerFrontierError> {
        durable_frontier.verify_against_chain(self, expected_persistence_policy_digest)?;
        self.observe_witness_frontier_v1(
            witness_id,
            challenge,
            source_policy,
            observed_at_unix_s,
            anchor_store,
        )
        .map_err(DurableLedgerFrontierError::WitnessAnchor)
    }
}

fn durable_claim_for_chain(
    chain: &Chain,
    persistence_policy_digest: [u8; 32],
) -> Result<DurableLedgerFrontierClaimV1, DurableLedgerFrontierError> {
    if chain.has_uncertain_persistence() {
        return Err(DurableLedgerFrontierError::PersistenceUncertain);
    }
    durable_claim_for_chain_allow_pending(chain, persistence_policy_digest)
}

fn durable_claim_for_chain_allow_pending(
    chain: &Chain,
    persistence_policy_digest: [u8; 32],
) -> Result<DurableLedgerFrontierClaimV1, DurableLedgerFrontierError> {
    validate_policy_digest(persistence_policy_digest)?;
    let claim = DurableLedgerFrontierClaimV1 {
        schema_version: DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION,
        entry_count: chain.entry_count(),
        head_hash: chain.last_hash(),
        ledger_public_key: chain.signing_key.verifying_key().to_bytes(),
        persistence_policy_digest,
    };
    claim.validate()?;
    Ok(claim)
}

fn validate_policy_digest(value: [u8; 32]) -> Result<(), DurableLedgerFrontierError> {
    if value == ZERO32 {
        return Err(DurableLedgerFrontierError::InvalidPersistencePolicy);
    }
    Ok(())
}

fn nonzero_diagnostic(value: [u8; 32], label: &[u8]) -> [u8; 32] {
    if value != ZERO32 {
        return value;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia.durable-ledger-frontier-diagnostic.v1\0");
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

/// Durable-ledger-frontier verification/issuance errors.
#[derive(Debug, Error)]
pub enum DurableLedgerFrontierError {
    /// Claim contained zero/unsupported structure.
    #[error("malformed durable Xenia ledger frontier claim")]
    MalformedClaim,
    /// Persistence-policy commitment cannot be zero.
    #[error("durable ledger persistence policy must be nonzero")]
    InvalidPersistencePolicy,
    /// Token was minted under a different persistence policy.
    #[error("durable ledger persistence policy mismatch")]
    PersistencePolicyMismatch,
    /// #287 still has an unresolved persistence outcome.
    #[error("Xenia ledger persistence remains unresolved")]
    PersistenceUncertain,
    /// Current chain no longer equals the frontier represented by the token.
    #[error("durable ledger token does not match current Xenia chain")]
    ChainFrontierMismatch,
    /// Authoritative storage verification rejected the restored frontier.
    #[error("durable ledger storage verifier rejected the frontier")]
    PersistenceVerificationRejected([u8; 32]),
    /// Underlying ledger operation failed before a durable result existed.
    #[error("Xenia ledger operation failed: {0}")]
    Ledger(#[from] LedgerError),
    /// #232 bounded-agent authority signer rejected the request.
    #[error("durable agent authority issuance failed: {0}")]
    AgentAuthority(#[from] AgentCapabilityAttestationError),
    /// Witness-anchor source rejected the request.
    #[error("durable witness-anchor issuance failed: {0}")]
    WitnessAnchor(#[from] WitnessFrontierAnchorError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    use super::*;
    use crate::{
        AgentCheckpointAnchorV1, ConsentEventRecord, ConsentKind, SignatureSuite,
        TranscriptSignatureSuiteV1,
    };

    const PERSISTENCE_POLICY: [u8; 32] = [0xD1; 32];

    fn event(request_byte: u8) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0x11; 32],
            session_id: Uuid::from_bytes([0x22; 16]),
            request_id: Uuid::from_bytes([request_byte; 16]),
            kind: ConsentKind::Approval,
            scope: "durable frontier test".into(),
        }
    }

    fn session() -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_bytes([0x22; 16]),
            [0x77; 32],
            SignatureSuite::Ed25519Rfc8032,
        )
    }

    fn authorization(chain: &Chain) -> AgentCapabilityAuthorizationV1 {
        AgentCapabilityAuthorizationV1 {
            schema_version: 1,
            authorization_id: [1; 16],
            session_id: [0x22; 16],
            session_transcript_hash: [0x77; 32],
            session_signature_suite: TranscriptSignatureSuiteV1::Ed25519Rfc8032,
            capability_digest: [0x44; 32],
            executor_workload_digest: [0x55; 32],
            authority_epoch: 9,
            issued_at_unix_s: 100,
            expires_at_unix_s: 200,
            nonce: [0x66; 16],
            ledger_entry_count: chain.entry_count(),
            ledger_head_hash: chain.last_hash(),
            prior_checkpoint: Some(AgentCheckpointAnchorV1 {
                sequence: 3,
                digest: [0x88; 32],
            }),
        }
    }

    #[test]
    fn persisted_append_mints_token_and_enables_durable_authority() {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let outcome = chain
            .append_transactional_outcome_durable_v1(event(1), PERSISTENCE_POLICY, |_, claim| {
                assert_eq!(claim.entry_count, 1);
                PersistenceDisposition::Persisted
            })
            .unwrap();
        let durable_frontier = match outcome {
            DurableLedgerAppendOutcomeV1::Persisted {
                durable_frontier, ..
            } => durable_frontier,
            _ => panic!("expected durable persisted result"),
        };
        assert_eq!(durable_frontier.entry_count(), 1);

        chain
            .attest_agent_capability_authorization_durable_v1(
                authorization(&chain),
                &session(),
                &durable_frontier,
                PERSISTENCE_POLICY,
            )
            .unwrap();
    }

    #[test]
    fn stale_token_cannot_authorize_after_chain_advances() {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let token = match chain
            .append_transactional_outcome_durable_v1(event(1), PERSISTENCE_POLICY, |_, _| {
                PersistenceDisposition::Persisted
            })
            .unwrap()
        {
            DurableLedgerAppendOutcomeV1::Persisted {
                durable_frontier, ..
            } => durable_frontier,
            _ => panic!("expected persisted"),
        };
        chain.append(event(2)).unwrap();
        assert!(matches!(
            chain.attest_agent_capability_authorization_durable_v1(
                authorization(&chain),
                &session(),
                &token,
                PERSISTENCE_POLICY,
            ),
            Err(DurableLedgerFrontierError::ChainFrontierMismatch)
        ));
    }

    #[test]
    fn unknown_append_mints_no_token_and_reconciliation_can_later_mint_one() {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let outcome = chain
            .append_transactional_outcome_durable_v1(event(1), PERSISTENCE_POLICY, |_, _| {
                PersistenceDisposition::OutcomeUnknown([0xEE; 32])
            })
            .unwrap();
        assert!(matches!(
            outcome,
            DurableLedgerAppendOutcomeV1::OutcomeUnknown { .. }
        ));
        assert!(chain.has_uncertain_persistence());
        assert!(matches!(
            chain.verify_restored_durable_frontier_v1(PERSISTENCE_POLICY, |_, _| Ok(())),
            Err(DurableLedgerFrontierError::PersistenceUncertain)
        ));

        let reconciled = chain
            .reconcile_pending_persistence_durable_v1(PERSISTENCE_POLICY, |_, pending, claim| {
                assert_eq!(pending.entry_count, claim.entry_count);
                assert_eq!(pending.head_hash, claim.head_hash);
                PersistenceDisposition::Persisted
            })
            .unwrap();
        let token = match reconciled {
            DurableLedgerReconciliationOutcomeV1::Persisted {
                durable_frontier, ..
            } => durable_frontier,
            _ => panic!("expected persisted reconciliation"),
        };
        assert!(!chain.has_uncertain_persistence());
        token
            .verify_against_chain(&chain, PERSISTENCE_POLICY)
            .unwrap();
    }

    #[test]
    fn restored_chain_requires_authoritative_exact_frontier_verification() {
        let mut original = Chain::new(SigningKey::from_bytes(&[3; 32]));
        original.append(event(1)).unwrap();
        let entries = original.into_entries();
        let restored = Chain::from_entries(entries, SigningKey::from_bytes(&[3; 32]));

        assert!(matches!(
            restored.verify_restored_durable_frontier_v1(PERSISTENCE_POLICY, |_, _| {
                Err([0xA1; 32])
            }),
            Err(DurableLedgerFrontierError::PersistenceVerificationRejected(
                _
            ))
        ));
        let token = restored
            .verify_restored_durable_frontier_v1(PERSISTENCE_POLICY, |chain, claim| {
                assert_eq!(chain.entry_count(), claim.entry_count);
                assert_eq!(chain.last_hash(), claim.head_hash);
                let resident: Vec<_> = chain.iter().cloned().collect();
                crate::Verifier::verify_chain(
                    &resident,
                    &SigningKey::from_bytes(&[3; 32]).verifying_key(),
                )
                .map_err(|_| [0xA2; 32])?;
                Ok(())
            })
            .unwrap();
        token
            .verify_against_chain(&restored, PERSISTENCE_POLICY)
            .unwrap();
    }
}
