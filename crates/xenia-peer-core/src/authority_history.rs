// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Signed, append-only machine-authority history for disconnected evidence qualification.
//!
//! Live authority answers whether a machine may act **now**. This module answers the separate
//! historical question: whether one exact machine authority epoch remained eligible from session
//! admission through a later observation time. History events form a domain-separated BLAKE3
//! chain. A signed head binds the exact chain head, a trusted completeness horizon, and a bounded
//! freshness horizon.
//!
//! Historical and current claims stay separate. Once a verified head covers an observation, the
//! past can be qualified without pretending the machine is authorized today. A separate
//! non-serializable freshness qualification is required before the same head may be treated as a
//! current authority snapshot. Transitions are non-retroactive, so a later append cannot rewrite
//! authority for time already covered by an earlier signed head.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Exact v1 schema number for authority-history events.
pub const MACHINE_AUTHORITY_HISTORY_EVENT_SCHEMA_V1: u8 = 1;
/// Exact v1 schema number for signed authority-history heads.
pub const MACHINE_AUTHORITY_HISTORY_HEAD_SCHEMA_V1: u8 = 1;

const EVENT_DIGEST_DOMAIN: &[u8] = b"xenia-machine-authority-history-event-v1\0";
const HEAD_SIGNATURE_DOMAIN: &[u8] = b"xenia-machine-authority-history-head-v1\0";

/// Grant payload for an authority-history event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthorityGrantV1 {
    /// Monotonic authority epoch being granted.
    pub authority_epoch: u64,
    /// Inclusive validity start.
    pub valid_from_ms: u64,
    /// Exclusive validity end.
    pub valid_until_ms: u64,
}

/// Revocation payload for an authority-history event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthorityRevocationV1 {
    /// Epoch being revoked.
    pub authority_epoch: u64,
    /// Inclusive instant at which that epoch ceases to be eligible.
    pub effective_at_ms: u64,
}

/// Supersession payload for an authority-history event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthoritySupersessionV1 {
    /// Existing epoch that ceases to be eligible.
    pub authority_epoch: u64,
    /// Strictly newer epoch that becomes eligible.
    pub next_authority_epoch: u64,
    /// Instant at which the transition takes effect.
    pub effective_at_ms: u64,
    /// Exclusive validity end for the new epoch.
    pub next_valid_until_ms: u64,
}

/// One append-only authority transition for a single hybrid machine identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineAuthorityHistoryTransitionV1 {
    /// Grant a new authority epoch.
    Grant(MachineAuthorityGrantV1),
    /// Revoke an existing authority epoch.
    Revoke(MachineAuthorityRevocationV1),
    /// Replace an existing epoch with a strictly newer epoch.
    Supersede(MachineAuthoritySupersessionV1),
}

/// One hash-chained authority-history event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthorityHistoryEventV1 {
    /// Exact wire schema number.
    pub schema_version: u8,
    /// Zero-based append-only sequence number for this machine identity.
    pub sequence: u64,
    /// Digest of the immediately preceding event. `None` is permitted only at sequence zero.
    pub previous_event_digest: Option<[u8; 32]>,
    /// Exact domain-separated hybrid signing-identity fingerprint.
    pub peer_identity_fingerprint: [u8; 32],
    /// Trusted-time instant at which this event was recorded by the authority source.
    pub recorded_at_ms: u64,
    /// Authority transition carried by this event.
    pub transition: MachineAuthorityHistoryTransitionV1,
}

impl MachineAuthorityHistoryEventV1 {
    /// Validate the event's self-contained shape before chain reconstruction.
    pub fn validate_shape(&self) -> Result<(), MachineAuthorityHistoryError> {
        if self.schema_version != MACHINE_AUTHORITY_HISTORY_EVENT_SCHEMA_V1 {
            return Err(MachineAuthorityHistoryError::InvalidEventSchema);
        }
        match (self.sequence, self.previous_event_digest) {
            (0, None) => {}
            (0, Some(_)) => return Err(MachineAuthorityHistoryError::RootHasPredecessor),
            (_, None) => return Err(MachineAuthorityHistoryError::MissingPredecessor),
            (_, Some(_)) => {}
        }
        match self.transition {
            MachineAuthorityHistoryTransitionV1::Grant(grant) => {
                if grant.valid_until_ms <= grant.valid_from_ms {
                    return Err(MachineAuthorityHistoryError::InvalidAuthorityInterval);
                }
                if grant.valid_from_ms < self.recorded_at_ms {
                    return Err(MachineAuthorityHistoryError::RetroactiveTransition);
                }
            }
            MachineAuthorityHistoryTransitionV1::Revoke(revocation) => {
                if revocation.effective_at_ms < self.recorded_at_ms {
                    return Err(MachineAuthorityHistoryError::RetroactiveTransition);
                }
            }
            MachineAuthorityHistoryTransitionV1::Supersede(supersession) => {
                if supersession.next_authority_epoch <= supersession.authority_epoch {
                    return Err(MachineAuthorityHistoryError::NonMonotonicEpoch);
                }
                if supersession.next_valid_until_ms <= supersession.effective_at_ms {
                    return Err(MachineAuthorityHistoryError::InvalidAuthorityInterval);
                }
                if supersession.effective_at_ms < self.recorded_at_ms {
                    return Err(MachineAuthorityHistoryError::RetroactiveTransition);
                }
            }
        }
        Ok(())
    }

    /// Deterministic domain-separated BLAKE3 digest used by the append-only chain.
    pub fn content_digest(&self) -> Result<[u8; 32], MachineAuthorityHistoryError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(EVENT_DIGEST_DOMAIN);
        hasher.update(&[self.schema_version]);
        hasher.update(&self.sequence.to_le_bytes());
        match self.previous_event_digest {
            Some(previous) => {
                hasher.update(&[1]);
                hasher.update(&previous);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&self.peer_identity_fingerprint);
        hasher.update(&self.recorded_at_ms.to_le_bytes());
        match self.transition {
            MachineAuthorityHistoryTransitionV1::Grant(grant) => {
                hasher.update(&[0]);
                hasher.update(&grant.authority_epoch.to_le_bytes());
                hasher.update(&grant.valid_from_ms.to_le_bytes());
                hasher.update(&grant.valid_until_ms.to_le_bytes());
            }
            MachineAuthorityHistoryTransitionV1::Revoke(revocation) => {
                hasher.update(&[1]);
                hasher.update(&revocation.authority_epoch.to_le_bytes());
                hasher.update(&revocation.effective_at_ms.to_le_bytes());
            }
            MachineAuthorityHistoryTransitionV1::Supersede(supersession) => {
                hasher.update(&[2]);
                hasher.update(&supersession.authority_epoch.to_le_bytes());
                hasher.update(&supersession.next_authority_epoch.to_le_bytes());
                hasher.update(&supersession.effective_at_ms.to_le_bytes());
                hasher.update(&supersession.next_valid_until_ms.to_le_bytes());
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Signed completeness/freshness statement for one authority-history chain head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthorityHistoryHeadV1 {
    /// Exact wire schema number.
    pub schema_version: u8,
    /// Machine identity whose history this head qualifies.
    pub peer_identity_fingerprint: [u8; 32],
    /// Sequence number of the exact history head.
    pub head_sequence: u64,
    /// Digest of the exact history head event.
    pub head_digest: [u8; 32],
    /// Authority source asserts the history is complete through this trusted-time instant.
    pub observed_through_ms: u64,
    /// Exclusive horizon after which this head cannot support **current** authority decisions.
    pub fresh_until_ms: u64,
}

impl MachineAuthorityHistoryHeadV1 {
    /// Validate the head's self-contained freshness shape.
    pub fn validate_shape(&self) -> Result<(), MachineAuthorityHistoryError> {
        if self.schema_version != MACHINE_AUTHORITY_HISTORY_HEAD_SCHEMA_V1 {
            return Err(MachineAuthorityHistoryError::InvalidHeadSchema);
        }
        if self.fresh_until_ms <= self.observed_through_ms {
            return Err(MachineAuthorityHistoryError::InvalidFreshnessWindow);
        }
        Ok(())
    }

    fn signing_digest(&self) -> Result<[u8; 32], MachineAuthorityHistoryError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(HEAD_SIGNATURE_DOMAIN);
        hasher.update(&[self.schema_version]);
        hasher.update(&self.peer_identity_fingerprint);
        hasher.update(&self.head_sequence.to_le_bytes());
        hasher.update(&self.head_digest);
        hasher.update(&self.observed_through_ms.to_le_bytes());
        hasher.update(&self.fresh_until_ms.to_le_bytes());
        Ok(*hasher.finalize().as_bytes())
    }

    /// Sign this exact history head with the authority source's Ed25519 key.
    pub fn sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<SignedMachineAuthorityHistoryHeadV1, MachineAuthorityHistoryError> {
        let digest = self.signing_digest()?;
        let signature = signing_key.sign(&digest).to_bytes().to_vec();
        Ok(SignedMachineAuthorityHistoryHeadV1 {
            head: self,
            signature: MachineAuthorityHistorySignatureV1::Ed25519(signature),
        })
    }
}

/// Signature envelope for a signed authority-history head.
///
/// V1 produces Ed25519 today. The tagged envelope keeps algorithm identity explicit so a later
/// qualified profile can add another suite without relabeling Ed25519 bytes as something stronger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineAuthorityHistorySignatureV1 {
    /// Ed25519 signature bytes. Exact length is validated before verification.
    Ed25519(Vec<u8>),
}

/// Portable signed authority-history head. Deserialization alone does not establish trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMachineAuthorityHistoryHeadV1 {
    /// Signed head claims.
    pub head: MachineAuthorityHistoryHeadV1,
    /// Explicit signature suite and bytes.
    pub signature: MachineAuthorityHistorySignatureV1,
}

impl SignedMachineAuthorityHistoryHeadV1 {
    /// Verify the signed head against an independently trusted authority public key.
    pub fn verify_signature(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), MachineAuthorityHistoryError> {
        let signature = match &self.signature {
            MachineAuthorityHistorySignatureV1::Ed25519(bytes) => {
                let array: [u8; 64] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| MachineAuthorityHistoryError::InvalidHeadSignature)?;
                Signature::from_bytes(&array)
            }
        };
        let digest = self.head.signing_digest()?;
        verifying_key
            .verify(&digest, &signature)
            .map_err(|_| MachineAuthorityHistoryError::InvalidHeadSignature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationReasonV1 {
    Revoked,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorityIntervalV1 {
    valid_from_ms: u64,
    valid_until_ms: u64,
    terminated_at_ms: Option<u64>,
    termination_reason: Option<TerminationReasonV1>,
}

/// Verified, non-serializable historical authority state.
///
/// This type can only be produced by [`verify_machine_authority_history`]. Persisted events and a
/// signed head remain evidence; they do not become positive historical authority until signature,
/// chain continuity, transition semantics, retained-head continuity and completeness all verify.
#[derive(Debug, Clone)]
pub struct VerifiedMachineAuthorityHistoryV1 {
    peer_identity_fingerprint: [u8; 32],
    observed_through_ms: u64,
    fresh_until_ms: u64,
    head_sequence: u64,
    head_digest: [u8; 32],
    intervals: BTreeMap<u64, AuthorityIntervalV1>,
}

impl VerifiedMachineAuthorityHistoryV1 {
    /// Machine identity whose history was verified.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Trusted-time instant through which the verified authority source asserts completeness.
    pub const fn observed_through_ms(&self) -> u64 {
        self.observed_through_ms
    }

    /// Exclusive freshness horizon for using this history as a current authority snapshot.
    pub const fn fresh_until_ms(&self) -> u64 {
        self.fresh_until_ms
    }

    /// Sequence number of the exact verified history head.
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    /// Digest of the exact verified history head event.
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    /// Qualify this signed head for current/offline authority use at one trusted-time instant.
    ///
    /// Historical eligibility does not require this token. This separate gate exists so an old
    /// signed history prefix can remain useful for auditing its covered past without allowing a
    /// disconnected node to keep treating that prefix as fresh current authority forever.
    pub fn qualify_current_snapshot(
        &self,
        now_ms: u64,
        trusted_time_available: bool,
    ) -> Result<FreshMachineAuthorityHistoryV1, MachineAuthorityHistoryError> {
        if !trusted_time_available {
            return Err(MachineAuthorityHistoryError::UntrustedTime);
        }
        if now_ms < self.observed_through_ms {
            return Err(MachineAuthorityHistoryError::HeadFromFuture);
        }
        if now_ms >= self.fresh_until_ms {
            return Err(MachineAuthorityHistoryError::StaleHistoryHead);
        }
        Ok(FreshMachineAuthorityHistoryV1 {
            peer_identity_fingerprint: self.peer_identity_fingerprint,
            now_ms,
            fresh_until_ms: self.fresh_until_ms,
            head_sequence: self.head_sequence,
            head_digest: self.head_digest,
        })
    }

    /// Qualify one exact authority epoch from session admission through an observation time.
    ///
    /// The observation must not precede session admission, the signed head must cover the
    /// observation time, and the requested epoch must remain eligible for the entire interval.
    /// A positive result is deliberately non-serializable and says nothing about current authority.
    pub fn qualify_session_observation(
        &self,
        authority_epoch: u64,
        session_authenticated_at_ms: u64,
        observation_at_ms: u64,
    ) -> Result<HistoricalMachineAuthorityQualificationV1, MachineAuthorityHistoryError> {
        if observation_at_ms < session_authenticated_at_ms {
            return Err(MachineAuthorityHistoryError::ObservationBeforeSession);
        }
        if observation_at_ms > self.observed_through_ms {
            return Err(MachineAuthorityHistoryError::HistoryNotCovered);
        }
        let interval = self
            .intervals
            .get(&authority_epoch)
            .copied()
            .ok_or(MachineAuthorityHistoryError::UnknownAuthorityEpoch)?;

        if session_authenticated_at_ms < interval.valid_from_ms
            || session_authenticated_at_ms >= interval.valid_until_ms
        {
            return Err(MachineAuthorityHistoryError::SessionOutsideAuthorityInterval);
        }
        if observation_at_ms >= interval.valid_until_ms {
            return Err(MachineAuthorityHistoryError::AuthorityExpiredBeforeObservation);
        }
        if let Some(terminated_at_ms) = interval.terminated_at_ms {
            if session_authenticated_at_ms >= terminated_at_ms || observation_at_ms >= terminated_at_ms {
                return Err(match interval.termination_reason {
                    Some(TerminationReasonV1::Revoked) => {
                        MachineAuthorityHistoryError::RevokedBeforeObservation
                    }
                    Some(TerminationReasonV1::Superseded) => {
                        MachineAuthorityHistoryError::SupersededBeforeObservation
                    }
                    None => MachineAuthorityHistoryError::AmbiguousHistory,
                });
            }
        }

        Ok(HistoricalMachineAuthorityQualificationV1 {
            peer_identity_fingerprint: self.peer_identity_fingerprint,
            authority_epoch,
            session_authenticated_at_ms,
            observation_at_ms,
            history_head_sequence: self.head_sequence,
            history_head_digest: self.head_digest,
            observed_through_ms: self.observed_through_ms,
        })
    }
}

/// Fresh, non-serializable proof that a signed history head is still usable for current decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshMachineAuthorityHistoryV1 {
    peer_identity_fingerprint: [u8; 32],
    now_ms: u64,
    fresh_until_ms: u64,
    head_sequence: u64,
    head_digest: [u8; 32],
}

impl FreshMachineAuthorityHistoryV1 {
    /// Machine identity covered by this fresh history snapshot.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Trusted-time instant at which freshness was evaluated.
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Exclusive offline/current-use horizon of the signed snapshot.
    pub const fn fresh_until_ms(&self) -> u64 {
        self.fresh_until_ms
    }

    /// Sequence number of the exact signed head whose freshness was checked.
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    /// Digest of the exact signed head whose freshness was checked.
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }
}

/// Non-serializable positive result that one historical session/observation interval was eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoricalMachineAuthorityQualificationV1 {
    peer_identity_fingerprint: [u8; 32],
    authority_epoch: u64,
    session_authenticated_at_ms: u64,
    observation_at_ms: u64,
    history_head_sequence: u64,
    history_head_digest: [u8; 32],
    observed_through_ms: u64,
}

impl HistoricalMachineAuthorityQualificationV1 {
    /// Machine identity qualified by the provider-owned history.
    pub const fn peer_identity_fingerprint(&self) -> [u8; 32] {
        self.peer_identity_fingerprint
    }

    /// Exact authority epoch qualified for the historical interval.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Session admission time qualified by history.
    pub const fn session_authenticated_at_ms(&self) -> u64 {
        self.session_authenticated_at_ms
    }

    /// Observation time qualified by history.
    pub const fn observation_at_ms(&self) -> u64 {
        self.observation_at_ms
    }

    /// Sequence number of the signed history head that supported this result.
    pub const fn history_head_sequence(&self) -> u64 {
        self.history_head_sequence
    }

    /// Digest of the signed history head event that supported this result.
    pub const fn history_head_digest(&self) -> [u8; 32] {
        self.history_head_digest
    }

    /// Completeness horizon of the signed history that supported this result.
    pub const fn observed_through_ms(&self) -> u64 {
        self.observed_through_ms
    }
}

/// Failure while validating, verifying, or qualifying machine-authority history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineAuthorityHistoryError {
    /// Event schema was not exactly v1.
    #[error("unsupported machine-authority history event schema")]
    InvalidEventSchema,
    /// Head schema was not exactly v1.
    #[error("unsupported machine-authority history head schema")]
    InvalidHeadSchema,
    /// Sequence-zero history event unexpectedly named a predecessor.
    #[error("machine-authority history root must not have a predecessor")]
    RootHasPredecessor,
    /// Non-root event omitted its predecessor digest.
    #[error("machine-authority history non-root event must name its predecessor")]
    MissingPredecessor,
    /// Authority validity interval was empty or reversed.
    #[error("machine-authority history interval must have positive duration")]
    InvalidAuthorityInterval,
    /// Authority epoch did not advance monotonically.
    #[error("machine-authority history epoch must advance monotonically")]
    NonMonotonicEpoch,
    /// A transition attempted to change authority before the transition was recorded.
    #[error("machine-authority history transitions must not be retroactive")]
    RetroactiveTransition,
    /// Signed freshness window was empty or reversed.
    #[error("machine-authority history freshness window must have positive duration")]
    InvalidFreshnessWindow,
    /// Signed head did not verify against the trusted authority key.
    #[error("machine-authority history head signature is invalid")]
    InvalidHeadSignature,
    /// Current-use qualification requires provider-approved trusted time.
    #[error("trusted time is required to qualify current machine-authority history")]
    UntrustedTime,
    /// Signed head claims completeness in the current verifier's future.
    #[error("machine-authority history head is not yet current")]
    HeadFromFuture,
    /// Signed head freshness horizon has expired for current authority use.
    #[error("machine-authority history head freshness horizon has expired")]
    StaleHistoryHead,
    /// No history events were supplied.
    #[error("machine-authority history is empty")]
    EmptyHistory,
    /// Event sequence was not contiguous from zero.
    #[error("machine-authority history sequence is discontinuous")]
    SequenceDiscontinuity,
    /// Event predecessor digest did not bind the immediately preceding event.
    #[error("machine-authority history predecessor binding is invalid")]
    PredecessorMismatch,
    /// Event identity differed from the signed head or another event.
    #[error("machine-authority history identity changed within one chain")]
    IdentityMismatch,
    /// An event was recorded later than the head's asserted completeness horizon.
    #[error("machine-authority history event lies beyond the signed completeness horizon")]
    EventBeyondHeadCoverage,
    /// Signed head sequence/digest did not match the supplied chain.
    #[error("signed machine-authority history head does not match supplied events")]
    HeadMismatch,
    /// A retained signed head is newer than the candidate head or has more coverage.
    #[error("machine-authority history rollback detected")]
    RetainedHeadRollback,
    /// Candidate chain conflicts with the exact retained signed head.
    #[error("machine-authority history fork detected against retained head")]
    RetainedHeadFork,
    /// Grant duplicated an existing authority epoch.
    #[error("machine-authority history contains a duplicate authority epoch")]
    DuplicateAuthorityEpoch,
    /// Authority intervals overlap or transition semantics conflict.
    #[error("machine-authority history contains ambiguous or overlapping authority state")]
    AmbiguousHistory,
    /// Revocation/supersession referred to a missing or already-terminated epoch.
    #[error("machine-authority history transition refers to unavailable authority state")]
    InvalidTransition,
    /// Signed history does not yet cover the requested observation time.
    #[error("machine-authority history does not cover the requested observation time")]
    HistoryNotCovered,
    /// Requested authority epoch does not appear in the verified history.
    #[error("requested authority epoch is absent from verified history")]
    UnknownAuthorityEpoch,
    /// Observation predates the session admission it is supposed to qualify.
    #[error("observation time precedes session authentication")]
    ObservationBeforeSession,
    /// Session admission was outside the requested authority epoch's interval.
    #[error("session authentication lies outside the historical authority interval")]
    SessionOutsideAuthorityInterval,
    /// Enrollment validity ended before the observation.
    #[error("machine authority expired before the observation")]
    AuthorityExpiredBeforeObservation,
    /// Revocation became effective before the observation interval completed.
    #[error("machine authority was revoked before the observation")]
    RevokedBeforeObservation,
    /// A newer authority epoch superseded the requested epoch before the observation.
    #[error("machine authority epoch was superseded before the observation")]
    SupersededBeforeObservation,
}

/// Verify a complete authority-history chain plus its signed completeness/freshness head.
///
/// `retained_head`, when supplied, must itself verify under the same trusted authority key. The
/// candidate chain must contain that exact retained sequence/digest and may never move backwards in
/// sequence or completeness coverage. Persisting the retained signed head in rollback-resistant
/// storage remains the embedding application's responsibility.
pub fn verify_machine_authority_history(
    events: &[MachineAuthorityHistoryEventV1],
    signed_head: &SignedMachineAuthorityHistoryHeadV1,
    verifying_key: &VerifyingKey,
    retained_head: Option<&SignedMachineAuthorityHistoryHeadV1>,
) -> Result<VerifiedMachineAuthorityHistoryV1, MachineAuthorityHistoryError> {
    signed_head.verify_signature(verifying_key)?;
    let head = &signed_head.head;
    if events.is_empty() {
        return Err(MachineAuthorityHistoryError::EmptyHistory);
    }

    if let Some(retained) = retained_head {
        retained.verify_signature(verifying_key)?;
        if retained.head.peer_identity_fingerprint != head.peer_identity_fingerprint {
            return Err(MachineAuthorityHistoryError::IdentityMismatch);
        }
        if head.head_sequence < retained.head.head_sequence
            || head.observed_through_ms < retained.head.observed_through_ms
        {
            return Err(MachineAuthorityHistoryError::RetainedHeadRollback);
        }
    }

    let mut previous_digest = None;
    let mut intervals = BTreeMap::<u64, AuthorityIntervalV1>::new();
    let mut last_epoch = None::<u64>;
    let mut last_effective_end = None::<u64>;

    for (index, event) in events.iter().enumerate() {
        event.validate_shape()?;
        let expected_sequence =
            u64::try_from(index).map_err(|_| MachineAuthorityHistoryError::SequenceDiscontinuity)?;
        if event.sequence != expected_sequence {
            return Err(MachineAuthorityHistoryError::SequenceDiscontinuity);
        }
        if event.peer_identity_fingerprint != head.peer_identity_fingerprint {
            return Err(MachineAuthorityHistoryError::IdentityMismatch);
        }
        if event.recorded_at_ms > head.observed_through_ms {
            return Err(MachineAuthorityHistoryError::EventBeyondHeadCoverage);
        }
        if event.previous_event_digest != previous_digest {
            return Err(MachineAuthorityHistoryError::PredecessorMismatch);
        }

        match event.transition {
            MachineAuthorityHistoryTransitionV1::Grant(grant) => {
                if intervals.contains_key(&grant.authority_epoch) {
                    return Err(MachineAuthorityHistoryError::DuplicateAuthorityEpoch);
                }
                if last_epoch.is_some_and(|epoch| grant.authority_epoch <= epoch) {
                    return Err(MachineAuthorityHistoryError::NonMonotonicEpoch);
                }
                if last_effective_end.is_some_and(|end| grant.valid_from_ms < end) {
                    return Err(MachineAuthorityHistoryError::AmbiguousHistory);
                }
                intervals.insert(
                    grant.authority_epoch,
                    AuthorityIntervalV1 {
                        valid_from_ms: grant.valid_from_ms,
                        valid_until_ms: grant.valid_until_ms,
                        terminated_at_ms: None,
                        termination_reason: None,
                    },
                );
                last_epoch = Some(grant.authority_epoch);
                last_effective_end = Some(grant.valid_until_ms);
            }
            MachineAuthorityHistoryTransitionV1::Revoke(revocation) => {
                let interval = intervals
                    .get_mut(&revocation.authority_epoch)
                    .ok_or(MachineAuthorityHistoryError::InvalidTransition)?;
                if interval.terminated_at_ms.is_some()
                    || revocation.effective_at_ms < interval.valid_from_ms
                    || revocation.effective_at_ms >= interval.valid_until_ms
                {
                    return Err(MachineAuthorityHistoryError::InvalidTransition);
                }
                interval.terminated_at_ms = Some(revocation.effective_at_ms);
                interval.termination_reason = Some(TerminationReasonV1::Revoked);
                if Some(revocation.authority_epoch) == last_epoch {
                    last_effective_end = Some(revocation.effective_at_ms);
                }
            }
            MachineAuthorityHistoryTransitionV1::Supersede(supersession) => {
                if intervals.contains_key(&supersession.next_authority_epoch) {
                    return Err(MachineAuthorityHistoryError::DuplicateAuthorityEpoch);
                }
                if last_epoch != Some(supersession.authority_epoch)
                    || supersession.next_authority_epoch <= supersession.authority_epoch
                {
                    return Err(MachineAuthorityHistoryError::InvalidTransition);
                }
                let interval = intervals
                    .get_mut(&supersession.authority_epoch)
                    .ok_or(MachineAuthorityHistoryError::InvalidTransition)?;
                if interval.terminated_at_ms.is_some()
                    || supersession.effective_at_ms < interval.valid_from_ms
                    || supersession.effective_at_ms >= interval.valid_until_ms
                    || supersession.next_valid_until_ms <= supersession.effective_at_ms
                {
                    return Err(MachineAuthorityHistoryError::InvalidTransition);
                }
                interval.terminated_at_ms = Some(supersession.effective_at_ms);
                interval.termination_reason = Some(TerminationReasonV1::Superseded);
                intervals.insert(
                    supersession.next_authority_epoch,
                    AuthorityIntervalV1 {
                        valid_from_ms: supersession.effective_at_ms,
                        valid_until_ms: supersession.next_valid_until_ms,
                        terminated_at_ms: None,
                        termination_reason: None,
                    },
                );
                last_epoch = Some(supersession.next_authority_epoch);
                last_effective_end = Some(supersession.next_valid_until_ms);
            }
        }

        previous_digest = Some(event.content_digest()?);
    }

    let last = events.last().ok_or(MachineAuthorityHistoryError::EmptyHistory)?;
    let last_digest = last.content_digest()?;
    if head.head_sequence != last.sequence || head.head_digest != last_digest {
        return Err(MachineAuthorityHistoryError::HeadMismatch);
    }

    if let Some(retained) = retained_head {
        let retained_event = events
            .iter()
            .find(|event| event.sequence == retained.head.head_sequence)
            .ok_or(MachineAuthorityHistoryError::RetainedHeadFork)?;
        if retained_event.content_digest()? != retained.head.head_digest {
            return Err(MachineAuthorityHistoryError::RetainedHeadFork);
        }
        if head.head_sequence == retained.head.head_sequence
            && head.head_digest != retained.head.head_digest
        {
            return Err(MachineAuthorityHistoryError::RetainedHeadFork);
        }
    }

    Ok(VerifiedMachineAuthorityHistoryV1 {
        peer_identity_fingerprint: head.peer_identity_fingerprint,
        observed_through_ms: head.observed_through_ms,
        fresh_until_ms: head.fresh_until_ms,
        head_sequence: head.head_sequence,
        head_digest: head.head_digest,
        intervals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 32] = [0x55; 32];

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn grant_payload(epoch: u64, valid_from_ms: u64, valid_until_ms: u64) -> MachineAuthorityGrantV1 {
        MachineAuthorityGrantV1 {
            authority_epoch: epoch,
            valid_from_ms,
            valid_until_ms,
        }
    }

    fn root_grant() -> MachineAuthorityHistoryEventV1 {
        MachineAuthorityHistoryEventV1 {
            schema_version: 1,
            sequence: 0,
            previous_event_digest: None,
            peer_identity_fingerprint: PEER,
            recorded_at_ms: 100,
            transition: MachineAuthorityHistoryTransitionV1::Grant(grant_payload(9, 100, 1_000)),
        }
    }

    fn append(
        previous: &MachineAuthorityHistoryEventV1,
        recorded_at_ms: u64,
        transition: MachineAuthorityHistoryTransitionV1,
    ) -> MachineAuthorityHistoryEventV1 {
        MachineAuthorityHistoryEventV1 {
            schema_version: 1,
            sequence: previous.sequence + 1,
            previous_event_digest: Some(previous.content_digest().unwrap()),
            peer_identity_fingerprint: PEER,
            recorded_at_ms,
            transition,
        }
    }

    fn sign_head(
        events: &[MachineAuthorityHistoryEventV1],
        observed_through_ms: u64,
        fresh_until_ms: u64,
    ) -> SignedMachineAuthorityHistoryHeadV1 {
        let last = events.last().unwrap();
        MachineAuthorityHistoryHeadV1 {
            schema_version: 1,
            peer_identity_fingerprint: PEER,
            head_sequence: last.sequence,
            head_digest: last.content_digest().unwrap(),
            observed_through_ms,
            fresh_until_ms,
        }
        .sign(&authority_key())
        .unwrap()
    }

    #[test]
    fn pre_revocation_observation_qualifies_but_post_revocation_fails() {
        let grant = root_grant();
        let revoke = append(
            &grant,
            500,
            MachineAuthorityHistoryTransitionV1::Revoke(MachineAuthorityRevocationV1 {
                authority_epoch: 9,
                effective_at_ms: 500,
            }),
        );
        let events = vec![grant, revoke];
        let head = sign_head(&events, 600, 700);
        let verified = verify_machine_authority_history(
            &events,
            &head,
            &authority_key().verifying_key(),
            None,
        )
        .unwrap();

        assert!(verified.qualify_session_observation(9, 200, 499).is_ok());
        assert_eq!(
            verified.qualify_session_observation(9, 200, 500),
            Err(MachineAuthorityHistoryError::RevokedBeforeObservation)
        );
    }

    #[test]
    fn epoch_rotation_qualifies_only_the_epoch_current_for_the_observation() {
        let grant = root_grant();
        let rotated = append(
            &grant,
            500,
            MachineAuthorityHistoryTransitionV1::Supersede(MachineAuthoritySupersessionV1 {
                authority_epoch: 9,
                next_authority_epoch: 10,
                effective_at_ms: 500,
                next_valid_until_ms: 1_500,
            }),
        );
        let events = vec![grant, rotated];
        let head = sign_head(&events, 800, 900);
        let verified = verify_machine_authority_history(
            &events,
            &head,
            &authority_key().verifying_key(),
            None,
        )
        .unwrap();

        assert_eq!(
            verified.qualify_session_observation(9, 200, 600),
            Err(MachineAuthorityHistoryError::SupersededBeforeObservation)
        );
        assert!(verified.qualify_session_observation(10, 500, 600).is_ok());
    }

    #[test]
    fn historical_proof_survives_head_staleness_but_current_use_does_not() {
        let events = vec![root_grant()];
        let head = sign_head(&events, 600, 700);
        let verified = verify_machine_authority_history(
            &events,
            &head,
            &authority_key().verifying_key(),
            None,
        )
        .unwrap();

        assert!(verified.qualify_session_observation(9, 200, 500).is_ok());
        assert!(verified.qualify_current_snapshot(650, true).is_ok());
        assert_eq!(
            verified.qualify_current_snapshot(700, true),
            Err(MachineAuthorityHistoryError::StaleHistoryHead)
        );
        assert_eq!(
            verified.qualify_current_snapshot(599, true),
            Err(MachineAuthorityHistoryError::HeadFromFuture)
        );
        assert_eq!(
            verified.qualify_current_snapshot(650, false),
            Err(MachineAuthorityHistoryError::UntrustedTime)
        );
    }

    #[test]
    fn tampered_event_or_head_signature_fails_closed() {
        let grant = root_grant();
        let events = vec![grant.clone()];
        let head = sign_head(&events, 200, 300);
        let key = authority_key();

        let mut tampered = grant;
        tampered.recorded_at_ms = 99;
        assert_eq!(
            verify_machine_authority_history(&[tampered], &head, &key.verifying_key(), None),
            Err(MachineAuthorityHistoryError::HeadMismatch)
        );

        let mut bad_head = head;
        let MachineAuthorityHistorySignatureV1::Ed25519(bytes) = &mut bad_head.signature;
        bytes[0] ^= 1;
        assert_eq!(
            verify_machine_authority_history(&events, &bad_head, &key.verifying_key(), None),
            Err(MachineAuthorityHistoryError::InvalidHeadSignature)
        );
    }

    #[test]
    fn retained_signed_head_detects_rollback_and_fork() {
        let grant = root_grant();
        let revoked = append(
            &grant,
            500,
            MachineAuthorityHistoryTransitionV1::Revoke(MachineAuthorityRevocationV1 {
                authority_epoch: 9,
                effective_at_ms: 500,
            }),
        );
        let root_events = vec![grant.clone()];
        let retained = sign_head(&root_events, 200, 1_000);
        let events = vec![grant, revoked];
        let current = sign_head(&events, 600, 1_000);
        let key = authority_key();

        assert!(verify_machine_authority_history(
            &events,
            &current,
            &key.verifying_key(),
            Some(&retained),
        )
        .is_ok());

        assert_eq!(
            verify_machine_authority_history(
                &root_events,
                &retained,
                &key.verifying_key(),
                Some(&current),
            ),
            Err(MachineAuthorityHistoryError::RetainedHeadRollback)
        );

        let mut forked_root = root_events[0].clone();
        forked_root.recorded_at_ms = 150;
        forked_root.transition =
            MachineAuthorityHistoryTransitionV1::Grant(grant_payload(9, 150, 1_000));
        let fork_events = vec![forked_root];
        let fork_head = sign_head(&fork_events, 200, 1_000);
        assert_eq!(
            verify_machine_authority_history(
                &fork_events,
                &fork_head,
                &key.verifying_key(),
                Some(&retained),
            ),
            Err(MachineAuthorityHistoryError::RetainedHeadFork)
        );
    }

    #[test]
    fn missing_ambiguous_and_uncovered_history_fail_closed() {
        let root = root_grant();
        let head = sign_head(&[root.clone()], 400, 500);
        let key = authority_key();
        let verified = verify_machine_authority_history(
            &[root.clone()],
            &head,
            &key.verifying_key(),
            None,
        )
        .unwrap();

        assert_eq!(
            verified.qualify_session_observation(10, 200, 300),
            Err(MachineAuthorityHistoryError::UnknownAuthorityEpoch)
        );
        assert_eq!(
            verified.qualify_session_observation(9, 200, 401),
            Err(MachineAuthorityHistoryError::HistoryNotCovered)
        );

        let duplicate = append(
            &root,
            200,
            MachineAuthorityHistoryTransitionV1::Grant(grant_payload(10, 200, 800)),
        );
        let ambiguous = vec![root, duplicate];
        let ambiguous_head = sign_head(&ambiguous, 400, 500);
        assert_eq!(
            verify_machine_authority_history(
                &ambiguous,
                &ambiguous_head,
                &key.verifying_key(),
                None,
            ),
            Err(MachineAuthorityHistoryError::AmbiguousHistory)
        );
    }

    #[test]
    fn retroactive_grant_revoke_or_rotation_is_rejected() {
        let mut root = root_grant();
        root.recorded_at_ms = 200;
        assert_eq!(
            root.validate_shape(),
            Err(MachineAuthorityHistoryError::RetroactiveTransition)
        );

        let root = root_grant();
        let retro_revoke = append(
            &root,
            500,
            MachineAuthorityHistoryTransitionV1::Revoke(MachineAuthorityRevocationV1 {
                authority_epoch: 9,
                effective_at_ms: 499,
            }),
        );
        assert_eq!(
            retro_revoke.validate_shape(),
            Err(MachineAuthorityHistoryError::RetroactiveTransition)
        );

        let retro_rotation = append(
            &root,
            500,
            MachineAuthorityHistoryTransitionV1::Supersede(MachineAuthoritySupersessionV1 {
                authority_epoch: 9,
                next_authority_epoch: 10,
                effective_at_ms: 499,
                next_valid_until_ms: 1_500,
            }),
        );
        assert_eq!(
            retro_rotation.validate_shape(),
            Err(MachineAuthorityHistoryError::RetroactiveTransition)
        );
    }

    #[test]
    fn malformed_signature_length_is_rejected() {
        let events = vec![root_grant()];
        let mut head = sign_head(&events, 200, 300);
        let MachineAuthorityHistorySignatureV1::Ed25519(bytes) = &mut head.signature;
        bytes.truncate(63);
        assert_eq!(
            head.verify_signature(&authority_key().verifying_key()),
            Err(MachineAuthorityHistoryError::InvalidHeadSignature)
        );
    }
}
