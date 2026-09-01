// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authority-owned namespace selection for Xenia external operation-authority retention.
//!
//! ADR-028 deliberately leaves `AuthorityRetentionNamespaceV1` as syntax rather than authority.
//! This crate closes that boundary: a deployment trust source must independently authenticate the
//! expected namespace commitment for the requested operation-authority domain before append or
//! readback can reach the raw provider backend contract.
//!
//! The verified token is private-field, non-serializable, single-use by the provided wrappers, and
//! short-lived. Serialized namespace bytes therefore cannot manufacture a successful trust result.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;
use xenia_operation_authority_retention_backend::{
    AuthorityRetentionBackendErrorV1, AuthorityRetentionNamespaceV1,
    ImmutableAuthorityRetentionBackendV1, append_via_backend_v1, readback_complete_lineage_v1,
};
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, OperationAuthorityRetentionModelV2,
    OperationAuthorityRetentionRecordV2,
};

/// Maximum lifetime of one in-process verified namespace token.
///
/// This is an application-time stale-token bound, not a Byzantine/trusted-clock claim.
pub const VERIFIED_NAMESPACE_TOKEN_MAX_LIFETIME_MS_V1: u64 = 60_000;

/// Result returned by the deployment's independently administered namespace trust source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceTrustOutcomeV1 {
    /// The trust source authenticated the current expected namespace commitment for the domain.
    Authenticated {
        /// Authority domain for which the result was issued.
        authority_domain_id: [u8; 16],
        /// Exact namespace digest the trust source says is current.
        expected_namespace_digest: [u8; 32],
        /// Non-zero commitment to the trust-source evidence/configuration used for this result.
        trust_evidence_digest: [u8; 32],
        /// Latest local Unix-millisecond time at which this result may begin an operation.
        valid_until_unix_ms: u64,
    },
    /// Trust source positively rejects the requested authority domain/namespace relationship.
    Rejected,
    /// Trust source cannot currently authenticate which namespace is current.
    Unknown,
}

/// External authority source for the expected namespace of one operation-authority domain.
///
/// Implementations are deployment trust roots. Examples may include a separately administered
/// registry, TPM/secure-element-backed configuration, or a remote witness service. Merely reading
/// rollbackable local application configuration is not sufficient for the ADR-029 deployment claim.
pub trait AuthorityRetentionNamespaceTrustSourceV1 {
    /// Authenticate the currently expected namespace for `authority_domain_id`.
    fn authenticate_expected_namespace(
        &mut self,
        authority_domain_id: [u8; 16],
    ) -> NamespaceTrustOutcomeV1;
}

/// Non-serializable successful namespace trust composition.
///
/// Fields are private and the type is intentionally neither `Clone` nor `Copy`. The append/readback
/// wrappers consume it so every external operation requires a fresh trust-source decision.
#[derive(Debug)]
pub struct VerifiedAuthorityRetentionNamespaceV1 {
    namespace: AuthorityRetentionNamespaceV1,
    namespace_digest: [u8; 32],
    trust_evidence_digest: [u8; 32],
    verified_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl VerifiedAuthorityRetentionNamespaceV1 {
    /// Exact namespace commitment that passed the external trust gate.
    pub const fn namespace_digest(&self) -> [u8; 32] {
        self.namespace_digest
    }

    /// Operation-authority domain bound by the verified namespace.
    pub const fn authority_domain_id(&self) -> [u8; 16] {
        self.namespace.authority_domain_id
    }

    /// Exact trust-source evidence commitment returned for this verification.
    pub const fn trust_evidence_digest(&self) -> [u8; 32] {
        self.trust_evidence_digest
    }

    /// Local time at which this namespace was verified.
    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    /// Effective local expiry after applying the trust-source and Xenia token-lifetime bounds.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    fn validate_live(&self, now_unix_ms: u64) -> Result<(), NamespaceGateErrorV1> {
        if now_unix_ms < self.verified_at_unix_ms {
            return Err(NamespaceGateErrorV1::ClockRegressedAfterVerification);
        }
        if now_unix_ms > self.expires_at_unix_ms {
            return Err(NamespaceGateErrorV1::VerifiedNamespaceTokenExpired);
        }
        Ok(())
    }
}

/// Authenticate one namespace against the deployment's external namespace trust source.
pub fn verify_authority_retention_namespace_v1<T: AuthorityRetentionNamespaceTrustSourceV1>(
    namespace: AuthorityRetentionNamespaceV1,
    trust_source: &mut T,
    now_unix_ms: u64,
) -> Result<VerifiedAuthorityRetentionNamespaceV1, NamespaceGateErrorV1> {
    namespace.validate()?;
    let namespace_digest = namespace.namespace_digest()?;
    let authority_domain_id = namespace.authority_domain_id;

    let (
        authenticated_domain_id,
        expected_namespace_digest,
        trust_evidence_digest,
        valid_until_unix_ms,
    ) = match trust_source.authenticate_expected_namespace(authority_domain_id) {
        NamespaceTrustOutcomeV1::Authenticated {
            authority_domain_id,
            expected_namespace_digest,
            trust_evidence_digest,
            valid_until_unix_ms,
        } => (
            authority_domain_id,
            expected_namespace_digest,
            trust_evidence_digest,
            valid_until_unix_ms,
        ),
        NamespaceTrustOutcomeV1::Rejected => return Err(NamespaceGateErrorV1::TrustSourceRejected),
        NamespaceTrustOutcomeV1::Unknown => return Err(NamespaceGateErrorV1::TrustSourceUnknown),
    };

    if authenticated_domain_id != authority_domain_id {
        return Err(NamespaceGateErrorV1::TrustSourceAuthorityDomainMismatch);
    }
    if expected_namespace_digest == [0u8; 32] {
        return Err(NamespaceGateErrorV1::ZeroExpectedNamespaceDigest);
    }
    if trust_evidence_digest == [0u8; 32] {
        return Err(NamespaceGateErrorV1::ZeroTrustEvidenceDigest);
    }
    if expected_namespace_digest != namespace_digest {
        return Err(NamespaceGateErrorV1::ExpectedNamespaceDigestMismatch);
    }
    if valid_until_unix_ms < now_unix_ms {
        return Err(NamespaceGateErrorV1::TrustAttestationExpired);
    }

    let local_max_expiry = now_unix_ms
        .checked_add(VERIFIED_NAMESPACE_TOKEN_MAX_LIFETIME_MS_V1)
        .ok_or(NamespaceGateErrorV1::CurrentTimeOverflow)?;
    let expires_at_unix_ms = valid_until_unix_ms.min(local_max_expiry);

    Ok(VerifiedAuthorityRetentionNamespaceV1 {
        namespace,
        namespace_digest,
        trust_evidence_digest,
        verified_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
    })
}

/// Append one ADR-027 record using a freshly verified namespace token.
///
/// The token is consumed even if the provider later rejects or returns an ambiguous outcome.
pub fn append_via_verified_namespace_v1<B: ImmutableAuthorityRetentionBackendV1>(
    model: &mut OperationAuthorityRetentionModelV2,
    verified_namespace: VerifiedAuthorityRetentionNamespaceV1,
    backend: &mut B,
    candidate: OperationAuthorityRetentionRecordV2,
    now_unix_ms: u64,
) -> Result<AuthorityRetentionAppendResultV2, NamespaceGateErrorV1> {
    verified_namespace.validate_live(now_unix_ms)?;
    Ok(append_via_backend_v1(
        model,
        &verified_namespace.namespace,
        backend,
        candidate,
    )?)
}

/// Read back the complete immutable ADR-027 lineage using one freshly verified namespace token.
pub fn readback_via_verified_namespace_v1<B: ImmutableAuthorityRetentionBackendV1>(
    verified_namespace: VerifiedAuthorityRetentionNamespaceV1,
    backend: &mut B,
    now_unix_ms: u64,
) -> Result<OperationAuthorityRetentionModelV2, NamespaceGateErrorV1> {
    verified_namespace.validate_live(now_unix_ms)?;
    Ok(readback_complete_lineage_v1(
        &verified_namespace.namespace,
        backend,
    )?)
}

/// Authenticate the namespace and append in one authority-owned operation.
pub fn authenticate_and_append_v1<
    T: AuthorityRetentionNamespaceTrustSourceV1,
    B: ImmutableAuthorityRetentionBackendV1,
>(
    model: &mut OperationAuthorityRetentionModelV2,
    namespace: AuthorityRetentionNamespaceV1,
    trust_source: &mut T,
    backend: &mut B,
    candidate: OperationAuthorityRetentionRecordV2,
    now_unix_ms: u64,
) -> Result<AuthorityRetentionAppendResultV2, NamespaceGateErrorV1> {
    let verified = verify_authority_retention_namespace_v1(namespace, trust_source, now_unix_ms)?;
    append_via_verified_namespace_v1(model, verified, backend, candidate, now_unix_ms)
}

/// Authenticate the namespace and perform complete immutable readback in one operation.
pub fn authenticate_and_readback_v1<
    T: AuthorityRetentionNamespaceTrustSourceV1,
    B: ImmutableAuthorityRetentionBackendV1,
>(
    namespace: AuthorityRetentionNamespaceV1,
    trust_source: &mut T,
    backend: &mut B,
    now_unix_ms: u64,
) -> Result<OperationAuthorityRetentionModelV2, NamespaceGateErrorV1> {
    let verified = verify_authority_retention_namespace_v1(namespace, trust_source, now_unix_ms)?;
    readback_via_verified_namespace_v1(verified, backend, now_unix_ms)
}

/// Fail-closed namespace trust-gate errors.
#[derive(Debug, Error)]
pub enum NamespaceGateErrorV1 {
    /// Raw namespace/backend contract rejected local syntax or provider behavior.
    #[error("authority retention backend rejected namespace-gated operation: {0}")]
    Backend(#[from] AuthorityRetentionBackendErrorV1),
    /// External namespace trust source positively rejected the request.
    #[error("authority retention namespace trust source rejected request")]
    TrustSourceRejected,
    /// External namespace trust source could not authenticate current namespace state.
    #[error("authority retention namespace trust source state is unknown")]
    TrustSourceUnknown,
    /// Trust source responded for another authority domain.
    #[error("namespace trust source authority-domain binding mismatch")]
    TrustSourceAuthorityDomainMismatch,
    /// Authenticated response omitted the expected namespace commitment.
    #[error("namespace trust source returned a zero expected namespace digest")]
    ZeroExpectedNamespaceDigest,
    /// Authenticated response omitted evidence identifying the trust decision.
    #[error("namespace trust source returned a zero trust-evidence digest")]
    ZeroTrustEvidenceDigest,
    /// External trust source authenticated a different namespace from the caller's candidate.
    #[error("candidate authority retention namespace is not the externally expected namespace")]
    ExpectedNamespaceDigestMismatch,
    /// Trust-source result expired before verification began.
    #[error("namespace trust-source attestation is expired")]
    TrustAttestationExpired,
    /// Local current time could not represent the bounded token lifetime.
    #[error("namespace verification current time overflow")]
    CurrentTimeOverflow,
    /// Local clock moved backward after a namespace token was issued.
    #[error("local clock regressed after namespace verification")]
    ClockRegressedAfterVerification,
    /// Verified namespace token exceeded its bounded application lifetime.
    #[error("verified namespace token expired before backend operation")]
    VerifiedNamespaceTokenExpired,
}
