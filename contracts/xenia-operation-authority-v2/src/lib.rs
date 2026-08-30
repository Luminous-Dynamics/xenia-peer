// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Consolidated recovery-safe authority chain for Xenia privileged operations.
//!
//! V2 is intentionally a thin authority layer over the exact semantic commitments produced
//! by the earlier grant/use/admission/effect-arm contracts. It adds the pieces recovery made
//! mandatory: authority-epoch binding, authenticated grant-issuance evidence, exact predecessor
//! chaining, and persistent store-generation binding.
//!
//! A raw pre-epoch grant digest cannot become valid in a later epoch merely by being wrapped
//! again. [`GrantAuthorityV2`] is only admissible when its issuance evidence and issuer identity
//! match values authenticated by an upstream trust domain (for example signed consent/approval
//! evidence or a durable authority ledger).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_epoch::{
    AuthorityEpochBindingV1, AuthorityEpochError, OperationAuthorityEpochV1,
};

/// Schema for [`GrantAuthorityV2`].
pub const GRANT_AUTHORITY_SCHEMA_V2: &str = "xenia-operation-grant-authority-v2";
/// Schema for [`UseAuthorityV2`].
pub const USE_AUTHORITY_SCHEMA_V2: &str = "xenia-operation-use-authority-v2";
/// Schema for [`AdmissionAuthorityV2`].
pub const ADMISSION_AUTHORITY_SCHEMA_V2: &str = "xenia-operation-admission-authority-v2";
/// Schema for [`StoreAuthorityV2`].
pub const STORE_AUTHORITY_SCHEMA_V2: &str = "xenia-operation-store-authority-v2";
/// Schema for [`EffectArmAuthorityV2`].
pub const EFFECT_ARM_AUTHORITY_SCHEMA_V2: &str = "xenia-effect-arm-authority-v2";

/// Digest domain for grant authority.
pub const GRANT_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] = b"xenia-operation-grant-authority-digest-v2";
/// Digest domain for use authority.
pub const USE_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] = b"xenia-operation-use-authority-digest-v2";
/// Digest domain for admission authority.
pub const ADMISSION_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-operation-admission-authority-digest-v2";
/// Digest domain for persistent store authority.
pub const STORE_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] = b"xenia-operation-store-authority-digest-v2";
/// Digest domain for effect-arm authority.
pub const EFFECT_ARM_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-arm-authority-digest-v2";

/// Externally authenticated facts required to recognize a grant as genuinely issued.
///
/// These values are not inferred from untrusted serialized grant bytes. A runtime obtains them
/// from its configured issuance trust path and compares them to the V2 authority record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedIssuanceContextV2 {
    /// Exact authenticated issuer identity/configuration commitment.
    pub issuer_authority_digest: [u8; 32],
    /// Exact authenticated issuance decision/evidence commitment.
    pub issuance_evidence_digest: [u8; 32],
}

/// Recovery-safe authority record for one already-validated raw operation grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAuthorityV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact commitment to the validated semantic grant record.
    pub raw_grant_digest: [u8; 32],
    /// Exact authority epoch in which the grant was issued.
    pub authority_epoch: AuthorityEpochBindingV1,
    /// Identity/configuration of the authority that issued this epoch-bound grant.
    pub issuer_authority_digest: [u8; 32],
    /// Commitment to the externally authenticated issuance decision/evidence.
    pub issuance_evidence_digest: [u8; 32],
    /// Evidence timestamp for issuance; ordering is not derived from wall clock alone.
    pub issued_at_unix_ms: u64,
}

impl GrantAuthorityV2 {
    /// Construct a candidate V2 authority record for a validated raw grant.
    pub fn new(
        raw_grant_digest: [u8; 32],
        current: &OperationAuthorityEpochV1,
        issuance: AuthenticatedIssuanceContextV2,
        issued_at_unix_ms: u64,
    ) -> Result<Self, AuthorityV2Error> {
        current.validate()?;
        require_nonzero(raw_grant_digest, AuthorityV2Error::ZeroRawGrantDigest)?;
        require_nonzero(
            issuance.issuer_authority_digest,
            AuthorityV2Error::ZeroIssuerAuthorityDigest,
        )?;
        require_nonzero(
            issuance.issuance_evidence_digest,
            AuthorityV2Error::ZeroIssuanceEvidenceDigest,
        )?;
        if issued_at_unix_ms < current.established_at_unix_ms {
            return Err(AuthorityV2Error::IssuancePredatesEpoch);
        }
        let value = Self {
            schema: GRANT_AUTHORITY_SCHEMA_V2.to_string(),
            raw_grant_digest,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
            issuer_authority_digest: issuance.issuer_authority_digest,
            issuance_evidence_digest: issuance.issuance_evidence_digest,
            issued_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax without trusting issuance authenticity.
    pub fn validate(&self) -> Result<(), AuthorityV2Error> {
        if self.schema != GRANT_AUTHORITY_SCHEMA_V2 {
            return Err(AuthorityV2Error::UnsupportedGrantSchema);
        }
        require_nonzero(self.raw_grant_digest, AuthorityV2Error::ZeroRawGrantDigest)?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        require_nonzero(
            self.issuer_authority_digest,
            AuthorityV2Error::ZeroIssuerAuthorityDigest,
        )?;
        require_nonzero(
            self.issuance_evidence_digest,
            AuthorityV2Error::ZeroIssuanceEvidenceDigest,
        )?;
        Ok(())
    }

    /// Require exact live epoch and externally authenticated issuance facts.
    pub fn validate_issued_against(
        &self,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedIssuanceContextV2,
    ) -> Result<(), AuthorityV2Error> {
        self.validate()?;
        self.authority_epoch.validate_against(current)?;
        if self.issued_at_unix_ms < current.established_at_unix_ms {
            return Err(AuthorityV2Error::IssuancePredatesEpoch);
        }
        if self.issuer_authority_digest != authenticated.issuer_authority_digest {
            return Err(AuthorityV2Error::IssuerAuthorityMismatch);
        }
        if self.issuance_evidence_digest != authenticated.issuance_evidence_digest {
            return Err(AuthorityV2Error::IssuanceEvidenceMismatch);
        }
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable grant-authority commitment.
    pub fn authority_digest(&self) -> Result<[u8; 32], AuthorityV2Error> {
        Ok(domain_digest(
            GRANT_AUTHORITY_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Recovery-safe authority record for one already-validated raw operation use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseAuthorityV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact operation id from the semantic use record.
    pub operation_id: [u8; 16],
    /// Exact commitment to the validated semantic use record.
    pub raw_use_digest: [u8; 32],
    /// Exact V2 grant authority consumed by this use.
    pub grant_authority_digest: [u8; 32],
}

impl UseAuthorityV2 {
    /// Construct a use authority after both raw use and grant authority have been validated.
    pub fn new(
        operation_id: [u8; 16],
        raw_use_digest: [u8; 32],
        grant: &GrantAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedIssuanceContextV2,
    ) -> Result<Self, AuthorityV2Error> {
        grant.validate_issued_against(current, authenticated)?;
        require_operation(operation_id)?;
        require_nonzero(raw_use_digest, AuthorityV2Error::ZeroRawUseDigest)?;
        let value = Self {
            schema: USE_AUTHORITY_SCHEMA_V2.to_string(),
            operation_id,
            raw_use_digest,
            grant_authority_digest: grant.authority_digest()?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax.
    pub fn validate(&self) -> Result<(), AuthorityV2Error> {
        if self.schema != USE_AUTHORITY_SCHEMA_V2 {
            return Err(AuthorityV2Error::UnsupportedUseSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(self.raw_use_digest, AuthorityV2Error::ZeroRawUseDigest)?;
        require_nonzero(
            self.grant_authority_digest,
            AuthorityV2Error::ZeroGrantAuthorityDigest,
        )?;
        Ok(())
    }

    /// Validate exact grant predecessor and live epoch/issuance context.
    pub fn validate_against(
        &self,
        grant: &GrantAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedIssuanceContextV2,
    ) -> Result<(), AuthorityV2Error> {
        self.validate()?;
        grant.validate_issued_against(current, authenticated)?;
        if self.grant_authority_digest != grant.authority_digest()? {
            return Err(AuthorityV2Error::GrantAuthorityDigestMismatch);
        }
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable use-authority commitment.
    pub fn authority_digest(&self) -> Result<[u8; 32], AuthorityV2Error> {
        Ok(domain_digest(
            USE_AUTHORITY_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Recovery-safe durable-admission authority record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAuthorityV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact admitted operation.
    pub operation_id: [u8; 16],
    /// Exact commitment to the immutable semantic admission record.
    pub raw_admission_digest: [u8; 32],
    /// Exact V2 use authority atomically consumed by admission.
    pub use_authority_digest: [u8; 32],
    /// Exact authority epoch serving this admission.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl AdmissionAuthorityV2 {
    /// Construct an admission authority after predecessor validation.
    pub fn new(
        raw_admission_digest: [u8; 32],
        use_authority: &UseAuthorityV2,
        grant: &GrantAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedIssuanceContextV2,
    ) -> Result<Self, AuthorityV2Error> {
        use_authority.validate_against(grant, current, authenticated)?;
        require_nonzero(
            raw_admission_digest,
            AuthorityV2Error::ZeroRawAdmissionDigest,
        )?;
        let value = Self {
            schema: ADMISSION_AUTHORITY_SCHEMA_V2.to_string(),
            operation_id: use_authority.operation_id,
            raw_admission_digest,
            use_authority_digest: use_authority.authority_digest()?,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax.
    pub fn validate(&self) -> Result<(), AuthorityV2Error> {
        if self.schema != ADMISSION_AUTHORITY_SCHEMA_V2 {
            return Err(AuthorityV2Error::UnsupportedAdmissionSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(
            self.raw_admission_digest,
            AuthorityV2Error::ZeroRawAdmissionDigest,
        )?;
        require_nonzero(
            self.use_authority_digest,
            AuthorityV2Error::ZeroUseAuthorityDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Validate exact predecessor and live authority epoch.
    pub fn validate_against(
        &self,
        use_authority: &UseAuthorityV2,
        grant: &GrantAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedIssuanceContextV2,
    ) -> Result<(), AuthorityV2Error> {
        self.validate()?;
        use_authority.validate_against(grant, current, authenticated)?;
        self.authority_epoch.validate_against(current)?;
        if self.operation_id != use_authority.operation_id {
            return Err(AuthorityV2Error::OperationIdMismatch);
        }
        if self.use_authority_digest != use_authority.authority_digest()? {
            return Err(AuthorityV2Error::UseAuthorityDigestMismatch);
        }
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable admission-authority commitment.
    pub fn authority_digest(&self) -> Result<[u8; 32], AuthorityV2Error> {
        Ok(domain_digest(
            ADMISSION_AUTHORITY_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Persistent exact store-generation/authority-epoch binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreAuthorityV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact receipt-store identity.
    pub store_id: [u8; 16],
    /// Exact receipt-store generation.
    pub store_generation: u64,
    /// Exact authority epoch permitted to spend against the store.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl StoreAuthorityV2 {
    /// Construct from the exact current authority epoch.
    pub fn from_epoch(current: &OperationAuthorityEpochV1) -> Result<Self, AuthorityV2Error> {
        current.validate()?;
        let value = Self {
            schema: STORE_AUTHORITY_SCHEMA_V2.to_string(),
            store_id: current.store_id,
            store_generation: current.store_generation,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax.
    pub fn validate(&self) -> Result<(), AuthorityV2Error> {
        if self.schema != STORE_AUTHORITY_SCHEMA_V2 {
            return Err(AuthorityV2Error::UnsupportedStoreSchema);
        }
        if self.store_id == [0u8; 16] {
            return Err(AuthorityV2Error::ZeroStoreId);
        }
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Require exact current store identity/generation and epoch.
    pub fn validate_against(
        &self,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityV2Error> {
        self.validate()?;
        current.validate()?;
        self.authority_epoch.validate_against(current)?;
        if self.store_id != current.store_id || self.store_generation != current.store_generation {
            return Err(AuthorityV2Error::StoreBindingMismatch);
        }
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable persistent store-authority commitment.
    pub fn authority_digest(&self) -> Result<[u8; 32], AuthorityV2Error> {
        Ok(domain_digest(
            STORE_AUTHORITY_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Final fresh effect-arm authority record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectArmAuthorityV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact operation being armed.
    pub operation_id: [u8; 16],
    /// Exact commitment to the validated fresh semantic arm authorization.
    pub raw_arm_authorization_digest: [u8; 32],
    /// Exact V2 durable-admission authority being armed.
    pub admission_authority_digest: [u8; 32],
    /// Exact persistent store-authority state observed for arming.
    pub store_authority_digest: [u8; 32],
    /// Exact current authority epoch at arm time.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl EffectArmAuthorityV2 {
    /// Construct after admission and store authority have both been validated.
    pub fn new(
        raw_arm_authorization_digest: [u8; 32],
        admission: &AdmissionAuthorityV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
    ) -> Result<Self, AuthorityV2Error> {
        admission.validate()?;
        admission.authority_epoch.validate_against(current)?;
        store.validate_against(current)?;
        require_nonzero(
            raw_arm_authorization_digest,
            AuthorityV2Error::ZeroRawArmAuthorizationDigest,
        )?;
        let value = Self {
            schema: EFFECT_ARM_AUTHORITY_SCHEMA_V2.to_string(),
            operation_id: admission.operation_id,
            raw_arm_authorization_digest,
            admission_authority_digest: admission.authority_digest()?,
            store_authority_digest: store.authority_digest()?,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax.
    pub fn validate(&self) -> Result<(), AuthorityV2Error> {
        if self.schema != EFFECT_ARM_AUTHORITY_SCHEMA_V2 {
            return Err(AuthorityV2Error::UnsupportedArmSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(
            self.raw_arm_authorization_digest,
            AuthorityV2Error::ZeroRawArmAuthorizationDigest,
        )?;
        require_nonzero(
            self.admission_authority_digest,
            AuthorityV2Error::ZeroAdmissionAuthorityDigest,
        )?;
        require_nonzero(
            self.store_authority_digest,
            AuthorityV2Error::ZeroStoreAuthorityDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Final live-gate validation after any external-anchor latency and immediately before effect.
    pub fn validate_final_gate(
        &self,
        admission: &AdmissionAuthorityV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityV2Error> {
        self.validate()?;
        admission.validate()?;
        store.validate_against(current)?;
        self.authority_epoch.validate_against(current)?;
        admission.authority_epoch.validate_against(current)?;
        if self.operation_id != admission.operation_id {
            return Err(AuthorityV2Error::OperationIdMismatch);
        }
        if self.admission_authority_digest != admission.authority_digest()? {
            return Err(AuthorityV2Error::AdmissionAuthorityDigestMismatch);
        }
        if self.store_authority_digest != store.authority_digest()? {
            return Err(AuthorityV2Error::StoreAuthorityDigestMismatch);
        }
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable final arm-authority commitment.
    pub fn authority_digest(&self) -> Result<[u8; 32], AuthorityV2Error> {
        Ok(domain_digest(
            EFFECT_ARM_AUTHORITY_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// V2 authority-chain validation failure.
#[derive(Debug, Error)]
pub enum AuthorityV2Error {
    /// Grant schema mismatch.
    #[error("unsupported grant authority v2 schema")]
    UnsupportedGrantSchema,
    /// Use schema mismatch.
    #[error("unsupported use authority v2 schema")]
    UnsupportedUseSchema,
    /// Admission schema mismatch.
    #[error("unsupported admission authority v2 schema")]
    UnsupportedAdmissionSchema,
    /// Store schema mismatch.
    #[error("unsupported store authority v2 schema")]
    UnsupportedStoreSchema,
    /// Arm schema mismatch.
    #[error("unsupported effect-arm authority v2 schema")]
    UnsupportedArmSchema,
    /// Raw grant digest is unset.
    #[error("raw grant digest must not be all zero")]
    ZeroRawGrantDigest,
    /// Raw use digest is unset.
    #[error("raw use digest must not be all zero")]
    ZeroRawUseDigest,
    /// Raw admission digest is unset.
    #[error("raw admission digest must not be all zero")]
    ZeroRawAdmissionDigest,
    /// Raw arm digest is unset.
    #[error("raw arm authorization digest must not be all zero")]
    ZeroRawArmAuthorizationDigest,
    /// Issuer identity commitment is unset.
    #[error("issuer authority digest must not be all zero")]
    ZeroIssuerAuthorityDigest,
    /// Issuance evidence commitment is unset.
    #[error("issuance evidence digest must not be all zero")]
    ZeroIssuanceEvidenceDigest,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Authority domain is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Authority epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Store id is unset.
    #[error("store id must not be all zero")]
    ZeroStoreId,
    /// Grant authority predecessor digest is unset.
    #[error("grant authority digest must not be all zero")]
    ZeroGrantAuthorityDigest,
    /// Use authority predecessor digest is unset.
    #[error("use authority digest must not be all zero")]
    ZeroUseAuthorityDigest,
    /// Admission authority predecessor digest is unset.
    #[error("admission authority digest must not be all zero")]
    ZeroAdmissionAuthorityDigest,
    /// Store authority digest is unset.
    #[error("store authority digest must not be all zero")]
    ZeroStoreAuthorityDigest,
    /// Issuance timestamp predates the authority epoch.
    #[error("grant issuance predates the bound authority epoch")]
    IssuancePredatesEpoch,
    /// Authenticated issuer differs from the grant record.
    #[error("authenticated issuer authority does not match grant authority v2")]
    IssuerAuthorityMismatch,
    /// Authenticated issuance evidence differs from the grant record.
    #[error("authenticated issuance evidence does not match grant authority v2")]
    IssuanceEvidenceMismatch,
    /// Use names a different grant authority.
    #[error("use authority grant predecessor mismatch")]
    GrantAuthorityDigestMismatch,
    /// Admission names a different use authority.
    #[error("admission authority use predecessor mismatch")]
    UseAuthorityDigestMismatch,
    /// Arm names a different admission authority.
    #[error("effect-arm admission predecessor mismatch")]
    AdmissionAuthorityDigestMismatch,
    /// Arm names a different persistent store authority.
    #[error("effect-arm store predecessor mismatch")]
    StoreAuthorityDigestMismatch,
    /// Store identity/generation differs from the live epoch.
    #[error("persistent store authority does not match current epoch")]
    StoreBindingMismatch,
    /// Operation identity differs from the predecessor chain.
    #[error("operation id mismatch across authority chain")]
    OperationIdMismatch,
    /// Authority epoch contract failure.
    #[error(transparent)]
    Epoch(#[from] AuthorityEpochError),
    /// Canonical encoding failed.
    #[error("failed to encode authority v2: {0}")]
    Encoding(#[from] bincode::Error),
}

fn validate_epoch_binding_syntax(binding: &AuthorityEpochBindingV1) -> Result<(), AuthorityV2Error> {
    if binding.authority_domain_id == [0u8; 16] {
        return Err(AuthorityV2Error::ZeroAuthorityDomainId);
    }
    require_nonzero(
        binding.authority_epoch_digest,
        AuthorityV2Error::ZeroAuthorityEpochDigest,
    )
}

fn require_operation(operation_id: [u8; 16]) -> Result<(), AuthorityV2Error> {
    if operation_id == [0u8; 16] {
        Err(AuthorityV2Error::ZeroOperationId)
    } else {
        Ok(())
    }
}

fn require_nonzero(value: [u8; 32], error: AuthorityV2Error) -> Result<(), AuthorityV2Error> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_authority_epoch::{
        AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
    };

    fn genesis() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: [1; 16],
            epoch_id: [2; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0; 32],
            store_id: [3; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 1_000,
        }
    }

    fn revoked(previous: &OperationAuthorityEpochV1) -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: previous.authority_domain_id,
            epoch_id: [4; 16],
            epoch_sequence: previous.epoch_sequence + 1,
            previous_epoch_digest: previous.epoch_digest().unwrap(),
            store_id: previous.store_id,
            store_generation: previous.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [0x90; 32],
            },
            established_at_unix_ms: 2_000,
        }
    }

    fn issuance(byte: u8) -> AuthenticatedIssuanceContextV2 {
        AuthenticatedIssuanceContextV2 {
            issuer_authority_digest: [0xA0; 32],
            issuance_evidence_digest: [byte; 32],
        }
    }

    #[test]
    fn grant_requires_exact_authenticated_issuance() {
        let epoch = genesis();
        let grant = GrantAuthorityV2::new([0x11; 32], &epoch, issuance(0xB0), 1_100).unwrap();
        grant
            .validate_issued_against(&epoch, issuance(0xB0))
            .unwrap();
        assert!(matches!(
            grant.validate_issued_against(&epoch, issuance(0xB1)),
            Err(AuthorityV2Error::IssuanceEvidenceMismatch)
        ));
    }

    #[test]
    fn old_grant_cannot_be_rewrapped_without_fresh_issuance_evidence() {
        let epoch = genesis();
        let old_issue = issuance(0xB0);
        let old = GrantAuthorityV2::new([0x11; 32], &epoch, old_issue, 1_100).unwrap();
        let next = revoked(&epoch);
        next.validate_successor(&epoch).unwrap();

        assert!(old.validate_issued_against(&next, old_issue).is_err());

        let fresh_issue = issuance(0xB2);
        let fresh = GrantAuthorityV2::new([0x11; 32], &next, fresh_issue, 2_100).unwrap();
        assert!(matches!(
            fresh.validate_issued_against(&next, old_issue),
            Err(AuthorityV2Error::IssuanceEvidenceMismatch)
        ));
        fresh.validate_issued_against(&next, fresh_issue).unwrap();
        assert_ne!(old.authority_digest().unwrap(), fresh.authority_digest().unwrap());
    }

    #[test]
    fn complete_chain_validates_and_binds_store() {
        let epoch = genesis();
        let issue = issuance(0xB0);
        let grant = GrantAuthorityV2::new([0x11; 32], &epoch, issue, 1_100).unwrap();
        let use_authority =
            UseAuthorityV2::new([0x22; 16], [0x33; 32], &grant, &epoch, issue).unwrap();
        let admission = AdmissionAuthorityV2::new(
            [0x44; 32],
            &use_authority,
            &grant,
            &epoch,
            issue,
        )
        .unwrap();
        let store = StoreAuthorityV2::from_epoch(&epoch).unwrap();
        let arm = EffectArmAuthorityV2::new([0x55; 32], &admission, &store, &epoch).unwrap();
        arm.validate_final_gate(&admission, &store, &epoch)
            .unwrap();
    }

    #[test]
    fn final_gate_fails_after_global_revocation() {
        let epoch = genesis();
        let issue = issuance(0xB0);
        let grant = GrantAuthorityV2::new([0x11; 32], &epoch, issue, 1_100).unwrap();
        let use_authority =
            UseAuthorityV2::new([0x22; 16], [0x33; 32], &grant, &epoch, issue).unwrap();
        let admission = AdmissionAuthorityV2::new(
            [0x44; 32],
            &use_authority,
            &grant,
            &epoch,
            issue,
        )
        .unwrap();
        let store = StoreAuthorityV2::from_epoch(&epoch).unwrap();
        let arm = EffectArmAuthorityV2::new([0x55; 32], &admission, &store, &epoch).unwrap();
        let next = revoked(&epoch);
        assert!(arm.validate_final_gate(&admission, &store, &next).is_err());
    }

    #[test]
    fn predecessor_tampering_changes_authority_chain() {
        let epoch = genesis();
        let issue = issuance(0xB0);
        let grant = GrantAuthorityV2::new([0x11; 32], &epoch, issue, 1_100).unwrap();
        let use_authority =
            UseAuthorityV2::new([0x22; 16], [0x33; 32], &grant, &epoch, issue).unwrap();
        let mut admission = AdmissionAuthorityV2::new(
            [0x44; 32],
            &use_authority,
            &grant,
            &epoch,
            issue,
        )
        .unwrap();
        admission.use_authority_digest[0] ^= 1;
        assert!(matches!(
            admission.validate_against(&use_authority, &grant, &epoch, issue),
            Err(AuthorityV2Error::UseAuthorityDigestMismatch)
        ));
    }
}
