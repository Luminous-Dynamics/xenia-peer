// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime-free Google Cloud Storage profile for Xenia operation-authority retention.
//!
//! This crate does not call Google Cloud. It freezes the exact provider configuration and runtime
//! permission requirements that a later SDK adapter must prove before it may implement ADR-028's
//! immutable backend contract.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_retention_backend::AuthorityRetentionNamespaceV1;

/// Exact GCS profile schema.
pub const GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1: &str =
    "xenia-gcs-authority-retention-profile-v1";
/// Exact Google Cloud Rust Storage crate selected for V1 qualification.
pub const GCS_RUST_SDK_CRATE_V1: &str = "google-cloud-storage";
/// Exact SDK version selected for the first V1 qualification lineage.
pub const GCS_RUST_SDK_VERSION_V1: &str = "1.18.0";
/// Storage API profile used by the current official Rust client.
pub const GCS_STORAGE_API_PROFILE_V1: &str = "google.storage.v2";
/// Provider profile digest domain.
pub const GCS_AUTHORITY_RETENTION_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-gcs-authority-retention-profile-digest-v1";
/// Object-name profile. Names are derived only from the namespace digest and retention sequence.
pub const GCS_OBJECT_NAME_PREFIX_V1: &str = "xenia-authority-retention/v1";
/// Google Cloud's documented maximum Bucket Lock retention period: 100 years.
pub const GCS_MAX_BUCKET_RETENTION_SECONDS_V1: u64 = 3_155_760_000;

/// Exact runtime object permissions allowed to the Xenia data-plane principal.
pub const GCS_RUNTIME_OBJECT_PERMISSIONS_V1: [&str; 3] = [
    "storage.objects.create",
    "storage.objects.get",
    "storage.objects.list",
];

/// Frozen provider requirements committed by ADR-028's `retention_policy_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsAuthorityRetentionProfileV1 {
    /// Exact profile schema.
    pub schema: String,
    /// Google Cloud project number that owns the dedicated bucket.
    pub project_number: u64,
    /// Globally unique dedicated bucket name.
    pub bucket_name: String,
    /// Exact bucket location/region/dual-region profile.
    pub bucket_location: String,
    /// Minimum locked bucket-retention period accepted by this deployment profile.
    pub minimum_bucket_retention_seconds: u64,
    /// Minimum recovery/history horizon the deployment promises to preserve.
    pub required_recovery_horizon_seconds: u64,
    /// Exact digest identifying the runtime service account / workload identity principal.
    pub runtime_principal_digest: [u8; 32],
    /// Exact digest identifying the separately administered bucket-retention authority.
    pub retention_admin_principal_digest: [u8; 32],
    /// Exact encryption/key-management profile commitment.
    pub encryption_profile_digest: [u8; 32],
    /// Exact organization/IAM hardening profile commitment outside object permissions.
    pub iam_policy_profile_digest: [u8; 32],
    /// Runtime permissions. V1 requires the exact sorted three-permission allowlist.
    pub runtime_object_permissions: Vec<String>,
    /// Require Bucket Lock's retention policy to be irreversibly locked.
    pub require_locked_bucket_retention: bool,
    /// Require uniform bucket-level access (no object ACL authorization path).
    pub require_uniform_bucket_level_access: bool,
    /// Require bucket-level public access prevention to be explicitly `enforced`.
    pub require_public_access_prevention_enforced: bool,
    /// V1 requires Object Versioning to be disabled.
    pub require_object_versioning_disabled: bool,
    /// V1 requires hierarchical namespace to be disabled.
    pub require_hierarchical_namespace_disabled: bool,
    /// V1 forbids Object Lifecycle Management rules in the dedicated bucket.
    pub require_no_lifecycle_rules: bool,
    /// Exact official Google Rust SDK crate name.
    pub rust_sdk_crate: String,
    /// Exact official Google Rust SDK version.
    pub rust_sdk_version: String,
    /// Exact provider API profile.
    pub storage_api_profile: String,
}

impl GcsAuthorityRetentionProfileV1 {
    /// Validate the frozen V1 provider requirements.
    pub fn validate(&self) -> Result<(), GcsProfileErrorV1> {
        if self.schema != GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1 {
            return Err(GcsProfileErrorV1::UnsupportedSchema);
        }
        if self.project_number == 0 {
            return Err(GcsProfileErrorV1::ZeroProjectNumber);
        }
        validate_bucket_name(&self.bucket_name)?;
        if self.bucket_location.trim().is_empty() {
            return Err(GcsProfileErrorV1::EmptyBucketLocation);
        }
        if self.minimum_bucket_retention_seconds == 0
            || self.minimum_bucket_retention_seconds > GCS_MAX_BUCKET_RETENTION_SECONDS_V1
        {
            return Err(GcsProfileErrorV1::InvalidMinimumRetention);
        }
        if self.required_recovery_horizon_seconds == 0
            || self.minimum_bucket_retention_seconds < self.required_recovery_horizon_seconds
        {
            return Err(GcsProfileErrorV1::RetentionBelowRecoveryHorizon);
        }
        if self.runtime_principal_digest == [0u8; 32]
            || self.retention_admin_principal_digest == [0u8; 32]
        {
            return Err(GcsProfileErrorV1::ZeroPrincipalDigest);
        }
        if self.runtime_principal_digest == self.retention_admin_principal_digest {
            return Err(GcsProfileErrorV1::RuntimeAndRetentionAdminMustDiffer);
        }
        if self.encryption_profile_digest == [0u8; 32] {
            return Err(GcsProfileErrorV1::ZeroEncryptionProfileDigest);
        }
        if self.iam_policy_profile_digest == [0u8; 32] {
            return Err(GcsProfileErrorV1::ZeroIamPolicyProfileDigest);
        }

        let expected = GCS_RUNTIME_OBJECT_PERMISSIONS_V1
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        if self.runtime_object_permissions != expected {
            return Err(GcsProfileErrorV1::UnexpectedRuntimePermissions);
        }
        if !self.require_locked_bucket_retention {
            return Err(GcsProfileErrorV1::BucketLockNotRequired);
        }
        if !self.require_uniform_bucket_level_access {
            return Err(GcsProfileErrorV1::UniformBucketLevelAccessNotRequired);
        }
        if !self.require_public_access_prevention_enforced {
            return Err(GcsProfileErrorV1::PublicAccessPreventionNotRequired);
        }
        if !self.require_object_versioning_disabled {
            return Err(GcsProfileErrorV1::ObjectVersioningDisablementNotRequired);
        }
        if !self.require_hierarchical_namespace_disabled {
            return Err(GcsProfileErrorV1::HierarchicalNamespaceDisablementNotRequired);
        }
        if !self.require_no_lifecycle_rules {
            return Err(GcsProfileErrorV1::LifecycleRuleAbsenceNotRequired);
        }
        if self.rust_sdk_crate != GCS_RUST_SDK_CRATE_V1
            || self.rust_sdk_version != GCS_RUST_SDK_VERSION_V1
            || self.storage_api_profile != GCS_STORAGE_API_PROFILE_V1
        {
            return Err(GcsProfileErrorV1::SdkLineageMismatch);
        }
        Ok(())
    }

    /// Canonical profile bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GcsProfileErrorV1> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Exact provider/profile commitment used as ADR-028's `retention_policy_digest`.
    pub fn profile_digest(&self) -> Result<[u8; 32], GcsProfileErrorV1> {
        Ok(domain_digest(
            GCS_AUTHORITY_RETENTION_PROFILE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Verify one ADR-028 namespace is committed to exactly this GCS profile.
    pub fn validate_namespace(
        &self,
        namespace: &AuthorityRetentionNamespaceV1,
    ) -> Result<(), GcsProfileErrorV1> {
        self.validate()?;
        namespace.validate()?;
        if namespace.retention_policy_digest != self.profile_digest()? {
            return Err(GcsProfileErrorV1::NamespacePolicyDigestMismatch);
        }
        Ok(())
    }

    /// Deterministic GCS object name for one ADR-028 locator.
    ///
    /// No caller-controlled path fragment is accepted. The namespace digest is hex encoded and the
    /// sequence is fixed-width decimal so lexical object ordering equals sequence ordering.
    pub fn object_name(
        &self,
        namespace_digest: [u8; 32],
        retention_sequence: u64,
    ) -> Result<String, GcsProfileErrorV1> {
        self.validate()?;
        Ok(format!(
            "{}/{}/{:020}.bin",
            GCS_OBJECT_NAME_PREFIX_V1,
            hex_lower(&namespace_digest),
            retention_sequence
        ))
    }

    /// Exact listing prefix for one namespace.
    pub fn namespace_object_prefix(
        &self,
        namespace_digest: [u8; 32],
    ) -> Result<String, GcsProfileErrorV1> {
        self.validate()?;
        Ok(format!(
            "{}/{}/",
            GCS_OBJECT_NAME_PREFIX_V1,
            hex_lower(&namespace_digest)
        ))
    }
}

/// Observed provisioned bucket properties needed to qualify the profile at runtime/deployment time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsObservedBucketStateV1 {
    /// Google Cloud project number containing the bucket.
    pub project_number: u64,
    /// Exact bucket name.
    pub bucket_name: String,
    /// Exact bucket location.
    pub bucket_location: String,
    /// Effective Bucket Lock retention period.
    pub bucket_retention_seconds: u64,
    /// Whether the bucket retention policy is irreversibly locked.
    pub bucket_retention_locked: bool,
    /// Whether uniform bucket-level access is enabled.
    pub uniform_bucket_level_access_enabled: bool,
    /// Whether public access prevention is explicitly `enforced` on the bucket.
    pub public_access_prevention_enforced: bool,
    /// Whether Object Versioning is enabled.
    pub object_versioning_enabled: bool,
    /// Whether hierarchical namespace is enabled.
    pub hierarchical_namespace_enabled: bool,
    /// Number of configured Object Lifecycle Management rules.
    pub lifecycle_rule_count: u32,
}

/// Verify provisioned bucket metadata satisfies the frozen V1 profile.
pub fn verify_observed_bucket_state_v1(
    profile: &GcsAuthorityRetentionProfileV1,
    observed: &GcsObservedBucketStateV1,
) -> Result<(), GcsProfileErrorV1> {
    profile.validate()?;
    if observed.project_number != profile.project_number
        || observed.bucket_name != profile.bucket_name
        || observed.bucket_location != profile.bucket_location
    {
        return Err(GcsProfileErrorV1::ObservedBucketIdentityMismatch);
    }
    if !observed.bucket_retention_locked
        || observed.bucket_retention_seconds < profile.minimum_bucket_retention_seconds
    {
        return Err(GcsProfileErrorV1::ObservedRetentionPolicyTooWeak);
    }
    if !observed.uniform_bucket_level_access_enabled {
        return Err(GcsProfileErrorV1::ObservedUniformAccessDisabled);
    }
    if !observed.public_access_prevention_enforced {
        return Err(GcsProfileErrorV1::ObservedPublicAccessPreventionDisabled);
    }
    if observed.object_versioning_enabled {
        return Err(GcsProfileErrorV1::ObservedObjectVersioningEnabled);
    }
    if observed.hierarchical_namespace_enabled {
        return Err(GcsProfileErrorV1::ObservedHierarchicalNamespaceEnabled);
    }
    if observed.lifecycle_rule_count != 0 {
        return Err(GcsProfileErrorV1::ObservedLifecycleRulesPresent);
    }
    Ok(())
}

/// Provider-profile validation errors.
#[derive(Debug, Error)]
pub enum GcsProfileErrorV1 {
    /// Profile schema mismatch.
    #[error("unsupported GCS authority retention profile schema")]
    UnsupportedSchema,
    /// Google project number was unset.
    #[error("GCS authority retention profile requires project number")]
    ZeroProjectNumber,
    /// Bucket name is empty/invalid for this strict profile.
    #[error("invalid GCS authority retention bucket name")]
    InvalidBucketName,
    /// Bucket location is empty.
    #[error("GCS authority retention bucket location is empty")]
    EmptyBucketLocation,
    /// Minimum retention is zero or above Google's documented 100-year maximum.
    #[error("invalid GCS minimum bucket retention period")]
    InvalidMinimumRetention,
    /// Locked retention period does not cover the profile's required recovery horizon.
    #[error("GCS retention period is below required recovery horizon")]
    RetentionBelowRecoveryHorizon,
    /// Runtime/admin identity commitment was unset.
    #[error("GCS runtime/admin principal digest must be non-zero")]
    ZeroPrincipalDigest,
    /// Runtime writer and retention administrator must be separate trust identities.
    #[error("GCS runtime writer and retention administrator must be distinct principals")]
    RuntimeAndRetentionAdminMustDiffer,
    /// Encryption/key-management profile was not committed.
    #[error("GCS encryption profile digest must be non-zero")]
    ZeroEncryptionProfileDigest,
    /// IAM hardening profile was not committed.
    #[error("GCS IAM policy profile digest must be non-zero")]
    ZeroIamPolicyProfileDigest,
    /// Runtime permissions differ from exact create/get/list V1 allowlist.
    #[error("GCS runtime object permissions differ from exact V1 allowlist")]
    UnexpectedRuntimePermissions,
    /// Profile did not require irreversible Bucket Lock.
    #[error("GCS profile must require locked bucket retention")]
    BucketLockNotRequired,
    /// Profile did not require uniform bucket-level access.
    #[error("GCS profile must require uniform bucket-level access")]
    UniformBucketLevelAccessNotRequired,
    /// Profile did not require explicit public access prevention.
    #[error("GCS profile must require public access prevention")]
    PublicAccessPreventionNotRequired,
    /// Profile did not require Object Versioning disabled.
    #[error("GCS profile must require Object Versioning disabled")]
    ObjectVersioningDisablementNotRequired,
    /// Profile did not require hierarchical namespace disabled.
    #[error("GCS profile must require hierarchical namespace disabled")]
    HierarchicalNamespaceDisablementNotRequired,
    /// Profile did not require no lifecycle rules.
    #[error("GCS profile must require no lifecycle rules")]
    LifecycleRuleAbsenceNotRequired,
    /// SDK/API lineage differs from the frozen first qualification target.
    #[error("GCS Rust SDK/API lineage mismatch")]
    SdkLineageMismatch,
    /// Namespace's ADR-028 policy commitment does not equal this exact profile.
    #[error("ADR-028 namespace does not commit the exact GCS profile")]
    NamespacePolicyDigestMismatch,
    /// Provisioned bucket identity/location differs from profile.
    #[error("observed GCS bucket identity does not match profile")]
    ObservedBucketIdentityMismatch,
    /// Provisioned Bucket Lock state/period is weaker than profile.
    #[error("observed GCS retention policy is not locked or is too short")]
    ObservedRetentionPolicyTooWeak,
    /// Uniform bucket-level access is not enabled.
    #[error("observed GCS bucket lacks uniform bucket-level access")]
    ObservedUniformAccessDisabled,
    /// Public access prevention is not explicitly enforced.
    #[error("observed GCS bucket lacks explicit public access prevention")]
    ObservedPublicAccessPreventionDisabled,
    /// Object Versioning is enabled, violating V1 first-writer semantics.
    #[error("observed GCS bucket has Object Versioning enabled")]
    ObservedObjectVersioningEnabled,
    /// Hierarchical namespace is enabled, outside V1 qualification.
    #[error("observed GCS bucket has hierarchical namespace enabled")]
    ObservedHierarchicalNamespaceEnabled,
    /// Lifecycle rules are present in the dedicated retention bucket.
    #[error("observed GCS bucket has lifecycle rules")]
    ObservedLifecycleRulesPresent,
    /// ADR-028 namespace validation failed.
    #[error("authority retention namespace rejected GCS profile: {0}")]
    Namespace(#[from] xenia_operation_authority_retention_backend::AuthorityRetentionBackendErrorV1),
    /// Canonical profile serialization failed.
    #[error("GCS profile serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn validate_bucket_name(name: &str) -> Result<(), GcsProfileErrorV1> {
    // Stricter than the provider's full naming grammar on purpose: lowercase DNS-like names only.
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 63 {
        return Err(GcsProfileErrorV1::InvalidBucketName);
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(GcsProfileErrorV1::InvalidBucketName);
    }
    if bytes.iter().any(|byte| {
        !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'.')
    }) {
        return Err(GcsProfileErrorV1::InvalidBucketName);
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_authority_retention_backend::AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1;

    fn profile() -> GcsAuthorityRetentionProfileV1 {
        GcsAuthorityRetentionProfileV1 {
            schema: GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1.to_string(),
            project_number: 123_456_789,
            bucket_name: "xenia-authority-retention-prod".to_string(),
            bucket_location: "africa-south1".to_string(),
            minimum_bucket_retention_seconds: 31_557_600,
            required_recovery_horizon_seconds: 31_557_600,
            runtime_principal_digest: [1u8; 32],
            retention_admin_principal_digest: [2u8; 32],
            encryption_profile_digest: [3u8; 32],
            iam_policy_profile_digest: [4u8; 32],
            runtime_object_permissions: GCS_RUNTIME_OBJECT_PERMISSIONS_V1
                .iter()
                .map(|permission| (*permission).to_string())
                .collect(),
            require_locked_bucket_retention: true,
            require_uniform_bucket_level_access: true,
            require_public_access_prevention_enforced: true,
            require_object_versioning_disabled: true,
            require_hierarchical_namespace_disabled: true,
            require_no_lifecycle_rules: true,
            rust_sdk_crate: GCS_RUST_SDK_CRATE_V1.to_string(),
            rust_sdk_version: GCS_RUST_SDK_VERSION_V1.to_string(),
            storage_api_profile: GCS_STORAGE_API_PROFILE_V1.to_string(),
        }
    }

    #[test]
    fn canonical_profile_binds_namespace_policy_digest() {
        let profile = profile();
        let namespace = AuthorityRetentionNamespaceV1 {
            schema: AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1.to_string(),
            authority_domain_id: [9u8; 16],
            retention_lineage_id: [10u8; 16],
            retention_policy_digest: profile.profile_digest().unwrap(),
        };
        profile.validate_namespace(&namespace).unwrap();
    }

    #[test]
    fn runtime_permission_expansion_is_rejected() {
        let mut profile = profile();
        profile.runtime_object_permissions.push("storage.objects.delete".to_string());
        assert!(matches!(
            profile.validate(),
            Err(GcsProfileErrorV1::UnexpectedRuntimePermissions)
        ));
    }

    #[test]
    fn runtime_and_retention_admin_must_be_separate() {
        let mut profile = profile();
        profile.retention_admin_principal_digest = profile.runtime_principal_digest;
        assert!(matches!(
            profile.validate(),
            Err(GcsProfileErrorV1::RuntimeAndRetentionAdminMustDiffer)
        ));
    }

    #[test]
    fn object_names_are_deterministic_and_lexically_ordered() {
        let profile = profile();
        let digest = [0xabu8; 32];
        let a = profile.object_name(digest, 7).unwrap();
        let b = profile.object_name(digest, 42).unwrap();
        assert!(a < b);
        assert!(a.ends_with("00000000000000000007.bin"));
        assert!(b.ends_with("00000000000000000042.bin"));
        assert!(a.starts_with(&profile.namespace_object_prefix(digest).unwrap()));
    }

    #[test]
    fn observed_bucket_must_be_locked_and_non_versioned() {
        let profile = profile();
        let mut observed = GcsObservedBucketStateV1 {
            project_number: profile.project_number,
            bucket_name: profile.bucket_name.clone(),
            bucket_location: profile.bucket_location.clone(),
            bucket_retention_seconds: profile.minimum_bucket_retention_seconds,
            bucket_retention_locked: true,
            uniform_bucket_level_access_enabled: true,
            public_access_prevention_enforced: true,
            object_versioning_enabled: false,
            hierarchical_namespace_enabled: false,
            lifecycle_rule_count: 0,
        };
        verify_observed_bucket_state_v1(&profile, &observed).unwrap();
        observed.object_versioning_enabled = true;
        assert!(matches!(
            verify_observed_bucket_state_v1(&profile, &observed),
            Err(GcsProfileErrorV1::ObservedObjectVersioningEnabled)
        ));
    }
}
