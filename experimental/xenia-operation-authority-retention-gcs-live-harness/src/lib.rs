// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Manual-only destructive Google Cloud Storage qualification harness.
//!
//! The ordinary crate is network-free. Cloud-mutating functions exist only behind the
//! `live-gcs-network` feature and consume ADR-035's fail-closed configuration. Provisioning,
//! runtime permission verification, irreversible retention locking, and teardown are separate
//! entry points so reversible qualification cannot fall through into Bucket Lock.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;
use xenia_operation_authority_retention_gcs_live_qualification::GcsLiveQualificationConfigV1;

/// Domain separator for IAM-member identity commitments used by ADR-035.
pub const GCS_LIVE_PRINCIPAL_DIGEST_DOMAIN_V1: &[u8] = b"xenia-gcs-live-principal-v1";
/// Environment variable containing the exact IAM member configured for the runtime principal.
pub const GCS_LIVE_RUNTIME_MEMBER_ENV_V1: &str = "XENIA_GCS_LIVE_RUNTIME_MEMBER";
/// Environment variable containing the exact IAM member describing the provisioning principal.
pub const GCS_LIVE_ADMIN_MEMBER_ENV_V1: &str = "XENIA_GCS_LIVE_ADMIN_MEMBER";

/// Exact runtime permissions required by the ADR-030 provider profile.
pub const GCS_RUNTIME_REQUIRED_PERMISSIONS_V1: &[&str] = &[
    "storage.objects.create",
    "storage.objects.get",
    "storage.objects.list",
];

/// Permissions that the runtime qualification credential must demonstrably lack.
pub const GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1: &[&str] = &[
    "storage.objects.delete",
    "storage.objects.update",
    "storage.objects.restore",
    "storage.objects.setRetention",
    "storage.buckets.update",
    "storage.buckets.delete",
    "storage.buckets.setIamPolicy",
];

/// Validated IAM identities bound to ADR-035's principal digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundLivePrincipalsV1 {
    runtime_member: String,
    admin_member: String,
}

impl BoundLivePrincipalsV1 {
    /// Parse exact IAM member strings from the current process environment and bind them to the
    /// already validated ADR-035 principal commitments.
    pub fn from_current_environment(
        config: &GcsLiveQualificationConfigV1,
    ) -> Result<Self, GcsLiveHarnessErrorV1> {
        let runtime_member = std::env::var(GCS_LIVE_RUNTIME_MEMBER_ENV_V1)
            .map_err(|_| GcsLiveHarnessErrorV1::MissingEnvironment(GCS_LIVE_RUNTIME_MEMBER_ENV_V1))?;
        let admin_member = std::env::var(GCS_LIVE_ADMIN_MEMBER_ENV_V1)
            .map_err(|_| GcsLiveHarnessErrorV1::MissingEnvironment(GCS_LIVE_ADMIN_MEMBER_ENV_V1))?;
        Self::new(config, runtime_member, admin_member)
    }

    /// Bind explicit member strings to the ADR-035 digests. This form supports cloud-free tests.
    pub fn new(
        config: &GcsLiveQualificationConfigV1,
        runtime_member: String,
        admin_member: String,
    ) -> Result<Self, GcsLiveHarnessErrorV1> {
        validate_iam_member_v1(&runtime_member)?;
        validate_iam_member_v1(&admin_member)?;
        if runtime_member == admin_member {
            return Err(GcsLiveHarnessErrorV1::RuntimeAdminMemberCollision);
        }
        if principal_digest_v1(&runtime_member) != config.runtime_principal_digest() {
            return Err(GcsLiveHarnessErrorV1::RuntimePrincipalDigestMismatch);
        }
        if principal_digest_v1(&admin_member) != config.admin_principal_digest() {
            return Err(GcsLiveHarnessErrorV1::AdminPrincipalDigestMismatch);
        }
        Ok(Self {
            runtime_member,
            admin_member,
        })
    }

    /// Exact IAM member granted runtime object privileges.
    pub fn runtime_member(&self) -> &str {
        &self.runtime_member
    }

    /// Exact IAM member expected to own provisioning/retention administration.
    pub fn admin_member(&self) -> &str {
        &self.admin_member
    }
}

/// Domain-separated commitment to one exact IAM member string.
pub fn principal_digest_v1(member: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GCS_LIVE_PRINCIPAL_DIGEST_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(member.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Lowercase hexadecimal form useful when preparing ADR-035 environment variables.
pub fn principal_digest_hex_v1(member: &str) -> Result<String, GcsLiveHarnessErrorV1> {
    validate_iam_member_v1(member)?;
    Ok(hex_lower(&principal_digest_v1(member)))
}

fn validate_iam_member_v1(member: &str) -> Result<(), GcsLiveHarnessErrorV1> {
    if member.is_empty()
        || member.len() > 2048
        || member.chars().any(char::is_whitespace)
        || member == "allUsers"
        || member == "allAuthenticatedUsers"
    {
        return Err(GcsLiveHarnessErrorV1::InvalidIamMember);
    }
    let accepted = member.starts_with("serviceAccount:")
        || member.starts_with("user:")
        || member.starts_with("group:")
        || member.starts_with("principal://")
        || member.starts_with("principalSet://");
    if !accepted {
        return Err(GcsLiveHarnessErrorV1::InvalidIamMember);
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

/// Cloud-independent harness errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcsLiveHarnessErrorV1 {
    /// Required harness environment variable is absent.
    #[error("missing live GCS harness environment variable: {0}")]
    MissingEnvironment(&'static str),
    /// IAM member is empty, public, malformed, or outside the accepted explicit-member profiles.
    #[error("invalid live GCS IAM member")]
    InvalidIamMember,
    /// Runtime and administration member strings are identical.
    #[error("runtime and administration IAM members must differ")]
    RuntimeAdminMemberCollision,
    /// Runtime member does not match ADR-035's configured digest.
    #[error("runtime IAM member digest does not match ADR-035 configuration")]
    RuntimePrincipalDigestMismatch,
    /// Administration member does not match ADR-035's configured digest.
    #[error("administration IAM member digest does not match ADR-035 configuration")]
    AdminPrincipalDigestMismatch,
}

/// Network-capable destructive provider functions. This module does not exist in ordinary builds.
#[cfg(feature = "live-gcs-network")]
pub mod cloud {
    use super::{
        BoundLivePrincipalsV1, GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1,
        GCS_RUNTIME_REQUIRED_PERMISSIONS_V1,
    };
    use google_cloud_gax::paginator::ItemPaginator;
    use google_cloud_iam_v1::model::Binding;
    use google_cloud_storage::{
        client::StorageControl,
        model::{
            Bucket,
            bucket::{
                HierarchicalNamespace, IamConfig, RetentionPolicy, SoftDeletePolicy, Versioning,
                iam_config::UniformBucketLevelAccess,
            },
        },
    };
    use google_cloud_wkt::{Duration, FieldMask};
    use std::{collections::BTreeSet, error::Error};
    use xenia_operation_authority_retention_gcs_live_qualification::{
        GcsLiveQualificationConfigV1, GcsLiveQualificationModeV1,
    };

    /// Boxed provider result used only by the manual destructive harness.
    pub type LiveCloudResultV1<T> = Result<T, Box<dyn Error + Send + Sync>>;

    /// Result of the runtime principal's effective-permission probe.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimePermissionProbeV1 {
        /// Required permissions positively observed for the current credential.
        pub required_present: Vec<String>,
        /// Forbidden permissions positively absent from the current credential.
        pub forbidden_absent: Vec<String>,
    }

    /// Create and harden one fresh ADR-035-derived qualification bucket, then bind the runtime IAM
    /// member to objectCreator + objectViewer. This entry point only accepts reversible mode.
    pub async fn provision_reversible_v1(
        control: &StorageControl,
        config: &GcsLiveQualificationConfigV1,
        principals: &BoundLivePrincipalsV1,
    ) -> LiveCloudResultV1<Bucket> {
        if config.mode() != GcsLiveQualificationModeV1::Reversible {
            return Err("admin-provision requires reversible ADR-035 mode".into());
        }

        let zero = Duration::new(0, 0)?;
        let bucket_request = Bucket::new()
            .set_project(format!("projects/{}", config.project_id()))
            .set_location(config.location())
            .set_storage_class("STANDARD")
            .set_iam_config(
                IamConfig::new()
                    .set_uniform_bucket_level_access(
                        UniformBucketLevelAccess::new().set_enabled(true),
                    )
                    .set_public_access_prevention("enforced"),
            )
            .set_soft_delete_policy(SoftDeletePolicy::new().set_retention_duration(zero))
            .set_versioning(Versioning::new().set_enabled(false))
            .set_hierarchical_namespace(HierarchicalNamespace::new().set_enabled(false));

        let bucket = control
            .create_bucket()
            .set_parent("projects/_")
            .set_bucket_id(config.bucket_name())
            .set_bucket(bucket_request)
            .send()
            .await?;
        verify_disposable_bucket_state_v1(config, &bucket)?;

        let resource = bucket_resource_v1(config.bucket_name());
        let mut policy = control
            .get_iam_policy()
            .set_resource(resource.clone())
            .send()
            .await?;
        ensure_binding_v1(
            &mut policy.bindings,
            "roles/storage.objectCreator",
            principals.runtime_member(),
        );
        ensure_binding_v1(
            &mut policy.bindings,
            "roles/storage.objectViewer",
            principals.runtime_member(),
        );
        control
            .set_iam_policy()
            .set_resource(resource)
            .set_policy(policy)
            .send()
            .await?;

        let verified = control
            .get_bucket()
            .set_name(bucket_resource_v1(config.bucket_name()))
            .send()
            .await?;
        verify_disposable_bucket_state_v1(config, &verified)?;
        Ok(verified)
    }

    /// Probe the effective permissions of the credential running this binary. Required object
    /// permissions must all be present and dangerous mutation/administration permissions absent.
    pub async fn probe_runtime_permissions_v1(
        control: &StorageControl,
        config: &GcsLiveQualificationConfigV1,
    ) -> LiveCloudResultV1<RuntimePermissionProbeV1> {
        let mut requested = GCS_RUNTIME_REQUIRED_PERMISSIONS_V1
            .iter()
            .chain(GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1.iter())
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        requested.sort();
        requested.dedup();

        let observed = control
            .test_iam_permissions()
            .set_resource(bucket_resource_v1(config.bucket_name()))
            .set_permissions(requested)
            .send()
            .await?;
        let granted = observed.permissions.into_iter().collect::<BTreeSet<_>>();

        let missing_required = GCS_RUNTIME_REQUIRED_PERMISSIONS_V1
            .iter()
            .filter(|permission| !granted.contains(**permission))
            .copied()
            .collect::<Vec<_>>();
        if !missing_required.is_empty() {
            return Err(format!("runtime credential lacks required permissions: {missing_required:?}").into());
        }
        let present_forbidden = GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1
            .iter()
            .filter(|permission| granted.contains(**permission))
            .copied()
            .collect::<Vec<_>>();
        if !present_forbidden.is_empty() {
            return Err(format!("runtime credential has forbidden permissions: {present_forbidden:?}").into());
        }

        Ok(RuntimePermissionProbeV1 {
            required_present: GCS_RUNTIME_REQUIRED_PERMISSIONS_V1
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            forbidden_absent: GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        })
    }

    /// Apply the short test retention period and irreversibly lock it. This entry point only accepts
    /// ADR-035 irreversible mode, whose second acknowledgement is bound to this exact bucket and
    /// retention interval.
    pub async fn lock_retention_policy_v1(
        control: &StorageControl,
        config: &GcsLiveQualificationConfigV1,
    ) -> LiveCloudResultV1<Bucket> {
        if config.mode() != GcsLiveQualificationModeV1::IrreversibleBucketLock
            || !config.irreversible_bucket_lock_armed()
        {
            return Err("admin-lock requires explicitly armed irreversible ADR-035 mode".into());
        }
        let bucket = control
            .get_bucket()
            .set_name(bucket_resource_v1(config.bucket_name()))
            .send()
            .await?;
        verify_disposable_bucket_state_v1(config, &bucket)?;
        if bucket
            .retention_policy
            .as_ref()
            .is_some_and(|policy| policy.is_locked)
        {
            return Err("qualification bucket retention policy is already locked".into());
        }

        let retention = RetentionPolicy::new().set_retention_duration(Duration::new(
            i64::try_from(config.retention_seconds())?,
            0,
        )?);
        let with_policy = control
            .update_bucket()
            .set_bucket(bucket.set_retention_policy(retention))
            .set_if_metageneration_match(bucket.metageneration)
            .set_update_mask(FieldMask::default().set_paths(["retention_policy"]))
            .send()
            .await?;
        verify_unlocked_retention_v1(config, &with_policy)?;

        let locked = control
            .lock_bucket_retention_policy()
            .set_bucket(with_policy.name.clone())
            .set_if_metageneration_match(with_policy.metageneration)
            .send()
            .await?;
        verify_locked_retention_v1(config, &locked)?;
        Ok(locked)
    }

    /// Delete all currently live objects and then delete the disposable bucket. On a locked bucket
    /// this naturally fails until each object satisfies the locked retention interval; rerunning the
    /// same explicit teardown after expiry is the intended cleanup path.
    pub async fn teardown_bucket_v1(
        control: &StorageControl,
        config: &GcsLiveQualificationConfigV1,
    ) -> LiveCloudResultV1<()> {
        let bucket = control
            .get_bucket()
            .set_name(bucket_resource_v1(config.bucket_name()))
            .send()
            .await?;
        verify_disposable_bucket_state_v1(config, &bucket)?;

        let mut items = control
            .list_objects()
            .set_parent(bucket_resource_v1(config.bucket_name()))
            .set_versions(false)
            .by_item();
        while let Some(item) = items.next().await {
            let object = item?;
            control
                .delete_object()
                .set_bucket(bucket_resource_v1(config.bucket_name()))
                .set_object(object.name)
                .set_generation(object.generation)
                .send()
                .await?;
        }

        let bucket = control
            .get_bucket()
            .set_name(bucket_resource_v1(config.bucket_name()))
            .send()
            .await?;
        control
            .delete_bucket()
            .set_name(bucket.name)
            .set_if_metageneration_match(bucket.metageneration)
            .send()
            .await?;
        Ok(())
    }

    fn ensure_binding_v1(bindings: &mut Vec<Binding>, role: &str, member: &str) {
        if let Some(binding) = bindings.iter_mut().find(|binding| binding.role == role) {
            if !binding.members.iter().any(|value| value == member) {
                binding.members.push(member.to_string());
            }
            return;
        }
        bindings.push(
            Binding::new()
                .set_role(role)
                .set_members(vec![member.to_string()]),
        );
    }

    fn verify_disposable_bucket_state_v1(
        config: &GcsLiveQualificationConfigV1,
        bucket: &Bucket,
    ) -> LiveCloudResultV1<()> {
        if bucket.name != bucket_resource_v1(config.bucket_name())
            || bucket.project != format!("projects/{}", config.project_id())
            || bucket.location != config.location()
        {
            return Err("qualification bucket identity/project/location mismatch".into());
        }
        let iam = bucket
            .iam_config
            .as_ref()
            .ok_or("qualification bucket missing IAM configuration")?;
        if !iam
            .uniform_bucket_level_access
            .as_ref()
            .is_some_and(|value| value.enabled)
            || iam.public_access_prevention != "enforced"
        {
            return Err("qualification bucket access hardening mismatch".into());
        }
        if !bucket
            .soft_delete_policy
            .as_ref()
            .and_then(|policy| policy.retention_duration.as_ref())
            .is_some_and(|duration| duration.seconds == 0 && duration.nanos == 0)
        {
            return Err("qualification bucket soft delete is not explicitly disabled".into());
        }
        if bucket.versioning.as_ref().is_some_and(|value| value.enabled) {
            return Err("qualification bucket Object Versioning is enabled".into());
        }
        if bucket
            .hierarchical_namespace
            .as_ref()
            .is_some_and(|value| value.enabled)
        {
            return Err("qualification bucket hierarchical namespace is enabled".into());
        }
        if bucket.lifecycle.is_some() {
            return Err("qualification bucket unexpectedly has lifecycle rules".into());
        }
        Ok(())
    }

    fn verify_unlocked_retention_v1(
        config: &GcsLiveQualificationConfigV1,
        bucket: &Bucket,
    ) -> LiveCloudResultV1<()> {
        let policy = bucket
            .retention_policy
            .as_ref()
            .ok_or("qualification bucket retention policy missing after update")?;
        if policy.is_locked {
            return Err("retention policy unexpectedly locked before explicit lock step".into());
        }
        verify_retention_duration_v1(config, policy)
    }

    fn verify_locked_retention_v1(
        config: &GcsLiveQualificationConfigV1,
        bucket: &Bucket,
    ) -> LiveCloudResultV1<()> {
        let policy = bucket
            .retention_policy
            .as_ref()
            .ok_or("qualification bucket retention policy missing after lock")?;
        if !policy.is_locked {
            return Err("Bucket Lock call returned without locked retention policy".into());
        }
        verify_retention_duration_v1(config, policy)
    }

    fn verify_retention_duration_v1(
        config: &GcsLiveQualificationConfigV1,
        policy: &RetentionPolicy,
    ) -> LiveCloudResultV1<()> {
        let duration = policy
            .retention_duration
            .as_ref()
            .ok_or("retention policy duration missing")?;
        if duration.seconds != i64::try_from(config.retention_seconds())? || duration.nanos != 0 {
            return Err("retention policy duration mismatch".into());
        }
        Ok(())
    }

    fn bucket_resource_v1(bucket: &str) -> String {
        format!("projects/_/buckets/{bucket}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xenia_operation_authority_retention_gcs_live_qualification::{
        expected_disposable_ack_v1, GCS_LIVE_QUALIFICATION_ARM_V1,
    };

    fn vars(runtime: &str, admin: &str) -> BTreeMap<String, String> {
        let project_id = "xenia-qual-project";
        let project_number = 123456789u64;
        let nonce = "0102030405060708";
        let bucket = "xenia-ar-qual-123456789-0102030405060708";
        BTreeMap::from([
            ("XENIA_GCS_LIVE_QUALIFICATION".to_string(), GCS_LIVE_QUALIFICATION_ARM_V1.to_string()),
            ("XENIA_GCS_LIVE_MODE".to_string(), "reversible".to_string()),
            ("XENIA_GCS_LIVE_PROJECT_ID".to_string(), project_id.to_string()),
            ("XENIA_GCS_LIVE_PROJECT_NUMBER".to_string(), project_number.to_string()),
            ("XENIA_GCS_LIVE_LOCATION".to_string(), "US".to_string()),
            ("XENIA_GCS_LIVE_RUN_NONCE_HEX".to_string(), nonce.to_string()),
            ("XENIA_GCS_LIVE_RETENTION_SECONDS".to_string(), "60".to_string()),
            ("XENIA_GCS_LIVE_RUNTIME_PRINCIPAL_DIGEST_HEX".to_string(), principal_digest_hex_v1(runtime).unwrap()),
            ("XENIA_GCS_LIVE_ADMIN_PRINCIPAL_DIGEST_HEX".to_string(), principal_digest_hex_v1(admin).unwrap()),
            ("XENIA_GCS_LIVE_DISPOSABLE_ACK".to_string(), expected_disposable_ack_v1(project_id, bucket)),
        ])
    }

    #[test]
    fn principal_binding_round_trips_exact_members() {
        let runtime = "serviceAccount:xenia-runtime@example.iam.gserviceaccount.com";
        let admin = "serviceAccount:xenia-admin@example.iam.gserviceaccount.com";
        let config = GcsLiveQualificationConfigV1::from_environment_map(&vars(runtime, admin)).unwrap();
        let bound = BoundLivePrincipalsV1::new(&config, runtime.to_string(), admin.to_string()).unwrap();
        assert_eq!(bound.runtime_member(), runtime);
        assert_eq!(bound.admin_member(), admin);
    }

    #[test]
    fn public_iam_members_are_refused() {
        assert!(matches!(
            principal_digest_hex_v1("allUsers"),
            Err(GcsLiveHarnessErrorV1::InvalidIamMember)
        ));
        assert!(matches!(
            principal_digest_hex_v1("allAuthenticatedUsers"),
            Err(GcsLiveHarnessErrorV1::InvalidIamMember)
        ));
    }

    #[test]
    fn member_strings_cannot_swap_roles_under_existing_digests() {
        let runtime = "serviceAccount:xenia-runtime@example.iam.gserviceaccount.com";
        let admin = "serviceAccount:xenia-admin@example.iam.gserviceaccount.com";
        let config = GcsLiveQualificationConfigV1::from_environment_map(&vars(runtime, admin)).unwrap();
        assert!(matches!(
            BoundLivePrincipalsV1::new(&config, admin.to_string(), runtime.to_string()),
            Err(GcsLiveHarnessErrorV1::RuntimePrincipalDigestMismatch)
        ));
    }

    #[test]
    fn runtime_permission_contract_is_minimal_and_disjoint() {
        let required = GCS_RUNTIME_REQUIRED_PERMISSIONS_V1.iter().copied().collect::<std::collections::BTreeSet<_>>();
        let forbidden = GCS_RUNTIME_FORBIDDEN_PERMISSIONS_V1.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert!(required.is_disjoint(&forbidden));
        assert_eq!(required, std::collections::BTreeSet::from([
            "storage.objects.create",
            "storage.objects.get",
            "storage.objects.list",
        ]));
    }
}
