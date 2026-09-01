// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed arming contract for disposable live Google Cloud Storage qualification.
//!
//! This crate performs no cloud calls. It exists so a later destructive harness cannot turn a
//! generic "run live tests" switch into bucket creation or irreversible Bucket Lock. A valid
//! configuration is constructible only from an exact disposable-purpose acknowledgement, a fresh
//! bucket nonce, distinct runtime/admin identity commitments, a bounded test retention interval,
//! and (for Bucket Lock) a second acknowledgement bound to the exact derived bucket and interval.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use thiserror::Error;

/// Exact live-qualification configuration schema.
pub const GCS_LIVE_QUALIFICATION_SCHEMA_V1: &str =
    "xenia-gcs-live-authority-retention-qualification-v1";
/// Exact primary arming value required before any future live-cloud action.
pub const GCS_LIVE_QUALIFICATION_ARM_V1: &str = "DISPOSABLE_QUALIFICATION_ONLY";
/// Fixed bucket prefix; callers cannot redirect the harness to an arbitrary existing bucket.
pub const GCS_LIVE_QUALIFICATION_BUCKET_PREFIX_V1: &str = "xenia-ar-qual-";
/// Maximum retention interval allowed by the disposable qualification harness.
///
/// This is intentionally far below a production retention horizon. Live qualification proves
/// provider mechanics; it does not substitute its short-lived test policy for deployment policy.
pub const GCS_LIVE_QUALIFICATION_MAX_RETENTION_SECONDS_V1: u64 = 300;
/// Minimum non-zero interval accepted by the harness.
pub const GCS_LIVE_QUALIFICATION_MIN_RETENTION_SECONDS_V1: u64 = 1;

/// Supported live-cloud qualification phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcsLiveQualificationModeV1 {
    /// Reversible qualification. Bucket retention may be configured but must remain unlocked.
    Reversible,
    /// Separately armed irreversible Bucket Lock qualification.
    IrreversibleBucketLock,
}

impl GcsLiveQualificationModeV1 {
    fn parse(value: &str) -> Result<Self, GcsLiveQualificationErrorV1> {
        match value {
            "reversible" => Ok(Self::Reversible),
            "irreversible-bucket-lock" => Ok(Self::IrreversibleBucketLock),
            _ => Err(GcsLiveQualificationErrorV1::UnsupportedMode),
        }
    }
}

/// Validated, non-forgeable-by-fields live-qualification configuration.
///
/// Fields are private so future cloud code must obtain this value through the fail-closed parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsLiveQualificationConfigV1 {
    schema: String,
    mode: GcsLiveQualificationModeV1,
    project_id: String,
    project_number: u64,
    location: String,
    run_nonce: [u8; 8],
    retention_seconds: u64,
    runtime_principal_digest: [u8; 32],
    admin_principal_digest: [u8; 32],
    bucket_name: String,
}

impl GcsLiveQualificationConfigV1 {
    /// Parse the current process environment into the exact fail-closed qualification contract.
    pub fn from_current_environment() -> Result<Self, GcsLiveQualificationErrorV1> {
        let vars = std::env::vars().collect::<BTreeMap<_, _>>();
        Self::from_environment_map(&vars)
    }

    /// Parse an environment map. This form exists so safety behavior can be tested without
    /// mutating process-global environment variables.
    pub fn from_environment_map(
        vars: &BTreeMap<String, String>,
    ) -> Result<Self, GcsLiveQualificationErrorV1> {
        if required(vars, "XENIA_GCS_LIVE_QUALIFICATION")? != GCS_LIVE_QUALIFICATION_ARM_V1 {
            return Err(GcsLiveQualificationErrorV1::PrimaryArmMismatch);
        }

        let mode = GcsLiveQualificationModeV1::parse(required(
            vars,
            "XENIA_GCS_LIVE_MODE",
        )?)?;
        let project_id = required(vars, "XENIA_GCS_LIVE_PROJECT_ID")?.to_string();
        validate_project_id(&project_id)?;
        let project_number = required(vars, "XENIA_GCS_LIVE_PROJECT_NUMBER")?
            .parse::<u64>()
            .map_err(|_| GcsLiveQualificationErrorV1::InvalidProjectNumber)?;
        if project_number == 0 {
            return Err(GcsLiveQualificationErrorV1::InvalidProjectNumber);
        }
        let location = required(vars, "XENIA_GCS_LIVE_LOCATION")?.to_string();
        validate_location(&location)?;
        let run_nonce = decode_hex_exact::<8>(required(vars, "XENIA_GCS_LIVE_RUN_NONCE_HEX")?)?;
        if run_nonce == [0u8; 8] {
            return Err(GcsLiveQualificationErrorV1::ZeroRunNonce);
        }
        let retention_seconds = required(vars, "XENIA_GCS_LIVE_RETENTION_SECONDS")?
            .parse::<u64>()
            .map_err(|_| GcsLiveQualificationErrorV1::InvalidRetentionSeconds)?;
        if !(GCS_LIVE_QUALIFICATION_MIN_RETENTION_SECONDS_V1
            ..=GCS_LIVE_QUALIFICATION_MAX_RETENTION_SECONDS_V1)
            .contains(&retention_seconds)
        {
            return Err(GcsLiveQualificationErrorV1::InvalidRetentionSeconds);
        }

        let runtime_principal_digest = decode_hex_exact::<32>(required(
            vars,
            "XENIA_GCS_LIVE_RUNTIME_PRINCIPAL_DIGEST_HEX",
        )?)?;
        let admin_principal_digest = decode_hex_exact::<32>(required(
            vars,
            "XENIA_GCS_LIVE_ADMIN_PRINCIPAL_DIGEST_HEX",
        )?)?;
        if runtime_principal_digest == [0u8; 32] || admin_principal_digest == [0u8; 32] {
            return Err(GcsLiveQualificationErrorV1::ZeroPrincipalDigest);
        }
        if runtime_principal_digest == admin_principal_digest {
            return Err(GcsLiveQualificationErrorV1::RuntimeAdminIdentityCollision);
        }

        let bucket_name = derive_bucket_name_v1(project_number, run_nonce);
        let expected_disposable = expected_disposable_ack_v1(&project_id, &bucket_name);
        if required(vars, "XENIA_GCS_LIVE_DISPOSABLE_ACK")? != expected_disposable {
            return Err(GcsLiveQualificationErrorV1::DisposableAckMismatch);
        }

        if mode == GcsLiveQualificationModeV1::IrreversibleBucketLock {
            let expected_lock = expected_irreversible_lock_ack_v1(&bucket_name, retention_seconds);
            if required(vars, "XENIA_GCS_LIVE_IRREVERSIBLE_LOCK_ACK")? != expected_lock {
                return Err(GcsLiveQualificationErrorV1::IrreversibleLockAckMismatch);
            }
        }

        Ok(Self {
            schema: GCS_LIVE_QUALIFICATION_SCHEMA_V1.to_string(),
            mode,
            project_id,
            project_number,
            location,
            run_nonce,
            retention_seconds,
            runtime_principal_digest,
            admin_principal_digest,
            bucket_name,
        })
    }

    /// Exact schema for evidence output.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Qualified phase.
    pub const fn mode(&self) -> GcsLiveQualificationModeV1 {
        self.mode
    }

    /// Dedicated qualification project ID.
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Dedicated qualification project number.
    pub const fn project_number(&self) -> u64 {
        self.project_number
    }

    /// Requested provider location.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Fresh run nonce bound into the derived bucket name.
    pub const fn run_nonce(&self) -> [u8; 8] {
        self.run_nonce
    }

    /// Short disposable retention interval.
    pub const fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }

    /// Exact digest identifying the least-privilege runtime principal under test.
    pub const fn runtime_principal_digest(&self) -> [u8; 32] {
        self.runtime_principal_digest
    }

    /// Exact digest identifying the separate provisioning/retention administration principal.
    pub const fn admin_principal_digest(&self) -> [u8; 32] {
        self.admin_principal_digest
    }

    /// Derived fresh bucket name. Existing arbitrary bucket names are never accepted as input.
    pub fn bucket_name(&self) -> &str {
        &self.bucket_name
    }

    /// Whether the irreversible Bucket Lock phase was explicitly and bucket-specifically armed.
    pub const fn irreversible_bucket_lock_armed(&self) -> bool {
        matches!(self.mode, GcsLiveQualificationModeV1::IrreversibleBucketLock)
    }

    /// Live bucket state required before the future authority-retention provider tests may run.
    ///
    /// Soft delete is explicitly disabled for this disposable qualification bucket because new GCS
    /// buckets otherwise default to a soft-delete retention period, which would make teardown and
    /// cleanup evidence ambiguous. Production policy may choose differently, but must commit that
    /// choice separately rather than inherit a provider default silently.
    pub const fn required_bucket_state(&self) -> GcsLiveRequiredBucketStateV1 {
        GcsLiveRequiredBucketStateV1 {
            uniform_bucket_level_access: true,
            public_access_prevention_enforced: true,
            soft_delete_disabled: true,
            object_versioning_disabled: true,
            hierarchical_namespace_disabled: true,
            no_lifecycle_rules: true,
        }
    }
}

/// Exact bucket hardening state required by the disposable qualification harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcsLiveRequiredBucketStateV1 {
    /// ACLs disabled; IAM is the only access-control path.
    pub uniform_bucket_level_access: bool,
    /// Bucket setting explicitly prevents public access.
    pub public_access_prevention_enforced: bool,
    /// Soft-delete retention disabled for deterministic disposable teardown.
    pub soft_delete_disabled: bool,
    /// Object Versioning disabled.
    pub object_versioning_disabled: bool,
    /// Hierarchical namespace disabled.
    pub hierarchical_namespace_disabled: bool,
    /// No Object Lifecycle Management rules.
    pub no_lifecycle_rules: bool,
}

/// Derive the only bucket name the harness may target for one run.
pub fn derive_bucket_name_v1(project_number: u64, run_nonce: [u8; 8]) -> String {
    format!(
        "{GCS_LIVE_QUALIFICATION_BUCKET_PREFIX_V1}{project_number}-{}",
        hex_lower(&run_nonce)
    )
}

/// Exact primary destructive acknowledgement expected for one project/bucket pair.
pub fn expected_disposable_ack_v1(project_id: &str, bucket_name: &str) -> String {
    format!("I_ACCEPT_DISPOSABLE_GCS_QUALIFICATION:{project_id}:{bucket_name}")
}

/// Exact second acknowledgement required for irreversible Bucket Lock.
pub fn expected_irreversible_lock_ack_v1(bucket_name: &str, retention_seconds: u64) -> String {
    format!("I_ACCEPT_IRREVERSIBLE_BUCKET_LOCK:{bucket_name}:{retention_seconds}")
}

/// Fail-closed live-qualification arming errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcsLiveQualificationErrorV1 {
    /// Required environment variable is absent.
    #[error("missing live qualification environment variable: {0}")]
    MissingEnvironment(&'static str),
    /// Primary live-test arm did not exactly match the disposable-only phrase.
    #[error("GCS live qualification primary arm mismatch")]
    PrimaryArmMismatch,
    /// Unknown qualification mode.
    #[error("unsupported GCS live qualification mode")]
    UnsupportedMode,
    /// Project ID is outside the strict canonical subset accepted by this harness.
    #[error("invalid dedicated GCS qualification project id")]
    InvalidProjectId,
    /// Project number is missing/zero/non-numeric.
    #[error("invalid dedicated GCS qualification project number")]
    InvalidProjectNumber,
    /// Location is empty or outside the strict canonical subset.
    #[error("invalid GCS qualification location")]
    InvalidLocation,
    /// Hex value is not exact lowercase canonical length/encoding.
    #[error("invalid canonical lowercase hex qualification value")]
    InvalidHex,
    /// Run nonce must not be all-zero.
    #[error("GCS qualification run nonce must be non-zero")]
    ZeroRunNonce,
    /// Retention interval is zero, non-numeric, or above the disposable ceiling.
    #[error("invalid disposable GCS qualification retention interval")]
    InvalidRetentionSeconds,
    /// Principal identity commitment was unset.
    #[error("GCS qualification principal digests must be non-zero")]
    ZeroPrincipalDigest,
    /// Runtime and administration principals must be distinct trust identities.
    #[error("GCS qualification runtime and admin principal digests must differ")]
    RuntimeAdminIdentityCollision,
    /// Project/bucket-specific disposable acknowledgement did not match.
    #[error("GCS disposable qualification acknowledgement mismatch")]
    DisposableAckMismatch,
    /// Irreversible-lock mode lacked the exact bucket/retention-specific second acknowledgement.
    #[error("GCS irreversible Bucket Lock acknowledgement mismatch")]
    IrreversibleLockAckMismatch,
}

fn required<'a>(
    vars: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, GcsLiveQualificationErrorV1> {
    vars.get(name)
        .map(String::as_str)
        .ok_or(GcsLiveQualificationErrorV1::MissingEnvironment(name))
}

fn validate_project_id(value: &str) -> Result<(), GcsLiveQualificationErrorV1> {
    if !(6..=30).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err(GcsLiveQualificationErrorV1::InvalidProjectId);
    }
    Ok(())
}

fn validate_location(value: &str) -> Result<(), GcsLiveQualificationErrorV1> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(GcsLiveQualificationErrorV1::InvalidLocation);
    }
    Ok(())
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], GcsLiveQualificationErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GcsLiveQualificationErrorV1::InvalidHex);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(value.as_bytes()[index * 2])?;
        let lo = hex_nibble(value.as_bytes()[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Result<u8, GcsLiveQualificationErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(GcsLiveQualificationErrorV1::InvalidHex),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(byte: u8, len: usize) -> String {
        format!("{byte:02x}").repeat(len)
    }

    fn base(mode: &str, nonce: &str, retention: u64) -> BTreeMap<String, String> {
        let project_id = "xenia-qual-123";
        let project_number = 123456789u64;
        let run_nonce = decode_hex_exact::<8>(nonce).unwrap();
        let bucket = derive_bucket_name_v1(project_number, run_nonce);
        BTreeMap::from([
            (
                "XENIA_GCS_LIVE_QUALIFICATION".to_string(),
                GCS_LIVE_QUALIFICATION_ARM_V1.to_string(),
            ),
            ("XENIA_GCS_LIVE_MODE".to_string(), mode.to_string()),
            (
                "XENIA_GCS_LIVE_PROJECT_ID".to_string(),
                project_id.to_string(),
            ),
            (
                "XENIA_GCS_LIVE_PROJECT_NUMBER".to_string(),
                project_number.to_string(),
            ),
            (
                "XENIA_GCS_LIVE_LOCATION".to_string(),
                "us-central1".to_string(),
            ),
            (
                "XENIA_GCS_LIVE_RUN_NONCE_HEX".to_string(),
                nonce.to_string(),
            ),
            (
                "XENIA_GCS_LIVE_RETENTION_SECONDS".to_string(),
                retention.to_string(),
            ),
            (
                "XENIA_GCS_LIVE_RUNTIME_PRINCIPAL_DIGEST_HEX".to_string(),
                hex(1, 32),
            ),
            (
                "XENIA_GCS_LIVE_ADMIN_PRINCIPAL_DIGEST_HEX".to_string(),
                hex(2, 32),
            ),
            (
                "XENIA_GCS_LIVE_DISPOSABLE_ACK".to_string(),
                expected_disposable_ack_v1(project_id, &bucket),
            ),
        ])
    }

    #[test]
    fn reversible_mode_is_armed_without_irreversible_ack() {
        let vars = base("reversible", "0102030405060708", 60);
        let config = GcsLiveQualificationConfigV1::from_environment_map(&vars).unwrap();
        assert_eq!(config.mode(), GcsLiveQualificationModeV1::Reversible);
        assert!(!config.irreversible_bucket_lock_armed());
        assert!(config.required_bucket_state().soft_delete_disabled);
        assert!(config.required_bucket_state().uniform_bucket_level_access);
    }

    #[test]
    fn old_disposable_ack_cannot_be_reused_for_new_nonce() {
        let old = base("reversible", "0102030405060708", 60);
        let mut new = base("reversible", "1112131415161718", 60);
        new.insert(
            "XENIA_GCS_LIVE_DISPOSABLE_ACK".to_string(),
            old["XENIA_GCS_LIVE_DISPOSABLE_ACK"].clone(),
        );
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&new),
            Err(GcsLiveQualificationErrorV1::DisposableAckMismatch)
        );
    }

    #[test]
    fn irreversible_mode_requires_second_bucket_specific_ack() {
        let vars = base("irreversible-bucket-lock", "0102030405060708", 60);
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&vars),
            Err(GcsLiveQualificationErrorV1::MissingEnvironment(
                "XENIA_GCS_LIVE_IRREVERSIBLE_LOCK_ACK"
            ))
        );
    }

    #[test]
    fn irreversible_ack_is_bound_to_exact_bucket_and_interval() {
        let mut vars = base("irreversible-bucket-lock", "0102030405060708", 60);
        let config_bucket = derive_bucket_name_v1(
            123456789,
            decode_hex_exact::<8>("0102030405060708").unwrap(),
        );
        vars.insert(
            "XENIA_GCS_LIVE_IRREVERSIBLE_LOCK_ACK".to_string(),
            expected_irreversible_lock_ack_v1(&config_bucket, 61),
        );
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&vars),
            Err(GcsLiveQualificationErrorV1::IrreversibleLockAckMismatch)
        );

        vars.insert(
            "XENIA_GCS_LIVE_IRREVERSIBLE_LOCK_ACK".to_string(),
            expected_irreversible_lock_ack_v1(&config_bucket, 60),
        );
        let config = GcsLiveQualificationConfigV1::from_environment_map(&vars).unwrap();
        assert!(config.irreversible_bucket_lock_armed());
    }

    #[test]
    fn runtime_and_admin_identity_must_not_collapse() {
        let mut vars = base("reversible", "0102030405060708", 60);
        vars.insert(
            "XENIA_GCS_LIVE_ADMIN_PRINCIPAL_DIGEST_HEX".to_string(),
            vars["XENIA_GCS_LIVE_RUNTIME_PRINCIPAL_DIGEST_HEX"].clone(),
        );
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&vars),
            Err(GcsLiveQualificationErrorV1::RuntimeAdminIdentityCollision)
        );
    }

    #[test]
    fn disposable_retention_ceiling_is_fail_closed() {
        let vars = base(
            "reversible",
            "0102030405060708",
            GCS_LIVE_QUALIFICATION_MAX_RETENTION_SECONDS_V1 + 1,
        );
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&vars),
            Err(GcsLiveQualificationErrorV1::InvalidRetentionSeconds)
        );
    }

    #[test]
    fn bucket_name_is_derived_and_within_gcs_name_length() {
        let vars = base("reversible", "0102030405060708", 60);
        let config = GcsLiveQualificationConfigV1::from_environment_map(&vars).unwrap();
        assert!(config.bucket_name().starts_with(GCS_LIVE_QUALIFICATION_BUCKET_PREFIX_V1));
        assert!(config.bucket_name().len() <= 63);
        assert_eq!(
            config.bucket_name(),
            "xenia-ar-qual-123456789-0102030405060708"
        );
    }

    #[test]
    fn uppercase_hex_is_rejected_to_avoid_multiple_ack_encodings() {
        let mut vars = base("reversible", "0102030405060708", 60);
        vars.insert(
            "XENIA_GCS_LIVE_RUN_NONCE_HEX".to_string(),
            "01020304050607AB".to_string(),
        );
        assert_eq!(
            GcsLiveQualificationConfigV1::from_environment_map(&vars),
            Err(GcsLiveQualificationErrorV1::InvalidHex)
        );
    }
}
