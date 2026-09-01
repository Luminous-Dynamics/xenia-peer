// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed activation-readiness contract for Xenia's live GCS qualification workflow.
//!
//! A serialized readiness manifest is evidence syntax, not authority. Activation requires a live
//! independently authenticated attestation over the exact manifest digest, and the verifier also
//! compares the manifest against the exact current main commit and inert workflow bytes being
//! promoted.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema identifier for the activation-readiness manifest.
pub const GCS_LIVE_ACTIVATION_SCHEMA_V1: &str = "xenia-gcs-live-activation-readiness-v1";
/// Repository ID frozen by ADR-037.
pub const XENIA_PEER_REPOSITORY_ID_V1: u64 = 1_214_159_052;
/// Repository owner ID frozen by ADR-037.
pub const XENIA_PEER_REPOSITORY_OWNER_ID_V1: u64 = 216_969_177;
/// Exact eventual active workflow path.
pub const GCS_LIVE_ACTIVE_WORKFLOW_PATH_V1: &str =
    ".github/workflows/operation-authority-retention-gcs-live-manual-v1.yml";
/// Exact inert workflow-contract path reviewed before activation.
pub const GCS_LIVE_INERT_WORKFLOW_PATH_V1: &str =
    ".github/workflow-contracts/operation-authority-retention-gcs-live-manual-v1.yml";
/// Maximum age of a manifest between observation and attempted activation.
pub const GCS_LIVE_ACTIVATION_MAX_MANIFEST_LIFETIME_MS_V1: u64 = 24 * 60 * 60 * 1_000;
/// Maximum lifetime of the independent live attestation used to activate.
pub const GCS_LIVE_ACTIVATION_MAX_ATTESTATION_LIFETIME_MS_V1: u64 = 15 * 60 * 1_000;

const MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"xenia-gcs-live-activation-manifest-v1";

/// Exact protected-environment names required by ADR-037.
pub const GCS_LIVE_REQUIRED_ENVIRONMENTS_V1: [&str; 4] = [
    "xenia-gcs-qual-admin-reversible",
    "xenia-gcs-qual-runtime",
    "xenia-gcs-qual-admin-lock",
    "xenia-gcs-qual-admin-cleanup",
];

/// One protected-environment policy and service-account binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsLiveEnvironmentBindingV1 {
    /// Exact GitHub environment name.
    pub environment_name: String,
    /// Commitment to the reviewed GitHub environment protection configuration.
    pub environment_policy_digest: [u8; 32],
    /// Commitment to the exact IAM member/service account authorized for this environment.
    pub service_account_member_digest: [u8; 32],
}

impl GcsLiveEnvironmentBindingV1 {
    fn validate(&self, expected_name: &str) -> Result<(), GcsLiveActivationErrorV1> {
        if self.environment_name != expected_name {
            return Err(GcsLiveActivationErrorV1::EnvironmentNameMismatch);
        }
        require_nonzero(self.environment_policy_digest, GcsLiveActivationErrorV1::ZeroEnvironmentPolicyDigest)?;
        require_nonzero(
            self.service_account_member_digest,
            GcsLiveActivationErrorV1::ZeroServiceAccountDigest,
        )?;
        Ok(())
    }
}

/// Exact external control-plane observations required before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsLiveActivationManifestV1 {
    /// Exact schema identifier.
    pub schema: String,
    /// Authority domain whose qualification lineage is being activated.
    pub authority_domain_id: [u8; 32],
    /// Frozen immutable GitHub repository ID.
    pub repository_id: u64,
    /// Frozen immutable GitHub owner ID.
    pub repository_owner_id: u64,
    /// Exact main-branch commit reviewed for activation (20 raw Git SHA-1 bytes).
    pub reviewed_main_sha: [u8; 20],
    /// SHA-256 of the exact inert workflow bytes to be promoted unchanged.
    pub inert_workflow_sha256: [u8; 32],
    /// Exact active workflow destination path.
    pub active_workflow_path: String,
    /// Qualification-evidence digest for the authority-gated GCS bridge (ADR-034/#217).
    pub bridge_qualification_evidence_digest: [u8; 32],
    /// Qualification-evidence digest for the disposable safety contract (ADR-035/#218).
    pub safety_qualification_evidence_digest: [u8; 32],
    /// Qualification-evidence digest for the destructive harness compiled on committed bytes.
    pub harness_qualification_evidence_digest: [u8; 32],
    /// Qualification-evidence digest for the inert workflow/WIF contract (ADR-037).
    pub workflow_contract_evidence_digest: [u8; 32],
    /// Canonical digest of the qualified ADR-030 GCS provider profile.
    pub gcs_profile_digest: [u8; 32],
    /// Commitment to the exact Google WIF provider resource name/configuration.
    pub wif_provider_digest: [u8; 32],
    /// Commitment to the exact WIF attribute mapping + attribute condition.
    pub wif_condition_digest: [u8; 32],
    /// Reversible-admin GitHub environment binding.
    pub admin_reversible: GcsLiveEnvironmentBindingV1,
    /// Runtime GitHub environment binding.
    pub runtime: GcsLiveEnvironmentBindingV1,
    /// Irreversible-lock GitHub environment binding.
    pub admin_lock: GcsLiveEnvironmentBindingV1,
    /// Cleanup GitHub environment binding.
    pub admin_cleanup: GcsLiveEnvironmentBindingV1,
    /// Fresh activation-attempt nonce.
    pub activation_nonce: [u8; 16],
    /// Time at which the external configuration/evidence was observed.
    pub observed_at_unix_ms: u64,
    /// Hard application deadline for this manifest.
    pub expires_at_unix_ms: u64,
}

impl GcsLiveActivationManifestV1 {
    /// Validate the manifest's complete local shape and frozen invariants.
    pub fn validate(&self) -> Result<(), GcsLiveActivationErrorV1> {
        if self.schema != GCS_LIVE_ACTIVATION_SCHEMA_V1 {
            return Err(GcsLiveActivationErrorV1::SchemaMismatch);
        }
        require_nonzero(self.authority_domain_id, GcsLiveActivationErrorV1::ZeroAuthorityDomain)?;
        if self.repository_id != XENIA_PEER_REPOSITORY_ID_V1
            || self.repository_owner_id != XENIA_PEER_REPOSITORY_OWNER_ID_V1
        {
            return Err(GcsLiveActivationErrorV1::RepositoryIdentityMismatch);
        }
        if self.reviewed_main_sha == [0u8; 20] {
            return Err(GcsLiveActivationErrorV1::ZeroMainSha);
        }
        require_nonzero(self.inert_workflow_sha256, GcsLiveActivationErrorV1::ZeroWorkflowDigest)?;
        if self.active_workflow_path != GCS_LIVE_ACTIVE_WORKFLOW_PATH_V1 {
            return Err(GcsLiveActivationErrorV1::ActiveWorkflowPathMismatch);
        }
        for digest in [
            self.bridge_qualification_evidence_digest,
            self.safety_qualification_evidence_digest,
            self.harness_qualification_evidence_digest,
            self.workflow_contract_evidence_digest,
        ] {
            require_nonzero(digest, GcsLiveActivationErrorV1::ZeroQualificationEvidenceDigest)?;
        }
        require_nonzero(self.gcs_profile_digest, GcsLiveActivationErrorV1::ZeroGcsProfileDigest)?;
        require_nonzero(self.wif_provider_digest, GcsLiveActivationErrorV1::ZeroWifProviderDigest)?;
        require_nonzero(self.wif_condition_digest, GcsLiveActivationErrorV1::ZeroWifConditionDigest)?;
        self.admin_reversible.validate(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[0])?;
        self.runtime.validate(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[1])?;
        self.admin_lock.validate(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[2])?;
        self.admin_cleanup.validate(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[3])?;

        let runtime = self.runtime.service_account_member_digest;
        if runtime == self.admin_reversible.service_account_member_digest
            || runtime == self.admin_lock.service_account_member_digest
            || runtime == self.admin_cleanup.service_account_member_digest
        {
            return Err(GcsLiveActivationErrorV1::RuntimeAdminIdentityCollision);
        }
        if self.activation_nonce == [0u8; 16] {
            return Err(GcsLiveActivationErrorV1::ZeroActivationNonce);
        }
        if self.observed_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.observed_at_unix_ms
            || self.expires_at_unix_ms - self.observed_at_unix_ms
                > GCS_LIVE_ACTIVATION_MAX_MANIFEST_LIFETIME_MS_V1
        {
            return Err(GcsLiveActivationErrorV1::InvalidManifestLifetime);
        }
        Ok(())
    }

    /// Deterministic domain-separated commitment to the complete manifest.
    pub fn manifest_digest(&self) -> Result<[u8; 32], GcsLiveActivationErrorV1> {
        self.validate()?;
        let bytes = bincode::serialize(self).map_err(GcsLiveActivationErrorV1::Serialization)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MANIFEST_DIGEST_DOMAIN_V1);
        hasher.update(&[0]);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Result returned by an independently administered activation-readiness trust source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcsLiveActivationAuthenticationV1 {
    /// The exact manifest digest was independently authenticated for a bounded live window.
    Authenticated {
        /// Identity/authority commitment of the system that authenticated readiness.
        authority_id_digest: [u8; 32],
        /// Exact manifest digest authenticated by the source.
        manifest_digest: [u8; 32],
        /// Time at which the source observed/approved the readiness state.
        authenticated_at_unix_ms: u64,
        /// Hard expiry of this live authentication result.
        valid_until_unix_ms: u64,
    },
    /// The source definitively rejects activation readiness.
    Rejected,
    /// The source cannot establish whether readiness is valid.
    Unknown,
}

/// External authority boundary for activation readiness.
///
/// Implementations used for the security profile must live outside the protected machine's
/// rollback/configuration domain. A trait implementation that simply trusts the manifest is not a
/// conforming authority source.
pub trait GcsLiveActivationTrustSourceV1 {
    /// Authenticate the exact manifest digest at the current application time.
    fn authenticate_readiness(
        &self,
        authority_domain_id: [u8; 32],
        manifest_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> GcsLiveActivationAuthenticationV1;
}

/// Non-serializable result proving the live readiness gate ran successfully.
#[derive(Debug)]
pub struct VerifiedGcsLiveActivationReadinessV1 {
    manifest_digest: [u8; 32],
    authority_id_digest: [u8; 32],
    reviewed_main_sha: [u8; 20],
    inert_workflow_sha256: [u8; 32],
}

impl VerifiedGcsLiveActivationReadinessV1 {
    /// Exact manifest digest authenticated by the external source.
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Exact external authority identity commitment.
    pub const fn authority_id_digest(&self) -> [u8; 32] {
        self.authority_id_digest
    }

    /// Exact reviewed main commit this readiness result applies to.
    pub const fn reviewed_main_sha(&self) -> [u8; 20] {
        self.reviewed_main_sha
    }

    /// Exact inert workflow bytes this readiness result applies to.
    pub const fn inert_workflow_sha256(&self) -> [u8; 32] {
        self.inert_workflow_sha256
    }
}

/// Verify the complete activation-readiness boundary.
///
/// `actual_main_sha` and `actual_inert_workflow_sha256` must be independently measured from the
/// checkout being proposed for activation; the serialized manifest cannot supply those observations
/// to itself.
pub fn verify_gcs_live_activation_readiness_v1<S: GcsLiveActivationTrustSourceV1>(
    manifest: &GcsLiveActivationManifestV1,
    actual_main_sha: [u8; 20],
    actual_inert_workflow_sha256: [u8; 32],
    active_workflow_present: bool,
    now_unix_ms: u64,
    trust_source: &S,
) -> Result<VerifiedGcsLiveActivationReadinessV1, GcsLiveActivationErrorV1> {
    manifest.validate()?;
    if active_workflow_present {
        return Err(GcsLiveActivationErrorV1::ActiveWorkflowAlreadyPresent);
    }
    if actual_main_sha != manifest.reviewed_main_sha {
        return Err(GcsLiveActivationErrorV1::ObservedMainShaMismatch);
    }
    if actual_inert_workflow_sha256 != manifest.inert_workflow_sha256 {
        return Err(GcsLiveActivationErrorV1::ObservedWorkflowDigestMismatch);
    }
    if now_unix_ms < manifest.observed_at_unix_ms || now_unix_ms > manifest.expires_at_unix_ms {
        return Err(GcsLiveActivationErrorV1::ManifestNotLive);
    }

    let manifest_digest = manifest.manifest_digest()?;
    let auth = trust_source.authenticate_readiness(
        manifest.authority_domain_id,
        manifest_digest,
        now_unix_ms,
    );
    let GcsLiveActivationAuthenticationV1::Authenticated {
        authority_id_digest,
        manifest_digest: authenticated_digest,
        authenticated_at_unix_ms,
        valid_until_unix_ms,
    } = auth
    else {
        return Err(match auth {
            GcsLiveActivationAuthenticationV1::Rejected => {
                GcsLiveActivationErrorV1::ReadinessRejected
            }
            GcsLiveActivationAuthenticationV1::Unknown => {
                GcsLiveActivationErrorV1::ReadinessUnknown
            }
            GcsLiveActivationAuthenticationV1::Authenticated { .. } => unreachable!(),
        });
    };

    require_nonzero(authority_id_digest, GcsLiveActivationErrorV1::ZeroAttestingAuthority)?;
    if authenticated_digest != manifest_digest {
        return Err(GcsLiveActivationErrorV1::AuthenticatedManifestDigestMismatch);
    }
    if authenticated_at_unix_ms < manifest.observed_at_unix_ms
        || authenticated_at_unix_ms > now_unix_ms
        || valid_until_unix_ms < now_unix_ms
        || valid_until_unix_ms <= authenticated_at_unix_ms
        || valid_until_unix_ms - authenticated_at_unix_ms
            > GCS_LIVE_ACTIVATION_MAX_ATTESTATION_LIFETIME_MS_V1
    {
        return Err(GcsLiveActivationErrorV1::InvalidAuthenticationLifetime);
    }

    Ok(VerifiedGcsLiveActivationReadinessV1 {
        manifest_digest,
        authority_id_digest,
        reviewed_main_sha: manifest.reviewed_main_sha,
        inert_workflow_sha256: manifest.inert_workflow_sha256,
    })
}

fn require_nonzero(
    value: [u8; 32],
    error: GcsLiveActivationErrorV1,
) -> Result<(), GcsLiveActivationErrorV1> {
    if value == [0u8; 32] {
        return Err(error);
    }
    Ok(())
}

/// Activation-readiness validation failures.
#[derive(Debug, Error)]
pub enum GcsLiveActivationErrorV1 {
    /// Manifest schema changed or is unknown.
    #[error("GCS live activation manifest schema mismatch")]
    SchemaMismatch,
    /// Authority domain was not set.
    #[error("GCS live activation authority domain must be non-zero")]
    ZeroAuthorityDomain,
    /// Repository or owner immutable ID differs from ADR-037.
    #[error("GCS live activation repository identity mismatch")]
    RepositoryIdentityMismatch,
    /// Main commit is unset.
    #[error("GCS live activation reviewed main SHA must be non-zero")]
    ZeroMainSha,
    /// Inert workflow commitment is unset.
    #[error("GCS live activation workflow digest must be non-zero")]
    ZeroWorkflowDigest,
    /// Active workflow path is not the ADR-037 path.
    #[error("GCS live activation workflow destination mismatch")]
    ActiveWorkflowPathMismatch,
    /// A prerequisite qualification-evidence commitment is unset.
    #[error("GCS live activation qualification evidence digest must be non-zero")]
    ZeroQualificationEvidenceDigest,
    /// Provider profile commitment is unset.
    #[error("GCS live activation GCS profile digest must be non-zero")]
    ZeroGcsProfileDigest,
    /// WIF provider commitment is unset.
    #[error("GCS live activation WIF provider digest must be non-zero")]
    ZeroWifProviderDigest,
    /// WIF mapping/condition commitment is unset.
    #[error("GCS live activation WIF condition digest must be non-zero")]
    ZeroWifConditionDigest,
    /// A protected-environment name is not the frozen ADR-037 name.
    #[error("GCS live activation protected environment name mismatch")]
    EnvironmentNameMismatch,
    /// Environment policy commitment is unset.
    #[error("GCS live activation environment policy digest must be non-zero")]
    ZeroEnvironmentPolicyDigest,
    /// Service-account/member identity commitment is unset.
    #[error("GCS live activation service-account digest must be non-zero")]
    ZeroServiceAccountDigest,
    /// Runtime identity must remain distinct from administration.
    #[error("GCS live activation runtime/admin identity collision")]
    RuntimeAdminIdentityCollision,
    /// Activation nonce is unset.
    #[error("GCS live activation nonce must be non-zero")]
    ZeroActivationNonce,
    /// Manifest lifetime is malformed or exceeds the V1 maximum.
    #[error("GCS live activation manifest lifetime is invalid")]
    InvalidManifestLifetime,
    /// The active workflow appeared before the readiness ceremony completed.
    #[error("GCS live activation workflow is already active")]
    ActiveWorkflowAlreadyPresent,
    /// Current checkout is not the reviewed main commit.
    #[error("GCS live activation observed main SHA mismatch")]
    ObservedMainShaMismatch,
    /// Current inert workflow bytes are not the reviewed bytes.
    #[error("GCS live activation observed inert workflow digest mismatch")]
    ObservedWorkflowDigestMismatch,
    /// Manifest is not currently live.
    #[error("GCS live activation manifest is stale or not yet live")]
    ManifestNotLive,
    /// External trust source definitively rejected readiness.
    #[error("GCS live activation readiness rejected by independent authority")]
    ReadinessRejected,
    /// External trust source could not establish readiness.
    #[error("GCS live activation readiness is unknown")]
    ReadinessUnknown,
    /// External authority identity was unset.
    #[error("GCS live activation attesting authority must be non-zero")]
    ZeroAttestingAuthority,
    /// External source authenticated a different manifest.
    #[error("GCS live activation authenticated manifest digest mismatch")]
    AuthenticatedManifestDigestMismatch,
    /// External authentication timing is stale, future-dated, or too long-lived.
    #[error("GCS live activation authentication lifetime is invalid")]
    InvalidAuthenticationLifetime,
    /// Canonical manifest serialization failed.
    #[error("GCS live activation serialization failed: {0}")]
    Serialization(#[source] Box<bincode::ErrorKind>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Trust {
        result: GcsLiveActivationAuthenticationV1,
    }

    impl GcsLiveActivationTrustSourceV1 for Trust {
        fn authenticate_readiness(
            &self,
            _authority_domain_id: [u8; 32],
            _manifest_digest: [u8; 32],
            _now_unix_ms: u64,
        ) -> GcsLiveActivationAuthenticationV1 {
            self.result.clone()
        }
    }

    fn binding(name: &str, policy: u8, sa: u8) -> GcsLiveEnvironmentBindingV1 {
        GcsLiveEnvironmentBindingV1 {
            environment_name: name.to_string(),
            environment_policy_digest: [policy; 32],
            service_account_member_digest: [sa; 32],
        }
    }

    fn manifest() -> GcsLiveActivationManifestV1 {
        GcsLiveActivationManifestV1 {
            schema: GCS_LIVE_ACTIVATION_SCHEMA_V1.to_string(),
            authority_domain_id: [1; 32],
            repository_id: XENIA_PEER_REPOSITORY_ID_V1,
            repository_owner_id: XENIA_PEER_REPOSITORY_OWNER_ID_V1,
            reviewed_main_sha: [2; 20],
            inert_workflow_sha256: [3; 32],
            active_workflow_path: GCS_LIVE_ACTIVE_WORKFLOW_PATH_V1.to_string(),
            bridge_qualification_evidence_digest: [4; 32],
            safety_qualification_evidence_digest: [5; 32],
            harness_qualification_evidence_digest: [6; 32],
            workflow_contract_evidence_digest: [7; 32],
            gcs_profile_digest: [8; 32],
            wif_provider_digest: [9; 32],
            wif_condition_digest: [10; 32],
            admin_reversible: binding(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[0], 11, 21),
            runtime: binding(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[1], 12, 22),
            admin_lock: binding(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[2], 13, 21),
            admin_cleanup: binding(GCS_LIVE_REQUIRED_ENVIRONMENTS_V1[3], 14, 21),
            activation_nonce: [15; 16],
            observed_at_unix_ms: 1_000_000,
            expires_at_unix_ms: 1_000_000 + 60_000,
        }
    }

    fn trusted(m: &GcsLiveActivationManifestV1, now: u64) -> Trust {
        Trust {
            result: GcsLiveActivationAuthenticationV1::Authenticated {
                authority_id_digest: [31; 32],
                manifest_digest: m.manifest_digest().unwrap(),
                authenticated_at_unix_ms: now - 1,
                valid_until_unix_ms: now + 30_000,
            },
        }
    }

    #[test]
    fn valid_live_readiness_requires_external_attestation() {
        let m = manifest();
        let now = 1_010_000;
        let verified = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            false,
            now,
            &trusted(&m, now),
        )
        .unwrap();
        assert_eq!(verified.manifest_digest(), m.manifest_digest().unwrap());
        assert_eq!(verified.authority_id_digest(), [31; 32]);
    }

    #[test]
    fn serialized_manifest_cannot_authenticate_itself() {
        let m = manifest();
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            false,
            1_010_000,
            &Trust {
                result: GcsLiveActivationAuthenticationV1::Unknown,
            },
        )
        .unwrap_err();
        assert!(matches!(error, GcsLiveActivationErrorV1::ReadinessUnknown));
    }

    #[test]
    fn changed_workflow_bytes_fail_before_trust_source_result_can_help() {
        let m = manifest();
        let now = 1_010_000;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            [99; 32],
            false,
            now,
            &trusted(&m, now),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GcsLiveActivationErrorV1::ObservedWorkflowDigestMismatch
        ));
    }

    #[test]
    fn changed_main_commit_fails() {
        let m = manifest();
        let now = 1_010_000;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            [99; 20],
            m.inert_workflow_sha256,
            false,
            now,
            &trusted(&m, now),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GcsLiveActivationErrorV1::ObservedMainShaMismatch
        ));
    }

    #[test]
    fn active_workflow_must_not_preexist_readiness_ceremony() {
        let m = manifest();
        let now = 1_010_000;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            true,
            now,
            &trusted(&m, now),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GcsLiveActivationErrorV1::ActiveWorkflowAlreadyPresent
        ));
    }

    #[test]
    fn runtime_cannot_share_admin_service_account_identity() {
        let mut m = manifest();
        m.runtime.service_account_member_digest = m.admin_reversible.service_account_member_digest;
        assert!(matches!(
            m.validate(),
            Err(GcsLiveActivationErrorV1::RuntimeAdminIdentityCollision)
        ));
    }

    #[test]
    fn stale_manifest_fails_even_with_matching_attestation() {
        let m = manifest();
        let now = m.expires_at_unix_ms + 1;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            false,
            now,
            &trusted(&m, now),
        )
        .unwrap_err();
        assert!(matches!(error, GcsLiveActivationErrorV1::ManifestNotLive));
    }

    #[test]
    fn attestation_for_different_manifest_fails() {
        let m = manifest();
        let now = 1_010_000;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            false,
            now,
            &Trust {
                result: GcsLiveActivationAuthenticationV1::Authenticated {
                    authority_id_digest: [31; 32],
                    manifest_digest: [88; 32],
                    authenticated_at_unix_ms: now - 1,
                    valid_until_unix_ms: now + 1_000,
                },
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GcsLiveActivationErrorV1::AuthenticatedManifestDigestMismatch
        ));
    }

    #[test]
    fn excessively_long_live_attestation_fails() {
        let m = manifest();
        let now = 1_010_000;
        let error = verify_gcs_live_activation_readiness_v1(
            &m,
            m.reviewed_main_sha,
            m.inert_workflow_sha256,
            false,
            now,
            &Trust {
                result: GcsLiveActivationAuthenticationV1::Authenticated {
                    authority_id_digest: [31; 32],
                    manifest_digest: m.manifest_digest().unwrap(),
                    authenticated_at_unix_ms: now,
                    valid_until_unix_ms: now + GCS_LIVE_ACTIVATION_MAX_ATTESTATION_LIFETIME_MS_V1 + 1,
                },
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GcsLiveActivationErrorV1::InvalidAuthenticationLifetime
        ));
    }
}
