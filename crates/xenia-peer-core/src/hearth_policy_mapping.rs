// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cross-repository compatibility contract for target-owned Hearth capability
//! mapping policy.
//!
//! This module deliberately does **not** evaluate Hearth state and does not
//! mint Xenia authority. It exists so Xenia can independently reproduce the
//! canonical HXB-2 mapping commitment emitted by Mycelix Hearth while reusing
//! Xenia's own [`DeviceCapabilityV1`] numeric taxonomy.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DeviceCapabilityV1, DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
    DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION,
};

/// HXB-2 mapping-policy schema version understood by this mirror.
pub const HEARTH_CAPABILITY_MAPPING_SCHEMA_VERSION: u16 = 1;

const POLICY_DOMAIN: &[u8] = b"hearth-xenia-capability-mapping-v1\0";
const MAX_MAPPING_ENTRIES: usize = 64;
const MAX_REQUIREMENTS_PER_ENTRY: usize = 16;
const MAX_CUSTOM_CAPABILITY_BYTES: usize = 128;

/// One Hearth Device Authority capability class required by target policy.
///
/// The first three variants mirror Hearth's coarse V1 semantic classes.
/// `Custom` is policy-owned and remains opaque to Xenia.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HearthCapabilityRequirementV1 {
    /// Read/observe class.
    Observe,
    /// Low-consequence actuation class.
    ActuateLow,
    /// High-consequence actuation class.
    ActuateHigh,
    /// Exact policy-specific Hearth capability class.
    Custom(String),
}

impl HearthCapabilityRequirementV1 {
    fn validate(&self) -> Result<(), HearthCapabilityMappingError> {
        if let Self::Custom(value) = self {
            if value.is_empty()
                || value.len() > MAX_CUSTOM_CAPABILITY_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(HearthCapabilityMappingError::InvalidCustomCapability);
            }
        }
        Ok(())
    }

    fn encode_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Observe => out.extend_from_slice(&1u16.to_be_bytes()),
            Self::ActuateLow => out.extend_from_slice(&2u16.to_be_bytes()),
            Self::ActuateHigh => out.extend_from_slice(&3u16.to_be_bytes()),
            Self::Custom(value) => {
                out.extend_from_slice(&u16::MAX.to_be_bytes());
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value.as_bytes());
            }
        }
    }
}

/// Explicit target-policy mapping for one exact Xenia V1 capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HearthCapabilityMappingEntryV1 {
    /// Exact Xenia capability from the local V1 enum.
    pub xenia_capability: DeviceCapabilityV1,
    /// Exact non-empty Hearth requirement set selected by target policy.
    pub required_hearth_capabilities: BTreeSet<HearthCapabilityRequirementV1>,
    /// Optional commitment to extra target-owned policy restrictions.
    pub additional_policy_commitment: Option<[u8; 32]>,
}

impl HearthCapabilityMappingEntryV1 {
    /// Construct and validate one mapping entry.
    pub fn new(
        xenia_capability: DeviceCapabilityV1,
        required_hearth_capabilities: impl IntoIterator<Item = HearthCapabilityRequirementV1>,
        additional_policy_commitment: Option<[u8; 32]>,
    ) -> Result<Self, HearthCapabilityMappingError> {
        let entry = Self {
            xenia_capability,
            required_hearth_capabilities: required_hearth_capabilities.into_iter().collect(),
            additional_policy_commitment,
        };
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> Result<(), HearthCapabilityMappingError> {
        if self.required_hearth_capabilities.is_empty() {
            return Err(HearthCapabilityMappingError::EmptyRequirementSet(
                self.xenia_capability as u16,
            ));
        }
        if self.required_hearth_capabilities.len() > MAX_REQUIREMENTS_PER_ENTRY {
            return Err(HearthCapabilityMappingError::TooManyRequirements(
                self.xenia_capability as u16,
            ));
        }
        for requirement in &self.required_hearth_capabilities {
            requirement.validate()?;
        }
        if self.additional_policy_commitment == Some([0; 32]) {
            return Err(HearthCapabilityMappingError::ZeroAdditionalPolicyCommitment(
                self.xenia_capability as u16,
            ));
        }
        Ok(())
    }
}

/// Serializable mirror of the Hearth HXB-2 mapping policy.
///
/// This object is compatibility/policy data only. Deserializing or validating
/// it never creates a Xenia capability grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HearthCapabilityMappingPolicyV1 {
    /// Exact HXB-2 mapping schema.
    pub schema_version: u16,
    /// Exact Xenia advertisement schema bound by the policy.
    pub xenia_advertisement_schema_version: u16,
    /// Exact Xenia request schema bound by the policy.
    pub xenia_request_schema_version: u16,
    /// Non-zero target-owned policy generation.
    pub policy_generation: u64,
    /// Explicit mappings. Canonical hashing sorts by Xenia numeric code.
    pub entries: Vec<HearthCapabilityMappingEntryV1>,
}

impl HearthCapabilityMappingPolicyV1 {
    /// Construct a V1 policy using Xenia's current local V1 schema constants.
    pub fn new(
        policy_generation: u64,
        entries: impl IntoIterator<Item = HearthCapabilityMappingEntryV1>,
    ) -> Result<Self, HearthCapabilityMappingError> {
        let policy = Self {
            schema_version: HEARTH_CAPABILITY_MAPPING_SCHEMA_VERSION,
            xenia_advertisement_schema_version:
                DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
            xenia_request_schema_version: DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION,
            policy_generation,
            entries: entries.into_iter().collect(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate structural and local-schema compatibility invariants.
    pub fn validate(&self) -> Result<(), HearthCapabilityMappingError> {
        if self.schema_version != HEARTH_CAPABILITY_MAPPING_SCHEMA_VERSION {
            return Err(HearthCapabilityMappingError::UnsupportedPolicySchema);
        }
        if self.xenia_advertisement_schema_version
            != DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION
        {
            return Err(HearthCapabilityMappingError::AdvertisementSchemaMismatch);
        }
        if self.xenia_request_schema_version != DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION {
            return Err(HearthCapabilityMappingError::RequestSchemaMismatch);
        }
        if self.policy_generation == 0 {
            return Err(HearthCapabilityMappingError::ZeroPolicyGeneration);
        }
        if self.entries.is_empty() {
            return Err(HearthCapabilityMappingError::EmptyPolicy);
        }
        if self.entries.len() > MAX_MAPPING_ENTRIES {
            return Err(HearthCapabilityMappingError::TooManyMappings);
        }

        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.xenia_capability) {
                return Err(HearthCapabilityMappingError::DuplicateMapping(
                    entry.xenia_capability as u16,
                ));
            }
        }
        Ok(())
    }

    /// Canonical domain-separated SHA-256 commitment compatible with Hearth
    /// HXB-2 V1.
    pub fn digest(&self) -> Result<[u8; 32], HearthCapabilityMappingError> {
        self.validate()?;

        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(POLICY_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.xenia_advertisement_schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.xenia_request_schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.policy_generation.to_be_bytes());

        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by_key(|entry| entry.xenia_capability as u16);
        bytes.extend_from_slice(&(entries.len() as u16).to_be_bytes());

        for entry in entries {
            bytes.extend_from_slice(&(entry.xenia_capability as u16).to_be_bytes());
            bytes.extend_from_slice(
                &(entry.required_hearth_capabilities.len() as u16).to_be_bytes(),
            );
            for requirement in &entry.required_hearth_capabilities {
                requirement.encode_canonical(&mut bytes);
            }
            match entry.additional_policy_commitment {
                None => bytes.push(0),
                Some(commitment) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&commitment);
                }
            }
        }

        Ok(Sha256::digest(bytes).into())
    }

    /// Resolve an exact requested subset into target-policy Hearth
    /// requirements.
    ///
    /// Success remains non-authoritative: this method does not query Hearth,
    /// verify grants, or bind a Xenia session generation.
    pub fn resolve_subset(
        &self,
        requested: &BTreeSet<DeviceCapabilityV1>,
    ) -> Result<ResolvedHearthRequirementsV1, HearthCapabilityMappingError> {
        self.validate()?;
        if requested.is_empty() {
            return Err(HearthCapabilityMappingError::EmptyRequestedSubset);
        }

        let mut required_hearth_capabilities = BTreeSet::new();
        let mut additional_policy_commitments = BTreeSet::new();
        for capability in requested {
            let mapping = self
                .entries
                .iter()
                .find(|entry| entry.xenia_capability == *capability)
                .ok_or(HearthCapabilityMappingError::UnmappedCapability(
                    *capability as u16,
                ))?;
            required_hearth_capabilities
                .extend(mapping.required_hearth_capabilities.iter().cloned());
            if let Some(commitment) = mapping.additional_policy_commitment {
                additional_policy_commitments.insert(commitment);
            }
        }

        Ok(ResolvedHearthRequirementsV1 {
            required_hearth_capabilities,
            additional_policy_commitments,
        })
    }
}

/// Exact requirements resolved for one Xenia requested subset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedHearthRequirementsV1 {
    /// Union of exact Hearth capability classes required by target policy.
    pub required_hearth_capabilities: BTreeSet<HearthCapabilityRequirementV1>,
    /// Exact extra-policy commitments that must be satisfied independently.
    pub additional_policy_commitments: BTreeSet<[u8; 32]>,
}

/// Structural/compatibility error for the non-authoritative mapping contract.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HearthCapabilityMappingError {
    /// Mapping schema is not HXB-2 V1.
    #[error("unsupported Hearth capability mapping schema")]
    UnsupportedPolicySchema,
    /// Policy names a different Xenia advertisement schema than this build.
    #[error("Hearth mapping advertisement schema does not match local Xenia schema")]
    AdvertisementSchemaMismatch,
    /// Policy names a different Xenia request schema than this build.
    #[error("Hearth mapping request schema does not match local Xenia schema")]
    RequestSchemaMismatch,
    /// Generation zero is reserved/invalid.
    #[error("Hearth mapping policy generation must be non-zero")]
    ZeroPolicyGeneration,
    /// A policy must map at least one capability.
    #[error("Hearth mapping policy must not be empty")]
    EmptyPolicy,
    /// V1 deliberately bounds the mapping size.
    #[error("too many Hearth capability mappings")]
    TooManyMappings,
    /// One Xenia capability may appear only once.
    #[error("duplicate Xenia capability mapping: {0}")]
    DuplicateMapping(u16),
    /// A mapped Xenia capability must require at least one Hearth class.
    #[error("Xenia capability mapping {0} has no Hearth requirements")]
    EmptyRequirementSet(u16),
    /// V1 deliberately bounds requirement-set size.
    #[error("Xenia capability mapping {0} has too many Hearth requirements")]
    TooManyRequirements(u16),
    /// Custom Hearth class is malformed or oversized.
    #[error("invalid custom Hearth capability requirement")]
    InvalidCustomCapability,
    /// All-zero policy commitment is reserved/invalid.
    #[error("Xenia capability mapping {0} has zero additional-policy commitment")]
    ZeroAdditionalPolicyCommitment(u16),
    /// Requested capability is not present in target policy.
    #[error("Xenia capability is not mapped by Hearth target policy: {0}")]
    UnmappedCapability(u16),
    /// Empty request subsets are invalid.
    #[error("requested capability subset must not be empty")]
    EmptyRequestedSubset,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        capability: DeviceCapabilityV1,
        requirements: impl IntoIterator<Item = HearthCapabilityRequirementV1>,
        additional: Option<[u8; 32]>,
    ) -> HearthCapabilityMappingEntryV1 {
        HearthCapabilityMappingEntryV1::new(capability, requirements, additional).unwrap()
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_hearth_cross_repository_vector_v1() {
        // Example policy only. The requirement choices are not universal
        // semantics for these Xenia capabilities.
        let policy = HearthCapabilityMappingPolicyV1::new(
            42,
            [
                entry(
                    DeviceCapabilityV1::PresentNotification,
                    [HearthCapabilityRequirementV1::ActuateLow],
                    None,
                ),
                entry(
                    DeviceCapabilityV1::CaptureCamera,
                    [HearthCapabilityRequirementV1::Custom(
                        "camera.observe.v1".into(),
                    )],
                    Some([0x11; 32]),
                ),
                entry(
                    DeviceCapabilityV1::BiometricApproval,
                    [HearthCapabilityRequirementV1::Custom(
                        "biometric.approve.v1".into(),
                    )],
                    None,
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            hex(policy.digest().unwrap()),
            "64cc86021c01bc0cdaf22992da45cf95e91e1d5a9af750d4cea67b6813a09251"
        );
    }

    #[test]
    fn vector_is_bound_to_xenias_own_v1_numeric_codes() {
        assert_eq!(DeviceCapabilityV1::PresentNotification as u16, 2);
        assert_eq!(DeviceCapabilityV1::CaptureCamera as u16, 10);
        assert_eq!(DeviceCapabilityV1::BiometricApproval as u16, 30);
    }

    #[test]
    fn digest_is_independent_of_entry_input_order() {
        let camera = entry(
            DeviceCapabilityV1::CaptureCamera,
            [HearthCapabilityRequirementV1::Observe],
            Some([0x44; 32]),
        );
        let approval = entry(
            DeviceCapabilityV1::BiometricApproval,
            [HearthCapabilityRequirementV1::ActuateHigh],
            None,
        );
        let a = HearthCapabilityMappingPolicyV1::new(7, [camera.clone(), approval.clone()])
            .unwrap();
        let b = HearthCapabilityMappingPolicyV1::new(7, [approval, camera]).unwrap();
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn local_schema_or_policy_substitution_changes_or_invalidates_subject() {
        let base = HearthCapabilityMappingPolicyV1::new(
            7,
            [entry(
                DeviceCapabilityV1::CaptureCamera,
                [HearthCapabilityRequirementV1::Observe],
                None,
            )],
        )
        .unwrap();
        let base_digest = base.digest().unwrap();

        let generation = HearthCapabilityMappingPolicyV1::new(
            8,
            [entry(
                DeviceCapabilityV1::CaptureCamera,
                [HearthCapabilityRequirementV1::Observe],
                None,
            )],
        )
        .unwrap();
        assert_ne!(base_digest, generation.digest().unwrap());

        let requirement = HearthCapabilityMappingPolicyV1::new(
            7,
            [entry(
                DeviceCapabilityV1::CaptureCamera,
                [HearthCapabilityRequirementV1::ActuateHigh],
                None,
            )],
        )
        .unwrap();
        assert_ne!(base_digest, requirement.digest().unwrap());

        let mut wrong_schema = base.clone();
        wrong_schema.xenia_request_schema_version += 1;
        assert_eq!(
            wrong_schema.digest(),
            Err(HearthCapabilityMappingError::RequestSchemaMismatch)
        );
    }

    #[test]
    fn subset_resolution_fails_closed_for_unmapped_capability() {
        let policy = HearthCapabilityMappingPolicyV1::new(
            1,
            [entry(
                DeviceCapabilityV1::CaptureCamera,
                [HearthCapabilityRequirementV1::Observe],
                None,
            )],
        )
        .unwrap();

        let requested = BTreeSet::from([DeviceCapabilityV1::ReadPreciseLocation]);
        assert_eq!(
            policy.resolve_subset(&requested),
            Err(HearthCapabilityMappingError::UnmappedCapability(21))
        );
    }

    #[test]
    fn validation_rejects_duplicate_empty_and_zero_commitment_mappings() {
        let camera = entry(
            DeviceCapabilityV1::CaptureCamera,
            [HearthCapabilityRequirementV1::Observe],
            None,
        );
        assert_eq!(
            HearthCapabilityMappingPolicyV1::new(1, [camera.clone(), camera]),
            Err(HearthCapabilityMappingError::DuplicateMapping(10))
        );
        assert_eq!(
            HearthCapabilityMappingEntryV1::new(
                DeviceCapabilityV1::CaptureCamera,
                [],
                None,
            ),
            Err(HearthCapabilityMappingError::EmptyRequirementSet(10))
        );
        assert_eq!(
            HearthCapabilityMappingEntryV1::new(
                DeviceCapabilityV1::CaptureCamera,
                [HearthCapabilityRequirementV1::Observe],
                Some([0; 32]),
            ),
            Err(HearthCapabilityMappingError::ZeroAdditionalPolicyCommitment(10))
        );
    }
}
