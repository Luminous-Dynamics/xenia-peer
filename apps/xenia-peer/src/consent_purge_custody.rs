// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent custody assertions for purge rollback evidence.
//!
//! A custody signature is an attestation by one configured key that one exact
//! retention obligation has an independently identified replica. It is not a
//! proof of hardware class, geographic separation, or continued availability.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consent_purge_retention::ConsentPurgeRetentionSubjectV1;
use serde_big_array::BigArray;

pub(crate) const CONSENT_PURGE_CUSTODY_ATTESTATION_SCHEMA: &str =
    "xenia-consent-purge-custody-attestation-v1";
pub(crate) const CONSENT_PURGE_CUSTODY_BUNDLE_SCHEMA: &str =
    "xenia-consent-purge-custody-bundle-v1";
pub(crate) const MAX_PURGE_CUSTODY_ATTESTATIONS: usize = 64;
pub(crate) const MAX_PURGE_CUSTODY_LOCATOR_BYTES: usize = 1024;
pub(crate) const MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentPurgeCustodyClassV1 {
    OfflineMedia,
    RemoteVault,
    HardwareProtected,
}

/// One custodian's signed assertion about one exact protected inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeCustodyAttestationV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) obligation_fingerprint: [u8; 32],
    pub(crate) retention_anchor_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) custody_class: ConsentPurgeCustodyClassV1,
    pub(crate) custody_locator_digest: [u8; 32],
    pub(crate) replica_id: [u8; 16],
    pub(crate) observed_at_unix_secs: u64,
    pub(crate) available_until_unix_secs: u64,
    pub(crate) custodian_public_key: [u8; 32],
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeCustodyBundleV1 {
    pub(crate) schema: String,
    pub(crate) obligation_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) attestations: Vec<ConsentPurgeCustodyAttestationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentPurgeCustodyError {
    #[error("consent purge custody attestation has unsupported schema: {schema}")]
    UnsupportedAttestationSchema { schema: String },
    #[error("consent purge custody bundle has unsupported schema: {schema}")]
    UnsupportedBundleSchema { schema: String },
    #[error("consent purge custody locator must be non-empty and at most {maximum} bytes")]
    InvalidLocator { maximum: usize },
    #[error("consent purge custody locator contains control characters")]
    LocatorContainsControl,
    #[error("consent purge custody replica id cannot be all zeroes")]
    ZeroReplicaId,
    #[error("consent purge custody attestation identity does not match the retention subject")]
    SubjectMismatch,
    #[error("consent purge custody attestation is not valid through the retention deadline")]
    AvailabilityTooShort,
    #[error("consent purge custody observation is outside its availability window")]
    InvalidAvailabilityWindow,
    #[error("consent purge custody assertion is no longer available at verification time")]
    AvailabilityExpired,
    #[error("consent purge custody observation timestamp is too far in the future")]
    ObservationFromFuture,
    #[error("consent purge custody public key is malformed")]
    BadCustodianPublicKey,
    #[error("consent purge custody signature is invalid")]
    InvalidCustodySignature,
    #[error("consent purge custody bundle refers to another retention obligation")]
    BundleSubjectMismatch,
    #[error("consent purge custody key appears more than once")]
    DuplicateCustodianKey,
    #[error("consent purge custody attestations are not in canonical key order")]
    AttestationOrderMismatch,
    #[error("consent purge custody replica id appears more than once")]
    DuplicateReplicaId,
    #[error("consent purge custody key is not trusted")]
    UntrustedCustodianKey,
    #[error("consent purge custody quorum cannot be zero")]
    ZeroCustodyQuorum,
    #[error("consent purge custody quorum was not met: observed={observed}, required={required}")]
    CustodyQuorumNotMet { observed: usize, required: usize },
    #[error("consent purge custody bundle exceeds {maximum} attestations: {count}")]
    TooManyAttestations { count: usize, maximum: usize },
    #[error("consent purge custody encoding length overflow")]
    EncodingLengthOverflow,
}

impl ConsentPurgeCustodyAttestationV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        subject: &ConsentPurgeRetentionSubjectV1,
        custody_class: ConsentPurgeCustodyClassV1,
        custody_locator: &str,
        replica_id: [u8; 16],
        signing_key: &SigningKey,
        observed_at_unix_secs: u64,
        available_until_unix_secs: u64,
    ) -> Result<Self, ConsentPurgeCustodyError> {
        let locator_digest = custody_locator_digest(custody_locator)?;
        if replica_id == [0u8; 16] {
            return Err(ConsentPurgeCustodyError::ZeroReplicaId);
        }
        if observed_at_unix_secs >= available_until_unix_secs {
            return Err(ConsentPurgeCustodyError::InvalidAvailabilityWindow);
        }
        if available_until_unix_secs < subject.retain_until_unix_secs {
            return Err(ConsentPurgeCustodyError::AvailabilityTooShort);
        }
        let mut attestation = Self {
            schema: CONSENT_PURGE_CUSTODY_ATTESTATION_SCHEMA.to_string(),
            ledger_epoch_id: subject.ledger_epoch_id,
            obligation_fingerprint: subject.obligation_fingerprint,
            retention_anchor_fingerprint: subject.anchor_fingerprint,
            protected_inventory_digest: subject.protected_inventory_digest,
            package_directory: subject.package_directory.clone(),
            custody_class,
            custody_locator_digest: locator_digest,
            replica_id,
            observed_at_unix_secs,
            available_until_unix_secs,
            custodian_public_key: signing_key.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        attestation.signature = signing_key
            .sign(&consent_purge_custody_attestation_message(&attestation)?)
            .to_bytes();
        attestation.verify(
            subject,
            observed_at_unix_secs,
            MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
        )?;
        Ok(attestation)
    }

    pub(crate) fn verify(
        &self,
        subject: &ConsentPurgeRetentionSubjectV1,
        now_unix_secs: u64,
        maximum_future_skew_secs: u64,
    ) -> Result<(), ConsentPurgeCustodyError> {
        self.validate_shape()?;
        if self.ledger_epoch_id != subject.ledger_epoch_id
            || self.obligation_fingerprint != subject.obligation_fingerprint
            || self.retention_anchor_fingerprint != subject.anchor_fingerprint
            || self.protected_inventory_digest != subject.protected_inventory_digest
            || self.package_directory != subject.package_directory
        {
            return Err(ConsentPurgeCustodyError::SubjectMismatch);
        }
        if self.available_until_unix_secs < subject.retain_until_unix_secs {
            return Err(ConsentPurgeCustodyError::AvailabilityTooShort);
        }
        if self.observed_at_unix_secs > now_unix_secs.saturating_add(maximum_future_skew_secs) {
            return Err(ConsentPurgeCustodyError::ObservationFromFuture);
        }
        if now_unix_secs > self.available_until_unix_secs {
            return Err(ConsentPurgeCustodyError::AvailabilityExpired);
        }
        let public_key = VerifyingKey::from_bytes(&self.custodian_public_key)
            .map_err(|_| ConsentPurgeCustodyError::BadCustodianPublicKey)?;
        public_key
            .verify(
                &consent_purge_custody_attestation_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeCustodyError::InvalidCustodySignature)
    }

    fn validate_shape(&self) -> Result<(), ConsentPurgeCustodyError> {
        if self.schema != CONSENT_PURGE_CUSTODY_ATTESTATION_SCHEMA {
            return Err(ConsentPurgeCustodyError::UnsupportedAttestationSchema {
                schema: self.schema.clone(),
            });
        }
        if self.custody_locator_digest == [0u8; 32] {
            return Err(ConsentPurgeCustodyError::InvalidLocator {
                maximum: MAX_PURGE_CUSTODY_LOCATOR_BYTES,
            });
        }
        if self.replica_id == [0u8; 16] {
            return Err(ConsentPurgeCustodyError::ZeroReplicaId);
        }
        if self.observed_at_unix_secs >= self.available_until_unix_secs {
            return Err(ConsentPurgeCustodyError::InvalidAvailabilityWindow);
        }
        Ok(())
    }
}

impl ConsentPurgeCustodyBundleV1 {
    pub(crate) fn new(subject: &ConsentPurgeRetentionSubjectV1) -> Self {
        Self {
            schema: CONSENT_PURGE_CUSTODY_BUNDLE_SCHEMA.to_string(),
            obligation_fingerprint: subject.obligation_fingerprint,
            protected_inventory_digest: subject.protected_inventory_digest,
            attestations: Vec::new(),
        }
    }

    pub(crate) fn add(
        &mut self,
        subject: &ConsentPurgeRetentionSubjectV1,
        attestation: ConsentPurgeCustodyAttestationV1,
    ) -> Result<(), ConsentPurgeCustodyError> {
        self.validate_subject(subject)?;
        if self.attestations.len() >= MAX_PURGE_CUSTODY_ATTESTATIONS {
            return Err(ConsentPurgeCustodyError::TooManyAttestations {
                count: self.attestations.len() + 1,
                maximum: MAX_PURGE_CUSTODY_ATTESTATIONS,
            });
        }
        if self
            .attestations
            .iter()
            .any(|existing| existing.custodian_public_key == attestation.custodian_public_key)
        {
            return Err(ConsentPurgeCustodyError::DuplicateCustodianKey);
        }
        if self
            .attestations
            .iter()
            .any(|existing| existing.replica_id == attestation.replica_id)
        {
            return Err(ConsentPurgeCustodyError::DuplicateReplicaId);
        }
        self.attestations.push(attestation);
        self.attestations
            .sort_by_key(|entry| entry.custodian_public_key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_quorum(
        &self,
        subject: &ConsentPurgeRetentionSubjectV1,
        trusted_custodian_keys: &[[u8; 32]],
        minimum_quorum: usize,
        now_unix_secs: u64,
        maximum_future_skew_secs: u64,
        required_available_until_unix_secs: u64,
    ) -> Result<(), ConsentPurgeCustodyError> {
        self.validate_subject(subject)?;
        if minimum_quorum == 0 {
            return Err(ConsentPurgeCustodyError::ZeroCustodyQuorum);
        }
        if self.attestations.len() > MAX_PURGE_CUSTODY_ATTESTATIONS {
            return Err(ConsentPurgeCustodyError::TooManyAttestations {
                count: self.attestations.len(),
                maximum: MAX_PURGE_CUSTODY_ATTESTATIONS,
            });
        }
        let trusted = trusted_custodian_keys
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut keys = BTreeSet::new();
        let mut replicas = BTreeSet::new();
        let mut previous_key: Option<[u8; 32]> = None;
        let mut observed = 0usize;
        for attestation in &self.attestations {
            if previous_key.is_some_and(|previous| previous >= attestation.custodian_public_key) {
                return Err(ConsentPurgeCustodyError::AttestationOrderMismatch);
            }
            previous_key = Some(attestation.custodian_public_key);
            if !keys.insert(attestation.custodian_public_key) {
                return Err(ConsentPurgeCustodyError::DuplicateCustodianKey);
            }
            if !replicas.insert(attestation.replica_id) {
                return Err(ConsentPurgeCustodyError::DuplicateReplicaId);
            }
            if !trusted.contains(&attestation.custodian_public_key) {
                return Err(ConsentPurgeCustodyError::UntrustedCustodianKey);
            }
            attestation.verify(subject, now_unix_secs, maximum_future_skew_secs)?;
            if attestation.available_until_unix_secs < required_available_until_unix_secs {
                return Err(ConsentPurgeCustodyError::AvailabilityTooShort);
            }
            observed += 1;
        }
        if observed < minimum_quorum {
            return Err(ConsentPurgeCustodyError::CustodyQuorumNotMet {
                observed,
                required: minimum_quorum,
            });
        }
        Ok(())
    }

    fn validate_subject(
        &self,
        subject: &ConsentPurgeRetentionSubjectV1,
    ) -> Result<(), ConsentPurgeCustodyError> {
        if self.schema != CONSENT_PURGE_CUSTODY_BUNDLE_SCHEMA {
            return Err(ConsentPurgeCustodyError::UnsupportedBundleSchema {
                schema: self.schema.clone(),
            });
        }
        if self.obligation_fingerprint != subject.obligation_fingerprint
            || self.protected_inventory_digest != subject.protected_inventory_digest
        {
            return Err(ConsentPurgeCustodyError::BundleSubjectMismatch);
        }
        Ok(())
    }
}

pub(crate) fn consent_purge_custody_bundle_fingerprint(
    bundle: &ConsentPurgeCustodyBundleV1,
) -> Result<[u8; 32], ConsentPurgeCustodyError> {
    if bundle.schema != CONSENT_PURGE_CUSTODY_BUNDLE_SCHEMA {
        return Err(ConsentPurgeCustodyError::UnsupportedBundleSchema {
            schema: bundle.schema.clone(),
        });
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-custody-bundle-fingerprint:v1");
    hasher.update(&bundle.obligation_fingerprint);
    hasher.update(&bundle.protected_inventory_digest);
    let count = u32::try_from(bundle.attestations.len())
        .map_err(|_| ConsentPurgeCustodyError::EncodingLengthOverflow)?;
    hasher.update(&count.to_be_bytes());
    for attestation in &bundle.attestations {
        hasher.update(&consent_purge_custody_attestation_fingerprint(attestation)?);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn consent_purge_custody_attestation_fingerprint(
    attestation: &ConsentPurgeCustodyAttestationV1,
) -> Result<[u8; 32], ConsentPurgeCustodyError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-custody-attestation-fingerprint:v1");
    hasher.update(&consent_purge_custody_attestation_message(attestation)?);
    hasher.update(&attestation.signature);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn custody_locator_digest(
    custody_locator: &str,
) -> Result<[u8; 32], ConsentPurgeCustodyError> {
    if custody_locator.is_empty() || custody_locator.len() > MAX_PURGE_CUSTODY_LOCATOR_BYTES {
        return Err(ConsentPurgeCustodyError::InvalidLocator {
            maximum: MAX_PURGE_CUSTODY_LOCATOR_BYTES,
        });
    }
    if custody_locator.chars().any(char::is_control) {
        return Err(ConsentPurgeCustodyError::LocatorContainsControl);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-custody-locator:v1");
    hasher.update(custody_locator.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_custody_attestation_message(
    attestation: &ConsentPurgeCustodyAttestationV1,
) -> Result<Vec<u8>, ConsentPurgeCustodyError> {
    if attestation.schema != CONSENT_PURGE_CUSTODY_ATTESTATION_SCHEMA {
        return Err(ConsentPurgeCustodyError::UnsupportedAttestationSchema {
            schema: attestation.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-custody-attestation:v1");
    append_bytes(&mut message, attestation.schema.as_bytes())?;
    message.extend_from_slice(&attestation.ledger_epoch_id);
    message.extend_from_slice(&attestation.obligation_fingerprint);
    message.extend_from_slice(&attestation.retention_anchor_fingerprint);
    message.extend_from_slice(&attestation.protected_inventory_digest);
    append_bytes(&mut message, attestation.package_directory.as_bytes())?;
    message.push(custody_class_tag(attestation.custody_class));
    message.extend_from_slice(&attestation.custody_locator_digest);
    message.extend_from_slice(&attestation.replica_id);
    message.extend_from_slice(&attestation.observed_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&attestation.available_until_unix_secs.to_be_bytes());
    message.extend_from_slice(&attestation.custodian_public_key);
    Ok(message)
}

fn custody_class_tag(class: ConsentPurgeCustodyClassV1) -> u8 {
    match class {
        ConsentPurgeCustodyClassV1::OfflineMedia => 1,
        ConsentPurgeCustodyClassV1::RemoteVault => 2,
        ConsentPurgeCustodyClassV1::HardwareProtected => 3,
    }
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConsentPurgeCustodyError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| ConsentPurgeCustodyError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> ConsentPurgeRetentionSubjectV1 {
        ConsentPurgeRetentionSubjectV1 {
            ledger_epoch_id: [1u8; 32],
            base_certificate_fingerprint: [2u8; 32],
            anchor_fingerprint: [3u8; 32],
            obligation_fingerprint: [4u8; 32],
            protected_inventory_digest: [5u8; 32],
            package_directory: "/rollback/xenia/package".to_string(),
            retain_until_unix_secs: 20_000,
        }
    }

    #[test]
    fn custody_attestation_binds_locator_class_and_subject() {
        let subject = subject();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let attestation = ConsentPurgeCustodyAttestationV1::sign(
            &subject,
            ConsentPurgeCustodyClassV1::RemoteVault,
            "vault://independent/site-a/object-9",
            [7u8; 16],
            &key,
            10_000,
            30_000,
        )
        .unwrap();
        attestation
            .verify(&subject, 10_001, MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS)
            .unwrap();
        let mut changed = attestation.clone();
        changed.custody_class = ConsentPurgeCustodyClassV1::OfflineMedia;
        assert!(matches!(
            changed.verify(&subject, 10_001, MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS),
            Err(ConsentPurgeCustodyError::InvalidCustodySignature)
        ));
    }

    #[test]
    fn custody_bundle_requires_distinct_trusted_replicas() {
        let subject = subject();
        let first_key = SigningKey::from_bytes(&[21u8; 32]);
        let second_key = SigningKey::from_bytes(&[22u8; 32]);
        let first = ConsentPurgeCustodyAttestationV1::sign(
            &subject,
            ConsentPurgeCustodyClassV1::OfflineMedia,
            "media://safe-a/tape-1",
            [1u8; 16],
            &first_key,
            10_000,
            30_000,
        )
        .unwrap();
        let second = ConsentPurgeCustodyAttestationV1::sign(
            &subject,
            ConsentPurgeCustodyClassV1::HardwareProtected,
            "hsm://vault-b/slot-4",
            [2u8; 16],
            &second_key,
            10_001,
            30_000,
        )
        .unwrap();
        let mut bundle = ConsentPurgeCustodyBundleV1::new(&subject);
        bundle.add(&subject, first).unwrap();
        bundle.add(&subject, second).unwrap();
        bundle
            .verify_quorum(
                &subject,
                &[
                    first_key.verifying_key().to_bytes(),
                    second_key.verifying_key().to_bytes(),
                ],
                2,
                10_002,
                MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
                subject.retain_until_unix_secs,
            )
            .unwrap();
        assert!(matches!(
            bundle.verify_quorum(
                &subject,
                &[first_key.verifying_key().to_bytes()],
                2,
                10_002,
                MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
                subject.retain_until_unix_secs,
            ),
            Err(ConsentPurgeCustodyError::UntrustedCustodianKey)
                | Err(ConsentPurgeCustodyError::CustodyQuorumNotMet { .. })
        ));
    }

    #[test]
    fn custody_bundle_rejects_noncanonical_order() {
        let subject = subject();
        let first_key = SigningKey::from_bytes(&[23u8; 32]);
        let second_key = SigningKey::from_bytes(&[24u8; 32]);
        let mut bundle = ConsentPurgeCustodyBundleV1::new(&subject);
        for (key, replica) in [(&first_key, [3u8; 16]), (&second_key, [4u8; 16])] {
            let attestation = ConsentPurgeCustodyAttestationV1::sign(
                &subject,
                ConsentPurgeCustodyClassV1::OfflineMedia,
                "media://independent/archive",
                replica,
                key,
                10_000,
                30_000,
            )
            .unwrap();
            bundle.add(&subject, attestation).unwrap();
        }
        bundle.attestations.reverse();
        assert!(matches!(
            bundle.verify_quorum(
                &subject,
                &[
                    first_key.verifying_key().to_bytes(),
                    second_key.verifying_key().to_bytes(),
                ],
                2,
                10_001,
                MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
                subject.retain_until_unix_secs,
            ),
            Err(ConsentPurgeCustodyError::AttestationOrderMismatch)
        ));
    }

    #[test]
    fn custody_attestation_expires_at_verification_time() {
        let subject = subject();
        let key = SigningKey::from_bytes(&[25u8; 32]);
        let attestation = ConsentPurgeCustodyAttestationV1::sign(
            &subject,
            ConsentPurgeCustodyClassV1::RemoteVault,
            "vault://site/expiring-object",
            [5u8; 16],
            &key,
            10_000,
            20_000,
        )
        .unwrap();
        assert!(matches!(
            attestation.verify(&subject, 20_001, MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,),
            Err(ConsentPurgeCustodyError::AvailabilityExpired)
        ));
    }

    #[test]
    fn custody_attestation_cannot_expire_before_retention() {
        let subject = subject();
        let key = SigningKey::from_bytes(&[31u8; 32]);
        assert!(matches!(
            ConsentPurgeCustodyAttestationV1::sign(
                &subject,
                ConsentPurgeCustodyClassV1::RemoteVault,
                "vault://site/object",
                [3u8; 16],
                &key,
                10_000,
                subject.retain_until_unix_secs - 1,
            ),
            Err(ConsentPurgeCustodyError::AvailabilityTooShort)
        ));
    }
}
