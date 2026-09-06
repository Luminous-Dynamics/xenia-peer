// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Non-authoritative device capability request intent for Spore/Holon.
//!
//! This contract binds an exact requested subset to an exact capability
//! advertisement and exact purpose/workload commitments. It still grants
//! nothing. A later Xenia authority integration must re-validate the request
//! and bind it to an authenticated session generation, transport profile,
//! consent/revocation state, and deadline before any device I/O is allowed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::device_capabilities::{
    DeviceCapabilityAdvertisementError, DeviceCapabilityAdvertisementV1, DeviceCapabilityV1,
};

/// Schema version for [`DeviceCapabilityRequestV1`].
pub const DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION: u16 = 1;

/// Maximum requested lifetime accepted by the V1 intent contract.
///
/// This is only an upper bound on what the requester asks for. It is not a
/// trusted clock, lease, or grant lifetime; later authority may shorten it.
pub const DEVICE_CAPABILITY_REQUEST_MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;

const REQUEST_DOMAIN: &[u8] = b"xenia.device-capability-request.v1\0";
const MAX_REQUESTED_CAPABILITIES: usize = 32;

/// Structural/subject-validation failure for a V1 capability request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DeviceCapabilityRequestError {
    /// The request schema is not V1.
    #[error("unsupported device capability request schema")]
    UnsupportedSchema,
    /// Request id must not use the all-zero sentinel.
    #[error("device capability request id must be non-zero")]
    ZeroRequestId,
    /// Advertisement commitment must not use the all-zero sentinel.
    #[error("advertisement digest must be non-zero")]
    ZeroAdvertisementDigest,
    /// Requesting application/workload commitment must be present.
    #[error("requester workload commitment must be non-zero")]
    ZeroRequesterWorkloadCommitment,
    /// Canonical purpose/presentation commitment must be present.
    #[error("purpose commitment must be non-zero")]
    ZeroPurposeCommitment,
    /// A request must name at least one potential function.
    #[error("device capability request must contain at least one capability")]
    EmptyCapabilitySet,
    /// Keep V1 requests deliberately bounded.
    #[error("too many requested device capabilities")]
    TooManyCapabilities,
    /// Zero-length or excessively long requested lifetimes are rejected.
    #[error("invalid requested capability lifetime")]
    InvalidRequestedLifetime,
    /// The referenced advertisement itself is malformed.
    #[error("invalid device capability advertisement")]
    InvalidAdvertisement,
    /// The request names a different advertisement digest.
    #[error("device capability request is bound to a different advertisement")]
    AdvertisementDigestMismatch,
    /// The request asks for a capability the advertisement did not declare.
    #[error("requested device capability was not advertised")]
    CapabilityNotAdvertised,
}

/// Exact non-authoritative request intent for a subset of one Holon's
/// advertised device functions.
///
/// The request is intentionally serializable because it may be presented,
/// transported, logged, or later included in signed consent evidence. Its
/// serialized form is **not authority**. No deserialized request can perform
/// device I/O without a separately constructed Xenia authority object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapabilityRequestV1 {
    /// Exact request schema.
    pub schema_version: u16,
    /// Caller-generated request correlation/idempotency id.
    pub request_id: [u8; 16],
    /// Canonical digest of the exact capability advertisement being targeted.
    pub advertisement_digest: [u8; 32],
    /// Commitment to the requesting application/workload identity/config.
    pub requester_workload_commitment: [u8; 32],
    /// Commitment to the canonical purpose/presentation shown for this request.
    pub purpose_commitment: [u8; 32],
    /// Requested duration only; later authority may shorten or reject it.
    pub requested_lifetime_ms: u64,
    /// Exact canonically ordered requested subset.
    pub requested_capabilities: BTreeSet<DeviceCapabilityV1>,
}

impl DeviceCapabilityRequestV1 {
    /// Construct and structurally validate a request intent.
    pub fn new(
        request_id: [u8; 16],
        advertisement_digest: [u8; 32],
        requester_workload_commitment: [u8; 32],
        purpose_commitment: [u8; 32],
        requested_lifetime_ms: u64,
        requested_capabilities: impl IntoIterator<Item = DeviceCapabilityV1>,
    ) -> Result<Self, DeviceCapabilityRequestError> {
        let request = Self {
            schema_version: DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION,
            request_id,
            advertisement_digest,
            requester_workload_commitment,
            purpose_commitment,
            requested_lifetime_ms,
            requested_capabilities: requested_capabilities.into_iter().collect(),
        };
        request.validate_structure()?;
        Ok(request)
    }

    /// Validate request-local invariants without claiming anything about the
    /// referenced advertisement or remote authority.
    pub fn validate_structure(&self) -> Result<(), DeviceCapabilityRequestError> {
        if self.schema_version != DEVICE_CAPABILITY_REQUEST_SCHEMA_VERSION {
            return Err(DeviceCapabilityRequestError::UnsupportedSchema);
        }
        if self.request_id == [0; 16] {
            return Err(DeviceCapabilityRequestError::ZeroRequestId);
        }
        if self.advertisement_digest == [0; 32] {
            return Err(DeviceCapabilityRequestError::ZeroAdvertisementDigest);
        }
        if self.requester_workload_commitment == [0; 32] {
            return Err(DeviceCapabilityRequestError::ZeroRequesterWorkloadCommitment);
        }
        if self.purpose_commitment == [0; 32] {
            return Err(DeviceCapabilityRequestError::ZeroPurposeCommitment);
        }
        if self.requested_capabilities.is_empty() {
            return Err(DeviceCapabilityRequestError::EmptyCapabilitySet);
        }
        if self.requested_capabilities.len() > MAX_REQUESTED_CAPABILITIES {
            return Err(DeviceCapabilityRequestError::TooManyCapabilities);
        }
        if self.requested_lifetime_ms == 0
            || self.requested_lifetime_ms > DEVICE_CAPABILITY_REQUEST_MAX_LIFETIME_MS
        {
            return Err(DeviceCapabilityRequestError::InvalidRequestedLifetime);
        }
        Ok(())
    }

    /// Verify that this intent names the exact supplied advertisement and asks
    /// only for capabilities that advertisement declares.
    ///
    /// Success still grants no authority. Later authenticated Xenia admission
    /// must perform its own point-of-use revalidation.
    pub fn validate_against(
        &self,
        advertisement: &DeviceCapabilityAdvertisementV1,
    ) -> Result<(), DeviceCapabilityRequestError> {
        self.validate_structure()?;
        let digest = advertisement
            .digest()
            .map_err(|_: DeviceCapabilityAdvertisementError| {
                DeviceCapabilityRequestError::InvalidAdvertisement
            })?;
        if digest != self.advertisement_digest {
            return Err(DeviceCapabilityRequestError::AdvertisementDigestMismatch);
        }
        if self
            .requested_capabilities
            .iter()
            .any(|capability| !advertisement.advertises(*capability))
        {
            return Err(DeviceCapabilityRequestError::CapabilityNotAdvertised);
        }
        Ok(())
    }

    /// Domain-separated canonical commitment to the complete request intent.
    ///
    /// The hand-written encoding is independent of serde/bincode layout.
    pub fn digest(&self) -> Result<[u8; 32], DeviceCapabilityRequestError> {
        self.validate_structure()?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(&self.schema_version.to_be_bytes());
        hasher.update(&self.request_id);
        hasher.update(&self.advertisement_digest);
        hasher.update(&self.requester_workload_commitment);
        hasher.update(&self.purpose_commitment);
        hasher.update(&self.requested_lifetime_ms.to_be_bytes());
        hasher.update(&(self.requested_capabilities.len() as u16).to_be_bytes());
        for capability in &self.requested_capabilities {
            hasher.update(&(*capability as u16).to_be_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_capabilities::{DeviceClassV1, DeviceCapabilityAdvertisementV1};

    fn advertisement() -> DeviceCapabilityAdvertisementV1 {
        DeviceCapabilityAdvertisementV1::new(
            [0x44; 32],
            DeviceClassV1::Phone,
            3,
            [
                DeviceCapabilityV1::CaptureCamera,
                DeviceCapabilityV1::BiometricApproval,
                DeviceCapabilityV1::PresentNotification,
            ],
        )
        .unwrap()
    }

    fn request(
        advertisement: &DeviceCapabilityAdvertisementV1,
    ) -> DeviceCapabilityRequestV1 {
        DeviceCapabilityRequestV1::new(
            [0x11; 16],
            advertisement.digest().unwrap(),
            [0x22; 32],
            [0x33; 32],
            60_000,
            [
                DeviceCapabilityV1::BiometricApproval,
                DeviceCapabilityV1::CaptureCamera,
            ],
        )
        .unwrap()
    }

    #[test]
    fn exact_advertised_subset_validates() {
        let advertisement = advertisement();
        let request = request(&advertisement);
        assert_eq!(request.validate_against(&advertisement), Ok(()));
    }

    #[test]
    fn unadvertised_capability_is_rejected() {
        let advertisement = advertisement();
        let request = DeviceCapabilityRequestV1::new(
            [0x11; 16],
            advertisement.digest().unwrap(),
            [0x22; 32],
            [0x33; 32],
            60_000,
            [DeviceCapabilityV1::ReadPreciseLocation],
        )
        .unwrap();

        assert_eq!(
            request.validate_against(&advertisement),
            Err(DeviceCapabilityRequestError::CapabilityNotAdvertised)
        );
    }

    #[test]
    fn advertisement_substitution_is_rejected_even_when_subset_exists() {
        let advertisement = advertisement();
        let request = request(&advertisement);
        let substituted = DeviceCapabilityAdvertisementV1::new(
            [0x45; 32],
            DeviceClassV1::Phone,
            3,
            advertisement.capabilities.iter().copied(),
        )
        .unwrap();

        assert_eq!(
            request.validate_against(&substituted),
            Err(DeviceCapabilityRequestError::AdvertisementDigestMismatch)
        );
    }

    #[test]
    fn canonical_request_digest_is_independent_of_input_order_and_duplicates() {
        let advertisement = advertisement();
        let digest = advertisement.digest().unwrap();

        let a = DeviceCapabilityRequestV1::new(
            [0x11; 16],
            digest,
            [0x22; 32],
            [0x33; 32],
            60_000,
            [
                DeviceCapabilityV1::CaptureCamera,
                DeviceCapabilityV1::BiometricApproval,
                DeviceCapabilityV1::CaptureCamera,
            ],
        )
        .unwrap();
        let b = DeviceCapabilityRequestV1::new(
            [0x11; 16],
            digest,
            [0x22; 32],
            [0x33; 32],
            60_000,
            [
                DeviceCapabilityV1::BiometricApproval,
                DeviceCapabilityV1::CaptureCamera,
            ],
        )
        .unwrap();

        assert_eq!(a, b);
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn digest_binds_request_id_advertisement_workload_purpose_lifetime_and_subset() {
        let advertisement = advertisement();
        let base = request(&advertisement);
        let base_digest = base.digest().unwrap();

        let variants = [
            DeviceCapabilityRequestV1::new(
                [0x12; 16],
                base.advertisement_digest,
                base.requester_workload_commitment,
                base.purpose_commitment,
                base.requested_lifetime_ms,
                base.requested_capabilities.iter().copied(),
            )
            .unwrap(),
            DeviceCapabilityRequestV1::new(
                base.request_id,
                [0x55; 32],
                base.requester_workload_commitment,
                base.purpose_commitment,
                base.requested_lifetime_ms,
                base.requested_capabilities.iter().copied(),
            )
            .unwrap(),
            DeviceCapabilityRequestV1::new(
                base.request_id,
                base.advertisement_digest,
                [0x66; 32],
                base.purpose_commitment,
                base.requested_lifetime_ms,
                base.requested_capabilities.iter().copied(),
            )
            .unwrap(),
            DeviceCapabilityRequestV1::new(
                base.request_id,
                base.advertisement_digest,
                base.requester_workload_commitment,
                [0x77; 32],
                base.requested_lifetime_ms,
                base.requested_capabilities.iter().copied(),
            )
            .unwrap(),
            DeviceCapabilityRequestV1::new(
                base.request_id,
                base.advertisement_digest,
                base.requester_workload_commitment,
                base.purpose_commitment,
                base.requested_lifetime_ms + 1,
                base.requested_capabilities.iter().copied(),
            )
            .unwrap(),
            DeviceCapabilityRequestV1::new(
                base.request_id,
                base.advertisement_digest,
                base.requester_workload_commitment,
                base.purpose_commitment,
                base.requested_lifetime_ms,
                [DeviceCapabilityV1::CaptureCamera],
            )
            .unwrap(),
        ];

        for variant in variants {
            assert_ne!(base_digest, variant.digest().unwrap());
        }
    }

    #[test]
    fn zero_or_unbounded_request_fields_are_rejected() {
        let advertisement = advertisement();
        let advertisement_digest = advertisement.digest().unwrap();
        let base_caps = [DeviceCapabilityV1::CaptureCamera];

        assert_eq!(
            DeviceCapabilityRequestV1::new(
                [0; 16],
                advertisement_digest,
                [0x22; 32],
                [0x33; 32],
                1,
                base_caps,
            ),
            Err(DeviceCapabilityRequestError::ZeroRequestId)
        );
        assert_eq!(
            DeviceCapabilityRequestV1::new(
                [0x11; 16],
                advertisement_digest,
                [0x22; 32],
                [0x33; 32],
                DEVICE_CAPABILITY_REQUEST_MAX_LIFETIME_MS + 1,
                base_caps,
            ),
            Err(DeviceCapabilityRequestError::InvalidRequestedLifetime)
        );
    }
}
