// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Host-neutral device capability advertisement for Spore/Holon integration.
//!
//! This module deliberately describes **what a Holon can potentially do**, not
//! what any remote peer is authorized to do.  An advertisement is discovery
//! evidence only.  It does not authenticate a peer, grant consent, mint an
//! application capability, or authorize device I/O.
//!
//! The stable Holon identity itself remains owned by the higher-level
//! Nixward/Spore identity layer.  Xenia binds only its 32-byte commitment so it
//! does not create a second Holon identity namespace.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version for [`DeviceCapabilityAdvertisementV1`].
pub const DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION: u16 = 1;

const ADVERTISEMENT_DOMAIN: &[u8] = b"xenia.device-capability-advertisement.v1\0";
const MAX_CAPABILITIES: usize = 64;

/// Coarse physical/product class of a Holon embodiment.
///
/// This is presentation/discovery metadata, not an authority tier. A phone is
/// not inherently more or less trusted than a desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum DeviceClassV1 {
    /// Desktop/workstation-class computer.
    Desktop = 1,
    /// Portable notebook-class computer.
    Laptop = 2,
    /// Phone-class handheld.
    Phone = 3,
    /// Tablet-class touch device.
    Tablet = 4,
    /// Watch or other small wearable.
    Wearable = 5,
    /// Television or fixed media display.
    Tv = 6,
    /// Vehicle-integrated computing surface.
    Vehicle = 7,
    /// XR headset or spatial-computing device.
    Xr = 8,
    /// Embedded/edge appliance.
    Embedded = 9,
    /// Device class not represented by the V1 taxonomy.
    Other = 65_535,
}

/// One function a Holon can potentially expose to another local/remote
/// experience.
///
/// Presence here is **not permission**.  Later Xenia authority must bind an
/// exact requested subset to an authenticated session generation and consent
/// evidence before Spore may use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum DeviceCapabilityV1 {
    /// Present an application/semantic surface on the device.
    PresentSurface = 1,
    /// Present a user notification.
    PresentNotification = 2,
    /// Control local media playback.
    ControlMedia = 3,
    /// Capture still/video camera data.
    CaptureCamera = 10,
    /// Capture microphone/audio input.
    CaptureMicrophone = 11,
    /// Produce speaker/audio output.
    ProduceAudio = 12,
    /// Provide coarse location suitable for regional context.
    ReadCoarseLocation = 20,
    /// Provide precise device location.
    ReadPreciseLocation = 21,
    /// Provide motion/orientation sensor observations.
    ReadMotionSensors = 22,
    /// Provide a coarse user-presence signal.
    ReadPresence = 23,
    /// Produce haptic feedback.
    ProduceHaptics = 24,
    /// Ask the local device to perform a biometric-backed user approval.
    BiometricApproval = 30,
    /// Ask the local secure hardware/key service to sign an approved payload.
    SecureSigning = 31,
    /// Read the local clipboard.
    ReadClipboard = 40,
    /// Write the local clipboard.
    WriteClipboard = 41,
    /// Send a user-selected file from this device.
    SendFile = 42,
    /// Receive a file onto this device.
    ReceiveFile = 43,
    /// Render a Spore ambient/world surface.
    PresentSporeWorld = 50,
}

/// Validation failure for a device capability advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DeviceCapabilityAdvertisementError {
    /// The advertised schema is not V1.
    #[error("unsupported device capability advertisement schema")]
    UnsupportedSchema,
    /// Holon identity commitment must not be the all-zero sentinel.
    #[error("Holon identity commitment must be non-zero")]
    ZeroHolonIdentityCommitment,
    /// V1 deliberately bounds the set to keep discovery messages small.
    #[error("too many advertised device capabilities")]
    TooManyCapabilities,
}

/// Non-authoritative discovery record for one Holon embodiment.
///
/// `holon_identity_commitment` is expected to be the 32-byte commitment of the
/// persistent Holon identity owned by the higher-level identity layer. Xenia
/// deliberately does not define or mint that identity.
///
/// `capability_epoch` lets the owning Holon distinguish successive capability
/// profiles (for example after hardware/policy changes). It is descriptive
/// state only; monotonicity and freshness are not established by this object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapabilityAdvertisementV1 {
    /// Exact schema version.
    pub schema_version: u16,
    /// Commitment to the higher-level persistent Holon identity.
    pub holon_identity_commitment: [u8; 32],
    /// Coarse device/embodiment class.
    pub device_class: DeviceClassV1,
    /// Owner-selected generation of the advertised capability profile.
    pub capability_epoch: u64,
    /// Canonically ordered set of potential device functions.
    pub capabilities: BTreeSet<DeviceCapabilityV1>,
}

impl DeviceCapabilityAdvertisementV1 {
    /// Construct and validate a V1 non-authoritative advertisement.
    pub fn new(
        holon_identity_commitment: [u8; 32],
        device_class: DeviceClassV1,
        capability_epoch: u64,
        capabilities: impl IntoIterator<Item = DeviceCapabilityV1>,
    ) -> Result<Self, DeviceCapabilityAdvertisementError> {
        let advertisement = Self {
            schema_version: DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
            holon_identity_commitment,
            device_class,
            capability_epoch,
            capabilities: capabilities.into_iter().collect(),
        };
        advertisement.validate()?;
        Ok(advertisement)
    }

    /// Validate structural V1 invariants.
    pub fn validate(&self) -> Result<(), DeviceCapabilityAdvertisementError> {
        if self.schema_version != DEVICE_CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION {
            return Err(DeviceCapabilityAdvertisementError::UnsupportedSchema);
        }
        if self.holon_identity_commitment == [0; 32] {
            return Err(DeviceCapabilityAdvertisementError::ZeroHolonIdentityCommitment);
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(DeviceCapabilityAdvertisementError::TooManyCapabilities);
        }
        Ok(())
    }

    /// Whether this Holon advertises the potential function.
    ///
    /// This answers only a discovery question. It MUST NOT be used as an
    /// authorization check.
    pub fn advertises(&self, capability: DeviceCapabilityV1) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Domain-separated canonical commitment to the complete advertisement.
    ///
    /// The encoding is hand-written so the commitment is independent of serde
    /// or bincode implementation details.
    pub fn digest(&self) -> Result<[u8; 32], DeviceCapabilityAdvertisementError> {
        self.validate()?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(ADVERTISEMENT_DOMAIN);
        hasher.update(&self.schema_version.to_be_bytes());
        hasher.update(&self.holon_identity_commitment);
        hasher.update(&(self.device_class as u16).to_be_bytes());
        hasher.update(&self.capability_epoch.to_be_bytes());
        hasher.update(&(self.capabilities.len() as u16).to_be_bytes());
        for capability in &self.capabilities {
            hasher.update(&(*capability as u16).to_be_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holon() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn canonical_digest_is_independent_of_input_order_and_duplicates() {
        let a = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            7,
            [
                DeviceCapabilityV1::CaptureCamera,
                DeviceCapabilityV1::BiometricApproval,
                DeviceCapabilityV1::CaptureCamera,
            ],
        )
        .unwrap();

        let b = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            7,
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
    fn digest_binds_holon_device_class_epoch_and_capability_set() {
        let base = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            7,
            [DeviceCapabilityV1::CaptureCamera],
        )
        .unwrap();

        let different_holon = DeviceCapabilityAdvertisementV1::new(
            [0x43; 32],
            DeviceClassV1::Phone,
            7,
            [DeviceCapabilityV1::CaptureCamera],
        )
        .unwrap();
        let different_class = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Tablet,
            7,
            [DeviceCapabilityV1::CaptureCamera],
        )
        .unwrap();
        let different_epoch = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            8,
            [DeviceCapabilityV1::CaptureCamera],
        )
        .unwrap();
        let different_capability = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            7,
            [DeviceCapabilityV1::CaptureMicrophone],
        )
        .unwrap();

        let digest = base.digest().unwrap();
        assert_ne!(digest, different_holon.digest().unwrap());
        assert_ne!(digest, different_class.digest().unwrap());
        assert_ne!(digest, different_epoch.digest().unwrap());
        assert_ne!(digest, different_capability.digest().unwrap());
    }

    #[test]
    fn zero_holon_identity_commitment_is_rejected() {
        assert_eq!(
            DeviceCapabilityAdvertisementV1::new(
                [0; 32],
                DeviceClassV1::Phone,
                0,
                [DeviceCapabilityV1::PresentSurface],
            ),
            Err(DeviceCapabilityAdvertisementError::ZeroHolonIdentityCommitment)
        );
    }

    #[test]
    fn advertisement_is_discovery_not_authority() {
        let advertisement = DeviceCapabilityAdvertisementV1::new(
            holon(),
            DeviceClassV1::Phone,
            1,
            [
                DeviceCapabilityV1::CaptureCamera,
                DeviceCapabilityV1::BiometricApproval,
            ],
        )
        .unwrap();

        assert!(advertisement.advertises(DeviceCapabilityV1::CaptureCamera));
        assert!(!advertisement.advertises(DeviceCapabilityV1::ReadPreciseLocation));
    }
}
