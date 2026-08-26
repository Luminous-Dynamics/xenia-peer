// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical selected-capability contexts for Xenia handshakes.
//!
//! This crate independently implements the negotiated-context encoding used by
//! `xenia-wire`. The implementations intentionally do not depend on one another:
//! conformance is established by frozen cross-language vectors instead of shared
//! code, so serialization drift remains detectable.
//!
//! A [`NegotiatedContextV1`] is canonical selected-protocol state. It is not, by
//! itself, proof that a handshake authenticated that state. The native handshake
//! must bind [`NegotiatedContextV1::hash`] into its authenticated transcript.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest, Sha256};

/// Domain separator for canonical negotiated contexts.
pub const NEGOTIATED_CONTEXT_V1_DOMAIN: &[u8] = b"xenia.negotiated-context.v1\0";

/// Stable digest algorithm label.
pub const NEGOTIATED_CONTEXT_HASH_ALGORITHM: &str = "sha256";

/// Maximum number of selected capabilities.
pub const MAX_NEGOTIATED_CAPABILITIES: usize = 64;

/// Maximum capability-name length in bytes.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;

/// Maximum capability-version length in bytes.
pub const MAX_CAPABILITY_VERSION_BYTES: usize = 32;

/// Canonical causal-authority capability name.
pub const CAUSAL_AUTHORITY_CAPABILITY_NAME: &[u8] = b"xenia.causal-authority";

/// Canonical causal-authority draft-04 version.
pub const CAUSAL_AUTHORITY_CAPABILITY_VERSION: &[u8] = b"draft-04";

/// One exact negotiated capability identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NegotiatedCapabilityV1 {
    name: Vec<u8>,
    version: Vec<u8>,
}

impl NegotiatedCapabilityV1 {
    /// Construct and validate one exact capability identifier.
    pub fn new(
        name: impl Into<Vec<u8>>,
        version: impl Into<Vec<u8>>,
    ) -> Result<Self, NegotiatedContextError> {
        let capability = Self {
            name: name.into(),
            version: version.into(),
        };
        capability.validate()?;
        Ok(capability)
    }

    /// Exact capability-name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Exact capability-version bytes.
    pub fn version(&self) -> &[u8] {
        &self.version
    }

    fn validate(&self) -> Result<(), NegotiatedContextError> {
        if self.name.is_empty() {
            return Err(NegotiatedContextError::EmptyCapabilityName);
        }
        if self.name.len() > MAX_CAPABILITY_NAME_BYTES {
            return Err(NegotiatedContextError::CapabilityNameTooLong);
        }
        if self.version.is_empty() {
            return Err(NegotiatedContextError::EmptyCapabilityVersion);
        }
        if self.version.len() > MAX_CAPABILITY_VERSION_BYTES {
            return Err(NegotiatedContextError::CapabilityVersionTooLong);
        }
        Ok(())
    }
}

/// Canonical selected capability set and transcript-binding digest.
///
/// Selection order does not affect the digest. Every exact capability name maps
/// to exactly one selected version; duplicate names fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedContextV1 {
    capabilities: Vec<NegotiatedCapabilityV1>,
    hash: [u8; 32],
}

impl NegotiatedContextV1 {
    /// Canonicalize and hash a selected capability set.
    ///
    /// Selection order does not affect the digest. Exact duplicates and
    /// multiple selected versions for the same exact capability name fail
    /// closed rather than becoming an ambiguous policy surface.
    pub fn from_capabilities<I>(capabilities: I) -> Result<Self, NegotiatedContextError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let mut capabilities: Vec<_> = capabilities.into_iter().collect();
        if capabilities.len() > MAX_NEGOTIATED_CAPABILITIES {
            return Err(NegotiatedContextError::TooManyCapabilities);
        }
        for capability in &capabilities {
            capability.validate()?;
        }

        capabilities.sort();
        if capabilities
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(NegotiatedContextError::DuplicateCapabilityName);
        }

        let hash = hash_capabilities(&capabilities);
        Ok(Self { capabilities, hash })
    }

    /// Canonical ordered selected capabilities.
    pub fn capabilities(&self) -> &[NegotiatedCapabilityV1] {
        &self.capabilities
    }

    /// SHA-256 transcript-binding digest.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Return true only for an exact selected name/version pair.
    pub fn contains(&self, name: &[u8], version: &[u8]) -> bool {
        self.capabilities
            .binary_search_by(|capability| {
                capability
                    .name()
                    .cmp(name)
                    .then_with(|| capability.version().cmp(version))
            })
            .is_ok()
    }

    /// Require this selected set to contain exact causal-authority draft-04.
    pub fn require_causal_authority_draft04(&self) -> Result<(), NegotiatedContextError> {
        if self.contains(
            CAUSAL_AUTHORITY_CAPABILITY_NAME,
            CAUSAL_AUTHORITY_CAPABILITY_VERSION,
        ) {
            Ok(())
        } else {
            Err(NegotiatedContextError::CausalAuthorityNotSelected)
        }
    }
}

/// Construct the exact causal-authority draft-04 capability identifier.
pub fn causal_authority_draft04_capability() -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec(),
    )
    .expect("built-in capability satisfies negotiated-context bounds")
}

fn hash_capabilities(capabilities: &[NegotiatedCapabilityV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATED_CONTEXT_V1_DOMAIN);
    hasher.update(
        u32::try_from(capabilities.len())
            .expect("capability count is bounded below u32::MAX")
            .to_be_bytes(),
    );

    for capability in capabilities {
        hash_len_prefixed(&mut hasher, capability.name());
        hash_len_prefixed(&mut hasher, capability.version());
    }

    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("component is bounded below u16::MAX");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// Canonical negotiated-context failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiatedContextError {
    /// More selected capabilities than the protocol bound permits.
    #[error("too many negotiated capabilities")]
    TooManyCapabilities,
    /// Empty capability name.
    #[error("capability name must not be empty")]
    EmptyCapabilityName,
    /// Capability name exceeds the protocol bound.
    #[error("capability name exceeds negotiated-context bound")]
    CapabilityNameTooLong,
    /// Empty capability version.
    #[error("capability version must not be empty")]
    EmptyCapabilityVersion,
    /// Capability version exceeds the protocol bound.
    #[error("capability version exceeds negotiated-context bound")]
    CapabilityVersionTooLong,
    /// More than one selected entry uses the same exact capability name.
    #[error("negotiated capability name has more than one selected version")]
    DuplicateCapabilityName,
    /// Exact causal-authority draft-04 is absent from the selected set.
    #[error("causal-authority draft-04 is not selected")]
    CausalAuthorityNotSelected,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    #[test]
    fn reproduces_authority_only_vector() {
        let context =
            NegotiatedContextV1::from_capabilities([causal_authority_draft04_capability()])
                .unwrap();
        assert_eq!(
            context.hash(),
            [
                0xff, 0xd0, 0xc4, 0xad, 0x0b, 0x13, 0x3e, 0x8a, 0xae, 0x58, 0xb0, 0xa7, 0x9b,
                0x51, 0x0f, 0xa9, 0x0f, 0x5e, 0xbf, 0xf9, 0x77, 0x51, 0xb5, 0xfc, 0x2b, 0x55,
                0xa7, 0xff, 0x79, 0x6c, 0x2a, 0x85,
            ]
        );
        assert!(context.require_causal_authority_draft04().is_ok());
    }

    #[test]
    fn reproduces_authority_plus_rekey_vector_independent_of_order() {
        let rekey = cap(b"xenia.operator-rekey", b"v1");
        let a = NegotiatedContextV1::from_capabilities([
            rekey.clone(),
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let b = NegotiatedContextV1::from_capabilities([
            causal_authority_draft04_capability(),
            rekey,
        ])
        .unwrap();
        let expected = [
            0xa4, 0x86, 0x15, 0xf6, 0xc5, 0xb7, 0x00, 0x4a, 0xa1, 0x9c, 0xd5, 0x7e, 0x34, 0x23,
            0x5c, 0xa3, 0x57, 0x75, 0xdf, 0xe0, 0xab, 0xd1, 0x04, 0x8c, 0x55, 0x95, 0xfe, 0x20,
            0xa8, 0xb5, 0x55, 0xe8,
        ];

        assert_eq!(a, b);
        assert_eq!(a.hash(), expected);
    }

    #[test]
    fn draft03_does_not_satisfy_draft04_policy() {
        let context = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-03",
        )])
        .unwrap();
        assert_eq!(
            context.require_causal_authority_draft04().unwrap_err(),
            NegotiatedContextError::CausalAuthorityNotSelected
        );
    }

    #[test]
    fn duplicate_names_versions_and_identifier_ambiguity_fail_closed() {
        let authority = causal_authority_draft04_capability();
        assert_eq!(
            NegotiatedContextV1::from_capabilities([authority.clone(), authority]).unwrap_err(),
            NegotiatedContextError::DuplicateCapabilityName
        );
        assert_eq!(
            NegotiatedContextV1::from_capabilities([
                cap(b"xenia.causal-authority", b"draft-03"),
                cap(b"xenia.causal-authority", b"draft-04"),
            ])
            .unwrap_err(),
            NegotiatedContextError::DuplicateCapabilityName
        );

        let context = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();
        assert!(!context.contains(b"XENIA.CAUSAL-AUTHORITY", b"draft-04"));
        assert!(!context.contains(b"xenia.causal-authority", b"DRAFT-04"));
    }
}
