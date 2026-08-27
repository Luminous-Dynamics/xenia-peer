// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical capability negotiation for Xenia handshakes.
//!
//! This crate independently implements the negotiated-context encoding used by
//! `xenia-wire`. The implementations intentionally do not depend on one another:
//! conformance is established by frozen cross-language vectors instead of shared
//! code, so serialization drift remains detectable.
//!
//! The trust boundary is deliberately split into three layers:
//!
//! 1. [`CapabilityOfferV1`] canonically represents what each peer offers.
//! 2. [`negotiate_capabilities`] deterministically derives the exact mutually
//!    supported selected set and a binding over both offers plus that selection.
//! 3. The outer Xenia handshake must authenticate the resulting offer/selection
//!    binding before an application may treat [`NegotiationEvidenceV1`] as an
//!    authenticated protocol fact.
//!
//! A selected context or negotiation evidence object is therefore canonical
//! protocol state, not proof by itself. Authentication remains the job of the
//! Ed25519 + ML-DSA handshake transcript.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest, Sha256};

/// Domain separator for canonical negotiated selected-capability contexts.
pub const NEGOTIATED_CONTEXT_V1_DOMAIN: &[u8] = b"xenia.negotiated-context.v1\0";

/// Domain separator for one peer's canonical capability offer.
pub const CAPABILITY_OFFER_V1_DOMAIN: &[u8] = b"xenia.capability-offer.v1\0";

/// Domain separator binding host offer, viewer offer, and deterministic selection.
pub const NEGOTIATION_BINDING_V1_DOMAIN: &[u8] = b"xenia.capability-negotiation-binding.v1\0";

/// Stable digest algorithm label for capability negotiation objects.
pub const NEGOTIATED_CONTEXT_HASH_ALGORITHM: &str = "sha256";

/// Maximum number of capability names in one offer or selected context.
pub const MAX_NEGOTIATED_CAPABILITIES: usize = 64;

/// Maximum number of ordered versions offered for one capability name.
pub const MAX_CAPABILITY_VERSIONS_PER_NAME: usize = 16;

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
    /// Construct and validate one exact selected capability identifier.
    pub fn new(
        name: impl Into<Vec<u8>>,
        version: impl Into<Vec<u8>>,
    ) -> Result<Self, NegotiatedContextError> {
        let capability = Self {
            name: name.into(),
            version: version.into(),
        };
        validate_name(&capability.name)?;
        validate_version(&capability.version)?;
        Ok(capability)
    }

    /// Exact capability-name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Exact selected capability-version bytes.
    pub fn version(&self) -> &[u8] {
        &self.version
    }
}

/// One capability name and the exact versions a peer offers, in preference order.
///
/// Version order is intentionally load-bearing. Xenia's deterministic selection
/// rule is host-preference-first: for every capability name offered by both
/// peers, the first host-preferred exact version also offered by the viewer is
/// selected. Capability *name* ordering is canonicalized separately and does not
/// affect the offer hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityOfferEntryV1 {
    name: Vec<u8>,
    versions_by_preference: Vec<Vec<u8>>,
}

impl CapabilityOfferEntryV1 {
    /// Construct one capability offer entry.
    pub fn new<I, V>(
        name: impl Into<Vec<u8>>,
        versions_by_preference: I,
    ) -> Result<Self, NegotiatedContextError>
    where
        I: IntoIterator<Item = V>,
        V: Into<Vec<u8>>,
    {
        let entry = Self {
            name: name.into(),
            versions_by_preference: versions_by_preference
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Exact capability-name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Offered exact versions, highest preference first.
    pub fn versions_by_preference(&self) -> &[Vec<u8>] {
        &self.versions_by_preference
    }

    /// Whether this offer contains the exact version bytes.
    pub fn supports(&self, version: &[u8]) -> bool {
        self.versions_by_preference
            .iter()
            .any(|candidate| candidate.as_slice() == version)
    }

    fn validate(&self) -> Result<(), NegotiatedContextError> {
        validate_name(&self.name)?;
        if self.versions_by_preference.is_empty() {
            return Err(NegotiatedContextError::EmptyCapabilityVersions);
        }
        if self.versions_by_preference.len() > MAX_CAPABILITY_VERSIONS_PER_NAME {
            return Err(NegotiatedContextError::TooManyCapabilityVersions);
        }
        for version in &self.versions_by_preference {
            validate_version(version)?;
        }
        for (index, version) in self.versions_by_preference.iter().enumerate() {
            if self.versions_by_preference[index + 1..]
                .iter()
                .any(|candidate| candidate == version)
            {
                return Err(NegotiatedContextError::DuplicateOfferedVersion);
            }
        }
        Ok(())
    }
}

/// Canonical capability offer from one handshake peer.
///
/// Entries are sorted by exact capability-name bytes before hashing. Duplicate
/// names fail closed. Version preference order within each entry is preserved
/// and authenticated because it determines deterministic selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityOfferV1 {
    entries: Vec<CapabilityOfferEntryV1>,
    hash: [u8; 32],
}

impl CapabilityOfferV1 {
    /// Canonicalize and hash one peer's capability offer.
    pub fn from_entries<I>(entries: I) -> Result<Self, NegotiatedContextError>
    where
        I: IntoIterator<Item = CapabilityOfferEntryV1>,
    {
        let mut entries: Vec<_> = entries.into_iter().collect();
        if entries.len() > MAX_NEGOTIATED_CAPABILITIES {
            return Err(NegotiatedContextError::TooManyCapabilities);
        }
        for entry in &entries {
            entry.validate()?;
        }
        entries.sort_by(|left, right| left.name().cmp(right.name()));
        if entries
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(NegotiatedContextError::DuplicateCapabilityName);
        }
        let hash = hash_offer(&entries);
        Ok(Self { entries, hash })
    }

    /// Canonical capability entries, sorted by exact name bytes.
    pub fn entries(&self) -> &[CapabilityOfferEntryV1] {
        &self.entries
    }

    /// SHA-256 hash of the canonical offer, including version preference order.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Find one offered capability by exact name bytes.
    pub fn find(&self, name: &[u8]) -> Option<&CapabilityOfferEntryV1> {
        self.entries
            .binary_search_by(|entry| entry.name().cmp(name))
            .ok()
            .map(|index| &self.entries[index])
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

        capabilities.sort();
        if capabilities
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(NegotiatedContextError::DuplicateCapabilityName);
        }

        let hash = hash_selected_capabilities(&capabilities);
        Ok(Self { capabilities, hash })
    }

    /// Canonical ordered selected capabilities.
    pub fn capabilities(&self) -> &[NegotiatedCapabilityV1] {
        &self.capabilities
    }

    /// SHA-256 selected-context digest.
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

/// Canonical, but not yet authenticated, negotiation evidence.
///
/// The binding commits to the host offer hash, viewer offer hash, and the exact
/// deterministic selected context. A handshake must authenticate
/// [`Self::binding_hash`] before an application may trust this evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationEvidenceV1 {
    host_offer_hash: [u8; 32],
    viewer_offer_hash: [u8; 32],
    selected_context: NegotiatedContextV1,
    binding_hash: [u8; 32],
}

impl NegotiationEvidenceV1 {
    /// Hash of the canonical host offer.
    pub fn host_offer_hash(&self) -> [u8; 32] {
        self.host_offer_hash
    }

    /// Hash of the canonical viewer offer.
    pub fn viewer_offer_hash(&self) -> [u8; 32] {
        self.viewer_offer_hash
    }

    /// Exact deterministic mutually supported selected context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        &self.selected_context
    }

    /// SHA-256 binding over host offer, viewer offer, and selected context.
    pub fn binding_hash(&self) -> [u8; 32] {
        self.binding_hash
    }

    /// Require causal-authority draft-04 in the deterministic selected context.
    pub fn require_causal_authority_draft04(&self) -> Result<(), NegotiatedContextError> {
        self.selected_context.require_causal_authority_draft04()
    }
}

/// Deterministically negotiate two canonical capability offers.
///
/// For every capability name present in both offers, the first exact version in
/// the host's authenticated preference order that the viewer also offers is
/// selected. Names without a mutually supported exact version are omitted.
/// Strict profiles such as causal authority must subsequently require their
/// exact selected version through policy rather than assuming presence.
pub fn negotiate_capabilities(
    host_offer: &CapabilityOfferV1,
    viewer_offer: &CapabilityOfferV1,
) -> Result<NegotiationEvidenceV1, NegotiatedContextError> {
    let mut selected = Vec::new();

    for host_entry in host_offer.entries() {
        let Some(viewer_entry) = viewer_offer.find(host_entry.name()) else {
            continue;
        };
        let Some(version) = host_entry
            .versions_by_preference()
            .iter()
            .find(|version| viewer_entry.supports(version.as_slice()))
        else {
            continue;
        };
        selected.push(NegotiatedCapabilityV1::new(
            host_entry.name().to_vec(),
            version.clone(),
        )?);
    }

    let selected_context = NegotiatedContextV1::from_capabilities(selected)?;
    let host_offer_hash = host_offer.hash();
    let viewer_offer_hash = viewer_offer.hash();
    let binding_hash = hash_negotiation_binding(
        &host_offer_hash,
        &viewer_offer_hash,
        &selected_context.hash(),
    );

    Ok(NegotiationEvidenceV1 {
        host_offer_hash,
        viewer_offer_hash,
        selected_context,
        binding_hash,
    })
}

/// Verify that an observed selected context is exactly the deterministic result
/// of the supplied host and viewer offers.
///
/// This prevents a caller from manufacturing a selected context that was not a
/// valid mutual selection. The supplied offers still need authentication by the
/// outer handshake transcript.
pub fn verify_selected_context(
    host_offer: &CapabilityOfferV1,
    viewer_offer: &CapabilityOfferV1,
    observed_selected: &NegotiatedContextV1,
) -> Result<NegotiationEvidenceV1, NegotiatedContextError> {
    let evidence = negotiate_capabilities(host_offer, viewer_offer)?;
    if evidence.selected_context() != observed_selected {
        return Err(NegotiatedContextError::SelectedContextMismatch);
    }
    Ok(evidence)
}

/// Construct the exact causal-authority draft-04 selected capability identifier.
pub fn causal_authority_draft04_capability() -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec(),
    )
    .expect("built-in capability satisfies negotiated-context bounds")
}

/// Construct a causal-authority offer entry containing only draft-04.
pub fn causal_authority_draft04_offer_entry() -> CapabilityOfferEntryV1 {
    CapabilityOfferEntryV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        [CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec()],
    )
    .expect("built-in capability offer satisfies negotiated-context bounds")
}

fn validate_name(name: &[u8]) -> Result<(), NegotiatedContextError> {
    if name.is_empty() {
        return Err(NegotiatedContextError::EmptyCapabilityName);
    }
    if name.len() > MAX_CAPABILITY_NAME_BYTES {
        return Err(NegotiatedContextError::CapabilityNameTooLong);
    }
    Ok(())
}

fn validate_version(version: &[u8]) -> Result<(), NegotiatedContextError> {
    if version.is_empty() {
        return Err(NegotiatedContextError::EmptyCapabilityVersion);
    }
    if version.len() > MAX_CAPABILITY_VERSION_BYTES {
        return Err(NegotiatedContextError::CapabilityVersionTooLong);
    }
    Ok(())
}

fn hash_selected_capabilities(capabilities: &[NegotiatedCapabilityV1]) -> [u8; 32] {
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

fn hash_offer(entries: &[CapabilityOfferEntryV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CAPABILITY_OFFER_V1_DOMAIN);
    hasher.update(
        u32::try_from(entries.len())
            .expect("capability count is bounded below u32::MAX")
            .to_be_bytes(),
    );

    for entry in entries {
        hash_len_prefixed(&mut hasher, entry.name());
        hasher.update(
            u16::try_from(entry.versions_by_preference().len())
                .expect("version count is bounded below u16::MAX")
                .to_be_bytes(),
        );
        for version in entry.versions_by_preference() {
            hash_len_prefixed(&mut hasher, version);
        }
    }

    hasher.finalize().into()
}

fn hash_negotiation_binding(
    host_offer_hash: &[u8; 32],
    viewer_offer_hash: &[u8; 32],
    selected_context_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_BINDING_V1_DOMAIN);
    hasher.update(host_offer_hash);
    hasher.update(viewer_offer_hash);
    hasher.update(selected_context_hash);
    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("component is bounded below u16::MAX");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// Canonical negotiated-context construction or verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiatedContextError {
    /// More capability names were supplied than the protocol bound permits.
    #[error("too many negotiated capabilities")]
    TooManyCapabilities,
    /// More versions were offered for one name than the protocol permits.
    #[error("too many versions offered for one capability")]
    TooManyCapabilityVersions,
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
    /// A capability offer did not contain any versions.
    #[error("capability offer must contain at least one version")]
    EmptyCapabilityVersions,
    /// More than one offer/selection entry uses the same exact capability name.
    #[error("capability name appears more than once")]
    DuplicateCapabilityName,
    /// One offer repeats the same exact version for a capability name.
    #[error("capability offer repeats an exact version")]
    DuplicateOfferedVersion,
    /// Exact causal-authority draft-04 is absent from the selected set.
    #[error("causal-authority draft-04 is not selected")]
    CausalAuthorityNotSelected,
    /// A claimed selected context differs from deterministic mutual negotiation.
    #[error("selected capability context does not match deterministic negotiation")]
    SelectedContextMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    fn offer_entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    #[test]
    fn reproduces_authority_only_selected_vector() {
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
    fn reproduces_authority_plus_rekey_selected_vector_independent_of_order() {
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
    fn offer_name_order_is_canonical_but_version_preference_is_load_bearing() {
        let authority = offer_entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        );
        let rekey = offer_entry(b"xenia.operator-rekey", &[b"v1"]);
        let a = CapabilityOfferV1::from_entries([authority.clone(), rekey.clone()]).unwrap();
        let b = CapabilityOfferV1::from_entries([rekey, authority]).unwrap();
        assert_eq!(a, b);

        let reversed_versions = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-03", b"draft-04"],
        )])
        .unwrap();
        let preferred_draft04 = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        )])
        .unwrap();
        assert_ne!(reversed_versions.hash(), preferred_draft04.hash());
    }

    #[test]
    fn deterministic_selection_uses_only_mutual_exact_versions_and_host_preference() {
        let host = CapabilityOfferV1::from_entries([
            offer_entry(
                b"xenia.causal-authority",
                &[b"draft-04", b"draft-03"],
            ),
            offer_entry(b"xenia.operator-rekey", &[b"v2", b"v1"]),
        ])
        .unwrap();
        let viewer = CapabilityOfferV1::from_entries([
            offer_entry(
                b"xenia.causal-authority",
                &[b"draft-03", b"draft-04"],
            ),
            offer_entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();

        let evidence = negotiate_capabilities(&host, &viewer).unwrap();
        assert!(
            evidence
                .selected_context()
                .contains(b"xenia.causal-authority", b"draft-04")
        );
        assert!(
            evidence
                .selected_context()
                .contains(b"xenia.operator-rekey", b"v1")
        );
        assert!(!evidence.selected_context().contains(b"xenia.operator-rekey", b"v2"));
    }

    #[test]
    fn causal_authority_requires_both_peers_to_offer_exact_draft04() {
        let host = CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let viewer = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-03"],
        )])
        .unwrap();

        let evidence = negotiate_capabilities(&host, &viewer).unwrap();
        assert_eq!(
            evidence.require_causal_authority_draft04().unwrap_err(),
            NegotiatedContextError::CausalAuthorityNotSelected
        );
    }

    #[test]
    fn binding_commits_to_both_offers_even_when_selection_is_unchanged() {
        let host = CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let viewer_minimal =
            CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let viewer_extra = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        )])
        .unwrap();

        let minimal = negotiate_capabilities(&host, &viewer_minimal).unwrap();
        let extra = negotiate_capabilities(&host, &viewer_extra).unwrap();
        assert_eq!(minimal.selected_context(), extra.selected_context());
        assert_ne!(minimal.viewer_offer_hash(), extra.viewer_offer_hash());
        assert_ne!(minimal.binding_hash(), extra.binding_hash());
    }

    #[test]
    fn representative_offer_and_binding_vectors_are_frozen() {
        let host = CapabilityOfferV1::from_entries([
            offer_entry(
                b"xenia.causal-authority",
                &[b"draft-04", b"draft-03"],
            ),
            offer_entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let viewer = CapabilityOfferV1::from_entries([
            offer_entry(b"xenia.causal-authority", &[b"draft-04"]),
            offer_entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let evidence = negotiate_capabilities(&host, &viewer).unwrap();

        assert_eq!(
            host.hash(),
            [
                0xad, 0x1c, 0x46, 0xf1, 0x40, 0x9f, 0xc3, 0xd3, 0x9c, 0x6b, 0xd5, 0xca, 0x6c,
                0x97, 0x9c, 0x97, 0xcd, 0x3a, 0x65, 0x76, 0x39, 0x9a, 0xfc, 0xb8, 0x58, 0xfe,
                0x0f, 0x00, 0xb5, 0x18, 0x8c, 0xca,
            ]
        );
        assert_eq!(
            viewer.hash(),
            [
                0x9a, 0x75, 0x16, 0x63, 0x95, 0x23, 0xa0, 0xf1, 0x46, 0x47, 0xde, 0xf7, 0x41,
                0x2b, 0x9b, 0x87, 0xea, 0xa7, 0x63, 0xd5, 0x94, 0xeb, 0x5e, 0xfb, 0x3d, 0x43,
                0xe1, 0x49, 0xe3, 0xf2, 0x61, 0x10,
            ]
        );
        assert_eq!(
            evidence.binding_hash(),
            [
                0x32, 0x0f, 0x93, 0x74, 0xb3, 0xdb, 0x96, 0x1e, 0xd1, 0x69, 0xaa, 0xc8, 0x6d,
                0x2c, 0x3e, 0x6c, 0x2c, 0x36, 0xea, 0x88, 0x5f, 0x14, 0x3b, 0x2d, 0xd9, 0x91,
                0xc8, 0xee, 0x75, 0xf3, 0xc5, 0x7b,
            ]
        );
    }

    #[test]
    fn manufactured_selected_context_is_rejected() {
        let host = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-03"],
        )])
        .unwrap();
        let viewer = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-03"],
        )])
        .unwrap();
        let manufactured =
            NegotiatedContextV1::from_capabilities([causal_authority_draft04_capability()])
                .unwrap();

        assert_eq!(
            verify_selected_context(&host, &viewer, &manufactured).unwrap_err(),
            NegotiatedContextError::SelectedContextMismatch
        );
    }

    #[test]
    fn duplicates_and_identifier_ambiguity_fail_closed() {
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
        assert_eq!(
            CapabilityOfferEntryV1::new(
                b"xenia.causal-authority".to_vec(),
                [b"draft-04".to_vec(), b"draft-04".to_vec()],
            )
            .unwrap_err(),
            NegotiatedContextError::DuplicateOfferedVersion
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
