// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical local policy over an authenticated Xenia negotiated-capability set.
//!
//! Negotiation and policy are deliberately separate trust concerns:
//!
//! - `xenia-negotiation` proves what both peers offered and deterministically selected.
//! - this crate states what the local endpoint is willing to accept.
//! - the outer handshake authenticates the negotiation binding.
//!
//! A peer cannot satisfy local downgrade policy merely by authenticating *some*
//! mutually supported selection. Consequential callers evaluate the authenticated
//! selected context against a [`NegotiationPolicyV1`] before enabling the feature.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest, Sha256};
use xenia_negotiation::{
    MAX_NEGOTIATED_CAPABILITIES, NegotiatedCapabilityV1, NegotiatedContextV1,
};

/// Domain separator for canonical local negotiation policy hashes.
pub const NEGOTIATION_POLICY_V1_DOMAIN: &[u8] = b"xenia.negotiation-policy.v1\0";

/// Maximum number of exact entries in either policy list.
pub const MAX_POLICY_CAPABILITIES: usize = MAX_NEGOTIATED_CAPABILITIES;

/// How strictly selected capabilities are constrained beyond the required set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyModeV1 {
    /// Every required exact capability must be selected; additional capabilities
    /// are permitted because they remain authenticated by the negotiation binding.
    Minimum = 0,
    /// Every required exact capability must be selected and every selected exact
    /// capability must also appear in the local allow-list.
    AllowList = 1,
}

/// Canonical local acceptance policy for an authenticated selected context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationPolicyV1 {
    mode: PolicyModeV1,
    required: Vec<NegotiatedCapabilityV1>,
    allowed: Vec<NegotiatedCapabilityV1>,
    hash: [u8; 32],
}

impl NegotiationPolicyV1 {
    /// Require a set of exact capabilities while permitting authenticated extras.
    pub fn minimum_required<I>(required: I) -> Result<Self, NegotiationPolicyError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let required = canonical_required(required)?;
        let allowed = Vec::new();
        let hash = hash_policy(PolicyModeV1::Minimum, &required, &allowed);
        Ok(Self {
            mode: PolicyModeV1::Minimum,
            required,
            allowed,
            hash,
        })
    }

    /// Require exact capabilities and constrain all selected capabilities to an
    /// explicit exact allow-list.
    ///
    /// Multiple allowed versions for the same capability name are valid because
    /// the negotiated selected context still contains exactly one version per
    /// name. Required entries themselves may not contain multiple versions for
    /// one name because that policy could never be satisfied.
    pub fn allow_list<I, J>(required: I, allowed: J) -> Result<Self, NegotiationPolicyError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
        J: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let required = canonical_required(required)?;
        let allowed = canonical_allowed(allowed)?;
        if required
            .iter()
            .any(|requirement| allowed.binary_search(requirement).is_err())
        {
            return Err(NegotiationPolicyError::RequiredCapabilityNotAllowed);
        }
        let hash = hash_policy(PolicyModeV1::AllowList, &required, &allowed);
        Ok(Self {
            mode: PolicyModeV1::AllowList,
            required,
            allowed,
            hash,
        })
    }

    /// Policy mode.
    pub fn mode(&self) -> PolicyModeV1 {
        self.mode
    }

    /// Canonical exact capabilities that must be present.
    pub fn required(&self) -> &[NegotiatedCapabilityV1] {
        &self.required
    }

    /// Canonical exact allow-list; empty for [`PolicyModeV1::Minimum`].
    pub fn allowed(&self) -> &[NegotiatedCapabilityV1] {
        &self.allowed
    }

    /// SHA-256 hash of the canonical local policy.
    ///
    /// This is audit evidence, not peer-negotiation evidence. A receipt may bind
    /// it to record which local downgrade policy was enforced.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Evaluate an already-authenticated deterministic selected context.
    pub fn evaluate(&self, selected: &NegotiatedContextV1) -> Result<(), NegotiationPolicyError> {
        if self.required.iter().any(|required| {
            !selected.contains(required.name(), required.version())
        }) {
            return Err(NegotiationPolicyError::RequiredCapabilityMissing);
        }

        if self.mode == PolicyModeV1::AllowList
            && selected
                .capabilities()
                .iter()
                .any(|capability| self.allowed.binary_search(capability).is_err())
        {
            return Err(NegotiationPolicyError::SelectedCapabilityNotAllowed);
        }

        Ok(())
    }
}

fn canonical_required<I>(required: I) -> Result<Vec<NegotiatedCapabilityV1>, NegotiationPolicyError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let mut required: Vec<_> = required.into_iter().collect();
    if required.len() > MAX_POLICY_CAPABILITIES {
        return Err(NegotiationPolicyError::TooManyPolicyCapabilities);
    }
    required.sort();
    if required
        .windows(2)
        .any(|pair| pair[0].name() == pair[1].name())
    {
        return Err(NegotiationPolicyError::DuplicateRequiredCapabilityName);
    }
    Ok(required)
}

fn canonical_allowed<I>(allowed: I) -> Result<Vec<NegotiatedCapabilityV1>, NegotiationPolicyError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let mut allowed: Vec<_> = allowed.into_iter().collect();
    if allowed.len() > MAX_POLICY_CAPABILITIES {
        return Err(NegotiationPolicyError::TooManyPolicyCapabilities);
    }
    allowed.sort();
    if allowed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(NegotiationPolicyError::DuplicateAllowedCapability);
    }
    Ok(allowed)
}

fn hash_policy(
    mode: PolicyModeV1,
    required: &[NegotiatedCapabilityV1],
    allowed: &[NegotiatedCapabilityV1],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_POLICY_V1_DOMAIN);
    hasher.update([mode as u8]);
    hash_capability_list(&mut hasher, required);
    hash_capability_list(&mut hasher, allowed);
    hasher.finalize().into()
}

fn hash_capability_list(hasher: &mut Sha256, capabilities: &[NegotiatedCapabilityV1]) {
    hasher.update(
        u32::try_from(capabilities.len())
            .expect("policy capability count is bounded below u32::MAX")
            .to_be_bytes(),
    );
    for capability in capabilities {
        hash_len_prefixed(hasher, capability.name());
        hash_len_prefixed(hasher, capability.version());
    }
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("negotiation identifiers are u16-bounded");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// Failure while constructing or enforcing a local negotiation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationPolicyError {
    /// A policy list exceeds the protocol's selected-capability bound.
    #[error("too many capabilities in negotiation policy")]
    TooManyPolicyCapabilities,
    /// Required policy contains two versions for one exact capability name.
    #[error("required policy contains more than one version for a capability name")]
    DuplicateRequiredCapabilityName,
    /// Allow-list repeats an exact capability/version pair.
    #[error("allow-list repeats an exact capability/version pair")]
    DuplicateAllowedCapability,
    /// A required exact capability is absent from the allow-list.
    #[error("required capability is not present in allow-list")]
    RequiredCapabilityNotAllowed,
    /// The authenticated selected context is missing an exact local requirement.
    #[error("authenticated negotiation is missing a required exact capability")]
    RequiredCapabilityMissing,
    /// The authenticated selected context contains a capability outside the local allow-list.
    #[error("authenticated negotiation selected a capability outside the local allow-list")]
    SelectedCapabilityNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    fn selected(capabilities: impl IntoIterator<Item = NegotiatedCapabilityV1>) -> NegotiatedContextV1 {
        NegotiatedContextV1::from_capabilities(capabilities).unwrap()
    }

    #[test]
    fn minimum_policy_rejects_downgrade_but_allows_authenticated_extras() {
        let policy = NegotiationPolicyV1::minimum_required([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();

        assert!(policy
            .evaluate(&selected([
                cap(b"xenia.causal-authority", b"draft-04"),
                cap(b"xenia.operator-rekey", b"v1"),
            ]))
            .is_ok());
        assert_eq!(
            policy
                .evaluate(&selected([cap(b"xenia.causal-authority", b"draft-03")]))
                .unwrap_err(),
            NegotiationPolicyError::RequiredCapabilityMissing
        );
    }

    #[test]
    fn allow_list_rejects_unreviewed_selected_extensions() {
        let authority = cap(b"xenia.causal-authority", b"draft-04");
        let rekey = cap(b"xenia.operator-rekey", b"v1");
        let policy = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [authority.clone(), rekey.clone()],
        )
        .unwrap();

        assert!(policy.evaluate(&selected([authority.clone(), rekey])).is_ok());
        assert_eq!(
            policy
                .evaluate(&selected([
                    authority,
                    cap(b"xenia.future-extension", b"v1"),
                ]))
                .unwrap_err(),
            NegotiationPolicyError::SelectedCapabilityNotAllowed
        );
    }

    #[test]
    fn required_multi_version_policy_fails_closed_as_unsatisfiable() {
        assert_eq!(
            NegotiationPolicyV1::minimum_required([
                cap(b"xenia.causal-authority", b"draft-03"),
                cap(b"xenia.causal-authority", b"draft-04"),
            ])
            .unwrap_err(),
            NegotiationPolicyError::DuplicateRequiredCapabilityName
        );
    }

    #[test]
    fn allow_list_must_contain_every_required_exact_capability() {
        assert_eq!(
            NegotiationPolicyV1::allow_list(
                [cap(b"xenia.causal-authority", b"draft-04")],
                [cap(b"xenia.causal-authority", b"draft-03")],
            )
            .unwrap_err(),
            NegotiationPolicyError::RequiredCapabilityNotAllowed
        );
    }

    #[test]
    fn policy_hash_vectors_are_frozen() {
        let authority = cap(b"xenia.causal-authority", b"draft-04");
        let minimum = NegotiationPolicyV1::minimum_required([authority.clone()]).unwrap();
        assert_eq!(
            hex::encode(minimum.hash()),
            "6456c40af9e104b82be0b0faf501c404c057d7b55928d339720a9c208f6eef0f"
        );

        let allow_list = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [authority, cap(b"xenia.operator-rekey", b"v1")],
        )
        .unwrap();
        assert_eq!(
            hex::encode(allow_list.hash()),
            "ed37983b2b76cbc7689d80ef2f008bdaf469483bbc2aa1caaed2352992b7fca4"
        );
    }
}
