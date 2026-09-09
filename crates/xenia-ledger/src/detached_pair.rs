// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opaque composition of two independently verified detached-message contracts.
//!
//! Some downstream operations require two distinct authorities over two distinct
//! canonical messages. Merely carrying two signature objects is insufficient: an
//! integration could accidentally reuse one verifier key for both roles, omit one
//! proof, or pair a retained witness with different message bytes.
//!
//! This module remains application-agnostic. Role IDs are ordered composition
//! metadata supplied by the caller; Xenia does not assign application semantics to
//! them. The verifier-owned security facts enforced here are that both inputs are
//! already opaque [`VerifiedDetachedMessageContractMatch`] values, each still binds
//! its independently supplied canonical message, the messages are distinct, and the
//! trusted verifier-key fingerprints are distinct.

use crate::VerifiedDetachedMessageContractMatch;
use thiserror::Error;

/// Opaque ordered witness that two distinct detached-message contracts were both
/// retained and re-bound to independently supplied canonical messages.
///
/// The fields are private and this type deliberately implements neither `Serialize`
/// nor `Deserialize`. It can only be constructed by
/// [`require_distinct_verified_detached_message_contract_pair`]. A process/storage
/// boundary therefore requires returning to raw evidence and rebuilding both
/// verifier-owned contract matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDetachedMessageContractPair {
    first_role_id: String,
    first: VerifiedDetachedMessageContractMatch,
    second_role_id: String,
    second: VerifiedDetachedMessageContractMatch,
}

impl VerifiedDetachedMessageContractPair {
    /// Caller-defined application role label retained for the first contract.
    pub fn first_role_id(&self) -> &str {
        &self.first_role_id
    }

    /// First verifier-owned contract witness.
    pub fn first(&self) -> &VerifiedDetachedMessageContractMatch {
        &self.first
    }

    /// Caller-defined application role label retained for the second contract.
    pub fn second_role_id(&self) -> &str {
        &self.second_role_id
    }

    /// Second verifier-owned contract witness.
    pub fn second(&self) -> &VerifiedDetachedMessageContractMatch {
        &self.second
    }
}

/// Require two existing verifier-owned contract witnesses to form one ordered,
/// distinct-authority pair.
///
/// This function performs no cryptography. Each input must already have been
/// produced by `require_verified_detached_message_contract(...)`. The supplied
/// canonical messages are rechecked against those opaque witnesses so a caller
/// cannot pair a valid witness with different bytes. The pair additionally requires
/// distinct role labels, distinct proof-domain message digests, and distinct trusted
/// verifier-key fingerprints.
#[allow(clippy::too_many_arguments)]
pub fn require_distinct_verified_detached_message_contract_pair(
    first_role_id: impl Into<String>,
    first: &VerifiedDetachedMessageContractMatch,
    first_message: &[u8],
    second_role_id: impl Into<String>,
    second: &VerifiedDetachedMessageContractMatch,
    second_message: &[u8],
) -> Result<VerifiedDetachedMessageContractPair, VerifiedDetachedMessageContractPairError> {
    let first_role_id = first_role_id.into();
    let second_role_id = second_role_id.into();

    if first_role_id.trim().is_empty() {
        return Err(VerifiedDetachedMessageContractPairError::EmptyFirstRoleId);
    }
    if second_role_id.trim().is_empty() {
        return Err(VerifiedDetachedMessageContractPairError::EmptySecondRoleId);
    }
    if first_role_id == second_role_id {
        return Err(VerifiedDetachedMessageContractPairError::DuplicateRoleId(
            first_role_id,
        ));
    }
    if !first.matches_message(first_message) {
        return Err(VerifiedDetachedMessageContractPairError::FirstMessageMismatch);
    }
    if !second.matches_message(second_message) {
        return Err(VerifiedDetachedMessageContractPairError::SecondMessageMismatch);
    }
    if first.message_digest() == second.message_digest() {
        return Err(VerifiedDetachedMessageContractPairError::DuplicateMessageDigest);
    }
    if first.public_key_fingerprint() == second.public_key_fingerprint() {
        return Err(VerifiedDetachedMessageContractPairError::DuplicateTrustedRoot);
    }

    Ok(VerifiedDetachedMessageContractPair {
        first_role_id,
        first: first.clone(),
        second_role_id,
        second: second.clone(),
    })
}

/// Failure to compose two verifier-owned detached-message contract witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifiedDetachedMessageContractPairError {
    /// The first application role label is empty or whitespace-only.
    #[error("first detached-contract pair role id must not be empty")]
    EmptyFirstRoleId,
    /// The second application role label is empty or whitespace-only.
    #[error("second detached-contract pair role id must not be empty")]
    EmptySecondRoleId,
    /// A single role label cannot satisfy both ordered positions.
    #[error("detached-contract pair role id {0} is duplicated")]
    DuplicateRoleId(String),
    /// The first retained witness belongs to different canonical message bytes.
    #[error("first detached-contract witness does not match the supplied canonical message")]
    FirstMessageMismatch,
    /// The second retained witness belongs to different canonical message bytes.
    #[error("second detached-contract witness does not match the supplied canonical message")]
    SecondMessageMismatch,
    /// Two roles must not collapse onto one canonical proof-domain message.
    #[error("detached-contract pair requires two distinct canonical message digests")]
    DuplicateMessageDigest,
    /// Two roles must be backed by distinct trusted verifier-key fingerprints.
    #[error("detached-contract pair requires two distinct trusted verifier-key fingerprints")]
    DuplicateTrustedRoot,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Ed25519EvidenceSignatureBackend, EvidencePublicKeyBinding, SignatureEnvelope,
        SignatureSuite, require_verified_detached_message_contract, verify_detached_message,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn contract_for(
        key_byte: u8,
        message: &[u8],
    ) -> VerifiedDetachedMessageContractMatch {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            signing_key.verifying_key().to_bytes(),
        );
        let signature = SignatureEnvelope::ed25519(signing_key.sign(message).to_bytes());
        let trusted = binding.public_key_fingerprint;
        let verified = verify_detached_message(
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
            &signature,
            &binding,
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();
        require_verified_detached_message_contract(
            &verified,
            SignatureSuite::Ed25519Rfc8032,
            trusted,
            message,
        )
        .unwrap()
    }

    #[test]
    fn distinct_messages_and_roots_produce_ordered_opaque_pair() {
        let observer_message = b"frozen configuration observation";
        let commissioning_message = b"observed commissioning authorization";
        let observer = contract_for(0x31, observer_message);
        let commissioning = contract_for(0x52, commissioning_message);

        let pair = require_distinct_verified_detached_message_contract_pair(
            "configuration-observer",
            &observer,
            observer_message,
            "commissioning-authority",
            &commissioning,
            commissioning_message,
        )
        .unwrap();

        assert_eq!(pair.first_role_id(), "configuration-observer");
        assert_eq!(pair.second_role_id(), "commissioning-authority");
        assert!(pair.first().matches_message(observer_message));
        assert!(pair.second().matches_message(commissioning_message));
        assert_ne!(
            pair.first().public_key_fingerprint(),
            pair.second().public_key_fingerprint()
        );
    }

    #[test]
    fn duplicate_role_id_is_rejected() {
        let first_message = b"first authority message";
        let second_message = b"second authority message";
        let first = contract_for(0x31, first_message);
        let second = contract_for(0x52, second_message);

        assert_eq!(
            require_distinct_verified_detached_message_contract_pair(
                "same-role",
                &first,
                first_message,
                "same-role",
                &second,
                second_message,
            ),
            Err(VerifiedDetachedMessageContractPairError::DuplicateRoleId(
                "same-role".to_owned()
            ))
        );
    }

    #[test]
    fn first_message_substitution_is_rejected() {
        let first = contract_for(0x31, b"observer message");
        let second_message = b"commissioning message";
        let second = contract_for(0x52, second_message);

        assert_eq!(
            require_distinct_verified_detached_message_contract_pair(
                "observer",
                &first,
                b"substituted observer message",
                "commissioner",
                &second,
                second_message,
            ),
            Err(VerifiedDetachedMessageContractPairError::FirstMessageMismatch)
        );
    }

    #[test]
    fn second_message_substitution_is_rejected() {
        let first_message = b"observer message";
        let first = contract_for(0x31, first_message);
        let second = contract_for(0x52, b"commissioning message");

        assert_eq!(
            require_distinct_verified_detached_message_contract_pair(
                "observer",
                &first,
                first_message,
                "commissioner",
                &second,
                b"substituted commissioning message",
            ),
            Err(VerifiedDetachedMessageContractPairError::SecondMessageMismatch)
        );
    }

    #[test]
    fn same_canonical_message_is_rejected_even_under_distinct_roots() {
        let message = b"one message cannot satisfy two roles";
        let first = contract_for(0x31, message);
        let second = contract_for(0x52, message);

        assert_eq!(
            require_distinct_verified_detached_message_contract_pair(
                "observer",
                &first,
                message,
                "commissioner",
                &second,
                message,
            ),
            Err(VerifiedDetachedMessageContractPairError::DuplicateMessageDigest)
        );
    }

    #[test]
    fn same_trusted_root_is_rejected_even_for_distinct_messages() {
        let first_message = b"observer message";
        let second_message = b"commissioning message";
        let first = contract_for(0x31, first_message);
        let second = contract_for(0x31, second_message);

        assert_eq!(
            require_distinct_verified_detached_message_contract_pair(
                "observer",
                &first,
                first_message,
                "commissioner",
                &second,
                second_message,
            ),
            Err(VerifiedDetachedMessageContractPairError::DuplicateTrustedRoot)
        );
    }

    #[test]
    fn pair_order_is_explicit_and_not_inferred_from_messages() {
        let first_message = b"message A";
        let second_message = b"message B";
        let first = contract_for(0x31, first_message);
        let second = contract_for(0x52, second_message);

        let pair = require_distinct_verified_detached_message_contract_pair(
            "role-B",
            &first,
            first_message,
            "role-A",
            &second,
            second_message,
        )
        .unwrap();

        assert_eq!(pair.first_role_id(), "role-B");
        assert_eq!(pair.second_role_id(), "role-A");
        assert_eq!(pair.first().message_digest(), first.message_digest());
        assert_eq!(pair.second().message_digest(), second.message_digest());
    }
}
