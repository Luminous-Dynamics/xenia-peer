// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Stable, key-free evidence exported from an already-completed Xenia handshake.
//!
//! This module deliberately exports **claims**, never traffic keys. A caller gets
//! the peer identity binding and canonical transcript/context bindings that were
//! established by `crate::handshake`, but none of the AEAD/rekey secret material.
//! Authorization is a separate layer: a completed handshake must first be admitted
//! by `crate::machine_authority` before portable machine-session evidence can be minted.

use serde::{Deserialize, Deserializer, Serialize};

use crate::handshake::{HandshakeOutcome, VerifiedPeerIdentity};
use crate::machine_authority::MachineAuthorityAdmissionV1;

/// Stable schema label for the cross-layer machine-session evidence record.
pub const VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1: &str =
    "xenia-verified-machine-session-evidence-v1";

const PEER_IDENTITY_BINDING_PREFIX: &str = "xenia-signing-identity-v1:blake3-256:";
const TRANSCRIPT_BINDING_PREFIX: &str = "xenia-handshake-transcript-v1:blake3-256:";
const NEGOTIATED_CONTEXT_BINDING_PREFIX: &str =
    "xenia-negotiated-session-context:blake3-256:";

/// Error while projecting or validating portable verified-session evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedSessionEvidenceError {
    /// The caller supplied an empty or non-canonical external session identifier.
    #[error("session_id must be nonempty canonical printable text")]
    InvalidSessionId,
    /// A machine-authority admission was minted for a different hybrid peer identity.
    #[error("machine authority admission does not match the verified handshake peer")]
    AdmissionIdentityMismatch,
    /// A machine-authority admission was minted for a different handshake transcript/context.
    #[error("machine authority admission does not match the verified handshake outcome")]
    AdmissionHandshakeMismatch,
    /// The requested evidence validity interval is empty or reversed.
    #[error("expires_at_ms must be greater than authenticated_at_ms")]
    InvalidValidityInterval,
    /// A deserialized record claimed a schema other than the exact v1 schema.
    #[error("unsupported verified machine-session evidence schema")]
    InvalidSchema,
    /// The peer identity binding is not the canonical v1 BLAKE3-256 form.
    #[error("peer_identity_binding is not canonical v1 BLAKE3-256 evidence")]
    InvalidPeerIdentityBinding,
    /// The handshake transcript binding is not the canonical v1 BLAKE3-256 form.
    #[error("evidence_binding is not canonical v1 handshake evidence")]
    InvalidEvidenceBinding,
    /// The optional negotiated-context binding is not canonical when present.
    #[error("negotiated_context_binding is not canonical v1 context evidence")]
    InvalidNegotiatedContextBinding,
}

/// Portable, immutable evidence for one authenticated **and locally admitted** machine session.
///
/// The constructor requires a [`MachineAuthorityAdmissionV1`] minted by local machine policy for
/// the exact peer **and exact handshake outcome**, so a cryptographically valid handshake cannot
/// acquire an authority epoch/lifetime directly from its caller and an old admission cannot be
/// migrated to another session. The wire schema remains portable and deserializable for
/// storage/transport; deserializing this shape alone is **not** cryptographic authentication or
/// current authority. A consumer must establish provenance and re-evaluate live
/// revocation/epoch/time state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedMachineSessionEvidenceV1 {
    schema: String,
    session_id: String,
    peer_identity_binding: String,
    authenticated_at_ms: u64,
    expires_at_ms: u64,
    authority_epoch: u64,
    evidence_binding: String,
    negotiated_context_binding: Option<String>,
}

/// Exact v1 serde surface. Keeping this separate lets deserialization validate
/// the record before exposing the public typed value and rejects undeclared fields
/// instead of silently carrying ambiguous evidence under the same schema label.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedMachineSessionEvidenceWireV1 {
    schema: String,
    session_id: String,
    peer_identity_binding: String,
    authenticated_at_ms: u64,
    expires_at_ms: u64,
    authority_epoch: u64,
    evidence_binding: String,
    negotiated_context_binding: Option<String>,
}

impl<'de> Deserialize<'de> for VerifiedMachineSessionEvidenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = VerifiedMachineSessionEvidenceWireV1::deserialize(deserializer)?;
        let evidence = Self {
            schema: wire.schema,
            session_id: wire.session_id,
            peer_identity_binding: wire.peer_identity_binding,
            authenticated_at_ms: wire.authenticated_at_ms,
            expires_at_ms: wire.expires_at_ms,
            authority_epoch: wire.authority_epoch,
            evidence_binding: wire.evidence_binding,
            negotiated_context_binding: wire.negotiated_context_binding,
        };
        evidence.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(evidence)
    }
}

impl VerifiedMachineSessionEvidenceV1 {
    /// Project a completed host-side authenticated handshake and a matching local policy
    /// admission into portable, secret-free evidence.
    ///
    /// The peer parameter is the [`VerifiedPeerIdentity`] returned by
    /// `perform_host_handshake_authenticating_peer`; its two signing keys have already passed the
    /// handshake's mandatory Ed25519 + ML-DSA verification. `admission` must have been minted by
    /// `MachineAuthorityPolicyV1` for this exact peer and this exact handshake outcome.
    pub fn from_verified_handshake(
        outcome: &HandshakeOutcome,
        peer: &VerifiedPeerIdentity,
        session_id: impl Into<String>,
        admission: &MachineAuthorityAdmissionV1,
    ) -> Result<Self, VerifiedSessionEvidenceError> {
        let peer_fingerprint = peer.signing_identity_fingerprint();
        if admission.peer_identity_fingerprint() != peer_fingerprint {
            return Err(VerifiedSessionEvidenceError::AdmissionIdentityMismatch);
        }
        if !admission.matches_handshake(outcome) {
            return Err(VerifiedSessionEvidenceError::AdmissionHandshakeMismatch);
        }

        let evidence = Self {
            schema: VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1.to_string(),
            session_id: session_id.into(),
            peer_identity_binding: format!(
                "{PEER_IDENTITY_BINDING_PREFIX}{}",
                hex_lower(&peer_fingerprint)
            ),
            authenticated_at_ms: admission.admitted_at_ms(),
            expires_at_ms: admission.expires_at_ms(),
            authority_epoch: admission.authority_epoch(),
            evidence_binding: format!(
                "{TRANSCRIPT_BINDING_PREFIX}{}",
                hex_lower(&outcome.transcript_hash)
            ),
            negotiated_context_binding: outcome.negotiated_context_hash.map(|hash| {
                format!(
                    "{NEGOTIATED_CONTEXT_BINDING_PREFIX}{}",
                    hex_lower(&hash)
                )
            }),
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    /// Stable provider schema label.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// External, non-secret session identifier.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Canonical binding to the authenticated hybrid signing identity.
    pub fn peer_identity_binding(&self) -> &str {
        &self.peer_identity_binding
    }

    /// Trusted-time instant at which local machine authority admitted this session.
    pub const fn authenticated_at_ms(&self) -> u64 {
        self.authenticated_at_ms
    }

    /// Exclusive hard validity horizon minted by local machine policy.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Authority generation that admitted the machine identity.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Binding to Xenia's canonical authenticated handshake transcript.
    pub fn evidence_binding(&self) -> &str {
        &self.evidence_binding
    }

    /// Optional binding to the negotiated transport/capability context.
    pub fn negotiated_context_binding(&self) -> Option<&str> {
        self.negotiated_context_binding.as_deref()
    }

    /// Validate the stable portable record after construction or storage.
    ///
    /// Deserialization calls this automatically. This does **not** re-verify the handshake or
    /// prove current authority; it guarantees only that the record is the exact canonical v1
    /// evidence shape before a higher authority layer evaluates provenance, enrollment,
    /// revocation, epoch and trusted time.
    pub fn validate_shape(&self) -> Result<(), VerifiedSessionEvidenceError> {
        if self.schema != VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1 {
            return Err(VerifiedSessionEvidenceError::InvalidSchema);
        }
        if self.session_id.trim().is_empty()
            || self.session_id.trim() != self.session_id
            || self.session_id.chars().any(char::is_control)
        {
            return Err(VerifiedSessionEvidenceError::InvalidSessionId);
        }
        if self.expires_at_ms <= self.authenticated_at_ms {
            return Err(VerifiedSessionEvidenceError::InvalidValidityInterval);
        }
        if !valid_binding(&self.peer_identity_binding, PEER_IDENTITY_BINDING_PREFIX) {
            return Err(VerifiedSessionEvidenceError::InvalidPeerIdentityBinding);
        }
        if !valid_binding(&self.evidence_binding, TRANSCRIPT_BINDING_PREFIX) {
            return Err(VerifiedSessionEvidenceError::InvalidEvidenceBinding);
        }
        if self
            .negotiated_context_binding
            .as_deref()
            .is_some_and(|binding| !valid_binding(binding, NEGOTIATED_CONTEXT_BINDING_PREFIX))
        {
            return Err(VerifiedSessionEvidenceError::InvalidNegotiatedContextBinding);
        }
        Ok(())
    }
}

/// Current, point-of-use authority facts corresponding to immutable session evidence.
///
/// This value has private fields, no public constructor and no serde implementation. Only the
/// machine-authority module can mint it from current local policy state; application code cannot
/// manufacture a convenient `revoked = false`/epoch snapshot and pass it off as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineSessionAuthorityContextV1 {
    now_ms: u64,
    authority_epoch: u64,
    trusted_time_available: bool,
    revoked: bool,
}

impl MachineSessionAuthorityContextV1 {
    pub(crate) const fn from_policy(
        now_ms: u64,
        authority_epoch: u64,
        trusted_time_available: bool,
        revoked: bool,
    ) -> Self {
        Self {
            now_ms,
            authority_epoch,
            trusted_time_available,
            revoked,
        }
    }

    /// Current trusted-time instant supplied by the machine authority policy.
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Current authority generation for the admitted identity.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Whether current time comes from an authority-approved trusted-time source.
    pub const fn trusted_time_available(&self) -> bool {
        self.trusted_time_available
    }

    /// Current revocation result evaluated at point of use.
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

impl VerifiedPeerIdentity {
    /// Domain-separated fingerprint over the exact hybrid signing identity that
    /// passed the host-side handshake.
    ///
    /// This is intentionally distinct from `host_identity_fingerprint`: the latter names the
    /// host-specific TOFU use case, while this method binds an authenticated peer on either side
    /// without relabeling it as the host.
    pub fn signing_identity_fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"xenia-signing-identity-fingerprint-v1");
        hasher.update(&self.ed25519_pk);
        hasher.update(&(self.ml_dsa_pk.len() as u64).to_le_bytes());
        hasher.update(&self.ml_dsa_pk);
        *hasher.finalize().as_bytes()
    }
}

fn valid_binding(binding: &str, prefix: &str) -> bool {
    let Some(hex) = binding.strip_prefix(prefix) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_authority::{MachineAuthorityPolicyV1, MachineAuthorityRecordV1};
    use xenia_handshake::derive_session_key_schedule;

    fn outcome(byte: u8) -> HandshakeOutcome {
        let transcript_hash = [byte; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([byte.wrapping_add(0x11); 32]),
            host_identity_fingerprint: [0x44; 32],
        }
    }

    fn peer(byte: u8) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [byte; 32],
            ml_dsa_pk: vec![byte.wrapping_add(1); xenia_handshake::ML_DSA_65_PK_LEN],
        }
    }

    fn admission_for(
        peer: &VerifiedPeerIdentity,
        outcome: &HandshakeOutcome,
    ) -> MachineAuthorityAdmissionV1 {
        let policy = MachineAuthorityPolicyV1::new(
            [MachineAuthorityRecordV1 {
                peer_identity_fingerprint: peer.signing_identity_fingerprint(),
                authority_epoch: 9,
                valid_from_ms: 50,
                valid_until_ms: 1_000,
                revoked: false,
            }],
            100,
        )
        .unwrap();
        policy
            .admit_verified_session(peer, outcome, 100, true)
            .unwrap()
    }

    #[test]
    fn portable_evidence_contains_no_session_key_material() {
        let peer = peer(0x55);
        let outcome = outcome(0x22);
        let admission = admission_for(&peer, &outcome);
        let evidence = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome,
            &peer,
            "session-1",
            &admission,
        )
        .unwrap();
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(!encoded.contains(&"11".repeat(32)));
        assert!(encoded.contains("xenia-handshake-transcript-v1"));
        assert!(encoded.contains("xenia-signing-identity-v1"));
        assert_eq!(evidence.authenticated_at_ms(), 100);
        assert_eq!(evidence.expires_at_ms(), 200);
        assert_eq!(evidence.authority_epoch(), 9);
        assert_eq!(evidence.validate_shape(), Ok(()));
    }

    #[test]
    fn admission_must_match_exact_verified_peer_and_handshake() {
        let admitted_peer = peer(0x55);
        let other_peer = peer(0x77);
        let admitted_outcome = outcome(0x22);
        let other_outcome = outcome(0x33);
        let admission = admission_for(&admitted_peer, &admitted_outcome);

        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &admitted_outcome,
                &other_peer,
                "session-1",
                &admission,
            ),
            Err(VerifiedSessionEvidenceError::AdmissionIdentityMismatch)
        );
        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &other_outcome,
                &admitted_peer,
                "session-1",
                &admission,
            ),
            Err(VerifiedSessionEvidenceError::AdmissionHandshakeMismatch)
        );
    }

    #[test]
    fn peer_fingerprint_changes_if_either_verified_key_changes() {
        let base = peer(0x55);
        let base_fingerprint = base.signing_identity_fingerprint();

        let mut ed_changed = base.clone();
        ed_changed.ed25519_pk[0] ^= 1;
        assert_ne!(base_fingerprint, ed_changed.signing_identity_fingerprint());

        let mut pq_changed = base;
        pq_changed.ml_dsa_pk[0] ^= 1;
        assert_ne!(base_fingerprint, pq_changed.signing_identity_fingerprint());
    }

    #[test]
    fn empty_or_noncanonical_session_id_fails_closed() {
        let peer = peer(0x55);
        let outcome = outcome(0x22);
        let admission = admission_for(&peer, &outcome);
        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &outcome,
                &peer,
                "",
                &admission,
            ),
            Err(VerifiedSessionEvidenceError::InvalidSessionId)
        );
        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &outcome,
                &peer,
                " session-1",
                &admission,
            ),
            Err(VerifiedSessionEvidenceError::InvalidSessionId)
        );
    }

    #[test]
    fn deserialization_rejects_schema_binding_and_field_drift() {
        let peer = peer(0x55);
        let outcome = outcome(0x22);
        let admission = admission_for(&peer, &outcome);
        let evidence = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome,
            &peer,
            "session-1",
            &admission,
        )
        .unwrap();

        let mut value = serde_json::to_value(&evidence).unwrap();
        value["schema"] = serde_json::Value::String(
            "xenia-verified-machine-session-evidence-v2".into(),
        );
        assert!(serde_json::from_value::<VerifiedMachineSessionEvidenceV1>(value).is_err());

        let mut value = serde_json::to_value(&evidence).unwrap();
        value["peer_identity_binding"] =
            serde_json::Value::String("xenia-signing-identity-v1:blake3-256:ABC".into());
        assert!(serde_json::from_value::<VerifiedMachineSessionEvidenceV1>(value).is_err());

        let mut value = serde_json::to_value(&evidence).unwrap();
        value["unexpected_authority_claim"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<VerifiedMachineSessionEvidenceV1>(value).is_err());
    }
}
