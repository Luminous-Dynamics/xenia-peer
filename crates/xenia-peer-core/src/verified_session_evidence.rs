// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Stable, key-free evidence exported from an already-completed Xenia handshake.
//!
//! This module deliberately exports **claims**, never traffic keys. A caller gets
//! the peer identity binding and canonical transcript/context bindings that were
//! established by `crate::handshake`, but none of the AEAD/rekey secret material.
//! Authorization is a separate layer: the daemon must bind this authenticated
//! session to its current enrollment/revocation state before treating it as
//! machine authority.

use serde::{Deserialize, Serialize};

use crate::handshake::{HandshakeOutcome, VerifiedPeerIdentity};

/// Stable schema label for the cross-layer machine-session evidence record.
pub const VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1: &str =
    "xenia-verified-machine-session-evidence-v1";

/// Stable schema label for a current authority/revocation context evaluation.
pub const MACHINE_SESSION_AUTHORITY_CONTEXT_SCHEMA_V1: &str =
    "xenia-machine-session-authority-context-v1";

const PEER_IDENTITY_BINDING_PREFIX: &str = "xenia-signing-identity-v1:blake3-256:";
const TRANSCRIPT_BINDING_PREFIX: &str = "xenia-handshake-transcript-v1:blake3-256:";
const NEGOTIATED_CONTEXT_BINDING_PREFIX: &str =
    "xenia-negotiated-session-context:blake3-256:";

/// Error while projecting or validating portable verified-session evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedSessionEvidenceError {
    /// The caller supplied an empty external session identifier.
    #[error("session_id must not be empty")]
    EmptySessionId,
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

/// Portable, immutable evidence for one authenticated machine session.
///
/// `authority_epoch` is supplied by the authority owner after the authenticated
/// peer has been admitted. Xenia's cryptographic handshake does not itself grant
/// application authority. Live revocation is intentionally absent from this
/// immutable record and belongs in [`MachineSessionAuthorityContextV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedMachineSessionEvidenceV1 {
    /// Stable schema label.
    pub schema: String,
    /// External session identifier. This is not a key and need not be secret.
    pub session_id: String,
    /// Domain-separated BLAKE3 binding to the authenticated peer's Ed25519 +
    /// ML-DSA-65 public keys.
    pub peer_identity_binding: String,
    /// Trusted-time instant at which the authority owner accepted this session.
    pub authenticated_at_ms: u64,
    /// Hard validity horizon for this evidence.
    pub expires_at_ms: u64,
    /// Authority generation that admitted the peer.
    pub authority_epoch: u64,
    /// Binding to Xenia's canonical authenticated handshake transcript.
    pub evidence_binding: String,
    /// Optional binding to the negotiated transport/capability context that was
    /// committed into the handshake.
    pub negotiated_context_binding: Option<String>,
}

impl VerifiedMachineSessionEvidenceV1 {
    /// Project a completed host-side authenticated handshake into portable,
    /// secret-free evidence.
    ///
    /// The peer parameter is the [`VerifiedPeerIdentity`] returned by
    /// `perform_host_handshake_authenticating_peer`; its two signing keys have
    /// already passed the handshake's mandatory Ed25519 + ML-DSA verification.
    pub fn from_verified_handshake(
        outcome: &HandshakeOutcome,
        peer: &VerifiedPeerIdentity,
        session_id: impl Into<String>,
        authenticated_at_ms: u64,
        expires_at_ms: u64,
        authority_epoch: u64,
    ) -> Result<Self, VerifiedSessionEvidenceError> {
        let evidence = Self {
            schema: VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1.to_string(),
            session_id: session_id.into(),
            peer_identity_binding: format!(
                "{PEER_IDENTITY_BINDING_PREFIX}{}",
                hex_lower(&peer.signing_identity_fingerprint())
            ),
            authenticated_at_ms,
            expires_at_ms,
            authority_epoch,
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

    /// Validate the stable portable record after deserialization or storage.
    ///
    /// This does **not** re-verify the handshake or grant authority. It only
    /// rejects malformed/non-canonical serialized evidence before a higher
    /// authority layer evaluates enrollment, revocation, epoch and trusted time.
    pub fn validate_shape(&self) -> Result<(), VerifiedSessionEvidenceError> {
        if self.schema != VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1 {
            return Err(VerifiedSessionEvidenceError::InvalidSchema);
        }
        if self.session_id.trim().is_empty() {
            return Err(VerifiedSessionEvidenceError::EmptySessionId);
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

/// Current, point-of-use authority facts corresponding to an immutable session
/// evidence record.
///
/// This mirrors the semantics a consumer needs to fail closed after a live
/// revocation or authority-policy change without rewriting historical handshake
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineSessionAuthorityContextV1 {
    /// Stable schema version is carried by the enclosing protocol; this type is
    /// intentionally a compact runtime value.
    pub now_ms: u64,
    /// Current authority generation for the admitted identity.
    pub authority_epoch: u64,
    /// Whether `now_ms` comes from an authority-approved trusted-time source.
    pub trusted_time_available: bool,
    /// Current revocation result, evaluated at point of use.
    pub revoked: bool,
}

impl VerifiedPeerIdentity {
    /// Domain-separated fingerprint over the exact hybrid signing identity that
    /// passed the host-side handshake.
    ///
    /// This is intentionally distinct from `host_identity_fingerprint`: the
    /// latter names the host-specific TOFU use case, while this method binds an
    /// authenticated peer on either side without relabeling it as the host.
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
    use xenia_handshake::derive_session_key_schedule;

    fn outcome() -> HandshakeOutcome {
        let transcript_hash = [0x22; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([0x33; 32]),
            host_identity_fingerprint: [0x44; 32],
        }
    }

    fn peer() -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [0x55; 32],
            ml_dsa_pk: vec![0x66; xenia_handshake::ML_DSA_65_PK_LEN],
        }
    }

    #[test]
    fn portable_evidence_contains_no_session_key_material() {
        let evidence = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome(),
            &peer(),
            "session-1",
            100,
            200,
            9,
        )
        .unwrap();
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(!encoded.contains(&"11".repeat(32)));
        assert!(encoded.contains("xenia-handshake-transcript-v1"));
        assert!(encoded.contains("xenia-signing-identity-v1"));
        assert_eq!(evidence.validate_shape(), Ok(()));
    }

    #[test]
    fn peer_fingerprint_changes_if_either_verified_key_changes() {
        let base = peer();
        let base_fingerprint = base.signing_identity_fingerprint();

        let mut ed_changed = base.clone();
        ed_changed.ed25519_pk[0] ^= 1;
        assert_ne!(base_fingerprint, ed_changed.signing_identity_fingerprint());

        let mut pq_changed = base;
        pq_changed.ml_dsa_pk[0] ^= 1;
        assert_ne!(base_fingerprint, pq_changed.signing_identity_fingerprint());
    }

    #[test]
    fn invalid_validity_interval_and_empty_id_fail_closed() {
        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &outcome(),
                &peer(),
                "",
                100,
                200,
                9,
            ),
            Err(VerifiedSessionEvidenceError::EmptySessionId)
        );
        assert_eq!(
            VerifiedMachineSessionEvidenceV1::from_verified_handshake(
                &outcome(),
                &peer(),
                "session-1",
                200,
                200,
                9,
            ),
            Err(VerifiedSessionEvidenceError::InvalidValidityInterval)
        );
    }

    #[test]
    fn deserialized_shape_rejects_schema_and_binding_drift() {
        let mut evidence = VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome(),
            &peer(),
            "session-1",
            100,
            200,
            9,
        )
        .unwrap();

        evidence.schema = "xenia-verified-machine-session-evidence-v2".into();
        assert_eq!(
            evidence.validate_shape(),
            Err(VerifiedSessionEvidenceError::InvalidSchema)
        );

        evidence.schema = VERIFIED_MACHINE_SESSION_EVIDENCE_SCHEMA_V1.into();
        evidence.peer_identity_binding = "xenia-signing-identity-v1:blake3-256:ABC".into();
        assert_eq!(
            evidence.validate_shape(),
            Err(VerifiedSessionEvidenceError::InvalidPeerIdentityBinding)
        );
    }
}
