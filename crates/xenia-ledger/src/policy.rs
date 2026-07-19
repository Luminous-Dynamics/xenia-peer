// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signature::{CURRENT_LEDGER_SIGNATURE_SUITE, SignatureSuite};

/// Stable evidence-profile summary for this crate's current ledger format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LedgerEvidenceProfile {
    /// Schema label for this profile structure.
    pub schema: &'static str,
    /// Hash used for per-entry hash-chain links.
    pub hash_chain: &'static str,
    /// Serializer used by the hash preimage.
    pub serialization: &'static str,
    /// Stable description of the entry-hash preimage layout.
    pub entry_hash_preimage: &'static str,
    /// Signature suite used by current ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Policy class represented by the current implementation.
    pub policy_profile: &'static str,
}

impl LedgerEvidenceProfile {
    /// Return true only when the ledger signature surface is post-quantum.
    pub const fn ledger_signature_is_post_quantum(self) -> bool {
        self.ledger_signature.is_post_quantum()
    }
}

/// Evidence-profile label for the current ledger implementation.
pub const CURRENT_LEDGER_EVIDENCE_PROFILE: LedgerEvidenceProfile = LedgerEvidenceProfile {
    schema: "xenia-ledger-evidence-profile-v1",
    hash_chain: "blake3-256",
    serialization: "bincode-1",
    entry_hash_preimage: "bincode-v1(seq,prev_hash,timestamp,event)",
    ledger_signature: CURRENT_LEDGER_SIGNATURE_SUITE,
    policy_profile: "hybrid-pre-pqc-v1",
};

/// Crypto policy class applied to an evidence manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoPolicyProfile {
    /// Current honest status: PQ key establishment with classical Ed25519 signatures.
    #[serde(rename = "hybrid-pre-pqc-v1")]
    HybridPrePqcV1,
    /// Target policy: PQ key establishment and PQ signatures on authority surfaces.
    #[serde(rename = "full-pqc-v1")]
    FullPqcV1,
}

impl CryptoPolicyProfile {
    /// Stable machine-readable label for evidence manifests.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "hybrid-pre-pqc-v1",
            Self::FullPqcV1 => "full-pqc-v1",
        }
    }

    /// Whether this policy requires PQ signatures for transcript and ledger authority.
    pub const fn requires_post_quantum_signatures(self) -> bool {
        matches!(self, Self::FullPqcV1)
    }
}

/// Whether a manifest explicitly permits classical signature/authentication fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradePolicy {
    /// Current compatibility mode: Ed25519 is allowed only because the manifest says so.
    #[serde(rename = "explicit-classical-signature-allowance")]
    ExplicitClassicalSignatureAllowance,
    /// Full-PQC mode: classical signature/authentication suites are rejected.
    #[serde(rename = "reject-classical-signatures")]
    RejectClassicalSignatures,
}

impl DowngradePolicy {
    /// Stable machine-readable label for evidence manifests.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::ExplicitClassicalSignatureAllowance => "explicit-classical-signature-allowance",
            Self::RejectClassicalSignatures => "reject-classical-signatures",
        }
    }
}

/// Machine-readable crypto manifest attached to exported Xenia evidence.
///
/// This is intentionally policy-oriented: it lets auditors reject a transcript
/// or ledger export before trusting individual entries when the artifact was
/// produced under a stronger policy than its algorithms satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EvidenceCryptoManifest {
    /// Schema label for this manifest shape.
    pub schema: &'static str,
    /// Policy class used to accept/reject algorithms.
    pub profile: CryptoPolicyProfile,
    /// Key-establishment suite.
    pub kem: &'static str,
    /// Signature suite authenticating the session transcript.
    pub transcript_signature: SignatureSuite,
    /// Signature suite used for consent-ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Per-entry hash/link function.
    pub hash_chain: &'static str,
    /// Session-key derivation function.
    pub kdf: &'static str,
    /// Frame sealing primitive.
    pub aead: &'static str,
    /// Downgrade/fallback behavior allowed by this evidence policy.
    pub downgrade_policy: DowngradePolicy,
}

impl EvidenceCryptoManifest {
    /// Validate that the manifest algorithms satisfy the declared policy.
    pub const fn validate_against_policy(self) -> Result<(), EvidencePolicyError> {
        match self.profile {
            CryptoPolicyProfile::HybridPrePqcV1 => {
                if self.transcript_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::PqTranscriptSignatureInHybridPrePqc);
                }
                if self.ledger_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::PqLedgerSignatureInHybridPrePqc);
                }
                if !matches!(
                    self.downgrade_policy,
                    DowngradePolicy::ExplicitClassicalSignatureAllowance
                ) {
                    return Err(
                        EvidencePolicyError::HybridPrePqcRequiresExplicitClassicalAllowance,
                    );
                }
            }
            CryptoPolicyProfile::FullPqcV1 => {
                if !self.transcript_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc);
                }
                if !self.ledger_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::ClassicalLedgerSignatureInFullPqc);
                }
                if !matches!(
                    self.downgrade_policy,
                    DowngradePolicy::RejectClassicalSignatures
                ) {
                    return Err(EvidencePolicyError::DowngradePolicyAllowsClassicalInFullPqc);
                }
            }
        }

        Ok(())
    }

    /// Whether both authority-bearing signature surfaces are post-quantum.
    pub const fn signatures_are_post_quantum(self) -> bool {
        self.transcript_signature.is_post_quantum() && self.ledger_signature.is_post_quantum()
    }
}

/// Evidence-policy validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidencePolicyError {
    /// A `hybrid-pre-pqc-v1` manifest declared a PQ transcript signature suite.
    #[error("hybrid-pre-pqc-v1 requires classical transcript signatures")]
    PqTranscriptSignatureInHybridPrePqc,
    /// A `hybrid-pre-pqc-v1` manifest declared a PQ ledger signature suite.
    #[error("hybrid-pre-pqc-v1 requires classical ledger signatures")]
    PqLedgerSignatureInHybridPrePqc,
    /// A `hybrid-pre-pqc-v1` manifest did not explicitly allow classical signatures.
    #[error("hybrid-pre-pqc-v1 requires explicit-classical-signature-allowance downgrade policy")]
    HybridPrePqcRequiresExplicitClassicalAllowance,
    /// A `full-pqc-v1` manifest declared a classical transcript signature suite.
    #[error("full-pqc-v1 rejects classical transcript signatures")]
    ClassicalTranscriptSignatureInFullPqc,
    /// A `full-pqc-v1` manifest declared a classical ledger signature suite.
    #[error("full-pqc-v1 rejects classical ledger signatures")]
    ClassicalLedgerSignatureInFullPqc,
    /// A `full-pqc-v1` manifest allowed classical-signature downgrade behavior.
    #[error("full-pqc-v1 requires reject-classical-signatures downgrade policy")]
    DowngradePolicyAllowsClassicalInFullPqc,
}

/// Current end-to-end evidence manifest emitted by Xenia's hybrid/pre-PQC stack.
pub const CURRENT_EVIDENCE_CRYPTO_MANIFEST: EvidenceCryptoManifest = EvidenceCryptoManifest {
    schema: "xenia-evidence-crypto-manifest-v1",
    profile: CryptoPolicyProfile::HybridPrePqcV1,
    kem: "ml-kem-768-fips203",
    transcript_signature: SignatureSuite::Ed25519Rfc8032,
    ledger_signature: CURRENT_LEDGER_SIGNATURE_SUITE,
    hash_chain: "blake3-256",
    kdf: "hkdf-sha256",
    aead: "chacha20-poly1305",
    downgrade_policy: DowngradePolicy::ExplicitClassicalSignatureAllowance,
};
