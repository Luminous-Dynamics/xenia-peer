// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit compatibility helpers for legacy Mycelix authenticated-proof v2.
//!
//! This crate intentionally does not depend on `xenia-zk-protocol` and V3 does
//! not depend on this crate. A caller must choose the legacy API explicitly.
//! There is no protocol sniffing and no "try V3, then V2" fallback.
//!
//! The crate reconstructs the historical signing digest only. Signature
//! verification (including legacy Dilithium5 key policy) belongs in an explicit
//! authentication adapter so legacy cryptography cannot become a new-proof
//! default by dependency accident.

use sha2::{Digest, Sha256};
use thiserror::Error;

pub const LEGACY_MYCELIX_PROTOCOL_VERSION: u32 = 2;
pub const LEGACY_MYCELIX_SIGNING_DOMAIN: &[u8] =
    b"MYCELIX:AuthenticatedProof:SignedEnvelope:v2";

const MAX_COMPONENT_LEN: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LegacyV2Error {
    #[error("legacy protocol version must be exactly 2")]
    WrongProtocolVersion,
    #[error("legacy backend wire id is unknown: {0}")]
    UnknownBackend(u8),
    #[error("legacy domain tag is not canonical: {0}")]
    InvalidDomain(&'static str),
}

/// Historical backend wire identifiers. Values are frozen protocol data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyBackendId {
    Risc0,
    Winterfell,
    Binius,
    Miden,
}

impl LegacyBackendId {
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::Risc0 => 1,
            Self::Winterfell => 2,
            Self::Binius => 3,
            Self::Miden => 4,
        }
    }

    pub const fn from_wire_id(value: u8) -> Result<Self, LegacyV2Error> {
        match value {
            1 => Ok(Self::Risc0),
            2 => Ok(Self::Winterfell),
            3 => Ok(Self::Binius),
            4 => Ok(Self::Miden),
            other => Err(LegacyV2Error::UnknownBackend(other)),
        }
    }
}

/// Inputs required to reconstruct the exact legacy V2 signed digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyMycelixV2Body<'a> {
    pub domain_tag: &'a [u8],
    pub protocol_version: u32,
    pub backend: LegacyBackendId,
    pub client_id: [u8; 32],
    pub timestamp_unix_seconds: u64,
    pub nonce: [u8; 32],
    pub public_inputs_hash: [u8; 32],
    pub proof: &'a [u8],
    pub energy_millijoules: u64,
}

impl LegacyMycelixV2Body<'_> {
    /// Reconstruct the exact digest historically signed by Mycelix v2.
    pub fn signed_digest(&self) -> Result<[u8; 32], LegacyV2Error> {
        if self.protocol_version != LEGACY_MYCELIX_PROTOCOL_VERSION {
            return Err(LegacyV2Error::WrongProtocolVersion);
        }
        validate_legacy_domain_tag(self.domain_tag)?;

        let mut hasher = Sha256::new();
        let domain_len = u32::try_from(self.domain_tag.len())
            .map_err(|_| LegacyV2Error::InvalidDomain("domain length exceeds v2 framing"))?;

        hasher.update(LEGACY_MYCELIX_SIGNING_DOMAIN);
        hasher.update(domain_len.to_le_bytes());
        hasher.update(self.domain_tag);
        hasher.update(self.protocol_version.to_le_bytes());
        hasher.update([self.backend.wire_id()]);
        hasher.update(self.client_id);
        hasher.update(self.timestamp_unix_seconds.to_le_bytes());
        hasher.update(self.nonce);
        hasher.update(self.public_inputs_hash);
        hasher.update(Sha256::digest(self.proof));
        hasher.update(self.energy_millijoules.to_le_bytes());
        Ok(hasher.finalize().into())
    }
}

/// Validate historical `ZTML:{Cluster}:{ProofType}:vN` canonical form.
pub fn validate_legacy_domain_tag(domain: &[u8]) -> Result<(), LegacyV2Error> {
    let value = std::str::from_utf8(domain)
        .map_err(|_| LegacyV2Error::InvalidDomain("domain is not UTF-8"))?;
    let mut parts = value.split(':');
    if parts.next() != Some("ZTML") {
        return Err(LegacyV2Error::InvalidDomain("missing ZTML namespace"));
    }
    let cluster = parts
        .next()
        .ok_or(LegacyV2Error::InvalidDomain("missing cluster"))?;
    let proof_type = parts
        .next()
        .ok_or(LegacyV2Error::InvalidDomain("missing proof type"))?;
    let version = parts
        .next()
        .ok_or(LegacyV2Error::InvalidDomain("missing version"))?;
    if parts.next().is_some() {
        return Err(LegacyV2Error::InvalidDomain("unexpected extra component"));
    }
    validate_component(cluster)?;
    validate_component(proof_type)?;
    let numeric = version
        .strip_prefix('v')
        .ok_or(LegacyV2Error::InvalidDomain("version must start with v"))?
        .parse::<u32>()
        .map_err(|_| LegacyV2Error::InvalidDomain("version is not an unsigned integer"))?;
    if numeric == 0 {
        return Err(LegacyV2Error::InvalidDomain("version must be non-zero"));
    }
    Ok(())
}

fn validate_component(value: &str) -> Result<(), LegacyV2Error> {
    if value.is_empty() || value.len() > MAX_COMPONENT_LEN {
        return Err(LegacyV2Error::InvalidDomain("component length is invalid"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(LegacyV2Error::InvalidDomain(
            "component contains non-canonical characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_mycelix_v2_golden_digest_is_preserved() {
        let body = LegacyMycelixV2Body {
            domain_tag: b"ZTML:Test:Unit:v1",
            protocol_version: 2,
            backend: LegacyBackendId::Winterfell,
            client_id: [0xAA; 32],
            timestamp_unix_seconds: 1_700_000_000,
            nonce: [0xBB; 32],
            public_inputs_hash: [0xCC; 32],
            proof: &[1, 2, 3, 4],
            energy_millijoules: 0,
        };
        assert_eq!(
            hex_lower(&body.signed_digest().unwrap()),
            "83d7aa6eb5cb2bf0af48d617d4176947b50ab341fd9a96bc859ad3e1829fcfd7"
        );
    }

    #[test]
    fn malformed_ztml_prefix_is_not_enough() {
        assert!(validate_legacy_domain_tag(b"ZTML:Test:Unit:Extra:v1").is_err());
    }

    #[test]
    fn legacy_version_is_explicit_and_fail_closed() {
        let body = LegacyMycelixV2Body {
            domain_tag: b"ZTML:Test:Unit:v1",
            protocol_version: 3,
            backend: LegacyBackendId::Winterfell,
            client_id: [0xAA; 32],
            timestamp_unix_seconds: 1_700_000_000,
            nonce: [0xBB; 32],
            public_inputs_hash: [0xCC; 32],
            proof: &[1, 2, 3, 4],
            energy_millijoules: 0,
        };
        assert_eq!(body.signed_digest(), Err(LegacyV2Error::WrongProtocolVersion));
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
}
