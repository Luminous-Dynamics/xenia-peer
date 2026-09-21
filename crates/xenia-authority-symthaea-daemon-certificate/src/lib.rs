// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical commitment contract for the Xenia daemon delegation certificate
//! referenced by portable Symthaea authorization receipts.
//!
//! The existing [`xenia_operator_proto::DaemonIdentityCertificate`] is a JSON-
//! friendly DTO whose public keys/signatures are hex strings. This crate defines
//! one canonical binary representation for hashing that certificate: decode all
//! six fields to their exact raw bytes, then encode them with explicit labels
//! under a domain separator.
//!
//! JSON field order, whitespace, and upper/lowercase hex therefore cannot change
//! the certificate commitment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use xenia_operator_proto::DaemonIdentityCertificate;

/// Domain separator for the canonical daemon delegation-certificate commitment.
pub const DAEMON_CERTIFICATE_COMMITMENT_DOMAIN_V1: &[u8] =
    b"xenia-daemon-delegation-certificate-commitment-v1\0";
/// Ed25519 public-key byte length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// ML-DSA-65 public-key byte length under Xenia's current FIPS-204 suite.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Ed25519 signature byte length.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 signature byte length under Xenia's current FIPS-204 suite.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// SHA-256 commitment length.
pub const SHA256_LEN: usize = 32;

/// Canonical raw certificate fields after strict hex decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDaemonIdentityCertificateV1 {
    /// Host identity Ed25519 public key.
    pub host_ed25519_pubkey: Vec<u8>,
    /// Host identity ML-DSA-65 public key.
    pub host_ml_dsa_pubkey: Vec<u8>,
    /// Delegated HTTP-auth Ed25519 public key.
    pub http_auth_ed25519_pubkey: Vec<u8>,
    /// Delegated HTTP-auth ML-DSA-65 public key.
    pub http_auth_ml_dsa_pubkey: Vec<u8>,
    /// Host Ed25519 signature over the daemon delegation transcript.
    pub host_ed_signature: Vec<u8>,
    /// Host ML-DSA-65 signature over the same delegation transcript.
    pub host_ml_dsa_signature: Vec<u8>,
}

impl CanonicalDaemonIdentityCertificateV1 {
    /// Parse the existing DTO into exact raw bytes, rejecting malformed hex or
    /// wrong lengths before a commitment can be produced.
    pub fn from_dto(cert: &DaemonIdentityCertificate) -> Option<Self> {
        Some(Self {
            host_ed25519_pubkey: decode_hex_exact(&cert.host_ed25519_pubkey, ED25519_PUBLIC_KEY_LEN)?,
            host_ml_dsa_pubkey: decode_hex_exact(
                &cert.host_ml_dsa_pubkey,
                ML_DSA_65_PUBLIC_KEY_LEN,
            )?,
            http_auth_ed25519_pubkey: decode_hex_exact(
                &cert.http_auth_ed25519_pubkey,
                ED25519_PUBLIC_KEY_LEN,
            )?,
            http_auth_ml_dsa_pubkey: decode_hex_exact(
                &cert.http_auth_ml_dsa_pubkey,
                ML_DSA_65_PUBLIC_KEY_LEN,
            )?,
            host_ed_signature: decode_hex_exact(&cert.host_ed_signature, ED25519_SIGNATURE_LEN)?,
            host_ml_dsa_signature: decode_hex_exact(
                &cert.host_ml_dsa_signature,
                ML_DSA_65_SIGNATURE_LEN,
            )?,
        })
    }

    /// Exact domain-separated canonical bytes hashed by [`Self::sha256`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DAEMON_CERTIFICATE_COMMITMENT_DOMAIN_V1);
        push_field(&mut out, "host_ed25519_pubkey", &self.host_ed25519_pubkey);
        push_field(&mut out, "host_ml_dsa_pubkey", &self.host_ml_dsa_pubkey);
        push_field(
            &mut out,
            "http_auth_ed25519_pubkey",
            &self.http_auth_ed25519_pubkey,
        );
        push_field(
            &mut out,
            "http_auth_ml_dsa_pubkey",
            &self.http_auth_ml_dsa_pubkey,
        );
        push_field(&mut out, "host_ed_signature", &self.host_ed_signature);
        push_field(
            &mut out,
            "host_ml_dsa_signature",
            &self.host_ml_dsa_signature,
        );
        out
    }

    /// SHA-256 of the exact canonical certificate bytes.
    pub fn sha256(&self) -> [u8; SHA256_LEN] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

/// Canonical SHA-256 commitment for an existing daemon certificate DTO.
pub fn daemon_certificate_commitment_sha256_v1(
    cert: &DaemonIdentityCertificate,
) -> Option<[u8; SHA256_LEN]> {
    CanonicalDaemonIdentityCertificateV1::from_dto(cert).map(|value| value.sha256())
}

fn decode_hex_exact(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    if value.len() != expected_len.checked_mul(2)? {
        return None;
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(expected_len);
    for pair in bytes.chunks_exact(2) {
        let hi = from_hex(pair[0])?;
        let lo = from_hex(pair[1])?;
        out.push((hi << 4) | lo);
    }
    (out.len() == expected_len).then_some(out)
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_len = u16::try_from(label.len()).expect("static label length fits u16");
    let value_len = u32::try_from(value.len()).expect("fixed certificate field fits u32");
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> DaemonIdentityCertificate {
        DaemonIdentityCertificate {
            host_ed25519_pubkey: "11".repeat(ED25519_PUBLIC_KEY_LEN),
            host_ml_dsa_pubkey: "22".repeat(ML_DSA_65_PUBLIC_KEY_LEN),
            http_auth_ed25519_pubkey: "33".repeat(ED25519_PUBLIC_KEY_LEN),
            http_auth_ml_dsa_pubkey: "44".repeat(ML_DSA_65_PUBLIC_KEY_LEN),
            host_ed_signature: "55".repeat(ED25519_SIGNATURE_LEN),
            host_ml_dsa_signature: "66".repeat(ML_DSA_65_SIGNATURE_LEN),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_certificate_commitment_vector_is_stable() {
        assert_eq!(
            hex(&daemon_certificate_commitment_sha256_v1(&cert()).unwrap()),
            "5f31eb152d82d7596b3e6c8d6541f20b9f26cc588ecf69d4da4c2999af725027"
        );
    }

    #[test]
    fn hex_case_and_json_spelling_do_not_change_raw_certificate_commitment() {
        let lower = cert();
        let mut upper = lower.clone();
        upper.host_ed25519_pubkey = upper.host_ed25519_pubkey.to_ascii_uppercase();
        upper.host_ml_dsa_pubkey = upper.host_ml_dsa_pubkey.to_ascii_uppercase();
        upper.http_auth_ed25519_pubkey = upper.http_auth_ed25519_pubkey.to_ascii_uppercase();
        upper.http_auth_ml_dsa_pubkey = upper.http_auth_ml_dsa_pubkey.to_ascii_uppercase();
        upper.host_ed_signature = upper.host_ed_signature.to_ascii_uppercase();
        upper.host_ml_dsa_signature = upper.host_ml_dsa_signature.to_ascii_uppercase();
        assert_eq!(
            daemon_certificate_commitment_sha256_v1(&lower),
            daemon_certificate_commitment_sha256_v1(&upper)
        );
    }

    #[test]
    fn every_certificate_field_is_commitment_bound() {
        let baseline = daemon_certificate_commitment_sha256_v1(&cert()).unwrap();

        let mut variants = Vec::new();
        let mut v = cert();
        v.host_ed25519_pubkey.replace_range(0..2, "aa");
        variants.push(v);
        let mut v = cert();
        v.host_ml_dsa_pubkey.replace_range(0..2, "aa");
        variants.push(v);
        let mut v = cert();
        v.http_auth_ed25519_pubkey.replace_range(0..2, "aa");
        variants.push(v);
        let mut v = cert();
        v.http_auth_ml_dsa_pubkey.replace_range(0..2, "aa");
        variants.push(v);
        let mut v = cert();
        v.host_ed_signature.replace_range(0..2, "aa");
        variants.push(v);
        let mut v = cert();
        v.host_ml_dsa_signature.replace_range(0..2, "aa");
        variants.push(v);

        for changed in variants {
            assert_ne!(
                baseline,
                daemon_certificate_commitment_sha256_v1(&changed).unwrap()
            );
        }
    }

    #[test]
    fn malformed_hex_or_wrong_lengths_fail_closed() {
        let mut value = cert();
        value.host_ed25519_pubkey.pop();
        assert!(daemon_certificate_commitment_sha256_v1(&value).is_none());

        let mut value = cert();
        value.host_ed25519_pubkey.replace_range(0..1, "z");
        assert!(daemon_certificate_commitment_sha256_v1(&value).is_none());

        let mut value = cert();
        value.host_ml_dsa_signature.pop();
        assert!(daemon_certificate_commitment_sha256_v1(&value).is_none());
    }
}
