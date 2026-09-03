// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Neutral ML-DSA-65 interoperability gate.
//!
//! The public key and signature were generated and independently verified by
//! OpenSSL 3.5.5 using Pure ML-DSA-65, an empty context, and the exact 32-byte
//! message `[0xA5; 32]`. The same literal vector is consumed by Symthaea's
//! independent `fips204` relying-party verifier.
//!
//! This test deliberately exercises only Xenia's production RustCrypto
//! `HandshakeManager::verify_ml_dsa` path. It introduces no alternate verifier,
//! signing implementation, or compatibility fallback.

use sha2::{Digest, Sha256};
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

const MESSAGE: [u8; 32] = [0xA5; 32];
const PUBLIC_KEY_HEX: &str = include_str!("test-vectors/openssl-3.5.5-mldsa65-public.hex");
const SIGNATURE_HEX: &str = include_str!("test-vectors/openssl-3.5.5-mldsa65-signature.hex");

const MESSAGE_SHA256: &str = "fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717";
const PUBLIC_KEY_SHA256: &str = "a0f077786cbea674bdf68eef84713d19822f1a61c0b82be7c0ec0e2292934afa";
const SIGNATURE_SHA256: &str = "a274d68afe37fdde6cd330a04fc91cef86756ea61c6f6a46c910d4999280c5e3";

const _: () = assert!(ML_DSA_65_PK_LEN == 1_952);
const _: () = assert!(ML_DSA_65_SIG_LEN == 3_309);

fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
    let input = input.trim();
    assert_eq!(input.len(), N * 2, "unexpected neutral-vector hex length");

    let bytes = input.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex byte in committed neutral vector"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing into String cannot fail");
    }
    out
}

#[test]
fn neutral_vector_bytes_match_frozen_public_commitments() {
    let public_key = decode_hex::<ML_DSA_65_PK_LEN>(PUBLIC_KEY_HEX);
    let signature = decode_hex::<ML_DSA_65_SIG_LEN>(SIGNATURE_HEX);

    assert_eq!(sha256_hex(&MESSAGE), MESSAGE_SHA256);
    assert_eq!(sha256_hex(&public_key), PUBLIC_KEY_SHA256);
    assert_eq!(sha256_hex(&signature), SIGNATURE_SHA256);
}

#[test]
fn rustcrypto_accepts_neutral_openssl_ml_dsa_65_vector() {
    let public_key = decode_hex::<ML_DSA_65_PK_LEN>(PUBLIC_KEY_HEX);
    let signature = decode_hex::<ML_DSA_65_SIG_LEN>(SIGNATURE_HEX);

    HandshakeManager::verify_ml_dsa(&public_key, &MESSAGE, &signature)
        .expect("RustCrypto must accept the neutral OpenSSL ML-DSA-65 vector");
}

#[test]
fn rustcrypto_rejects_neutral_vector_message_or_signature_mutation() {
    let public_key = decode_hex::<ML_DSA_65_PK_LEN>(PUBLIC_KEY_HEX);
    let signature = decode_hex::<ML_DSA_65_SIG_LEN>(SIGNATURE_HEX);

    let mut changed_message = MESSAGE;
    changed_message[0] ^= 1;
    assert!(HandshakeManager::verify_ml_dsa(&public_key, &changed_message, &signature).is_err());

    let mut changed_signature = signature;
    changed_signature[0] ^= 1;
    assert!(HandshakeManager::verify_ml_dsa(&public_key, &MESSAGE, &changed_signature).is_err());
}
