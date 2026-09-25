// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(feature = "pqc-signatures")]

use ml_dsa::{Generate, Keypair, MlDsa65, Signer, SigningKey};
use serde_json::Value;
use xenia_ledger::{EvidenceSignatureBackend, MlDsa65EvidenceSignatureBackend};

const FIXTURE: &str = include_str!("fixtures/mldsa65_repeated_hint_wycheproof_v1.json");

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex fixture must have even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("valid hex") as u8;
            let lo = (pair[1] as char).to_digit(16).expect("valid hex") as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture JSON must parse")
}

#[test]
fn pinned_repeated_hint_fixture_has_exact_provenance_and_shape() {
    let f = fixture();

    assert_eq!(f["schema"], "xenia-mldsa65-wycheproof-regression-v1");
    assert_eq!(f["upstream"]["repository"], "C2SP/wycheproof");
    assert_eq!(
        f["upstream"]["commit"],
        "613a2e44cb645a9890e49f8d8798cd59ef38379b"
    );
    assert_eq!(
        f["upstream"]["path"],
        "testvectors_v1/mldsa_65_verify_test.json"
    );
    assert_eq!(
        f["upstream"]["blob_sha1"],
        "049f74be9785af926623e56530ab3aa9384179e8"
    );
    assert_eq!(f["upstream"]["license"], "Apache-2.0");
    assert_eq!(f["algorithm"], "ML-DSA-65");
    assert_eq!(f["case"]["tc_id"], 19);
    assert_eq!(f["case"]["comment"], "signature with a repeated hint");
    assert_eq!(f["case"]["expected_result"], "invalid");
    assert_eq!(f["case"]["flags"][0], "InvalidHintsEncoding");

    let public_key = decode_hex(f["public_key_hex"].as_str().unwrap());
    let message = decode_hex(f["case"]["message_hex"].as_str().unwrap());
    let signature = decode_hex(f["case"]["signature_hex"].as_str().unwrap());

    assert_eq!(public_key.len(), 1952, "ML-DSA-65 public-key length drift");
    assert_eq!(message.len(), 32, "pinned Wycheproof message length drift");
    assert_eq!(signature.len(), 3309, "ML-DSA-65 signature length drift");
}

#[test]
fn current_mldsa65_backend_accepts_a_provider_generated_signature() {
    let backend = MlDsa65EvidenceSignatureBackend;
    let signing_key = SigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key().encode();
    let message = b"xenia-crypto-fv-001c2a-positive-control";
    let signature = signing_key.sign(message).encode();

    backend
        .verify_signature(verifying_key.as_ref(), message, signature.as_ref())
        .expect("current ML-DSA-65 backend must verify its own valid signature");
}

#[test]
fn current_mldsa65_backend_rejects_pinned_repeated_hint_signature() {
    let f = fixture();
    let public_key = decode_hex(f["public_key_hex"].as_str().unwrap());
    let message = decode_hex(f["case"]["message_hex"].as_str().unwrap());
    let signature = decode_hex(f["case"]["signature_hex"].as_str().unwrap());
    let backend = MlDsa65EvidenceSignatureBackend;

    let result = backend.verify_signature(&public_key, &message, &signature);
    assert!(
        result.is_err(),
        "pinned Wycheproof repeated-hint signature must be rejected"
    );
}
