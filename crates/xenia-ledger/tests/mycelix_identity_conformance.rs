// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use xenia_ledger::{
    Ed25519EvidenceSignatureBackend, EvidenceArtifactBinding, EvidencePublicKeyBinding,
    SignatureSuite, sign_evidence_artifact_binding_ed25519,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    fixture_schema: String,
    did: String,
    xenia_key_fingerprint_hex: String,
    xenia_signature_suite: String,
    xenia_artifact_domain: String,
    xenia_artifact_schema: String,
    subject_ref: String,
    canonical_bytes_len: usize,
    canonical_bytes_hex: String,
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "fixture hex must have an even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("valid fixture hex");
            let low = (pair[1] as char).to_digit(16).expect("valid fixture hex");
            ((high << 4) | low) as u8
        })
        .collect()
}

#[test]
fn xenia_authenticates_exact_mycelix_key_did_binding_bytes() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/mycelix-key-did-binding-v1.json"
    ))
    .expect("valid conformance fixture");

    assert_eq!(
        fixture.fixture_schema,
        "mycelix-xenia-key-binding-conformance-v1"
    );
    assert_eq!(fixture.did, fixture.subject_ref);
    assert_eq!(fixture.xenia_signature_suite, "ed25519-rfc8032");

    let artifact_bytes = decode_hex(&fixture.canonical_bytes_hex);
    assert_eq!(artifact_bytes.len(), fixture.canonical_bytes_len);

    let binding = EvidenceArtifactBinding::from_artifact(
        fixture.xenia_artifact_domain.clone(),
        fixture.xenia_artifact_schema.clone(),
        fixture.subject_ref.clone(),
        &artifact_bytes,
    )
    .expect("Mycelix fixture metadata must satisfy Xenia artifact invariants");

    let signing_key = SigningKey::from_bytes(&[0x11; 32]);
    let key_binding = EvidencePublicKeyBinding::new(
        SignatureSuite::Ed25519Rfc8032,
        signing_key.verifying_key().to_bytes().to_vec(),
    );
    let embedded_fingerprint: [u8; 32] = decode_hex(&fixture.xenia_key_fingerprint_hex)
        .try_into()
        .expect("fixture fingerprint must be exactly 32 bytes");
    assert_eq!(
        embedded_fingerprint, key_binding.public_key_fingerprint,
        "the key that signs the association must be the key fingerprint embedded in the association"
    );

    let attestation = sign_evidence_artifact_binding_ed25519(binding.clone(), &signing_key)
        .expect("fixture binding must be signable");

    let verified = attestation
        .verify(
            &artifact_bytes,
            &key_binding,
            &Ed25519EvidenceSignatureBackend,
        )
        .expect("exact Mycelix canonical bytes must verify through Xenia");

    assert_eq!(verified.binding(), &binding);
    assert_eq!(
        verified.signature_suite(),
        SignatureSuite::Ed25519Rfc8032
    );
    assert_eq!(
        verified.signer_public_key_fingerprint(),
        &embedded_fingerprint
    );
}

#[test]
fn mutation_or_semantic_relabel_cannot_reuse_the_attestation() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/mycelix-key-did-binding-v1.json"
    ))
    .expect("valid conformance fixture");
    let artifact_bytes = decode_hex(&fixture.canonical_bytes_hex);

    let binding = EvidenceArtifactBinding::from_artifact(
        fixture.xenia_artifact_domain,
        fixture.xenia_artifact_schema,
        fixture.subject_ref,
        &artifact_bytes,
    )
    .unwrap();
    let signing_key = SigningKey::from_bytes(&[0x11; 32]);
    let key_binding = EvidencePublicKeyBinding::new(
        SignatureSuite::Ed25519Rfc8032,
        signing_key.verifying_key().to_bytes().to_vec(),
    );
    let attestation = sign_evidence_artifact_binding_ed25519(binding, &signing_key).unwrap();

    let mut mutated_bytes = artifact_bytes.clone();
    let last = mutated_bytes.len() - 1;
    mutated_bytes[last] ^= 0x01;
    assert!(
        attestation
            .verify(
                &mutated_bytes,
                &key_binding,
                &Ed25519EvidenceSignatureBackend,
            )
            .is_err()
    );

    let mut relabeled = attestation.clone();
    relabeled.binding.artifact_domain = "mycelix-governance-authorization".into();
    assert!(
        relabeled
            .verify(
                &artifact_bytes,
                &key_binding,
                &Ed25519EvidenceSignatureBackend,
            )
            .is_err()
    );
}
