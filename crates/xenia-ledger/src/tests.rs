// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::hash::compute_entry_hash;
use ed25519_dalek::{Signer, SigningKey};
#[cfg(feature = "pqc-signatures")]
use std::time::SystemTime;
use uuid::Uuid;

fn sample_event(kind: ConsentKind) -> ConsentEventRecord {
    ConsentEventRecord {
        source_id: [0xAB; 32],
        session_id: Uuid::from_bytes([1u8; 16]),
        request_id: Uuid::from_bytes([2u8; 16]),
        kind,
        scope: "view screen".to_string(),
    }
}

fn new_signing_key() -> SigningKey {
    new_signing_key_from_seed(7)
}

fn new_signing_key_from_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn consent_kind_stable_names_are_contractual() {
    let cases = [
        (ConsentKind::Request, "consent.requested"),
        (ConsentKind::Approval, "consent.granted"),
        (ConsentKind::Denial, "consent.denied"),
        (ConsentKind::Revocation, "consent.revoked"),
        (ConsentKind::Violation, "consent.protocol_violation"),
        (ConsentKind::AthenaTriage, "admin.athena_triage"),
        (
            ConsentKind::AuthorizationBinding,
            "consent.authorization_binding",
        ),
        (
            ConsentKind::LifecycleTermination,
            "consent.lifecycle_termination",
        ),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.stable_name(), expected);
        assert!(expected.contains('.'));
        assert_eq!(expected, expected.to_ascii_lowercase());
        assert!(!expected.contains(' '));
    }
}

#[test]
fn consent_event_record_uses_stable_kind_name() {
    let event = sample_event(ConsentKind::Approval);
    assert_eq!(event.stable_name(), "consent.granted");
}

#[test]
fn signature_suite_labels_are_contractual() {
    assert_eq!(
        SignatureSuite::Ed25519Rfc8032.stable_label(),
        "ed25519-rfc8032"
    );
    assert_eq!(
        SignatureSuite::MlDsa65Fips204.stable_label(),
        "ml-dsa-65-fips204"
    );
    assert_eq!(
        SignatureSuite::MlDsa87Fips204.stable_label(),
        "ml-dsa-87-fips204"
    );
    assert_eq!(
        SignatureSuite::SlhDsaFips205.stable_label(),
        "slh-dsa-fips205"
    );
    assert!(!SignatureSuite::Ed25519Rfc8032.is_post_quantum());
    assert!(SignatureSuite::MlDsa65Fips204.is_post_quantum());
}

#[test]
fn stable_crypto_labels_are_used_for_json_serialization() {
    assert_eq!(
        serde_json::to_value(SignatureSuite::Ed25519Rfc8032).unwrap(),
        "ed25519-rfc8032"
    );
    assert_eq!(
        serde_json::to_value(SignatureSuite::MlDsa65Fips204).unwrap(),
        "ml-dsa-65-fips204"
    );
    assert_eq!(
        serde_json::to_value(CryptoPolicyProfile::HybridPrePqcV1).unwrap(),
        "hybrid-pre-pqc-v1"
    );
    assert_eq!(
        serde_json::to_value(CryptoPolicyProfile::FullPqcV1).unwrap(),
        "full-pqc-v1"
    );
    assert_eq!(
        serde_json::to_value(DowngradePolicy::ExplicitClassicalSignatureAllowance).unwrap(),
        "explicit-classical-signature-allowance"
    );
    assert_eq!(
        serde_json::to_value(DowngradePolicy::RejectClassicalSignatures).unwrap(),
        "reject-classical-signatures"
    );

    let manifest = serde_json::to_value(CURRENT_EVIDENCE_CRYPTO_MANIFEST).unwrap();
    assert_eq!(manifest["profile"], "hybrid-pre-pqc-v1");
    assert_eq!(manifest["transcript_signature"], "ed25519-rfc8032");
    assert_eq!(manifest["ledger_signature"], "ed25519-rfc8032");
    assert_eq!(
        manifest["downgrade_policy"],
        "explicit-classical-signature-allowance"
    );
}

#[test]
fn stable_crypto_labels_are_used_for_json_deserialization() {
    assert_eq!(
        serde_json::from_str::<SignatureSuite>(r#""ml-dsa-65-fips204""#).unwrap(),
        SignatureSuite::MlDsa65Fips204
    );
    assert_eq!(
        serde_json::from_str::<CryptoPolicyProfile>(r#""full-pqc-v1""#).unwrap(),
        CryptoPolicyProfile::FullPqcV1
    );
    assert_eq!(
        serde_json::from_str::<DowngradePolicy>(r#""reject-classical-signatures""#).unwrap(),
        DowngradePolicy::RejectClassicalSignatures
    );
}

#[test]
fn evidence_public_key_binding_computes_and_validates_fingerprint() {
    let signing_key = new_signing_key();
    let public_key = signing_key.verifying_key().to_bytes();
    let binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
    let backend = Ed25519EvidenceSignatureBackend;

    assert_eq!(binding.schema, EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA);
    assert_eq!(binding.signature_suite, SignatureSuite::Ed25519Rfc8032);
    assert_eq!(binding.public_key.len(), 32);
    assert_eq!(
        binding.public_key_fingerprint,
        compute_evidence_public_key_fingerprint(&binding.public_key)
    );
    binding
        .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend)
        .unwrap();
}

#[test]
fn evidence_public_key_binding_rejects_tampered_fingerprint() {
    let signing_key = new_signing_key();
    let public_key = signing_key.verifying_key().to_bytes();
    let mut binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
    binding.public_key_fingerprint[0] ^= 0x80;
    let backend = Ed25519EvidenceSignatureBackend;

    assert_eq!(
        binding.validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
        Err(EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch)
    );
}

#[test]
fn evidence_public_key_binding_rejects_bad_suite_and_length() {
    let backend = Ed25519EvidenceSignatureBackend;
    let bad_suite = EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, vec![0u8; 1952]);
    assert_eq!(
        bad_suite
            .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
        Err(
            EvidencePublicKeyBindingError::SignatureSuiteManifestMismatch {
                manifest_suite: SignatureSuite::Ed25519Rfc8032,
                binding_suite: SignatureSuite::MlDsa65Fips204,
            }
        )
    );

    let bad_length = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, vec![0u8; 31]);
    assert_eq!(
        bad_length
            .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
        Err(EvidencePublicKeyBindingError::BadPublicKeyLength {
            signature_suite: SignatureSuite::Ed25519Rfc8032,
            expected: 32,
            found: 31,
        })
    );
}

#[test]
fn signature_envelope_uses_stable_algorithm_label() {
    let envelope = SignatureEnvelope::ed25519([0xA5; 64]);
    assert_eq!(envelope.algorithm, "ed25519-rfc8032");
    assert_eq!(envelope.signature.len(), 64);
    assert_eq!(envelope.suite().unwrap(), SignatureSuite::Ed25519Rfc8032);
    assert!(!envelope.is_post_quantum().unwrap());
    assert_eq!(envelope.to_legacy_ed25519().unwrap(), [0xA5; 64]);
}

#[test]
fn pq_signature_envelope_shape_is_supported_before_verification_backend() {
    let envelope = SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x5A; 3309]);
    assert_eq!(envelope.algorithm, "ml-dsa-65-fips204");
    assert_eq!(envelope.suite().unwrap(), SignatureSuite::MlDsa65Fips204);
    assert!(envelope.is_post_quantum().unwrap());
    assert!(matches!(
        envelope.to_legacy_ed25519(),
        Err(SignatureEnvelopeError::UnsupportedLegacySuite { .. })
    ));
}

#[test]
fn ed25519_evidence_signature_backend_verifies_current_entries() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
    let backend = Ed25519EvidenceSignatureBackend;

    assert_eq!(backend.suite(), SignatureSuite::Ed25519Rfc8032);
    backend
        .verify_signature(&pk.to_bytes(), &entry.entry_hash, &entry.signature)
        .expect("current Ed25519 backend should verify ledger entry signatures");
}

#[test]
fn transactional_append_keeps_the_entry_when_persist_succeeds() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    let entry = chain
        .append_transactional(sample_event(ConsentKind::Request), |_entries| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(entry.seq, 0);
    assert_eq!(chain.len(), 1);
}

#[test]
fn transactional_append_rolls_back_when_persist_fails() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    // A prior, already-committed entry -- proves the rollback removes
    // only the failed entry, not the whole chain.
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let err = chain
        .append_transactional(sample_event(ConsentKind::Approval), |_entries| {
            Err("disk full")
        })
        .unwrap_err();
    assert!(matches!(
        err,
        TransactionalAppendError::Persist("disk full")
    ));
    // The failed entry must not be observable -- length and head hash
    // are exactly as before the failed call.
    assert_eq!(chain.len(), 1);
    assert_eq!(
        chain.iter().last().unwrap().event.kind,
        ConsentKind::Request
    );
}

#[test]
fn transactional_append_persist_closure_sees_the_full_entry_list_including_the_new_one() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut observed_len = 0usize;
    chain
        .append_transactional(sample_event(ConsentKind::Approval), |entries| {
            observed_len = entries.len();
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(
        observed_len, 2,
        "persist must see the just-appended entry too"
    );
}

#[test]
fn ed25519_evidence_signature_backend_rejects_bad_lengths() {
    let backend = Ed25519EvidenceSignatureBackend;

    assert!(matches!(
        backend.verify_signature(&[0u8; 31], b"message", &[0u8; 64]),
        Err(EvidenceSignatureBackendError::BadPublicKeyLength {
            expected: 32,
            found: 31
        })
    ));
    assert!(matches!(
        backend.verify_signature(&[0u8; 32], b"message", &[0u8; 63]),
        Err(EvidenceSignatureBackendError::BadSignatureLength {
            expected: 64,
            found: 63
        })
    ));
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn ml_dsa_65_backend_verifies_real_signature_bytes() {
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = b"xenia-ledger ml-dsa-65 evidence backend smoke";
    let signature = signing_key.sign(message);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.encode();
    let signature_bytes = signature.encode();
    let backend = MlDsa65EvidenceSignatureBackend;

    backend
        .verify_signature(public_key_bytes.as_ref(), message, signature_bytes.as_ref())
        .unwrap();
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn ml_dsa_65_backend_rejects_tampered_signature() {
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = b"xenia-ledger ml-dsa tamper test";
    let signature = signing_key.sign(message);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.encode();
    let mut signature_bytes = signature.encode().to_vec();
    signature_bytes[0] ^= 0x80;
    let backend = MlDsa65EvidenceSignatureBackend;

    assert_eq!(
        backend.verify_signature(public_key_bytes.as_ref(), message, &signature_bytes),
        Err(EvidenceSignatureBackendError::BadSignature)
    );
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn full_pqc_evidence_bundle_can_verify_with_ml_dsa_backend() {
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.encode();
    let timestamp = SystemTime::UNIX_EPOCH;
    let event = sample_event(ConsentKind::Approval);
    let entry_hash = compute_entry_hash(0, &[0u8; 32], &timestamp, &event).unwrap();
    let signature = signing_key.sign(&entry_hash).encode();
    let entry = LedgerEntryExport {
        seq: 0,
        prev_hash: [0u8; 32],
        timestamp,
        event,
        entry_hash,
        signature: SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, {
            let signature_bytes: &[u8] = signature.as_ref();
            signature_bytes.to_vec()
        }),
    };
    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let backend = MlDsa65EvidenceSignatureBackend;

    Verifier::verify_evidence_bundle_with_backend(
        manifest,
        &[entry],
        public_key_bytes.as_ref(),
        &backend,
    )
    .unwrap();
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn ml_dsa_65_evidence_chain_exports_real_pq_signed_entries() {
    use ml_dsa::{MlDsa65, SigningKey};

    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let mut chain = new_ml_dsa_65_evidence_chain(signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let entries = chain.export_entries();
    assert_eq!(chain.len(), 2);
    assert_eq!(entries[0].seq, 0);
    assert_eq!(entries[1].seq, 1);
    assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
    assert_eq!(
        entries[0].signature.suite().unwrap(),
        SignatureSuite::MlDsa65Fips204
    );
    assert_eq!(entries[0].signature.signature.len(), 3309);

    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let backend = MlDsa65EvidenceSignatureBackend;
    Verifier::verify_evidence_bundle_with_backend(
        manifest,
        &entries,
        &chain.public_key_bytes(),
        &backend,
    )
    .unwrap();
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn ml_dsa_65_evidence_bundle_can_verify_with_public_key_binding() {
    use ml_dsa::{MlDsa65, SigningKey};

    let seed = ml_dsa::B32::default();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let mut chain = new_ml_dsa_65_evidence_chain(signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let entries = chain.export_entries();
    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
    let backend = MlDsa65EvidenceSignatureBackend;

    assert_eq!(key_binding.public_key.len(), 1952);
    assert_eq!(
        key_binding.public_key_fingerprint,
        compute_evidence_public_key_fingerprint(&key_binding.public_key)
    );
    Verifier::verify_evidence_bundle_with_key_binding(manifest, &entries, &key_binding, &backend)
        .unwrap();
}

#[test]
fn current_evidence_profile_is_explicitly_hybrid_pre_pqc() {
    let profile = Verifier::evidence_profile();
    assert_eq!(profile.schema, "xenia-ledger-evidence-profile-v1");
    assert_eq!(profile.hash_chain, "blake3-256");
    assert_eq!(profile.ledger_signature.stable_label(), "ed25519-rfc8032");
    assert_eq!(profile.policy_profile, "hybrid-pre-pqc-v1");
    assert!(!profile.ledger_signature_is_post_quantum());
}

#[test]
fn current_evidence_manifest_allows_hybrid_pre_pqc_only_explicitly() {
    let manifest = Verifier::evidence_crypto_manifest();
    assert_eq!(manifest.schema, "xenia-evidence-crypto-manifest-v1");
    assert_eq!(manifest.profile.stable_label(), "hybrid-pre-pqc-v1");
    assert_eq!(manifest.kem, "ml-kem-768-fips203");
    assert_eq!(
        manifest.transcript_signature.stable_label(),
        "ed25519-rfc8032"
    );
    assert_eq!(manifest.ledger_signature.stable_label(), "ed25519-rfc8032");
    assert_eq!(
        manifest.downgrade_policy.stable_label(),
        "explicit-classical-signature-allowance"
    );
    assert!(!manifest.signatures_are_post_quantum());
    Verifier::verify_evidence_crypto_manifest(manifest).unwrap();
}

#[test]
fn hybrid_pre_pqc_manifest_rejects_pq_signature_surfaces() {
    let invalid_transcript = EvidenceCryptoManifest {
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    assert_eq!(
        Verifier::verify_evidence_crypto_manifest(invalid_transcript),
        Err(EvidencePolicyError::PqTranscriptSignatureInHybridPrePqc)
    );

    let invalid_ledger = EvidenceCryptoManifest {
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    assert_eq!(
        Verifier::verify_evidence_crypto_manifest(invalid_ledger),
        Err(EvidencePolicyError::PqLedgerSignatureInHybridPrePqc)
    );
}

#[test]
fn hybrid_pre_pqc_manifest_requires_explicit_classical_allowance() {
    let invalid = EvidenceCryptoManifest {
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert_eq!(
        Verifier::verify_evidence_crypto_manifest(invalid),
        Err(EvidencePolicyError::HybridPrePqcRequiresExplicitClassicalAllowance)
    );
}

#[test]
fn full_pqc_manifest_rejects_classical_signature_surfaces() {
    let invalid = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert_eq!(
        Verifier::verify_evidence_crypto_manifest(invalid),
        Err(EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc)
    );
}

#[test]
fn full_pqc_manifest_requires_reject_classical_downgrade_policy() {
    let invalid = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::ExplicitClassicalSignatureAllowance,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert_eq!(
        Verifier::verify_evidence_crypto_manifest(invalid),
        Err(EvidencePolicyError::DowngradePolicyAllowsClassicalInFullPqc)
    );
}

#[test]
fn full_pqc_manifest_accepts_only_pq_signatures_and_reject_policy() {
    let valid = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert!(valid.signatures_are_post_quantum());
    Verifier::verify_evidence_crypto_manifest(valid).unwrap();
}

#[test]
fn empty_chain_verifies_vacuously() {
    let sk = new_signing_key();
    let chain = Chain::new(sk.clone());
    let pk = sk.verifying_key();
    Verifier::verify_chain(chain.iter().cloned().collect::<Vec<_>>().as_slice(), &pk).unwrap();
}

#[test]
fn genesis_entry_has_zero_prev_hash_and_seq_zero() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
    assert_eq!(entry.seq, 0);
    assert_eq!(entry.prev_hash, [0u8; 32]);
}

#[test]
fn chain_of_five_entries_links_and_verifies() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);

    for kind in [
        ConsentKind::Request,
        ConsentKind::Approval,
        ConsentKind::Revocation,
        ConsentKind::Request,
        ConsentKind::Denial,
    ] {
        chain.append(sample_event(kind)).unwrap();
    }

    let entries: Vec<_> = chain.iter().cloned().collect();
    assert_eq!(entries.len(), 5);

    // Sequence monotone.
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.seq, i as u64);
    }

    // Hash link: each prev_hash matches previous entry_hash.
    for w in entries.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].entry_hash);
    }

    Verifier::verify_chain(&entries, &pk).unwrap();
}

#[test]
fn checkpoint_of_empty_chain_verifies_and_reports_zero_entries() {
    let sk = new_signing_key();
    let chain = Chain::new(sk);
    let checkpoint = chain.sign_checkpoint(1_700_000_000);
    assert_eq!(checkpoint.entry_count, 0);
    assert_eq!(checkpoint.head_hash, [0u8; 32]);
    Verifier::verify_checkpoint(&checkpoint).unwrap();
}

#[test]
fn checkpoint_commits_to_entry_count_and_head_hash() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let expected_head = chain.last_hash();

    let checkpoint = chain.sign_checkpoint(1_700_000_000);
    assert_eq!(checkpoint.entry_count, 2);
    assert_eq!(checkpoint.head_hash, expected_head);
    Verifier::verify_checkpoint(&checkpoint).unwrap();
}

#[test]
fn checkpoint_reveals_no_event_contents() {
    // A checkpoint's only fields are schema/entry_count/head_hash/
    // ledger_public_key/timestamp/signature -- confirm serializing one
    // never mentions the scope string an auditor-facing but
    // unauthenticated caller must not see.
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain
        .append(ConsentEventRecord {
            source_id: [0xCDu8; 32],
            session_id: Uuid::from_bytes([2u8; 16]),
            request_id: Uuid::from_bytes([3u8; 16]),
            kind: ConsentKind::Request,
            scope: "a-secret-looking-scope-string".to_string(),
        })
        .unwrap();
    let checkpoint = chain.sign_checkpoint(1_700_000_000);
    let json = serde_json::to_string(&checkpoint).unwrap();
    assert!(!json.contains("secret-looking-scope"));
}

#[test]
fn tampered_checkpoint_entry_count_is_rejected() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut checkpoint = chain.sign_checkpoint(1_700_000_000);
    checkpoint.entry_count += 1;
    assert_eq!(
        Verifier::verify_checkpoint(&checkpoint),
        Err(CheckpointError::BadSignature)
    );
}

#[test]
fn tampered_checkpoint_head_hash_is_rejected() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut checkpoint = chain.sign_checkpoint(1_700_000_000);
    checkpoint.head_hash[0] ^= 0xFF;
    assert_eq!(
        Verifier::verify_checkpoint(&checkpoint),
        Err(CheckpointError::BadSignature)
    );
}

#[test]
fn checkpoint_from_a_different_ledger_key_is_rejected() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut checkpoint = chain.sign_checkpoint(1_700_000_000);
    // Swap in an unrelated key -- the signature no longer verifies
    // under it, and the caller can't produce a valid signature without
    // the corresponding secret.
    let other = new_signing_key_from_seed(8);
    checkpoint.ledger_public_key = other.verifying_key().to_bytes();
    assert_eq!(
        Verifier::verify_checkpoint(&checkpoint),
        Err(CheckpointError::BadSignature)
    );
}

#[test]
fn checkpoint_with_unsupported_schema_is_rejected() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut checkpoint = chain.sign_checkpoint(1_700_000_000);
    checkpoint.schema = "some-other-schema-v1".to_string();
    assert_eq!(
        Verifier::verify_checkpoint(&checkpoint),
        Err(CheckpointError::UnsupportedSchema {
            schema: "some-other-schema-v1".to_string()
        })
    );
}

#[test]
fn checkpoint_head_hash_matches_last_entry_hash_for_a_full_export() {
    // The property the daemon's authenticated export endpoint relies
    // on: an export covering the whole chain ties to the public
    // checkpoint via a plain equality check, no Merkle proof needed
    // for a linear hash chain.
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    for kind in [
        ConsentKind::Request,
        ConsentKind::Approval,
        ConsentKind::Revocation,
    ] {
        chain.append(sample_event(kind)).unwrap();
    }
    let entries: Vec<_> = chain.iter().cloned().collect();
    let checkpoint = chain.sign_checkpoint(1_700_000_000);

    Verifier::verify_chain(&entries, &pk).unwrap();
    Verifier::verify_checkpoint(&checkpoint).unwrap();
    assert_eq!(entries.last().unwrap().entry_hash, checkpoint.head_hash);
    assert_eq!(entries.len() as u64, checkpoint.entry_count);
}

#[test]
fn exported_entries_verify_with_signature_envelopes() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();
    assert_eq!(exported.len(), 2);
    assert_eq!(exported[0].signature.algorithm, "ed25519-rfc8032");
    assert_eq!(exported[0].signature.signature.len(), 64);
    Verifier::verify_exported_chain(&exported, &pk).unwrap();
}

#[test]
fn exported_entry_round_trips_to_legacy_shape() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let legacy = chain.iter().next().unwrap().clone();
    let exported = legacy.to_export_entry();
    let restored = exported.to_legacy_entry().unwrap();
    assert_eq!(restored, legacy);
}

#[test]
fn current_export_verifier_rejects_pq_signature_until_backend_lands() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let mut exported = chain.export_entries();
    exported[0].signature =
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x42; 3309]);

    assert_eq!(
        Verifier::verify_exported_chain(&exported, &pk),
        Err(VerifyError::UnsupportedSignatureSuite {
            seq: 0,
            signature_suite: SignatureSuite::MlDsa65Fips204,
        })
    );
}

#[test]
fn explicit_backend_rejects_entry_suite_mismatch() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut exported = chain.export_entries();
    exported[0].signature =
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x42; 3309]);

    assert_eq!(
        Verifier::verify_exported_chain_with_backend(
            &exported,
            &[0u8; 32],
            &Ed25519EvidenceSignatureBackend,
        ),
        Err(VerifyError::SignatureBackendSuiteMismatch {
            seq: 0,
            entry_suite: SignatureSuite::MlDsa65Fips204,
            backend_suite: SignatureSuite::Ed25519Rfc8032,
        })
    );
}

#[test]
fn current_export_verifier_rejects_unknown_signature_label() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let mut exported = chain.export_entries();
    exported[0].signature = SignatureEnvelope {
        algorithm: "unknown-sig-v1".to_string(),
        signature: vec![0; 64],
    };

    assert_eq!(
        Verifier::verify_exported_chain(&exported, &pk),
        Err(VerifyError::UnknownSignatureSuite {
            seq: 0,
            algorithm: "unknown-sig-v1".to_string(),
        })
    );
}

#[test]
fn current_export_verifier_rejects_bad_ed25519_length() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let mut exported = chain.export_entries();
    exported[0].signature = SignatureEnvelope::new(SignatureSuite::Ed25519Rfc8032, vec![0; 63]);

    assert_eq!(
        Verifier::verify_exported_chain(&exported, &pk),
        Err(VerifyError::BadSignatureLength {
            seq: 0,
            expected: 64,
            found: 63,
        })
    );
}

#[test]
fn tampering_with_event_kind_breaks_entry_hash() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let mut entries: Vec<_> = chain.iter().cloned().collect();
    entries[0].event.kind = ConsentKind::Denial; // flip Approval to Denial after the fact

    match Verifier::verify_chain(&entries, &pk) {
        Err(VerifyError::EntryHashMismatch { seq: 0 }) => {}
        other => panic!("expected EntryHashMismatch, got {other:?}"),
    }
}

#[test]
fn tampering_with_entry_hash_breaks_signature() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let mut entries: Vec<_> = chain.iter().cloned().collect();
    // Mutate entry_hash to something "plausibly valid" — recompute
    // for a fake event to keep EntryHashMismatch from firing first.
    let fake_event = sample_event(ConsentKind::Denial);
    entries[0].event = fake_event.clone();
    entries[0].entry_hash = compute_entry_hash(
        entries[0].seq,
        &entries[0].prev_hash,
        &entries[0].timestamp,
        &fake_event,
    )
    .unwrap();

    // entry_hash now recomputes correctly, but the signature was
    // over the ORIGINAL entry_hash, so verification fails on the
    // signature step.
    match Verifier::verify_chain(&entries, &pk) {
        Err(VerifyError::BadSignature { seq: 0 }) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn reordering_entries_breaks_hash_link() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let mut entries: Vec<_> = chain.iter().cloned().collect();
    entries.swap(0, 1); // reorder

    let err = Verifier::verify_chain(&entries, &pk).unwrap_err();
    // The OutOfOrder check fires before BrokenLink because sequence
    // numbers are checked first at each index.
    assert!(matches!(err, VerifyError::OutOfOrder { .. }));
}

#[test]
fn wrong_public_key_rejects_valid_chain() {
    let sk = new_signing_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let entries: Vec<_> = chain.iter().cloned().collect();
    let valid_pk = new_signing_key().verifying_key();
    let wrong_pk = new_signing_key_from_seed(8).verifying_key();
    assert_ne!(valid_pk.to_bytes(), wrong_pk.to_bytes());

    match Verifier::verify_chain(&entries, &wrong_pk) {
        Err(VerifyError::BadSignature { seq: 0 }) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn rehydrated_chain_can_continue_appending() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();

    let entries_out = {
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();
        chain.into_entries()
    };

    let mut chain = Chain::from_entries(entries_out, sk);
    chain.append(sample_event(ConsentKind::Revocation)).unwrap();

    let entries: Vec<_> = chain.iter().cloned().collect();
    assert_eq!(entries.len(), 3);
    Verifier::verify_chain(&entries, &pk).unwrap();
}

#[test]
fn forged_genesis_with_nonzero_prev_hash_is_rejected() {
    let sk = new_signing_key();
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let mut entries: Vec<_> = chain.iter().cloned().collect();
    // Forge a nonzero prev_hash on genesis. We have to also
    // recompute entry_hash and re-sign to get past those checks.
    entries[0].prev_hash = [0xFFu8; 32];
    entries[0].entry_hash = compute_entry_hash(
        entries[0].seq,
        &entries[0].prev_hash,
        &entries[0].timestamp,
        &entries[0].event,
    )
    .unwrap();
    entries[0].signature = sk.sign(&entries[0].entry_hash).to_bytes();

    match Verifier::verify_chain(&entries, &pk) {
        Err(VerifyError::BadGenesis) => {}
        other => panic!("expected BadGenesis, got {other:?}"),
    }
}

#[test]
fn evidence_bundle_verification_accepts_current_manifest_and_exported_chain() {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();

    Verifier::verify_evidence_bundle(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &exported, &pk).unwrap();
}

#[test]
fn evidence_bundle_verification_accepts_public_key_binding() {
    let sk = SigningKey::from_bytes(&[52u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let backend = Ed25519EvidenceSignatureBackend;

    Verifier::verify_evidence_bundle_with_key_binding(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &exported,
        &key_binding,
        &backend,
    )
    .unwrap();
}

#[test]
fn evidence_bundle_verification_rejects_tampered_public_key_binding() {
    let sk = SigningKey::from_bytes(&[53u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let mut key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    key_binding.public_key_fingerprint[0] ^= 0x40;
    let backend = Ed25519EvidenceSignatureBackend;

    assert_eq!(
        Verifier::verify_evidence_bundle_with_key_binding(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &exported,
            &key_binding,
            &backend,
        ),
        Err(EvidenceBundleVerifyError::PublicKeyBinding(
            EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch
        ))
    );
}

#[test]
fn evidence_bundle_verification_rejects_manifest_backend_suite_mismatch() {
    let sk = SigningKey::from_bytes(&[43u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let overstated_manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert_eq!(
        Verifier::verify_evidence_bundle(overstated_manifest, &exported, &pk),
        Err(EvidenceBundleVerifyError::LedgerBackendSuiteMismatch {
            manifest_suite: SignatureSuite::MlDsa65Fips204,
            backend_suite: SignatureSuite::Ed25519Rfc8032,
        })
    );
}

#[test]
fn evidence_bundle_verification_rejects_manifest_policy_before_chain_trust() {
    let sk = SigningKey::from_bytes(&[44u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let invalid_full_pqc_manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };

    assert_eq!(
        Verifier::verify_evidence_bundle(invalid_full_pqc_manifest, &exported, &pk),
        Err(EvidenceBundleVerifyError::ManifestPolicy(
            EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc
        ))
    );
}

#[test]
fn session_transcript_binding_uses_stable_hash_and_labels() {
    let session_id = Uuid::from_bytes([1u8; 16]);
    let binding = SessionTranscriptBinding::new(
        session_id,
        b"canonical xenia handshake transcript v1",
        SignatureSuite::Ed25519Rfc8032,
    );

    assert_eq!(binding.schema, SESSION_TRANSCRIPT_BINDING_SCHEMA);
    assert_eq!(
        binding.transcript_hash_algorithm,
        SESSION_TRANSCRIPT_HASH_ALGORITHM
    );
    assert_eq!(binding.session_id, session_id);
    assert_eq!(binding.transcript_hash.len(), 32);
    assert_ne!(binding.transcript_hash, [0u8; 32]);
    binding
        .validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST)
        .unwrap();
}

#[test]
fn signed_transcript_bound_evidence_bundle_accepts_current_single_session_export() {
    let sk = SigningKey::from_bytes(&[55u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia signed handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );
    let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let backend = Ed25519EvidenceSignatureBackend;

    Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &transcript_signature,
        &key_binding,
        &exported,
        &key_binding,
        &backend,
        &backend,
    )
    .unwrap();
}

#[test]
fn signed_transcript_bound_evidence_bundle_rejects_tampered_transcript_signature() {
    let sk = SigningKey::from_bytes(&[56u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia signed handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );
    let mut transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
    transcript_signature.signature.signature[0] ^= 0x80;
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let backend = Ed25519EvidenceSignatureBackend;

    assert!(matches!(
        Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &transcript_signature,
            &key_binding,
            &exported,
            &key_binding,
            &backend,
            &backend,
        ),
        Err(EvidenceBundleVerifyError::TranscriptSignatureBackend {
            signature_suite: SignatureSuite::Ed25519Rfc8032,
            source: EvidenceSignatureBackendError::BadSignature,
        })
    ));
}

#[test]
fn unsigned_transcript_bound_full_pqc_bundle_is_rejected() {
    let sk = SigningKey::from_bytes(&[57u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia unsigned full-pqc transcript",
        manifest.transcript_signature,
    );

    assert_eq!(
        Verifier::verify_transcript_bound_evidence_bundle(manifest, &binding, &exported, &pk,),
        Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc)
    );
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn full_pqc_signed_transcript_bound_bundle_can_verify_with_ml_dsa() {
    use ml_dsa::{MlDsa65, SigningKey};

    let seed = ml_dsa::B32::default();
    let ledger_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let transcript_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let mut chain = new_ml_dsa_65_evidence_chain(ledger_signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let entries = chain.export_entries();
    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let binding = SessionTranscriptBinding::new(
        entries[0].event.session_id,
        b"canonical xenia full-pqc signed handshake transcript v1",
        manifest.transcript_signature,
    );
    let transcript_signature =
        sign_session_transcript_binding_ml_dsa_65(&binding, &transcript_signing_key);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
    let backend = MlDsa65EvidenceSignatureBackend;

    Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest,
        &binding,
        &transcript_signature,
        &key_binding,
        &entries,
        &key_binding,
        &backend,
        &backend,
    )
    .unwrap();
}

#[test]
fn transcript_bound_evidence_bundle_accepts_current_single_session_export() {
    let sk = SigningKey::from_bytes(&[45u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );

    Verifier::verify_transcript_bound_evidence_bundle(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &exported,
        &pk,
    )
    .unwrap();
}

#[test]
fn transcript_bound_evidence_bundle_rejects_empty_ledger() {
    let sk = SigningKey::from_bytes(&[46u8; 32]);
    let pk = sk.verifying_key();
    let binding = SessionTranscriptBinding::new(
        Uuid::from_bytes([1u8; 16]),
        b"canonical xenia handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );

    assert_eq!(
        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &[],
            &pk,
        ),
        Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle)
    );
}

#[test]
fn transcript_bound_evidence_bundle_rejects_session_mismatch_before_chain_trust() {
    let sk = SigningKey::from_bytes(&[47u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let original_session = exported[0].event.session_id;
    let binding_session = Uuid::from_bytes([9u8; 16]);
    let binding = SessionTranscriptBinding::new(
        binding_session,
        b"canonical xenia handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );

    assert_eq!(
        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &exported,
            &pk,
        ),
        Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
            seq: 0,
            binding_session_id: binding_session,
            entry_session_id: original_session,
        })
    );
}

#[test]
fn transcript_binding_rejects_manifest_signature_mismatch() {
    let binding = SessionTranscriptBinding::new(
        Uuid::from_bytes([1u8; 16]),
        b"canonical xenia handshake transcript v1",
        SignatureSuite::MlDsa65Fips204,
    );

    assert_eq!(
        binding.validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST),
        Err(TranscriptBindingError::TranscriptSignatureSuiteMismatch {
            manifest_suite: SignatureSuite::Ed25519Rfc8032,
            binding_suite: SignatureSuite::MlDsa65Fips204,
        })
    );
}

#[test]
fn transcript_binding_rejects_all_zero_hash_placeholder() {
    let binding = SessionTranscriptBinding::from_hash(
        Uuid::from_bytes([1u8; 16]),
        [0u8; 32],
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );

    assert_eq!(
        binding.validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST),
        Err(TranscriptBindingError::EmptyTranscriptHash)
    );
}

#[test]
fn sealed_signed_transcript_bound_bundle_accepts_current_single_session_export() {
    let sk = SigningKey::from_bytes(&[58u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia sealed signed handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );
    let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let bundle_seal = sign_evidence_bundle_seal_ed25519(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &key_binding,
        &exported,
        &key_binding,
        &sk,
    )
    .unwrap();
    let backend = Ed25519EvidenceSignatureBackend;

    Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &transcript_signature,
        &bundle_seal,
        &key_binding,
        &exported,
        &key_binding,
        &backend,
        &backend,
    )
    .unwrap();
}

#[test]
fn sealed_signed_transcript_bound_bundle_rejects_tampered_seal_fingerprint() {
    let sk = SigningKey::from_bytes(&[59u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia sealed signed handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );
    let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let mut bundle_seal = sign_evidence_bundle_seal_ed25519(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &key_binding,
        &exported,
        &key_binding,
        &sk,
    )
    .unwrap();
    bundle_seal.ledger_public_key_fingerprint[0] ^= 0x01;
    let backend = Ed25519EvidenceSignatureBackend;

    assert_eq!(
        Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &transcript_signature,
            &bundle_seal,
            &key_binding,
            &exported,
            &key_binding,
            &backend,
            &backend,
        ),
        Err(EvidenceBundleVerifyError::BundleSeal(
            EvidenceBundleSealError::LedgerPublicKeyFingerprintMismatch
        ))
    );
}

#[test]
fn sealed_signed_transcript_bound_bundle_rejects_tampered_seal_signature() {
    let sk = SigningKey::from_bytes(&[60u8; 32]);
    let pk = sk.verifying_key();
    let mut chain = Chain::new(sk.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    let exported = chain.export_entries();
    let binding = SessionTranscriptBinding::new(
        exported[0].event.session_id,
        b"canonical xenia sealed signed handshake transcript v1",
        CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
    );
    let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
    let mut bundle_seal = sign_evidence_bundle_seal_ed25519(
        CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        &binding,
        &key_binding,
        &exported,
        &key_binding,
        &sk,
    )
    .unwrap();
    bundle_seal.signature.signature[0] ^= 0x80;
    let backend = Ed25519EvidenceSignatureBackend;

    assert!(matches!(
        Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &transcript_signature,
            &bundle_seal,
            &key_binding,
            &exported,
            &key_binding,
            &backend,
            &backend,
        ),
        Err(EvidenceBundleVerifyError::BundleSealSignatureBackend {
            signature_suite: SignatureSuite::Ed25519Rfc8032,
            source: EvidenceSignatureBackendError::BadSignature,
        })
    ));
}

#[cfg(feature = "pqc-signatures")]
#[test]
fn full_pqc_sealed_bundle_can_verify_with_ml_dsa() {
    use ml_dsa::{MlDsa65, SigningKey};

    let seed = ml_dsa::B32::default();
    let ledger_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let transcript_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let mut chain = new_ml_dsa_65_evidence_chain(ledger_signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let entries = chain.export_entries();
    let manifest = EvidenceCryptoManifest {
        profile: CryptoPolicyProfile::FullPqcV1,
        transcript_signature: SignatureSuite::MlDsa65Fips204,
        ledger_signature: SignatureSuite::MlDsa65Fips204,
        downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
        ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
    };
    let binding = SessionTranscriptBinding::new(
        entries[0].event.session_id,
        b"canonical xenia full-pqc sealed signed handshake transcript v1",
        manifest.transcript_signature,
    );
    let transcript_signature =
        sign_session_transcript_binding_ml_dsa_65(&binding, &transcript_signing_key);
    let key_binding =
        EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
    let bundle_seal = sign_evidence_bundle_seal_ml_dsa_65(
        manifest,
        &binding,
        &key_binding,
        &entries,
        &key_binding,
        &transcript_signing_key,
    )
    .unwrap();
    let backend = MlDsa65EvidenceSignatureBackend;

    Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest,
        &binding,
        &transcript_signature,
        &bundle_seal,
        &key_binding,
        &entries,
        &key_binding,
        &backend,
        &backend,
    )
    .unwrap();
}

#[test]
fn checkpoint_monotonicity_detects_rollback_and_same_height_fork() {
    let signing_key = SigningKey::from_bytes(&[31u8; 32]);
    let mut chain = Chain::new(signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let first = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let second = chain.sign_checkpoint(101);

    Verifier::verify_checkpoint_monotonic(&first, &second).unwrap();

    let mut rollback = first.clone();
    rollback.timestamp_unix_secs = 102;
    let message = checkpoint_message(
        rollback.entry_count,
        &rollback.head_hash,
        &rollback.ledger_public_key,
        rollback.timestamp_unix_secs,
    );
    rollback.signature = SigningKey::from_bytes(&[31u8; 32])
        .sign(&message)
        .to_bytes();
    assert!(matches!(
        Verifier::verify_checkpoint_monotonic(&second, &rollback),
        Err(CheckpointContinuityError::EntryCountRegressed { .. })
    ));

    let mut fork_chain = Chain::new(SigningKey::from_bytes(&[31u8; 32]));
    fork_chain
        .append(sample_event(ConsentKind::Denial))
        .unwrap();
    let fork = fork_chain.sign_checkpoint(101);
    assert!(matches!(
        Verifier::verify_checkpoint_monotonic(&first, &fork),
        Err(CheckpointContinuityError::ForkAtSameHeight { entry_count: 1 })
    ));
}

#[test]
fn retained_checkpoint_must_be_an_exact_prefix_of_the_ledger() {
    let signing_key = SigningKey::from_bytes(&[32u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut chain = Chain::new(signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let retained = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let entries = chain.into_entries();

    Verifier::verify_checkpoint_prefix(&retained, &entries, &verifying_key).unwrap();

    let older_entries = entries[..0].to_vec();
    assert!(matches!(
        Verifier::verify_checkpoint_prefix(&retained, &older_entries, &verifying_key),
        Err(CheckpointContinuityError::CheckpointAheadOfLedger { .. })
            | Err(CheckpointContinuityError::Ledger(_))
    ));
}

#[test]
fn checkpoint_extension_requires_every_intervening_signed_entry() {
    let signing_key = SigningKey::from_bytes(&[33u8; 32]);
    let mut chain = Chain::new(signing_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let retained = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    chain.append(sample_event(ConsentKind::Revocation)).unwrap();
    let candidate = chain.sign_checkpoint(101);
    let entries = chain.into_entries();
    let suffix = &entries[retained.entry_count as usize..];

    Verifier::verify_checkpoint_extension(&retained, &candidate, suffix).unwrap();
    assert!(matches!(
        Verifier::verify_checkpoint_extension(&retained, &candidate, &suffix[..1]),
        Err(CheckpointContinuityError::ExtensionLengthMismatch { .. })
    ));

    let mut tampered = suffix.to_vec();
    tampered[0].event.scope.push_str(" tampered");
    assert!(matches!(
        Verifier::verify_checkpoint_extension(&retained, &candidate, &tampered),
        Err(CheckpointContinuityError::SuffixEntryHashMismatch { .. })
    ));
}

#[test]
fn ledger_key_transition_requires_both_epoch_keys() {
    use crate::{LedgerKeyTransition, Verifier};
    use ed25519_dalek::SigningKey;

    let old = SigningKey::from_bytes(&[41u8; 32]);
    let new = SigningKey::from_bytes(&[42u8; 32]);
    let mut old_chain = crate::Chain::new(old.clone());
    old_chain
        .append(sample_event(ConsentKind::Request))
        .unwrap();
    let previous = old_chain.sign_checkpoint(100);
    let transition = LedgerKeyTransition::sign(previous.clone(), &old, &new, 101).unwrap();

    Verifier::verify_ledger_key_transition(&transition).unwrap();

    let mut tampered = transition.clone();
    tampered.new_key_signature[0] ^= 0x80;
    assert!(Verifier::verify_ledger_key_transition(&tampered).is_err());
}

#[test]
fn ledger_key_transition_rejects_same_key_and_predated_handover() {
    use crate::{LedgerKeyTransition, LedgerKeyTransitionError};
    use ed25519_dalek::SigningKey;

    let old = SigningKey::from_bytes(&[45u8; 32]);
    let new = SigningKey::from_bytes(&[46u8; 32]);
    let chain = crate::Chain::new(old.clone());
    let previous = chain.sign_checkpoint(100);

    assert!(matches!(
        LedgerKeyTransition::sign(previous.clone(), &old, &old, 101),
        Err(LedgerKeyTransitionError::KeyUnchanged)
    ));
    assert!(matches!(
        LedgerKeyTransition::sign(previous, &old, &new, 99),
        Err(LedgerKeyTransitionError::TransitionPredatesCheckpoint)
    ));
}

#[test]
fn ledger_key_transition_authorizes_a_fresh_successor_epoch() {
    use crate::{LedgerKeyTransition, Verifier};
    use ed25519_dalek::SigningKey;

    let old = SigningKey::from_bytes(&[43u8; 32]);
    let new = SigningKey::from_bytes(&[44u8; 32]);
    let mut old_chain = crate::Chain::new(old.clone());
    old_chain
        .append(sample_event(ConsentKind::Request))
        .unwrap();
    let previous = old_chain.sign_checkpoint(100);
    let transition = LedgerKeyTransition::sign(previous.clone(), &old, &new, 101).unwrap();

    let mut successor = crate::Chain::new(new);
    successor
        .append(sample_event(ConsentKind::Request))
        .unwrap();
    let candidate = successor.sign_checkpoint(102);
    let entries = successor.iter().cloned().collect::<Vec<_>>();

    Verifier::verify_ledger_key_successor(&previous, &transition, &candidate, &entries).unwrap();
}

#[test]
fn checkpoint_witness_bundle_requires_distinct_trusted_quorum() {
    use crate::{CheckpointWitnessBundle, Verifier};
    use ed25519_dalek::SigningKey;

    let ledger_key = SigningKey::from_bytes(&[51u8; 32]);
    let witness_a = SigningKey::from_bytes(&[52u8; 32]);
    let witness_b = SigningKey::from_bytes(&[53u8; 32]);
    let mut chain = crate::Chain::new(ledger_key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let mut bundle = CheckpointWitnessBundle::new(chain.sign_checkpoint(100)).unwrap();
    bundle.sign_with(&witness_a, 101).unwrap();
    bundle.sign_with(&witness_b, 102).unwrap();

    let trusted = [
        witness_a.verifying_key().to_bytes(),
        witness_b.verifying_key().to_bytes(),
    ];
    Verifier::verify_checkpoint_witness_quorum(&bundle, &trusted, 2).unwrap();
    assert!(Verifier::verify_checkpoint_witness_quorum(&bundle, &trusted, 3).is_err());
}

#[test]
fn checkpoint_witness_bundle_enforces_the_signature_bound() {
    use crate::{CheckpointWitnessBundle, CheckpointWitnessError, MAX_CHECKPOINT_WITNESSES};
    use ed25519_dalek::SigningKey;

    let ledger_key = SigningKey::from_bytes(&[57u8; 32]);
    let chain = crate::Chain::new(ledger_key);
    let mut bundle = CheckpointWitnessBundle::new(chain.sign_checkpoint(100)).unwrap();
    for seed in 1..=MAX_CHECKPOINT_WITNESSES {
        let witness = SigningKey::from_bytes(&[seed as u8; 32]);
        bundle.sign_with(&witness, 101).unwrap();
    }
    let extra = SigningKey::from_bytes(&[65u8; 32]);
    assert!(matches!(
        bundle.sign_with(&extra, 101),
        Err(CheckpointWitnessError::TooManyWitnesses { .. })
    ));
}

#[test]
fn checkpoint_witness_bundle_rejects_tampering_and_untrusted_keys() {
    use crate::{CheckpointWitnessBundle, Verifier};
    use ed25519_dalek::SigningKey;

    let ledger_key = SigningKey::from_bytes(&[54u8; 32]);
    let witness = SigningKey::from_bytes(&[55u8; 32]);
    let other = SigningKey::from_bytes(&[56u8; 32]);
    let chain = crate::Chain::new(ledger_key);
    let mut bundle = CheckpointWitnessBundle::new(chain.sign_checkpoint(100)).unwrap();
    bundle.sign_with(&witness, 101).unwrap();

    assert!(Verifier::verify_checkpoint_witness_quorum(
        &bundle,
        &[other.verifying_key().to_bytes()],
        1,
    )
    .is_err());

    bundle.witnesses[0].signature[0] ^= 0x40;
    assert!(
        Verifier::verify_checkpoint_witness_quorum(
            &bundle,
            &[witness.verifying_key().to_bytes()],
            1,
        )
        .is_err()
    );
}

#[test]
fn archive_segment_proves_every_entry_between_checkpoints() {
    use crate::{LedgerArchiveSegment, Verifier};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[61u8; 32]);
    let mut chain = crate::Chain::new(key);
    let base = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let segment = LedgerArchiveSegment::from_chain(&chain, base, 101).unwrap();

    assert_eq!(segment.entries.len(), 2);
    Verifier::verify_ledger_archive_segment(&segment).unwrap();
}

#[test]
fn archive_segment_rejects_missing_or_tampered_entries() {
    use crate::{LedgerArchiveSegment, Verifier};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[62u8; 32]);
    let mut chain = crate::Chain::new(key);
    let base = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let segment = LedgerArchiveSegment::from_chain(&chain, base, 101).unwrap();

    let mut missing = segment.clone();
    missing.entries.pop();
    assert!(Verifier::verify_ledger_archive_segment(&missing).is_err());

    let mut tampered = segment;
    tampered.segment_digest[0] ^= 0x20;
    assert!(Verifier::verify_ledger_archive_segment(&tampered).is_err());
}

#[test]
fn archive_sequence_digest_commits_to_ordered_verified_segments() {
    let key = SigningKey::from_bytes(&[63u8; 32]);
    let mut chain = crate::Chain::new(key);
    let genesis = chain.sign_checkpoint(100);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let first = LedgerArchiveSegment::from_chain(&chain, genesis, 101).unwrap();

    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let second =
        LedgerArchiveSegment::from_chain(&chain, first.terminal_checkpoint.clone(), 102).unwrap();
    let segments = vec![first.clone(), second.clone()];

    let digest = ledger_archive_sequence_digest(&segments).unwrap();
    assert_eq!(digest, ledger_archive_sequence_digest(&segments).unwrap());

    let reordered = vec![second, first];
    assert!(ledger_archive_sequence_digest(&reordered).is_err());
    assert_eq!(
        ledger_archive_sequence_digest(&[]),
        Err(LedgerArchiveError::EmptySequence)
    );
}

#[test]
fn archive_sequence_verifier_enforces_segment_bound_before_walking() {
    let too_many = vec![
        LedgerArchiveSegment {
            schema: LEDGER_ARCHIVE_SEGMENT_SCHEMA.to_string(),
            base_checkpoint: crate::Chain::new(SigningKey::from_bytes(&[64u8; 32]))
                .sign_checkpoint(100),
            entries: Vec::new(),
            terminal_checkpoint: crate::Chain::new(SigningKey::from_bytes(&[64u8; 32]))
                .sign_checkpoint(100),
            segment_digest: [0u8; 32],
        };
        MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS + 1
    ];
    assert!(matches!(
        Verifier::verify_ledger_archive_sequence(&too_many),
        Err(LedgerArchiveError::TooManySegments { .. })
    ));
}

#[test]
fn compaction_manifest_binds_archive_recovery_and_live_head() {
    let key = SigningKey::from_bytes(&[65u8; 32]);
    let mut chain = crate::Chain::new(key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let archived = chain.sign_checkpoint(101);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();

    let manifest = chain
        .sign_compaction_manifest(archived, [0xA1; 32], [0xB2; 32], 102)
        .unwrap();
    let entries = chain.iter().cloned().collect::<Vec<_>>();
    Verifier::verify_ledger_compaction_manifest_against_entries(
        &manifest,
        &entries,
        &SigningKey::from_bytes(&[65u8; 32]).verifying_key(),
    )
    .unwrap();

    let mut tampered = manifest;
    tampered.recovery_summary_digest[0] ^= 0x01;
    assert_eq!(
        Verifier::verify_ledger_compaction_manifest(&tampered),
        Err(LedgerCompactionError::BadSignature)
    );
}

#[test]
fn compaction_manifest_refuses_regressed_or_forked_current_heads() {
    let key = SigningKey::from_bytes(&[66u8; 32]);
    let mut chain = crate::Chain::new(key.clone());
    chain.append(sample_event(ConsentKind::Request)).unwrap();
    let older_current = chain.sign_checkpoint(102);
    chain.append(sample_event(ConsentKind::Approval)).unwrap();
    let newer_archive = chain.sign_checkpoint(101);

    let regressed = LedgerCompactionManifest {
        schema: LEDGER_COMPACTION_MANIFEST_SCHEMA.to_string(),
        archived_through_checkpoint: newer_archive,
        current_checkpoint: older_current,
        archive_sequence_digest: [0xA1; 32],
        recovery_summary_digest: [0xB2; 32],
        timestamp_unix_secs: 102,
        signature: [0u8; 64],
    };
    assert_eq!(
        Verifier::verify_ledger_compaction_manifest(&regressed),
        Err(LedgerCompactionError::CurrentBeforeArchive)
    );

    let mut left = crate::Chain::new(key.clone());
    left.append(sample_event(ConsentKind::Request)).unwrap();
    let archived = left.sign_checkpoint(100);
    let mut right = crate::Chain::new(key);
    right.append(sample_event(ConsentKind::Denial)).unwrap();
    let current = right.sign_checkpoint(101);
    let forked = LedgerCompactionManifest {
        schema: LEDGER_COMPACTION_MANIFEST_SCHEMA.to_string(),
        archived_through_checkpoint: archived,
        current_checkpoint: current,
        archive_sequence_digest: [0xA1; 32],
        recovery_summary_digest: [0xB2; 32],
        timestamp_unix_secs: 101,
        signature: [0u8; 64],
    };
    assert_eq!(
        Verifier::verify_ledger_compaction_manifest(&forked),
        Err(LedgerCompactionError::ForkAtArchiveBoundary)
    );
}

#[test]
fn compaction_manifest_refuses_placeholders_and_unrelated_boundaries() {
    let key = SigningKey::from_bytes(&[66u8; 32]);
    let mut chain = crate::Chain::new(key);
    chain.append(sample_event(ConsentKind::Request)).unwrap();

    assert_eq!(
        chain.sign_compaction_manifest(chain.sign_checkpoint(100), [0u8; 32], [0xB2; 32], 101,),
        Err(LedgerCompactionError::EmptyDigest {
            field: "archive_sequence",
        })
    );

    let other = crate::Chain::new(SigningKey::from_bytes(&[67u8; 32]));
    assert!(
        chain
            .sign_compaction_manifest(other.sign_checkpoint(100), [0xA1; 32], [0xB2; 32], 101,)
            .is_err()
    );
}

#[test]
fn checkpoint_freshness_rejects_stale_and_future_anchors() {
    use crate::{CheckpointFreshnessPolicy, Verifier};
    use ed25519_dalek::SigningKey;

    let chain = crate::Chain::new(SigningKey::from_bytes(&[63u8; 32]));
    let checkpoint = chain.sign_checkpoint(100);
    let policy = CheckpointFreshnessPolicy {
        max_age_secs: Some(20),
        max_future_skew_secs: 5,
    };
    Verifier::verify_checkpoint_freshness(&checkpoint, 120, policy).unwrap();
    assert!(Verifier::verify_checkpoint_freshness(&checkpoint, 121, policy).is_err());

    let future = chain.sign_checkpoint(126);
    assert!(Verifier::verify_checkpoint_freshness(&future, 120, policy).is_err());
}

#[test]
fn checkpoint_suffix_chain_preserves_absolute_sequence_frontier() {
    let key = SigningKey::from_bytes(&[68u8; 32]);
    let public_key = key.verifying_key();
    let mut complete = crate::Chain::new(key.clone());
    complete.append(sample_event(ConsentKind::Request)).unwrap();
    let base = complete.sign_checkpoint(100);
    complete
        .append(sample_event(ConsentKind::Approval))
        .unwrap();
    let terminal = complete.sign_checkpoint(101);
    let suffix = complete.iter().skip(1).cloned().collect::<Vec<_>>();

    Verifier::verify_checkpoint_extension(&base, &terminal, &suffix).unwrap();
    let mut compacted = crate::Chain::from_checkpoint_suffix(base.clone(), suffix, key);
    assert_eq!(compacted.entry_count(), 2);
    assert_eq!(compacted.resident_len(), 1);
    assert_eq!(compacted.base_checkpoint(), Some(&base));
    assert_eq!(compacted.last_hash(), terminal.head_hash);

    let appended = compacted
        .append(sample_event(ConsentKind::Revocation))
        .unwrap();
    assert_eq!(appended.seq, 2);
    assert_eq!(appended.prev_hash, terminal.head_hash);
    assert_eq!(compacted.entry_count(), 3);
    assert_eq!(compacted.resident_len(), 2);
    Verifier::verify_checkpoint_extension(
        compacted.base_checkpoint().unwrap(),
        &compacted.sign_checkpoint(102),
        &compacted.iter().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        compacted.sign_checkpoint(102).ledger_public_key,
        public_key.to_bytes()
    );
}

#[test]
fn transactional_chain_callback_observes_compacted_anchor_and_rolls_back() {
    let key = SigningKey::from_bytes(&[69u8; 32]);
    let complete = crate::Chain::new(key.clone());
    let base = complete.sign_checkpoint(100);
    let mut compacted = crate::Chain::from_checkpoint_suffix(base, Vec::new(), key);

    let result =
        compacted.append_transactional_chain(sample_event(ConsentKind::Request), |candidate| {
            assert_eq!(candidate.entry_count(), 1);
            assert_eq!(candidate.resident_len(), 1);
            assert!(candidate.base_checkpoint().is_some());
            Err("disk full")
        });
    assert!(matches!(
        result,
        Err(crate::TransactionalAppendError::Persist("disk full"))
    ));
    assert_eq!(compacted.entry_count(), 0);
    assert_eq!(compacted.resident_len(), 0);
    assert!(compacted.base_checkpoint().is_some());
}
