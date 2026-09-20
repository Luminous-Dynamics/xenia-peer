    use super::*;
    use xenia_handshake::HandshakeManager;

    fn identity(ed: u8, ml: u8) -> (HandshakeManager, HybridPublicIdentityV1) {
        let manager = HandshakeManager::from_identity_seeds([ed; 32], [ml; 32]);
        let public = HybridPublicIdentityV1 {
            ed25519_public_key: manager.identity_public_key_bytes(),
            ml_dsa_65_public_key: manager.ml_dsa_public_key_bytes().to_vec(),
        };
        (manager, public)
    }

    fn auth_pair(
        manager: &HandshakeManager,
        public: &HybridPublicIdentityV1,
        subject_sha: [u8; 32],
    ) -> Vec<SubjectAuthentication> {
        let ids = public.signer_ids().unwrap();
        let context = lineage_authentication_context_v1().unwrap();
        let ed_digest = authenticated_subject_digest(
            &context,
            &subject_sha,
            AuthenticationSuiteId::ED25519,
            &ids.ed25519,
        )
        .unwrap();
        let ml_digest = authenticated_subject_digest(
            &context,
            &subject_sha,
            AuthenticationSuiteId::ML_DSA_65_FIPS204,
            &ids.ml_dsa_65,
        )
        .unwrap();
        vec![
            SubjectAuthentication {
                suite: AuthenticationSuiteId::ED25519,
                signer_key_id: ids.ed25519,
                signature: manager.sign(&ed_digest).to_bytes().to_vec(),
            },
            SubjectAuthentication {
                suite: AuthenticationSuiteId::ML_DSA_65_FIPS204,
                signer_key_id: ids.ml_dsa_65,
                signature: manager.sign_ml_dsa(&ml_digest).to_vec(),
            },
        ]
    }

    fn policy() -> (
        HistoricalLineageTrustPolicyV1,
        HandshakeManager,
        HandshakeManager,
        HandshakeManager,
    ) {
        let (old_mgr, old_keys) = identity(0x11, 0x12);
        let (new_mgr, _) = identity(0x21, 0x22);
        let (recovery_mgr, recovery_keys) = identity(0x31, 0x32);
        (
            HistoricalLineageTrustPolicyV1 {
                stable_identity_commitment: [0xA5; 32],
                genesis: HistoricalKeyEpochV1 {
                    epoch: 1,
                    valid_from_unix_ms: 1_000,
                    keys: old_keys,
                },
                recovery_authority: Some(recovery_keys),
            },
            old_mgr,
            new_mgr,
            recovery_mgr,
        )
    }

    #[test]
    fn normal_rotation_cross_authenticates_and_preserves_history() {
        let (policy, old_mgr, new_mgr, _) = policy();
        let (_, new_keys) = identity(0x21, 0x22);
        let subject = HistoricalKeyTransitionSubjectV1 {
            stable_identity_commitment: policy.stable_identity_commitment,
            transition_sequence: 1,
            predecessor_certificate_sha256: None,
            from_epoch: policy.genesis.clone(),
            to_epoch: HistoricalKeyEpochV1 {
                epoch: 2,
                valid_from_unix_ms: 2_000,
                keys: new_keys.clone(),
            },
            kind: HistoricalKeyTransitionKindV1::Rotate,
            effective_at_unix_ms: 2_000,
            prior_epoch_trust_cutoff_unix_ms: None,
        };
        let subject_sha = transition_subject_sha256_v1(&subject).unwrap();
        let mut authentications = auth_pair(&old_mgr, &policy.genesis.keys, subject_sha);
        authentications.extend(auth_pair(&new_mgr, &new_keys, subject_sha));
        let certificate = HistoricalKeyTransitionCertificateV1 {
            subject,
            authentications,
        };
        let lineage = verify_historical_lineage_v1(&policy, &[certificate]).unwrap();
        assert_eq!(lineage.intervals().len(), 2);
        assert!(matches!(
            lineage.resolve_at(1_500),
            HistoricalEpochResolutionV1::Eligible { epoch: 1, .. }
        ));
        assert!(matches!(
            lineage.resolve_at(2_500),
            HistoricalEpochResolutionV1::Eligible { epoch: 2, .. }
        ));
    }

    #[test]
    fn compromise_recovery_creates_explicit_untrusted_window() {
        let (policy, _, new_mgr, recovery_mgr) = policy();
        let (_, new_keys) = identity(0x21, 0x22);
        let recovery_keys = policy.recovery_authority.as_ref().unwrap();
        let subject = HistoricalKeyTransitionSubjectV1 {
            stable_identity_commitment: policy.stable_identity_commitment,
            transition_sequence: 1,
            predecessor_certificate_sha256: None,
            from_epoch: policy.genesis.clone(),
            to_epoch: HistoricalKeyEpochV1 {
                epoch: 2,
                valid_from_unix_ms: 3_000,
                keys: new_keys.clone(),
            },
            kind: HistoricalKeyTransitionKindV1::RecoverCompromise,
            effective_at_unix_ms: 3_000,
            prior_epoch_trust_cutoff_unix_ms: Some(2_200),
        };
        let subject_sha = transition_subject_sha256_v1(&subject).unwrap();
        let mut authentications = auth_pair(&recovery_mgr, recovery_keys, subject_sha);
        authentications.extend(auth_pair(&new_mgr, &new_keys, subject_sha));
        let certificate = HistoricalKeyTransitionCertificateV1 {
            subject,
            authentications,
        };
        let lineage = verify_historical_lineage_v1(&policy, &[certificate]).unwrap();
        assert!(matches!(
            lineage.resolve_at(2_100),
            HistoricalEpochResolutionV1::Eligible { epoch: 1, .. }
        ));
        assert_eq!(
            lineage.resolve_at(2_500),
            HistoricalEpochResolutionV1::CompromiseWindow {
                epoch: 1,
                trust_cutoff_exclusive_unix_ms: 2_200,
                valid_until_exclusive_unix_ms: Some(3_000),
            }
        );
        assert!(matches!(
            lineage.resolve_at(3_000),
            HistoricalEpochResolutionV1::Eligible { epoch: 2, .. }
        ));
    }

    #[test]
    fn rotation_rejects_subject_substitution_and_missing_cross_signature() {
        let (policy, old_mgr, new_mgr, _) = policy();
        let (_, new_keys) = identity(0x21, 0x22);
        let mut subject = HistoricalKeyTransitionSubjectV1 {
            stable_identity_commitment: policy.stable_identity_commitment,
            transition_sequence: 1,
            predecessor_certificate_sha256: None,
            from_epoch: policy.genesis.clone(),
            to_epoch: HistoricalKeyEpochV1 {
                epoch: 2,
                valid_from_unix_ms: 2_000,
                keys: new_keys.clone(),
            },
            kind: HistoricalKeyTransitionKindV1::Rotate,
            effective_at_unix_ms: 2_000,
            prior_epoch_trust_cutoff_unix_ms: None,
        };
        let signed_sha = transition_subject_sha256_v1(&subject).unwrap();
        let mut authentications = auth_pair(&old_mgr, &policy.genesis.keys, signed_sha);
        authentications.extend(auth_pair(&new_mgr, &new_keys, signed_sha));
        authentications.pop();
        let missing = HistoricalKeyTransitionCertificateV1 {
            subject: subject.clone(),
            authentications,
        };
        assert_eq!(
            verify_historical_lineage_v1(&policy, &[missing]).unwrap_err(),
            HistoricalLineageError::AuthenticationSetMismatch
        );

        let mut authentications = auth_pair(&old_mgr, &policy.genesis.keys, signed_sha);
        authentications.extend(auth_pair(&new_mgr, &new_keys, signed_sha));
        subject.effective_at_unix_ms = 2_001;
        subject.to_epoch.valid_from_unix_ms = 2_001;
        let substituted = HistoricalKeyTransitionCertificateV1 {
            subject,
            authentications,
        };
        assert!(matches!(
            verify_historical_lineage_v1(&policy, &[substituted]),
            Err(HistoricalLineageError::Verification(
                SubjectAuthenticationVerificationError::SignatureInvalid
            ))
        ));
    }

    #[test]
    fn predecessor_digest_and_sequence_are_chain_bound() {
        let (policy, old_mgr, new_mgr, _) = policy();
        let (_, new_keys) = identity(0x21, 0x22);
        let subject = HistoricalKeyTransitionSubjectV1 {
            stable_identity_commitment: policy.stable_identity_commitment,
            transition_sequence: 2,
            predecessor_certificate_sha256: Some([0x44; 32]),
            from_epoch: policy.genesis.clone(),
            to_epoch: HistoricalKeyEpochV1 {
                epoch: 2,
                valid_from_unix_ms: 2_000,
                keys: new_keys.clone(),
            },
            kind: HistoricalKeyTransitionKindV1::Rotate,
            effective_at_unix_ms: 2_000,
            prior_epoch_trust_cutoff_unix_ms: None,
        };
        let subject_sha = transition_subject_sha256_v1(&subject).unwrap();
        let mut authentications = auth_pair(&old_mgr, &policy.genesis.keys, subject_sha);
        authentications.extend(auth_pair(&new_mgr, &new_keys, subject_sha));
        let certificate = HistoricalKeyTransitionCertificateV1 { subject, authentications };
        assert_eq!(
            verify_historical_lineage_v1(&policy, &[certificate]).unwrap_err(),
            HistoricalLineageError::NonContiguousTransitionSequence
        );
    }

    #[test]
    fn historical_resolution_is_not_trusted_time() {
        let (policy, _, _, _) = policy();
        let lineage = verify_historical_lineage_v1(&policy, &[]).unwrap();
        assert!(matches!(
            lineage.resolve_at(u64::MAX),
            HistoricalEpochResolutionV1::Eligible { epoch: 1, .. }
        ));
    }
