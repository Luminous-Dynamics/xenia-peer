/// Verify an entire transition chain from an externally pinned genesis.
pub fn verify_historical_lineage_v1(
    policy: &HistoricalLineageTrustPolicyV1,
    certificates: &[HistoricalKeyTransitionCertificateV1],
) -> Result<VerifiedHistoricalLineageV1, HistoricalLineageError> {
    policy.validate()?;
    let mut lineage = VerifiedHistoricalLineageV1 {
        stable_identity_commitment: policy.stable_identity_commitment,
        intervals: vec![VerifiedHistoricalKeyIntervalV1 {
            epoch: policy.genesis.clone(),
            valid_until_exclusive_unix_ms: None,
            trust_cutoff_exclusive_unix_ms: None,
            opened_by_certificate_sha256: None,
            closed_by_certificate_sha256: None,
        }],
        last_certificate_sha256: None,
    };

    for certificate in certificates {
        verify_and_apply_transition(policy, &mut lineage, certificate)?;
    }
    Ok(lineage)
}

fn verify_and_apply_transition(
    policy: &HistoricalLineageTrustPolicyV1,
    lineage: &mut VerifiedHistoricalLineageV1,
    certificate: &HistoricalKeyTransitionCertificateV1,
) -> Result<(), HistoricalLineageError> {
    let subject = &certificate.subject;
    let expected_sequence = lineage.intervals.len() as u64;
    if subject.transition_sequence != expected_sequence {
        return Err(HistoricalLineageError::NonContiguousTransitionSequence);
    }
    if subject.predecessor_certificate_sha256 != lineage.last_certificate_sha256 {
        return Err(HistoricalLineageError::PredecessorCertificateMismatch);
    }
    if subject.stable_identity_commitment != policy.stable_identity_commitment {
        return Err(HistoricalLineageError::StableIdentityMismatch);
    }
    require_nonzero(subject.stable_identity_commitment, "stable identity commitment")?;
    subject.from_epoch.validate()?;
    subject.to_epoch.validate()?;

    let current = lineage
        .intervals
        .last()
        .expect("verified lineage always contains pinned genesis");
    if subject.from_epoch != current.epoch {
        return Err(HistoricalLineageError::FromEpochMismatch);
    }
    if subject.to_epoch.epoch != subject.from_epoch.epoch + 1 {
        return Err(HistoricalLineageError::EpochNotIncremented);
    }
    if subject.effective_at_unix_ms <= subject.from_epoch.valid_from_unix_ms {
        return Err(HistoricalLineageError::InvalidEffectiveTime);
    }
    if subject.to_epoch.valid_from_unix_ms != subject.effective_at_unix_ms {
        return Err(HistoricalLineageError::SuccessorStartMismatch);
    }

    let from_ids = subject.from_epoch.keys.signer_ids()?;
    let to_ids = subject.to_epoch.keys.signer_ids()?;
    let subject_sha = transition_subject_sha256_v1(subject)?;

    let expected_signers = match subject.kind {
        HistoricalKeyTransitionKindV1::Rotate => {
            if from_ids == to_ids {
                return Err(HistoricalLineageError::RotationDidNotChangeKeys);
            }
            if subject.prior_epoch_trust_cutoff_unix_ms.is_some() {
                return Err(HistoricalLineageError::RotationHasCompromiseCutoff);
            }
            canonical_expected_signers(&[
                (AuthenticationSuiteId::ED25519, from_ids.ed25519),
                (AuthenticationSuiteId::ML_DSA_65_FIPS204, from_ids.ml_dsa_65),
                (AuthenticationSuiteId::ED25519, to_ids.ed25519),
                (AuthenticationSuiteId::ML_DSA_65_FIPS204, to_ids.ml_dsa_65),
            ])
        }
        HistoricalKeyTransitionKindV1::RecoverCompromise => {
            let recovery = policy
                .recovery_authority
                .as_ref()
                .ok_or(HistoricalLineageError::RecoveryAuthorityMissing)?;
            let recovery_ids = recovery.signer_ids()?;
            if recovery_ids.ed25519 == to_ids.ed25519 || recovery_ids.ml_dsa_65 == to_ids.ml_dsa_65 {
                return Err(HistoricalLineageError::RecoveryAuthorityOverlap);
            }
            let cutoff = subject
                .prior_epoch_trust_cutoff_unix_ms
                .ok_or(HistoricalLineageError::InvalidCompromiseCutoff)?;
            if cutoff < subject.from_epoch.valid_from_unix_ms || cutoff > subject.effective_at_unix_ms {
                return Err(HistoricalLineageError::InvalidCompromiseCutoff);
            }
            canonical_expected_signers(&[
                (AuthenticationSuiteId::ED25519, recovery_ids.ed25519),
                (AuthenticationSuiteId::ML_DSA_65_FIPS204, recovery_ids.ml_dsa_65),
                (AuthenticationSuiteId::ED25519, to_ids.ed25519),
                (AuthenticationSuiteId::ML_DSA_65_FIPS204, to_ids.ml_dsa_65),
            ])
        }
    };

    verify_exact_authentication_set(
        certificate,
        &expected_signers,
        subject.kind,
        &subject.from_epoch.keys,
        &subject.to_epoch.keys,
        policy.recovery_authority.as_ref(),
        subject_sha,
    )?;

    let certificate_sha = transition_certificate_sha256_v1(certificate)?;
    let current = lineage
        .intervals
        .last_mut()
        .expect("verified lineage always contains pinned genesis");
    current.valid_until_exclusive_unix_ms = Some(subject.effective_at_unix_ms);
    current.trust_cutoff_exclusive_unix_ms = subject.prior_epoch_trust_cutoff_unix_ms;
    current.closed_by_certificate_sha256 = Some(certificate_sha);

    lineage.intervals.push(VerifiedHistoricalKeyIntervalV1 {
        epoch: subject.to_epoch.clone(),
        valid_until_exclusive_unix_ms: None,
        trust_cutoff_exclusive_unix_ms: None,
        opened_by_certificate_sha256: Some(certificate_sha),
        closed_by_certificate_sha256: None,
    });
    lineage.last_certificate_sha256 = Some(certificate_sha);
    Ok(())
}

fn canonical_expected_signers(
    signers: &[(AuthenticationSuiteId, [u8; 32])],
) -> Vec<(AuthenticationSuiteId, [u8; 32])> {
    let mut out = Vec::new();
    for signer in signers {
        if !out.iter().any(|existing| existing == signer) {
            out.push(*signer);
        }
    }
    out
}

fn verify_exact_authentication_set(
    certificate: &HistoricalKeyTransitionCertificateV1,
    expected: &[(AuthenticationSuiteId, [u8; 32])],
    kind: HistoricalKeyTransitionKindV1,
    from_keys: &HybridPublicIdentityV1,
    to_keys: &HybridPublicIdentityV1,
    recovery_keys: Option<&HybridPublicIdentityV1>,
    subject_sha: [u8; 32],
) -> Result<(), HistoricalLineageError> {
    if certificate.authentications.len() != expected.len() {
        return Err(HistoricalLineageError::AuthenticationSetMismatch);
    }
    for pair in certificate.authentications.windows(2) {
        if pair[0].suite == pair[1].suite && pair[0].signer_key_id == pair[1].signer_key_id {
            return Err(HistoricalLineageError::DuplicateAuthenticationIdentity);
        }
    }
    for (actual, expected_identity) in certificate.authentications.iter().zip(expected) {
        if (actual.suite, actual.signer_key_id) != *expected_identity {
            return Err(HistoricalLineageError::AuthenticationSetMismatch);
        }
    }

    let mut verifier_identities: Vec<(AuthenticationSuiteId, [u8; 32])> = Vec::new();
    let mut verifiers: Vec<Box<dyn SubjectAuthenticationVerifier>> = Vec::new();
    let mut add_pair = |keys: &HybridPublicIdentityV1| -> Result<(), HistoricalLineageError> {
        let ed = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&keys.ed25519_public_key)?;
        let ed_identity = (AuthenticationSuiteId::ED25519, ed.signer_key_id());
        if !verifier_identities.contains(&ed_identity) {
            verifier_identities.push(ed_identity);
            verifiers.push(Box::new(ed));
        }
        let ml = MlDsa65AuthenticationVerifier::try_from_public_key_bytes(&keys.ml_dsa_65_public_key)?;
        let ml_identity = (AuthenticationSuiteId::ML_DSA_65_FIPS204, ml.signer_key_id());
        if !verifier_identities.contains(&ml_identity) {
            verifier_identities.push(ml_identity);
            verifiers.push(Box::new(ml));
        }
        Ok(())
    };

    match kind {
        HistoricalKeyTransitionKindV1::Rotate => add_pair(from_keys)?,
        HistoricalKeyTransitionKindV1::RecoverCompromise => add_pair(
            recovery_keys.ok_or(HistoricalLineageError::RecoveryAuthorityMissing)?,
        )?,
    }
    add_pair(to_keys)?;
    let registry = AuthenticationVerifierRegistryV1::try_new(verifiers)?;
    let context = lineage_authentication_context_v1()?;

    for authentication in &certificate.authentications {
        let digest = authenticated_subject_digest(
            &context,
            &subject_sha,
            authentication.suite,
            &authentication.signer_key_id,
        )?;
        verify_authentication(&registry, &digest, authentication)?;
    }
    Ok(())
}

