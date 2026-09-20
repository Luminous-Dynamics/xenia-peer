/// Canonical application context used by every V1 lineage authentication.
pub fn lineage_authentication_context_v1(
) -> Result<AuthenticationContextId, AuthenticationProtocolError> {
    AuthenticationContextId::try_new("XENIA", "IdentityLineage", "KeyEpochTransition", 1)
}

/// Hash the exact canonical transition subject.
pub fn transition_subject_sha256_v1(
    subject: &HistoricalKeyTransitionSubjectV1,
) -> Result<[u8; 32], HistoricalLineageError> {
    subject.from_epoch.validate()?;
    subject.to_epoch.validate()?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(TRANSITION_SUBJECT_DOMAIN_V1);
    bytes.extend_from_slice(&subject.stable_identity_commitment);
    bytes.extend_from_slice(&subject.transition_sequence.to_le_bytes());
    append_optional_digest(&mut bytes, subject.predecessor_certificate_sha256);
    append_epoch(&mut bytes, &subject.from_epoch);
    append_epoch(&mut bytes, &subject.to_epoch);
    bytes.push(subject.kind.wire_id());
    bytes.extend_from_slice(&subject.effective_at_unix_ms.to_le_bytes());
    append_optional_u64(&mut bytes, subject.prior_epoch_trust_cutoff_unix_ms);
    Ok(Sha256::digest(bytes).into())
}

/// Hash a canonical certificate, including exact ordered detached authentications.
pub fn transition_certificate_sha256_v1(
    certificate: &HistoricalKeyTransitionCertificateV1,
) -> Result<[u8; 32], HistoricalLineageError> {
    let subject_sha = transition_subject_sha256_v1(&certificate.subject)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(TRANSITION_CERTIFICATE_DOMAIN_V1);
    bytes.extend_from_slice(&subject_sha);
    let count = u32::try_from(certificate.authentications.len())
        .map_err(|_| AuthenticationProtocolError::LengthOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for authentication in &certificate.authentications {
        authentication.validate()?;
        bytes.extend_from_slice(&authentication.suite.wire_id().to_le_bytes());
        bytes.extend_from_slice(&authentication.signer_key_id);
        let len = u32::try_from(authentication.signature.len())
            .map_err(|_| AuthenticationProtocolError::LengthOverflow)?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&authentication.signature);
    }
    Ok(Sha256::digest(bytes).into())
}

fn append_epoch(out: &mut Vec<u8>, epoch: &HistoricalKeyEpochV1) {
    out.extend_from_slice(&epoch.epoch.to_le_bytes());
    out.extend_from_slice(&epoch.valid_from_unix_ms.to_le_bytes());
    out.extend_from_slice(&epoch.keys.ed25519_public_key);
    out.extend_from_slice(&epoch.keys.ml_dsa_65_public_key);
}

fn append_optional_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

fn append_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn require_nonzero(value: [u8; 32], field: &'static str) -> Result<(), HistoricalLineageError> {
    if value == [0; 32] {
        Err(HistoricalLineageError::ZeroDigest(field))
    } else {
        Ok(())
    }
}

