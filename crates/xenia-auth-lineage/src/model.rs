
/// Closed transition classes for V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HistoricalKeyTransitionKindV1 {
    /// Normal continuity: retiring and successor operational keys cross-authenticate.
    Rotate,
    /// Recovery after suspected/known compromise using a separately pinned recovery authority.
    RecoverCompromise,
}

impl HistoricalKeyTransitionKindV1 {
    const fn wire_id(self) -> u8 {
        match self {
            Self::Rotate => 1,
            Self::RecoverCompromise => 2,
        }
    }
}

/// Exact hybrid public-key material for one operational or recovery identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridPublicIdentityV1 {
    pub ed25519_public_key: [u8; 32],
    pub ml_dsa_65_public_key: Vec<u8>,
}

impl HybridPublicIdentityV1 {
    /// Validate encodings and derive the generic-auth signer identities.
    pub fn signer_ids(&self) -> Result<HybridSignerIdsV1, HistoricalLineageError> {
        let ed = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&self.ed25519_public_key)?;
        let ml = MlDsa65AuthenticationVerifier::try_from_public_key_bytes(&self.ml_dsa_65_public_key)?;
        Ok(HybridSignerIdsV1 {
            ed25519: ed.signer_key_id(),
            ml_dsa_65: ml.signer_key_id(),
        })
    }
}

/// Generic-auth signer identities for one hybrid key pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridSignerIdsV1 {
    pub ed25519: [u8; 32],
    pub ml_dsa_65: [u8; 32],
}

/// One operational key epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalKeyEpochV1 {
    pub epoch: u64,
    pub valid_from_unix_ms: u64,
    pub keys: HybridPublicIdentityV1,
}

impl HistoricalKeyEpochV1 {
    fn validate(&self) -> Result<(), HistoricalLineageError> {
        if self.epoch == 0 {
            return Err(HistoricalLineageError::ZeroEpoch);
        }
        self.keys.signer_ids()?;
        Ok(())
    }
}

/// Externally configured root policy. The genesis is pinned, not self-authenticating.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalLineageTrustPolicyV1 {
    pub stable_identity_commitment: [u8; 32],
    pub genesis: HistoricalKeyEpochV1,
    pub recovery_authority: Option<HybridPublicIdentityV1>,
}

impl HistoricalLineageTrustPolicyV1 {
    pub fn validate(&self) -> Result<(), HistoricalLineageError> {
        require_nonzero(self.stable_identity_commitment, "stable identity commitment")?;
        self.genesis.validate()?;
        if let Some(recovery) = &self.recovery_authority {
            recovery.signer_ids()?;
        }
        Ok(())
    }
}

/// Canonical transition subject authenticated by the required hybrid identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalKeyTransitionSubjectV1 {
    pub stable_identity_commitment: [u8; 32],
    pub transition_sequence: u64,
    pub predecessor_certificate_sha256: Option<[u8; 32]>,
    pub from_epoch: HistoricalKeyEpochV1,
    pub to_epoch: HistoricalKeyEpochV1,
    pub kind: HistoricalKeyTransitionKindV1,
    pub effective_at_unix_ms: u64,
    pub prior_epoch_trust_cutoff_unix_ms: Option<u64>,
}

/// Portable transition certificate. Parsing creates no verified lineage state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalKeyTransitionCertificateV1 {
    pub subject: HistoricalKeyTransitionSubjectV1,
    pub authentications: Vec<SubjectAuthentication>,
}

/// One verified historical key interval reconstructed from the append-only chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHistoricalKeyIntervalV1 {
    pub epoch: HistoricalKeyEpochV1,
    pub valid_until_exclusive_unix_ms: Option<u64>,
    pub trust_cutoff_exclusive_unix_ms: Option<u64>,
    pub opened_by_certificate_sha256: Option<[u8; 32]>,
    pub closed_by_certificate_sha256: Option<[u8; 32]>,
}

/// Fully verified lineage from one externally pinned genesis policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHistoricalLineageV1 {
    stable_identity_commitment: [u8; 32],
    intervals: Vec<VerifiedHistoricalKeyIntervalV1>,
    last_certificate_sha256: Option<[u8; 32]>,
}

impl VerifiedHistoricalLineageV1 {
    pub fn stable_identity_commitment(&self) -> [u8; 32] {
        self.stable_identity_commitment
    }

    pub fn intervals(&self) -> &[VerifiedHistoricalKeyIntervalV1] {
        &self.intervals
    }

    pub fn last_certificate_sha256(&self) -> Option<[u8; 32]> {
        self.last_certificate_sha256
    }

    /// Pure historical resolution against a caller-supplied timestamp.
    ///
    /// This does not establish that the timestamp itself is trustworthy.
    pub fn resolve_at(&self, unix_ms: u64) -> HistoricalEpochResolutionV1 {
        for interval in &self.intervals {
            let starts = unix_ms >= interval.epoch.valid_from_unix_ms;
            let before_end = interval
                .valid_until_exclusive_unix_ms
                .is_none_or(|end| unix_ms < end);
            if !(starts && before_end) {
                continue;
            }
            if let Some(cutoff) = interval.trust_cutoff_exclusive_unix_ms {
                if unix_ms >= cutoff {
                    return HistoricalEpochResolutionV1::CompromiseWindow {
                        epoch: interval.epoch.epoch,
                        trust_cutoff_exclusive_unix_ms: cutoff,
                        valid_until_exclusive_unix_ms: interval.valid_until_exclusive_unix_ms,
                    };
                }
            }
            return HistoricalEpochResolutionV1::Eligible {
                epoch: interval.epoch.epoch,
                signer_ids: interval
                    .epoch
                    .keys
                    .signer_ids()
                    .expect("verified lineage stores already-validated key material"),
            };
        }
        HistoricalEpochResolutionV1::NoEligibleEpoch
    }
}

/// Historical resolution does not imply trusted time or current authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalEpochResolutionV1 {
    Eligible {
        epoch: u64,
        signer_ids: HybridSignerIdsV1,
    },
    CompromiseWindow {
        epoch: u64,
        trust_cutoff_exclusive_unix_ms: u64,
        valid_until_exclusive_unix_ms: Option<u64>,
    },
    NoEligibleEpoch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HistoricalLineageError {
    #[error("{0} must be non-zero")]
    ZeroDigest(&'static str),
    #[error("epoch must be greater than zero")]
    ZeroEpoch,
    #[error("transition sequence must be contiguous")]
    NonContiguousTransitionSequence,
    #[error("transition predecessor certificate does not match the verified chain")]
    PredecessorCertificateMismatch,
    #[error("transition stable identity does not match the pinned policy")]
    StableIdentityMismatch,
    #[error("transition from-epoch does not equal the verified current epoch")]
    FromEpochMismatch,
    #[error("successor epoch must increment by exactly one")]
    EpochNotIncremented,
    #[error("transition effective time must be after the current epoch start")]
    InvalidEffectiveTime,
    #[error("successor valid-from must equal transition effective time")]
    SuccessorStartMismatch,
    #[error("normal rotation must change at least one operational key")]
    RotationDidNotChangeKeys,
    #[error("normal rotation cannot carry a compromise cutoff")]
    RotationHasCompromiseCutoff,
    #[error("compromise recovery requires a configured recovery authority")]
    RecoveryAuthorityMissing,
    #[error("recovery authority must not overlap the successor operational keys")]
    RecoveryAuthorityOverlap,
    #[error("compromise recovery requires a cutoff inside the prior epoch interval")]
    InvalidCompromiseCutoff,
    #[error("transition authentication set is not the exact canonical signer set")]
    AuthenticationSetMismatch,
    #[error("transition certificate contains duplicate suite/key authentication")]
    DuplicateAuthenticationIdentity,
    #[error(transparent)]
    Protocol(#[from] AuthenticationProtocolError),
    #[error(transparent)]
    Adapter(#[from] AuthenticationAdapterError),
    #[error(transparent)]
    Verification(#[from] SubjectAuthenticationVerificationError),
}

