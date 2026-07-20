// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signed preflight manifests for future consent-ledger compaction.
//!
//! A compaction manifest does not delete anything. It binds an exact verified
//! archive sequence and an application-defined recovery summary to both the
//! archived boundary and the current live ledger head. A deployment can retain
//! the manifest with the archive artifacts, then require the same commitments
//! before any later pruning implementation is allowed to mutate live state.

use ed25519_dalek::{Signature, Signer, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{
    checkpoint_fingerprint, Chain, CheckpointContinuityError, CheckpointError,
    LedgerCheckpoint, LedgerEntry, Verifier,
};

/// Stable schema label for [`LedgerCompactionManifest`].
pub const LEDGER_COMPACTION_MANIFEST_SCHEMA: &str = "xenia-ledger-compaction-manifest-v1";

/// Signed binding between archived history, recovery state, and the live head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCompactionManifest {
    /// Must equal [`LEDGER_COMPACTION_MANIFEST_SCHEMA`].
    pub schema: String,
    /// Exact signed checkpoint at the end of the archived history.
    pub archived_through_checkpoint: LedgerCheckpoint,
    /// Exact signed checkpoint of the full live ledger during preflight.
    pub current_checkpoint: LedgerCheckpoint,
    /// Commitment returned by [`crate::ledger_archive_sequence_digest`].
    pub archive_sequence_digest: [u8; 32],
    /// Application-defined commitment to replay indexes and recovery state.
    pub recovery_summary_digest: [u8; 32],
    /// Unix seconds when this preflight manifest was produced.
    pub timestamp_unix_secs: u64,
    /// Ed25519 signature by the ledger key over [`ledger_compaction_manifest_message`].
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Domain-separated bytes signed by the ledger authority for compaction preflight.
pub fn ledger_compaction_manifest_message(
    archived_checkpoint_fingerprint: &[u8; 32],
    current_checkpoint_fingerprint: &[u8; 32],
    archive_sequence_digest: &[u8; 32],
    recovery_summary_digest: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(b"xenia:ledger-compaction-manifest:v1");
    message.push(0);
    message.extend_from_slice(LEDGER_COMPACTION_MANIFEST_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(archived_checkpoint_fingerprint);
    message.extend_from_slice(current_checkpoint_fingerprint);
    message.extend_from_slice(archive_sequence_digest);
    message.extend_from_slice(recovery_summary_digest);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

/// Why a compaction preflight manifest was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerCompactionError {
    /// The manifest schema is unknown.
    #[error("unsupported ledger compaction manifest schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the artifact.
        schema: String,
    },
    /// One of the embedded signed checkpoints was invalid.
    #[error("ledger compaction checkpoint failure: {0}")]
    Checkpoint(#[from] CheckpointError),
    /// The archived and current checkpoints used different ledger keys.
    #[error("ledger compaction checkpoints use different ledger keys")]
    LedgerKeyMismatch,
    /// The manifest timestamp preceded the archived boundary.
    #[error("ledger compaction manifest predates the archived checkpoint")]
    ManifestPredatesArchive,
    /// The current checkpoint timestamp did not equal the signed manifest time.
    #[error("current checkpoint timestamp does not match compaction manifest timestamp")]
    CurrentTimestampMismatch,
    /// The claimed current live head was older than the archived boundary.
    #[error("ledger compaction current checkpoint precedes the archived boundary")]
    CurrentBeforeArchive,
    /// Checkpoints at the same height committed to different ledger heads.
    #[error("ledger compaction checkpoints fork at the archived boundary")]
    ForkAtArchiveBoundary,
    /// An all-zero commitment placeholder was supplied.
    #[error("ledger compaction {field} digest must not be all zero")]
    EmptyDigest {
        /// Commitment field that was empty.
        field: &'static str,
    },
    /// The ledger-authority signature did not verify.
    #[error("ledger compaction manifest signature is invalid")]
    BadSignature,
    /// The archived or current checkpoint did not match the supplied ledger.
    #[error("ledger compaction continuity failure: {0}")]
    Continuity(#[from] CheckpointContinuityError),
}

impl Verifier {
    /// Verify the manifest schema, checkpoints, commitments, and authority signature.
    pub fn verify_ledger_compaction_manifest(
        manifest: &LedgerCompactionManifest,
    ) -> Result<(), LedgerCompactionError> {
        if manifest.schema != LEDGER_COMPACTION_MANIFEST_SCHEMA {
            return Err(LedgerCompactionError::UnsupportedSchema {
                schema: manifest.schema.clone(),
            });
        }
        Self::verify_checkpoint(&manifest.archived_through_checkpoint)?;
        Self::verify_checkpoint(&manifest.current_checkpoint)?;
        if manifest.archived_through_checkpoint.ledger_public_key
            != manifest.current_checkpoint.ledger_public_key
        {
            return Err(LedgerCompactionError::LedgerKeyMismatch);
        }
        if manifest.timestamp_unix_secs
            < manifest.archived_through_checkpoint.timestamp_unix_secs
        {
            return Err(LedgerCompactionError::ManifestPredatesArchive);
        }
        if manifest.current_checkpoint.timestamp_unix_secs != manifest.timestamp_unix_secs {
            return Err(LedgerCompactionError::CurrentTimestampMismatch);
        }
        if manifest.current_checkpoint.entry_count
            < manifest.archived_through_checkpoint.entry_count
        {
            return Err(LedgerCompactionError::CurrentBeforeArchive);
        }
        if manifest.current_checkpoint.entry_count
            == manifest.archived_through_checkpoint.entry_count
            && manifest.current_checkpoint.head_hash
                != manifest.archived_through_checkpoint.head_hash
        {
            return Err(LedgerCompactionError::ForkAtArchiveBoundary);
        }
        if manifest.archive_sequence_digest == [0u8; 32] {
            return Err(LedgerCompactionError::EmptyDigest {
                field: "archive_sequence",
            });
        }
        if manifest.recovery_summary_digest == [0u8; 32] {
            return Err(LedgerCompactionError::EmptyDigest {
                field: "recovery_summary",
            });
        }

        let archived = checkpoint_fingerprint(&manifest.archived_through_checkpoint)?;
        let current = checkpoint_fingerprint(&manifest.current_checkpoint)?;
        let message = ledger_compaction_manifest_message(
            &archived,
            &current,
            &manifest.archive_sequence_digest,
            &manifest.recovery_summary_digest,
            manifest.timestamp_unix_secs,
        );
        let key = VerifyingKey::from_bytes(
            &manifest.archived_through_checkpoint.ledger_public_key,
        )
        .map_err(|_| CheckpointError::BadPublicKey)?;
        key.verify(&message, &Signature::from_bytes(&manifest.signature))
            .map_err(|_| LedgerCompactionError::BadSignature)
    }

    /// Verify the manifest and prove both checkpoints against the supplied full ledger.
    pub fn verify_ledger_compaction_manifest_against_entries(
        manifest: &LedgerCompactionManifest,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), LedgerCompactionError> {
        Self::verify_ledger_compaction_manifest(manifest)?;
        Self::verify_checkpoint_prefix(
            &manifest.archived_through_checkpoint,
            entries,
            public_key,
        )?;
        Self::verify_checkpoint_prefix(&manifest.current_checkpoint, entries, public_key)?;
        Ok(())
    }
}

impl Chain {
    /// Sign a non-destructive compaction preflight manifest for the current chain.
    pub fn sign_compaction_manifest(
        &self,
        archived_through_checkpoint: LedgerCheckpoint,
        archive_sequence_digest: [u8; 32],
        recovery_summary_digest: [u8; 32],
        timestamp_unix_secs: u64,
    ) -> Result<LedgerCompactionManifest, LedgerCompactionError> {
        if archive_sequence_digest == [0u8; 32] {
            return Err(LedgerCompactionError::EmptyDigest {
                field: "archive_sequence",
            });
        }
        if recovery_summary_digest == [0u8; 32] {
            return Err(LedgerCompactionError::EmptyDigest {
                field: "recovery_summary",
            });
        }
        let public_key = self.signing_key.verifying_key();
        let entries = self.iter().cloned().collect::<Vec<_>>();
        Verifier::verify_checkpoint_prefix(
            &archived_through_checkpoint,
            &entries,
            &public_key,
        )?;
        if timestamp_unix_secs < archived_through_checkpoint.timestamp_unix_secs {
            return Err(LedgerCompactionError::ManifestPredatesArchive);
        }
        let current_checkpoint = self.sign_checkpoint(timestamp_unix_secs);
        let archived = checkpoint_fingerprint(&archived_through_checkpoint)?;
        let current = checkpoint_fingerprint(&current_checkpoint)?;
        let message = ledger_compaction_manifest_message(
            &archived,
            &current,
            &archive_sequence_digest,
            &recovery_summary_digest,
            timestamp_unix_secs,
        );
        Ok(LedgerCompactionManifest {
            schema: LEDGER_COMPACTION_MANIFEST_SCHEMA.to_string(),
            archived_through_checkpoint,
            current_checkpoint,
            archive_sequence_digest,
            recovery_summary_digest,
            timestamp_unix_secs,
            signature: self.signing_key.sign(&message).to_bytes(),
        })
    }
}
