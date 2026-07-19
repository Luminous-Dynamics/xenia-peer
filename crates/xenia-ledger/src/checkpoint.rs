// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::verify::Verifier;

/// Stable schema label for [`LedgerCheckpoint`].
pub const LEDGER_CHECKPOINT_SCHEMA: &str = "xenia-ledger-checkpoint-v1";

/// A public commitment to the current state of a [`crate::Chain`] -- safe to
/// expose without any authentication, unlike the ledger's actual entries.
///
/// A checkpoint reveals only how many entries exist, the current chain
/// head hash, the ledger's verifying key, and a timestamp, all signed by
/// the same Ed25519 key that signs every ledger entry. It deliberately
/// carries none of [`crate::ConsentEventRecord`]'s contents (session/request IDs,
/// scope strings, timing of individual events) -- those can reveal
/// operational metadata (session relationships, revocation activity,
/// incident-response patterns) even when nothing is "secret" in the
/// cryptographic sense. A third party who periodically retains checkpoints
/// can later detect the ledger being rewritten or truncated (a checkpoint
/// whose `entry_count`/`head_hash` don't extend monotonically and
/// consistently from an earlier one they hold) without ever seeing ledger
/// contents, and without trusting whichever daemon serves the checkpoint at
/// query time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpoint {
    /// Must equal [`LEDGER_CHECKPOINT_SCHEMA`].
    pub schema: String,
    /// Number of entries in the chain when this checkpoint was produced
    /// (0 for an empty chain).
    pub entry_count: u64,
    /// [`crate::Chain::last_hash`] at the time this checkpoint was produced --
    /// `[0; 32]` for an empty chain.
    pub head_hash: [u8; 32],
    /// The ledger's Ed25519 verifying key. Lets a holder of an earlier
    /// checkpoint confirm a later one is still signed by the same
    /// authority (a changed key here, at the same or a related endpoint,
    /// is exactly as significant as a changed sealed-channel host
    /// fingerprint -- see `xenia-operator-agent`'s `host_trust` module).
    pub ledger_public_key: [u8; 32],
    /// Unix seconds this checkpoint was produced.
    pub timestamp_unix_secs: u64,
    /// Ed25519 signature over [`checkpoint_message`] for this checkpoint's
    /// own fields.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// The domain-separated message a [`LedgerCheckpoint`]'s signature covers.
/// Length-prefixing every variable-length field and fixing the order of
/// fixed-length ones prevents two different checkpoints from ever hashing
/// to the same message.
pub fn checkpoint_message(
    entry_count: u64,
    head_hash: &[u8; 32],
    ledger_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64 + LEDGER_CHECKPOINT_SCHEMA.len());
    message.extend_from_slice(b"xenia:ledger-checkpoint:v1");
    message.push(0);
    message.extend_from_slice(LEDGER_CHECKPOINT_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(&entry_count.to_be_bytes());
    message.extend_from_slice(head_hash);
    message.extend_from_slice(ledger_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

/// Why a [`LedgerCheckpoint`] failed to verify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    /// The checkpoint's `schema` field is not [`LEDGER_CHECKPOINT_SCHEMA`].
    #[error("unsupported ledger checkpoint schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the checkpoint.
        schema: String,
    },
    /// The checkpoint's embedded public key is not a valid Ed25519 key.
    #[error("ledger checkpoint has a malformed public key")]
    BadPublicKey,
    /// The checkpoint's signature does not verify against its own fields
    /// and embedded public key.
    #[error("ledger checkpoint signature is invalid")]
    BadSignature,
}

impl Verifier {
    /// Verify a [`LedgerCheckpoint`]'s signature against its own embedded
    /// public key and fields.
    ///
    /// This only confirms internal self-consistency (the signature really
    /// is over these exact fields, under this exact key) -- it does *not*
    /// by itself confirm the embedded public key is the one a caller
    /// already trusts for a given ledger/endpoint. A caller holding an
    /// earlier checkpoint (or any other independently-obtained copy of the
    /// ledger's public key) should additionally compare
    /// `ledger_public_key` against that -- the same trust-on-first-use
    /// discipline `xenia-operator-agent`'s `host_trust` module applies to
    /// the sealed-channel host identity.
    pub fn verify_checkpoint(checkpoint: &LedgerCheckpoint) -> Result<(), CheckpointError> {
        if checkpoint.schema != LEDGER_CHECKPOINT_SCHEMA {
            return Err(CheckpointError::UnsupportedSchema {
                schema: checkpoint.schema.clone(),
            });
        }
        let public_key = VerifyingKey::from_bytes(&checkpoint.ledger_public_key)
            .map_err(|_| CheckpointError::BadPublicKey)?;
        let message = checkpoint_message(
            checkpoint.entry_count,
            &checkpoint.head_hash,
            &checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        );
        let signature = Signature::from_bytes(&checkpoint.signature);
        public_key
            .verify(&message, &signature)
            .map_err(|_| CheckpointError::BadSignature)
    }
}
