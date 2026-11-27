// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Compact append-only Merkle consistency proofs for operation-WAL records.
//!
//! Implements the tree shape and consistency proof construction from RFC 9162
//! Section 2.1 using SHA-256 and explicit leaf/node domain separation. Each
//! WAL record hash is the input leaf. The WAL's record-body and hash-chain
//! verifier remain responsible for authenticating that leaf.
//!
//! A consistency proof demonstrates that a later tree preserves the prefix
//! committed by an earlier tree. It does not prove that an arbitrary leaf is
//! authorized or that a local WAL record body is valid.
//!
//! Proof size is O(log n), in contrast to a linear list of every intervening
//! hash-chain link. A local WAL may retain its hash chain for crash recovery
//! and exact-head identity while using this proof for witness continuity.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// One RFC 9162-style Merkle consistency proof between two tree sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationWalMerkleConsistencyProof {
    /// Number of leaves committed by the old tree.
    pub old_tree_size: u64,
    /// Number of leaves committed by the new tree.
    pub new_tree_size: u64,
    /// Minimal RFC 9162 consistency path; normally O(log new_tree_size).
    pub nodes: Vec<[u8; 32]>,
}

/// Compact append-only Merkle frontier for amortized O(1) appends.
///
/// Peaks are stored by height. The root is computed by folding non-empty
/// peaks from highest to lowest, preserving RFC 9162's left-complete tree
/// shape. This frontier is sufficient to continue appending after restart;
/// arbitrary historical consistency proofs still require the relevant
/// leaf/node store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationWalMerkleFrontier {
    leaf_count: u64,
    peaks: Vec<Option<[u8; 32]>>,
}

/// Fail-closed errors from Merkle tree/proof operations.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum OperationWalMerkleError {
    /// The old tree size exceeds the new tree size.
    #[error("Merkle consistency tree size regressed")]
    TreeSizeRegressed,
    /// The supplied old root is not the RFC 9162 empty-tree hash.
    #[error("Merkle old root does not match the empty tree")]
    EmptyRootMismatch,
    /// A proof is missing required nodes or carries extra nodes.
    #[error("Merkle consistency proof has an invalid node count")]
    InvalidProofLength,
    /// A reconstructed old root differs from the retained old root.
    #[error("Merkle consistency proof does not reconstruct the old root")]
    OldRootMismatch,
    /// A reconstructed new root differs from the candidate root.
    #[error("Merkle consistency proof does not reconstruct the new root")]
    NewRootMismatch,
    /// A consistency verifier ended before reaching the new tree root.
    #[error("Merkle consistency proof ended before the root")]
    IncompleteProof,
    /// An index/size operation overflowed.
    #[error("Merkle tree size exhausted")]
    TreeSizeExhausted,
    /// An in-memory index could not be represented by the platform.
    #[error("Merkle tree size cannot be represented on this platform")]
    PlatformSizeOverflow,
    /// A restored frontier's peaks are inconsistent with its leaf count.
    #[error("Merkle frontier is inconsistent with its leaf count")]
    InvalidFrontier,
}

impl OperationWalMerkleFrontier {
    /// Create an empty frontier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a frontier from a serialized leaf count and peak set.
    ///
    /// The caller must authenticate the restored frontier against a trusted
    /// checkpoint or reconstruct it from the verified WAL.
    pub fn from_parts(
        leaf_count: u64,
        peaks: Vec<Option<[u8; 32]>>,
    ) -> Result<Self, OperationWalMerkleError> {
        let expected_len = if leaf_count == 0 {
            0
        } else {
            (u64::BITS - leaf_count.leading_zeros()) as usize
        };
        if peaks.len() != expected_len {
            return Err(OperationWalMerkleError::InvalidFrontier);
        }
        for (height, peak) in peaks.iter().enumerate() {
            let set = ((leaf_count >> height) & 1) == 1;
            if peak.is_some() != set {
                return Err(OperationWalMerkleError::InvalidFrontier);
            }
        }
        Ok(Self { leaf_count, peaks })
    }

    /// Append one complete WAL record hash using amortized O(1) merges.
    pub fn append_record_hash(
        &mut self,
        record_hash: [u8; 32],
    ) -> Result<(), OperationWalMerkleError> {
        let mut carry = leaf_hash(&record_hash);
        let mut height = 0_usize;
        let next_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(OperationWalMerkleError::TreeSizeExhausted)?;

        while ((self.leaf_count >> height) & 1) == 1 {
            let left = self
                .peaks
                .get_mut(height)
                .and_then(Option::take)
                .ok_or(OperationWalMerkleError::InvalidFrontier)?;
            carry = node_hash(&left, &carry);
            height = height
                .checked_add(1)
                .ok_or(OperationWalMerkleError::TreeSizeExhausted)?;
        }

        if self.peaks.len() <= height {
            self.peaks.resize(height + 1, None);
        }
        if self.peaks[height].is_some() {
            return Err(OperationWalMerkleError::InvalidFrontier);
        }
        self.peaks[height] = Some(carry);
        self.leaf_count = next_count;
        Ok(())
    }

    /// Number of WAL record hashes committed by this frontier.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Current RFC 9162 Merkle Tree Hash.
    pub fn root(&self) -> [u8; 32] {
        let mut root: Option<[u8; 32]> = None;
        for peak in self.peaks.iter().rev().flatten() {
            root = Some(match root {
                Some(right) => node_hash(peak, &right),
                None => *peak,
            });
        }
        root.unwrap_or_else(empty_tree_hash)
    }

    /// Export the frontier representation for authenticated persistence.
    pub fn into_parts(self) -> (u64, Vec<Option<[u8; 32]>>) {
        (self.leaf_count, self.peaks)
    }
}

/// RFC 9162 tree hash for an ordered list of complete WAL record hashes.
pub fn operation_wal_merkle_root(record_hashes: &[[u8; 32]]) -> [u8; 32] {
    merkle_tree_hash(record_hashes)
}

/// Generate the minimal consistency path from the first old_tree_size record
/// hashes to the full record_hashes tree.
///
/// For an empty old tree and a non-empty new tree, this profile includes the
/// new root as a single path node so both sizes and roots remain bound.
pub fn generate_operation_wal_consistency_proof(
    record_hashes: &[[u8; 32]],
    old_tree_size: u64,
) -> Result<OperationWalMerkleConsistencyProof, OperationWalMerkleError> {
    let new_tree_size = u64::try_from(record_hashes.len())
        .map_err(|_| OperationWalMerkleError::PlatformSizeOverflow)?;
    if old_tree_size > new_tree_size {
        return Err(OperationWalMerkleError::TreeSizeRegressed);
    }
    let old_size = usize::try_from(old_tree_size)
        .map_err(|_| OperationWalMerkleError::PlatformSizeOverflow)?;

    let nodes = if old_size == 0 && new_tree_size > 0 {
        vec![merkle_tree_hash(record_hashes)]
    } else if old_size == record_hashes.len() {
        Vec::new()
    } else {
        let mut nodes = Vec::new();
        consistency_subproof(old_size, record_hashes, true, &mut nodes);
        nodes
    };

    Ok(OperationWalMerkleConsistencyProof {
        old_tree_size,
        new_tree_size,
        nodes,
    })
}

/// Verify a compact append-only proof against two independently retained roots.
pub fn verify_operation_wal_consistency_proof(
    old_tree_size: u64,
    old_root: [u8; 32],
    new_tree_size: u64,
    new_root: [u8; 32],
    proof: &OperationWalMerkleConsistencyProof,
) -> Result<(), OperationWalMerkleError> {
    if proof.old_tree_size != old_tree_size || proof.new_tree_size != new_tree_size {
        return Err(OperationWalMerkleError::InvalidProofLength);
    }
    if old_tree_size > new_tree_size {
        return Err(OperationWalMerkleError::TreeSizeRegressed);
    }
    if old_tree_size == 0 {
        if old_root != empty_tree_hash() {
            return Err(OperationWalMerkleError::EmptyRootMismatch);
        }
        if new_tree_size == 0 {
            if !proof.nodes.is_empty() && proof.nodes.as_slice() != [new_root] {
                return Err(OperationWalMerkleError::InvalidProofLength);
            }
            return if old_root == new_root {
                Ok(())
            } else {
                Err(OperationWalMerkleError::NewRootMismatch)
            };
        }
        return if proof.nodes.as_slice() == [new_root] {
            Ok(())
        } else {
            Err(OperationWalMerkleError::InvalidProofLength)
        };
    }
    if old_tree_size == new_tree_size {
        return if proof.nodes.is_empty() && old_root == new_root {
            Ok(())
        } else if old_root != new_root {
            Err(OperationWalMerkleError::NewRootMismatch)
        } else {
            Err(OperationWalMerkleError::InvalidProofLength)
        };
    }
    if proof.nodes.is_empty() {
        return Err(OperationWalMerkleError::InvalidProofLength);
    }

    let mut path = proof.nodes.iter().copied();
    let mut fn_index = old_tree_size - 1;
    let mut sn_index = new_tree_size - 1;
    while fn_index & 1 == 1 {
        fn_index >>= 1;
        sn_index >>= 1;
    }

    let (mut first_root, mut second_root) = if old_tree_size.is_power_of_two() {
        (old_root, old_root)
    } else {
        let first = path
            .next()
            .ok_or(OperationWalMerkleError::InvalidProofLength)?;
        (first, first)
    };

    for node in path {
        combine_consistency_node(
            &mut first_root,
            &mut second_root,
            &mut fn_index,
            &mut sn_index,
            node,
        )?;
    }

    if sn_index != 0 {
        return Err(OperationWalMerkleError::IncompleteProof);
    }
    if first_root != old_root {
        return Err(OperationWalMerkleError::OldRootMismatch);
    }
    if second_root != new_root {
        return Err(OperationWalMerkleError::NewRootMismatch);
    }
    Ok(())
}

fn combine_consistency_node(
    first_root: &mut [u8; 32],
    second_root: &mut [u8; 32],
    fn_index: &mut u64,
    sn_index: &mut u64,
    node: [u8; 32],
) -> Result<(), OperationWalMerkleError> {
    if *sn_index == 0 {
        return Err(OperationWalMerkleError::IncompleteProof);
    }
    if (*fn_index & 1) == 1 || *fn_index == *sn_index {
        *first_root = node_hash(&node, first_root);
        *second_root = node_hash(&node, second_root);
        while (*fn_index & 1) == 0 && *fn_index != 0 {
            *fn_index >>= 1;
            *sn_index >>= 1;
        }
    } else {
        *second_root = node_hash(second_root, &node);
    }
    *fn_index >>= 1;
    *sn_index >>= 1;
    Ok(())
}

fn consistency_subproof(
    old_tree_size: usize,
    record_hashes: &[[u8; 32]],
    old_root_known: bool,
    output: &mut Vec<[u8; 32]>,
) {
    let new_tree_size = record_hashes.len();
    if old_tree_size == new_tree_size {
        if !old_root_known {
            output.push(merkle_tree_hash(record_hashes));
        }
        return;
    }

    let split = largest_power_of_two_less_than(new_tree_size);
    if old_tree_size <= split {
        consistency_subproof(
            old_tree_size,
            &record_hashes[..split],
            old_root_known,
            output,
        );
        output.push(merkle_tree_hash(&record_hashes[split..]));
    } else {
        consistency_subproof(
            old_tree_size - split,
            &record_hashes[split..],
            false,
            output,
        );
        output.push(merkle_tree_hash(&record_hashes[..split]));
    }
}

fn merkle_tree_hash(record_hashes: &[[u8; 32]]) -> [u8; 32] {
    match record_hashes.len() {
        0 => empty_tree_hash(),
        1 => leaf_hash(&record_hashes[0]),
        count => {
            let split = largest_power_of_two_less_than(count);
            let left = merkle_tree_hash(&record_hashes[..split]);
            let right = merkle_tree_hash(&record_hashes[split..]);
            node_hash(&left, &right)
        }
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    let highest_bit = usize::BITS - 1 - (value - 1).leading_zeros();
    1_usize << highest_bit
}

fn empty_tree_hash() -> [u8; 32] {
    Sha256::digest(b"").into()
}

fn leaf_hash(record_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(record_hash);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|index| {
                let mut bytes = [0_u8; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                bytes[8..16].copy_from_slice(&((index as u64) ^ 0xA5A5_5A5A).to_le_bytes());
                bytes
            })
            .collect()
    }

    #[test]
    fn empty_and_singleton_roots_match_rfc_9162_shape() {
        assert_eq!(operation_wal_merkle_root(&[]), empty_tree_hash());
        assert_eq!(operation_wal_merkle_root(&[[7; 32]]), leaf_hash(&[7; 32]));
    }

    #[test]
    fn every_prefix_consistency_proof_verifies_for_small_trees() {
        for new_size in 1..=96 {
            let records = sample_records(new_size);
            let new_root = operation_wal_merkle_root(&records);
            for old_size in 0..=new_size {
                let old_root = operation_wal_merkle_root(&records[..old_size]);
                let proof = generate_operation_wal_consistency_proof(
                    &records,
                    old_size as u64,
                )
                .unwrap_or_else(|error| panic!("proof {old_size}->{new_size} failed: {error:?}"));
                verify_operation_wal_consistency_proof(
                    old_size as u64,
                    old_root,
                    new_size as u64,
                    new_root,
                    &proof,
                )
                .unwrap_or_else(|error| panic!("verify {old_size}->{new_size} failed: {error:?}"));
                if old_size > 0 && old_size < new_size {
                    let limit = (usize::BITS - new_size.leading_zeros()) as usize + 1;
                    assert!(
                        proof.nodes.len() <= limit,
                        "proof {old_size}->{new_size} had {} nodes, limit {limit}",
                        proof.nodes.len()
                    );
                }
            }
        }
    }

    #[test]
    fn proof_rejects_wrong_roots_sizes_and_tampered_nodes() {
        let records = sample_records(37);
        let old_root = operation_wal_merkle_root(&records[..13]);
        let new_root = operation_wal_merkle_root(&records);
        let proof = generate_operation_wal_consistency_proof(&records, 13)
            .unwrap_or_else(|error| panic!("proof generation failed: {error:?}"));

        let mut wrong_old = old_root;
        wrong_old[0] ^= 1;
        assert_eq!(
            verify_operation_wal_consistency_proof(13, wrong_old, 37, new_root, &proof),
            Err(OperationWalMerkleError::OldRootMismatch)
        );

        let mut wrong_new = new_root;
        wrong_new[0] ^= 1;
        assert_eq!(
            verify_operation_wal_consistency_proof(13, old_root, 37, wrong_new, &proof),
            Err(OperationWalMerkleError::NewRootMismatch)
        );

        let mut tampered = proof.clone();
        tampered.nodes[0][0] ^= 1;
        assert!(
            verify_operation_wal_consistency_proof(13, old_root, 37, new_root, &tampered).is_err()
        );
        assert_eq!(
            verify_operation_wal_consistency_proof(13, old_root, 36, new_root, &proof),
            Err(OperationWalMerkleError::InvalidProofLength)
        );
    }

    #[test]
    fn frontier_root_matches_full_tree_for_every_prefix() {
        let records = sample_records(2_048);
        let mut frontier = OperationWalMerkleFrontier::new();
        assert_eq!(frontier.root(), operation_wal_merkle_root(&[]));
        for (index, record_hash) in records.iter().enumerate() {
            frontier
                .append_record_hash(*record_hash)
                .unwrap_or_else(|error| panic!("frontier append {index} failed: {error:?}"));
            assert_eq!(
                frontier.root(),
                operation_wal_merkle_root(&records[..=index]),
                "frontier root diverged at leaf {index}"
            );
        }
    }

    #[test]
    fn frontier_round_trips_and_rejects_inconsistent_peaks() {
        let records = sample_records(333);
        let mut frontier = OperationWalMerkleFrontier::new();
        for record in &records {
            frontier
                .append_record_hash(*record)
                .unwrap_or_else(|error| panic!("frontier append failed: {error:?}"));
        }
        let (count, peaks) = frontier.into_parts();
        let restored = OperationWalMerkleFrontier::from_parts(count, peaks)
            .unwrap_or_else(|error| panic!("frontier restore failed: {error:?}"));
        assert_eq!(restored.root(), operation_wal_merkle_root(&records));
        assert_eq!(
            OperationWalMerkleFrontier::from_parts(333, vec![None]),
            Err(OperationWalMerkleError::InvalidFrontier)
        );
    }

    #[test]
    fn empty_and_equal_size_proofs_are_explicit() {
        let records = sample_records(4);
        let empty_root = operation_wal_merkle_root(&[]);
        let full_root = operation_wal_merkle_root(&records);
        let from_empty = generate_operation_wal_consistency_proof(&records, 0)
            .unwrap_or_else(|error| panic!("empty proof generation failed: {error:?}"));
        assert_eq!(from_empty.nodes, vec![full_root]);
        assert!(verify_operation_wal_consistency_proof(
            0, empty_root, 4, full_root, &from_empty,
        ).is_ok());

        let same = generate_operation_wal_consistency_proof(&records, 4)
            .unwrap_or_else(|error| panic!("equal proof generation failed: {error:?}"));
        assert!(same.nodes.is_empty());
        assert!(verify_operation_wal_consistency_proof(
            4, full_root, 4, full_root, &same,
        ).is_ok());
    }
}
