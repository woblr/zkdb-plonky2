//! Merkle tree implementation.
//!
//! Uses Blake3 for hashing. A production impl would use Poseidon for
//! in-circuit verifiability, but Blake3 is used here until the proving
//! backend is integrated.

use crate::commitment::root::{CommitmentRoot, MerklePath};

// ─────────────────────────────────────────────────────────────────────────────
// Hash functions
// ─────────────────────────────────────────────────────────────────────────────

/// Hash a single leaf value.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    // Domain-separate leaves from internal nodes.
    let mut preimage = Vec::with_capacity(1 + data.len());
    preimage.push(0x00); // leaf domain tag
    preimage.extend_from_slice(data);
    *blake3::hash(&preimage).as_bytes()
}

/// Hash two child nodes into a parent.
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 65];
    preimage[0] = 0x01; // internal node domain tag
    preimage[1..33].copy_from_slice(left);
    preimage[33..65].copy_from_slice(right);
    *blake3::hash(&preimage).as_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle tree
// ─────────────────────────────────────────────────────────────────────────────

/// A binary Merkle tree over a fixed set of leaves.
///
/// Leaves are padded to the next power of two with zero hashes.
/// The root is the Blake3 hash of the concatenated child hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All levels: levels[0] = leaves, levels[last] = [root].
    levels: Vec<Vec<[u8; 32]>>,
    /// Number of original (non-padded) leaves.
    pub leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from raw leaf data.
    pub fn build(leaf_data: &[[u8; 32]]) -> Self {
        assert!(
            !leaf_data.is_empty(),
            "MerkleTree requires at least one leaf"
        );

        let n = leaf_data.len().next_power_of_two();
        let mut leaves: Vec<[u8; 32]> = leaf_data.to_vec();
        // Pad with zero-hashes
        while leaves.len() < n {
            leaves.push([0u8; 32]);
        }

        let mut levels = vec![leaves.clone()];
        let mut current = leaves;

        while current.len() > 1 {
            let parent: Vec<[u8; 32]> = current
                .chunks(2)
                .map(|pair| hash_nodes(&pair[0], &pair[1]))
                .collect();
            levels.push(parent.clone());
            current = parent;
        }

        Self {
            leaf_count: leaf_data.len(),
            levels,
        }
    }

    /// Build from raw data slices (hashes each leaf first).
    pub fn build_from_data(data: &[&[u8]]) -> Self {
        let hashes: Vec<[u8; 32]> = data.iter().map(|d| hash_leaf(d)).collect();
        Self::build(&hashes)
    }

    /// The root of the tree.
    pub fn root(&self) -> CommitmentRoot {
        CommitmentRoot(*self.levels.last().unwrap().first().unwrap())
    }

    /// Generate a Merkle inclusion proof for the leaf at position `index`.
    pub fn proof(&self, index: usize) -> Option<MerklePath> {
        if index >= self.leaf_count {
            return None;
        }

        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();
        let mut current_idx = index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if current_idx.is_multiple_of(2) {
                current_idx + 1
            } else {
                current_idx - 1
            };
            let is_right = current_idx % 2 == 1;
            siblings.push(level[sibling_idx]);
            path_bits.push(is_right);
            current_idx /= 2;
        }

        Some(MerklePath {
            siblings,
            path_bits,
        })
    }

    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_verify_proof() {
        let data: Vec<[u8; 32]> = (0u8..8)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i;
                b
            })
            .collect();

        let tree = MerkleTree::build(&data);
        let root = tree.root();

        for i in 0..8 {
            let proof = tree.proof(i).unwrap();
            let computed = proof.compute_root(&data[i]);
            assert_eq!(computed, root, "proof failed at index {}", i);
        }
    }

    #[test]
    fn single_leaf_tree() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::build(&[leaf]);
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        let computed = proof.compute_root(&leaf);
        assert_eq!(computed, root);
    }
}
