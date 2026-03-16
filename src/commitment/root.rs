//! Commitment root types: chunk roots, table roots, snapshot roots.

use crate::types::ChunkId;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Core root types
// ─────────────────────────────────────────────────────────────────────────────

/// A 32-byte commitment root (Blake3 / Poseidon depending on backend).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CommitmentRoot(pub [u8; 32]);

impl CommitmentRoot {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 32]> for CommitmentRoot {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl std::fmt::Display for CommitmentRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chunk commitment
// ─────────────────────────────────────────────────────────────────────────────

/// Content-addressed identifier derived from chunk root hash.
impl ChunkId {
    pub fn from_root(root: &CommitmentRoot) -> Self {
        // Content address: first 32 bytes of blake3(root_bytes)
        let hash = *blake3::hash(&root.0).as_bytes();
        Self(uuid::Uuid::from_slice(&hash[..16]).unwrap_or_default())
    }
}

/// Metadata about a single committed chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkEntry {
    pub chunk_index: u32,
    pub chunk_id: ChunkId,
    pub chunk_root: CommitmentRoot,
    /// First row index in this chunk (0-based, global row index).
    pub row_start: u64,
    /// Exclusive end row index.
    pub row_end: u64,
    /// Number of leaves in the Merkle tree for this chunk.
    pub leaf_count: u32,
}

impl ChunkEntry {
    pub fn row_count(&self) -> u64 {
        self.row_end - self.row_start
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Table root (root over all chunk roots for a single table)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRoot {
    /// Table name (matches schema).
    pub table_name: String,
    /// Merkle root over all chunk roots.
    pub root: CommitmentRoot,
    pub chunk_count: u32,
    pub row_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle path (used in circuit for membership proof)
// ─────────────────────────────────────────────────────────────────────────────

/// A Merkle inclusion proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
    /// Bit for each level: 0 = current node is left, 1 = current is right.
    pub path_bits: Vec<bool>,
}

impl MerklePath {
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Recompute the root from this path and a leaf hash.
    ///
    /// Uses the same domain-separated `hash_nodes` as `MerkleTree::build`.
    pub fn compute_root(&self, leaf_hash: &[u8; 32]) -> CommitmentRoot {
        use crate::commitment::merkle::hash_nodes;
        let mut current = *leaf_hash;
        for (sibling, is_right) in self.siblings.iter().zip(self.path_bits.iter()) {
            current = if *is_right {
                // current is the right child: parent = hash(sibling, current)
                hash_nodes(sibling, &current)
            } else {
                // current is the left child: parent = hash(current, sibling)
                hash_nodes(&current, sibling)
            };
        }
        CommitmentRoot(current)
    }
}
