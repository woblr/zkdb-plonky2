//! Merkle path verification gadget.
//!
//! Verifies inclusion proofs against a Merkle root commitment.

/// Verify a Merkle inclusion proof.
/// Given leaf_hash, path siblings, path indices (0=left, 1=right), and root,
/// verify the inclusion.
pub fn verify_merkle_path(
    leaf_hash: &[u8; 32],
    path: &[[u8; 32]],
    path_indices: &[bool],
    root: &[u8; 32],
) -> bool {
    if path.len() != path_indices.len() {
        return false;
    }

    let mut current = *leaf_hash;
    for (sibling, &is_right) in path.iter().zip(path_indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }

    current == *root
}

/// Hash two 32-byte nodes to produce parent hash.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

/// Compute a Merkle root from leaf hashes.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    // Pad to power of 2
    while current_level.len() & (current_level.len() - 1) != 0 {
        current_level.push([0u8; 32]);
    }

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            next_level.push(hash_pair(&chunk[0], &chunk[1]));
        }
        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_single_leaf() {
        let leaf = *blake3::hash(b"hello").as_bytes();
        let root = compute_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_two_leaves() {
        let a = *blake3::hash(b"a").as_bytes();
        let b = *blake3::hash(b"b").as_bytes();
        let root = compute_merkle_root(&[a, b]);
        assert_eq!(root, hash_pair(&a, &b));
    }

    #[test]
    fn merkle_path_verification() {
        let a = *blake3::hash(b"a").as_bytes();
        let b = *blake3::hash(b"b").as_bytes();
        let root = compute_merkle_root(&[a, b]);

        // Verify leaf 'a' is at index 0 (left)
        assert!(verify_merkle_path(&a, &[b], &[false], &root));
        // Verify leaf 'b' is at index 1 (right)
        assert!(verify_merkle_path(&b, &[a], &[true], &root));
    }
}
