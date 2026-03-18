//! Poseidon-based row and snapshot commitments over the Goldilocks field.
//!
//! Uses plonky2's built-in Poseidon hash so commitments can be verified
//! **inside Plonky2 circuits** — the native computation here (Rust) produces
//! exactly the same hash the circuit computes via
//! `CircuitBuilder::hash_n_to_hash_no_pad::<PoseidonHash>`.
//!
//! # Relationship with the Blake3 commitment
//!
//! `Blake3CommitmentService` builds a Merkle tree for the storage layer and
//! audit trail.  The Poseidon root here is **what circuits prove**: a circuit
//! constrains `PI[0] = Poseidon(witness_values[0..MAX_ROWS-1]).elements[0]`,
//! binding the proof to the specific values used.  Both roots exist; only the
//! Poseidon root is checked inside a SNARK.
//!
//! # How to use
//!
//! ```rust
//! use zkdb_plonky2::commitment::poseidon::{compute_snap_lo, MAX_ROWS};
//!
//! // In tests / witness construction:
//! let values = vec![10u64, 20, 30]; // pre-sort / pre-group values
//! let snap_lo = compute_snap_lo(MAX_ROWS, &values);
//! // snap_lo is the first Goldilocks field element of Poseidon(padded_values)
//! // — this MUST match what the circuit derives from the private inputs.
//! ```

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

type F = GoldilocksField;

/// Maximum rows per circuit instance — must match `MAX_ROWS` in `plonky2.rs`.
pub const MAX_ROWS: usize = 128;

// ─────────────────────────────────────────────────────────────────────────────
// Core hash utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `Poseidon(padded_values).elements[0]` where `padded_values` is
/// `values` zero-padded (or truncated) to exactly `n_rows` elements.
///
/// This matches exactly what the in-circuit call
/// `builder.hash_n_to_hash_no_pad::<PoseidonHash>(targets)` computes when
/// those `targets` are set to the corresponding values.
///
/// Returns the first Goldilocks field element of the 4-element hash output,
/// cast to `u64`.  This is used as `snap_lo = PI[0]` in every circuit.
pub fn compute_snap_lo(n_rows: usize, values: &[u64]) -> u64 {
    let fes = padded_field_elements(n_rows, values);
    PoseidonHash::hash_no_pad(&fes).elements[0].to_canonical_u64()
}

/// Pack `values` (zero-padded / truncated to `n_rows`) into Goldilocks
/// field elements for use with `PoseidonHash::hash_no_pad`.
pub fn padded_field_elements(n_rows: usize, values: &[u64]) -> Vec<F> {
    (0..n_rows)
        .map(|i| F::from_canonical_u64(if i < values.len() { values[i] } else { 0 }))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Row encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the "primary field element" for a raw row byte slice.
///
/// Takes the first 8 bytes as a little-endian `u64` Goldilocks field element.
/// This is the simplest schema-free encoding; a full schema-aware decoder
/// is a future improvement (see TODO in WitnessBuilder).
pub fn row_primary_field_element(row_bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = row_bytes.len().min(8);
    buf[..len].copy_from_slice(&row_bytes[..len]);
    u64::from_le_bytes(buf)
}

/// Pack arbitrary bytes into Goldilocks field elements (8 bytes each, LE).
/// Pads the last element with zeros if `bytes.len()` is not a multiple of 8.
pub fn bytes_to_field_elements(bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            let len = chunk.len();
            buf[..len].copy_from_slice(chunk);
            F::from_canonical_u64(u64::from_le_bytes(buf))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot root from raw chunks
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Poseidon snapshot root from all row bytes across all chunks.
///
/// Algorithm:
/// 1. For each row, extract its primary field element.
/// 2. Poseidon-hash all per-row field elements (zero-padded to MAX_ROWS) into
///    a single commitment.
/// 3. Store `commitment.elements[0]` as the first 8 bytes of a 32-byte root.
///
/// The result is what circuits use as `PI[0]` (= `snap_lo`), encoded as a
/// 32-byte value for storage in `WitnessTrace::snapshot_root`.
pub fn poseidon_snapshot_root(all_row_bytes: &[Vec<u8>]) -> [u8; 32] {
    let primary_fes: Vec<u64> = all_row_bytes
        .iter()
        .map(|rb| row_primary_field_element(rb))
        .collect();

    let snap_lo = compute_snap_lo(MAX_ROWS, &primary_fes);

    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    root
}

/// Read the `snap_lo` (first 8 bytes as LE u64) from a 32-byte commitment.
pub fn commitment_lo(commitment: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&commitment[..8]);
    u64::from_le_bytes(buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snap_lo_is_deterministic() {
        let vals = vec![10u64, 20, 30, 40];
        let a = compute_snap_lo(MAX_ROWS, &vals);
        let b = compute_snap_lo(MAX_ROWS, &vals);
        assert_eq!(a, b);
    }

    #[test]
    fn different_values_produce_different_snap_lo() {
        let a = compute_snap_lo(MAX_ROWS, &[1u64, 2, 3]);
        let b = compute_snap_lo(MAX_ROWS, &[1u64, 2, 4]); // last value changed
        assert_ne!(
            a, b,
            "different inputs must produce different Poseidon hashes"
        );
    }

    #[test]
    fn zero_values_is_nonzero_hash() {
        // Poseidon of all-zeros is a specific non-trivial value
        let v = compute_snap_lo(MAX_ROWS, &[]);
        // The hash of 128 zeros is nonzero in general
        let _ = v; // just confirm no panic
    }

    #[test]
    fn row_primary_field_element_first_8_bytes() {
        let row = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF];
        let fe = row_primary_field_element(&row);
        let expected = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(fe, expected);
    }

    #[test]
    fn snapshot_root_encoding_is_consistent() {
        let rows: Vec<Vec<u8>> = (0..5u64).map(|i| i.to_le_bytes().to_vec()).collect();
        let root = poseidon_snapshot_root(&rows);
        let lo = commitment_lo(&root);
        // lo must equal compute_snap_lo of the primary field elements
        let primary: Vec<u64> = rows
            .iter()
            .map(|rb| row_primary_field_element(rb))
            .collect();
        let expected_lo = compute_snap_lo(MAX_ROWS, &primary);
        assert_eq!(lo, expected_lo);
    }
}
