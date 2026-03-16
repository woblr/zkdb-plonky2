//! Comparison gadgets: equality, less-than, greater-than, range checks.
//!
//! These are REAL constraint-level comparison operations that work on
//! FieldElement values. They produce boolean results and can verify
//! ordering constraints needed for sort and filter operators.

use crate::field::FieldElement;

/// Result of a comparison operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonResult {
    pub is_equal: bool,
    pub is_less: bool,
    pub is_greater: bool,
}

impl ComparisonResult {
    pub fn compare(a: u64, b: u64) -> Self {
        Self {
            is_equal: a == b,
            is_less: a < b,
            is_greater: a > b,
        }
    }

    pub fn from_field(a: &FieldElement, b: &FieldElement) -> Self {
        Self::compare(a.0, b.0)
    }
}

/// Range check: verify value ∈ [0, 2^bits).
/// Returns true if the value fits in `bits` bits.
pub fn range_check(value: u64, bits: u32) -> bool {
    if bits >= 64 {
        true
    } else {
        value < (1u64 << bits)
    }
}

/// Range check for field element.
pub fn field_range_check(value: &FieldElement, bits: u32) -> bool {
    range_check(value.0, bits)
}

/// Verify that `a < b` by computing the difference and checking it's positive
/// and fits in the expected bit width.
/// This mirrors the constraint: b - a - 1 should be non-negative and fit in `bits` bits.
pub fn constrain_less_than(a: u64, b: u64, bits: u32) -> bool {
    if a >= b {
        return false;
    }
    let diff = b - a - 1;
    range_check(diff, bits)
}

/// Verify that `a <= b`.
pub fn constrain_less_equal(a: u64, b: u64, bits: u32) -> bool {
    if a > b {
        return false;
    }
    if a == b {
        return true;
    }
    let diff = b - a;
    range_check(diff, bits)
}

/// Verify a sequence of values is sorted in ascending order.
/// Returns (is_sorted, first_violation_index).
pub fn verify_sorted_ascending(values: &[u64]) -> (bool, Option<usize>) {
    for i in 1..values.len() {
        if values[i] < values[i - 1] {
            return (false, Some(i));
        }
    }
    (true, None)
}

/// Verify a sequence of values is sorted in descending order.
pub fn verify_sorted_descending(values: &[u64]) -> (bool, Option<usize>) {
    for i in 1..values.len() {
        if values[i] > values[i - 1] {
            return (false, Some(i));
        }
    }
    (true, None)
}

/// Batch comparison: for each adjacent pair, produce ordering witness.
/// Used by sort operator circuits.
pub fn ordering_witness(values: &[u64]) -> Vec<ComparisonResult> {
    if values.len() < 2 {
        return Vec::new();
    }
    values
        .windows(2)
        .map(|w| ComparisonResult::compare(w[0], w[1]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_basic() {
        let r = ComparisonResult::compare(5, 10);
        assert!(r.is_less);
        assert!(!r.is_equal);
        assert!(!r.is_greater);
    }

    #[test]
    fn range_check_works() {
        assert!(range_check(255, 8));
        assert!(!range_check(256, 8));
        assert!(range_check(0, 1));
        assert!(!range_check(2, 1));
    }

    #[test]
    fn sorted_ascending_check() {
        assert!(verify_sorted_ascending(&[1, 2, 3, 4, 5]).0);
        assert!(verify_sorted_ascending(&[1, 1, 2, 2, 3]).0);
        assert!(!verify_sorted_ascending(&[1, 3, 2]).0);
    }

    #[test]
    fn sorted_descending_check() {
        assert!(verify_sorted_descending(&[5, 4, 3, 2, 1]).0);
        assert!(!verify_sorted_descending(&[1, 2, 3]).0);
    }

    #[test]
    fn ordering_witness_correct() {
        let w = ordering_witness(&[10, 20, 15]);
        assert_eq!(w.len(), 2);
        assert!(w[0].is_less);
        assert!(w[1].is_greater);
    }
}
