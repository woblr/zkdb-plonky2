//! Permutation gadgets for proving set equality / reordering.
//!
//! Used by sort and join operators to prove that the output is a valid
//! reordering of the input (no rows added/removed).

/// Verify two multisets are equal (same elements, possibly different order).
/// Uses sorting-based comparison.
pub fn multiset_equal(a: &[u64], b: &[u64]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut sa: Vec<u64> = a.to_vec();
    let mut sb: Vec<u64> = b.to_vec();
    sa.sort();
    sb.sort();
    sa == sb
}

/// Compute a random-evaluation fingerprint for a multiset.
/// Fingerprint = Π(challenge - values[i]) over all i.
/// Two multisets are equal with high probability if their fingerprints match
/// for a random challenge.
pub fn multiset_fingerprint(values: &[u64], challenge: u64) -> u64 {
    values
        .iter()
        .fold(1u64, |acc, &v| acc.wrapping_mul(challenge.wrapping_sub(v)))
}

/// Verify a permutation maps input to output correctly.
pub fn verify_permutation_mapping(input: &[u64], output: &[u64], perm: &[usize]) -> bool {
    if input.len() != output.len() || perm.len() != input.len() {
        return false;
    }
    for (i, &p) in perm.iter().enumerate() {
        if p >= input.len() || output[i] != input[p] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiset_equal_basic() {
        assert!(multiset_equal(&[3, 1, 2], &[1, 2, 3]));
        assert!(!multiset_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!multiset_equal(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn fingerprint_equal_sets() {
        let challenge = 12345u64;
        let a = vec![10, 20, 30];
        let b = vec![30, 10, 20];
        assert_eq!(
            multiset_fingerprint(&a, challenge),
            multiset_fingerprint(&b, challenge)
        );
    }

    #[test]
    fn permutation_mapping() {
        let input = vec![50, 30, 10, 40, 20];
        let perm = vec![2, 4, 1, 3, 0]; // sorted ascending indices
        let output: Vec<u64> = perm.iter().map(|&i| input[i]).collect();
        assert_eq!(output, vec![10, 20, 30, 40, 50]);
        assert!(verify_permutation_mapping(&input, &output, &perm));
    }
}
