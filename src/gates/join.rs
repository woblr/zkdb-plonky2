//! Join gadgets: equi-join matching, join planning, execution trace.
//!
//! Implements real join logic for matching rows between two tables
//! based on equality of key columns.

/// Equi-join match: for each row in the left table, find matching rows in right table.
/// Both sides must be sorted by the join key.
///
/// Returns a list of (left_index, right_index) pairs.
pub fn equi_join_sorted(left_keys: &[u64], right_keys: &[u64]) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    let mut ri = 0;

    for (li, &lk) in left_keys.iter().enumerate() {
        // Advance right pointer to first match
        while ri < right_keys.len() && right_keys[ri] < lk {
            ri += 1;
        }
        // Collect all matching right rows
        let mut rj = ri;
        while rj < right_keys.len() && right_keys[rj] == lk {
            matches.push((li, rj));
            rj += 1;
        }
    }

    matches
}

/// Hash-based equi-join: index right table, probe with left table.
/// Does not require sorted input.
pub fn equi_join_hash(left_keys: &[u64], right_keys: &[u64]) -> Vec<(usize, usize)> {
    use std::collections::HashMap;

    // Build hash index on right side
    let mut right_index: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &k) in right_keys.iter().enumerate() {
        right_index.entry(k).or_default().push(i);
    }

    // Probe with left side
    let mut matches = Vec::new();
    for (li, &lk) in left_keys.iter().enumerate() {
        if let Some(right_indices) = right_index.get(&lk) {
            for &ri in right_indices {
                matches.push((li, ri));
            }
        }
    }

    matches
}

/// Join trace for witness generation and proof construction.
#[derive(Debug, Clone)]
pub struct JoinTrace {
    pub left_keys: Vec<u64>,
    pub right_keys: Vec<u64>,
    pub matched_pairs: Vec<(usize, usize)>,
    pub left_matched: Vec<bool>,
    pub right_matched: Vec<bool>,
    pub result_count: usize,
}

impl JoinTrace {
    /// Build join trace using hash join.
    pub fn build(left_keys: &[u64], right_keys: &[u64]) -> Self {
        let matched_pairs = equi_join_hash(left_keys, right_keys);
        let mut left_matched = vec![false; left_keys.len()];
        let mut right_matched = vec![false; right_keys.len()];
        for &(li, ri) in &matched_pairs {
            left_matched[li] = true;
            right_matched[ri] = true;
        }
        Self {
            left_keys: left_keys.to_vec(),
            right_keys: right_keys.to_vec(),
            matched_pairs: matched_pairs.clone(),
            left_matched,
            right_matched,
            result_count: matched_pairs.len(),
        }
    }

    /// Verify join correctness: all matched pairs have equal keys.
    pub fn verify(&self) -> bool {
        for &(li, ri) in &self.matched_pairs {
            if li >= self.left_keys.len() || ri >= self.right_keys.len() {
                return false;
            }
            if self.left_keys[li] != self.right_keys[ri] {
                return false;
            }
        }
        true
    }

    /// Verify completeness: no missed matches.
    pub fn verify_complete(&self) -> bool {
        let expected = equi_join_hash(&self.left_keys, &self.right_keys);
        if expected.len() != self.matched_pairs.len() {
            return false;
        }
        // All expected matches should be present
        for pair in &expected {
            if !self.matched_pairs.contains(pair) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_join_basic() {
        let left = vec![1, 2, 3, 4, 5];
        let right = vec![2, 4, 6];
        let matches = equi_join_sorted(&left, &right);
        assert_eq!(matches, vec![(1, 0), (3, 1)]);
    }

    #[test]
    fn sorted_join_duplicates() {
        let left = vec![1, 2, 2, 3];
        let right = vec![2, 2, 3];
        let matches = equi_join_sorted(&left, &right);
        // Both left[1] and left[2] match right[0] and right[1]
        assert_eq!(matches, vec![(1, 0), (1, 1), (2, 0), (2, 1), (3, 2)]);
    }

    #[test]
    fn hash_join_basic() {
        let left = vec![5, 3, 1, 4, 2];
        let right = vec![2, 4, 6];
        let matches = equi_join_hash(&left, &right);
        assert_eq!(matches.len(), 2);
        // left[3]=4 matches right[1]=4, left[4]=2 matches right[0]=2
        assert!(matches.contains(&(3, 1)));
        assert!(matches.contains(&(4, 0)));
    }

    #[test]
    fn join_trace_verify() {
        let left = vec![1, 2, 3, 4, 5];
        let right = vec![3, 5, 7];
        let trace = JoinTrace::build(&left, &right);
        assert!(trace.verify());
        assert!(trace.verify_complete());
        assert_eq!(trace.result_count, 2);
    }

    #[test]
    fn join_no_matches() {
        let left = vec![1, 2, 3];
        let right = vec![4, 5, 6];
        let trace = JoinTrace::build(&left, &right);
        assert!(trace.verify());
        assert_eq!(trace.result_count, 0);
    }
}
