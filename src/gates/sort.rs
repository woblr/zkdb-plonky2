//! Sort gadgets: verify ordering, permutation checks, top-k selection.
//!
//! These are the building blocks for the sort operator circuit.

/// Verify a slice is sorted ascending. Returns the index of the first violation, or None.
pub fn verify_ascending(values: &[u64]) -> Option<usize> {
    for i in 1..values.len() {
        if values[i] < values[i - 1] {
            return Some(i);
        }
    }
    None
}

/// Verify a slice is sorted descending.
pub fn verify_descending(values: &[u64]) -> Option<usize> {
    for i in 1..values.len() {
        if values[i] > values[i - 1] {
            return Some(i);
        }
    }
    None
}

/// Produce a sorting permutation (indices that would sort the slice).
pub fn sort_permutation_asc(values: &[u64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..values.len()).collect();
    indices.sort_by_key(|&i| values[i]);
    indices
}

/// Produce a descending sort permutation.
pub fn sort_permutation_desc(values: &[u64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..values.len()).collect();
    indices.sort_by(|&a, &b| values[b].cmp(&values[a]));
    indices
}

/// Apply a permutation to reorder values.
pub fn apply_permutation<T: Clone>(values: &[T], perm: &[usize]) -> Vec<T> {
    perm.iter().map(|&i| values[i].clone()).collect()
}

/// Verify that `perm` is a valid permutation of [0..n).
pub fn verify_permutation(perm: &[usize], n: usize) -> bool {
    if perm.len() != n {
        return false;
    }
    let mut seen = vec![false; n];
    for &i in perm {
        if i >= n || seen[i] {
            return false;
        }
        seen[i] = true;
    }
    true
}

/// Top-K selection: return indices of the K smallest values.
pub fn top_k_ascending(values: &[u64], k: usize) -> Vec<usize> {
    let mut perm = sort_permutation_asc(values);
    perm.truncate(k);
    perm
}

/// Top-K selection: return indices of the K largest values.
pub fn top_k_descending(values: &[u64], k: usize) -> Vec<usize> {
    let mut perm = sort_permutation_desc(values);
    perm.truncate(k);
    perm
}

/// Sort trace for witness generation.
#[derive(Debug, Clone)]
pub struct SortTrace {
    pub input_values: Vec<u64>,
    pub permutation: Vec<usize>,
    pub sorted_values: Vec<u64>,
    pub ascending: bool,
}

impl SortTrace {
    pub fn build_ascending(values: &[u64]) -> Self {
        let perm = sort_permutation_asc(values);
        let sorted = apply_permutation(values, &perm);
        Self {
            input_values: values.to_vec(),
            permutation: perm,
            sorted_values: sorted,
            ascending: true,
        }
    }

    pub fn build_descending(values: &[u64]) -> Self {
        let perm = sort_permutation_desc(values);
        let sorted = apply_permutation(values, &perm);
        Self {
            input_values: values.to_vec(),
            permutation: perm,
            sorted_values: sorted,
            ascending: false,
        }
    }

    pub fn verify(&self) -> bool {
        if !verify_permutation(&self.permutation, self.input_values.len()) {
            return false;
        }
        let reordered = apply_permutation(&self.input_values, &self.permutation);
        if reordered != self.sorted_values {
            return false;
        }
        if self.ascending {
            verify_ascending(&self.sorted_values).is_none()
        } else {
            verify_descending(&self.sorted_values).is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_ascending() {
        let vals = vec![30, 10, 50, 20, 40];
        let trace = SortTrace::build_ascending(&vals);
        assert!(trace.verify());
        assert_eq!(trace.sorted_values, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn sort_descending() {
        let vals = vec![30, 10, 50, 20, 40];
        let trace = SortTrace::build_descending(&vals);
        assert!(trace.verify());
        assert_eq!(trace.sorted_values, vec![50, 40, 30, 20, 10]);
    }

    #[test]
    fn top_k() {
        let vals = vec![30, 10, 50, 20, 40];
        let top3 = top_k_ascending(&vals, 3);
        let selected: Vec<u64> = top3.iter().map(|&i| vals[i]).collect();
        assert_eq!(selected, vec![10, 20, 30]);
    }

    #[test]
    fn permutation_roundtrip() {
        let vals = vec![5, 3, 8, 1, 4];
        let perm = sort_permutation_asc(&vals);
        assert!(verify_permutation(&perm, vals.len()));
        let sorted = apply_permutation(&vals, &perm);
        assert_eq!(sorted, vec![1, 3, 4, 5, 8]);
    }
}
