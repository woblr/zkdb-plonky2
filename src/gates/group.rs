//! Group boundary gadgets for GROUP BY operator.
//!
//! Given a sorted sequence of group keys, identify group boundaries
//! and accumulate per-group aggregates. This is the constraint logic
//! that backs the group_by operator circuit.

/// A group boundary marker: indicates where groups start/end in sorted data.
#[derive(Debug, Clone)]
pub struct GroupBoundary {
    /// For each row: 1 if this row starts a new group, 0 otherwise.
    /// First row is always 1.
    pub is_boundary: Vec<u64>,
    /// Group index for each row (0-based, incrementing at boundaries).
    pub group_index: Vec<u64>,
    /// Total number of distinct groups.
    pub num_groups: u64,
}

impl GroupBoundary {
    /// Compute group boundaries from sorted group keys.
    /// Adjacent equal keys belong to the same group.
    pub fn from_sorted_keys(keys: &[u64]) -> Self {
        if keys.is_empty() {
            return Self {
                is_boundary: vec![],
                group_index: vec![],
                num_groups: 0,
            };
        }

        let n = keys.len();
        let mut is_boundary = vec![0u64; n];
        let mut group_index = vec![0u64; n];

        is_boundary[0] = 1;
        group_index[0] = 0;
        let mut current_group = 0u64;

        for i in 1..n {
            if keys[i] != keys[i - 1] {
                is_boundary[i] = 1;
                current_group += 1;
            }
            group_index[i] = current_group;
        }

        Self {
            is_boundary,
            group_index,
            num_groups: current_group + 1,
        }
    }

    /// Compute group boundaries from sorted composite keys (multiple columns).
    pub fn from_sorted_composite_keys(key_columns: &[&[u64]]) -> Self {
        if key_columns.is_empty() || key_columns[0].is_empty() {
            return Self {
                is_boundary: vec![],
                group_index: vec![],
                num_groups: 0,
            };
        }

        let n = key_columns[0].len();
        let mut is_boundary = vec![0u64; n];
        let mut group_index = vec![0u64; n];

        is_boundary[0] = 1;
        group_index[0] = 0;
        let mut current_group = 0u64;

        for i in 1..n {
            let keys_differ = key_columns.iter().any(|col| col[i] != col[i - 1]);
            if keys_differ {
                is_boundary[i] = 1;
                current_group += 1;
            }
            group_index[i] = current_group;
        }

        Self {
            is_boundary,
            group_index,
            num_groups: current_group + 1,
        }
    }

    /// Verify that group boundaries are consistent with the keys.
    pub fn verify(&self, keys: &[u64]) -> bool {
        if keys.len() != self.is_boundary.len() {
            return false;
        }
        if keys.is_empty() {
            return true;
        }
        if self.is_boundary[0] != 1 {
            return false;
        }
        for i in 1..keys.len() {
            let expected_boundary = if keys[i] != keys[i - 1] { 1 } else { 0 };
            if self.is_boundary[i] != expected_boundary {
                return false;
            }
        }
        true
    }
}

/// Per-group aggregate accumulation.
#[derive(Debug, Clone)]
pub struct GroupAggregate {
    /// Group key value for each group.
    pub group_keys: Vec<u64>,
    /// Accumulated sum per group.
    pub group_sums: Vec<u64>,
    /// Row count per group.
    pub group_counts: Vec<u64>,
}

impl GroupAggregate {
    /// Compute per-group SUM and COUNT from sorted data + boundaries.
    pub fn accumulate(keys: &[u64], values: &[u64], boundaries: &GroupBoundary) -> Self {
        let num_groups = boundaries.num_groups as usize;
        let mut group_keys = Vec::with_capacity(num_groups);
        let mut group_sums = vec![0u64; num_groups];
        let mut group_counts = vec![0u64; num_groups];

        if keys.is_empty() {
            return Self {
                group_keys,
                group_sums,
                group_counts,
            };
        }

        // First group key
        group_keys.push(keys[0]);

        for i in 0..keys.len() {
            let g = boundaries.group_index[i] as usize;
            if boundaries.is_boundary[i] == 1 && g > 0 {
                group_keys.push(keys[i]);
            }
            group_sums[g] = group_sums[g].wrapping_add(values[i]);
            group_counts[g] += 1;
        }

        Self {
            group_keys,
            group_sums,
            group_counts,
        }
    }

    /// Compute per-group average.
    pub fn group_averages(&self) -> Vec<Option<f64>> {
        self.group_sums
            .iter()
            .zip(self.group_counts.iter())
            .map(|(&s, &c)| {
                if c == 0 {
                    None
                } else {
                    Some(s as f64 / c as f64)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_boundary_single_column() {
        let keys = vec![1, 1, 2, 2, 2, 3];
        let gb = GroupBoundary::from_sorted_keys(&keys);
        assert_eq!(gb.num_groups, 3);
        assert_eq!(gb.is_boundary, vec![1, 0, 1, 0, 0, 1]);
        assert_eq!(gb.group_index, vec![0, 0, 1, 1, 1, 2]);
        assert!(gb.verify(&keys));
    }

    #[test]
    fn group_aggregate_sum_count() {
        let keys = vec![1, 1, 2, 2, 3];
        let values = vec![10, 20, 30, 40, 50];
        let gb = GroupBoundary::from_sorted_keys(&keys);
        let agg = GroupAggregate::accumulate(&keys, &values, &gb);
        assert_eq!(agg.group_keys, vec![1, 2, 3]);
        assert_eq!(agg.group_sums, vec![30, 70, 50]);
        assert_eq!(agg.group_counts, vec![2, 2, 1]);
    }

    #[test]
    fn group_aggregate_averages() {
        let keys = vec![1, 1, 2, 2];
        let values = vec![10, 30, 20, 40];
        let gb = GroupBoundary::from_sorted_keys(&keys);
        let agg = GroupAggregate::accumulate(&keys, &values, &gb);
        let avgs = agg.group_averages();
        assert_eq!(avgs, vec![Some(20.0), Some(30.0)]);
    }
}
