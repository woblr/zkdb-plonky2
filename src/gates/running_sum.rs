//! Running sum / accumulator gadget.
//!
//! Used for aggregate operators (SUM, COUNT, AVG) to prove correct accumulation.

/// Running sum trace: for each row, track the partial accumulation.
#[derive(Debug, Clone)]
pub struct RunningSumTrace {
    pub values: Vec<u64>,
    pub selectors: Vec<u64>,
    pub partial_sums: Vec<u64>,
    pub final_sum: u64,
    pub selected_count: u64,
}

impl RunningSumTrace {
    /// Build running sum trace from values and selectors.
    pub fn build(values: &[u64], selectors: &[u64]) -> Self {
        assert_eq!(values.len(), selectors.len());
        let n = values.len();
        let mut partial_sums = Vec::with_capacity(n);
        let mut acc = 0u64;
        let mut count = 0u64;

        for i in 0..n {
            if selectors[i] == 1 {
                acc = acc.wrapping_add(values[i]);
                count += 1;
            }
            partial_sums.push(acc);
        }

        Self {
            values: values.to_vec(),
            selectors: selectors.to_vec(),
            partial_sums,
            final_sum: acc,
            selected_count: count,
        }
    }

    /// Verify the running sum trace is consistent.
    /// For each row: partial_sums[i] = partial_sums[i-1] + selectors[i] * values[i]
    pub fn verify(&self) -> bool {
        let n = self.values.len();
        if n == 0 {
            return self.final_sum == 0 && self.selected_count == 0;
        }

        let mut expected_acc = 0u64;
        let mut expected_count = 0u64;

        for i in 0..n {
            if self.selectors[i] == 1 {
                expected_acc = expected_acc.wrapping_add(self.values[i]);
                expected_count += 1;
            }
            if self.partial_sums[i] != expected_acc {
                return false;
            }
        }

        self.final_sum == expected_acc && self.selected_count == expected_count
    }

    /// Compute average (returns None if count is zero).
    pub fn average(&self) -> Option<f64> {
        if self.selected_count == 0 {
            None
        } else {
            Some(self.final_sum as f64 / self.selected_count as f64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_sum_all_selected() {
        let trace = RunningSumTrace::build(&[10, 20, 30], &[1, 1, 1]);
        assert!(trace.verify());
        assert_eq!(trace.final_sum, 60);
        assert_eq!(trace.selected_count, 3);
        assert_eq!(trace.partial_sums, vec![10, 30, 60]);
    }

    #[test]
    fn running_sum_partial() {
        let trace = RunningSumTrace::build(&[10, 20, 30, 40], &[1, 0, 1, 0]);
        assert!(trace.verify());
        assert_eq!(trace.final_sum, 40);
        assert_eq!(trace.selected_count, 2);
    }

    #[test]
    fn running_sum_average() {
        let trace = RunningSumTrace::build(&[10, 20, 30], &[1, 1, 1]);
        assert_eq!(trace.average(), Some(20.0));
    }
}
