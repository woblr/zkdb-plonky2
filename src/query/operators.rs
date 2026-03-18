//! Real operator execution engine.
//!
//! This module implements actual data-processing logic for each operator type.
//! Unlike the circuit layer (which deals with constraint-level proofs), this module
//! performs the actual row-level computation that produces results and execution traces.
//!
//! Execution traces are used as witness data for proof generation.

use crate::gates::{
    group::{GroupAggregate, GroupBoundary},
    join::JoinTrace,
    running_sum::RunningSumTrace,
    sort::SortTrace,
};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Column data representation for operator execution
// ─────────────────────────────────────────────────────────────────────────────

/// A columnar data batch — the execution unit for operators.
#[derive(Debug, Clone)]
pub struct DataBatch {
    pub columns: Vec<ColumnData>,
    pub row_count: usize,
}

/// A single column's data.
#[derive(Debug, Clone)]
pub struct ColumnData {
    pub name: String,
    /// Raw u64 values. Text columns use hash of string.
    pub values: Vec<u64>,
}

impl DataBatch {
    pub fn new(columns: Vec<ColumnData>) -> Self {
        let row_count = columns.first().map(|c| c.values.len()).unwrap_or(0);
        Self { columns, row_count }
    }

    pub fn column_by_name(&self, name: &str) -> Option<&ColumnData> {
        self.columns.iter().find(|c| c.name == name)
    }

    pub fn column_values(&self, name: &str) -> Option<&[u64]> {
        self.column_by_name(name).map(|c| c.values.as_slice())
    }

    pub fn select_rows(&self, indices: &[usize]) -> DataBatch {
        let columns = self
            .columns
            .iter()
            .map(|col| ColumnData {
                name: col.name.clone(),
                values: indices.iter().map(|&i| col.values[i]).collect(),
            })
            .collect();
        DataBatch::new(columns)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filter operator
// ─────────────────────────────────────────────────────────────────────────────

/// Filter execution result.
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub output: DataBatch,
    pub selector: Vec<u64>,
    pub selected_count: usize,
    pub input_count: usize,
}

/// Execute a filter: select rows where the predicate column satisfies a condition.
/// For now, supports comparison predicates on a single column.
pub fn execute_filter(
    input: &DataBatch,
    column_name: &str,
    predicate: impl Fn(u64) -> bool,
) -> FilterResult {
    let col = input
        .column_by_name(column_name)
        .expect("filter column not found");

    let selector: Vec<u64> = col
        .values
        .iter()
        .map(|&v| if predicate(v) { 1 } else { 0 })
        .collect();
    let selected_indices: Vec<usize> = selector
        .iter()
        .enumerate()
        .filter(|(_, &s)| s == 1)
        .map(|(i, _)| i)
        .collect();
    let selected_count = selected_indices.len();
    let output = input.select_rows(&selected_indices);

    FilterResult {
        output,
        selector,
        selected_count,
        input_count: input.row_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate operator
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate execution result (no grouping).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateResult {
    pub sum: u64,
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub avg: f64,
    pub running_sum_trace: Vec<u64>,
}

/// Execute a simple aggregate (no group-by) on a column.
pub fn execute_aggregate(values: &[u64]) -> AggregateResult {
    if values.is_empty() {
        return AggregateResult {
            sum: 0,
            count: 0,
            min: 0,
            max: 0,
            avg: 0.0,
            running_sum_trace: vec![],
        };
    }

    let selectors: Vec<u64> = vec![1; values.len()];
    let trace = RunningSumTrace::build(values, &selectors);

    AggregateResult {
        sum: trace.final_sum,
        count: trace.selected_count,
        min: *values.iter().min().unwrap(),
        max: *values.iter().max().unwrap(),
        avg: trace.average().unwrap_or(0.0),
        running_sum_trace: trace.partial_sums,
    }
}

/// Execute a filtered aggregate.
pub fn execute_filtered_aggregate(values: &[u64], selectors: &[u64]) -> AggregateResult {
    let trace = RunningSumTrace::build(values, selectors);

    let selected_vals: Vec<u64> = values
        .iter()
        .zip(selectors.iter())
        .filter(|(_, &s)| s == 1)
        .map(|(&v, _)| v)
        .collect();

    let (min, max) = if selected_vals.is_empty() {
        (0, 0)
    } else {
        (
            *selected_vals.iter().min().unwrap(),
            *selected_vals.iter().max().unwrap(),
        )
    };

    AggregateResult {
        sum: trace.final_sum,
        count: trace.selected_count,
        min,
        max,
        avg: trace.average().unwrap_or(0.0),
        running_sum_trace: trace.partial_sums,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Group By operator — REAL implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Group-by execution result.
#[derive(Debug, Clone)]
pub struct GroupByResult {
    pub group_keys: Vec<u64>,
    pub group_sums: Vec<u64>,
    pub group_counts: Vec<u64>,
    pub group_averages: Vec<f64>,
    pub num_groups: usize,
    /// The sort trace proving data was sorted by group key.
    pub sort_trace: SortTrace,
    /// The group boundary witness.
    pub boundary: GroupBoundary,
    /// Per-group aggregate accumulation.
    pub aggregate: GroupAggregate,
}

/// Execute GROUP BY with SUM and COUNT on a single group key column.
/// This is a REAL implementation that:
/// 1. Sorts data by group key (producing a sort permutation trace)
/// 2. Identifies group boundaries
/// 3. Accumulates per-group aggregates
pub fn execute_group_by(group_key_values: &[u64], agg_values: &[u64]) -> GroupByResult {
    assert_eq!(group_key_values.len(), agg_values.len());

    // Step 1: Sort by group key
    let sort_trace = SortTrace::build_ascending(group_key_values);

    // Step 2: Apply sort permutation to both key and value columns
    let sorted_keys: Vec<u64> = sort_trace
        .permutation
        .iter()
        .map(|&i| group_key_values[i])
        .collect();
    let sorted_vals: Vec<u64> = sort_trace
        .permutation
        .iter()
        .map(|&i| agg_values[i])
        .collect();

    // Step 3: Identify group boundaries
    let boundary = GroupBoundary::from_sorted_keys(&sorted_keys);

    // Step 4: Accumulate per-group aggregates
    let aggregate = GroupAggregate::accumulate(&sorted_keys, &sorted_vals, &boundary);
    let group_averages: Vec<f64> = aggregate
        .group_sums
        .iter()
        .zip(aggregate.group_counts.iter())
        .map(|(&s, &c)| if c > 0 { s as f64 / c as f64 } else { 0.0 })
        .collect();
    let num_groups = aggregate.group_keys.len();

    GroupByResult {
        group_keys: aggregate.group_keys.clone(),
        group_sums: aggregate.group_sums.clone(),
        group_counts: aggregate.group_counts.clone(),
        group_averages,
        num_groups,
        sort_trace,
        boundary,
        aggregate,
    }
}

/// Execute GROUP BY with multiple group key columns (composite key).
pub fn execute_group_by_composite(key_columns: &[&[u64]], agg_values: &[u64]) -> GroupByResult {
    if key_columns.is_empty() {
        return execute_group_by(&[], &[]);
    }

    let n = key_columns[0].len();

    // Sort by composite key (primary key first)
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_by(|&a, &b| {
        for col in key_columns {
            match col[a].cmp(&col[b]) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    });

    // Build sort trace for primary key column
    let sort_trace = SortTrace {
        input_values: key_columns[0].to_vec(),
        permutation: indices.clone(),
        sorted_values: indices.iter().map(|&i| key_columns[0][i]).collect(),
        ascending: true,
    };

    let sorted_primary_keys: Vec<u64> = indices.iter().map(|&i| key_columns[0][i]).collect();
    let sorted_vals: Vec<u64> = indices.iter().map(|&i| agg_values[i]).collect();

    let sorted_key_columns: Vec<Vec<u64>> = key_columns
        .iter()
        .map(|col| indices.iter().map(|&i| col[i]).collect())
        .collect();
    let sorted_key_refs: Vec<&[u64]> = sorted_key_columns.iter().map(|v| v.as_slice()).collect();

    let boundary = GroupBoundary::from_sorted_composite_keys(&sorted_key_refs);
    let aggregate = GroupAggregate::accumulate(&sorted_primary_keys, &sorted_vals, &boundary);
    let group_averages: Vec<f64> = aggregate
        .group_sums
        .iter()
        .zip(aggregate.group_counts.iter())
        .map(|(&s, &c)| if c > 0 { s as f64 / c as f64 } else { 0.0 })
        .collect();
    let num_groups = aggregate.group_keys.len();

    GroupByResult {
        group_keys: aggregate.group_keys.clone(),
        group_sums: aggregate.group_sums.clone(),
        group_counts: aggregate.group_counts.clone(),
        group_averages,
        num_groups,
        sort_trace,
        boundary,
        aggregate,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sort operator — REAL implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Sort execution result.
#[derive(Debug, Clone)]
pub struct SortResult {
    pub output: DataBatch,
    pub sort_trace: SortTrace,
}

/// Execute ORDER BY ascending on a column.
pub fn execute_sort_asc(input: &DataBatch, sort_column: &str) -> SortResult {
    let col = input
        .column_by_name(sort_column)
        .expect("sort column not found");

    let sort_trace = SortTrace::build_ascending(&col.values);
    let output = input.select_rows(&sort_trace.permutation);

    SortResult { output, sort_trace }
}

/// Execute ORDER BY descending on a column.
pub fn execute_sort_desc(input: &DataBatch, sort_column: &str) -> SortResult {
    let col = input
        .column_by_name(sort_column)
        .expect("sort column not found");

    let sort_trace = SortTrace::build_descending(&col.values);
    let output = input.select_rows(&sort_trace.permutation);

    SortResult { output, sort_trace }
}

/// Execute TOP-K (LIMIT after sort).
pub fn execute_top_k(
    input: &DataBatch,
    sort_column: &str,
    k: usize,
    ascending: bool,
) -> SortResult {
    let col = input
        .column_by_name(sort_column)
        .expect("sort column not found");

    let mut sort_trace = if ascending {
        SortTrace::build_ascending(&col.values)
    } else {
        SortTrace::build_descending(&col.values)
    };

    sort_trace.permutation.truncate(k);
    sort_trace.sorted_values.truncate(k);
    let output = input.select_rows(&sort_trace.permutation);

    SortResult { output, sort_trace }
}

// ─────────────────────────────────────────────────────────────────────────────
// Join operator — REAL implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Join execution result.
#[derive(Debug, Clone)]
pub struct JoinResult {
    pub output: DataBatch,
    pub join_trace: JoinTrace,
    pub result_count: usize,
}

/// Execute an equi-join between two data batches on specified key columns.
/// This is a REAL hash-join implementation.
pub fn execute_equi_join(
    left: &DataBatch,
    right: &DataBatch,
    left_key: &str,
    right_key: &str,
) -> JoinResult {
    let left_col = left
        .column_by_name(left_key)
        .expect("left join key not found");
    let right_col = right
        .column_by_name(right_key)
        .expect("right join key not found");

    // Build join trace using real hash join from gates module
    let join_trace = JoinTrace::build(&left_col.values, &right_col.values);

    // Build output columns by combining matched rows
    let mut output_columns: Vec<ColumnData> = Vec::new();

    // Add left table columns (prefixed with table name if needed)
    for col in &left.columns {
        let values: Vec<u64> = join_trace
            .matched_pairs
            .iter()
            .map(|&(li, _)| col.values[li])
            .collect();
        output_columns.push(ColumnData {
            name: format!("left_{}", col.name),
            values,
        });
    }

    // Add right table columns
    for col in &right.columns {
        let values: Vec<u64> = join_trace
            .matched_pairs
            .iter()
            .map(|&(_, ri)| col.values[ri])
            .collect();
        output_columns.push(ColumnData {
            name: format!("right_{}", col.name),
            values,
        });
    }

    let result_count = join_trace.result_count;
    let output = DataBatch::new(output_columns);

    JoinResult {
        output,
        join_trace,
        result_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution trace types (used as witness data for proving)
// ─────────────────────────────────────────────────────────────────────────────

/// Complete execution trace for a query operator pipeline.
/// This is what gets fed to the circuit/proving layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub operator_name: String,
    pub input_row_count: usize,
    pub output_row_count: usize,
    /// Serialized trace data specific to the operator.
    pub trace_data: serde_json::Value,
    /// Commitment to the output (Blake3 hash).
    pub output_commitment: [u8; 32],
}

impl ExecutionTrace {
    pub fn for_filter(filter: &FilterResult) -> Self {
        let output_hash = blake3::hash(
            &filter
                .selector
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        Self {
            operator_name: "filter".into(),
            input_row_count: filter.input_count,
            output_row_count: filter.selected_count,
            trace_data: serde_json::json!({
                "selector": filter.selector,
                "selected_count": filter.selected_count,
            }),
            output_commitment: *output_hash.as_bytes(),
        }
    }

    pub fn for_group_by(result: &GroupByResult) -> Self {
        let data = serde_json::json!({
            "num_groups": result.num_groups,
            "group_keys": result.group_keys,
            "group_sums": result.group_sums,
            "group_counts": result.group_counts,
        });
        let output_hash = blake3::hash(data.to_string().as_bytes());
        Self {
            operator_name: "group_by".into(),
            input_row_count: result.sort_trace.input_values.len(),
            output_row_count: result.num_groups,
            trace_data: data,
            output_commitment: *output_hash.as_bytes(),
        }
    }

    pub fn for_sort(result: &SortResult) -> Self {
        let data = serde_json::json!({
            "permutation": result.sort_trace.permutation,
            "ascending": result.sort_trace.ascending,
        });
        let output_hash = blake3::hash(data.to_string().as_bytes());
        Self {
            operator_name: "sort".into(),
            input_row_count: result.sort_trace.input_values.len(),
            output_row_count: result.output.row_count,
            trace_data: data,
            output_commitment: *output_hash.as_bytes(),
        }
    }

    pub fn for_join(result: &JoinResult) -> Self {
        let data = serde_json::json!({
            "matched_pairs": result.join_trace.matched_pairs,
            "result_count": result.result_count,
        });
        let output_hash = blake3::hash(data.to_string().as_bytes());
        Self {
            operator_name: "join".into(),
            input_row_count: result.join_trace.left_keys.len() + result.join_trace.right_keys.len(),
            output_row_count: result.result_count,
            trace_data: data,
            output_commitment: *output_hash.as_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_batch() -> DataBatch {
        DataBatch::new(vec![
            ColumnData {
                name: "id".into(),
                values: vec![0, 1, 2, 3, 4],
            },
            ColumnData {
                name: "amount".into(),
                values: vec![100, 500, 200, 800, 300],
            },
            ColumnData {
                name: "region".into(),
                values: vec![1, 2, 1, 2, 1],
            },
        ])
    }

    #[test]
    fn filter_execution() {
        let batch = sample_batch();
        let result = execute_filter(&batch, "amount", |v| v > 250);
        assert_eq!(result.selected_count, 3); // 500, 800, 300
        assert_eq!(result.output.row_count, 3);
    }

    #[test]
    fn aggregate_execution() {
        let values = vec![100, 500, 200, 800, 300];
        let result = execute_aggregate(&values);
        assert_eq!(result.sum, 1900);
        assert_eq!(result.count, 5);
        assert_eq!(result.min, 100);
        assert_eq!(result.max, 800);
    }

    #[test]
    fn group_by_execution() {
        let keys = vec![2, 1, 2, 1, 2];
        let values = vec![100, 200, 300, 400, 500];
        let result = execute_group_by(&keys, &values);

        assert_eq!(result.num_groups, 2);
        // Group 1: values 200, 400 → sum=600, count=2
        // Group 2: values 100, 300, 500 → sum=900, count=3
        assert_eq!(result.group_keys, vec![1, 2]);
        assert_eq!(result.group_sums, vec![600, 900]);
        assert_eq!(result.group_counts, vec![2, 3]);
        assert!(result.sort_trace.verify());
    }

    #[test]
    fn sort_ascending_execution() {
        let batch = sample_batch();
        let result = execute_sort_asc(&batch, "amount");
        let sorted_amounts = result.output.column_values("amount").unwrap();
        assert_eq!(sorted_amounts, &[100, 200, 300, 500, 800]);
        assert!(result.sort_trace.verify());
    }

    #[test]
    fn sort_descending_execution() {
        let batch = sample_batch();
        let result = execute_sort_desc(&batch, "amount");
        let sorted_amounts = result.output.column_values("amount").unwrap();
        assert_eq!(sorted_amounts, &[800, 500, 300, 200, 100]);
        assert!(result.sort_trace.verify());
    }

    #[test]
    fn top_k_execution() {
        let batch = sample_batch();
        let result = execute_top_k(&batch, "amount", 3, true);
        assert_eq!(result.output.row_count, 3);
        let amounts = result.output.column_values("amount").unwrap();
        assert_eq!(amounts, &[100, 200, 300]);
    }

    #[test]
    fn equi_join_execution() {
        let left = DataBatch::new(vec![
            ColumnData {
                name: "id".into(),
                values: vec![1, 2, 3, 4, 5],
            },
            ColumnData {
                name: "dept_id".into(),
                values: vec![10, 20, 10, 30, 20],
            },
        ]);
        let right = DataBatch::new(vec![
            ColumnData {
                name: "dept_id".into(),
                values: vec![10, 20, 40],
            },
            ColumnData {
                name: "dept_name".into(),
                values: vec![100, 200, 400],
            },
        ]);
        let result = execute_equi_join(&left, &right, "dept_id", "dept_id");
        // Matches: (0,0), (1,1), (2,0), (4,1)
        assert_eq!(result.result_count, 4);
        assert!(result.join_trace.verify());
    }

    #[test]
    fn execution_trace_for_filter() {
        let batch = sample_batch();
        let result = execute_filter(&batch, "amount", |v| v > 250);
        let trace = ExecutionTrace::for_filter(&result);
        assert_eq!(trace.operator_name, "filter");
        assert_eq!(trace.output_row_count, 3);
    }

    #[test]
    fn execution_trace_for_group_by() {
        let keys = vec![1, 1, 2, 2, 3];
        let values = vec![10, 20, 30, 40, 50];
        let result = execute_group_by(&keys, &values);
        let trace = ExecutionTrace::for_group_by(&result);
        assert_eq!(trace.operator_name, "group_by");
        assert_eq!(trace.output_row_count, 3);
    }

    #[test]
    fn execution_trace_for_sort() {
        let batch = sample_batch();
        let result = execute_sort_asc(&batch, "amount");
        let trace = ExecutionTrace::for_sort(&result);
        assert_eq!(trace.operator_name, "sort");
    }

    #[test]
    fn execution_trace_for_join() {
        let left = DataBatch::new(vec![ColumnData {
            name: "key".into(),
            values: vec![1, 2, 3],
        }]);
        let right = DataBatch::new(vec![ColumnData {
            name: "key".into(),
            values: vec![2, 3, 4],
        }]);
        let result = execute_equi_join(&left, &right, "key", "key");
        let trace = ExecutionTrace::for_join(&result);
        assert_eq!(trace.operator_name, "join");
        assert_eq!(trace.output_row_count, 2);
    }
}
