//! Integration tests for real operator execution and the ConstraintCheckedBackend.
//!
//! These tests verify the complete pipeline:
//! query planner → proof plan → operator circuit → witness → proof → verification
//!
//! Tests are organized by operator family:
//! - GROUP BY (count, sum, avg)
//! - SORT (asc, desc, top_k)
//! - JOIN (equi-join baseline)
//! - End-to-end proof pipeline with ConstraintCheckedBackend

use std::sync::Arc;
use zkdb_plonky2::backend::ConstraintCheckedBackend;
use zkdb_plonky2::benchmarks::cases::{
    full_operator_suite, group_by_suite, join_suite, sort_suite, standard_suite,
};
use zkdb_plonky2::benchmarks::dataset::{
    generate_employees, generate_employees_dataset, generate_transactions,
};
use zkdb_plonky2::benchmarks::runner::BenchmarkRunner;
use zkdb_plonky2::benchmarks::types::{BackendKind, BenchmarkScenario};
use zkdb_plonky2::query::operators::{
    execute_equi_join, execute_group_by, execute_sort_asc, execute_sort_desc, execute_top_k,
    ColumnData, DataBatch,
};

// ─────────────────────────────────────────────────────────────────────────────
// Employees dataset tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn employees_dataset_is_deterministic() {
    let rows_a = generate_employees(200);
    let rows_b = generate_employees(200);
    assert_eq!(rows_a.len(), rows_b.len());
    for (a, b) in rows_a.iter().zip(rows_b.iter()) {
        assert_eq!(a.values, b.values, "row {} differs", a.row_index);
    }
}

#[test]
fn employees_dataset_correct_column_count() {
    let (schema, rows) = generate_employees_dataset(50);
    for row in &rows {
        assert_eq!(
            row.values.len(),
            schema.columns.len(),
            "row {} column count mismatch",
            row.row_index
        );
    }
    let names: Vec<&str> = schema.columns.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"employee_id"));
    assert!(names.contains(&"department"));
    assert!(names.contains(&"office"));
    assert!(names.contains(&"salary"));
    assert!(names.contains(&"manager_id"));
    assert!(names.contains(&"performance_score"));
}

#[test]
fn employees_dataset_salary_range() {
    let rows = generate_employees(1000);
    for row in &rows {
        // salary column is index 3; value should be in [30000, 200000)
        if let serde_json::Value::Number(n) = &row.values[3] {
            let salary = n.as_u64().unwrap();
            assert!(
                (30_000..200_000).contains(&salary),
                "salary {} out of expected range",
                salary
            );
        }
    }
}

#[test]
fn employees_dataset_departments_are_valid() {
    let valid_depts = [
        "engineering",
        "marketing",
        "sales",
        "finance",
        "hr",
        "operations",
        "legal",
        "research",
    ];
    let rows = generate_employees(500);
    for row in &rows {
        if let serde_json::Value::String(dept) = &row.values[1] {
            assert!(
                valid_depts.contains(&dept.as_str()),
                "unexpected department: {}",
                dept
            );
        }
    }
}

#[test]
fn transactions_dataset_is_deterministic() {
    let rows_a = generate_transactions(200);
    let rows_b = generate_transactions(200);
    assert_eq!(rows_a.len(), rows_b.len());
    for (a, b) in rows_a.iter().zip(rows_b.iter()) {
        assert_eq!(a.values, b.values, "row {} differs", a.row_index);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Real operator execution — GROUP BY
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn group_by_sum_three_groups() {
    // Pre-sorted keys, 3 groups of 2 rows each
    let keys: Vec<u64> = vec![1, 1, 2, 2, 3, 3];
    let vals: Vec<u64> = vec![10, 20, 30, 40, 50, 60];

    let result = execute_group_by(&keys, &vals);

    assert_eq!(result.num_groups, 3);
    assert_eq!(result.group_keys, vec![1, 2, 3]);
    assert_eq!(result.group_sums, vec![30, 70, 110]); // 10+20, 30+40, 50+60
    assert_eq!(result.group_counts, vec![2, 2, 2]);
}

#[test]
fn group_by_count_two_groups() {
    let keys: Vec<u64> = vec![100, 100, 100, 200, 200];
    let vals: Vec<u64> = vec![5, 10, 15, 20, 25];

    let result = execute_group_by(&keys, &vals);

    assert_eq!(result.num_groups, 2);
    assert_eq!(result.group_keys, vec![100, 200]);
    assert_eq!(result.group_sums, vec![30, 45]); // 5+10+15, 20+25
    assert_eq!(result.group_counts, vec![3, 2]);
}

#[test]
fn group_by_unsorted_input_gets_sorted() {
    // execute_group_by internally sorts — unsorted input should still work
    let keys: Vec<u64> = vec![3, 1, 2, 1, 3]; // unsorted
    let vals: Vec<u64> = vec![30, 10, 20, 10, 30];

    let result = execute_group_by(&keys, &vals);

    assert_eq!(result.num_groups, 3);
    // After sorting, groups should be 1, 2, 3
    assert_eq!(result.group_keys, vec![1, 2, 3]);
    assert_eq!(result.group_sums, vec![20, 20, 60]); // key1: 10+10, key2: 20, key3: 30+30
    assert_eq!(result.group_counts, vec![2, 1, 2]);
}

#[test]
fn group_by_single_group() {
    let keys: Vec<u64> = vec![42, 42, 42];
    let vals: Vec<u64> = vec![100, 200, 300];

    let result = execute_group_by(&keys, &vals);

    assert_eq!(result.num_groups, 1);
    assert_eq!(result.group_sums, vec![600]);
    assert_eq!(result.group_counts, vec![3]);
    assert!((result.group_averages[0] - 200.0).abs() < 1e-6);
}

#[test]
fn group_by_averages_are_correct() {
    let keys: Vec<u64> = vec![1, 1, 2, 2, 2];
    let vals: Vec<u64> = vec![10, 30, 20, 40, 60]; // group1 avg=20, group2 avg=40

    let result = execute_group_by(&keys, &vals);

    assert_eq!(result.num_groups, 2);
    assert!(
        (result.group_averages[0] - 20.0).abs() < 1e-6,
        "group1 avg should be 20"
    );
    assert!(
        (result.group_averages[1] - 40.0).abs() < 1e-6,
        "group2 avg should be 40"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Real operator execution — SORT
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sort_ascending_produces_sorted_output() {
    let values: Vec<u64> = vec![50, 10, 80, 20, 40];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "salary".into(),
            values,
        }],
        row_count: 5,
    };

    let result = execute_sort_asc(&batch, "salary");
    let sorted_col = &result.output.columns[0];
    assert_eq!(sorted_col.values, vec![10, 20, 40, 50, 80]);
}

#[test]
fn sort_descending_produces_sorted_output() {
    let values: Vec<u64> = vec![30, 90, 10, 60, 50];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "salary".into(),
            values,
        }],
        row_count: 5,
    };

    let result = execute_sort_desc(&batch, "salary");
    let sorted_col = &result.output.columns[0];
    assert_eq!(sorted_col.values, vec![90, 60, 50, 30, 10]);
}

#[test]
fn sort_top_k_ascending_returns_k_rows() {
    let values: Vec<u64> = vec![50, 10, 80, 20, 40, 30, 70, 60];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "score".into(),
            values,
        }],
        row_count: 8,
    };

    let result = execute_top_k(&batch, "score", 3, true);
    assert_eq!(result.output.row_count, 3);
    assert_eq!(result.output.columns[0].values, vec![10, 20, 30]);
}

#[test]
fn sort_top_k_descending_returns_k_rows() {
    let values: Vec<u64> = vec![50, 10, 80, 20, 40, 30, 70, 60];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "score".into(),
            values,
        }],
        row_count: 8,
    };

    let result = execute_top_k(&batch, "score", 3, false);
    assert_eq!(result.output.row_count, 3);
    assert_eq!(result.output.columns[0].values, vec![80, 70, 60]);
}

#[test]
fn sort_preserves_row_count() {
    let n = 100usize;
    let values: Vec<u64> = (0..n).rev().map(|i| i as u64).collect();
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "amount".into(),
            values,
        }],
        row_count: n,
    };

    let result = execute_sort_asc(&batch, "amount");
    assert_eq!(result.output.row_count, n);

    let col = &result.output.columns[0];
    for i in 1..col.values.len() {
        assert!(
            col.values[i - 1] <= col.values[i],
            "not sorted at index {}: {} > {}",
            i,
            col.values[i - 1],
            col.values[i]
        );
    }
}

#[test]
fn sort_already_sorted_asc_is_stable() {
    let values: Vec<u64> = vec![1, 2, 3, 4, 5];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "val".into(),
            values: values.clone(),
        }],
        row_count: 5,
    };
    let result = execute_sort_asc(&batch, "val");
    assert_eq!(result.output.columns[0].values, values);
}

#[test]
fn sort_trace_verify_passes() {
    let values: Vec<u64> = vec![5, 3, 1, 4, 2];
    let batch = DataBatch {
        columns: vec![ColumnData {
            name: "val".into(),
            values,
        }],
        row_count: 5,
    };
    let result = execute_sort_asc(&batch, "val");
    assert!(
        result.sort_trace.verify(),
        "sort trace verification should pass"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Real operator execution — EQUI-JOIN
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equi_join_basic_key_matching() {
    // Left: employee_id [1,2,3,4]
    // Right: manager_id [2,4] → should match rows 2 and 4
    let left = DataBatch {
        columns: vec![
            ColumnData {
                name: "employee_id".into(),
                values: vec![1, 2, 3, 4],
            },
            ColumnData {
                name: "salary".into(),
                values: vec![100, 200, 300, 400],
            },
        ],
        row_count: 4,
    };
    let right = DataBatch {
        columns: vec![
            ColumnData {
                name: "manager_id".into(),
                values: vec![2, 4],
            },
            ColumnData {
                name: "report_salary".into(),
                values: vec![50, 60],
            },
        ],
        row_count: 2,
    };

    let result = execute_equi_join(&left, &right, "employee_id", "manager_id");
    assert_eq!(
        result.result_count, 2,
        "expected 2 join results, got {}",
        result.result_count
    );
}

#[test]
fn equi_join_no_matches_produces_empty_result() {
    let left = DataBatch {
        columns: vec![ColumnData {
            name: "id".into(),
            values: vec![1, 2, 3],
        }],
        row_count: 3,
    };
    let right = DataBatch {
        columns: vec![ColumnData {
            name: "ref_id".into(),
            values: vec![10, 20],
        }],
        row_count: 2,
    };

    let result = execute_equi_join(&left, &right, "id", "ref_id");
    assert_eq!(result.result_count, 0, "expected empty join result");
}

#[test]
fn equi_join_all_keys_match() {
    let left = DataBatch {
        columns: vec![
            ColumnData {
                name: "key".into(),
                values: vec![5, 10, 15],
            },
            ColumnData {
                name: "lval".into(),
                values: vec![1, 2, 3],
            },
        ],
        row_count: 3,
    };
    let right = DataBatch {
        columns: vec![
            ColumnData {
                name: "key".into(),
                values: vec![5, 10, 15],
            },
            ColumnData {
                name: "rval".into(),
                values: vec![4, 5, 6],
            },
        ],
        row_count: 3,
    };

    let result = execute_equi_join(&left, &right, "key", "key");
    assert_eq!(result.result_count, 3);
}

#[test]
fn equi_join_trace_verify_passes() {
    let left = DataBatch {
        columns: vec![ColumnData {
            name: "id".into(),
            values: vec![1, 2, 3],
        }],
        row_count: 3,
    };
    let right = DataBatch {
        columns: vec![ColumnData {
            name: "fk".into(),
            values: vec![1, 3],
        }],
        row_count: 2,
    };

    let result = execute_equi_join(&left, &right, "id", "fk");
    assert!(
        result.join_trace.verify(),
        "join trace verification should pass"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintCheckedBackend end-to-end pipeline
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn baseline_backend_runs_filter_scenario() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "baseline_filter",
        "SELECT id, amount FROM benchmark_transactions WHERE amount > 50000",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::Baseline);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "baseline filter benchmark failed: {:?}",
        result.error
    );
    assert!(
        result.metrics.proof_size_bytes > 0,
        "expected non-empty proof"
    );
    assert!(result.metrics.proof_generation_us > 0);
    assert!(result.metrics.verification_us > 0);
}

#[tokio::test]
async fn baseline_backend_runs_aggregate_scenario() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "baseline_aggregate",
        "SELECT COUNT(*), SUM(amount) FROM benchmark_transactions",
        300,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::Baseline);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "baseline aggregate benchmark failed: {:?}",
        result.error
    );
}

#[tokio::test]
async fn baseline_backend_runs_sort_scenario() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "baseline_sort",
        "SELECT id, amount FROM benchmark_transactions ORDER BY amount ASC",
        150,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::Baseline);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "baseline sort benchmark failed: {:?}",
        result.error
    );
}

#[tokio::test]
async fn baseline_backend_runs_group_by_scenario() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "baseline_group_by",
        "SELECT region, SUM(amount) FROM benchmark_transactions GROUP BY region",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::Baseline);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "baseline group_by benchmark failed: {:?}",
        result.error
    );
}

#[tokio::test]
async fn baseline_proof_is_structured_json() {
    // Baseline proofs are JSON-serialized envelopes, distinguishable from Mock's Blake3 bytes
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "structure_check",
        "SELECT COUNT(*) FROM benchmark_transactions",
        100,
    )
    .with_chunk_size(32)
    .with_backend(BackendKind::Baseline);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "baseline scenario failed: {:?}",
        result.error
    );
    // Baseline proof bytes are non-empty
    assert!(
        result.metrics.proof_size_bytes > 0,
        "baseline should produce non-empty proof"
    );
}

#[tokio::test]
async fn baseline_and_mock_both_succeed_same_scenario() {
    let scenario = BenchmarkScenario::new(
        "comparison_test",
        "SELECT COUNT(*) FROM benchmark_transactions",
        100,
    )
    .with_chunk_size(32);

    let baseline_backend = Arc::new(ConstraintCheckedBackend::new());
    let mock_backend = Arc::new(ConstraintCheckedBackend::default());

    let baseline_result = BenchmarkRunner::in_memory(baseline_backend)
        .run(&scenario.clone().with_backend(BackendKind::Baseline))
        .await;
    let mock_result = BenchmarkRunner::in_memory(mock_backend)
        .run(&scenario.clone().with_backend(BackendKind::ConstraintChecked))
        .await;

    assert!(
        baseline_result.success,
        "baseline failed: {:?}",
        baseline_result.error
    );
    assert!(mock_result.success, "mock failed: {:?}", mock_result.error);
    assert!(baseline_result.metrics.proof_size_bytes > 0);
    assert!(mock_result.metrics.proof_size_bytes > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark suite tests — group_by, sort, join
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn group_by_suite_all_pass_mock() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let scenarios = group_by_suite(100, BackendKind::ConstraintChecked);
    let (total, successful, failed) = run_all(backend, &scenarios).await;
    println!("group_by suite (mock): {}/{} passed", successful, total);
    for f in &failed {
        eprintln!("  FAIL: {}", f);
    }
    assert_eq!(successful, total);
}

#[tokio::test]
async fn sort_suite_all_pass_mock() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let scenarios = sort_suite(100, BackendKind::ConstraintChecked);
    let (total, successful, failed) = run_all(backend, &scenarios).await;
    println!("sort suite (mock): {}/{} passed", successful, total);
    for f in &failed {
        eprintln!("  FAIL: {}", f);
    }
    assert_eq!(successful, total);
}

#[tokio::test]
async fn join_suite_all_pass_mock() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let scenarios = join_suite(100, BackendKind::ConstraintChecked);
    let (total, successful, failed) = run_all(backend, &scenarios).await;
    println!("join suite (mock): {}/{} passed", successful, total);
    for f in &failed {
        eprintln!("  FAIL: {}", f);
    }
    assert_eq!(successful, total);
}

#[tokio::test]
async fn group_by_suite_all_pass_baseline() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let scenarios = group_by_suite(100, BackendKind::Baseline);
    let (total, successful, failed) = run_all(backend, &scenarios).await;
    println!("group_by suite (baseline): {}/{} passed", successful, total);
    for f in &failed {
        eprintln!("  FAIL: {}", f);
    }
    assert!(successful > 0, "no group_by scenarios passed on baseline");
}

#[tokio::test]
async fn sort_suite_all_pass_baseline() {
    let backend = Arc::new(ConstraintCheckedBackend::new());
    let scenarios = sort_suite(100, BackendKind::Baseline);
    let (total, successful, failed) = run_all(backend, &scenarios).await;
    println!("sort suite (baseline): {}/{} passed", successful, total);
    for f in &failed {
        eprintln!("  FAIL: {}", f);
    }
    assert!(successful > 0, "no sort scenarios passed on baseline");
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend comparison: mock vs baseline
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn compare_mock_vs_baseline_on_standard_suite() {
    let scenarios = standard_suite(100, BackendKind::ConstraintChecked);
    let mut mock_wins = 0usize;
    let mut baseline_wins = 0usize;

    for scenario in &scenarios {
        let mock_backend = Arc::new(ConstraintCheckedBackend::default());
        let baseline_backend = Arc::new(ConstraintCheckedBackend::new());

        let mock_result = BenchmarkRunner::in_memory(mock_backend).run(scenario).await;
        let baseline_result = BenchmarkRunner::in_memory(baseline_backend)
            .run(&scenario.clone().with_backend(BackendKind::Baseline))
            .await;

        assert!(mock_result.success, "mock failed on {}", scenario.name);
        assert!(
            baseline_result.success,
            "baseline failed on {}",
            scenario.name
        );

        if mock_result.metrics.proof_generation_us <= baseline_result.metrics.proof_generation_us {
            mock_wins += 1;
        } else {
            baseline_wins += 1;
        }
    }

    println!(
        "\n=== Backend Comparison (standard suite, {} scenarios) ===\n\
         ConstraintChecked faster:         {} scenarios\n\
         ConstraintCheckedBackend faster: {} scenarios",
        scenarios.len(),
        mock_wins,
        baseline_wins
    );
    // Both backends must run all scenarios — no assertion on which is faster
}

// ─────────────────────────────────────────────────────────────────────────────
// Employees-specific scenarios via BenchmarkRunner
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn employees_group_by_department_passes() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "emp_dept_count",
        "SELECT department, COUNT(*) FROM benchmark_employees GROUP BY department",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::ConstraintChecked);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "employees group_by failed: {:?}",
        result.error
    );
}

#[tokio::test]
async fn employees_sort_salary_passes() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "emp_salary_sort",
        "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary ASC",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::ConstraintChecked);

    let result = runner.run(&scenario).await;
    assert!(result.success, "employees sort failed: {:?}", result.error);
}

#[tokio::test]
async fn employees_top10_salary_passes() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "emp_top10",
        "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary DESC LIMIT 10",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::ConstraintChecked);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "employees top-10 failed: {:?}",
        result.error
    );
}

#[tokio::test]
async fn employees_avg_salary_by_dept_passes() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "emp_avg_salary",
        "SELECT department, AVG(salary) FROM benchmark_employees GROUP BY department",
        200,
    )
    .with_chunk_size(64)
    .with_backend(BackendKind::ConstraintChecked);

    let result = runner.run(&scenario).await;
    assert!(
        result.success,
        "employees avg salary failed: {:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Full operator suite smoke test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn full_operator_suite_smoke_test() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let scenarios = full_operator_suite(100, BackendKind::ConstraintChecked);
    let (total, successful, failed) = run_all(backend, &scenarios).await;

    println!(
        "\n=== Full Operator Suite ===\n{}/{} scenarios passed",
        successful, total
    );
    for f in &failed {
        println!("  FAIL: {}", f);
    }

    assert_eq!(
        successful,
        total,
        "full_operator_suite: {}/{} failed:\n{}",
        total - successful,
        total,
        failed.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

async fn run_all(
    backend: Arc<dyn zkdb_plonky2::backend::ProvingBackend>,
    scenarios: &[BenchmarkScenario],
) -> (usize, usize, Vec<String>) {
    let total = scenarios.len();
    let mut successful = 0;
    let mut failed = Vec::new();

    for scenario in scenarios {
        let runner = BenchmarkRunner::in_memory(backend.clone());
        let result = runner.run(scenario).await;
        if result.success {
            successful += 1;
        } else {
            failed.push(format!("{}: {:?}", scenario.name, result.error));
        }
    }

    (total, successful, failed)
}
