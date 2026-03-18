//! Integration test: runs the benchmark pipeline end-to-end.

use std::sync::Arc;
use zkdb_plonky2::backend::ConstraintCheckedBackend;
use zkdb_plonky2::benchmarks::cases::standard_suite;
use zkdb_plonky2::benchmarks::dataset::generate_benchmark_dataset;
use zkdb_plonky2::benchmarks::metrics::results_to_json;
use zkdb_plonky2::benchmarks::runner::BenchmarkRunner;
use zkdb_plonky2::benchmarks::types::{BackendKind, BenchmarkScenario};

#[tokio::test]
async fn single_benchmark_scenario_succeeds() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "test_filter",
        "SELECT id, amount FROM benchmark_transactions WHERE amount > 50000",
        500,
    )
    .with_chunk_size(128);

    let result = runner.run(&scenario).await;
    result.print_summary();

    assert!(result.success, "benchmark failed: {:?}", result.error);
    assert!(result.metrics.proof_size_bytes > 0);
    assert!(result.metrics.proof_generation_us > 0);
    assert!(result.metrics.verification_us > 0);
    assert!(result.metrics.total_us > 0);
    assert!(result.metrics.chunk_count > 0);
    assert_eq!(result.metrics.row_count, 500);
}

#[tokio::test]
async fn count_aggregate_benchmark() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "test_count",
        "SELECT COUNT(*) FROM benchmark_transactions",
        200,
    )
    .with_chunk_size(64);

    let result = runner.run(&scenario).await;
    assert!(result.success, "benchmark failed: {:?}", result.error);
}

#[tokio::test]
async fn sum_with_filter_benchmark() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "test_sum_filter",
        "SELECT SUM(amount) FROM benchmark_transactions WHERE region = 'us-east'",
        300,
    )
    .with_chunk_size(64);

    let result = runner.run(&scenario).await;
    assert!(result.success, "benchmark failed: {:?}", result.error);
}

#[tokio::test]
async fn standard_suite_runs_all_scenarios() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let scenarios = standard_suite(100, BackendKind::ConstraintChecked);

    // Each scenario needs its own runner since each creates a fresh dataset
    let mut results = Vec::new();
    for scenario in &scenarios {
        let runner = BenchmarkRunner::in_memory(backend.clone());
        let result = runner.run(scenario).await;
        results.push(result);
    }

    let total = results.len();
    let successful = results.iter().filter(|r| r.success).count();

    println!("\n=== Suite Results ===");
    println!(
        "Total: {}, Successful: {}, Failed: {}",
        total,
        successful,
        total - successful
    );
    for r in &results {
        println!(
            "  {} — {} — proof: {} bytes, prove: {} µs",
            r.scenario.name,
            if r.success { "OK" } else { "FAIL" },
            r.metrics.proof_size_bytes,
            r.metrics.proof_generation_us
        );
    }

    // All scenarios should pass
    assert_eq!(successful, total, "some scenarios failed");

    // Verify JSON serialization works
    let json = results_to_json(&results);
    assert!(!json.is_empty());
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert!(parsed.is_array());
}

#[tokio::test]
async fn dataset_generation_is_deterministic() {
    let (schema_a, rows_a) = generate_benchmark_dataset(100);
    let (schema_b, rows_b) = generate_benchmark_dataset(100);

    // Schemas have different IDs, but same column structure
    assert_eq!(schema_a.columns.len(), schema_b.columns.len());
    for (ca, cb) in schema_a.columns.iter().zip(schema_b.columns.iter()) {
        assert_eq!(ca.name, cb.name);
        assert_eq!(ca.col_type, cb.col_type);
    }

    // Rows are value-identical
    assert_eq!(rows_a.len(), rows_b.len());
    for (ra, rb) in rows_a.iter().zip(rows_b.iter()) {
        assert_eq!(ra.values, rb.values);
    }
}

#[tokio::test]
async fn repeated_benchmark_produces_multiple_results() {
    let backend = Arc::new(ConstraintCheckedBackend::default());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "repeated_test",
        "SELECT COUNT(*) FROM benchmark_transactions",
        50,
    )
    .with_chunk_size(32);

    let results = runner.run_repeated(&scenario, 3).await;
    assert_eq!(results.len(), 3);

    for r in &results {
        assert!(r.success, "iteration failed: {:?}", r.error);
    }
}
