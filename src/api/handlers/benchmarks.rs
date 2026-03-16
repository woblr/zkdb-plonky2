//! Benchmark handlers: run individual scenarios, suite, list, compare, export.

use axum::{
    extract::{Path, State},
    Json,
};

use crate::api::dto::benchmark::{
    BenchmarkResultResponse, BenchmarkSuiteResponse, CompareBenchmarksRequest,
    RunBenchmarkRequest, RunSuiteRequest,
};
use crate::api::error::ApiResult;
use crate::api::state::AppState;
use crate::benchmarks::cases::{extended_suite, standard_suite};
use crate::benchmarks::compare::BenchmarkComparison;
use crate::benchmarks::runner::BenchmarkRunner;
use crate::benchmarks::storage::BenchmarkStore;
use crate::benchmarks::types::BackendKind;

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/benchmarks/run
// ─────────────────────────────────────────────────────────────────────────────

/// Run a single benchmark scenario.
pub async fn run_benchmark(
    State(state): State<AppState>,
    Json(req): Json<RunBenchmarkRequest>,
) -> ApiResult<Json<BenchmarkResultResponse>> {
    let scenario = req.into_scenario();

    let runner = BenchmarkRunner::in_memory(state.backend.clone());
    let result = runner.run(&scenario).await;

    result.print_summary();

    // Persist result
    if let Ok(store) = BenchmarkStore::default_location() {
        let _ = store.save(&result);
    }

    Ok(Json(result.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/benchmarks/suite
// ─────────────────────────────────────────────────────────────────────────────

/// Run the standard (or extended) benchmark suite.
pub async fn run_suite(
    State(state): State<AppState>,
    Json(req): Json<RunSuiteRequest>,
) -> ApiResult<Json<BenchmarkSuiteResponse>> {
    let backend = match req.backend.as_deref() {
        Some("plonky2") => BackendKind::Plonky2,
        Some("plonky3") => BackendKind::Plonky3,
        Some("halo2") => BackendKind::Halo2,
        _ => BackendKind::Mock,
    };

    let scenarios = if req.extended {
        extended_suite(req.row_count, backend)
    } else {
        standard_suite(req.row_count, backend)
    };

    let runner = BenchmarkRunner::in_memory(state.backend.clone());
    let results = runner.run_suite(&scenarios).await;

    let total_scenarios = results.len();
    let successful = results.iter().filter(|r| r.success).count();
    let failed = total_scenarios - successful;

    // Print summaries
    for r in &results {
        r.print_summary();
    }

    // Persist suite
    if let Ok(store) = BenchmarkStore::default_location() {
        let _ = store.save_suite(&results);
    }

    let response_results: Vec<BenchmarkResultResponse> =
        results.into_iter().map(Into::into).collect();

    Ok(Json(BenchmarkSuiteResponse {
        results: response_results,
        total_scenarios,
        successful,
        failed,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// List stored benchmark run IDs.
pub async fn list_benchmarks() -> ApiResult<Json<serde_json::Value>> {
    let store = BenchmarkStore::default_location()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let run_ids = store
        .list_run_ids()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let suites = store
        .list_suites()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "run_ids": run_ids,
        "suites": suites,
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/benchmarks/:run_id
// ─────────────────────────────────────────────────────────────────────────────

/// Get a stored benchmark result by run ID.
pub async fn get_benchmark(
    Path(run_id): Path<String>,
) -> ApiResult<Json<BenchmarkResultResponse>> {
    let store = BenchmarkStore::default_location()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let result = store
        .load(&run_id)
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    Ok(Json(result.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/benchmarks/compare
// ─────────────────────────────────────────────────────────────────────────────

/// Compare two stored suite results.
pub async fn compare_benchmarks(
    Json(req): Json<CompareBenchmarksRequest>,
) -> ApiResult<Json<BenchmarkComparison>> {
    let store = BenchmarkStore::default_location()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let results_a = store
        .load_suite(&req.run_id_a)
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;
    let results_b = store
        .load_suite(&req.run_id_b)
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let comparison = BenchmarkComparison::compare(
        &req.run_id_a,
        &req.run_id_b,
        &results_a,
        &results_b,
    );

    comparison.print();

    Ok(Json(comparison))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/benchmarks/export
// ─────────────────────────────────────────────────────────────────────────────

/// Export all stored benchmark results as JSON.
pub async fn export_benchmarks() -> ApiResult<Json<serde_json::Value>> {
    let store = BenchmarkStore::default_location()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let json_str = store
        .export_all_json()
        .map_err(|e| crate::types::ZkDbError::Internal(e.to_string()))?;

    let value: serde_json::Value = serde_json::from_str(&json_str)
        .unwrap_or(serde_json::json!([]));

    Ok(Json(value))
}
