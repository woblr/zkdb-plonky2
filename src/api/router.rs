//! Axum router assembly.

use crate::api::{
    handlers::{
        benchmarks::{
            compare_benchmarks, export_benchmarks, get_benchmark, list_benchmarks, run_benchmark,
            run_suite,
        },
        datasets::{
            activate_snapshot, create_dataset, create_snapshot, get_dataset, ingest_rows,
            list_datasets, list_snapshots,
        },
        queries::{get_job, get_proof, get_query_result, submit_query, verify_proof},
    },
    state::AppState,
};
use axum::{
    extract::State,
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Dataset routes
        .route("/v1/datasets", post(create_dataset).get(list_datasets))
        .route("/v1/datasets/:dataset_id", get(get_dataset))
        .route("/v1/datasets/:dataset_id/ingest", post(ingest_rows))
        .route(
            "/v1/datasets/:dataset_id/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route(
            "/v1/datasets/:dataset_id/snapshots/:snapshot_id/activate",
            post(activate_snapshot),
        )
        // Query routes
        .route("/v1/queries", post(submit_query))
        .route("/v1/queries/:query_id", get(get_query_result))
        // Proof routes
        .route("/v1/proofs/:proof_id", get(get_proof))
        .route("/v1/proofs/verify", post(verify_proof))
        // Benchmark routes
        .route("/v1/benchmarks", get(list_benchmarks))
        .route("/v1/benchmarks/run", post(run_benchmark))
        .route("/v1/benchmarks/suite", post(run_suite))
        .route("/v1/benchmarks/compare", post(compare_benchmarks))
        .route("/v1/benchmarks/export", get(export_benchmarks))
        .route("/v1/benchmarks/:run_id", get(get_benchmark))
        // Job routes
        .route("/v1/jobs/:job_id", get(get_job))
        // System info
        .route("/v1/system/info", get(system_info))
        // Health
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok", "service": "zkdb" }))
}

async fn system_info(State(state): State<AppState>) -> axum::Json<serde_json::Value> {
    let backends: Vec<serde_json::Value> = state
        .provers
        .keys()
        .map(|name| {
            let (zk, succinct, label) = match name.as_str() {
                "plonky2" => (true, true, "Plonky2 SNARK — FRI-based, Goldilocks field, zero-knowledge"),
                "constraint_checked" => (false, false, "Hash-chain audit — real constraints, NOT zero-knowledge"),
                _ => (false, false, "Unknown"),
            };
            serde_json::json!({
                "name": name,
                "has_zero_knowledge": zk,
                "is_succinct": succinct,
                "description": label,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "service": "zkdb",
        "version": env!("CARGO_PKG_VERSION"),
        "default_backend": state.default_backend,
        "available_backends": backends,
        "max_rows_per_circuit": 128,
        "field": "Goldilocks (2^64 - 2^32 + 1)",
        "hash": "Poseidon (PoseidonGoldilocksConfig)",
    }))
}
