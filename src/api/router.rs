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
        // Health
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok", "service": "zkdb" }))
}
