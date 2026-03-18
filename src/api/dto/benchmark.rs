//! Benchmark-related request/response DTOs.

use crate::benchmarks::types::{BackendKind, BenchmarkResult, BenchmarkScenario};
use crate::types::ZkDbError;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Request DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Request to run a single benchmark scenario.
#[derive(Debug, Deserialize)]
pub struct RunBenchmarkRequest {
    /// Scenario name (used for display). If absent, auto-generated.
    #[serde(default)]
    pub name: Option<String>,
    /// SQL query to benchmark.
    pub sql: String,
    /// Number of rows in the benchmark dataset.
    #[serde(default = "default_row_count")]
    pub row_count: usize,
    /// Chunk size for ingestion.
    #[serde(default)]
    pub chunk_size: Option<u32>,
    /// Which backend to use. Required. Valid values: "mock", "constraint_checked", "plonky2".
    /// Unknown or missing backend returns HTTP 400.
    pub backend: String,
    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_row_count() -> usize {
    1000
}

/// Request to run the standard benchmark suite.
#[derive(Debug, Deserialize)]
pub struct RunSuiteRequest {
    /// Number of rows per scenario.
    #[serde(default = "default_row_count")]
    pub row_count: usize,
    /// Which backend to use. Required. Valid values: "mock", "constraint_checked", "plonky2".
    /// Unknown or missing backend returns HTTP 400.
    pub backend: String,
    /// If true, run the extended suite with heavier scenarios.
    #[serde(default)]
    pub extended: bool,
}

/// Request to compare two benchmark runs.
#[derive(Debug, Deserialize)]
pub struct CompareBenchmarksRequest {
    pub run_id_a: String,
    pub run_id_b: String,
}

impl RunBenchmarkRequest {
    /// Convert DTO into a `BenchmarkScenario`, returning an error for unknown backends.
    pub fn into_scenario(self) -> Result<BenchmarkScenario, ZkDbError> {
        let name = self.name.unwrap_or_else(|| "custom".to_string());
        let backend = parse_backend_kind(&self.backend)?;
        let mut scenario = BenchmarkScenario::new(name, self.sql, self.row_count)
            .with_backend(backend)
            .with_tags(self.tags);
        if let Some(cs) = self.chunk_size {
            scenario = scenario.with_chunk_size(cs);
        }
        Ok(scenario)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Summary response for a single benchmark run.
#[derive(Debug, Serialize)]
pub struct BenchmarkResultResponse {
    pub run_id: String,
    pub scenario_name: String,
    pub backend: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub row_count: usize,
    pub chunk_count: usize,
    pub metrics: MetricsResponse,
    pub quality: QualityResponse,
    pub classification: ClassificationResponse,
    pub dataset_id: String,
    pub snapshot_id: String,
    pub query_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub dataset_generation_us: u64,
    pub ingestion_us: u64,
    pub snapshot_creation_us: u64,
    pub snapshot_activation_us: u64,
    pub query_planning_us: u64,
    pub proof_generation_us: u64,
    pub verification_us: u64,
    pub total_us: u64,
    pub proof_size_bytes: usize,
    pub verification_key_size_bytes: usize,
    pub proving_throughput_rps: f64,
}

#[derive(Debug, Serialize)]
pub struct QualityResponse {
    pub overall: String,
    pub proof_generation_time: String,
    pub verification_time: String,
    pub proof_size: String,
    pub vk_size: String,
}

#[derive(Debug, Serialize)]
pub struct ClassificationResponse {
    pub query_family: String,
    pub operator_family: String,
    pub complexity_class: String,
}

/// Response for the suite endpoint.
#[derive(Debug, Serialize)]
pub struct BenchmarkSuiteResponse {
    pub results: Vec<BenchmarkResultResponse>,
    pub total_scenarios: usize,
    pub successful: usize,
    pub failed: usize,
}

impl From<BenchmarkResult> for BenchmarkResultResponse {
    fn from(r: BenchmarkResult) -> Self {
        Self {
            run_id: r.run_id.to_string(),
            scenario_name: r.scenario.name.clone(),
            backend: r.scenario.backend.to_string(),
            success: r.success,
            error: r.error,
            row_count: r.metrics.row_count,
            chunk_count: r.metrics.chunk_count,
            metrics: MetricsResponse {
                dataset_generation_us: r.metrics.dataset_generation_us,
                ingestion_us: r.metrics.ingestion_us,
                snapshot_creation_us: r.metrics.snapshot_creation_us,
                snapshot_activation_us: r.metrics.snapshot_activation_us,
                query_planning_us: r.metrics.query_planning_us,
                proof_generation_us: r.metrics.proof_generation_us,
                verification_us: r.metrics.verification_us,
                total_us: r.metrics.total_us,
                proof_size_bytes: r.metrics.proof_size_bytes,
                verification_key_size_bytes: r.metrics.verification_key_size_bytes,
                proving_throughput_rps: r.metrics.proving_throughput_rps(),
            },
            quality: QualityResponse {
                overall: r.metrics.quality.overall.to_string(),
                proof_generation_time: r.metrics.quality.proof_generation_time.to_string(),
                verification_time: r.metrics.quality.verification_time.to_string(),
                proof_size: r.metrics.quality.proof_size.to_string(),
                vk_size: r.metrics.quality.vk_size.to_string(),
            },
            classification: ClassificationResponse {
                query_family: r.scenario.query_family.to_string(),
                operator_family: r.scenario.operator_family.to_string(),
                complexity_class: r.scenario.complexity_class.to_string(),
            },
            dataset_id: r.dataset_id.to_string(),
            snapshot_id: r.snapshot_id.to_string(),
            query_id: r.query_id.to_string(),
            proof_id: r.proof_id.map(|p| p.to_string()),
        }
    }
}

/// Parse a backend name string into a `BackendKind`.
///
/// Returns `Err` for unknown or empty values — callers must propagate this
/// as a 400 Bad Request. There is no silent fallback to Mock.
/// Parse a backend name string into a `BackendKind`.
///
/// "mock" is no longer valid — MockBackend has been removed.
/// Returns `Err` for unknown or empty values; callers propagate this as HTTP 400.
pub fn parse_backend_kind(s: &str) -> Result<BackendKind, ZkDbError> {
    match s.trim() {
        "constraint_checked" | "baseline" => Ok(BackendKind::ConstraintChecked),
        "plonky2" => Ok(BackendKind::Plonky2),
        "plonky3" => Ok(BackendKind::Plonky3),
        "halo2" => Ok(BackendKind::Halo2),
        "mock" => Err(ZkDbError::Schema(
            "'mock' backend has been removed. \
             Use 'constraint_checked' for integration testing or 'plonky2' for production ZK proving."
                .into(),
        )),
        "" => Err(ZkDbError::Schema(
            "backend is required. Valid values: constraint_checked, plonky2".into(),
        )),
        other => Err(ZkDbError::Schema(format!(
            "unknown backend '{}'. Valid values: constraint_checked, plonky2",
            other
        ))),
    }
}
