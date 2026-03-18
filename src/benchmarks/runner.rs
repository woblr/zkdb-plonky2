//! Benchmark runner: drives the full zkDB pipeline and collects metrics.
//!
//! The runner executes:
//!   1. Generate dataset
//!   2. Create dataset + ingest rows
//!   3. Create snapshot
//!   4. Activate snapshot
//!   5. Submit query
//!   6. Build proof plan + generate proof
//!   7. Verify proof
//!   8. Collect all metrics

use crate::backend::traits::ProvingBackend;
use crate::benchmarks::dataset::{generate_transactions, transactions_schema};
use crate::benchmarks::metrics::Stopwatch;
use crate::benchmarks::types::{
    BenchmarkMetrics, BenchmarkResult, BenchmarkRunId, BenchmarkScenario, MetricQualityFlags,
};
use crate::commitment::service::CommitmentService;
use crate::database::service::DatasetService;
use crate::database::storage::{ChunkStore, DatasetRepository, SnapshotRepository};
use crate::policy::engine::PolicyEngine;
use crate::proof::artifacts::{InMemoryProofStore, VerificationRequest};
use crate::proof::{Prover, Verifier};
use crate::query::service::{QueryRequest, QueryService};
use crate::types::{DatasetId, ProofId, QueryId, SnapshotId};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkRunner
// ─────────────────────────────────────────────────────────────────────────────

pub struct BenchmarkRunner {
    dataset_service: Arc<DatasetService>,
    query_service: Arc<QueryService>,
    prover: Arc<Prover>,
    verifier: Arc<Verifier>,
    #[allow(dead_code)]
    proof_store: Arc<InMemoryProofStore>,
}

impl BenchmarkRunner {
    /// Create a benchmark runner from existing services (shared with the API server).
    pub fn new(
        dataset_service: Arc<DatasetService>,
        query_service: Arc<QueryService>,
        prover: Arc<Prover>,
        verifier: Arc<Verifier>,
        proof_store: Arc<InMemoryProofStore>,
    ) -> Self {
        Self {
            dataset_service,
            query_service,
            prover,
            verifier,
            proof_store,
        }
    }

    /// Create a self-contained runner with in-memory storage and a given backend.
    pub fn in_memory(backend: Arc<dyn ProvingBackend>) -> Self {
        use crate::commitment::service::Blake3CommitmentService;
        use crate::database::storage::{
            InMemoryChunkStore, InMemoryDatasetRepository, InMemorySnapshotRepository,
        };

        let dataset_repo = Arc::new(InMemoryDatasetRepository::new());
        let snapshot_repo = Arc::new(InMemorySnapshotRepository::new());
        let chunk_store = Arc::new(InMemoryChunkStore::new());
        let commitment_svc: Arc<dyn CommitmentService> = Arc::new(Blake3CommitmentService);

        let dataset_service = Arc::new(DatasetService::new(
            dataset_repo as Arc<dyn DatasetRepository>,
            snapshot_repo as Arc<dyn SnapshotRepository>,
            chunk_store.clone() as Arc<dyn ChunkStore>,
            commitment_svc,
        ));

        let policy_engine = Arc::new(PolicyEngine::new());
        let query_service = Arc::new(QueryService::new(dataset_service.clone(), policy_engine));

        let proof_store = Arc::new(InMemoryProofStore::new());
        let prover = Arc::new(Prover::new(
            backend.clone(),
            chunk_store as Arc<dyn ChunkStore>,
            proof_store.clone(),
        ));
        let verifier = Arc::new(Verifier::new(backend, proof_store.clone()));

        Self {
            dataset_service,
            query_service,
            prover,
            verifier,
            proof_store,
        }
    }

    /// Run a single benchmark scenario end-to-end.
    pub async fn run(&self, scenario: &BenchmarkScenario) -> BenchmarkResult {
        let run_id = BenchmarkRunId::new();
        let started_at_ms = now_ms();
        let mut sw = Stopwatch::start();
        let mut metrics = BenchmarkMetrics::empty();
        metrics.row_count = scenario.row_count;
        metrics.quality = MetricQualityFlags::from_backend(&scenario.backend);

        let mut dataset_id = DatasetId::new();
        let mut snapshot_id = SnapshotId::new();
        let mut query_id = QueryId::new();
        let mut proof_id: Option<ProofId> = None;

        let result = self
            .run_inner(
                scenario,
                &mut sw,
                &mut metrics,
                &mut dataset_id,
                &mut snapshot_id,
                &mut query_id,
                &mut proof_id,
            )
            .await;

        metrics.total_us = sw.total_us();
        let finished_at_ms = now_ms();

        match result {
            Ok(()) => BenchmarkResult {
                run_id,
                scenario: scenario.clone(),
                dataset_id,
                snapshot_id,
                query_id,
                proof_id,
                metrics,
                success: true,
                error: None,
                started_at_ms,
                finished_at_ms,
            },
            Err(e) => BenchmarkResult {
                run_id,
                scenario: scenario.clone(),
                dataset_id,
                snapshot_id,
                query_id,
                proof_id,
                metrics,
                success: false,
                error: Some(e.to_string()),
                started_at_ms,
                finished_at_ms,
            },
        }
    }

    async fn run_inner(
        &self,
        scenario: &BenchmarkScenario,
        sw: &mut Stopwatch,
        metrics: &mut BenchmarkMetrics,
        dataset_id: &mut DatasetId,
        snapshot_id: &mut SnapshotId,
        query_id: &mut QueryId,
        proof_id: &mut Option<ProofId>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // ── 1. Generate dataset ────────────────────────────────────────────
        let schema = transactions_schema(DatasetId::new());
        let rows = generate_transactions(scenario.row_count);
        metrics.dataset_generation_us = sw.lap();

        // ── 2. Create dataset + ingest ─────────────────────────────────────
        let ds_record = self.dataset_service.create_dataset(schema).await?;
        *dataset_id = ds_record.dataset_id.clone();

        let ingest_result = self
            .dataset_service
            .ingest_rows(&ds_record.dataset_id, rows, Some(scenario.chunk_size))
            .await?;
        metrics.ingestion_us = sw.lap();
        metrics.chunk_count = ingest_result.chunks_created as usize;

        // ── 3. Create snapshot ─────────────────────────────────────────────
        let snap_record = self
            .dataset_service
            .create_snapshot(&ds_record.dataset_id)
            .await?;
        *snapshot_id = snap_record.snapshot_id.clone();
        metrics.snapshot_creation_us = sw.lap();

        // ── 4. Activate snapshot ───────────────────────────────────────────
        self.dataset_service
            .activate_snapshot(&ds_record.dataset_id, &snap_record.snapshot_id)
            .await?;
        metrics.snapshot_activation_us = sw.lap();

        // ── 5. Submit query ────────────────────────────────────────────────
        let request = QueryRequest {
            dataset_id: ds_record.dataset_id.clone(),
            sql: scenario.sql.clone(),
            snapshot_id: Some(snap_record.snapshot_id.clone()),
            user_id: Some("benchmark".to_string()),
            user_roles: vec!["admin".to_string()],
        };
        let normalized = self.query_service.submit(request).await?;
        *query_id = normalized.query_id.clone();

        // ── 6. Build proof plan + generate proof ───────────────────────────
        let proof_plan = self.query_service.build_proof_plan(&normalized).await?;
        metrics.query_planning_us = sw.lap();

        let artifact = self.prover.prove(&normalized, &proof_plan).await?;
        metrics.proof_generation_us = sw.lap();
        metrics.proof_size_bytes = artifact.proof_bytes.len();
        metrics.verification_key_size_bytes = artifact.verification_key_bytes.len();
        let pid = artifact.proof_id.clone();
        *proof_id = Some(pid.clone());

        // ── 7. Verify proof ────────────────────────────────────────────────
        let ver_req = VerificationRequest {
            proof_id: pid,
            expected_snapshot_root: None,
            expected_query_hash: None,
        };
        let verification = self.verifier.verify(ver_req).await?;
        metrics.verification_us = sw.lap();

        if !verification.is_valid {
            return Err(format!(
                "verification failed: {}",
                verification.error.unwrap_or_default()
            )
            .into());
        }

        Ok(())
    }

    /// Run a full suite of scenarios, returning all results.
    pub async fn run_suite(&self, scenarios: &[BenchmarkScenario]) -> Vec<BenchmarkResult> {
        let mut results = Vec::with_capacity(scenarios.len());
        for scenario in scenarios {
            let result = self.run(scenario).await;
            results.push(result);
        }
        results
    }

    /// Run a single scenario multiple times and return all results (for statistical analysis).
    pub async fn run_repeated(
        &self,
        scenario: &BenchmarkScenario,
        iterations: usize,
    ) -> Vec<BenchmarkResult> {
        let mut results = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            // Each iteration needs its own in-memory runner since datasets are ephemeral
            results.push(self.run(scenario).await);
        }
        results
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
