//! Shared application state injected into every handler.

use crate::backend::traits::ProvingBackend;
use crate::commitment::service::CommitmentService;
use crate::database::service::DatasetService;
use crate::database::storage::{ChunkStore, DatasetRepository, SnapshotRepository};
use crate::jobs::JobRegistry;
use crate::policy::engine::PolicyEngine;
use crate::proof::artifacts::InMemoryProofStore;
use crate::proof::{Prover, Verifier};
use crate::query::service::QueryService;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub dataset_service: Arc<DatasetService>,
    pub query_service: Arc<QueryService>,
    pub prover: Arc<Prover>,
    pub verifier: Arc<Verifier>,
    pub proof_store: Arc<InMemoryProofStore>,
    pub job_registry: Arc<JobRegistry>,
    pub policy_engine: Arc<PolicyEngine>,
    /// Proving backend — exposed so benchmark runner can create isolated instances.
    pub backend: Arc<dyn ProvingBackend>,
}

impl AppState {
    pub fn new(
        dataset_repo: Arc<dyn DatasetRepository>,
        snapshot_repo: Arc<dyn SnapshotRepository>,
        chunk_store: Arc<dyn ChunkStore>,
        commitment_svc: Arc<dyn CommitmentService>,
        backend: Arc<dyn ProvingBackend>,
        policy_engine: PolicyEngine,
    ) -> Self {
        let proof_store = Arc::new(InMemoryProofStore::new());
        let policy_engine = Arc::new(policy_engine);
        let job_registry = Arc::new(JobRegistry::new());

        let dataset_service = Arc::new(DatasetService::new(
            dataset_repo,
            snapshot_repo,
            chunk_store.clone(),
            commitment_svc,
        ));

        let query_service = Arc::new(QueryService::new(
            dataset_service.clone(),
            policy_engine.clone(),
        ));

        let prover = Arc::new(Prover::new(
            backend.clone(),
            chunk_store,
            proof_store.clone(),
        ));

        let verifier = Arc::new(Verifier::new(backend.clone(), proof_store.clone()));

        Self {
            dataset_service,
            query_service,
            prover,
            verifier,
            proof_store,
            job_registry,
            policy_engine,
            backend,
        }
    }
}
