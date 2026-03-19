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
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub dataset_service: Arc<DatasetService>,
    pub query_service: Arc<QueryService>,
    pub verifier: Arc<Verifier>,
    pub proof_store: Arc<InMemoryProofStore>,
    pub job_registry: Arc<JobRegistry>,
    pub policy_engine: Arc<PolicyEngine>,
    /// Per-backend provers keyed by backend name (e.g. "plonky2", "constraint_checked").
    pub provers: Arc<HashMap<String, Arc<Prover>>>,
    /// Default backend name used when no backend is specified in a request.
    pub default_backend: String,
}

impl AppState {
    pub fn new(
        dataset_repo: Arc<dyn DatasetRepository>,
        snapshot_repo: Arc<dyn SnapshotRepository>,
        chunk_store: Arc<dyn ChunkStore>,
        commitment_svc: Arc<dyn CommitmentService>,
        backends: Vec<(String, Arc<dyn ProvingBackend>)>,
        default_backend: String,
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

        // Use the first backend for verification (artifact deserialization is backend-agnostic).
        let verifier_backend = backends
            .first()
            .map(|(_, b)| b.clone())
            .expect("at least one backend required");

        let verifier = Arc::new(Verifier::new(verifier_backend, proof_store.clone()));

        let provers: HashMap<String, Arc<Prover>> = backends
            .into_iter()
            .map(|(name, backend)| {
                let prover = Arc::new(Prover::new(backend, chunk_store.clone(), proof_store.clone()));
                (name, prover)
            })
            .collect();

        Self {
            dataset_service,
            query_service,
            verifier,
            proof_store,
            job_registry,
            policy_engine,
            provers: Arc::new(provers),
            default_backend,
        }
    }

    /// Returns the prover for the requested backend name, or the default if not found.
    pub fn get_prover(&self, backend_name: &str) -> Arc<Prover> {
        self.provers
            .get(backend_name)
            .or_else(|| self.provers.get(&self.default_backend))
            .cloned()
            .expect("default prover must exist")
    }
}
