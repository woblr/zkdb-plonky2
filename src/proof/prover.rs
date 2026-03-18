//! Prover: orchestrates witness generation and proof generation for a query.

use crate::backend::traits::ProvingBackend;
use crate::circuit::witness::WitnessBuilder;
use crate::database::storage::ChunkStore;
use crate::proof::artifacts::{InMemoryProofStore, ProofArtifact};
use crate::query::proof_plan::ProofPlan;
use crate::query::service::NormalizedQuery;
use crate::types::ZkResult;
use std::sync::Arc;

pub struct Prover {
    backend: Arc<dyn ProvingBackend>,
    chunk_store: Arc<dyn ChunkStore>,
    proof_store: Arc<InMemoryProofStore>,
}

impl Prover {
    pub fn new(
        backend: Arc<dyn ProvingBackend>,
        chunk_store: Arc<dyn ChunkStore>,
        proof_store: Arc<InMemoryProofStore>,
    ) -> Self {
        Self {
            backend,
            chunk_store,
            proof_store,
        }
    }

    /// Full prove pipeline: witness → circuit → proof → store.
    pub async fn prove(
        &self,
        normalized: &NormalizedQuery,
        proof_plan: &ProofPlan,
    ) -> ZkResult<ProofArtifact> {
        // 1. Load snapshot chunks from store
        let chunks = self
            .chunk_store
            .read_snapshot_chunks(&normalized.snapshot_id)
            .await?;

        // 2. Build witness trace from chunks
        let witness = WitnessBuilder::build(
            normalized.query_id.clone(),
            normalized.snapshot_id.clone(),
            proof_plan,
            &chunks,
        )?;

        // 3. Compile circuit
        let circuit = self.backend.compile_circuit(proof_plan).await?;

        // 4. Generate proof
        let artifact = self.backend.prove(circuit.as_ref(), &witness).await?;

        // 5. Store proof
        self.proof_store.save(artifact.clone());

        Ok(artifact)
    }
}
