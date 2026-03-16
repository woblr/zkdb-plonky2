//! Verifier: verifies a proof artifact against its public inputs.

use crate::backend::traits::ProvingBackend;
use crate::proof::artifacts::{InMemoryProofStore, VerificationRequest, VerificationResult};
use crate::types::ZkResult;
use std::sync::Arc;

pub struct Verifier {
    backend: Arc<dyn ProvingBackend>,
    proof_store: Arc<InMemoryProofStore>,
}

impl Verifier {
    pub fn new(
        backend: Arc<dyn ProvingBackend>,
        proof_store: Arc<InMemoryProofStore>,
    ) -> Self {
        Self { backend, proof_store }
    }

    pub async fn verify(&self, request: VerificationRequest) -> ZkResult<VerificationResult> {
        // Load the artifact
        let artifact = self.proof_store.get(&request.proof_id)?;

        // Optionally check expected public inputs
        if let Some(expected_root) = request.expected_snapshot_root {
            if artifact.public_inputs.snapshot_root != expected_root {
                return Ok(VerificationResult::invalid(
                    "snapshot root mismatch",
                ));
            }
        }
        if let Some(expected_hash) = request.expected_query_hash {
            if artifact.public_inputs.query_hash != expected_hash {
                return Ok(VerificationResult::invalid("query hash mismatch"));
            }
        }

        // Run backend verification
        self.backend.verify(&artifact).await
    }
}
