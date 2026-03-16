//! Mock proving backend for unit testing.
//!
//! Produces deterministic "proofs" (Blake3 hashes of the witness)
//! that verify against the same inputs without any real proving.

use crate::backend::traits::{CircuitHandle, ProvingBackend};
use crate::circuit::witness::WitnessTrace;
use crate::proof::artifacts::{ProofArtifact, ProofSystemKind, PublicInputs, VerificationResult};
use crate::query::proof_plan::ProofPlan;
use crate::types::{BackendTag, ProofId, ZkResult};
use async_trait::async_trait;
use serde_json;

// ─────────────────────────────────────────────────────────────────────────────
// Mock circuit handle
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MockCircuitHandle {
    pub plan_hash: [u8; 32],
    pub public_input_count: usize,
}

impl CircuitHandle for MockCircuitHandle {
    fn backend_tag(&self) -> BackendTag {
        BackendTag::Mock
    }

    fn num_public_inputs(&self) -> usize {
        self.public_input_count
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock backend
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct MockBackend;

#[async_trait]
impl ProvingBackend for MockBackend {
    fn tag(&self) -> BackendTag {
        BackendTag::Mock
    }

    async fn compile_circuit(&self, plan: &ProofPlan) -> ZkResult<Box<dyn CircuitHandle>> {
        let plan_json = serde_json::to_string(plan).unwrap_or_default();
        let plan_hash = *blake3::hash(plan_json.as_bytes()).as_bytes();
        Ok(Box::new(MockCircuitHandle {
            plan_hash,
            public_input_count: 3, // snapshot_root, query_hash, result_commitment
        }))
    }

    async fn prove(
        &self,
        circuit: &dyn CircuitHandle,
        witness: &WitnessTrace,
    ) -> ZkResult<ProofArtifact> {
        // Deterministic mock proof = Blake3(circuit_handle_info || witness_bytes)
        let mut hasher = blake3::Hasher::new();
        let circuit_tag = format!("{:?}", circuit.backend_tag());
        hasher.update(circuit_tag.as_bytes());
        hasher.update(&witness.proof_bytes_placeholder());
        let proof_bytes = hasher.finalize().as_bytes().to_vec();

        let public_inputs = PublicInputs {
            snapshot_root: witness.snapshot_root,
            query_hash: witness.query_hash,
            result_commitment: witness.result_commitment,
            result_row_count: witness.result_row_count,
        };

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: witness.query_id.clone(),
            snapshot_id: witness.snapshot_id.clone(),
            backend: BackendTag::Mock,
            proof_system: ProofSystemKind::None,
            proof_bytes,
            public_inputs,
            verification_key_bytes: vec![1u8; 32], // mock VK
            created_at_ms: now_ms(),
        })
    }

    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        // Mock verification: always succeed if proof_bytes is non-empty
        let is_valid = !artifact.proof_bytes.is_empty();
        Ok(VerificationResult {
            is_valid,
            snapshot_root: artifact.public_inputs.snapshot_root,
            query_hash: artifact.public_inputs.query_hash,
            result_commitment: artifact.public_inputs.result_commitment,
            backend: artifact.backend.clone(),
            proof_system: ProofSystemKind::None,
            error: if is_valid {
                None
            } else {
                Some("mock: empty proof bytes".into())
            },
        })
    }

    async fn fold(
        &self,
        left: &ProofArtifact,
        right: &ProofArtifact,
    ) -> ZkResult<ProofArtifact> {
        // Mock fold: combine proof bytes with Blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(&left.proof_bytes);
        hasher.update(&right.proof_bytes);
        let folded_bytes = hasher.finalize().as_bytes().to_vec();

        // Merge public inputs: use left's snapshot_root, combine result commitments
        let mut combined_commitment_input = [0u8; 64];
        combined_commitment_input[..32].copy_from_slice(&left.public_inputs.result_commitment);
        combined_commitment_input[32..].copy_from_slice(&right.public_inputs.result_commitment);
        let combined_commitment = *blake3::hash(&combined_commitment_input).as_bytes();

        let public_inputs = PublicInputs {
            snapshot_root: left.public_inputs.snapshot_root,
            query_hash: left.public_inputs.query_hash,
            result_commitment: combined_commitment,
            result_row_count: left.public_inputs.result_row_count
                + right.public_inputs.result_row_count,
        };

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: left.query_id.clone(),
            snapshot_id: left.snapshot_id.clone(),
            backend: BackendTag::Mock,
            proof_system: ProofSystemKind::None,
            proof_bytes: folded_bytes,
            public_inputs,
            verification_key_bytes: vec![1u8; 32],
            created_at_ms: now_ms(),
        })
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
