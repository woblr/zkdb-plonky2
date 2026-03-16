//! Plonky2Backend — honest stub for the Plonky2 FRI-based SNARK.
//!
//! ## What this backend WILL be
//!
//! - Plonky2 SNARK over the Goldilocks field (2^64 − 2^32 + 1).
//! - FRI polynomial commitment scheme.
//! - Zero-knowledge (blinded witness).
//! - Succinct verification: O(log n) field ops.
//! - Recursive proof folding via Plonky2's native recursion circuits.
//!
//! ## Current status: NOT YET WIRED
//!
//! `prove()` returns `Err(ZkDbError::Proving("Plonky2 proving not yet wired"))`.
//! The stub exists so that:
//! - The registry can register a `Plonky2` entry with accurate capability flags.
//! - CLI / API consumers can see the backend listed with honest `ProofSystemKind::Plonky2Snark`.
//! - Downstream integration can be tested against the trait boundary without a live prover.
//!
//! ## Honest label
//!
//! `ProofSystemKind::Plonky2Snark`

use crate::backend::traits::{CircuitHandle, ProvingBackend};
use crate::circuit::witness::WitnessTrace;
use crate::proof::artifacts::{ProofArtifact, ProofSystemKind, VerificationResult};
use crate::query::proof_plan::ProofPlan;
use crate::types::{BackendTag, ZkDbError, ZkResult};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit handle (stub)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Plonky2CircuitHandle {
    pub plan_hash: [u8; 32],
}

impl CircuitHandle for Plonky2CircuitHandle {
    fn backend_tag(&self) -> BackendTag {
        BackendTag::Plonky2
    }

    fn num_public_inputs(&self) -> usize {
        // Standard: snapshot_root, query_hash, result_commitment
        3
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plonky2Backend
// ─────────────────────────────────────────────────────────────────────────────

/// Honest stub for the Plonky2 FRI-based SNARK backend.
///
/// All methods except `tag()` and `compile_circuit()` return errors until
/// the proving path is wired. This is intentional and documented.
#[derive(Debug, Default)]
pub struct Plonky2Backend;

impl Plonky2Backend {
    /// Construct the stub. Does not initialize any prover state.
    pub fn new_stub() -> Self {
        Self
    }
}

#[async_trait]
impl ProvingBackend for Plonky2Backend {
    fn tag(&self) -> BackendTag {
        BackendTag::Plonky2
    }

    async fn compile_circuit(&self, plan: &ProofPlan) -> ZkResult<Box<dyn CircuitHandle>> {
        let plan_json = serde_json::to_string(plan).unwrap_or_default();
        let plan_hash = *blake3::hash(plan_json.as_bytes()).as_bytes();
        Ok(Box::new(Plonky2CircuitHandle { plan_hash }))
    }

    async fn prove(
        &self,
        _circuit: &dyn CircuitHandle,
        _witness: &WitnessTrace,
    ) -> ZkResult<ProofArtifact> {
        Err(ZkDbError::Proving(
            "Plonky2 proving not yet wired — stub only. \
             Use ConstraintCheckedBackend for real constraint validation, \
             or MockBackend for testing."
                .into(),
        ))
    }

    async fn verify(&self, _artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        Ok(VerificationResult::invalid_with_backend(
            "Plonky2 verification not yet wired — stub only",
            BackendTag::Plonky2,
            ProofSystemKind::Plonky2Snark,
        ))
    }

    async fn fold(
        &self,
        _left: &ProofArtifact,
        _right: &ProofArtifact,
    ) -> ZkResult<ProofArtifact> {
        Err(ZkDbError::Proving(
            "Plonky2 recursive folding not yet wired — stub only".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::witness::WitnessTrace;
    use crate::commitment::root::CommitmentRoot;
    use crate::query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
    };
    use crate::types::{DatasetId, QueryId, SnapshotId};

    fn stub_plan() -> ProofPlan {
        let tid = TaskId::new();
        ProofPlan {
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            dataset_id: DatasetId::new(),
            snapshot_root: CommitmentRoot::zero(),
            topology: AggregationTopology {
                tasks: vec![ProvingTask {
                    task_id: tid.clone(),
                    operator: ProofOperator::Scan { chunk_indices: vec![0], column_names: None },
                    depends_on: vec![],
                }],
                root_task_id: tid,
            },
            leaf_count: 1,
        }
    }

    #[tokio::test]
    async fn tag_is_plonky2() {
        let b = Plonky2Backend::new_stub();
        assert_eq!(b.tag(), BackendTag::Plonky2);
    }

    #[tokio::test]
    async fn compile_circuit_succeeds() {
        let b = Plonky2Backend::new_stub();
        let plan = stub_plan();
        let circuit = b.compile_circuit(&plan).await;
        assert!(circuit.is_ok(), "compile_circuit must succeed for stub");
        assert_eq!(circuit.unwrap().backend_tag(), BackendTag::Plonky2);
    }

    #[tokio::test]
    async fn prove_returns_error_not_yet_wired() {
        let b = Plonky2Backend::new_stub();
        let plan = stub_plan();
        let circuit = b.compile_circuit(&plan).await.unwrap();
        let witness = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        let result = b.prove(circuit.as_ref(), &witness).await;
        assert!(result.is_err(), "prove() must return Err for stub");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not yet wired"),
            "error must mention 'not yet wired': {}", msg
        );
    }

    #[tokio::test]
    async fn verify_returns_invalid_not_yet_wired() {
        use crate::proof::artifacts::{ProofArtifact, PublicInputs};
        use crate::types::ProofId;

        let b = Plonky2Backend::new_stub();
        let artifact = ProofArtifact {
            proof_id: ProofId::new(),
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            backend: BackendTag::Plonky2,
            proof_system: ProofSystemKind::Plonky2Snark,
            proof_bytes: vec![0u8; 32],
            public_inputs: PublicInputs {
                snapshot_root: [0u8; 32],
                query_hash: [0u8; 32],
                result_commitment: [0u8; 32],
                result_row_count: 0,
            },
            verification_key_bytes: vec![],
            created_at_ms: 0,
        };
        let result = b.verify(&artifact).await.unwrap();
        assert!(!result.is_valid, "stub verify must return is_valid=false");
        assert_eq!(result.proof_system, ProofSystemKind::Plonky2Snark,
            "proof_system label must be Plonky2Snark even for stub");
    }

    #[tokio::test]
    async fn proof_system_label_is_plonky2_snark_not_hash_chain() {
        use crate::proof::artifacts::{ProofArtifact, PublicInputs, ProofSystemKind};
        use crate::types::ProofId;

        let b = Plonky2Backend::new_stub();
        let artifact = ProofArtifact {
            proof_id: ProofId::new(),
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            backend: BackendTag::Plonky2,
            proof_system: ProofSystemKind::Plonky2Snark,
            proof_bytes: vec![],
            public_inputs: PublicInputs {
                snapshot_root: [0u8; 32],
                query_hash: [0u8; 32],
                result_commitment: [0u8; 32],
                result_row_count: 0,
            },
            verification_key_bytes: vec![],
            created_at_ms: 0,
        };
        let vr = b.verify(&artifact).await.unwrap();
        assert_ne!(vr.proof_system, ProofSystemKind::HashChainAudit,
            "Plonky2 must not be labeled HashChainAudit");
        assert_ne!(vr.proof_system, ProofSystemKind::None,
            "Plonky2 must not be labeled None");
        assert_eq!(vr.proof_system, ProofSystemKind::Plonky2Snark);
    }
}
