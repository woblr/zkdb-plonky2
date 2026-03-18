//! ConstraintCheckedBackend — real operator execution + constraint validation.
//!
//! ## What this backend IS
//!
//! - Runs every operator circuit's `validate_witness()` call (real mathematical checks).
//! - Enforces sort ordering, group boundaries, selector booleanity, running-sum
//!   consistency, join key equality, and multiset preservation.
//! - Produces a structured, content-addressed artifact that can be re-verified
//!   deterministically by anyone with the same public inputs.
//!
//! ## What this backend is NOT
//!
//! - It is NOT a zero-knowledge proof system. The verifier sees the full witness
//!   digest chain; there is no hiding property.
//! - It is NOT succinct. Verification cost is O(columns * rows), not O(1).
//! - It does NOT use polynomial commitments, FFTs, elliptic curve pairings,
//!   or any SNARK/STARK construction.
//! - It should NOT be called "Plonky2" or "Halo2" or any real proof system name.
//!
//! ## Honest label
//!
//! `ProofSystemKind::HashChainAudit` — a deterministic constraint-checked
//! hash-chain audit log. Useful for correctness assurance without cryptographic
//! zero-knowledge guarantees.

use crate::backend::traits::{CircuitHandle, ProvingBackend};
use crate::circuit::operator::{CircuitParams, OperatorCircuit};
use crate::circuit::witness::WitnessTrace;
use crate::proof::artifacts::{ProofArtifact, ProofSystemKind, PublicInputs, VerificationResult};
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::{BackendTag, ProofId, ZkDbError, ZkResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit handle
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConstraintCheckedCircuitHandle {
    pub plan_hash: [u8; 32],
    pub params: CircuitParams,
    pub operator_tag: String,
    pub public_input_count: usize,
}

impl CircuitHandle for ConstraintCheckedCircuitHandle {
    fn backend_tag(&self) -> BackendTag {
        BackendTag::ConstraintChecked
    }

    fn num_public_inputs(&self) -> usize {
        self.public_input_count
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof envelope
// ─────────────────────────────────────────────────────────────────────────────

/// Structured artifact produced by `ConstraintCheckedBackend`.
///
/// NOT a zk proof. A hash-chain audit log binding a validated witness to
/// the public inputs via Blake3. Re-derivation from public inputs is O(n).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintCheckedEnvelope {
    /// Commitment output from `OperatorCircuit::validate_witness()`.
    pub constraint_digest: [u8; 32],
    /// H(constraint_digest ‖ snapshot_root ‖ query_hash)
    pub public_input_binding: [u8; 32],
    /// Per-column Blake3 commitments.
    pub column_commitments: Vec<[u8; 32]>,
    /// Merkle root of column_commitments.
    pub column_root: [u8; 32],
    /// H(public_input_binding ‖ column_root ‖ result_commitment)
    pub envelope_root: [u8; 32],
    /// Human-readable operator name for display/debugging.
    pub operator_tag: String,
    /// Row count processed.
    pub row_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintCheckedBackend
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConstraintCheckedBackend {
    params: CircuitParams,
}

impl ConstraintCheckedBackend {
    pub fn new() -> Self {
        Self {
            params: CircuitParams::default(),
        }
    }

    pub fn with_params(params: CircuitParams) -> Self {
        Self { params }
    }

    // ── internal helpers ────────────────────────────────────────────────────

    fn root_operator(plan: &ProofPlan) -> &ProofOperator {
        let root_id = &plan.topology.root_task_id;
        plan.topology
            .tasks
            .iter()
            .find(|t| &t.task_id == root_id)
            .map(|t| &t.operator)
            .or_else(|| plan.topology.tasks.last().map(|t| &t.operator))
            .expect("proof plan has no tasks")
    }

    fn column_commitments(witness: &WitnessTrace) -> Vec<[u8; 32]> {
        witness
            .columns
            .iter()
            .map(|col| {
                let mut h = blake3::Hasher::new();
                h.update(col.column_name.as_bytes());
                for fe in &col.values {
                    h.update(&fe.to_canonical_bytes());
                }
                for &null in &col.nulls {
                    h.update(&[null as u8]);
                }
                *h.finalize().as_bytes()
            })
            .collect()
    }

    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        let mut cur = leaves.to_vec();
        while cur.len() > 1 {
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            for pair in cur.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&pair[0]);
                h.update(pair.get(1).unwrap_or(&pair[0]));
                next.push(*h.finalize().as_bytes());
            }
            cur = next;
        }
        cur[0]
    }

    fn public_input_binding(
        constraint_digest: &[u8; 32],
        snapshot_root: &[u8; 32],
        query_hash: &[u8; 32],
    ) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(constraint_digest)
            .update(snapshot_root)
            .update(query_hash)
            .finalize()
            .as_bytes()
    }

    fn envelope_root(
        pib: &[u8; 32],
        column_root: &[u8; 32],
        result_commitment: &[u8; 32],
    ) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(pib)
            .update(column_root)
            .update(result_commitment)
            .finalize()
            .as_bytes()
    }

    fn select_circuit_for_tag(&self, tag: &str) -> Box<dyn OperatorCircuit> {
        use crate::circuit::operator::*;
        match tag {
            "table_scan" => Box::new(TableScanCircuit),
            "filter" => Box::new(FilterCircuit {
                predicate_json: String::new(),
            }),
            "projection" => Box::new(ProjectionCircuit {
                items_json: String::new(),
            }),
            "aggregate" => Box::new(AggregateCircuit {
                aggregates_json: String::new(),
            }),
            "group_by" => Box::new(GroupByCircuit {
                group_by_json: String::new(),
                aggregates_json: String::new(),
            }),
            "sort" => Box::new(SortCircuit {
                keys_json: String::new(),
            }),
            "hash_join" => Box::new(JoinCircuit {
                condition_json: None,
                kind_json: String::new(),
            }),
            _ => Box::new(TableScanCircuit),
        }
    }
}

impl Default for ConstraintCheckedBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProvingBackend for ConstraintCheckedBackend {
    fn tag(&self) -> BackendTag {
        BackendTag::ConstraintChecked
    }

    async fn compile_circuit(&self, plan: &ProofPlan) -> ZkResult<Box<dyn CircuitHandle>> {
        let plan_json = serde_json::to_string(plan).unwrap_or_default();
        let plan_hash = *blake3::hash(plan_json.as_bytes()).as_bytes();
        let root_op = Self::root_operator(plan);
        let circ = self.select_circuit_for_tag(&{
            use crate::circuit::operator::circuit_for_operator;
            circuit_for_operator(root_op).operator_kind().to_string()
        });
        let pi_count = circ.public_input_count();
        let operator_tag = circ.operator_kind().to_string();
        Ok(Box::new(ConstraintCheckedCircuitHandle {
            plan_hash,
            params: self.params.clone(),
            operator_tag,
            public_input_count: pi_count,
        }))
    }

    async fn prove(
        &self,
        circuit: &dyn CircuitHandle,
        witness: &WitnessTrace,
    ) -> ZkResult<ProofArtifact> {
        let handle = circuit
            .as_any()
            .downcast_ref::<ConstraintCheckedCircuitHandle>()
            .ok_or_else(|| {
                ZkDbError::internal("ConstraintCheckedBackend::prove called with wrong handle type")
            })?;
        let plan_hash = handle.plan_hash;
        let op_tag = handle.operator_tag.clone();

        // Real constraint validation
        let constraint_digest = self
            .select_circuit_for_tag(&op_tag)
            .validate_witness(witness)
            .map_err(|e| {
                ZkDbError::internal(format!("constraint validation failed [{}]: {}", op_tag, e))
            })?;

        // Build hash-chain audit envelope
        let col_commitments = Self::column_commitments(witness);
        let col_root = Self::merkle_root(&col_commitments);
        let pib = Self::public_input_binding(
            &constraint_digest,
            &witness.snapshot_root,
            &witness.query_hash,
        );
        let env_root = Self::envelope_root(&pib, &col_root, &witness.result_commitment);

        let envelope = ConstraintCheckedEnvelope {
            constraint_digest,
            public_input_binding: pib,
            column_commitments: col_commitments,
            column_root: col_root,
            envelope_root: env_root,
            operator_tag: op_tag.clone(),
            row_count: witness.result_row_count,
        };

        let proof_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ZkDbError::internal(format!("envelope serialization: {}", e)))?;

        // Verification key = plan_hash + operator_tag + params
        let vk_bytes = serde_json::to_vec(&serde_json::json!({
            "plan_hash": hex::encode(plan_hash),
            "operator_tag": op_tag,
            "max_rows": handle.params.max_rows,
            "num_columns": handle.params.num_columns,
        }))
        .unwrap_or_default();

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: witness.query_id.clone(),
            snapshot_id: witness.snapshot_id.clone(),
            backend: BackendTag::ConstraintChecked,
            proof_system: ProofSystemKind::HashChainAudit,
            capabilities: crate::proof::artifacts::ProofCapabilities::default(),
            proof_bytes,
            public_inputs: PublicInputs {
                snapshot_root: witness.snapshot_root,
                query_hash: witness.query_hash,
                result_commitment: witness.result_commitment,
                result_row_count: witness.result_row_count,
                result_sum: 0,
                result_commit_lo: 0,
                group_output_lo: 0,
                join_right_snap_lo: 0,
                join_unmatched_count: 0,
                pred_op: 0,
                pred_val: 0,
                sort_secondary_snap_lo: 0,
                sort_secondary_hi_snap_lo: 0,
                group_vals_snap_lo: 0,
                agg_n_real: 0,
            },
            verification_key_bytes: vk_bytes,
            created_at_ms: now_ms(),
        })
    }

    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        let env: ConstraintCheckedEnvelope = match serde_json::from_slice(&artifact.proof_bytes) {
            Ok(e) => e,
            Err(e) => {
                return Ok(VerificationResult::invalid_with_backend(
                    format!("malformed envelope: {}", e),
                    BackendTag::ConstraintChecked,
                    ProofSystemKind::HashChainAudit,
                ))
            }
        };

        // Re-derive public_input_binding from artifact's public inputs
        let expected_pib = Self::public_input_binding(
            &env.constraint_digest,
            &artifact.public_inputs.snapshot_root,
            &artifact.public_inputs.query_hash,
        );
        if expected_pib != env.public_input_binding {
            return Ok(VerificationResult::invalid_with_backend(
                "public_input_binding mismatch — proof not generated from these public inputs",
                BackendTag::ConstraintChecked,
                ProofSystemKind::HashChainAudit,
            ));
        }

        // Re-derive column root
        let expected_col_root = Self::merkle_root(&env.column_commitments);
        if expected_col_root != env.column_root {
            return Ok(VerificationResult::invalid_with_backend(
                "column_root mismatch — column commitments are inconsistent",
                BackendTag::ConstraintChecked,
                ProofSystemKind::HashChainAudit,
            ));
        }

        // Re-derive envelope root
        let expected_env_root = Self::envelope_root(
            &env.public_input_binding,
            &env.column_root,
            &artifact.public_inputs.result_commitment,
        );
        if expected_env_root != env.envelope_root {
            return Ok(VerificationResult::invalid_with_backend(
                "envelope_root mismatch — result_commitment was tampered",
                BackendTag::ConstraintChecked,
                ProofSystemKind::HashChainAudit,
            ));
        }

        Ok(VerificationResult {
            is_valid: true,
            snapshot_root: artifact.public_inputs.snapshot_root,
            query_hash: artifact.public_inputs.query_hash,
            result_commitment: artifact.public_inputs.result_commitment,
            result_commit_poseidon_lo: artifact.public_inputs.result_commit_lo,
            backend: BackendTag::ConstraintChecked,
            proof_system: ProofSystemKind::HashChainAudit,
            capabilities: crate::proof::artifacts::ProofCapabilities::default(),
            error: None,
            warnings: vec![],
            completeness_proved: true,
            external_anchor_status: crate::proof::artifacts::ExternalAnchorStatus::Unanchored,
        })
    }

    async fn fold(&self, left: &ProofArtifact, right: &ProofArtifact) -> ZkResult<ProofArtifact> {
        let lenv: ConstraintCheckedEnvelope = serde_json::from_slice(&left.proof_bytes)
            .map_err(|e| ZkDbError::internal(format!("fold: left invalid: {}", e)))?;
        let renv: ConstraintCheckedEnvelope = serde_json::from_slice(&right.proof_bytes)
            .map_err(|e| ZkDbError::internal(format!("fold: right invalid: {}", e)))?;

        // Fold constraint digests
        let folded_cd = *blake3::Hasher::new()
            .update(&lenv.constraint_digest)
            .update(&renv.constraint_digest)
            .finalize()
            .as_bytes();

        // Combine column commitments from both
        let mut combined = lenv.column_commitments.clone();
        combined.extend_from_slice(&renv.column_commitments);
        let folded_col_root = Self::merkle_root(&combined);

        // Fold result commitments
        let folded_rc = *blake3::Hasher::new()
            .update(&left.public_inputs.result_commitment)
            .update(&right.public_inputs.result_commitment)
            .finalize()
            .as_bytes();

        let pib = Self::public_input_binding(
            &folded_cd,
            &left.public_inputs.snapshot_root,
            &left.public_inputs.query_hash,
        );
        let env_root = Self::envelope_root(&pib, &folded_col_root, &folded_rc);

        let envelope = ConstraintCheckedEnvelope {
            constraint_digest: folded_cd,
            public_input_binding: pib,
            column_commitments: combined,
            column_root: folded_col_root,
            envelope_root: env_root,
            operator_tag: "recursive_fold".into(),
            row_count: lenv.row_count + renv.row_count,
        };

        let proof_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ZkDbError::internal(format!("fold serialization: {}", e)))?;

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: left.query_id.clone(),
            snapshot_id: left.snapshot_id.clone(),
            backend: BackendTag::ConstraintChecked,
            proof_system: ProofSystemKind::HashChainAudit,
            capabilities: crate::proof::artifacts::ProofCapabilities::default(),
            proof_bytes,
            public_inputs: PublicInputs {
                snapshot_root: left.public_inputs.snapshot_root,
                query_hash: left.public_inputs.query_hash,
                result_commitment: folded_rc,
                result_row_count: left.public_inputs.result_row_count
                    + right.public_inputs.result_row_count,
                result_sum: 0,
                result_commit_lo: 0,
                group_output_lo: 0,
                join_right_snap_lo: 0,
                join_unmatched_count: 0,
                pred_op: 0,
                pred_val: 0,
                sort_secondary_snap_lo: 0,
                sort_secondary_hi_snap_lo: 0,
                group_vals_snap_lo: 0,
                agg_n_real: 0,
            },
            verification_key_bytes: left.verification_key_bytes.clone(),
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::witness::{ColumnTrace, WitnessTrace};
    use crate::commitment::root::CommitmentRoot;
    use crate::field::FieldElement;
    use crate::query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
    };
    use crate::types::{DatasetId, QueryId, SnapshotId};

    fn make_plan(op: ProofOperator) -> ProofPlan {
        let tid = TaskId::new();
        ProofPlan {
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            dataset_id: DatasetId::new(),
            snapshot_root: CommitmentRoot::zero(),
            topology: AggregationTopology {
                tasks: vec![ProvingTask {
                    task_id: tid.clone(),
                    operator: op,
                    depends_on: vec![],
                }],
                root_task_id: tid,
            },
            leaf_count: 1,
            poseidon_snap_lo: 0,
            operator_params: crate::query::proof_plan::OperatorParams::default(),
            schema_json: None,
        }
    }

    fn scan_witness(rows: usize) -> WitnessTrace {
        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        w.columns = vec![ColumnTrace::new(
            "col_a",
            (0..rows).map(|i| FieldElement(i as u64)).collect(),
        )];
        w.result_row_count = rows as u64;
        w.result_commitment = *blake3::hash(b"scan").as_bytes();
        w
    }

    fn sorted_witness(asc: bool, n: usize) -> WitnessTrace {
        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        let vals: Vec<FieldElement> = if asc {
            (0..n).map(|i| FieldElement(i as u64)).collect()
        } else {
            (0..n).rev().map(|i| FieldElement(i as u64)).collect()
        };
        w.columns = vec![ColumnTrace::new("sort_key", vals)];
        w.result_row_count = n as u64;
        w.result_commitment = *blake3::hash(b"sorted").as_bytes();
        w
    }

    fn group_witness() -> WitnessTrace {
        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        let keys = vec![1, 1, 2, 2, 3].into_iter().map(FieldElement).collect();
        let vals = vec![10, 20, 30, 40, 50]
            .into_iter()
            .map(FieldElement)
            .collect();
        w.columns = vec![
            ColumnTrace::new("group_key", keys),
            ColumnTrace::new("value", vals),
        ];
        w.result_row_count = 5;
        w.result_commitment = *blake3::hash(b"group").as_bytes();
        w
    }

    // ── prove + verify ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn prove_and_verify_scan() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Scan {
            chunk_indices: vec![0],
            column_names: None,
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let a = b.prove(c.as_ref(), &scan_witness(10)).await.unwrap();

        assert_eq!(a.backend, BackendTag::ConstraintChecked);
        assert_eq!(a.proof_system, ProofSystemKind::HashChainAudit);

        let vr = b.verify(&a).await.unwrap();
        assert!(vr.is_valid, "{:?}", vr.error);
    }

    #[tokio::test]
    async fn prove_and_verify_sort() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Sort {
            keys_json: "[]".into(),
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let a = b.prove(c.as_ref(), &sorted_witness(true, 5)).await.unwrap();

        assert_eq!(a.proof_system, ProofSystemKind::HashChainAudit);
        let vr = b.verify(&a).await.unwrap();
        assert!(vr.is_valid);
    }

    #[tokio::test]
    async fn prove_and_verify_group_by() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::PartialAggregate {
            group_by_json: "[]".into(),
            aggregates_json: "[]".into(),
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let a = b.prove(c.as_ref(), &group_witness()).await.unwrap();
        let vr = b.verify(&a).await.unwrap();
        assert!(vr.is_valid);
    }

    // ── tampered artifact must fail ──────────────────────────────────────────

    #[tokio::test]
    async fn tampered_result_commitment_fails() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Scan {
            chunk_indices: vec![0],
            column_names: None,
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let mut a = b.prove(c.as_ref(), &scan_witness(5)).await.unwrap();
        a.public_inputs.result_commitment = [0xABu8; 32];
        let vr = b.verify(&a).await.unwrap();
        assert!(!vr.is_valid, "tampered commitment must not verify");
    }

    #[tokio::test]
    async fn tampered_snapshot_root_fails() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Scan {
            chunk_indices: vec![0],
            column_names: None,
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let mut a = b.prove(c.as_ref(), &scan_witness(5)).await.unwrap();
        a.public_inputs.snapshot_root = [0xCDu8; 32];
        let vr = b.verify(&a).await.unwrap();
        assert!(!vr.is_valid, "tampered snapshot root must not verify");
    }

    // ── adversarial: unsorted witness should fail SortCircuit ───────────────

    #[tokio::test]
    async fn unsorted_witness_fails_sort_circuit() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Sort {
            keys_json: "[]".into(),
        });
        let c = b.compile_circuit(&plan).await.unwrap();

        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        // deliberately not sorted: [3, 1, 4, 1, 5]
        let vals = vec![3, 1, 4, 1, 5].into_iter().map(FieldElement).collect();
        w.columns = vec![ColumnTrace::new("sort_key", vals)];
        w.result_row_count = 5;
        w.result_commitment = *blake3::hash(b"bad").as_bytes();

        let r = b.prove(c.as_ref(), &w).await;
        assert!(
            r.is_err(),
            "unsorted witness must fail constraint validation"
        );
        let msg = format!("{:?}", r.err().unwrap());
        assert!(
            msg.contains("constraint validation failed"),
            "error must mention constraint validation: {}",
            msg
        );
    }

    // ── fold ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fold_two_proofs() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Scan {
            chunk_indices: vec![0],
            column_names: None,
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let a1 = b.prove(c.as_ref(), &scan_witness(4)).await.unwrap();
        let a2 = b.prove(c.as_ref(), &scan_witness(3)).await.unwrap();
        let folded = b.fold(&a1, &a2).await.unwrap();
        assert_eq!(folded.public_inputs.result_row_count, 7);
        assert_eq!(folded.proof_system, ProofSystemKind::HashChainAudit);
        let vr = b.verify(&folded).await.unwrap();
        assert!(vr.is_valid);
    }

    // ── proof_system label is correct ────────────────────────────────────────

    #[tokio::test]
    async fn proof_system_is_hash_chain_audit_not_zk() {
        let b = ConstraintCheckedBackend::new();
        let plan = make_plan(ProofOperator::Scan {
            chunk_indices: vec![0],
            column_names: None,
        });
        let c = b.compile_circuit(&plan).await.unwrap();
        let a = b.prove(c.as_ref(), &scan_witness(3)).await.unwrap();

        assert_ne!(
            a.proof_system,
            ProofSystemKind::Plonky2Snark,
            "must not be labeled as Plonky2Snark"
        );
        assert_ne!(
            a.proof_system,
            ProofSystemKind::Halo2Snark,
            "must not be labeled as Halo2Snark"
        );
        assert_eq!(
            a.proof_system,
            ProofSystemKind::HashChainAudit,
            "must be labeled HashChainAudit"
        );
    }
}
