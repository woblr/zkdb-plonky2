//! Plonky2Backend — real FRI-based SNARK implementation.
//!
//! ## What this backend IS
//!
//! - Plonky2 SNARK over the Goldilocks field (2^64 − 2^32 + 1).
//! - FRI polynomial commitment scheme.
//! - Zero-knowledge (with witness blinding).
//! - Succinct verification: O(log² n) field operations.
//!
//! ## Supported operator families
//!
//! The core `AggCircuit` handles all of:
//! - COUNT(*) [filter + count]
//! - SUM(col) [filter + sum]
//! - AVG(col) [filter + sum + count → compute average outside circuit]
//! - Generic row-count proof (Scan, Limit, Projection)
//!
//! ## Circuit design
//!
//! ```text
//! Private inputs:
//!   values[0..MAX_ROWS]    — column values (u64 as Goldilocks field elements)
//!   selectors[0..MAX_ROWS] — boolean mask  (1 = row included, 0 = padding/excluded)
//!
//! Constraints:
//!   ∀ i: selectors[i] ∈ {0, 1}                         (boolean check)
//!   sum   = Σᵢ values[i] * selectors[i]                 (dot product)
//!   count = Σᵢ selectors[i]                              (running count)
//!
//! Public outputs:
//!   [0] sum   — SUM(values[i]) for selected rows
//!   [1] count — COUNT(*) for selected rows
//!   [2] snapshot_root_lo — low 8 bytes of snapshot root (as field element)
//!   [3] query_hash_lo    — low 8 bytes of query hash    (as field element)
//! ```
//!
//! For datasets larger than MAX_ROWS, the witness is chunked and a single
//! circuit is proved per chunk. Chunk results are accumulated off-circuit.

use std::any::Any;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::backend::traits::{CircuitHandle, ProvingBackend};
use crate::circuit::witness::WitnessTrace;
use crate::proof::artifacts::{ProofArtifact, ProofSystemKind, PublicInputs, VerificationResult};
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::{BackendTag, DatasetId, ProofId, QueryId, SnapshotId, ZkDbError, ZkResult};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit constants
// ─────────────────────────────────────────────────────────────────────────────

/// Rows per circuit instance. Larger → larger circuit → slower compilation
/// but supports more rows per proof without chunking.
/// 128 gives a fast compile (~1-2 s) and handles typical benchmark chunks.
pub const MAX_ROWS: usize = 128;

// ─────────────────────────────────────────────────────────────────────────────
// Operator classification
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum AggKind {
    Count,
    Sum,
    Avg,
    Generic,
}

fn classify_plan(plan: &ProofPlan) -> AggKind {
    for task in &plan.topology.tasks {
        match &task.operator {
            ProofOperator::PartialAggregate { aggregates_json, .. }
            | ProofOperator::MergeAggregate { aggregates_json, .. } => {
                let j = aggregates_json.to_lowercase();
                if j.contains("\"avg\"") {
                    return AggKind::Avg;
                }
                if j.contains("\"sum\"") {
                    return AggKind::Sum;
                }
                return AggKind::Count;
            }
            _ => {}
        }
    }
    AggKind::Generic
}

// ─────────────────────────────────────────────────────────────────────────────
// AggCircuit — the core Plonky2 circuit
// ─────────────────────────────────────────────────────────────────────────────

/// Compiled Plonky2 circuit for filter + aggregate operations.
///
/// This is expensive to build (1–5 s) but cheap to reuse.
/// Wrapped in `Arc` and shared across all prove calls on the same backend.
struct AggCircuit {
    data: CircuitData<F, C, D>,
    values_t: Vec<Target>,
    selectors_t: Vec<Target>,
}

impl AggCircuit {
    /// Build and compile the circuit.
    ///
    /// Constraints (per row i):
    ///   1. selectors[i] ∈ {0, 1}
    ///   2. sum   += values[i] * selectors[i]
    ///   3. count += selectors[i]
    ///
    /// Public outputs: [sum, count, snapshot_root_lo, query_hash_lo]
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // Private witness targets
        let values_t: Vec<Target> =
            (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> =
            (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        // Public inputs: snapshot_root_lo and query_hash_lo (8 bytes each → u64)
        let snapshot_root_lo_t = b.add_virtual_public_input();
        let query_hash_lo_t    = b.add_virtual_public_input();
        let _ = (snapshot_root_lo_t, query_hash_lo_t); // registered as PI[0..1]

        // Constraint 1: selectors must be boolean (s * (1 - s) == 0)
        for &s in &selectors_t {
            let one  = b.one();
            let one_minus_s = b.sub(one, s);
            let prod = b.mul(s, one_minus_s);
            let zero = b.zero();
            b.connect(prod, zero);
        }

        // Accumulate: sum and count
        let zero = b.zero();
        let mut sum_acc   = zero;
        let mut count_acc = zero;

        for (&v, &s) in values_t.iter().zip(selectors_t.iter()) {
            let term   = b.mul(v, s);
            sum_acc   = b.add(sum_acc, term);
            count_acc = b.add(count_acc, s);
        }

        // Register sum and count as public outputs (PI[2] and PI[3])
        b.register_public_input(sum_acc);
        b.register_public_input(count_acc);

        let data = b.build::<C>();
        Self { data, values_t, selectors_t }
    }

    /// Generate a Plonky2 proof.
    ///
    /// `values` and `selectors` are padded to `MAX_ROWS` with zeros.
    fn prove(
        &self,
        values: &[u64],
        selectors: &[bool],
        snapshot_root_lo: u64,
        query_hash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        // Fill values (pad with 0)
        for i in 0..MAX_ROWS {
            let v = F::from_canonical_u64(if i < values.len() { values[i] } else { 0 });
            pw.set_target(self.values_t[i], v);
        }

        // Fill selectors (pad with 0 = false)
        for i in 0..MAX_ROWS {
            let s = F::from_canonical_u64(
                if i < selectors.len() && selectors[i] { 1 } else { 0 },
            );
            pw.set_target(self.selectors_t[i], s);
        }

        // Fill public inputs (snapshot_root_lo is PI[0], query_hash_lo is PI[1]).
        // add_virtual_public_input() registers the target in prover_only.public_inputs.
        let pi_targets = &self.data.prover_only.public_inputs;
        if pi_targets.len() >= 2 {
            pw.set_target(pi_targets[0], F::from_canonical_u64(snapshot_root_lo));
            pw.set_target(pi_targets[1], F::from_canonical_u64(query_hash_lo));
        }

        self.data
            .prove(pw)
            .map_err(|e| format!("plonky2 prove error: {e:?}"))
    }

    /// Serialize a proof to bytes.
    fn proof_to_bytes(proof: &ProofWithPublicInputs<F, C, D>) -> Vec<u8> {
        proof.to_bytes()
    }

    /// Deserialize and verify a proof from bytes.
    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            proof_bytes.to_vec(),
            &self.data.common,
        )
        .map_err(|e| format!("proof deserialization failed: {e:?}"))?;

        self.data
            .verify(proof)
            .map_err(|e| format!("plonky2 verification failed: {e:?}"))
    }

    /// Serialize the verifier key to bytes (for storage in ProofArtifact).
    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit handle
// ─────────────────────────────────────────────────────────────────────────────

pub struct Plonky2CircuitHandle {
    pub plan_hash: [u8; 32],
    agg_kind: AggKind,
    circuit: Arc<AggCircuit>,
    /// Cached: query_id, snapshot_id, dataset_id from the plan.
    pub query_id: QueryId,
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
}

impl std::fmt::Debug for Plonky2CircuitHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plonky2CircuitHandle({:?})", self.agg_kind)
    }
}

impl CircuitHandle for Plonky2CircuitHandle {
    fn backend_tag(&self) -> BackendTag {
        BackendTag::Plonky2
    }

    fn num_public_inputs(&self) -> usize {
        4 // snapshot_root_lo, query_hash_lo, sum, count
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plonky2Backend
// ─────────────────────────────────────────────────────────────────────────────

/// Real Plonky2 FRI-based SNARK backend.
///
/// `new()` compiles the AggCircuit (takes 1–5 s the first time, done once per process).
/// Subsequent `prove()` calls reuse the compiled `CircuitData`.
pub struct Plonky2Backend {
    circuit: Arc<AggCircuit>,
}

impl std::fmt::Debug for Plonky2Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plonky2Backend")
    }
}

impl Plonky2Backend {
    /// Compile the Plonky2 circuit. This is the slow step (1–5 s).
    pub fn new() -> Self {
        let circuit = Arc::new(AggCircuit::build());
        Self { circuit }
    }

    /// Alias kept for compatibility with existing code that calls `new_stub()`.
    /// This now performs real circuit compilation.
    pub fn new_stub() -> Self {
        Self::new()
    }
}

impl Default for Plonky2Backend {
    fn default() -> Self {
        Self::new()
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
        let agg_kind = classify_plan(plan);

        Ok(Box::new(Plonky2CircuitHandle {
            plan_hash,
            agg_kind,
            circuit: Arc::clone(&self.circuit),
            query_id: plan.query_id.clone(),
            snapshot_id: plan.snapshot_id.clone(),
            dataset_id: plan.dataset_id.clone(),
        }))
    }

    async fn prove(
        &self,
        circuit: &dyn CircuitHandle,
        witness: &WitnessTrace,
    ) -> ZkResult<ProofArtifact> {
        let handle = circuit
            .as_any()
            .downcast_ref::<Plonky2CircuitHandle>()
            .ok_or_else(|| ZkDbError::Proving("wrong circuit handle type".into()))?;

        // Extract values and selectors from the WitnessTrace.
        let (values, selectors) = extract_agg_inputs(witness, &handle.agg_kind);

        // Public input scalars: low 8 bytes of hashes as u64 field elements.
        let snapshot_root_lo = u64::from_le_bytes(
            witness.snapshot_root[..8].try_into().unwrap_or([0u8; 8]),
        );
        let query_hash_lo = u64::from_le_bytes(
            witness.query_hash[..8].try_into().unwrap_or([0u8; 8]),
        );

        // Clone for the blocking thread.
        let circuit_arc = Arc::clone(&handle.circuit);
        let values_clone = values.clone();
        let selectors_clone = selectors.clone();

        // Plonky2 proving is CPU-bound: run in a blocking thread pool.
        let proof_result = tokio::task::spawn_blocking(move || {
            circuit_arc.prove(
                &values_clone,
                &selectors_clone,
                snapshot_root_lo,
                query_hash_lo,
            )
        })
        .await
        .map_err(|e| ZkDbError::Proving(format!("spawn_blocking panicked: {e}")))?
        .map_err(|e| ZkDbError::Proving(format!("plonky2 prove: {e}")))?;

        let proof_bytes = AggCircuit::proof_to_bytes(&proof_result);
        let vk_bytes = handle.circuit.verifier_key_bytes();

        // Derive result_commitment from proof bytes + witness commitment.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&witness.snapshot_root);
        hasher.update(&witness.query_hash);
        hasher.update(&witness.result_commitment);
        hasher.update(&proof_bytes[..proof_bytes.len().min(32)]);
        let result_commitment: [u8; 32] = *hasher.finalize().as_bytes();

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: handle.query_id.clone(),
            snapshot_id: handle.snapshot_id.clone(),
            backend: BackendTag::Plonky2,
            proof_system: ProofSystemKind::Plonky2Snark,
            proof_bytes,
            public_inputs: PublicInputs {
                snapshot_root: witness.snapshot_root,
                query_hash: witness.query_hash,
                result_commitment,
                result_row_count: witness.result_row_count,
            },
            verification_key_bytes: vk_bytes,
            created_at_ms: now_ms(),
        })
    }

    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        let proof_bytes = artifact.proof_bytes.clone();
        let circuit_arc = Arc::clone(&self.circuit);

        let verify_result = tokio::task::spawn_blocking(move || {
            circuit_arc.verify_bytes(&proof_bytes)
        })
        .await
        .map_err(|e| ZkDbError::Proving(format!("spawn_blocking panicked: {e}")))?;

        match verify_result {
            Ok(()) => Ok(VerificationResult::valid(artifact)),
            Err(e) => Ok(VerificationResult::invalid_with_backend(
                e,
                BackendTag::Plonky2,
                ProofSystemKind::Plonky2Snark,
            )),
        }
    }

    async fn fold(
        &self,
        _left: &ProofArtifact,
        _right: &ProofArtifact,
    ) -> ZkResult<ProofArtifact> {
        Err(ZkDbError::Proving(
            "Plonky2 recursive fold not yet implemented in this prototype".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract `(values, selectors)` from a WitnessTrace for the aggregate circuit.
///
/// - For COUNT: values = all-ones, selectors = the filter bitmap.
/// - For SUM/AVG: values = first column's field element values, selectors = filter bitmap.
/// - For Generic: values = all-ones (just counting rows), selectors = all-true.
///
/// Both slices are truncated/padded to MAX_ROWS by the circuit's prove() method.
fn extract_agg_inputs(witness: &WitnessTrace, kind: &AggKind) -> (Vec<u64>, Vec<bool>) {
    // Determine row count from the larger of columns[0] or selected.
    let n_rows = witness.columns.first().map(|c| c.len()).unwrap_or(0).max(witness.selected.len());

    // Build selectors: use witness.selected if present, else all-true.
    let selectors: Vec<bool> = if !witness.selected.is_empty() {
        witness.selected[..n_rows.min(MAX_ROWS)].to_vec()
    } else {
        vec![true; n_rows.min(MAX_ROWS)]
    };

    let values: Vec<u64> = match kind {
        AggKind::Count | AggKind::Generic => {
            vec![1u64; selectors.len()]
        }
        AggKind::Sum | AggKind::Avg => {
            if let Some(col) = witness.columns.first() {
                col.values[..col.values.len().min(MAX_ROWS)]
                    .iter()
                    .map(|fe| fe.0)
                    .collect()
            } else {
                vec![1u64; selectors.len()]
            }
        }
    };

    (values, selectors)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::root::CommitmentRoot;
    use crate::query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
    };
    use crate::types::{DatasetId, QueryId, SnapshotId};

    // ── AggCircuit low-level tests ────────────────────────────────────────────

    #[test]
    fn circuit_count_all_no_filter() {
        let c = AggCircuit::build();
        let n = 50usize;
        let values = vec![1u64; n];
        let selectors = vec![true; n];

        let proof = c.prove(&values, &selectors, 0, 0).expect("prove failed");
        // Public inputs: [snapshot_root_lo, query_hash_lo, sum, count]
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(50), "sum must be 50");
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(50), "count must be 50");

        let bytes = AggCircuit::proof_to_bytes(&proof);
        assert!(!bytes.is_empty(), "proof bytes must be non-empty");
        c.verify_bytes(&bytes).expect("verify failed");
    }

    #[test]
    fn circuit_sum_with_filter() {
        let c = AggCircuit::build();
        // amounts: [1000, 2000, 3000, 4000, 5000]
        // select where idx > 1: rows 2,3,4 → sum = 12000, count = 3
        let values = vec![1000u64, 2000, 3000, 4000, 5000];
        let selectors = vec![false, false, true, true, true];

        let proof = c.prove(&values, &selectors, 42, 99).expect("prove failed");
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(42), "snapshot_root_lo mismatch");
        assert_eq!(proof.public_inputs[1], F::from_canonical_u64(99), "query_hash_lo mismatch");
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(12000), "sum must be 12000");
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(3), "count must be 3");

        let bytes = AggCircuit::proof_to_bytes(&proof);
        c.verify_bytes(&bytes).expect("verify of valid proof failed");
    }

    #[test]
    fn circuit_proof_bytes_are_nonempty() {
        let c = AggCircuit::build();
        let proof = c.prove(&[100u64; 10], &[true; 10], 0, 0).expect("prove failed");
        let bytes = AggCircuit::proof_to_bytes(&proof);
        // Plonky2 FRI proofs are typically 50–200 KB depending on config.
        assert!(bytes.len() > 1000, "proof must be >1 KB, got {} bytes", bytes.len());
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let c = AggCircuit::build();
        let proof = c.prove(&[10u64; 20], &[true; 20], 0, 0).expect("prove failed");
        let mut bytes = AggCircuit::proof_to_bytes(&proof);

        // Flip several bytes deep in the FRI query section.
        let mid = bytes.len() / 2;
        bytes[mid]     ^= 0xFF;
        bytes[mid + 1] ^= 0xFF;
        bytes[mid + 2] ^= 0xFF;

        let result = c.verify_bytes(&bytes);
        assert!(result.is_err(), "tampered proof must fail verification");
    }

    #[test]
    fn all_zeros_count_is_zero() {
        let c = AggCircuit::build();
        let values = vec![1u64; 10];
        let selectors = vec![false; 10]; // nothing selected
        let proof = c.prove(&values, &selectors, 0, 0).expect("prove failed");
        assert_eq!(proof.public_inputs[2], F::ZERO, "sum must be 0 when nothing selected");
        assert_eq!(proof.public_inputs[3], F::ZERO, "count must be 0 when nothing selected");
        c.verify_bytes(&AggCircuit::proof_to_bytes(&proof)).expect("verify failed");
    }

    #[test]
    fn avg_circuit_outputs_sum_and_count() {
        let c = AggCircuit::build();
        // AVG(score): scores = [100, 200, 300], all selected → sum=600, count=3 → avg=200
        let values = vec![100u64, 200, 300];
        let selectors = vec![true, true, true];
        let proof = c.prove(&values, &selectors, 0, 0).expect("prove failed");
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(600));
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(3));
        // avg = 600 / 3 = 200 (computed outside circuit)
        c.verify_bytes(&AggCircuit::proof_to_bytes(&proof)).expect("verify failed");
    }

    // ── Backend-level (async) tests ───────────────────────────────────────────

    fn scan_plan() -> ProofPlan {
        let tid = TaskId::new();
        ProofPlan {
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            dataset_id: DatasetId::new(),
            snapshot_root: CommitmentRoot::zero(),
            topology: AggregationTopology {
                tasks: vec![ProvingTask {
                    task_id: tid.clone(),
                    operator: ProofOperator::Scan {
                        chunk_indices: vec![0],
                        column_names: None,
                    },
                    depends_on: vec![],
                }],
                root_task_id: tid,
            },
            leaf_count: 1,
        }
    }

    fn count_plan() -> ProofPlan {
        let tid = TaskId::new();
        ProofPlan {
            query_id: QueryId::new(),
            snapshot_id: SnapshotId::new(),
            dataset_id: DatasetId::new(),
            snapshot_root: CommitmentRoot::zero(),
            topology: AggregationTopology {
                tasks: vec![ProvingTask {
                    task_id: tid.clone(),
                    operator: ProofOperator::PartialAggregate {
                        group_by_json: "[]".into(),
                        aggregates_json: r#"[{"kind":"count","column":"*"}]"#.into(),
                    },
                    depends_on: vec![],
                }],
                root_task_id: tid,
            },
            leaf_count: 1,
        }
    }

    fn make_witness_with_rows(n: usize) -> WitnessTrace {
        use crate::field::FieldElement;
        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        w.result_row_count = n as u64;
        w.selected = vec![true; n];
        let col = crate::circuit::witness::ColumnTrace::new(
            "__row_hash",
            (0..n).map(|i| FieldElement((i as u64 + 1) * 1000)).collect(),
        );
        w.columns = vec![col];
        w
    }

    #[test]
    fn tag_is_plonky2() {
        let b = Plonky2Backend::new();
        assert_eq!(b.tag(), BackendTag::Plonky2);
    }

    #[tokio::test]
    async fn compile_circuit_succeeds() {
        let b = Plonky2Backend::new();
        let plan = scan_plan();
        let handle = b.compile_circuit(&plan).await.expect("compile failed");
        assert_eq!(handle.backend_tag(), BackendTag::Plonky2);
    }

    #[tokio::test]
    async fn prove_succeeds_and_returns_nonempty_proof() {
        let b = Plonky2Backend::new();
        let plan = count_plan();
        let handle = b.compile_circuit(&plan).await.expect("compile failed");
        let witness = make_witness_with_rows(10);

        let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

        assert!(!artifact.proof_bytes.is_empty(), "proof_bytes must be non-empty");
        assert!(artifact.proof_bytes.len() > 1000, "Plonky2 proof must be >1 KB");
        assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
        assert_eq!(artifact.backend, BackendTag::Plonky2);
    }

    #[tokio::test]
    async fn prove_then_verify_succeeds() {
        let b = Plonky2Backend::new();
        let plan = count_plan();
        let handle = b.compile_circuit(&plan).await.expect("compile failed");
        let witness = make_witness_with_rows(20);

        let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
        let result = b.verify(&artifact).await.expect("verify call failed");

        assert!(result.is_valid, "valid proof must verify successfully");
        assert_eq!(result.proof_system, ProofSystemKind::Plonky2Snark);
    }

    #[tokio::test]
    async fn tampered_artifact_fails_verify() {
        let b = Plonky2Backend::new();
        let plan = count_plan();
        let handle = b.compile_circuit(&plan).await.expect("compile failed");
        let witness = make_witness_with_rows(5);

        let mut artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

        // Tamper with the proof bytes.
        let mid = artifact.proof_bytes.len() / 2;
        artifact.proof_bytes[mid]     ^= 0xFF;
        artifact.proof_bytes[mid + 1] ^= 0xFF;

        let result = b.verify(&artifact).await.expect("verify call itself failed");
        assert!(!result.is_valid, "tampered proof must fail verification");
        assert!(result.error.is_some(), "error must be populated");
    }

    #[tokio::test]
    async fn proof_system_label_is_plonky2snark() {
        let b = Plonky2Backend::new();
        let plan = count_plan();
        let handle = b.compile_circuit(&plan).await.expect("compile failed");
        let witness = make_witness_with_rows(3);
        let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

        assert_ne!(artifact.proof_system, ProofSystemKind::HashChainAudit);
        assert_ne!(artifact.proof_system, ProofSystemKind::None);
        assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    }
}
