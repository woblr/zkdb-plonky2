//! Adversarial tests: tampered witnesses and proof artifacts MUST fail.
//!
//! Every test in this file is a negative test:
//! - A valid artifact is produced first.
//! - It is then tampered with.
//! - Verification MUST return `is_valid=false` OR `prove()` MUST return `Err`.
//!
//! These tests prevent regression on the security properties of the
//! `ConstraintCheckedBackend`. They cover:
//! 1. Tampered proof bytes (corrupt envelope)
//! 2. Tampered result_commitment (public input mismatch)
//! 3. Tampered snapshot_root (public input mismatch)
//! 4. Tampered query_hash (public input mismatch)
//! 5. Unsorted sort witness → prove() returns Err
//! 6. Sort multiset violation → prove() returns Err (row swapped in)
//! 7. Unsorted group_by key → prove() returns Err
//! 8. Group_by multiset violation → prove() returns Err
//! 9. Join key mismatch → prove() returns Err
//! 10. Join column length mismatch → prove() returns Err
//! 11. Join result_row_count mismatch → prove() returns Err
//! 12. Empty proof bytes → verify() returns is_valid=false

use zkdb_plonky2::{
    backend::{ConstraintCheckedBackend, ProvingBackend},
    circuit::witness::{ColumnTrace, WitnessTrace},
    commitment::root::CommitmentRoot,
    field::FieldElement,
    proof::artifacts::{ProofSystemKind},
    query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
    },
    types::{BackendTag, DatasetId, ProofId, QueryId, SnapshotId},
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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
    }
}

fn scan_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![ColumnTrace::new(
        "col_a",
        (0..n).map(|i| FieldElement(i as u64)).collect(),
    )];
    w.result_row_count = n as u64;
    w.result_commitment = *blake3::hash(b"scan").as_bytes();
    w
}

#[allow(dead_code)]
fn sorted_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    let vals: Vec<FieldElement> = (0..n).map(|i| FieldElement(i as u64)).collect();
    // input_columns = same as output for this test (no permutation needed)
    w.input_columns = vec![ColumnTrace::new("__row_hash_input", vals.clone())];
    w.columns = vec![ColumnTrace::new("sort_key", vals)];
    w.result_row_count = n as u64;
    w.result_commitment = *blake3::hash(b"sorted").as_bytes();
    w
}

#[allow(dead_code)]
fn group_witness() -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    let keys: Vec<FieldElement> = vec![1, 1, 2, 2, 3].into_iter().map(FieldElement).collect();
    let vals: Vec<FieldElement> = vec![10, 20, 30, 40, 50].into_iter().map(FieldElement).collect();
    w.input_columns = vec![ColumnTrace::new("__row_hash_input", keys.clone())];
    w.columns = vec![
        ColumnTrace::new("group_key", keys),
        ColumnTrace::new("value", vals),
    ];
    w.result_row_count = 5;
    w.result_commitment = *blake3::hash(b"group").as_bytes();
    w
}

#[allow(dead_code)]
fn join_witness_matching(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    let keys: Vec<FieldElement> = (0..n).map(|i| FieldElement(i as u64)).collect();
    w.columns = vec![
        ColumnTrace::new("left_key",  keys.clone()),
        ColumnTrace::new("right_key", keys),
    ];
    w.result_row_count = n as u64;
    w.result_commitment = *blake3::hash(b"join").as_bytes();
    w
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Tampered proof bytes → verify() must fail
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_proof_bytes_fails_verification() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let mut artifact = b.prove(circuit.as_ref(), &scan_witness(5)).await.unwrap();

    // Corrupt the serialized proof envelope
    artifact.proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let vr = b.verify(&artifact).await.unwrap();
    assert!(!vr.is_valid, "corrupted proof bytes must not verify");
    assert!(vr.error.is_some(), "error message expected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Tampered result_commitment → verify() must fail
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_result_commitment_fails_verification() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let mut artifact = b.prove(circuit.as_ref(), &scan_witness(5)).await.unwrap();

    artifact.public_inputs.result_commitment = [0xABu8; 32];

    let vr = b.verify(&artifact).await.unwrap();
    assert!(!vr.is_valid, "tampered result_commitment must not verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Tampered snapshot_root → verify() must fail
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_snapshot_root_fails_verification() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let mut artifact = b.prove(circuit.as_ref(), &scan_witness(5)).await.unwrap();

    artifact.public_inputs.snapshot_root = [0xCDu8; 32];

    let vr = b.verify(&artifact).await.unwrap();
    assert!(!vr.is_valid, "tampered snapshot_root must not verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Tampered query_hash → verify() must fail
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_query_hash_fails_verification() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let mut artifact = b.prove(circuit.as_ref(), &scan_witness(5)).await.unwrap();

    artifact.public_inputs.query_hash = [0xEFu8; 32];

    let vr = b.verify(&artifact).await.unwrap();
    assert!(!vr.is_valid, "tampered query_hash must not verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Unsorted sort witness → prove() must return Err
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unsorted_witness_fails_sort_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Sort { keys_json: "[]".into() });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // [5, 3, 1, 4, 2] — neither ascending nor descending
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![ColumnTrace::new(
        "sort_key",
        vec![5, 3, 1, 4, 2].into_iter().map(FieldElement).collect(),
    )];
    w.result_row_count = 5;
    w.result_commitment = *blake3::hash(b"bad_sort").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "unsorted witness must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("constraint validation failed"),
        "error must mention constraint validation: {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Sort multiset violation: output is sorted but a value was injected
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sort_multiset_violation_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Sort { keys_json: "[]".into() });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // Input: [1, 3, 5, 7, 9] (pre-sort)
    // Output: [1, 2, 5, 7, 9] — valid sort order but 2 was injected (replaced 3)
    let input_vals: Vec<FieldElement> = vec![1, 3, 5, 7, 9].into_iter().map(FieldElement).collect();
    let output_vals: Vec<FieldElement> = vec![1, 2, 5, 7, 9].into_iter().map(FieldElement).collect();

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.input_columns = vec![ColumnTrace::new("__row_hash_input", input_vals)];
    w.columns = vec![ColumnTrace::new("sort_key", output_vals)];
    w.result_row_count = 5;
    w.result_commitment = *blake3::hash(b"injected").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "multiset violation must fail prove");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("constraint validation failed"),
        "error must mention constraint validation: {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Unsorted group_by key → prove() must return Err
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unsorted_group_key_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::PartialAggregate {
        group_by_json: r#"["dept"]"#.into(),
        aggregates_json: "[]".into(),
    });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // Keys: [2, 1, 3] — not sorted
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![ColumnTrace::new(
        "group_key",
        vec![2, 1, 3].into_iter().map(FieldElement).collect(),
    )];
    w.result_row_count = 3;
    w.result_commitment = *blake3::hash(b"bad_group").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "unsorted group key must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("constraint validation failed"),
        "error must mention constraint validation: {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Group_by multiset violation: sorted but row was swapped in
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn group_by_multiset_violation_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::PartialAggregate {
        group_by_json: r#"["dept"]"#.into(),
        aggregates_json: "[]".into(),
    });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // Input: [1, 1, 2, 3] — original multiset
    // Output: [1, 1, 2, 4] — 4 was injected (replaced 3), but still sorted
    let input_vals: Vec<FieldElement> = vec![1u64, 1, 2, 3].into_iter().map(FieldElement).collect();
    let output_vals: Vec<FieldElement> = vec![1u64, 1, 2, 4].into_iter().map(FieldElement).collect();

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.input_columns = vec![ColumnTrace::new("__row_hash_input", input_vals)];
    w.columns = vec![ColumnTrace::new("group_key", output_vals)];
    w.result_row_count = 4;
    w.result_commitment = *blake3::hash(b"injected_group").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "group_by multiset violation must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("constraint validation failed"),
        "error must mention constraint validation: {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Join key mismatch → prove() must return Err
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn join_key_mismatch_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::HashJoin {
        condition_json: None,
        kind_json: "inner".into(),
    });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // Row 2: left_key=5 but right_key=99 — mismatch
    let left_keys: Vec<FieldElement>  = vec![1, 2, 5].into_iter().map(FieldElement).collect();
    let right_keys: Vec<FieldElement> = vec![1, 2, 99].into_iter().map(FieldElement).collect();

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![
        ColumnTrace::new("left_key",  left_keys),
        ColumnTrace::new("right_key", right_keys),
    ];
    w.result_row_count = 3;
    w.result_commitment = *blake3::hash(b"bad_join").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "join key mismatch must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("constraint validation failed"),
        "error must mention constraint validation: {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Join column length mismatch → prove() must return Err
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn join_column_length_mismatch_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::HashJoin {
        condition_json: None,
        kind_json: "inner".into(),
    });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // left_key has 3 rows, right_key has 2 rows
    let left_keys: Vec<FieldElement>  = vec![1, 2, 3].into_iter().map(FieldElement).collect();
    let right_keys: Vec<FieldElement> = vec![1, 2].into_iter().map(FieldElement).collect();

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![
        ColumnTrace::new("left_key",  left_keys),
        ColumnTrace::new("right_key", right_keys),
    ];
    w.result_row_count = 3;
    w.result_commitment = *blake3::hash(b"length_mismatch").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "join column length mismatch must fail");
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Join result_row_count mismatch → prove() must return Err
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn join_result_row_count_mismatch_fails_prove() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::HashJoin {
        condition_json: None,
        kind_json: "inner".into(),
    });
    let circuit = b.compile_circuit(&plan).await.unwrap();

    // Actual matched rows: 2, but result_row_count says 5
    let keys: Vec<FieldElement> = vec![1, 2].into_iter().map(FieldElement).collect();
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.columns = vec![
        ColumnTrace::new("left_key",  keys.clone()),
        ColumnTrace::new("right_key", keys),
    ];
    w.result_row_count = 99; // wrong!
    w.result_commitment = *blake3::hash(b"count_lie").as_bytes();

    let result = b.prove(circuit.as_ref(), &w).await;
    assert!(result.is_err(), "wrong result_row_count must fail join prove");
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Empty proof bytes → verify() must return is_valid=false
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_proof_bytes_fails_verification() {
    use zkdb_plonky2::proof::artifacts::{ProofArtifact, PublicInputs};

    let b = ConstraintCheckedBackend::new();
    let artifact = ProofArtifact {
        proof_id: ProofId::new(),
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        backend: BackendTag::ConstraintChecked,
        proof_system: ProofSystemKind::HashChainAudit,
        proof_bytes: vec![],  // empty!
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
    assert!(!vr.is_valid, "empty proof bytes must not verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Valid witness proves and verifies correctly (baseline sanity check)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_witness_proves_and_verifies() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let artifact = b.prove(circuit.as_ref(), &scan_witness(10)).await.unwrap();

    assert_eq!(artifact.backend, BackendTag::ConstraintChecked);
    assert_eq!(artifact.proof_system, ProofSystemKind::HashChainAudit);

    let vr = b.verify(&artifact).await.unwrap();
    assert!(vr.is_valid, "valid artifact must verify: {:?}", vr.error);
    assert_eq!(vr.proof_system, ProofSystemKind::HashChainAudit);
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Plonky2 stub prove() returns error, NOT a success
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_stub_prove_always_errors() {
    use zkdb_plonky2::backend::Plonky2Backend;

    let b = Plonky2Backend::new_stub();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let witness = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let result = b.prove(circuit.as_ref(), &witness).await;
    assert!(result.is_err(), "Plonky2 stub prove must always return Err");

    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("not yet wired"),
        "Plonky2 stub error must say 'not yet wired': {}", msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Proof system label never mislabels ConstraintChecked as a real SNARK
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn constraint_checked_never_labeled_as_real_snark() {
    let b = ConstraintCheckedBackend::new();
    let plan = make_plan(ProofOperator::Scan { chunk_indices: vec![0], column_names: None });
    let circuit = b.compile_circuit(&plan).await.unwrap();
    let artifact = b.prove(circuit.as_ref(), &scan_witness(3)).await.unwrap();

    assert!(
        !artifact.proof_system.is_zero_knowledge(),
        "ConstraintChecked must NOT be zero-knowledge"
    );
    assert!(
        !artifact.proof_system.is_succinct(),
        "ConstraintChecked must NOT be succinct"
    );
    assert!(
        !artifact.proof_system.has_polynomial_commitments(),
        "ConstraintChecked must NOT have polynomial commitments"
    );
    assert!(
        artifact.proof_system.has_real_constraints(),
        "ConstraintChecked MUST have real constraints"
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::HashChainAudit);
}
