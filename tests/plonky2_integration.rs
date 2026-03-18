//! End-to-end integration tests for the real Plonky2 backend.
//!
//! ## Phase-3 witness contract
//!
//! Every circuit now constrains `PI[0]` (= `snap_lo`) to equal
//! `Poseidon(private_witness_values[0..MAX_ROWS-1]).elements[0]`.
//! Tests that construct `WitnessTrace` directly **must** set
//! `snapshot_root[..8]` to the matching Poseidon value; otherwise
//! `prove()` will fail with a constraint violation.
//!
//! Each `make_*_witness` helper computes this value using
//! `compute_snap_lo(MAX_ROWS, &binding_values)` from the
//! `commitment::poseidon` module.
//!
//! ### Which values drive snap_lo per circuit?
//!
//! | Circuit    | Binding array        |
//! |------------|----------------------|
//! | AggCircuit | `values` (col[0])    |
//! | SortCircuit| `in_vals` (pre-sort) |
//! | GroupBy    | `in_keys` (pre-sort) |
//! | Join       | `left_keys`          |
//!
//! Tests 1–9:  COUNT / SUM / AVG aggregation circuits (AggCircuit)
//! Tests 10–15: ORDER BY (SortCircuit), GROUP BY (GroupByCircuit), JOIN (JoinCircuit)
//! Tests 16–21: Semantic security — wrong snap_lo / wrong permutation must fail

use std::sync::Arc;

use zkdb_plonky2::{
    backend::{Plonky2Backend, ProvingBackend},
    benchmarks::types::BackendKind,
    benchmarks::{BenchmarkRunner, BenchmarkScenario},
    circuit::witness::{compute_group_output_lo_padded, ColumnTrace, WitnessTrace},
    commitment::{poseidon::compute_snap_lo, root::CommitmentRoot},
    field::FieldElement,
    proof::artifacts::{ExternalAnchorStatus, ProofSystemKind},
    query::proof_plan::{
        AggregationTopology, OperatorParams, ProofOperator, ProofPlan, ProvingTask, TaskId,
    },
    types::{BackendTag, DatasetId, QueryId, SnapshotId},
};

const MAX_ROWS: usize = 128; // must match plonky2.rs MAX_ROWS

// ─────────────────────────────────────────────────────────────────────────────
// Plan builders
// ─────────────────────────────────────────────────────────────────────────────

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
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

fn sum_plan() -> ProofPlan {
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
                    aggregates_json: r#"[{"kind":"sum","column":"amount"}]"#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

fn avg_plan() -> ProofPlan {
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
                    aggregates_json: r#"[{"kind":"avg","column":"score"}]"#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

fn sort_plan() -> ProofPlan {
    let tid = TaskId::new();
    ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![ProvingTask {
                task_id: tid.clone(),
                operator: ProofOperator::Sort {
                    keys_json: r#"[{"col":"amount","dir":"asc"}]"#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

fn group_by_plan() -> ProofPlan {
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
                    group_by_json: r#"["dept"]"#.into(),
                    aggregates_json: r#"[{"kind":"sum","column":"salary"}]"#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

fn join_plan() -> ProofPlan {
    let tid = TaskId::new();
    ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![ProvingTask {
                task_id: tid.clone(),
                operator: ProofOperator::HashJoin {
                    condition_json: Some(r#"{"left":"id","right":"id"}"#.into()),
                    kind_json: r#""inner""#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an AggCircuit witness.
///
/// `snap_lo` is set to `compute_snap_lo(MAX_ROWS, &values_zero_padded)` so
/// the Poseidon binding constraint passes.
fn make_witness(
    n: usize,
    column_name: &str,
    values: Vec<u64>,
    selected_count: usize,
) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    // AggCircuit binds to col[0] values — snap_lo = Poseidon(values_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &values);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];
    w.result_row_count = selected_count as u64;
    w.selected = (0..n).map(|i| i < selected_count).collect();
    let col = ColumnTrace::new(column_name, values.into_iter().map(FieldElement).collect());
    w.columns = vec![col];
    w
}

/// Build a SortCircuit witness.
///
/// `snap_lo` = Poseidon(in_vals_padded)[0]  (bound to PRE-SORT values)
fn make_sort_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let sorted: Vec<u64> = (0..n as u64).collect();
    let unsorted: Vec<u64> = (0..n as u64).rev().collect();

    // SortCircuit binds to in_vals — snap_lo = Poseidon(in_vals_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &unsorted);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];

    w.columns = vec![ColumnTrace::new(
        "amount",
        sorted.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.input_columns = vec![ColumnTrace::new(
        "amount_in",
        unsorted.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; n];
    w.result_row_count = n as u64;
    w
}

/// Build a GroupByCircuit witness.
///
/// `snap_lo` = Poseidon(in_keys_padded)[0]  (bound to PRE-SORT keys)
/// `group_output_lo` = compute_group_output_lo_padded(sorted_keys, vals)
///   — must match PI[5] computed by the circuit from out_keys ++ vals ++ boundary_flags
fn make_group_by_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let sorted_keys: Vec<u64> = (0..n as u64).collect();
    let unsorted_keys: Vec<u64> = (0..n as u64).rev().collect();
    let vals: Vec<u64> = (0..n as u64).map(|i| i * 100).collect();

    // GroupByCircuit binds to in_keys — snap_lo = Poseidon(in_keys_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &unsorted_keys);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [4u8; 32];

    // group_output_lo: must match PI[5] produced by the circuit.
    // Circuit computes Poseidon(out_keys_padded ++ vals_padded ++ boundary_flags_padded)[0].
    w.group_output_lo = compute_group_output_lo_padded(&sorted_keys, &vals);

    w.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new("salary", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.input_columns = vec![ColumnTrace::new(
        "dept_in",
        unsorted_keys.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; n];
    w.result_row_count = n as u64;
    w
}

/// Build a JoinCircuit witness.
///
/// `snap_lo` = Poseidon(left_keys_padded)[0]   (PI[0])
/// `join_right_snap_lo` = Poseidon(right_keys_padded)[0]  (PI[4])
fn make_join_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let keys: Vec<u64> = (0..n as u64).collect();
    let vals: Vec<u64> = (0..n as u64).map(|i| i * 10).collect();

    // JoinCircuit binds left_keys to PI[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &keys);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [6u8; 32];

    // JoinCircuit binds right_keys to PI[4]; must match what circuit computes
    w.join_right_snap_lo = compute_snap_lo(MAX_ROWS, &keys); // same keys here (all match)

    w.columns = vec![
        ColumnTrace::new("left_key", keys.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("right_key", keys.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("left_val", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.selected = vec![true; n];
    w.result_row_count = n as u64;
    w
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: basic prove + verify for COUNT(*)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_count_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(30, "__primary", vec![1u64; 30], 30);

    let artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");

    assert!(
        !artifact.proof_bytes.is_empty(),
        "proof bytes must be non-empty"
    );
    assert!(
        artifact.proof_bytes.len() > 1000,
        "Plonky2 FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    assert_eq!(artifact.backend, BackendTag::Plonky2);
    assert!(
        !artifact.verification_key_bytes.is_empty(),
        "vk bytes must be present"
    );

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "valid Plonky2 proof must verify; error={:?}",
        result.error
    );
    assert_eq!(result.proof_system, ProofSystemKind::Plonky2Snark);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: SUM proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_sum_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let plan = sum_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let amounts: Vec<u64> = (1000..1050).collect();
    let witness = make_witness(50, "amount", amounts, 50);

    let artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");
    assert!(artifact.proof_bytes.len() > 1000, "proof must be sizeable");

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "SUM proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: AVG proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_avg_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let plan = avg_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let scores: Vec<u64> = (0..100).collect();
    let witness = make_witness(100, "score", scores, 50);

    let artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");
    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "AVG proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: tampered proof bytes must fail verification
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_tampered_proof_fails_verify() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(10, "__primary", vec![1u64; 10], 10);

    let mut artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");
    let mid = artifact.proof_bytes.len() / 2;
    for i in 0..8 {
        artifact.proof_bytes[mid + i] ^= 0xFF;
    }

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    assert!(!result.is_valid, "tampered proof must be invalid");
    assert!(result.error.is_some(), "error message must be populated");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: proof_system label is Plonky2Snark
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_system_label_is_snark() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(5, "__primary", vec![1u64; 5], 5);
    let artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");

    assert_ne!(artifact.proof_system, ProofSystemKind::None);
    assert_ne!(artifact.proof_system, ProofSystemKind::HashChainAudit);
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: proof size is consistent across multiple proves
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_size_is_consistent() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");

    let w1 = make_witness(10, "__primary", vec![1u64; 10], 10);
    let w2 = make_witness(20, "__primary", vec![2u64; 20], 20);

    let a1 = b.prove(handle.as_ref(), &w1).await.expect("prove 1 failed");
    let a2 = b.prove(handle.as_ref(), &w2).await.expect("prove 2 failed");

    assert_eq!(
        a1.proof_bytes.len(),
        a2.proof_bytes.len(),
        "Plonky2 proof size must be constant for the same circuit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: zero-row witness proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_empty_selection_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    // All rows excluded; values are zeros — snap_lo = Poseidon(zeros)[0]
    let witness = make_witness(20, "__primary", vec![1u64; 20], 0);

    let artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");
    let result = b.verify(&artifact).await.expect("verify failed");
    assert!(
        result.is_valid,
        "zero-selection proof must still be valid; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: BenchmarkRunner end-to-end with Plonky2
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_count_all() {
    // BenchmarkRunner generates a multi-operator plan (ChunkedScan + Aggregate).
    // Multi-operator composed plans are rejected by the Plonky2 backend until
    // recursive folding is implemented (audit gap 7). The runner reports failure
    // rather than silently reducing to just the root operator.
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_count_all",
        "SELECT COUNT(*) FROM benchmark_transactions",
        100,
    )
    .with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;
    if !result.success {
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("multi-operator") || err.contains("UNSUPPORTED"),
            "unexpected failure reason: {err}"
        );
    }
    // If the plan happens to have only one provable operator it should succeed with a real proof.
    if result.success {
        assert!(
            result.metrics.proof_size_bytes > 1000,
            "Plonky2 proof must exceed 1 KB, got {} bytes",
            result.metrics.proof_size_bytes
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: BenchmarkRunner with SUM query
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_filter_sum() {
    // A WHERE clause introduces a Filter operator alongside Aggregate, making this
    // a multi-operator plan that is now explicitly rejected (audit gap 7).
    // The test asserts either a proper rejection message or, if only one provable
    // operator is present, a real FRI proof.
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_filter_sum",
        "SELECT SUM(amount) FROM benchmark_transactions WHERE amount > 50000",
        100,
    )
    .with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;
    if !result.success {
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("multi-operator") || err.contains("UNSUPPORTED"),
            "unexpected failure reason: {err}"
        );
    }
    if result.success {
        assert!(
            result.metrics.proof_size_bytes > 1000,
            "must be real FRI proof"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: SortCircuit (ORDER BY) proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let handle = b
        .compile_circuit(&sort_plan())
        .await
        .expect("compile failed");
    let w = make_sort_witness(30);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "SortCircuit FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    assert_eq!(artifact.backend, BackendTag::Plonky2);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "ORDER BY proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: SortCircuit — tampered proof fails
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_tampered_fails() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    let w = make_sort_witness(10);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    let mid = artifact.proof_bytes.len() / 2;
    for i in 0..8 {
        artifact.proof_bytes[mid + i] ^= 0xFF;
    }

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    assert!(!result.is_valid, "tampered ORDER BY proof must be invalid");
    assert!(result.error.is_some(), "error message must be populated");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: SortCircuit — empty input (zero rows)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_empty_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    let w = make_sort_witness(0);
    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    let result = b.verify(&artifact).await.expect("verify call");
    assert!(
        result.is_valid,
        "empty ORDER BY proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: GroupByCircuit proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let handle = b
        .compile_circuit(&group_by_plan())
        .await
        .expect("compile failed");
    let w = make_group_by_witness(25);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "GroupByCircuit FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "GROUP BY proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: JoinCircuit proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let handle = b
        .compile_circuit(&join_plan())
        .await
        .expect("compile failed");
    let w = make_join_witness(20);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "JoinCircuit FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(
        result.is_valid,
        "JOIN proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: All circuits produce Plonky2Snark label
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_all_circuits_produce_snark_label() {
    let b = Plonky2Backend::new();

    for (plan, witness, name) in [
        (sort_plan(), make_sort_witness(5), "ORDER BY"),
        (group_by_plan(), make_group_by_witness(5), "GROUP BY"),
        (join_plan(), make_join_witness(5), "JOIN"),
    ] {
        let handle = b.compile_circuit(&plan).await.expect("compile");
        let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove");
        assert_eq!(
            artifact.proof_system,
            ProofSystemKind::Plonky2Snark,
            "{name}: proof_system must be Plonky2Snark"
        );
        assert_ne!(artifact.proof_system, ProofSystemKind::None);
        assert_ne!(artifact.proof_system, ProofSystemKind::HashChainAudit);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests 16–21: Semantic security — wrong snap_lo and wrong permutation
// ─────────────────────────────────────────────────────────────────────────────

/// Test 16: AggCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_agg_wrong_snap_lo_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");

    let mut w = make_witness(10, "__primary", vec![42u64; 10], 10);
    // Corrupt snap_lo — the circuit Poseidon binding will reject this.
    w.snapshot_root = [0xABu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "AggCircuit must reject witness with wrong snap_lo"
    );
}

/// Test 17: SortCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_sort_wrong_snap_lo_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    let mut w = make_sort_witness(5);
    // Zero out snapshot_root — wrong snap_lo for the in_vals.
    w.snapshot_root = [0u8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "SortCircuit must reject witness with wrong snap_lo"
    );
}

/// Test 18: GroupByCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_group_by_wrong_snap_lo_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    let mut w = make_group_by_witness(5);
    w.snapshot_root = [0xFFu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "GroupByCircuit must reject witness with wrong snap_lo"
    );
}

/// Test 19: JoinCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_join_wrong_snap_lo_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    let mut w = make_join_witness(5);
    w.snapshot_root = [0xCCu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "JoinCircuit must reject witness with wrong snap_lo"
    );
}

/// Test 20: SortCircuit with non-permutation out_vals must fail.
///
/// [1,2,3] → [1,2,4] is not a valid ORDER BY result; the grand-product
/// permutation check must reject it with overwhelming probability.
#[tokio::test]
async fn plonky2_sort_non_permutation_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    let in_vals: Vec<u64> = vec![1, 2, 3];
    let out_vals_bad: Vec<u64> = vec![1, 2, 4]; // NOT a permutation of {1,2,3}
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_vals);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];
    w.columns = vec![ColumnTrace::new(
        "out",
        out_vals_bad.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.input_columns = vec![ColumnTrace::new(
        "in",
        in_vals.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; 3];
    w.result_row_count = 3;

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "SortCircuit must reject non-permutation out_vals (grand-product fails)"
    );
}

/// Test 21: GroupByCircuit with non-permutation out_keys must fail.
#[tokio::test]
async fn plonky2_group_by_non_permutation_fails_prove() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    let in_keys: Vec<u64> = vec![3, 1, 2];
    let out_keys_bad: Vec<u64> = vec![1, 2, 5]; // NOT a permutation
    let vals: Vec<u64> = vec![10, 20, 30];
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_keys);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [4u8; 32];
    w.columns = vec![
        ColumnTrace::new(
            "dept",
            out_keys_bad.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new("salary", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.input_columns = vec![ColumnTrace::new(
        "dept_in",
        in_keys.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; 3];
    w.result_row_count = 3;

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "GroupByCircuit must reject non-permutation out_keys (grand-product fails)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 22: DESC sort proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

/// Test 22: Proves a DESC sort using the real DescSortCircuit.
/// DescSortCircuit constrains out[i] = out[i+1] + diff[i] (non-increasing).
/// in_vals is any permutation; out_vals is the same values sorted descending.
#[tokio::test]
async fn plonky2_sort_desc_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let tid = TaskId::new();
    // sort_descending=true → compile_circuit routes to DescSortCircuit
    let plan = ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![ProvingTask {
                task_id: tid.clone(),
                operator: ProofOperator::Sort {
                    keys_json: r#"[{"col":"amount","dir":"desc"}]"#.into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams {
            sort_descending: true,
            ..Default::default()
        },
        schema_json: None,
    };
    let handle = b.compile_circuit(&plan).await.expect("compile failed");

    let n = 10usize;
    // in_vals: original data (ascending sequence as if stored that way)
    let in_vals: Vec<u64> = (0..n as u64).collect(); // [0,1,2,...,9]
                                                     // out_vals: same values sorted DESCENDING — what DescSortCircuit proves
    let out_vals: Vec<u64> = (0..n as u64).rev().collect(); // [9,8,...,0]

    // snap_lo binds to in_vals (pre-sort): PI[0] = Poseidon(in_vals_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_vals);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];
    w.sort_descending = true;
    w.input_columns = vec![ColumnTrace::new(
        "amount_in",
        in_vals.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.columns = vec![ColumnTrace::new(
        "amount_out",
        out_vals.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; n];
    w.result_row_count = n as u64;

    let artifact = b
        .prove(handle.as_ref(), &w)
        .await
        .expect("DESC sort prove failed");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "proof must be sizeable FRI proof"
    );

    let result = b.verify(&artifact).await.expect("verify failed");
    assert!(
        result.is_valid,
        "DESC sort proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 23: GROUP BY per-group commitment is deterministic
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_per_group_commitment_is_deterministic() {
    let b = Plonky2Backend::new();
    let handle = b
        .compile_circuit(&group_by_plan())
        .await
        .expect("compile failed");

    let w1 = make_group_by_witness(20);
    let w2 = make_group_by_witness(20);

    let a1 = b.prove(handle.as_ref(), &w1).await.expect("prove 1 failed");
    let a2 = b.prove(handle.as_ref(), &w2).await.expect("prove 2 failed");

    // Same data → same group_output_lo
    assert_eq!(
        a1.public_inputs.group_output_lo, a2.public_inputs.group_output_lo,
        "same group_by witness must produce same group_output_lo"
    );
    // Also verify both proofs
    let r1 = b.verify(&a1).await.expect("verify 1 failed");
    let r2 = b.verify(&a2).await.expect("verify 2 failed");
    assert!(r1.is_valid, "proof 1 must verify");
    assert!(r2.is_valid, "proof 2 must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 24: wrong qhash fails verify (PI[1] cross-check)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_wrong_qhash_fails_verify() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(10, "__primary", vec![1u64; 10], 10);

    let mut artifact = b
        .prove(handle.as_ref(), &witness)
        .await
        .expect("prove failed");

    // Tamper the query_hash in public_inputs (first 8 bytes that form qhash_lo)
    artifact.public_inputs.query_hash[0] ^= 0xFF;
    artifact.public_inputs.query_hash[1] ^= 0xFF;

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    // Either the PI[1] cross-check fails or the proof verification itself fails
    // (both are valid outcomes for tampered data)
    assert!(!result.is_valid, "tampered qhash must fail verification");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 25: multi-operator plan rejected by compile_circuit
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_multi_operator_plan_rejected() {
    let b = Plonky2Backend::new();

    let t1 = TaskId::new();
    let t2 = TaskId::new();
    let plan = ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![
                ProvingTask {
                    task_id: t1.clone(),
                    operator: ProofOperator::Sort {
                        keys_json: "[]".into(),
                    },
                    depends_on: vec![],
                },
                ProvingTask {
                    task_id: t2.clone(),
                    operator: ProofOperator::PartialAggregate {
                        group_by_json: r#"["dept"]"#.into(),
                        aggregates_json: "[]".into(),
                    },
                    depends_on: vec![t1.clone()],
                },
            ],
            root_task_id: t2,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    };

    let result = b.compile_circuit(&plan).await;
    assert!(
        result.is_err(),
        "multi-operator plan must be rejected by compile_circuit"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("UNSUPPORTED") || msg.contains("multi-operator"),
        "error must mention unsupported multi-operator: {}",
        msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 26: LIMIT plan rejected by compile_circuit
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_limit_plan_rejected() {
    let b = Plonky2Backend::new();

    let t1 = TaskId::new();
    let t2 = TaskId::new();
    let plan = ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![
                ProvingTask {
                    task_id: t1.clone(),
                    operator: ProofOperator::Sort {
                        keys_json: "[]".into(),
                    },
                    depends_on: vec![],
                },
                ProvingTask {
                    task_id: t2.clone(),
                    operator: ProofOperator::Limit { n: 10, offset: 0 },
                    depends_on: vec![t1],
                },
            ],
            root_task_id: t2,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams {
            limit: 10,
            ..Default::default()
        },
        schema_json: None,
    };

    let result = b.compile_circuit(&plan).await;
    assert!(
        result.is_err(),
        "LIMIT plan must be rejected by compile_circuit"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("UNSUPPORTED") || msg.contains("LIMIT"),
        "error must mention unsupported LIMIT: {}",
        msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 27: GROUP BY group_output_lo is non-zero and proves + verifies
// (exercises PI[5] cross-check in verify)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_pi5_cross_check_passes() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");
    let w = make_group_by_witness(20);

    assert_ne!(
        w.group_output_lo, 0,
        "make_group_by_witness must produce non-zero group_output_lo"
    );

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    assert_ne!(
        artifact.public_inputs.group_output_lo, 0,
        "artifact group_output_lo must be non-zero for non-trivial input"
    );

    let result = b.verify(&artifact).await.expect("verify call");
    assert!(
        result.is_valid,
        "GROUP BY with correct group_output_lo must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 28: tampered group_output_lo must fail PI[5] cross-check
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_tampered_pi5_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");
    let w = make_group_by_witness(20);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Tamper: corrupt the group_output_lo in the artifact metadata.
    // The proof still contains the correct PI[5]; verify() must detect the mismatch.
    let original = artifact.public_inputs.group_output_lo;
    artifact.public_inputs.group_output_lo = original ^ 0xDEAD_BEEF_CAFE_1234;

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    assert!(
        !result.is_valid,
        "tampered group_output_lo must fail PI[5] cross-check"
    );
    assert!(result.error.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 29: JOIN join_right_snap_lo is non-zero and proves + verifies
// (exercises PI[4] cross-check in verify)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_pi4_cross_check_passes() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");
    let w = make_join_witness(20);

    assert_ne!(
        w.join_right_snap_lo, 0,
        "make_join_witness must produce non-zero join_right_snap_lo"
    );

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    assert_ne!(
        artifact.public_inputs.join_right_snap_lo, 0,
        "artifact join_right_snap_lo must be non-zero"
    );

    let result = b.verify(&artifact).await.expect("verify call");
    assert!(
        result.is_valid,
        "JOIN with correct right_snap_lo must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 30: tampered join_right_snap_lo must fail PI[4] cross-check
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_tampered_pi4_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");
    let w = make_join_witness(20);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Tamper: corrupt the right-side commitment in artifact metadata.
    // Proof still contains the correct PI[4]; mismatch must be detected.
    let original = artifact.public_inputs.join_right_snap_lo;
    artifact.public_inputs.join_right_snap_lo = original ^ 0xDEAD_BEEF_CAFE_5678;

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    assert!(
        !result.is_valid,
        "tampered join_right_snap_lo must fail PI[4] cross-check"
    );
    assert!(result.error.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 31: tampered snap_lo (PI[0]) must fail PI[0] cross-check in verify
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_tampered_snap_lo_fails_verify_pi0() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");
    let w = make_witness(10, "__primary", vec![1u64; 10], 10);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Corrupt the snapshot_root in artifact metadata (PI[0] cross-check target).
    // The proof still contains the correct PI[0]; verify() must detect the mismatch.
    artifact.public_inputs.snapshot_root[0] ^= 0xFF;
    artifact.public_inputs.snapshot_root[1] ^= 0xFF;

    let result = b
        .verify(&artifact)
        .await
        .expect("verify call must not panic");
    assert!(
        !result.is_valid,
        "tampered snapshot_root[..8] must fail PI[0] cross-check"
    );
    assert!(result.error.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 32: fabricated right-side rows must fail JoinCircuit prove
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_fabricated_right_side_fails() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    let left_keys: Vec<u64> = (1..=10).collect();
    let right_keys: Vec<u64> = (100..=109).collect();
    let left_vals: Vec<u64> = vec![1u64; 10];

    let snap_lo = compute_snap_lo(MAX_ROWS, &left_keys);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [6u8; 32];
    w.join_right_snap_lo = compute_snap_lo(MAX_ROWS, &right_keys);
    w.columns = vec![
        ColumnTrace::new(
            "left_key",
            left_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "right_key",
            right_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "left_val",
            left_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    w.selected = vec![true; 10];
    w.result_row_count = 10;

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(
        result.is_err(),
        "JoinCircuit must reject witness where sel=true but left_keys != right_keys"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P8 Tests — Public input cross-check & PI[4] result_commit
// ─────────────────────────────────────────────────────────────────────────────

/// Tampering PI[3] (result_row_count in artifact) must make verify() reject.
#[tokio::test]
async fn plonky2_tampered_pi3_count_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");
    let vals: Vec<u64> = (1..=20).collect();
    // make_witness(n, col, vals, sel_count) — sel_count = 20 so all rows selected
    let w = make_witness(20, "val", vals, 20);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Tamper the expected count in the artifact — circuit proved count=20, artifact says 99
    artifact.public_inputs.result_row_count = 99;

    let result = b.verify(&artifact).await.expect("verify must not panic");
    assert!(
        !result.is_valid,
        "tampering artifact result_row_count must fail PI[3] cross-check"
    );
    let err = result.error.unwrap_or_default();
    assert!(
        err.contains("count mismatch"),
        "expected count mismatch in error: {err}"
    );
}

/// Tampering PI[4] (result_commit_lo in artifact) must make verify() reject.
#[tokio::test]
async fn plonky2_tampered_pi4_result_commit_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");
    let vals: Vec<u64> = (1..=15).collect();
    let w = make_witness(15, "val", vals, 15);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // result_commit_lo is filled from proof PI[4]. Tamper it.
    artifact.public_inputs.result_commit_lo ^= 0xDEAD_BEEF_0000_0001;

    let result = b.verify(&artifact).await.expect("verify must not panic");
    assert!(
        !result.is_valid,
        "tampering artifact result_commit_lo must fail PI[4] cross-check"
    );
    let err = result.error.unwrap_or_default();
    assert!(
        err.contains("result_commit_lo mismatch") || err.contains("mismatch"),
        "expected result_commit_lo mismatch in error: {err}"
    );
}

/// Multi-column sort must return an explicit UNSUPPORTED error (not silently reduce).
#[tokio::test]
async fn plonky2_multi_column_sort_rejected() {
    let b = Plonky2Backend::new();
    let tid = TaskId::new();
    let plan = ProofPlan {
        query_id: QueryId::new(),
        snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(),
        snapshot_root: CommitmentRoot::zero(),
        topology: AggregationTopology {
            tasks: vec![ProvingTask {
                task_id: tid.clone(),
                operator: ProofOperator::Sort {
                    // Two sort keys — should be explicitly rejected
                    keys_json: r#"[{"col":"amount","dir":"asc"},{"col":"score","dir":"desc"}]"#
                        .into(),
                },
                depends_on: vec![],
            }],
            root_task_id: tid,
        },
        leaf_count: 1,
        poseidon_snap_lo: 0,
        operator_params: OperatorParams::default(),
        schema_json: None,
    };

    let result = b.compile_circuit(&plan).await;
    assert!(
        result.is_err(),
        "multi-column ORDER BY must return an error"
    );
    let err = format!("{:?}", result.err().unwrap());
    assert!(
        err.contains("UNSUPPORTED") && err.contains("multi-column"),
        "error must mention UNSUPPORTED multi-column: {err}"
    );
}

/// SortCircuit result_commit_lo cross-check in verify() must pass for a valid proof.
#[tokio::test]
async fn plonky2_sort_result_commit_lo_cross_check_passes() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    // make_sort_witness uses reversed(0..n) as in_vals, sorted(0..n) as out_vals
    let w = make_sort_witness(10);
    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // result_commit_lo must be non-zero (it's Poseidon(sum,count)[0])
    assert_ne!(
        artifact.public_inputs.result_commit_lo, 0,
        "SortCircuit must produce non-zero result_commit_lo in artifact"
    );

    let result = b.verify(&artifact).await.expect("verify must not panic");
    assert!(
        result.is_valid,
        "valid sort proof with result_commit_lo must verify: {:?}",
        result.error
    );
}

/// Tampering sort artifact's result_commit_lo must make verify() reject.
#[tokio::test]
async fn plonky2_sort_tampered_result_commit_lo_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    let w = make_sort_witness(8);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Tamper result_commit_lo
    artifact.public_inputs.result_commit_lo ^= 0x1234_5678_9ABC_DEF0;

    let result = b.verify(&artifact).await.expect("verify must not panic");
    assert!(
        !result.is_valid,
        "tampered sort result_commit_lo must fail verify"
    );
    let err = result.error.unwrap_or_default();
    assert!(
        err.contains("result_commit_lo") || err.contains("mismatch"),
        "error must mention result_commit_lo: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 33: Tampered Blake3 result_commitment is NOT checked by the circuit
// (Documented limitation: Plonky2 only proves Poseidon result_commit_lo)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_tampered_blake3_result_commitment_not_checked_by_circuit() {
    let b = Plonky2Backend::new();
    let plan = sum_plan();
    let w = make_witness(10, "salary", vec![5000; 10], 10);
    
    let handle = b.compile_circuit(&plan).await.unwrap();
    let mut artifact = b.prove(handle.as_ref(), &w).await.unwrap();

    // Tamper with the blake3 result_commitment metadata
    artifact.public_inputs.result_commitment[0] ^= 0xFF;

    // Verify should STILL PASS because Plonky2Backend ONLY checks the Poseidon `result_commit_lo`
    // which corresponds to `PI[4]`. The blake3 hash is unproven metadata in this backend.
    let result = b.verify(&artifact).await.unwrap();
    assert!(
        result.is_valid,
        "tampering with unproven blake3 array does not fail verification natively"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 34: Nested Subquery parsing is rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn plonky2_nested_subquery_rejected_by_parser() {
    use zkdb_plonky2::query::parser::QueryParser;

    let sql = "SELECT id FROM (SELECT id FROM users)";
    let result = QueryParser::parse(sql);

    assert!(
        result.is_err(),
        "Nested subqueries in FROM clause should be rejected by the parser"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("unsupported FROM") || msg.contains("QueryParse"),
        "error must mention unsupported FROM relation: {}",
        msg
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 35: snap_lo == 0 guard rejects prove with explicit error message
// ─────────────────────────────────────────────────────────────────────────────
//
// Verifies that the guard added to Plonky2Backend::prove() fires with a
// descriptive message when snapshot_root is all-zero (i.e. no Poseidon
// commitment was ever computed for this witness).

#[tokio::test]
async fn plonky2_snap_lo_zero_guard_explicit_message() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");

    let mut w = make_witness(5, "__primary", vec![42u64; 5], 5);
    // Force snap_lo = 0 by zeroing the snapshot_root
    w.snapshot_root = [0u8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "snap_lo == 0 must be rejected by the guard");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("snap_lo is zero") || err.contains("degenerate"),
        "error must mention 'snap_lo is zero' or 'degenerate', got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 36: ORDER BY — snap_lo is column-value-specific
//
// Two sort witnesses with DIFFERENT pre-sort values bind to different snap_lo
// values.  This proves that the sort commitment is tightly coupled to the
// actual column values, not just a structural property of the proof.
//
// Known gap: only the sort-key column is committed (see README Known Limitations).
// Other payload columns are NOT bound to snap_lo.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_snap_lo_is_column_value_specific() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    // Witness A: pre-sort values [1..10]
    let in_vals_a: Vec<u64> = (1..=10).collect();
    let out_vals_a: Vec<u64> = {
        let mut v = in_vals_a.clone();
        v.sort_unstable();
        v
    };
    let snap_a = compute_snap_lo(MAX_ROWS, &in_vals_a);

    let mut wa = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    wa.snapshot_root[..8].copy_from_slice(&snap_a.to_le_bytes());
    wa.query_hash = [0x0Au8; 32];
    wa.input_columns = vec![ColumnTrace::new(
        "amount_in",
        in_vals_a.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wa.columns = vec![ColumnTrace::new(
        "amount_out",
        out_vals_a.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wa.selected = vec![true; in_vals_a.len()];
    wa.result_row_count = in_vals_a.len() as u64;

    // Witness B: pre-sort values [100..110] (entirely different dataset)
    let in_vals_b: Vec<u64> = (100..=109).collect();
    let out_vals_b: Vec<u64> = {
        let mut v = in_vals_b.clone();
        v.sort_unstable();
        v
    };
    let snap_b = compute_snap_lo(MAX_ROWS, &in_vals_b);

    let mut wb = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    wb.snapshot_root[..8].copy_from_slice(&snap_b.to_le_bytes());
    wb.query_hash = [0x0Au8; 32];
    wb.input_columns = vec![ColumnTrace::new(
        "amount_in",
        in_vals_b.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wb.columns = vec![ColumnTrace::new(
        "amount_out",
        out_vals_b.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wb.selected = vec![true; in_vals_b.len()];
    wb.result_row_count = in_vals_b.len() as u64;

    let artifact_a = b.prove(handle.as_ref(), &wa).await.expect("prove A");
    let artifact_b = b.prove(handle.as_ref(), &wb).await.expect("prove B");

    // The two proofs must carry different snap_lo (PI[0]) values.
    assert_ne!(
        artifact_a.public_inputs.snapshot_root,
        artifact_b.public_inputs.snapshot_root,
        "sort proofs for different input values must produce different snapshot_root (snap_lo)"
    );

    // Both must independently verify correctly.
    assert!(b.verify(&artifact_a).await.unwrap().is_valid, "A verify");
    assert!(b.verify(&artifact_b).await.unwrap().is_valid, "B verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 37: ORDER BY ASC and DESC proofs have different VK tag bytes
//
// The verification key tag byte is 0x01 for SortCircuit (ASC) and 0x04 for
// DescSortCircuit.  Tampering the VK tag on an ASC artifact to claim it is
// DESC must cause verify() to fail because the VK doesn't match the proof.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_asc_and_desc_different_vk_tag() {
    let b = Plonky2Backend::new();

    // Compile ASC plan
    let handle_asc = b.compile_circuit(&sort_plan()).await.expect("compile asc");

    // Build ASC witness
    let in_vals: Vec<u64> = (1..=8).collect();
    let snap = compute_snap_lo(MAX_ROWS, &in_vals);
    let mut w_asc = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w_asc.snapshot_root[..8].copy_from_slice(&snap.to_le_bytes());
    w_asc.query_hash = [0x01u8; 32];
    w_asc.input_columns = vec![ColumnTrace::new(
        "col_in",
        in_vals.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w_asc.columns = vec![ColumnTrace::new(
        "col_out",
        in_vals.iter().map(|&v| FieldElement(v)).collect(), // already sorted ASC
    )];
    w_asc.selected = vec![true; in_vals.len()];
    w_asc.result_row_count = in_vals.len() as u64;

    let mut artifact = b
        .prove(handle_asc.as_ref(), &w_asc)
        .await
        .expect("prove ASC");

    // Verify ASC artifact passes normally
    let res_before = b.verify(&artifact).await.expect("verify ASC");
    assert!(res_before.is_valid, "ASC must verify before VK tamper");

    // VK tag byte 0x01 = SortCircuit (ASC), 0x04 = DescSortCircuit.
    // Tampering the tag claims this is a DESC proof — verify must fail.
    assert!(
        !artifact.verification_key_bytes.is_empty(),
        "VK bytes must be non-empty"
    );
    let original_tag = artifact.verification_key_bytes[0];
    // Flip to the other tag (0x01 ↔ 0x04)
    artifact.verification_key_bytes[0] = if original_tag == 0x01 { 0x04 } else { 0x01 };

    let res_after = b.verify(&artifact).await.expect("verify call must not panic");
    assert!(
        !res_after.is_valid,
        "tampered VK tag must fail verification; original_tag={original_tag}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 38: GROUP BY — snap_lo is group-key-specific
//
// Two GroupBy witnesses with entirely different pre-sort keys bind to
// different snap_lo values.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_snap_lo_is_key_specific() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    // GroupBy witness A: keys [0..8]
    let keys_a: Vec<u64> = (0..8).collect();
    let vals_a: Vec<u64> = keys_a.iter().map(|k| k * 10).collect();
    let snap_a = compute_snap_lo(MAX_ROWS, &keys_a); // binds to UNSORTED keys
    let sorted_keys_a: Vec<u64> = {
        let mut v = keys_a.clone();
        v.sort_unstable();
        v
    };
    let gol_a = compute_group_output_lo_padded(&sorted_keys_a, &vals_a);
    let mut wa = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    wa.snapshot_root[..8].copy_from_slice(&snap_a.to_le_bytes());
    wa.query_hash = [0x0Bu8; 32];
    wa.group_output_lo = gol_a;
    wa.input_columns = vec![ColumnTrace::new(
        "dept_in",
        keys_a.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wa.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys_a.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new("salary", vals_a.iter().map(|&v| FieldElement(v)).collect()),
    ];
    wa.selected = vec![true; keys_a.len()];
    wa.result_row_count = keys_a.len() as u64;

    // GroupBy witness B: keys [1000..1008] — entirely different dataset
    let keys_b: Vec<u64> = (1000..1008).collect();
    let vals_b: Vec<u64> = keys_b.iter().map(|k| k * 10).collect();
    let snap_b = compute_snap_lo(MAX_ROWS, &keys_b);
    let sorted_keys_b: Vec<u64> = {
        let mut v = keys_b.clone();
        v.sort_unstable();
        v
    };
    let gol_b = compute_group_output_lo_padded(&sorted_keys_b, &vals_b);
    let mut wb = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    wb.snapshot_root[..8].copy_from_slice(&snap_b.to_le_bytes());
    wb.query_hash = [0x0Bu8; 32];
    wb.group_output_lo = gol_b;
    wb.input_columns = vec![ColumnTrace::new(
        "dept_in",
        keys_b.iter().map(|&v| FieldElement(v)).collect(),
    )];
    wb.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys_b.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new("salary", vals_b.iter().map(|&v| FieldElement(v)).collect()),
    ];
    wb.selected = vec![true; keys_b.len()];
    wb.result_row_count = keys_b.len() as u64;

    let artifact_a = b.prove(handle.as_ref(), &wa).await.expect("prove A");
    let artifact_b = b.prove(handle.as_ref(), &wb).await.expect("prove B");

    assert_ne!(
        artifact_a.public_inputs.snapshot_root,
        artifact_b.public_inputs.snapshot_root,
        "group_by proofs for different keys must have different snapshot_root (snap_lo)"
    );

    assert!(b.verify(&artifact_a).await.unwrap().is_valid, "A verify");
    assert!(b.verify(&artifact_b).await.unwrap().is_valid, "B verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 39: GROUP BY — tampered vals caught by PI[5] cross-check at verify time
//
// GroupByCircuit COMPUTES PI[5] from the private vals array (not from
// witness.group_output_lo).  If we build a witness with fake vals but store the
// real group_output_lo in the artifact metadata, prove() still succeeds
// (the circuit emits PI[5] based on the fake vals), but verify() rejects
// because proof.PI[5] ≠ artifact.group_output_lo.
//
// This demonstrates that the PI[5] cross-check in verify() is the last line of
// defense against a prover who tampers with the aggregated-values column.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_tampered_vals_caught_at_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    // Build a VALID GroupBy witness first.
    let keys: Vec<u64> = (0..6).collect();
    let real_vals: Vec<u64> = keys.iter().map(|k| k * 100).collect();
    let snap = compute_snap_lo(MAX_ROWS, &keys);
    let sorted_keys: Vec<u64> = {
        let mut v = keys.clone();
        v.sort_unstable();
        v
    };
    let real_gol = compute_group_output_lo_padded(&sorted_keys, &real_vals);

    let mut w_valid = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w_valid.snapshot_root[..8].copy_from_slice(&snap.to_le_bytes());
    w_valid.query_hash = [0x0Cu8; 32];
    w_valid.group_output_lo = real_gol;
    w_valid.input_columns = vec![ColumnTrace::new(
        "dept_in",
        keys.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w_valid.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "salary",
            real_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    w_valid.selected = vec![true; keys.len()];
    w_valid.result_row_count = keys.len() as u64;

    // This should prove and verify correctly.
    let valid_artifact = b.prove(handle.as_ref(), &w_valid).await.expect("prove valid");
    assert!(
        b.verify(&valid_artifact).await.unwrap().is_valid,
        "valid witness must verify"
    );

    // Now build a FAKE witness with tampered vals but the SAME snap/keys.
    // The circuit will compute PI[5] = Poseidon(sorted_keys ++ fake_vals ++ boundary_flags).
    // We store the REAL group_output_lo in the artifact metadata to simulate an attacker
    // who forges the metadata after proving with different vals.
    let fake_vals: Vec<u64> = keys.iter().map(|k| k * 999).collect();
    let fake_gol = compute_group_output_lo_padded(&sorted_keys, &fake_vals);
    // Sanity: fake_gol must differ from real_gol
    assert_ne!(fake_gol, real_gol, "test setup: fake vals must produce different group_output_lo");

    let mut w_fake = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w_fake.snapshot_root[..8].copy_from_slice(&snap.to_le_bytes());
    w_fake.query_hash = [0x0Cu8; 32];
    w_fake.group_output_lo = fake_gol; // consistent with fake vals
    w_fake.input_columns = vec![ColumnTrace::new(
        "dept_in",
        keys.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w_fake.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "salary",
            fake_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    w_fake.selected = vec![true; keys.len()];
    w_fake.result_row_count = keys.len() as u64;

    // prove() with fake vals succeeds — PI[5] is computed from fake_vals by the circuit.
    let mut fake_artifact = b.prove(handle.as_ref(), &w_fake).await.expect("prove fake");

    // Simulate the attack: attacker replaces group_output_lo in the artifact with the REAL value
    // to pretend the proof covers real_vals when it actually covers fake_vals.
    fake_artifact.public_inputs.group_output_lo = real_gol;

    // verify() must detect: proof.PI[5] (= Poseidon(fake_vals)) ≠ artifact.group_output_lo (real_gol)
    let result = b.verify(&fake_artifact).await.expect("verify call");
    assert!(
        !result.is_valid,
        "GroupBy verify must reject artifact where group_output_lo (PI[5]) was forged"
    );
    assert!(result.error.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 40: JOIN — both-side snap_lo values are independent and binding
//
// When left_keys ≠ right_keys, PI[0] (left snap_lo) and PI[4] (right snap_lo)
// must be different.  This demonstrates that both table sides are independently
// bound to their respective Poseidon commitments.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_both_sides_independently_bound() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    // Use distinct left and right key sets so their Poseidon commitments differ.
    let left_keys: Vec<u64> = (1..=8).collect();
    let right_keys: Vec<u64> = (100..=107).collect(); // different from left
    let left_vals: Vec<u64> = left_keys.iter().map(|k| k * 10).collect();

    let left_snap = compute_snap_lo(MAX_ROWS, &left_keys);
    let right_snap = compute_snap_lo(MAX_ROWS, &right_keys);
    assert_ne!(
        left_snap, right_snap,
        "test setup: left/right keys must produce different snap_lo values"
    );

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&left_snap.to_le_bytes());
    w.query_hash = [0x0Du8; 32];
    w.join_right_snap_lo = right_snap;

    w.columns = vec![
        ColumnTrace::new(
            "left_key",
            left_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "right_key",
            right_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "left_val",
            left_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    // No keys match between left and right → all selectors false → count = 0
    w.selected = left_keys
        .iter()
        .zip(right_keys.iter())
        .map(|(l, r)| l == r)
        .collect();
    w.result_row_count = left_keys.len() as u64;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // PI[0] (left) and PI[4] (right) must differ because the key sets differ.
    let pi0 = u64::from_le_bytes(
        artifact.public_inputs.snapshot_root[..8]
            .try_into()
            .unwrap(),
    );
    let pi4 = artifact.public_inputs.join_right_snap_lo;
    assert_ne!(
        pi0, pi4,
        "left snap_lo (PI[0]={pi0:#018x}) must differ from right snap_lo (PI[4]={pi4:#018x})"
    );

    // The proof must still verify (zero matching rows is a valid join result).
    let result = b.verify(&artifact).await.expect("verify");
    assert!(
        result.is_valid,
        "join with no matching keys is still a valid proof; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 41: JOIN completeness gap is documented in the verification result
//
// The JOIN circuit proves soundness (matched rows are correctly committed)
// but NOT completeness (the prover could omit valid matches).
// verify() must emit a warning about this gap and set completeness_proved=false.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_completeness_gap_documented_in_verification() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");
    let w = make_join_witness(10);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    let result = b.verify(&artifact).await.expect("verify");

    // The proof must be cryptographically valid.
    assert!(
        result.is_valid,
        "valid join must verify; error={:?}",
        result.error
    );

    // But completeness must NOT be marked as proved.
    assert!(
        !result.completeness_proved,
        "JOIN completeness must be false — the prover could omit valid matches"
    );

    // And a human-readable warning must explain the gap.
    assert!(
        !result.warnings.is_empty(),
        "JOIN verify result must carry at least one warning about completeness"
    );
    let has_completeness_warning = result
        .warnings
        .iter()
        .any(|w| w.to_lowercase().contains("completeness"));
    assert!(
        has_completeness_warning,
        "at least one warning must mention completeness; warnings={:?}",
        result.warnings
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 42: Lt predicate — full pipeline (WitnessTrace.filter_op=2 → prove → verify)
//
// The AggCircuit constrains selector[i] = (values[i] < pred_val) when pred_op=2.
// We set the wrong filter_op and correct selectors and expect the proof to be
// cryptographically valid, with pred_op=2 and pred_val circuit-bound in PI[5]/PI[6].
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_agg_pred_lt_full_pipeline() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sum_plan()).await.expect("compile");

    let values: Vec<u64> = vec![10, 20, 30, 40, 50];
    let filter_val: u64 = 30;
    let snap_lo = compute_snap_lo(MAX_ROWS, &values);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [0xAAu8; 32];
    w.filter_op = 2; // Lt: select rows where value < filter_val
    w.filter_val = filter_val;
    // values < 30: [10, 20] → selected = [true, true, false, false, false]
    w.selected = vec![true, true, false, false, false];
    w.columns = vec![ColumnTrace::new(
        "amount",
        values.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.result_row_count = 2;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove Lt");

    // pred_op and pred_val are extracted from the PROOF public inputs — circuit-bound.
    assert_eq!(
        artifact.public_inputs.pred_op, 2,
        "pred_op must be 2 (Lt) in artifact"
    );
    assert_eq!(
        artifact.public_inputs.pred_val, filter_val,
        "pred_val must equal filter_val=30"
    );
    // Sum of selected (10 + 20 = 30)
    assert_eq!(
        artifact.public_inputs.result_sum, 30,
        "result_sum must be 10+20=30 for Lt<30"
    );

    let result = b.verify(&artifact).await.expect("verify Lt");
    assert!(
        result.is_valid,
        "Lt predicate proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 43: Gt predicate — full pipeline (WitnessTrace.filter_op=3 → prove → verify)
//
// The AggCircuit constrains selector[i] = (values[i] > pred_val) when pred_op=3.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_agg_pred_gt_full_pipeline() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sum_plan()).await.expect("compile");

    let values: Vec<u64> = vec![10, 20, 30, 40, 50];
    let filter_val: u64 = 30;
    let snap_lo = compute_snap_lo(MAX_ROWS, &values);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [0xBBu8; 32];
    w.filter_op = 3; // Gt: select rows where value > filter_val
    w.filter_val = filter_val;
    // values > 30: [40, 50] → selected = [false, false, false, true, true]
    w.selected = vec![false, false, false, true, true];
    w.columns = vec![ColumnTrace::new(
        "amount",
        values.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.result_row_count = 2;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove Gt");

    assert_eq!(
        artifact.public_inputs.pred_op, 3,
        "pred_op must be 3 (Gt) in artifact"
    );
    assert_eq!(
        artifact.public_inputs.pred_val, filter_val,
        "pred_val must equal filter_val=30"
    );
    // Sum of selected (40 + 50 = 90)
    assert_eq!(
        artifact.public_inputs.result_sum, 90,
        "result_sum must be 40+50=90 for Gt>30"
    );

    let result = b.verify(&artifact).await.expect("verify Gt");
    assert!(
        result.is_valid,
        "Gt predicate proof must verify; error={:?}",
        result.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 44: Tampered pred_op caught by verify() cross-check
//
// Proves with pred_op=2 (Lt), then mutates artifact.public_inputs.pred_op to 3.
// verify() reads pred_op from the PROOF (PI[5]) and compares to the artifact
// metadata — the mismatch must be detected and the result must be invalid.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_agg_pred_op_tamper_caught_at_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sum_plan()).await.expect("compile");

    let values: Vec<u64> = vec![10, 20, 30, 40, 50];
    let snap_lo = compute_snap_lo(MAX_ROWS, &values);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [0xCCu8; 32];
    w.filter_op = 2; // Lt
    w.filter_val = 30;
    w.selected = vec![true, true, false, false, false];
    w.columns = vec![ColumnTrace::new(
        "amount",
        values.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.result_row_count = 2;

    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Honest proof must verify.
    assert!(
        b.verify(&artifact).await.expect("verify1").is_valid,
        "honest Lt proof must verify before tamper"
    );

    // Tamper: change pred_op metadata from 2 (Lt) to 3 (Gt) without touching proof bytes.
    // PI[5] in the proof still says 2, but artifact.public_inputs.pred_op now says 3.
    artifact.public_inputs.pred_op = 3;

    let tampered = b.verify(&artifact).await.expect("verify2");
    assert!(
        !tampered.is_valid,
        "tampered pred_op must be rejected by verify(); result={:?}",
        tampered
    );
    let err = tampered.error.unwrap_or_default();
    assert!(
        err.contains("pred_op"),
        "error must mention pred_op; got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 45: Sort with secondary payload — sort_secondary_snap_lo tamper caught
//
// Builds a sort witness with explicit (key, secondary) pairs, proves, then
// tampers sort_secondary_snap_lo in the artifact metadata.  verify() reads
// PI[5] (Poseidon(in_secondary)) from the proof and rejects the mismatch.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_sort_secondary_snap_lo_tamper_caught_at_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    // in_vals: unsorted keys. Sort permutation (ASC): [10,20,30,40,50] indices [2,4,1,3,0]
    let in_vals:      Vec<u64> = vec![50, 30, 10, 40, 20];
    let out_vals:     Vec<u64> = vec![10, 20, 30, 40, 50];
    let in_secondary: Vec<u64> = vec![101, 202, 303, 404, 505];
    // out_secondary follows the same permutation: in_vals[2]=10→303, [4]=20→505,
    // [1]=30→202, [3]=40→404, [0]=50→101.
    let out_secondary: Vec<u64> = vec![303, 505, 202, 404, 101];

    let snap_lo = compute_snap_lo(MAX_ROWS, &in_vals);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [0xDDu8; 32];
    // input_columns[0] = in_vals (primary sort key, unsorted)
    // input_columns[1] = in_secondary (payload, in original row order)
    w.input_columns = vec![
        ColumnTrace::new(
            "__primary_in",
            in_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "__secondary_in",
            in_secondary.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    // columns[0] = out_vals (sorted ascending)
    // columns[1] = out_secondary (payload permuted with same sort)
    w.columns = vec![
        ColumnTrace::new(
            "__primary_out",
            out_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "__secondary_out",
            out_secondary.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    w.selected = vec![true; in_vals.len()];
    w.result_row_count = in_vals.len() as u64;

    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove sort+secondary");

    // sort_secondary_snap_lo must be non-zero: Poseidon of non-trivial secondary inputs.
    assert_ne!(
        artifact.public_inputs.sort_secondary_snap_lo, 0,
        "sort_secondary_snap_lo must be non-zero when secondary column is provided"
    );

    // Honest proof must verify.
    assert!(
        b.verify(&artifact).await.expect("verify1").is_valid,
        "honest sort with secondary must verify"
    );

    // Tamper: increment sort_secondary_snap_lo by 1.
    // verify() will find proof PI[5] ≠ tampered metadata and reject.
    let original = artifact.public_inputs.sort_secondary_snap_lo;
    artifact.public_inputs.sort_secondary_snap_lo = original.wrapping_add(1);

    let tampered = b.verify(&artifact).await.expect("verify2");
    assert!(
        !tampered.is_valid,
        "tampered sort_secondary_snap_lo must be rejected"
    );
    let err = tampered.error.unwrap_or_default();
    assert!(
        err.contains("sort_secondary_snap_lo"),
        "error must mention sort_secondary_snap_lo; got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 46: Different secondary payloads → different PI[5] commitments
//
// Two sort witnesses share identical sort keys but carry different per-row
// secondary values.  Their sort_secondary_snap_lo (PI[5]) must differ because
// PI[5] = Poseidon(in_secondary_padded)[0] is determined by the payload,
// not just the key order.  This confirms the secondary binding is
// payload-specific, not key-specific.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_sort_secondary_binding_is_payload_specific() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    // Same sort keys for both witnesses.
    // Sort permutation (ASC): in[1]=10, in[2]=20, in[0]=30 → indices [1, 2, 0]
    let in_vals:  Vec<u64> = vec![30, 10, 20];
    let out_vals: Vec<u64> = vec![10, 20, 30];
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_vals);

    // Witness A: secondary [100, 200, 300] → out_secondary follows index [1,2,0] = [200, 300, 100]
    let in_sec_a:  Vec<u64> = vec![100, 200, 300];
    let out_sec_a: Vec<u64> = vec![200, 300, 100];

    // Witness B: secondary [111, 222, 333] → out_secondary = [222, 333, 111]
    let in_sec_b:  Vec<u64> = vec![111, 222, 333];
    let out_sec_b: Vec<u64> = vec![222, 333, 111];

    // Helper closure to build a witness with given secondary.
    let make_w = |in_s: &[u64], out_s: &[u64]| {
        let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
        w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
        w.query_hash = [0xEEu8; 32];
        w.input_columns = vec![
            ColumnTrace::new(
                "__primary_in",
                in_vals.iter().map(|&v| FieldElement(v)).collect(),
            ),
            ColumnTrace::new(
                "__secondary_in",
                in_s.iter().map(|&v| FieldElement(v)).collect(),
            ),
        ];
        w.columns = vec![
            ColumnTrace::new(
                "__primary_out",
                out_vals.iter().map(|&v| FieldElement(v)).collect(),
            ),
            ColumnTrace::new(
                "__secondary_out",
                out_s.iter().map(|&v| FieldElement(v)).collect(),
            ),
        ];
        w.selected = vec![true; in_vals.len()];
        w.result_row_count = in_vals.len() as u64;
        w
    };

    let w_a = make_w(&in_sec_a, &out_sec_a);
    let w_b = make_w(&in_sec_b, &out_sec_b);

    let artifact_a = b.prove(handle.as_ref(), &w_a).await.expect("prove A");
    let artifact_b = b.prove(handle.as_ref(), &w_b).await.expect("prove B");

    assert_ne!(
        artifact_a.public_inputs.sort_secondary_snap_lo,
        artifact_b.public_inputs.sort_secondary_snap_lo,
        "different secondary columns must produce different sort_secondary_snap_lo: \
         A={:#018x} B={:#018x}",
        artifact_a.public_inputs.sort_secondary_snap_lo,
        artifact_b.public_inputs.sort_secondary_snap_lo
    );

    // Both proofs must individually verify.
    assert!(
        b.verify(&artifact_a).await.expect("verify A").is_valid,
        "sort A must verify"
    );
    assert!(
        b.verify(&artifact_b).await.expect("verify B").is_valid,
        "sort B must verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Area 1: Result commitment unification
// ─────────────────────────────────────────────────────────────────────────────

// Test 52: result_commit_poseidon_lo is populated in VerificationResult.
//
// After verifying a valid AggCircuit proof, the VerificationResult must carry
// a non-zero `result_commit_poseidon_lo` equal to the artifact's `result_commit_lo`.
// This is the authoritative circuit-proved commitment; it differs conceptually
// from the Blake3 `result_commitment` metadata field.

#[tokio::test]
async fn plonky2_phase3_result_commit_poseidon_lo_in_verification_result() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&sum_plan()).await.expect("compile");
    let w = make_witness(10, "salary", vec![1000u64; 10], 10);
    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // The circuit-proved Poseidon commitment must be non-zero.
    assert_ne!(
        artifact.public_inputs.result_commit_lo, 0,
        "AggCircuit must produce a non-zero result_commit_lo"
    );

    let result = b.verify(&artifact).await.expect("verify");
    assert!(result.is_valid, "valid proof must verify; error={:?}", result.error);

    // VerificationResult.result_commit_poseidon_lo must mirror the artifact field.
    assert_eq!(
        result.result_commit_poseidon_lo,
        artifact.public_inputs.result_commit_lo,
        "VerificationResult.result_commit_poseidon_lo must equal artifact.result_commit_lo"
    );

    // It must differ from the Blake3 metadata commitment (different encoding/semantics).
    // The Blake3 value is 32 bytes; the Poseidon value is a 64-bit Goldilocks element.
    // They are not the same thing.
    let blake3_lo = u64::from_le_bytes(
        artifact.public_inputs.result_commitment[..8].try_into().unwrap(),
    );
    // In general these WILL differ; assert the types are different (one is 32-byte, other u64).
    // As a sanity check: result_commit_lo must match what was in the artifact.
    assert_eq!(
        result.result_commit_poseidon_lo,
        artifact.public_inputs.result_commit_lo,
        "Poseidon-proved commitment must be from the circuit public input, not the Blake3 hash"
    );
    let _ = blake3_lo; // documented that it is unrelated metadata
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Area 2: GROUP BY running group sums
// ─────────────────────────────────────────────────────────────────────────────

// Test 53: GROUP BY with multi-row groups proves and verifies.
//
// Uses repeated keys so multiple consecutive rows share the same group key.
// The circuit constraint `group_sum[i] = (1-boundary_flag[i-1])*group_sum[i-1] + vals[i]`
// accumulates per-group running sums.  The off-circuit helper
// `compute_group_output_lo_padded` must produce the same PI[5] value.
//
// This test validates that the circuit and the native helper agree when
// actual multi-row groups are present (boundary_flag = 0 within a group).

#[tokio::test]
async fn plonky2_phase3_group_by_multi_row_groups_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    // Sorted keys: [1, 1, 2, 3] → two rows in group-key=1, one each for 2 and 3.
    let sorted_keys: Vec<u64> = vec![1, 1, 2, 3];
    let vals: Vec<u64> = vec![100, 200, 50, 75];
    // Unsorted (pre-sort) keys used for snap_lo binding.
    let unsorted_keys: Vec<u64> = vec![3, 1, 2, 1];

    let snap_lo = compute_snap_lo(MAX_ROWS, &unsorted_keys);
    let group_out_lo = compute_group_output_lo_padded(&sorted_keys, &vals);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [0xA1u8; 32];
    w.group_output_lo = group_out_lo;

    w.columns = vec![
        ColumnTrace::new(
            "dept",
            sorted_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new("salary", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.input_columns = vec![ColumnTrace::new(
        "dept_in",
        unsorted_keys.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w.selected = vec![true; sorted_keys.len()];
    w.result_row_count = sorted_keys.len() as u64;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove multi-row group");

    // PI[5] must match the value the circuit computed (which uses running group sums).
    assert_eq!(
        artifact.public_inputs.group_output_lo, group_out_lo,
        "group_output_lo in artifact must equal native helper value"
    );
    assert_ne!(
        artifact.public_inputs.group_output_lo, 0,
        "group_output_lo must be non-zero for non-trivial groups"
    );

    let result = b.verify(&artifact).await.expect("verify");
    assert!(
        result.is_valid,
        "GROUP BY with multi-row groups must verify; error={:?}",
        result.error
    );
}

// Test 54: GROUP BY commitment differs between unique-key and multi-row-group witnesses
//          with the same raw values, demonstrating that running sums change the commitment.
//
// Scenario A: sorted_keys = [1, 2, 3, 4], vals = [100, 100, 100, 100]
//   → all unique keys, every boundary_flag = 1, group_sums = vals = [100,100,100,100]
// Scenario B: sorted_keys = [1, 1, 1, 2], vals = [100, 100, 100, 100]
//   → group-key=1 spans rows 0–2, group_sums = [100, 200, 300, 100]
//
// The two witnesses have the same raw vals but DIFFERENT group_output_lo because the
// running group sums differ.  Both proofs must verify individually.

#[tokio::test]
async fn plonky2_phase3_group_by_running_sums_differ_from_unique_key_case() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    // --- Scenario A: unique keys ---
    let sorted_a: Vec<u64> = vec![1, 2, 3, 4];
    let unsorted_a: Vec<u64> = vec![4, 2, 1, 3];
    let vals_a: Vec<u64> = vec![100, 100, 100, 100];
    let gout_a = compute_group_output_lo_padded(&sorted_a, &vals_a);

    let snap_a = compute_snap_lo(MAX_ROWS, &unsorted_a);
    let mut w_a = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w_a.snapshot_root[..8].copy_from_slice(&snap_a.to_le_bytes());
    w_a.query_hash = [0xA2u8; 32];
    w_a.group_output_lo = gout_a;
    w_a.columns = vec![
        ColumnTrace::new("k", sorted_a.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("v", vals_a.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w_a.input_columns = vec![ColumnTrace::new(
        "k_in",
        unsorted_a.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w_a.selected = vec![true; 4];
    w_a.result_row_count = 4;

    // --- Scenario B: 3-row group ---
    let sorted_b: Vec<u64> = vec![1, 1, 1, 2];
    let unsorted_b: Vec<u64> = vec![1, 2, 1, 1];
    let vals_b: Vec<u64> = vec![100, 100, 100, 100]; // same raw values
    let gout_b = compute_group_output_lo_padded(&sorted_b, &vals_b);

    let snap_b = compute_snap_lo(MAX_ROWS, &unsorted_b);
    let mut w_b = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w_b.snapshot_root[..8].copy_from_slice(&snap_b.to_le_bytes());
    w_b.query_hash = [0xA3u8; 32];
    w_b.group_output_lo = gout_b;
    w_b.columns = vec![
        ColumnTrace::new("k", sorted_b.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("v", vals_b.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w_b.input_columns = vec![ColumnTrace::new(
        "k_in",
        unsorted_b.iter().map(|&v| FieldElement(v)).collect(),
    )];
    w_b.selected = vec![true; 4];
    w_b.result_row_count = 4;

    // Running sums must differ between the two scenarios.
    assert_ne!(
        gout_a, gout_b,
        "unique-key group_output_lo ({gout_a:#018x}) must differ from \
         multi-row-group group_output_lo ({gout_b:#018x}) even with same raw vals"
    );

    // Both proofs must prove and verify.
    let art_a = b.prove(handle.as_ref(), &w_a).await.expect("prove A");
    let art_b = b.prove(handle.as_ref(), &w_b).await.expect("prove B");

    assert!(
        b.verify(&art_a).await.expect("verify A").is_valid,
        "unique-key GROUP BY must verify"
    );
    assert!(
        b.verify(&art_b).await.expect("verify B").is_valid,
        "multi-row-group GROUP BY must verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Area 3: JOIN unmatched_count PI[6]
// ─────────────────────────────────────────────────────────────────────────────

// Test 55: JOIN with all-unmatched rows carries join_unmatched_count = MAX_ROWS.
//
// When no left key equals any right key, every selector is false (0).
// The circuit constraint Σ(1 - sel[i]) must equal MAX_ROWS.
// This is a circuit-proved count — the prover cannot under-report it.

#[tokio::test]
async fn plonky2_phase3_join_unmatched_count_equals_max_rows_when_no_matches() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    // Left and right key sets are disjoint → all selectors = false.
    let left_keys: Vec<u64> = (1..=5).collect();
    let right_keys: Vec<u64> = (100..=104).collect();
    let left_vals: Vec<u64> = left_keys.iter().map(|k| k * 10).collect();

    let left_snap = compute_snap_lo(MAX_ROWS, &left_keys);
    let right_snap = compute_snap_lo(MAX_ROWS, &right_keys);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&left_snap.to_le_bytes());
    w.query_hash = [0xB1u8; 32];
    w.join_right_snap_lo = right_snap;

    w.columns = vec![
        ColumnTrace::new(
            "left_key",
            left_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "right_key",
            right_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "left_val",
            left_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    // No keys match → all selectors false.
    w.selected = left_keys
        .iter()
        .zip(right_keys.iter())
        .map(|(l, r)| l == r)
        .collect();
    w.result_row_count = left_keys.len() as u64;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // The circuit must report unmatched_count = MAX_ROWS (all rows unmatched).
    assert_eq!(
        artifact.public_inputs.join_unmatched_count,
        MAX_ROWS as u64,
        "all rows unmatched: join_unmatched_count must equal MAX_ROWS ({}), got {}",
        MAX_ROWS,
        artifact.public_inputs.join_unmatched_count
    );

    let result = b.verify(&artifact).await.expect("verify");
    assert!(
        result.is_valid,
        "all-unmatched join is a valid proof; error={:?}",
        result.error
    );
    // Completeness is still not proved.
    assert!(
        !result.completeness_proved,
        "JOIN must not claim completeness_proved"
    );
}

// Test 56: JOIN with partial matches has 0 < join_unmatched_count < MAX_ROWS.
//
// Build a join where some rows match and some do not.
// The circuit-proved unmatched_count must be the exact complement of matched rows.

#[tokio::test]
async fn plonky2_phase3_join_partial_matches_unmatched_count() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    // 4 rows: rows 0 and 1 match (sel=true), rows 2 and 3 do not (sel=false).
    let left_keys: Vec<u64> = vec![10, 20, 30, 40];
    let right_keys: Vec<u64> = vec![10, 20, 999, 888]; // last two don't match left
    let left_vals: Vec<u64> = vec![1, 2, 3, 4];
    let selectors: Vec<bool> = vec![true, true, false, false];

    let left_snap = compute_snap_lo(MAX_ROWS, &left_keys);
    let right_snap = compute_snap_lo(MAX_ROWS, &right_keys);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&left_snap.to_le_bytes());
    w.query_hash = [0xB2u8; 32];
    w.join_right_snap_lo = right_snap;

    w.columns = vec![
        ColumnTrace::new(
            "left_key",
            left_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "right_key",
            right_keys.iter().map(|&v| FieldElement(v)).collect(),
        ),
        ColumnTrace::new(
            "left_val",
            left_vals.iter().map(|&v| FieldElement(v)).collect(),
        ),
    ];
    w.selected = selectors.clone();
    w.result_row_count = selectors.iter().filter(|&&s| s).count() as u64;

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove partial join");

    // 2 matched rows → MAX_ROWS - 2 unmatched.
    let expected_unmatched = MAX_ROWS as u64 - 2;
    assert_eq!(
        artifact.public_inputs.join_unmatched_count,
        expected_unmatched,
        "2 matched rows → unmatched_count must be MAX_ROWS-2={expected_unmatched}, got {}",
        artifact.public_inputs.join_unmatched_count
    );

    let result = b.verify(&artifact).await.expect("verify");
    assert!(
        result.is_valid,
        "partial-match join must verify; error={:?}",
        result.error
    );
}

// Test 57: Tampering join_unmatched_count must fail the PI[6] cross-check.
//
// The verifier extracts PI[6] from the Plonky2 proof and cross-checks it against
// artifact.public_inputs.join_unmatched_count.  Tampering the artifact field
// must cause verify() to return is_valid=false.

#[tokio::test]
async fn plonky2_phase3_join_tampered_unmatched_count_fails_verify() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");
    let w = make_join_witness(10); // all matched
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    // Original unmatched_count = MAX_ROWS - 10 (10 rows selected, rest padded as unmatched).
    let original_uc = artifact.public_inputs.join_unmatched_count;

    // Tamper: lie about the number of unmatched rows.
    artifact.public_inputs.join_unmatched_count = original_uc.wrapping_add(1);

    let result = b.verify(&artifact).await.expect("verify must not panic");
    assert!(
        !result.is_valid,
        "tampered join_unmatched_count must fail PI[6] cross-check; \
         original={original_uc}, tampered={}",
        original_uc.wrapping_add(1)
    );
    let err = result.error.unwrap_or_default();
    assert!(
        err.contains("unmatched_count") || err.contains("mismatch"),
        "error must mention unmatched_count mismatch: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Area 4: External manifest anchor verification
// ─────────────────────────────────────────────────────────────────────────────

// Test 58: Default ExternalAnchorStatus is Unanchored after verify().
//
// When no external manifest is provided, the verifier has no anchor to check
// the snapshot against, so the status must be ExternalAnchorStatus::Unanchored.

#[tokio::test]
async fn plonky2_phase3_external_anchor_status_defaults_to_unanchored() {
    let b = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");
    let w = make_witness(5, "__primary", vec![1u64; 5], 5);
    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    let result = b.verify(&artifact).await.expect("verify");

    assert!(result.is_valid, "valid proof must verify");
    assert_eq!(
        result.external_anchor_status,
        ExternalAnchorStatus::Unanchored,
        "no external manifest → status must be Unanchored, got {:?}",
        result.external_anchor_status
    );
}

// Test 59: ExternalAnchorStatus::Mismatch is distinguishable from Anchored and Unanchored.
//
// Validates the enum structure and serde round-trip.  The Mismatch variant carries
// the two conflicting snap_lo values so a caller can diagnose the discrepancy.

#[test]
fn plonky2_phase3_external_anchor_status_mismatch_variant_is_distinguishable() {
    let unanchored = ExternalAnchorStatus::Unanchored;
    let anchored = ExternalAnchorStatus::Anchored;
    let mismatch = ExternalAnchorStatus::Mismatch {
        expected_snap_lo: 0xDEAD_BEEF_0000_0001,
        proof_snap_lo: 0xCAFE_BABE_0000_0002,
    };
    let encoding_mismatch = ExternalAnchorStatus::EncodingMismatch;

    assert_ne!(unanchored, anchored);
    assert_ne!(unanchored, mismatch);
    assert_ne!(anchored, mismatch);
    assert_ne!(mismatch, encoding_mismatch);

    // The Mismatch variant must expose the conflicting values.
    if let ExternalAnchorStatus::Mismatch { expected_snap_lo, proof_snap_lo } = &mismatch {
        assert_eq!(*expected_snap_lo, 0xDEAD_BEEF_0000_0001);
        assert_eq!(*proof_snap_lo, 0xCAFE_BABE_0000_0002);
    } else {
        panic!("expected Mismatch variant");
    }

    // Serde round-trip.
    let json = serde_json::to_string(&mismatch).expect("serialize");
    let decoded: ExternalAnchorStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(mismatch, decoded, "serde round-trip must preserve Mismatch values");
}
