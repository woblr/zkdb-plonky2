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
    benchmarks::{BenchmarkRunner, BenchmarkScenario},
    benchmarks::types::BackendKind,
    circuit::witness::{ColumnTrace, WitnessTrace},
    commitment::{
        poseidon::compute_snap_lo,
        root::CommitmentRoot,
    },
    field::FieldElement,
    proof::artifacts::ProofSystemKind,
    query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
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
    }
}

fn sort_plan() -> ProofPlan {
    let tid = TaskId::new();
    ProofPlan {
        query_id: QueryId::new(), snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(), snapshot_root: CommitmentRoot::zero(),
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
    }
}

fn group_by_plan() -> ProofPlan {
    let tid = TaskId::new();
    ProofPlan {
        query_id: QueryId::new(), snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(), snapshot_root: CommitmentRoot::zero(),
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
    }
}

fn join_plan() -> ProofPlan {
    let tid = TaskId::new();
    ProofPlan {
        query_id: QueryId::new(), snapshot_id: SnapshotId::new(),
        dataset_id: DatasetId::new(), snapshot_root: CommitmentRoot::zero(),
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
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an AggCircuit witness.
///
/// `snap_lo` is set to `compute_snap_lo(MAX_ROWS, &values_zero_padded)` so
/// the Poseidon binding constraint passes.
fn make_witness(n: usize, column_name: &str, values: Vec<u64>, selected_count: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    // AggCircuit binds to col[0] values — snap_lo = Poseidon(values_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &values);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];
    w.result_row_count = selected_count as u64;
    w.selected = (0..n).map(|i| i < selected_count).collect();
    let col = ColumnTrace::new(
        column_name,
        values.into_iter().map(FieldElement).collect(),
    );
    w.columns = vec![col];
    w
}

/// Build a SortCircuit witness.
///
/// `snap_lo` = Poseidon(in_vals_padded)[0]  (bound to PRE-SORT values)
fn make_sort_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let sorted:   Vec<u64> = (0..n as u64).collect();
    let unsorted: Vec<u64> = (0..n as u64).rev().collect();

    // SortCircuit binds to in_vals — snap_lo = Poseidon(in_vals_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &unsorted);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [2u8; 32];

    w.columns       = vec![ColumnTrace::new("amount", sorted.iter().map(|&v| FieldElement(v)).collect())];
    w.input_columns = vec![ColumnTrace::new("amount_in", unsorted.iter().map(|&v| FieldElement(v)).collect())];
    w.selected      = vec![true; n];
    w.result_row_count = n as u64;
    w
}

/// Build a GroupByCircuit witness.
///
/// `snap_lo` = Poseidon(in_keys_padded)[0]  (bound to PRE-SORT keys)
fn make_group_by_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let sorted_keys:   Vec<u64> = (0..n as u64).collect();
    let unsorted_keys: Vec<u64> = (0..n as u64).rev().collect();
    let vals:          Vec<u64> = (0..n as u64).map(|i| i * 100).collect();

    // GroupByCircuit binds to in_keys — snap_lo = Poseidon(in_keys_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &unsorted_keys);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [4u8; 32];

    w.columns       = vec![
        ColumnTrace::new("dept",   sorted_keys.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("salary", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.input_columns = vec![ColumnTrace::new("dept_in", unsorted_keys.iter().map(|&v| FieldElement(v)).collect())];
    w.selected      = vec![true; n];
    w.result_row_count = n as u64;
    w
}

/// Build a JoinCircuit witness.
///
/// `snap_lo` = Poseidon(left_keys_padded)[0]
fn make_join_witness(n: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());

    let keys: Vec<u64> = (0..n as u64).collect();
    let vals: Vec<u64> = (0..n as u64).map(|i| i * 10).collect();

    // JoinCircuit binds to left_keys — snap_lo = Poseidon(left_keys_padded)[0]
    let snap_lo = compute_snap_lo(MAX_ROWS, &keys);
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash = [6u8; 32];

    w.columns  = vec![
        ColumnTrace::new("left_key",  keys.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("right_key", keys.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("left_val",  vals.iter().map(|&v| FieldElement(v)).collect()),
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
    let b      = Plonky2Backend::new();
    let plan   = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(30, "__primary", vec![1u64; 30], 30);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

    assert!(!artifact.proof_bytes.is_empty(), "proof bytes must be non-empty");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "Plonky2 FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    assert_eq!(artifact.backend, BackendTag::Plonky2);
    assert!(!artifact.verification_key_bytes.is_empty(), "vk bytes must be present");

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "valid Plonky2 proof must verify; error={:?}", result.error);
    assert_eq!(result.proof_system, ProofSystemKind::Plonky2Snark);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: SUM proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_sum_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let plan   = sum_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let amounts: Vec<u64> = (1000..1050).collect();
    let witness = make_witness(50, "amount", amounts, 50);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    assert!(artifact.proof_bytes.len() > 1000, "proof must be sizeable");

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "SUM proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: AVG proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_avg_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let plan   = avg_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let scores: Vec<u64> = (0..100).collect();
    let witness = make_witness(100, "score", scores, 50);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    let result   = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "AVG proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: tampered proof bytes must fail verification
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_tampered_proof_fails_verify() {
    let b      = Plonky2Backend::new();
    let plan   = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(10, "__primary", vec![1u64; 10], 10);

    let mut artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    let mid = artifact.proof_bytes.len() / 2;
    for i in 0..8 { artifact.proof_bytes[mid + i] ^= 0xFF; }

    let result = b.verify(&artifact).await.expect("verify call must not panic");
    assert!(!result.is_valid, "tampered proof must be invalid");
    assert!(result.error.is_some(), "error message must be populated");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: proof_system label is Plonky2Snark
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_system_label_is_snark() {
    let b      = Plonky2Backend::new();
    let plan   = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(5, "__primary", vec![1u64; 5], 5);
    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

    assert_ne!(artifact.proof_system, ProofSystemKind::None);
    assert_ne!(artifact.proof_system, ProofSystemKind::HashChainAudit);
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: proof size is consistent across multiple proves
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_size_is_consistent() {
    let b      = Plonky2Backend::new();
    let plan   = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");

    let w1 = make_witness(10, "__primary", vec![1u64; 10], 10);
    let w2 = make_witness(20, "__primary", vec![2u64; 20], 20);

    let a1 = b.prove(handle.as_ref(), &w1).await.expect("prove 1 failed");
    let a2 = b.prove(handle.as_ref(), &w2).await.expect("prove 2 failed");

    assert_eq!(
        a1.proof_bytes.len(), a2.proof_bytes.len(),
        "Plonky2 proof size must be constant for the same circuit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: zero-row witness proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_empty_selection_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let plan   = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    // All rows excluded; values are zeros — snap_lo = Poseidon(zeros)[0]
    let witness = make_witness(20, "__primary", vec![1u64; 20], 0);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    let result   = b.verify(&artifact).await.expect("verify failed");
    assert!(result.is_valid, "zero-selection proof must still be valid; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: BenchmarkRunner end-to-end with Plonky2
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_count_all() {
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner  = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_count_all",
        "SELECT COUNT(*) FROM benchmark_transactions",
        100,
    ).with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;
    assert!(result.success, "benchmark must succeed; error={:?}", result.error);
    assert!(result.metrics.proof_size_bytes > 1000,
        "Plonky2 proof must exceed 1 KB, got {} bytes", result.metrics.proof_size_bytes);
    assert!(result.metrics.proof_generation_us > 0, "prove time must be non-zero");
    assert!(result.metrics.verification_us > 0, "verify time must be non-zero");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: BenchmarkRunner with SUM query
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_filter_sum() {
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner  = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_filter_sum",
        "SELECT SUM(amount) FROM benchmark_transactions WHERE amount > 50000",
        100,
    ).with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;
    assert!(result.success, "filter+sum benchmark must succeed; error={:?}", result.error);
    assert!(result.metrics.proof_size_bytes > 1000, "must be real FRI proof");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: SortCircuit (ORDER BY) proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile failed");
    let w      = make_sort_witness(30);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(artifact.proof_bytes.len() > 1000,
        "SortCircuit FRI proof must exceed 1 KB, got {} bytes", artifact.proof_bytes.len());
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    assert_eq!(artifact.backend, BackendTag::Plonky2);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "ORDER BY proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: SortCircuit — tampered proof fails
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_tampered_fails() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    let w      = make_sort_witness(10);
    let mut artifact = b.prove(handle.as_ref(), &w).await.expect("prove");

    let mid = artifact.proof_bytes.len() / 2;
    for i in 0..8 { artifact.proof_bytes[mid + i] ^= 0xFF; }

    let result = b.verify(&artifact).await.expect("verify call must not panic");
    assert!(!result.is_valid, "tampered ORDER BY proof must be invalid");
    assert!(result.error.is_some(), "error message must be populated");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: SortCircuit — empty input (zero rows)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_order_by_empty_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");
    let w      = make_sort_witness(0);
    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove");
    let result   = b.verify(&artifact).await.expect("verify call");
    assert!(result.is_valid, "empty ORDER BY proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: GroupByCircuit proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_group_by_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile failed");
    let w      = make_group_by_witness(25);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(artifact.proof_bytes.len() > 1000,
        "GroupByCircuit FRI proof must exceed 1 KB, got {} bytes", artifact.proof_bytes.len());
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "GROUP BY proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: JoinCircuit proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_join_proves_and_verifies() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile failed");
    let w      = make_join_witness(20);

    let artifact = b.prove(handle.as_ref(), &w).await.expect("prove failed");
    assert!(artifact.proof_bytes.len() > 1000,
        "JoinCircuit FRI proof must exceed 1 KB, got {} bytes", artifact.proof_bytes.len());
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);

    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "JOIN proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: All circuits produce Plonky2Snark label
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_all_circuits_produce_snark_label() {
    let b = Plonky2Backend::new();

    for (plan, witness, name) in [
        (sort_plan(),     make_sort_witness(5),     "ORDER BY"),
        (group_by_plan(), make_group_by_witness(5), "GROUP BY"),
        (join_plan(),     make_join_witness(5),     "JOIN"),
    ] {
        let handle   = b.compile_circuit(&plan).await.expect("compile");
        let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove");
        assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark,
            "{name}: proof_system must be Plonky2Snark");
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
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&count_plan()).await.expect("compile");

    let mut w = make_witness(10, "__primary", vec![42u64; 10], 10);
    // Corrupt snap_lo — the circuit Poseidon binding will reject this.
    w.snapshot_root = [0xABu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "AggCircuit must reject witness with wrong snap_lo");
}

/// Test 17: SortCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_sort_wrong_snap_lo_fails_prove() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    let mut w = make_sort_witness(5);
    // Zero out snapshot_root — wrong snap_lo for the in_vals.
    w.snapshot_root = [0u8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "SortCircuit must reject witness with wrong snap_lo");
}

/// Test 18: GroupByCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_group_by_wrong_snap_lo_fails_prove() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    let mut w = make_group_by_witness(5);
    w.snapshot_root = [0xFFu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "GroupByCircuit must reject witness with wrong snap_lo");
}

/// Test 19: JoinCircuit with wrong snap_lo must fail to prove.
#[tokio::test]
async fn plonky2_join_wrong_snap_lo_fails_prove() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&join_plan()).await.expect("compile");

    let mut w = make_join_witness(5);
    w.snapshot_root = [0xCCu8; 32];

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "JoinCircuit must reject witness with wrong snap_lo");
}

/// Test 20: SortCircuit with non-permutation out_vals must fail.
///
/// [1,2,3] → [1,2,4] is not a valid ORDER BY result; the grand-product
/// permutation check must reject it with overwhelming probability.
#[tokio::test]
async fn plonky2_sort_non_permutation_fails_prove() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&sort_plan()).await.expect("compile");

    let in_vals:  Vec<u64> = vec![1, 2, 3];
    let out_vals_bad: Vec<u64> = vec![1, 2, 4]; // NOT a permutation of {1,2,3}
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_vals);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash    = [2u8; 32];
    w.columns       = vec![ColumnTrace::new("out", out_vals_bad.iter().map(|&v| FieldElement(v)).collect())];
    w.input_columns = vec![ColumnTrace::new("in",  in_vals.iter().map(|&v| FieldElement(v)).collect())];
    w.selected      = vec![true; 3];
    w.result_row_count = 3;

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "SortCircuit must reject non-permutation out_vals (grand-product fails)");
}

/// Test 21: GroupByCircuit with non-permutation out_keys must fail.
#[tokio::test]
async fn plonky2_group_by_non_permutation_fails_prove() {
    let b      = Plonky2Backend::new();
    let handle = b.compile_circuit(&group_by_plan()).await.expect("compile");

    let in_keys:  Vec<u64> = vec![3, 1, 2];
    let out_keys_bad: Vec<u64> = vec![1, 2, 5]; // NOT a permutation
    let vals:     Vec<u64> = vec![10, 20, 30];
    let snap_lo = compute_snap_lo(MAX_ROWS, &in_keys);

    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    w.query_hash    = [4u8; 32];
    w.columns       = vec![
        ColumnTrace::new("dept",   out_keys_bad.iter().map(|&v| FieldElement(v)).collect()),
        ColumnTrace::new("salary", vals.iter().map(|&v| FieldElement(v)).collect()),
    ];
    w.input_columns = vec![ColumnTrace::new("dept_in", in_keys.iter().map(|&v| FieldElement(v)).collect())];
    w.selected      = vec![true; 3];
    w.result_row_count = 3;

    let result = b.prove(handle.as_ref(), &w).await;
    assert!(result.is_err(), "GroupByCircuit must reject non-permutation out_keys (grand-product fails)");
}
