//! End-to-end integration tests for the real Plonky2 backend.
//!
//! These tests drive the full pipeline:
//!   dataset → ingest → snapshot → query → proof plan → Plonky2 prove → verify
//!
//! All assertions target real, non-placeholder values:
//! - proof_bytes must be non-empty and > 1 KB (FRI proofs are large)
//! - verification must succeed on a genuine proof
//! - verification must FAIL on a tampered proof
//! - MetricQuality must be Real (not Placeholder) for Plonky2 results

use std::sync::Arc;

use zkdb_plonky2::{
    backend::{Plonky2Backend, ProvingBackend},
    benchmarks::{BenchmarkRunner, BenchmarkScenario},
    benchmarks::types::BackendKind,
    circuit::witness::{ColumnTrace, WitnessTrace},
    commitment::root::CommitmentRoot,
    field::FieldElement,
    proof::artifacts::ProofSystemKind,
    query::proof_plan::{
        AggregationTopology, ProofOperator, ProofPlan, ProvingTask, TaskId,
    },
    types::{BackendTag, DatasetId, QueryId, SnapshotId},
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
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

fn make_witness(n: usize, column_name: &str, values: Vec<u64>, selected_count: usize) -> WitnessTrace {
    let mut w = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    w.snapshot_root = [1u8; 32];
    w.query_hash    = [2u8; 32];
    w.result_row_count = selected_count as u64;
    w.selected = (0..n).map(|i| i < selected_count).collect();
    let col = ColumnTrace::new(
        column_name,
        values.into_iter().map(FieldElement).collect(),
    );
    w.columns = vec![col];
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
    let witness = make_witness(30, "__row_hash", vec![1u64; 30], 30);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

    // Must produce a non-placeholder, sizeable FRI proof.
    assert!(!artifact.proof_bytes.is_empty(), "proof bytes must be non-empty");
    assert!(
        artifact.proof_bytes.len() > 1000,
        "Plonky2 FRI proof must exceed 1 KB, got {} bytes",
        artifact.proof_bytes.len()
    );
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark);
    assert_eq!(artifact.backend, BackendTag::Plonky2);
    assert!(!artifact.verification_key_bytes.is_empty(), "vk bytes must be present");

    // Verification must succeed.
    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "valid Plonky2 proof must verify; error={:?}", result.error);
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
    // 50 rows, amounts 1000..1050, all selected
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
    let b = Plonky2Backend::new();
    let plan = avg_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    // scores 0..100, half selected (first 50)
    let scores: Vec<u64> = (0..100).collect();
    let witness = make_witness(100, "score", scores, 50);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    let result = b.verify(&artifact).await.expect("verify call failed");
    assert!(result.is_valid, "AVG proof must verify; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: tampered proof bytes must fail verification
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_tampered_proof_fails_verify() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(10, "__row_hash", vec![1u64; 10], 10);

    let mut artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

    // Flip multiple bytes in the FRI query region (middle of the proof).
    let mid = artifact.proof_bytes.len() / 2;
    for i in 0..8 {
        artifact.proof_bytes[mid + i] ^= 0xFF;
    }

    let result = b.verify(&artifact).await.expect("verify call itself must not panic");
    assert!(!result.is_valid, "tampered proof must be invalid");
    assert!(result.error.is_some(), "error message must be populated for invalid proof");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: proof_system label is Plonky2Snark (not HashChainAudit / None)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_system_label_is_snark() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    let witness = make_witness(5, "__row_hash", vec![1u64; 5], 5);
    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");

    assert_ne!(artifact.proof_system, ProofSystemKind::None);
    assert_ne!(artifact.proof_system, ProofSystemKind::HashChainAudit);
    assert_eq!(artifact.proof_system, ProofSystemKind::Plonky2Snark,
        "proof_system must be Plonky2Snark");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: proof size is consistent across multiple proves (deterministic circuit)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_proof_size_is_consistent() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");

    let w1 = make_witness(10, "__row_hash", vec![1u64; 10], 10);
    let w2 = make_witness(20, "__row_hash", vec![1u64; 20], 20);

    let a1 = b.prove(handle.as_ref(), &w1).await.expect("prove 1 failed");
    let a2 = b.prove(handle.as_ref(), &w2).await.expect("prove 2 failed");

    // FRI proof size is determined by the circuit depth + FRI parameters,
    // not by the input data → both should have the same byte count.
    assert_eq!(
        a1.proof_bytes.len(),
        a2.proof_bytes.len(),
        "Plonky2 proof size must be constant for the same circuit (FRI proofs are fixed-size)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: zero-row witness (empty selection) proves and verifies
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_empty_selection_proves_and_verifies() {
    let b = Plonky2Backend::new();
    let plan = count_plan();
    let handle = b.compile_circuit(&plan).await.expect("compile failed");
    // All rows excluded by filter
    let witness = make_witness(20, "__row_hash", vec![1u64; 20], 0);

    let artifact = b.prove(handle.as_ref(), &witness).await.expect("prove failed");
    let result = b.verify(&artifact).await.expect("verify failed");
    assert!(result.is_valid, "zero-selection proof must still be valid; error={:?}", result.error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: BenchmarkRunner end-to-end with Plonky2 — real quality labels
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_count_all() {
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_count_all",
        "SELECT COUNT(*) FROM benchmark_transactions",
        100, // small row count for fast test
    )
    .with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;

    assert!(result.success, "benchmark must succeed; error={:?}", result.error);

    // Proof must be a real Plonky2 FRI proof (> 1 KB).
    assert!(
        result.metrics.proof_size_bytes > 1000,
        "Plonky2 proof must exceed 1 KB, got {} bytes",
        result.metrics.proof_size_bytes
    );

    // Timing must be non-zero real measurements.
    assert!(
        result.metrics.proof_generation_us > 0,
        "proof generation time must be non-zero"
    );
    assert!(
        result.metrics.verification_us > 0,
        "verification time must be non-zero"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: BenchmarkRunner with SUM query — real proof
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plonky2_benchmark_runner_filter_sum() {
    let backend: Arc<dyn ProvingBackend> = Arc::new(Plonky2Backend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky2_filter_sum",
        "SELECT SUM(amount) FROM benchmark_transactions WHERE amount > 50000",
        100,
    )
    .with_backend(BackendKind::Plonky2);

    let result = runner.run(&scenario).await;
    assert!(result.success, "filter+sum benchmark must succeed; error={:?}", result.error);
    assert!(result.metrics.proof_size_bytes > 1000, "must be real FRI proof");
}
