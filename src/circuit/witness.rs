//! Witness trace types.
//!
//! A witness trace holds the concrete values that will be assigned to
//! circuit wires during proving. It is generated from chunk data before
//! the circuit is built.

use crate::field::FieldElement;
use crate::types::{QueryId, SnapshotId};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Column trace
// ─────────────────────────────────────────────────────────────────────────────

/// Witness values for a single column (one value per row in the chunk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnTrace {
    pub column_name: String,
    pub values: Vec<FieldElement>,
    /// Null bitmap (true = null, false = present). Empty if no nulls.
    pub nulls: Vec<bool>,
}

impl ColumnTrace {
    pub fn new(column_name: impl Into<String>, values: Vec<FieldElement>) -> Self {
        let len = values.len();
        Self {
            column_name: column_name.into(),
            values,
            nulls: vec![false; len],
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness trace
// ─────────────────────────────────────────────────────────────────────────────

/// All witness values for a single proving task over one or more chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessTrace {
    pub query_id: QueryId,
    pub snapshot_id: SnapshotId,
    /// Public inputs committed to in the proof.
    pub snapshot_root: [u8; 32],
    pub query_hash: [u8; 32],
    pub result_commitment: [u8; 32],
    pub result_row_count: u64,
    /// Per-column output traces (post-operator values, e.g. sorted output).
    pub columns: Vec<ColumnTrace>,
    /// Per-column input traces (pre-operator values, before any sort/transform).
    ///
    /// Populated by `WitnessBuilder` for operators that reorder rows (Sort,
    /// GroupBy). When non-empty, `SortCircuit` uses these to verify that the
    /// output `columns` are a valid permutation of the input (multiset equality).
    /// Empty for operators where input == output order (Scan, Filter, etc.).
    pub input_columns: Vec<ColumnTrace>,
    /// Selected row bitmap (true = row passes predicate / is included).
    pub selected: Vec<bool>,
    /// Intermediate aggregate values (for aggregate operators).
    pub aggregates: Vec<AggregateWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateWitness {
    pub column_name: String,
    pub kind: String,
    pub value: FieldElement,
    pub count: u64,
}

impl WitnessTrace {
    pub fn new(query_id: QueryId, snapshot_id: SnapshotId) -> Self {
        Self {
            query_id,
            snapshot_id,
            snapshot_root: [0u8; 32],
            query_hash: [0u8; 32],
            result_commitment: [0u8; 32],
            result_row_count: 0,
            columns: vec![],
            input_columns: vec![],
            selected: vec![],
            aggregates: vec![],
        }
    }

    /// Produce a deterministic byte sequence representing this witness,
    /// used as input to mock proving.
    pub fn proof_bytes_placeholder(&self) -> Vec<u8> {
        let json = serde_json::to_string(self).unwrap_or_default();
        let hash = *blake3::hash(json.as_bytes()).as_bytes();
        hash.to_vec()
    }

    pub fn row_count(&self) -> usize {
        self.columns.first().map(|c| c.len()).unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WitnessBuilder
// ─────────────────────────────────────────────────────────────────────────────

use crate::database::storage::StagedChunk;
use crate::proof::artifacts::PublicInputs;
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::ZkResult;

/// Builds a `WitnessTrace` from chunk data and a proof plan.
///
/// The witness is shaped to match what the root operator's circuit expects:
/// - For Sort operators: column values are sorted ascending so the circuit
///   constraint (output must be sorted) is satisfied.
/// - For GroupBy operators: column values are sorted by key (group-sort precondition).
/// - For all other operators: values are in chunk order (natural row order).
pub struct WitnessBuilder;

impl WitnessBuilder {
    pub fn build(
        query_id: QueryId,
        snapshot_id: SnapshotId,
        proof_plan: &ProofPlan,
        chunks: &[StagedChunk],
    ) -> ZkResult<WitnessTrace> {
        let mut trace = WitnessTrace::new(query_id, snapshot_id);

        // Set public inputs from plan
        trace.snapshot_root = *proof_plan.snapshot_root.as_bytes();
        trace.query_hash = PublicInputs::compute_query_hash(&proof_plan.query_id.to_string());

        // Build per-chunk column traces from raw bytes:
        // one column "row_bytes" with Blake3 hash of each row's bytes (u64 representation).
        let mut all_row_hashes: Vec<FieldElement> = Vec::new();
        let mut all_selected: Vec<bool> = Vec::new();
        let mut total_rows: u64 = 0;

        for chunk in chunks {
            for row_bytes in &chunk.row_bytes {
                let hash_bytes = *blake3::hash(row_bytes).as_bytes();
                // Pack first 8 bytes into a field element
                let fe_bytes: [u8; 8] = hash_bytes[..8].try_into().unwrap_or([0u8; 8]);
                all_row_hashes.push(FieldElement::from_canonical_bytes(fe_bytes));
                all_selected.push(true);
                total_rows += 1;
            }
        }

        // Inspect the root operator to determine if the witness column
        // needs to be pre-processed to satisfy circuit constraints.
        let root_op = Self::root_operator(proof_plan);
        match root_op {
            ProofOperator::Sort { .. } => {
                // SortCircuit requires output column to be sorted (ascending or descending).
                // Save pre-sort values as input_columns so SortCircuit can verify
                // multiset equality (output is a valid permutation of input).
                let pre_sort = all_row_hashes.clone();
                all_row_hashes.sort_by_key(|fe| fe.0);
                trace.input_columns = vec![ColumnTrace::new("__row_hash_input", pre_sort)];
            }
            ProofOperator::PartialAggregate { .. } | ProofOperator::MergeAggregate { .. } => {
                // GroupByCircuit requires key column to be sorted.
                // Save pre-sort values as input_columns for multiset verification.
                let pre_sort = all_row_hashes.clone();
                all_row_hashes.sort_by_key(|fe| fe.0);
                trace.input_columns = vec![ColumnTrace::new("__row_hash_input", pre_sort)];
            }
            _ => {
                // Other operators (Scan, Filter, Projection, etc.) have no ordering requirement.
                // input_columns stays empty — no reordering happened.
            }
        }

        trace.columns = vec![ColumnTrace::new("__row_hash", all_row_hashes)];
        trace.selected = all_selected;
        trace.result_row_count = total_rows;

        // Compute result_commitment = Blake3 of all selected row hashes (in order)
        let selected_bytes: Vec<u8> = trace
            .columns
            .iter()
            .flat_map(|c| {
                c.values
                    .iter()
                    .zip(trace.selected.iter())
                    .filter(|(_, &sel)| sel)
                    .flat_map(|(fe, _)| fe.to_canonical_bytes())
            })
            .collect();
        trace.result_commitment = *blake3::hash(&selected_bytes).as_bytes();

        Ok(trace)
    }

    /// Return the root operator of the proof plan.
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
}
