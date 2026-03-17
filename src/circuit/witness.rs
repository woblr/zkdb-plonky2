//! Witness trace types and builder.
//!
//! A witness trace holds the concrete values that will be assigned to
//! circuit wires during proving. It is generated from chunk data before
//! the circuit is built.
//!
//! ## Phase-3 changes
//!
//! `WitnessBuilder::build` now produces a **Poseidon-bound** witness:
//!
//! - `columns[0]` holds the *primary field element* of each row (first 8 bytes
//!   of `row_bytes` as a little-endian u64), **not** a Blake3 hash.
//! - `snapshot_root` is set to `poseidon_snapshot_root(all_row_bytes)` so it
//!   matches the `PI[0]` that the circuit constrains.  The old Blake3 root that
//!   came from the proof plan is **not** used — circuits prove against the
//!   Poseidon root, not against the Blake3 Merkle root.
//!
//! TODO (schema-aware decoding):
//!   A full implementation would take the `DatasetSchema` as a parameter and
//!   decode each `row_bytes` slice column-by-column according to `ColumnType`.
//!   The current approach packs the first 8 raw bytes of each row.  For
//!   datasets where the primary numeric column occupies bytes 0–7 this is
//!   exact; for other layouts it is an approximation.

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
    ///
    /// **Phase 3**: `snapshot_root` now holds the *Poseidon-based* commitment
    /// to the row data (first 8 bytes = `snap_lo` used as `PI[0]`).
    /// The Blake3 Merkle root is kept separately in the snapshot manifest.
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
    /// output `columns` are a valid permutation of the input (multiset equality
    /// via grand-product check in Phase 3).
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

use crate::commitment::poseidon::{
    poseidon_snapshot_root, row_primary_field_element,
};
use crate::database::storage::StagedChunk;
use crate::proof::artifacts::PublicInputs;
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::ZkResult;

/// Builds a `WitnessTrace` from chunk data and a proof plan.
///
/// ## Phase-3 semantics
///
/// - Row values are the *primary field element* of each row (first 8 raw bytes
///   as LE u64).  This is used for **both** column data and Poseidon binding.
/// - `snapshot_root` = `poseidon_snapshot_root(all_row_bytes)`.  The first 8
///   bytes of this value equal `snap_lo` = `Poseidon(padded_primary_fes)[0]`,
///   which the circuit constrains via `b.connect(hash_out.elements[0], PI[0])`.
/// - For Sort/GroupBy operators, the column is sorted **after** the primary
///   field elements are collected; the original order is kept in
///   `input_columns[0]` for the grand-product permutation check.
pub struct WitnessBuilder;

impl WitnessBuilder {
    pub fn build(
        query_id: QueryId,
        snapshot_id: SnapshotId,
        proof_plan: &ProofPlan,
        chunks: &[StagedChunk],
    ) -> ZkResult<WitnessTrace> {
        let mut trace = WitnessTrace::new(query_id, snapshot_id);

        // Set query_hash from plan
        trace.query_hash =
            PublicInputs::compute_query_hash(&proof_plan.query_id.to_string());

        // ── Step 1: collect all row bytes across all chunks ──────────────────
        let mut all_row_bytes: Vec<Vec<u8>> = Vec::new();
        for chunk in chunks {
            for row_bytes in &chunk.row_bytes {
                all_row_bytes.push(row_bytes.clone());
            }
        }

        // ── Step 2: extract primary field element for each row ───────────────
        //
        // Phase-3 uses the first 8 bytes of each row's canonical bytes as a
        // Goldilocks field element.  This represents the leading (typically
        // numeric) column.
        //
        // TODO: schema-aware decoding — accept a `DatasetSchema` parameter and
        // decode each column according to `ColumnType::fixed_byte_width()`.
        let all_primary_fes: Vec<u64> = all_row_bytes
            .iter()
            .map(|rb| row_primary_field_element(rb))
            .collect();

        let total_rows = all_primary_fes.len() as u64;

        // ── Step 3: compute Poseidon snapshot root ───────────────────────────
        //
        // This is what PI[0] (snap_lo) in the circuit is constrained to equal.
        // It is derived purely from the row data, not from the Blake3 Merkle
        // root in proof_plan.snapshot_root.
        trace.snapshot_root = poseidon_snapshot_root(&all_row_bytes);

        // ── Step 4: shape per-operator columns ───────────────────────────────
        let root_op = Self::root_operator(proof_plan);
        match root_op {
            ProofOperator::Sort { .. } => {
                // SortCircuit requires:
                //   - input_columns[0]  = pre-sort primary field elements
                //   - columns[0]        = post-sort (ascending)
                //
                // Grand-product check in circuit verifies that sorted output
                // is a permutation of the unsorted input.
                let pre_sort: Vec<FieldElement> =
                    all_primary_fes.iter().map(|&v| FieldElement(v)).collect();
                let mut sorted_vals = all_primary_fes.clone();
                sorted_vals.sort_unstable();
                let post_sort: Vec<FieldElement> =
                    sorted_vals.iter().map(|&v| FieldElement(v)).collect();

                trace.input_columns =
                    vec![ColumnTrace::new("__primary_in", pre_sort)];
                trace.columns = vec![ColumnTrace::new("__primary_out", post_sort)];
            }

            ProofOperator::PartialAggregate { .. }
            | ProofOperator::MergeAggregate { .. } => {
                // For GroupBy: sort keys for the circuit; keep original for
                // grand-product permutation check.
                let pre_sort: Vec<FieldElement> =
                    all_primary_fes.iter().map(|&v| FieldElement(v)).collect();
                let mut sorted_vals = all_primary_fes.clone();
                sorted_vals.sort_unstable();
                let post_sort: Vec<FieldElement> =
                    sorted_vals.iter().map(|&v| FieldElement(v)).collect();

                trace.input_columns =
                    vec![ColumnTrace::new("__primary_in", pre_sort)];
                trace.columns = vec![ColumnTrace::new("__primary_out", post_sort)];
            }

            _ => {
                // Scan, Filter, Projection, Limit, HashJoin, RecursiveFold:
                // no reordering needed.
                let fes: Vec<FieldElement> =
                    all_primary_fes.iter().map(|&v| FieldElement(v)).collect();
                trace.columns = vec![ColumnTrace::new("__primary", fes)];
            }
        }

        trace.selected = vec![true; all_row_bytes.len()];
        trace.result_row_count = total_rows;

        // ── Step 5: result_commitment ─────────────────────────────────────────
        //
        // Commit to (snapshot_root, query_hash, selected primary field elements).
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
