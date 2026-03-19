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
//! ## Schema-aware decoding
//!
//! When `proof_plan.schema_json` is present, column values are decoded from
//! the canonical row byte encoding using `circuit::decoder::decode_column_u64`.
//! The column used depends on `proof_plan.operator_params`:
//!   - Sort: `sort_column` (or first column / raw bytes as fallback)
//!   - GroupBy: `group_by_column` for keys, `agg_column` for vals
//!   - JOIN: `join_left_key` / `join_right_key` from schema
//!
//! ## DESC sort handling
//!
//! For DESC sorts, `WitnessBuilder` places values in truly descending order in
//! `out_vals`. This is passed to `DescSortCircuit` (TAG_DESC_SORT=4), which
//! constrains `out[i] = out[i+1] + diff[i]` (non-increasing monotonicity).
//! The `WitnessTrace.sort_descending` field is used by the backend to route
//! to the correct circuit. ASC and DESC produce cryptographically distinct
//! proofs with different VK tags — the verifier cannot swap them.

use crate::field::FieldElement;
use crate::types::{QueryId, SnapshotId, ZkDbError};
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
    /// Whether sort is descending (stored for proof plan metadata, not circuit-constrained).
    pub sort_descending: bool,
    /// Poseidon commitment over the grouped output relation.
    /// Must equal Poseidon(out_keys_padded ++ vals_padded ++ boundary_flags_padded)[0]
    /// using the same MAX_ROWS padding the GroupByCircuit applies.
    /// Exposed as PI[5] in GroupByCircuit — circuit-constrained.
    pub group_output_lo: u64,
    /// Poseidon(right_keys_padded)[0] — right-side binding for JoinCircuit PI[4].
    /// Circuit-constrained; must equal compute_snap_lo(MAX_ROWS, &right_keys).
    pub join_right_snap_lo: u64,
    /// Predicate operation code for AggCircuit: 0 = None, 1 = Eq.
    pub filter_op: u64,
    /// Predicate target value for AggCircuit.
    pub filter_val: u64,
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
            sort_descending: false,
            group_output_lo: 0,
            join_right_snap_lo: 0,
            filter_op: 0,
            filter_val: 0,
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

use crate::circuit::decoder::decode_column_u64;
use crate::commitment::poseidon::{
    bytes_to_field_elements, compute_snap_lo, row_primary_field_element, MAX_ROWS,
};
use plonky2::field::types::PrimeField64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use crate::database::schema::DatasetSchema;
use crate::database::storage::StagedChunk;
use crate::proof::artifacts::PublicInputs;
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::ZkResult;

/// Builds a `WitnessTrace` from chunk data and a proof plan.
///
/// ## Phase-3 semantics
///
/// - Row values are the *primary field element* of each row (first 8 raw bytes
///   as LE u64) OR schema-decoded column value if schema is available.
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
        trace.query_hash = PublicInputs::compute_query_hash(&proof_plan.query_id.to_string());

        // ── Step 1: collect all row bytes across all chunks ──────────────────
        let mut all_row_bytes: Vec<Vec<u8>> = Vec::new();
        for chunk in chunks {
            for row_bytes in &chunk.row_bytes {
                all_row_bytes.push(row_bytes.clone());
            }
        }

        // ── Step 2: parse schema if available ────────────────────────────────
        let schema: Option<DatasetSchema> = proof_plan
            .schema_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let params = &proof_plan.operator_params;

        let total_rows = all_row_bytes.len() as u64;

        // ── Step 3 + 4: extract operator-specific columns THEN compute snap_lo ─
        //
        // CRITICAL: snap_lo = PI[0] must equal Poseidon(binding_values_padded)[0].
        // The binding_values are the exact column values fed into the circuit's
        // private input array.  We must compute snap_lo from those values,
        // NOT from raw row_primary_field_element (which reads the 8-byte row_index
        // prefix, not actual column data).
        //
        // Order: extract operator-specific column → compute snap_lo from it.
        let root_op = Self::root_operator(proof_plan);
        match root_op {
            ProofOperator::Sort { .. } => {
                // Schema-aware extraction using sort_column
                let pre_sort_vals = extract_col(&all_row_bytes, &schema, &params.sort_column, 0)?;

                // snap_lo binds to in_vals (pre-sort) — same as SortCircuit / DescSortCircuit binding
                let snap_lo = compute_snap_lo(MAX_ROWS, &pre_sort_vals);

                trace.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());

                // Compute per-row secondary values via Poseidon(row_bytes)[0].
                //
                // This replaces the former Blake3(row_bytes)[..8] truncation.  The change
                // removes the external Blake3 dependency from the secondary fingerprint and
                // makes the hash function consistent with the rest of the circuit system
                // (all in-circuit hashes use Poseidon over the Goldilocks field).
                //
                // Compute per-row 128-bit fingerprints using BOTH Poseidon output elements:
                //   lo = Poseidon(row_fes)[0],  hi = Poseidon(row_fes)[1]
                //
                // The grand-product uses three independent challenges (r1, r2, r3) derived
                // from Poseidon(snap, qhash)[0..=2], giving ~128-bit collision resistance
                // for the payload binding (vs ~64-bit with a single element).
                let in_secondary_lo: Vec<u64>;
                let in_secondary_hi: Vec<u64>;
                {
                    let hashes: Vec<_> = all_row_bytes
                        .iter()
                        .map(|rb| {
                            let fes = bytes_to_field_elements(rb);
                            PoseidonHash::hash_no_pad(&fes)
                        })
                        .collect();
                    in_secondary_lo = hashes.iter().map(|h| h.elements[0].to_canonical_u64()).collect();
                    in_secondary_hi = hashes.iter().map(|h| h.elements[1].to_canonical_u64()).collect();
                }

                // Sort BOTH secondary halves with the same permutation as the sort keys.
                // Triple (key, sec_lo, sec_hi) — sort by key, keep both halves aligned.
                let mut triples: Vec<(u64, u64, u64)> = pre_sort_vals
                    .iter()
                    .copied()
                    .zip(in_secondary_lo.iter().copied())
                    .zip(in_secondary_hi.iter().copied())
                    .map(|((k, lo), hi)| (k, lo, hi))
                    .collect();
                if params.sort_descending {
                    triples.sort_by(|a, b| b.0.cmp(&a.0));
                } else {
                    triples.sort_by_key(|p| p.0);
                }
                let sorted_vals:     Vec<u64> = triples.iter().map(|t| t.0).collect();
                let out_secondary_lo: Vec<u64> = triples.iter().map(|t| t.1).collect();
                let out_secondary_hi: Vec<u64> = triples.iter().map(|t| t.2).collect();

                trace.sort_descending = params.sort_descending;

                let pre_sort: Vec<FieldElement>     = pre_sort_vals.iter().map(|&v| FieldElement(v)).collect();
                let post_sort: Vec<FieldElement>    = sorted_vals.iter().map(|&v| FieldElement(v)).collect();
                let in_lo_fes: Vec<FieldElement>    = in_secondary_lo.iter().map(|&v| FieldElement(v)).collect();
                let out_lo_fes: Vec<FieldElement>   = out_secondary_lo.iter().map(|&v| FieldElement(v)).collect();
                let in_hi_fes: Vec<FieldElement>    = in_secondary_hi.iter().map(|&v| FieldElement(v)).collect();
                let out_hi_fes: Vec<FieldElement>   = out_secondary_hi.iter().map(|&v| FieldElement(v)).collect();

                trace.input_columns = vec![
                    ColumnTrace::new("__primary_in",       pre_sort),
                    ColumnTrace::new("__secondary_in",     in_lo_fes),
                    ColumnTrace::new("__secondary_in_hi",  in_hi_fes),
                ];
                trace.columns = vec![
                    ColumnTrace::new("__primary_out",      post_sort),
                    ColumnTrace::new("__secondary_out",    out_lo_fes),
                    ColumnTrace::new("__secondary_out_hi", out_hi_fes),
                ];
            }

            ProofOperator::PartialAggregate { group_by_json, .. }
            | ProofOperator::MergeAggregate { group_by_json, .. } => {
                let is_group_by = group_by_json != "[]" && !group_by_json.trim().is_empty();

                if is_group_by {
                    // GroupByCircuit: binds to in_keys (pre-sort group-by column)
                    // group_by_column must be named; agg_column may be None for COUNT(*) —
                    // in that case fall back to the first schema column explicitly.
                    let agg_col_resolved: Option<String> = params
                        .agg_column
                        .clone()
                        .filter(|n| !n.is_empty())
                        .or_else(|| {
                            schema
                                .as_ref()
                                .and_then(|s| s.columns.first())
                                .map(|c| c.name.clone())
                        });
                    let pre_sort_keys =
                        extract_col(&all_row_bytes, &schema, &params.group_by_column, 0)?;
                    let vals = extract_col(&all_row_bytes, &schema, &agg_col_resolved, 0)?;

                    // snap_lo binds to in_keys — same as GroupByCircuit binding
                    let snap_lo = compute_snap_lo(MAX_ROWS, &pre_sort_keys);
    
                    trace.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());

                    let mut sorted_keys = pre_sort_keys.clone();
                    sorted_keys.sort_unstable();

                    let pre_sort: Vec<FieldElement> =
                        pre_sort_keys.iter().map(|&v| FieldElement(v)).collect();
                    let post_sort: Vec<FieldElement> =
                        sorted_keys.iter().map(|&v| FieldElement(v)).collect();
                    let val_fes: Vec<FieldElement> =
                        vals.iter().map(|&v| FieldElement(v)).collect();

                    trace.input_columns = vec![ColumnTrace::new("__primary_in", pre_sort)];
                    trace.columns = vec![
                        ColumnTrace::new("__primary_out", post_sort.clone()),
                        ColumnTrace::new("__vals", val_fes),
                    ];

                    // Compute group_output_lo = Poseidon over the circuit's padded arrays
                    let sorted_keys_u64: Vec<u64> = post_sort.iter().map(|fe| fe.0).collect();
                    trace.group_output_lo = compute_group_output_lo_padded(&sorted_keys_u64, &vals);
                } else {
                    // Plain aggregate (COUNT/SUM/AVG): AggCircuit binds to values.
                    //
                    // Effective column priority:
                    //   1. agg_column (SUM/AVG target — e.g. "salary")
                    //   2. filter_column (COUNT(*) WHERE col > val — filter col drives binding)
                    //   3. first schema column (COUNT(*) with no WHERE)
                    //
                    // This allows COUNT(*) WHERE amount > 50000 to work: the circuit
                    // runs the predicate over the `amount` column even though there is no
                    // explicit aggregation column.
                    let agg_col_resolved: Option<String> = params
                        .agg_column
                        .clone()
                        .filter(|n| !n.is_empty())
                        .or_else(|| params.filter_column.clone().filter(|n| !n.is_empty()))
                        .or_else(|| {
                            schema
                                .as_ref()
                                .and_then(|s| s.columns.first())
                                .map(|c| c.name.clone())
                        });
                    let fes_vals = extract_col(&all_row_bytes, &schema, &agg_col_resolved, 0)?;

                    // snap_lo binds to values — same as AggCircuit binding
                    let snap_lo = compute_snap_lo(MAX_ROWS, &fes_vals);
    
                    trace.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());

                    if let Some(fc) = &params.filter_column {
                        // The filter column must match the effective binding column.
                        // SUM(salary) WHERE dept='X' is rejected (different columns).
                        // COUNT(*) WHERE amount>50000 is allowed (filter col IS the binding col).
                        let binding_col = agg_col_resolved.as_deref().unwrap_or("");
                        if binding_col != fc.as_str() {
                            return Err(crate::types::ZkDbError::internal(format!(
                                "Filter column '{}' must match aggregation column '{:?}' in this zkDB prototype. \
                                 Cross-column filter (e.g. SUM(salary) WHERE dept=X) is not yet supported.",
                                fc, params.agg_column
                            )));
                        }
                        match params.filter_op.as_deref() {
                            Some("eq") => trace.filter_op = 1,
                            Some("lt") => trace.filter_op = 2,
                            Some("gt") => trace.filter_op = 3,
                            _ => {}
                        }
                        trace.filter_val = params.filter_value.unwrap_or(0);
                    }

                    let fes: Vec<FieldElement> =
                        fes_vals.iter().map(|&v| FieldElement(v)).collect();
                    trace.columns = vec![ColumnTrace::new("__primary", fes)];

                    let mut selected = vec![true; all_row_bytes.len()];
                    match trace.filter_op {
                        1 => {
                            // Eq: selector[i] = (values[i] == pred_val)
                            for (i, v) in fes_vals.iter().enumerate() {
                                selected[i] = *v == trace.filter_val;
                            }
                        }
                        2 => {
                            // Lt: selector[i] = (values[i] < pred_val)
                            for (i, v) in fes_vals.iter().enumerate() {
                                selected[i] = *v < trace.filter_val;
                            }
                        }
                        3 => {
                            // Gt: selector[i] = (values[i] > pred_val)
                            for (i, v) in fes_vals.iter().enumerate() {
                                selected[i] = *v > trace.filter_val;
                            }
                        }
                        _ => {} // filter_op=0 (None): all rows selected (default)
                    }
                    trace.selected = selected;
                }
            }

            ProofOperator::HashJoin { .. } => {
                // Schema-aware JOIN witness building.
                // join_left_key and join_right_key must be named (compile_circuit enforces this).
                // join_left_val_column may be None — resolve to first schema column explicitly.
                let left_val_col_resolved: Option<String> = params
                    .join_left_val_column
                    .clone()
                    .filter(|n| !n.is_empty())
                    .or_else(|| {
                        schema
                            .as_ref()
                            .and_then(|s| s.columns.first())
                            .map(|c| c.name.clone())
                    });
                let left_keys = extract_col(&all_row_bytes, &schema, &params.join_left_key, 0)?;
                let right_keys = extract_col(&all_row_bytes, &schema, &params.join_right_key, 1)?;
                let left_vals =
                    extract_col(&all_row_bytes, &schema, &left_val_col_resolved, 0)?;

                // snap_lo binds to left_keys — same as JoinCircuit left binding
                let snap_lo = compute_snap_lo(MAX_ROWS, &left_keys);

                trace.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());

                // right_snap_lo binds to right_keys — JoinCircuit PI[4]
                let right_snap_lo = compute_snap_lo(MAX_ROWS, &right_keys);

                // CRITICAL CROSS-CHECK: If the plan specifies an expected right-side commitment, enforce it here.
                // This anchors the right table to the manifest, preventing the prover from using arbitrary data.
                if params.join_right_poseidon_snap_lo != 0
                    && right_snap_lo != params.join_right_poseidon_snap_lo
                {
                    return Err(ZkDbError::internal(format!(
                        "right-side commitment mismatch: expected {:#018x}, computed {:#018x}",
                        params.join_right_poseidon_snap_lo, right_snap_lo
                    )));
                }

                trace.join_right_snap_lo = right_snap_lo;

                let lk_fes: Vec<FieldElement> =
                    left_keys.iter().map(|&v| FieldElement(v)).collect();
                let rk_fes: Vec<FieldElement> =
                    right_keys.iter().map(|&v| FieldElement(v)).collect();
                let lv_fes: Vec<FieldElement> =
                    left_vals.iter().map(|&v| FieldElement(v)).collect();

                trace.columns = vec![
                    ColumnTrace::new("left_key", lk_fes),
                    ColumnTrace::new("right_key", rk_fes),
                    ColumnTrace::new("left_val", lv_fes),
                ];
                // Selectors: rows where left_key == right_key
                trace.selected = left_keys
                    .iter()
                    .zip(right_keys.iter())
                    .map(|(lk, rk)| lk == rk)
                    .collect();
            }

            _ => {
                // Scan, Filter, Projection, Limit, RecursiveFold:
                // AggCircuit path — bind to first column values.
                // Resolve the first schema column explicitly rather than passing None.
                let first_col_name: Option<String> = schema
                    .as_ref()
                    .and_then(|s| s.columns.first())
                    .map(|c| c.name.clone());
                let fes_vals = extract_col(&all_row_bytes, &schema, &first_col_name, 0)?;

                // snap_lo binds to values — same as AggCircuit binding
                let snap_lo = compute_snap_lo(MAX_ROWS, &fes_vals);

                trace.snapshot_root[..8].copy_from_slice(&snap_lo.to_le_bytes());

                let fes: Vec<FieldElement> = fes_vals.iter().map(|&v| FieldElement(v)).collect();
                trace.columns = vec![ColumnTrace::new("__primary", fes)];
                trace.selected = vec![true; all_row_bytes.len()];
            }
        }

        // Ensure selected is populated for non-HashJoin cases
        if trace.selected.is_empty() {
            trace.selected = vec![true; all_row_bytes.len()];
        }
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
                    .zip(trace.selected.iter().chain(std::iter::repeat(&true)))
                    .filter(|(_, &sel)| sel)
                    .flat_map(|(fe, _)| fe.to_canonical_bytes().to_vec())
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

/// Extract u64 field-element values for a named column from row bytes.
///
/// `col_name` MUST be `Some(non-empty string)` when `schema` is `Some`.
/// Callers are responsible for resolving any default/fallback column name
/// BEFORE calling this function.  Passing `None` when a schema is available
/// is a hard error — silent fallback columns were a soundness gap where an
/// operator could bind to the wrong column without any indication.
///
/// The `_fallback_col` parameter is retained only for backward-compatible
/// call-site signatures; it is no longer used when schema is present.
pub fn extract_col(
    all_row_bytes: &[Vec<u8>],
    schema: &Option<DatasetSchema>,
    col_name: &Option<String>,
    _fallback_col: usize,
) -> ZkResult<Vec<u64>> {
    if let Some(schema) = schema.as_ref() {
        if let Some(name) = col_name.as_ref().filter(|n| !n.is_empty()) {
            return Ok(all_row_bytes
                .iter()
                .map(|rb| decode_column_u64(rb, schema, name).unwrap_or(0))
                .collect());
        }
        // No silent fallback: require an explicit column name when schema is present.
        return Err(crate::types::ZkDbError::internal(
            "extract_col: operator requires an explicit column name but none was provided. \
             Callers must resolve the column name (e.g. first schema column for COUNT(*)) \
             before calling extract_col — silent fallback columns were removed to prevent \
             the prover from binding to the wrong column without any error.",
        ));
    }

    // Fallback mode strictly for when NO schema is given (i.e. tests/debug without schema).
    Ok(all_row_bytes
        .iter()
        .map(|rb| row_primary_field_element(rb))
        .collect())
}


/// Compute group_output_lo using the same padding and encoding as GroupByCircuit.
///
/// GroupByCircuit pads out_keys, group_sums, and vals to MAX_ROWS (zeros at FRONT),
/// and boundary_flags to MAX_ROWS-1.  We replicate that here so the
/// off-circuit value matches PI[5] from the circuit.
///
/// ## Phase-3 change: running group sums instead of raw per-row values
///
/// PI[5] = Poseidon(out_keys_padded ++ group_sums_padded ++ boundary_flags_padded)[0]
///
/// `group_sums[i]` is the running aggregate sum within the group ending at row i:
/// - `group_sums[0] = vals[0]`
/// - `group_sums[i] = (1 - boundary_flag[i-1]) * group_sums[i-1] + vals[i]`
///   (resets at each group boundary, accumulates within a group)
///
/// This makes PI[5] commit to per-group output aggregates rather than raw per-row values.
///
/// Inputs: sorted_keys and vals are the unpadded (actual row count) slices.
pub fn compute_group_output_lo_padded(sorted_keys: &[u64], vals: &[u64]) -> u64 {
    use crate::commitment::poseidon::MAX_ROWS;

    let n_valid = sorted_keys.len().min(MAX_ROWS);
    let n_pad = MAX_ROWS - n_valid;

    // Build padded out_keys (zeros at front, real values at back)
    let mut out_keys_padded = vec![0u64; MAX_ROWS];
    for i in 0..n_valid {
        out_keys_padded[n_pad + i] = sorted_keys[i];
    }

    // Build padded vals (same front-padding scheme)
    let mut vals_padded = vec![0u64; MAX_ROWS];
    for i in 0..n_valid {
        let v = if i < vals.len() { vals[i] } else { 0 };
        vals_padded[n_pad + i] = v;
    }

    // Build boundary_flags (MAX_ROWS - 1): flag[i] = 1 iff out_keys_padded[i+1] > out_keys_padded[i]
    let bf_len = MAX_ROWS - 1;
    let mut boundary_flags = vec![0u64; bf_len];
    for i in 0..bf_len {
        let d = out_keys_padded[i + 1].saturating_sub(out_keys_padded[i]);
        boundary_flags[i] = if d > 0 { 1 } else { 0 };
    }

    // Build running group sums (matches GroupByCircuit constraint):
    //   group_sum[0] = vals[0]
    //   group_sum[i] = (1 - flag[i-1]) * group_sum[i-1] + vals[i]
    // Uses wrapping_add to proxy Goldilocks field addition for large values.
    let mut group_sums = vec![0u64; MAX_ROWS];
    group_sums[0] = vals_padded[0];
    for i in 1..MAX_ROWS {
        let f = boundary_flags[i - 1];
        group_sums[i] = if f == 0 {
            group_sums[i - 1].wrapping_add(vals_padded[i])
        } else {
            vals_padded[i]
        };
    }

    // Concatenate: out_keys_padded ++ group_sums_padded ++ boundary_flags
    let total = MAX_ROWS + MAX_ROWS + bf_len;
    let mut group_vec: Vec<u64> = Vec::with_capacity(total);
    group_vec.extend_from_slice(&out_keys_padded);
    group_vec.extend_from_slice(&group_sums);
    group_vec.extend_from_slice(&boundary_flags);

    compute_snap_lo(total, &group_vec)
}
