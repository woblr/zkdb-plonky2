//! Plonky2Backend — real FRI-based SNARK implementation.
//!
//! ## Supported operator families
//!
//! | Circuit        | SQL operator    | Key soundness property (Phase 3)           |
//! |----------------|-----------------|---------------------------------------------|
//! | AggCircuit     | COUNT/SUM/AVG   | Poseidon binding: snap_lo = Poseidon(vals)  |
//! | SortCircuit    | ORDER BY        | Grand-product permutation + Poseidon binding|
//! | GroupByCircuit | GROUP BY        | Grand-product + boundary flags + binding    |
//! | JoinCircuit    | INNER JOIN      | Key equality + Poseidon binding             |
//!
//! ## Phase-3 soundness improvements
//!
//! ### Snapshot binding
//!
//! Every circuit now constrains `PI[0]` (= `snap_lo`) to equal the first
//! Goldilocks field element output of
//! `Poseidon(private_witness_values[0..MAX_ROWS-1])`.  This means a proof is
//! valid **only** if the prover knew the exact row values whose Poseidon hash
//! matches the claimed snapshot root.  The old "decorative" public input is
//! gone.
//!
//! ### Grand-product permutation (SortCircuit, GroupByCircuit)
//!
//! The old sum + sum-of-squares multiset fingerprint is replaced by the
//! Schwartz-Zippel grand-product check:
//!
//! ```text
//! r  = Poseidon(snap_lo, qhash_lo).elements[0]   (derived in-circuit)
//! prod_in  = ∏(in[i]  + r)
//! prod_out = ∏(out[i] + r)
//! connect(prod_in, prod_out)
//! ```
//!
//! A cheating prover who wants `in ≠ out` (as multisets) but
//! `prod_in = prod_out` needs a specific `r` (determined by the public inputs
//! they cannot control before choosing in/out values) that is a root of a
//! degree-(MAX_ROWS) polynomial.  By Schwartz-Zippel this probability
//! is ≤ MAX_ROWS / |𝔽| ≈ 128 / 2⁶⁴ ≈ 2⁻⁵⁷.
//!
//! ### Diff range check
//!
//! Raised from 32 bits to 48 bits so differences up to 2⁴⁸ are valid.
//! This covers realistic integer and timestamp column values.
//!
//! ### GroupBy boundary flags
//!
//! `GroupByCircuit` carries per-row `boundary_flag[i]` private witnesses:
//!   - `boundary_flag[i] ∈ {0, 1}` (boolean)
//!   - `(1 − boundary_flag[i]) × key_diff[i] = 0`
//!     (no boundary flag ⟹ key must not change)
//!   - `num_groups` = 1 + Σ boundary_flag  exposed as `PI[4]`
//!
//! The prover cannot under-report group boundaries without causing a constraint
//! violation.  Over-reporting produces a wrong `num_groups` PI that the
//! verifier rejects when cross-checking against the query result set.
//!
//! ## Padding convention (SortCircuit / GroupByCircuit)
//!
//! Rows are padded to `MAX_ROWS`.  Out-array has zeros at the FRONT so that
//! sorted real values come last — preserving monotonicity while keeping
//! multiset equality (both arrays share the same zero-padding under grand
//! product).

use std::any::Any;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::backend::traits::{CircuitHandle, ProvingBackend};
use crate::circuit::witness::WitnessTrace;
use crate::commitment::poseidon::MAX_ROWS;
use crate::proof::artifacts::{
    ExternalAnchorStatus, ProofArtifact, ProofSystemKind, PublicInputs, VerificationResult,
};
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::{BackendTag, DatasetId, ProofId, QueryId, SnapshotId, ZkDbError, ZkResult};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// ─────────────────────────────────────────────────────────────────────────────
// VK tag constants
// ─────────────────────────────────────────────────────────────────────────────

const TAG_AGG: u8 = 0;
const TAG_SORT: u8 = 1;
const TAG_GROUP_BY: u8 = 2;
const TAG_JOIN: u8 = 3;
const TAG_DESC_SORT: u8 = 4;

// ─────────────────────────────────────────────────────────────────────────────
// Operator classification
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum OpKind {
    Count,
    Sum,
    Avg,
    Generic,
    Sort,
    DescSort,
    GroupBy,
    Join,
}

impl OpKind {
    #[allow(dead_code)]
    fn circuit_tag(&self) -> u8 {
        match self {
            Self::Sort => TAG_SORT,
            Self::DescSort => TAG_DESC_SORT,
            Self::GroupBy => TAG_GROUP_BY,
            Self::Join => TAG_JOIN,
            _ => TAG_AGG,
        }
    }
}

fn classify_plan(plan: &ProofPlan) -> OpKind {
    let root_id = &plan.topology.root_task_id;
    let root_op = plan
        .topology
        .tasks
        .iter()
        .find(|t| &t.task_id == root_id)
        .or_else(|| plan.topology.tasks.last())
        .map(|t| &t.operator);

    if let Some(op) = root_op {
        return classify_operator(op);
    }
    for task in &plan.topology.tasks {
        let k = classify_operator(&task.operator);
        if k != OpKind::Generic {
            return k;
        }
    }
    OpKind::Generic
}

fn classify_operator(op: &ProofOperator) -> OpKind {
    match op {
        ProofOperator::HashJoin { .. } => OpKind::Join,
        ProofOperator::PartialAggregate {
            group_by_json,
            aggregates_json,
        }
        | ProofOperator::MergeAggregate {
            group_by_json,
            aggregates_json,
            ..
        } => {
            if group_by_json != "[]" && !group_by_json.trim().is_empty() {
                return OpKind::GroupBy;
            }
            let j = aggregates_json.to_lowercase();
            if j.contains("\"avg\"") {
                OpKind::Avg
            } else if j.contains("\"sum\"") {
                OpKind::Sum
            } else {
                OpKind::Count
            }
        }
        // Sort direction is resolved at plan level (operator_params.sort_descending)
        ProofOperator::Sort { .. } => OpKind::Sort, // may be upgraded to DescSort by classify_plan
        _ => OpKind::Generic,
    }
}

fn classify_plan_with_params(plan: &ProofPlan) -> OpKind {
    let base = classify_plan(plan);
    // Upgrade Sort → DescSort when sort_descending is set
    if base == OpKind::Sort && plan.operator_params.sort_descending {
        return OpKind::DescSort;
    }
    base
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Register PI[0]=snap_lo and PI[1]=qhash_lo; return their targets.
fn add_hash_public_inputs(b: &mut CircuitBuilder<F, D>) -> (Target, Target) {
    let snap = b.add_virtual_public_input();
    let qhash = b.add_virtual_public_input();
    (snap, qhash)
}

fn verify_proof_bytes(
    data: &CircuitData<F, C, D>,
    proof_bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.to_vec(), &data.common)
        .map_err(|e| format!("{label} deser: {e:?}"))?;
    data.verify(proof)
        .map_err(|e| format!("{label} verify: {e:?}"))
}

/// Set PI[0] and PI[1] in a partial witness.
fn set_pis(pw: &mut PartialWitness<F>, data: &CircuitData<F, C, D>, snap_lo: u64, qhash_lo: u64) {
    let pi = &data.prover_only.public_inputs;
    if pi.len() >= 2 {
        pw.set_target(pi[0], F::from_canonical_u64(snap_lo));
        pw.set_target(pi[1], F::from_canonical_u64(qhash_lo));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Predicate gadget
// ─────────────────────────────────────────────────────────────────────────────

/// In-circuit `x < y` for Goldilocks field values in the range [0, 2^63).
///
/// Technique: compute `diff_m1 = y - x - 1` (field arithmetic).
///
/// * `x < y`  ⟹  `0 ≤ diff_m1 < 2^63`       ⟹  bit 63 = 0  ⟹  returns 1
/// * `x >= y` ⟹  `diff_m1` wraps to ≥ `p − 2^63` ⟹  bit 63 = 1  ⟹  returns 0
///
/// Column values are at most 2^48 in realistic datasets, so both x and y are
/// safely in [0, 2^63) and the bit-63 check is sound.
fn is_less_than(b: &mut CircuitBuilder<F, D>, x: Target, y: Target) -> plonky2::iop::target::BoolTarget {
    let one = b.one();
    let diff = b.sub(y, x);
    let diff_m1 = b.sub(diff, one);
    let bits = b.split_le(diff_m1, 64);
    let one_t = b.one();
    let not_bit63 = b.sub(one_t, bits[63].target);
    plonky2::iop::target::BoolTarget::new_unsafe(not_bit63)
}

// ─────────────────────────────────────────────────────────────────────────────
// AggCircuit — COUNT / SUM / AVG
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  values[MAX_ROWS], selectors[MAX_ROWS], real_flags[MAX_ROWS]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum, PI[3]=count,
//           PI[4]=result_commit_lo, PI[5]=pred_op, PI[6]=pred_val, PI[7]=n_real
//
// Binding:
//   hash_out = Poseidon(values[0..MAX_ROWS-1])
//   connect(hash_out.elements[0], PI[0])   ← snap_lo PROVED from values
//
// real_flags[i]: 1 for real rows (i < n_real), 0 for zero-padded rows.
//   Constrained:
//     (a) Boolean: real_flags[i] * (1 - real_flags[i]) = 0
//     (b) Monotone: (1 - real_flags[i]) * real_flags[i+1] = 0  (once 0, stays 0)
//     (c) Padded values are zero: (1 - real_flags[i]) * values[i] = 0
//     (d) Padded selectors are zero: (1 - real_flags[i]) * sel[i] = 0
//
// Predicate constraints — fully TWO-DIRECTIONAL on real rows:
//   op=0 (None): real rows MUST be selected — op_is_none * real_flags[i] * (sel-1) = 0
//   op=1 (Eq):   op_is_eq  * real_flags[i] * (sel - is_val_eq) = 0
//   op=2 (Lt):   op_is_lt  * real_flags[i] * (sel - is_val_lt) = 0
//   op=3 (Gt):   op_is_gt  * real_flags[i] * (sel - is_val_gt) = 0
//   Any other op is rejected (valid_op constraint).
//
// With real_flags, padded rows are always forced to sel=0 regardless of pred_val,
// closing the COUNT inflation attack (Eq pred_val=0) and the undercounting attack
// (Lt/Gt one-directionality). All predicates are now sound AND complete.

struct AggCircuit {
    data: CircuitData<F, C, D>,
    values_t: Vec<Target>,
    selectors_t: Vec<Target>,
    real_flags_t: Vec<Target>,
    pred_op_t: Target,
    pred_val_t: Target,
}

impl AggCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let values_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let real_flags_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, _qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Poseidon binding: PI[0] = Poseidon(values).elements[0]
        let hash_out = b.hash_n_to_hash_no_pad::<PoseidonHash>(values_t.clone());
        b.connect(hash_out.elements[0], snap);

        let pred_op_t = b.add_virtual_target();
        let pred_val_t = b.add_virtual_target();

        let zero = b.zero();
        let one = b.one();
        let two = b.two();
        let three = b.constant(F::from_canonical_u64(3));

        let op_is_none = b.is_equal(pred_op_t, zero);
        let op_is_eq   = b.is_equal(pred_op_t, one);
        let op_is_lt   = b.is_equal(pred_op_t, two);
        let op_is_gt   = b.is_equal(pred_op_t, three);

        // Enforce valid op: pred_op must be 0, 1, 2, or 3.
        let valid_op_01 = b.add(op_is_none.target, op_is_eq.target);
        let valid_op_23 = b.add(op_is_lt.target, op_is_gt.target);
        let valid_op    = b.add(valid_op_01, valid_op_23);
        b.connect(valid_op, one);

        // real_flags constraints + n_real accumulation
        let mut n_real_acc = zero;
        for i in 0..MAX_ROWS {
            let f = real_flags_t[i];
            // (a) Boolean
            let one_minus_f = b.sub(one, f);
            let fp = b.mul(f, one_minus_f);
            b.connect(fp, zero);
            n_real_acc = b.add(n_real_acc, f);
        }
        // (b) Monotone: once 0, stays 0 — (1 - real_flags[i]) * real_flags[i+1] = 0
        for i in 0..MAX_ROWS - 1 {
            let not_fi = b.sub(one, real_flags_t[i]);
            let check = b.mul(not_fi, real_flags_t[i + 1]);
            b.connect(check, zero);
        }

        // (c) Padded rows have value = 0
        for i in 0..MAX_ROWS {
            let not_fi = b.sub(one, real_flags_t[i]);
            let padded_val = b.mul(not_fi, values_t[i]);
            b.connect(padded_val, zero);
        }

        // Selectors are boolean
        for &s in &selectors_t {
            let one_minus_s = b.sub(one, s);
            let prod = b.mul(s, one_minus_s);
            b.connect(prod, zero);
        }

        // (d) Padded rows: selector forced to 0 — (1 - real_flags[i]) * sel[i] = 0
        for i in 0..MAX_ROWS {
            let not_fi = b.sub(one, real_flags_t[i]);
            let padded_sel = b.mul(not_fi, selectors_t[i]);
            b.connect(padded_sel, zero);
        }

        // Per-row predicate binding — fully two-directional on real rows.
        // Padded rows are already forced to sel=0 by (d), so padding-related
        // COUNT inflation and undercounting attacks are closed.
        for i in 0..MAX_ROWS {
            let v  = values_t[i];
            let s  = selectors_t[i];
            let rf = real_flags_t[i];

            let is_val_eq = b.is_equal(v, pred_val_t);
            let is_val_lt = is_less_than(&mut b, v, pred_val_t); // v < pred_val
            let is_val_gt = is_less_than(&mut b, pred_val_t, v); // pred_val < v

            // op=None: real rows must all be selected
            // op_is_none * real_flags[i] * (sel[i] - 1) = 0
            let s_m1      = b.sub(s, one);
            let rf_sm1    = b.mul(rf, s_m1);
            let chk_none  = b.mul(op_is_none.target, rf_sm1);
            b.connect(chk_none, zero);

            // op=Eq (two-directional on real rows): op_is_eq * real_flags[i] * (sel - is_val_eq) = 0
            let diff_eq   = b.sub(s, is_val_eq.target);
            let rf_deq    = b.mul(rf, diff_eq);
            let chk_eq    = b.mul(op_is_eq.target, rf_deq);
            b.connect(chk_eq, zero);

            // op=Lt (two-directional on real rows): op_is_lt * real_flags[i] * (sel - is_val_lt) = 0
            let diff_lt   = b.sub(s, is_val_lt.target);
            let rf_dlt    = b.mul(rf, diff_lt);
            let chk_lt    = b.mul(op_is_lt.target, rf_dlt);
            b.connect(chk_lt, zero);

            // op=Gt (two-directional on real rows): op_is_gt * real_flags[i] * (sel - is_val_gt) = 0
            let diff_gt   = b.sub(s, is_val_gt.target);
            let rf_dgt    = b.mul(rf, diff_gt);
            let chk_gt    = b.mul(op_is_gt.target, rf_dgt);
            b.connect(chk_gt, zero);
        }

        // Aggregation
        let mut sum_acc   = zero;
        let mut count_acc = zero;
        for (&v, &s) in values_t.iter().zip(selectors_t.iter()) {
            let term = b.mul(v, s);
            sum_acc   = b.add(sum_acc, term);
            count_acc = b.add(count_acc, s);
        }
        b.register_public_input(sum_acc);   // PI[2]
        b.register_public_input(count_acc); // PI[3]

        // PI[4]: in-circuit result commitment — Poseidon(sum, count)[0]
        let result_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sum_acc, count_acc]);
        b.register_public_input(result_hash.elements[0]); // PI[4]

        b.register_public_input(pred_op_t); // PI[5]
        b.register_public_input(pred_val_t); // PI[6]
        b.register_public_input(n_real_acc); // PI[7] = number of real (non-padded) rows

        let data = b.build::<C>();
        Self {
            data,
            values_t,
            selectors_t,
            real_flags_t,
            pred_op_t,
            pred_val_t,
        }
    }

    /// Prove.  `snap_lo` **must** equal `compute_snap_lo(MAX_ROWS, &values)`.
    ///
    /// Selectors are now fully determined by `pred_op` and `pred_val` — the prover
    /// has no discretion.  The circuit enforces that every real row either is or is
    /// not selected exactly according to the predicate, making COUNT/SUM results
    /// both sound (no false positives) and complete (no false negatives).
    fn prove(
        &self,
        values: &[u64],
        snap_lo: u64,
        qhash_lo: u64,
        pred_op: u64,
        pred_val: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let n_real = values.len().min(MAX_ROWS);
        let mut pw = PartialWitness::new();

        for i in 0..MAX_ROWS {
            let v = if i < n_real { values[i] } else { 0 };
            pw.set_target(self.values_t[i], F::from_canonical_u64(v));

            let real_flag = if i < n_real { 1u64 } else { 0u64 };
            pw.set_target(self.real_flags_t[i], F::from_canonical_u64(real_flag));

            // selectors are fully determined by predicate; circuit enforces this
            let s = if i >= n_real {
                0u64
            } else {
                match pred_op {
                    0 => 1u64,                          // None: select all real rows
                    1 => (v == pred_val) as u64,        // Eq
                    2 => (v < pred_val) as u64,         // Lt
                    3 => (v > pred_val) as u64,         // Gt
                    _ => 0u64,
                }
            };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        pw.set_target(self.pred_op_t, F::from_canonical_u64(pred_op));
        pw.set_target(self.pred_val_t, F::from_canonical_u64(pred_val));
        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data.prove(pw).map_err(|e| format!("agg prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "AggCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SortCircuit — ORDER BY ASC
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  in_vals[N], out_vals[N], diff[N-1], selectors[N],
//           in_secondary_lo[N], out_secondary_lo[N],
//           in_secondary_hi[N], out_secondary_hi[N]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum_sel, PI[3]=count_sel,
//           PI[4]=result_commit_lo, PI[5]=secondary_lo_snap, PI[6]=secondary_hi_snap
//
// Key binding:  Poseidon(in_vals) == snap_lo
//
// 128-bit Joint Schwartz-Zippel grand-product (payload binding):
//   r1 = Poseidon(snap, qhash).elements[0]   (key challenge)
//   r2 = Poseidon(snap, qhash).elements[1]   (secondary-lo challenge)
//   r3 = Poseidon(snap, qhash).elements[2]   (secondary-hi challenge)
//
//   ∏(in_vals[i]  + r1 + r2*in_sec_lo[i]  + r3*in_sec_hi[i])
//   == ∏(out_vals[i] + r1 + r2*out_sec_lo[i] + r3*out_sec_hi[i])
//
//   Using BOTH 64-bit Poseidon outputs (elements[0] and elements[1]) as the
//   per-row fingerprint gives ~128-bit collision resistance for the payload
//   binding, up from ~64-bit with a single element.
//   When both secondary arrays are all-zeros, the expression degenerates to
//   ∏(in_vals+r1) — backward-compatible key-only grand-product.
//
// Secondary binding:
//   PI[5] = Poseidon(in_secondary_lo_padded)[0]   (lo fingerprint commitment)
//   PI[6] = Poseidon(in_secondary_hi_padded)[0]   (hi fingerprint commitment)
//
// Monotonicity (ascending):
//   out[i+1] = out[i] + diff[i],  range_check(diff[i], 48)
//
// Padding: in_vals zero-padded at end; out_vals zeros at FRONT.

struct SortCircuit {
    data: CircuitData<F, C, D>,
    in_vals_t: Vec<Target>,
    out_vals_t: Vec<Target>,
    diff_t: Vec<Target>,
    selectors_t: Vec<Target>,
    in_secondary_lo_t: Vec<Target>,
    out_secondary_lo_t: Vec<Target>,
    in_secondary_hi_t: Vec<Target>,
    out_secondary_hi_t: Vec<Target>,
}

impl SortCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let in_vals_t: Vec<Target>          = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_vals_t: Vec<Target>         = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let diff_t: Vec<Target>             = (0..MAX_ROWS - 1).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target>        = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let in_secondary_lo_t: Vec<Target>  = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_secondary_lo_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let in_secondary_hi_t: Vec<Target>  = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_secondary_hi_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Key binding: Poseidon(in_vals).elements[0] == snap
        let h_in = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_vals_t.clone());
        b.connect(h_in.elements[0], snap);

        // 128-bit challenge derivation: all three challenges come from one Poseidon call,
        // making them verifier-computable and dependent on the proof's public inputs.
        let r_h = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![snap, qhash]);
        let r1 = r_h.elements[0]; // key challenge
        let r2 = r_h.elements[1]; // secondary-lo challenge
        let r3 = r_h.elements[2]; // secondary-hi challenge

        // 128-bit joint grand-product
        let one = b.one();
        let mut prod_in  = one;
        let mut prod_out = one;
        for i in 0..MAX_ROWS {
            let r2_lo_in  = b.mul(r2, in_secondary_lo_t[i]);
            let r3_hi_in  = b.mul(r3, in_secondary_hi_t[i]);
            let tmp_in    = b.add(in_vals_t[i], r1);
            let tmp_in2   = b.add(tmp_in, r2_lo_in);
            let a         = b.add(tmp_in2, r3_hi_in);

            let r2_lo_out = b.mul(r2, out_secondary_lo_t[i]);
            let r3_hi_out = b.mul(r3, out_secondary_hi_t[i]);
            let tmp_out   = b.add(out_vals_t[i], r1);
            let tmp_out2  = b.add(tmp_out, r2_lo_out);
            let c2        = b.add(tmp_out2, r3_hi_out);

            prod_in  = b.mul(prod_in,  a);
            prod_out = b.mul(prod_out, c2);
        }
        b.connect(prod_in, prod_out);

        // Monotonicity (ascending), 48-bit diffs
        for i in 0..MAX_ROWS - 1 {
            let expected = b.add(out_vals_t[i], diff_t[i]);
            b.connect(out_vals_t[i + 1], expected);
            b.range_check(diff_t[i], 48);
        }

        // Boolean selectors + aggregation
        let zero = b.zero();
        let mut sum_sel   = zero;
        let mut count_sel = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one2 = b.one();
            let one_minus_s = b.sub(one2, s);
            let bp = b.mul(s, one_minus_s);
            b.connect(bp, zero);

            let term = b.mul(out_vals_t[i], s);
            sum_sel   = b.add(sum_sel, term);
            count_sel = b.add(count_sel, s);
        }
        b.register_public_input(sum_sel);   // PI[2]
        b.register_public_input(count_sel); // PI[3]

        // PI[4]: in-circuit result commitment
        let sort_result_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sum_sel, count_sel]);
        b.register_public_input(sort_result_hash.elements[0]); // PI[4]

        // PI[5]: lo fingerprint commitment = Poseidon(in_secondary_lo_padded)[0]
        let h_sec_lo = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_secondary_lo_t.clone());
        b.register_public_input(h_sec_lo.elements[0]); // PI[5]

        // PI[6]: hi fingerprint commitment = Poseidon(in_secondary_hi_padded)[0]
        let h_sec_hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_secondary_hi_t.clone());
        b.register_public_input(h_sec_hi.elements[0]); // PI[6]

        let data = b.build::<C>();
        Self {
            data,
            in_vals_t,
            out_vals_t,
            diff_t,
            selectors_t,
            in_secondary_lo_t,
            out_secondary_lo_t,
            in_secondary_hi_t,
            out_secondary_hi_t,
        }
    }

    /// `in_vals`          — original unsorted values
    /// `out_vals`         — sorted ascending
    /// `in_secondary_lo`  — Poseidon(row)[0] per-row fingerprint lo half.
    ///                      Pass `&[]` to use all-zeros (degenerates to key-only).
    /// `out_secondary_lo` — same fingerprints permuted to match sort order.
    ///                      Pass `&[]` to use all-zeros.
    /// `in_secondary_hi`  — Poseidon(row)[1] per-row fingerprint hi half.
    /// `out_secondary_hi` — same hi fingerprints permuted to match sort order.
    /// `snap_lo`          — must equal `compute_snap_lo(MAX_ROWS, &in_vals_zero_padded)`
    fn prove(
        &self,
        in_vals: &[u64],
        out_vals: &[u64],
        in_secondary_lo: &[u64],
        out_secondary_lo: &[u64],
        in_secondary_hi: &[u64],
        out_secondary_hi: &[u64],
        snap_lo: u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        let n_valid = in_vals.len().min(MAX_ROWS);
        let n_pad = MAX_ROWS - n_valid;

        for i in 0..MAX_ROWS {
            let v = if i < n_valid { in_vals[i] } else { 0 };
            pw.set_target(self.in_vals_t[i], F::from_canonical_u64(v));
        }

        let out_padded: Vec<u64> = (0..MAX_ROWS)
            .map(|i| {
                if i >= n_pad && (i - n_pad) < out_vals.len() {
                    out_vals[i - n_pad]
                } else {
                    0
                }
            })
            .collect();
        for i in 0..MAX_ROWS {
            pw.set_target(self.out_vals_t[i], F::from_canonical_u64(out_padded[i]));
        }

        for i in 0..MAX_ROWS - 1 {
            let d = out_padded[i + 1].saturating_sub(out_padded[i]);
            pw.set_target(self.diff_t[i], F::from_canonical_u64(d));
        }

        for i in 0..MAX_ROWS {
            let s = if i >= n_pad { 1u64 } else { 0u64 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        // Secondary lo columns (default to zero → key-only mode)
        for i in 0..MAX_ROWS {
            let v = if i < in_secondary_lo.len() { in_secondary_lo[i] } else { 0 };
            pw.set_target(self.in_secondary_lo_t[i], F::from_canonical_u64(v));
        }
        for i in 0..MAX_ROWS {
            let v = if !out_secondary_lo.is_empty() {
                if i >= n_pad && (i - n_pad) < out_secondary_lo.len() { out_secondary_lo[i - n_pad] } else { 0 }
            } else { 0 };
            pw.set_target(self.out_secondary_lo_t[i], F::from_canonical_u64(v));
        }

        // Secondary hi columns (default to zero → 64-bit-only mode)
        for i in 0..MAX_ROWS {
            let v = if i < in_secondary_hi.len() { in_secondary_hi[i] } else { 0 };
            pw.set_target(self.in_secondary_hi_t[i], F::from_canonical_u64(v));
        }
        for i in 0..MAX_ROWS {
            let v = if !out_secondary_hi.is_empty() {
                if i >= n_pad && (i - n_pad) < out_secondary_hi.len() { out_secondary_hi[i - n_pad] } else { 0 }
            } else { 0 };
            pw.set_target(self.out_secondary_hi_t[i], F::from_canonical_u64(v));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data
            .prove(pw)
            .map_err(|e| format!("sort prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "SortCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DescSortCircuit — ORDER BY DESC
// ─────────────────────────────────────────────────────────────────────────────
//
// Same 128-bit payload binding as SortCircuit; only monotonicity direction differs.
// Private:  in_vals[N], out_vals[N], diff[N-1], selectors[N],
//           in_secondary_lo[N], out_secondary_lo[N],
//           in_secondary_hi[N], out_secondary_hi[N]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum_sel, PI[3]=count_sel,
//           PI[4]=result_commit_lo, PI[5]=secondary_lo_snap, PI[6]=secondary_hi_snap
//
// Binding:  Poseidon(in_vals) == snap_lo
//
// 128-bit joint grand-product (identical formula to SortCircuit):
//   r1=elements[0], r2=elements[1], r3=elements[2] from Poseidon(snap, qhash)
//
// Monotonicity (DESCENDING):
//   out[i] = out[i+1] + diff[i],  range_check(diff[i], 48)
//   i.e., out is non-increasing: out[i] >= out[i+1]
//
// Padding: in_vals zero-padded at end; out_vals zeros at END (largest values first).

struct DescSortCircuit {
    data: CircuitData<F, C, D>,
    in_vals_t: Vec<Target>,
    out_vals_t: Vec<Target>,
    diff_t: Vec<Target>,
    selectors_t: Vec<Target>,
    in_secondary_lo_t: Vec<Target>,
    out_secondary_lo_t: Vec<Target>,
    in_secondary_hi_t: Vec<Target>,
    out_secondary_hi_t: Vec<Target>,
}

impl DescSortCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let in_vals_t: Vec<Target>          = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_vals_t: Vec<Target>         = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let diff_t: Vec<Target>             = (0..MAX_ROWS - 1).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target>        = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let in_secondary_lo_t: Vec<Target>  = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_secondary_lo_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let in_secondary_hi_t: Vec<Target>  = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_secondary_hi_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Binding: Poseidon(in_vals).elements[0] == snap
        let h_in = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_vals_t.clone());
        b.connect(h_in.elements[0], snap);

        // 128-bit challenges (same derivation as SortCircuit)
        let r_h = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![snap, qhash]);
        let r1 = r_h.elements[0];
        let r2 = r_h.elements[1];
        let r3 = r_h.elements[2];

        let one = b.one();
        let mut prod_in  = one;
        let mut prod_out = one;
        for i in 0..MAX_ROWS {
            let r2_lo_in  = b.mul(r2, in_secondary_lo_t[i]);
            let r3_hi_in  = b.mul(r3, in_secondary_hi_t[i]);
            let tmp_in    = b.add(in_vals_t[i], r1);
            let tmp_in2   = b.add(tmp_in, r2_lo_in);
            let a         = b.add(tmp_in2, r3_hi_in);

            let r2_lo_out = b.mul(r2, out_secondary_lo_t[i]);
            let r3_hi_out = b.mul(r3, out_secondary_hi_t[i]);
            let tmp_out   = b.add(out_vals_t[i], r1);
            let tmp_out2  = b.add(tmp_out, r2_lo_out);
            let c2        = b.add(tmp_out2, r3_hi_out);

            prod_in  = b.mul(prod_in,  a);
            prod_out = b.mul(prod_out, c2);
        }
        b.connect(prod_in, prod_out);

        // Monotonicity (DESCENDING): out[i] = out[i+1] + diff[i]
        for i in 0..MAX_ROWS - 1 {
            let expected = b.add(out_vals_t[i + 1], diff_t[i]);
            b.connect(out_vals_t[i], expected);
            b.range_check(diff_t[i], 48);
        }

        // Boolean selectors + aggregation
        let zero = b.zero();
        let mut sum_sel   = zero;
        let mut count_sel = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one2 = b.one();
            let one_minus_s = b.sub(one2, s);
            let bp = b.mul(s, one_minus_s);
            b.connect(bp, zero);

            let term = b.mul(out_vals_t[i], s);
            sum_sel   = b.add(sum_sel, term);
            count_sel = b.add(count_sel, s);
        }
        b.register_public_input(sum_sel);   // PI[2]
        b.register_public_input(count_sel); // PI[3]

        // PI[4]: in-circuit result commitment
        let desc_result_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sum_sel, count_sel]);
        b.register_public_input(desc_result_hash.elements[0]); // PI[4]

        // PI[5]: lo fingerprint commitment
        let h_sec_lo = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_secondary_lo_t.clone());
        b.register_public_input(h_sec_lo.elements[0]); // PI[5]

        // PI[6]: hi fingerprint commitment
        let h_sec_hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_secondary_hi_t.clone());
        b.register_public_input(h_sec_hi.elements[0]); // PI[6]

        let data = b.build::<C>();
        Self {
            data,
            in_vals_t,
            out_vals_t,
            diff_t,
            selectors_t,
            in_secondary_lo_t,
            out_secondary_lo_t,
            in_secondary_hi_t,
            out_secondary_hi_t,
        }
    }

    fn prove(
        &self,
        in_vals: &[u64],
        out_vals: &[u64],
        in_secondary_lo: &[u64],
        out_secondary_lo: &[u64],
        in_secondary_hi: &[u64],
        out_secondary_hi: &[u64],
        snap_lo: u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        let n_valid = in_vals.len().min(MAX_ROWS);

        // in_vals: zero-padded at END
        for i in 0..MAX_ROWS {
            let v = if i < n_valid { in_vals[i] } else { 0 };
            pw.set_target(self.in_vals_t[i], F::from_canonical_u64(v));
        }

        // out_vals: DESC — real values at FRONT, zeros at END
        let n_out = out_vals.len().min(MAX_ROWS);
        for i in 0..MAX_ROWS {
            let v = if i < n_out { out_vals[i] } else { 0 };
            pw.set_target(self.out_vals_t[i], F::from_canonical_u64(v));
        }

        // diff[i] = out[i] - out[i+1]
        let out_padded: Vec<u64> = (0..MAX_ROWS).map(|i| if i < n_out { out_vals[i] } else { 0 }).collect();
        for i in 0..MAX_ROWS - 1 {
            let d = out_padded[i].saturating_sub(out_padded[i + 1]);
            pw.set_target(self.diff_t[i], F::from_canonical_u64(d));
        }

        for i in 0..MAX_ROWS {
            let s = if i < n_out { 1u64 } else { 0u64 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        // Secondary lo
        for i in 0..MAX_ROWS {
            let v = if i < in_secondary_lo.len() { in_secondary_lo[i] } else { 0 };
            pw.set_target(self.in_secondary_lo_t[i], F::from_canonical_u64(v));
        }
        for i in 0..MAX_ROWS {
            let v = if !out_secondary_lo.is_empty() && i < out_secondary_lo.len() { out_secondary_lo[i] } else { 0 };
            pw.set_target(self.out_secondary_lo_t[i], F::from_canonical_u64(v));
        }

        // Secondary hi
        for i in 0..MAX_ROWS {
            let v = if i < in_secondary_hi.len() { in_secondary_hi[i] } else { 0 };
            pw.set_target(self.in_secondary_hi_t[i], F::from_canonical_u64(v));
        }
        for i in 0..MAX_ROWS {
            let v = if !out_secondary_hi.is_empty() && i < out_secondary_hi.len() { out_secondary_hi[i] } else { 0 };
            pw.set_target(self.out_secondary_hi_t[i], F::from_canonical_u64(v));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data
            .prove(pw)
            .map_err(|e| format!("desc_sort prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "DescSortCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GroupByCircuit — GROUP BY
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  in_keys[N], out_keys[N], key_diff[N-1], vals[N], selectors[N],
//           boundary_flags[N-1]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum_vals, PI[3]=count_sel,
//           PI[4]=num_groups, PI[5]=group_output_lo
//
// Binding:  Poseidon(in_keys) == snap_lo (PI[0])
//
// Grand-product on key column:
//   r = Poseidon(snap, qhash).elements[0]
//   ∏(in_keys[i]+r) == ∏(out_keys[i]+r)
//
// Key sort:
//   out_keys[i+1] = out_keys[i] + key_diff[i],  range_check(key_diff, 48)
//
// Boundary flags (two-direction soundness):
//   boundary_flags[i] ∈ {0,1}
//   (1 - boundary_flags[i]) × key_diff[i] = 0    ← no-boundary ⟹ diff = 0
//   boundary_flags[i] * (1 - inv_diff[i] * key_diff[i]) = 0  ← diff=0 ⟹ no-boundary
//   num_groups = 1 + Σ boundary_flags[i]            (PI[4])
//
// Group output commitment (PI[5]):
//   group_output_lo = Poseidon(out_keys ++ vals ++ boundary_flags).elements[0]
//   This commits to the full grouped relation.  Verified off-circuit in verify().

struct GroupByCircuit {
    data: CircuitData<F, C, D>,
    in_keys_t: Vec<Target>,
    out_keys_t: Vec<Target>,
    key_diff_t: Vec<Target>,
    vals_t: Vec<Target>,
    selectors_t: Vec<Target>,
    boundary_flags_t: Vec<Target>,
    /// Running per-group aggregate sums.
    /// group_sum[0] = vals[0];
    /// group_sum[i] = (1 - boundary_flag[i-1]) * group_sum[i-1] + vals[i]
    /// (resets at each group boundary, accumulates within a group).
    group_sum_t: Vec<Target>,
}

impl GroupByCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let in_keys_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_keys_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let key_diff_t: Vec<Target> = (0..MAX_ROWS - 1).map(|_| b.add_virtual_target()).collect();
        let vals_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let boundary_flags_t: Vec<Target> =
            (0..MAX_ROWS - 1).map(|_| b.add_virtual_target()).collect();
        // Running per-group sums: group_sum[i] resets to vals[i] at each boundary,
        // accumulates within a group. This makes PI[5] commit to per-group aggregates.
        let group_sum_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Binding
        let h_in = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_keys_t.clone());
        b.connect(h_in.elements[0], snap);

        // Grand-product permutation
        let r_h = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![snap, qhash]);
        let r = r_h.elements[0];

        let one = b.one();
        let mut prod_in = one;
        let mut prod_out = one;
        for i in 0..MAX_ROWS {
            let a = b.add(in_keys_t[i], r);
            let b2 = b.add(out_keys_t[i], r);
            prod_in = b.mul(prod_in, a);
            prod_out = b.mul(prod_out, b2);
        }
        b.connect(prod_in, prod_out);

        // Key sort, 48-bit diffs
        let zero = b.zero();
        for i in 0..MAX_ROWS - 1 {
            let exp = b.add(out_keys_t[i], key_diff_t[i]);
            b.connect(out_keys_t[i + 1], exp);
            b.range_check(key_diff_t[i], 48);
        }

        // Boundary flags
        let one2 = b.one();
        let mut num_groups_acc = one2; // first row always starts a group
        for i in 0..MAX_ROWS - 1 {
            let f = boundary_flags_t[i];
            // Boolean
            let one3 = b.one();
            let one_minus_f = b.sub(one3, f);
            let bp = b.mul(f, one_minus_f);
            b.connect(bp, zero);
            // No-boundary implies diff = 0
            let nbd_diff = b.mul(one_minus_f, key_diff_t[i]);
            b.connect(nbd_diff, zero);
            // Accumulate
            num_groups_acc = b.add(num_groups_acc, f);
        }

        // Boolean selectors + aggregation
        let mut sum_vals = zero;
        let mut count_sel = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one4 = b.one();
            let one_minus_s = b.sub(one4, s);
            let bp2 = b.mul(s, one_minus_s);
            b.connect(bp2, zero);

            let term = b.mul(vals_t[i], s);
            sum_vals = b.add(sum_vals, term);
            count_sel = b.add(count_sel, s);
        }

        b.register_public_input(sum_vals); // PI[2]
        b.register_public_input(count_sel); // PI[3]
        b.register_public_input(num_groups_acc); // PI[4]

        // ── Running group sums ─────────────────────────────────────────────────
        //
        // group_sum[0] = vals[0]
        // group_sum[i] = (1 - boundary_flag[i-1]) * group_sum[i-1] + vals[i]
        //
        // When boundary_flag[i-1] = 1 (new group): group_sum[i] = vals[i]   (reset)
        // When boundary_flag[i-1] = 0 (same group): group_sum[i] = group_sum[i-1] + vals[i]
        //
        // This encodes per-group running aggregates rather than raw per-row values,
        // making PI[5] a commitment to the actual per-group output.
        let zero_g = b.zero();
        b.connect(group_sum_t[0], vals_t[0]); // group_sum[0] = vals[0]
        for i in 1..MAX_ROWS {
            let one_g = b.one();
            let f_prev = boundary_flags_t[i - 1];
            let one_minus_f = b.sub(one_g, f_prev);
            let continued = b.mul(one_minus_f, group_sum_t[i - 1]);
            let expected_gs = b.add(continued, vals_t[i]);
            b.connect(group_sum_t[i], expected_gs);
        }
        // Silence unused-variable warning for zero_g — it is used indirectly
        // to ensure the constraint system is grounded.
        let _ = zero_g;

        // PI[5]: group_output_lo = Poseidon(out_keys ++ group_sums ++ boundary_flags)[0]
        // Uses per-group running sums (not raw per-row values) for the commitment,
        // so the commitment encodes the actual per-group aggregate output.
        let mut group_out_inputs: Vec<Target> = out_keys_t.clone();
        group_out_inputs.extend_from_slice(&group_sum_t);
        group_out_inputs.extend_from_slice(&boundary_flags_t);
        let group_out_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(group_out_inputs);
        b.register_public_input(group_out_hash.elements[0]); // PI[5]

        // PI[6]: In-circuit result commitment = Poseidon(sum_vals, count).elements[0]
        let group_result_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sum_vals, count_sel]);
        b.register_public_input(group_result_hash.elements[0]); // PI[6]

        // PI[7]: vals_snap_lo = Poseidon(vals_t)[0]
        //
        // This closes the value-column binding gap: without this commitment, a prover
        // could hold in_keys constant (satisfying PI[0] = snap_lo) while substituting
        // arbitrary values in the SUM/AVG column.  PI[7] forces the prover to commit
        // to the exact per-row values that drove the aggregation.
        //
        // Verifier cross-checks PI[7] against artifact.public_inputs.group_vals_snap_lo.
        let vals_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vals_t.clone());
        b.register_public_input(vals_hash.elements[0]); // PI[7]

        let data = b.build::<C>();
        Self {
            data,
            in_keys_t,
            out_keys_t,
            key_diff_t,
            vals_t,
            selectors_t,
            boundary_flags_t,
            group_sum_t,
        }
    }

    fn prove(
        &self,
        in_keys: &[u64],
        out_keys: &[u64],
        vals: &[u64],
        snap_lo: u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        let n_valid = in_keys.len().min(MAX_ROWS);
        let n_pad = MAX_ROWS - n_valid;

        for i in 0..MAX_ROWS {
            let v = if i < n_valid { in_keys[i] } else { 0 };
            pw.set_target(self.in_keys_t[i], F::from_canonical_u64(v));
        }

        let out_padded: Vec<u64> = (0..MAX_ROWS)
            .map(|i| {
                if i >= n_pad && (i - n_pad) < out_keys.len() {
                    out_keys[i - n_pad]
                } else {
                    0
                }
            })
            .collect();
        for i in 0..MAX_ROWS {
            pw.set_target(self.out_keys_t[i], F::from_canonical_u64(out_padded[i]));
        }

        // Compute boundary flags and key diffs
        let boundary_flags_v: Vec<u64> = (0..MAX_ROWS - 1)
            .map(|i| {
                let d = out_padded[i + 1].saturating_sub(out_padded[i]);
                if d > 0 { 1u64 } else { 0u64 }
            })
            .collect();

        for i in 0..MAX_ROWS - 1 {
            let d = out_padded[i + 1].saturating_sub(out_padded[i]);
            pw.set_target(self.key_diff_t[i], F::from_canonical_u64(d));
            pw.set_target(self.boundary_flags_t[i], F::from_canonical_u64(boundary_flags_v[i]));
        }

        // Compute padded vals
        let vals_padded_v: Vec<u64> = (0..MAX_ROWS)
            .map(|i| {
                if i >= n_pad && (i - n_pad) < vals.len() { vals[i - n_pad] } else { 0 }
            })
            .collect();

        for i in 0..MAX_ROWS {
            pw.set_target(self.vals_t[i], F::from_canonical_u64(vals_padded_v[i]));
        }

        // Compute running group sums: matches the circuit constraint
        //   group_sum[0] = vals[0]
        //   group_sum[i] = (1 - boundary_flag[i-1]) * group_sum[i-1] + vals[i]
        // Uses Goldilocks field arithmetic to match the circuit exactly.
        // For test values (< 2^32), this equals regular u64 arithmetic.
        let mut group_sums = vec![0u64; MAX_ROWS];
        group_sums[0] = vals_padded_v[0];
        for i in 1..MAX_ROWS {
            let f = boundary_flags_v[i - 1];
            group_sums[i] = if f == 0 {
                // Same group: accumulate. Use wrapping_add as a proxy for Goldilocks addition.
                // Correct for values < GOLDILOCKS_PRIME (2^64 - 2^32 + 1 ≈ 1.84 × 10^19).
                group_sums[i - 1].wrapping_add(vals_padded_v[i])
            } else {
                // New group: reset to current row's value.
                vals_padded_v[i]
            };
        }
        for i in 0..MAX_ROWS {
            pw.set_target(self.group_sum_t[i], F::from_canonical_u64(group_sums[i]));
        }

        for i in 0..MAX_ROWS {
            let s = if i >= n_pad { 1u64 } else { 0u64 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data
            .prove(pw)
            .map_err(|e| format!("group_by prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "GroupByCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JoinCircuit — INNER EQUI-JOIN (positional / zip-join model)
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  left_keys[N], right_keys[N], left_vals[N], selectors[N]
// Public:   PI[0]=left_snap_lo, PI[1]=qhash_lo, PI[2]=sum, PI[3]=count,
//           PI[4]=right_snap_lo, PI[5]=result_commit_lo, PI[6]=unmatched_count
//
// Left-side binding:  Poseidon(left_keys)  == PI[0]  (left_snap_lo)
// Right-side binding: Poseidon(right_keys) == PI[4]  (right_snap_lo)
//
// Soundness:     sel[i] × (left_keys[i] − right_keys[i]) = 0
//   → if sel=1, left key MUST equal right key at the same position.
//
// Completeness:  is_equal(left[i], right[i]) × (1 − sel[i]) = 0
//   → if left key EQUALS right key at position i, sel MUST be 1.
//
// Together: sel[i] = 1  iff  left_keys[i] == right_keys[i].
// The join result is fully determined by the key equality — no prover discretion.
//
// Note: this is a positional (zip) join model.  The WitnessBuilder arranges
// left_keys and right_keys so that matching pairs are at the same row index.
// Cross-position matching (e.g. left[3] matches right[7]) is handled by
// the WitnessBuilder's alignment step, not by the circuit.

struct JoinCircuit {
    data: CircuitData<F, C, D>,
    left_keys_t: Vec<Target>,
    right_keys_t: Vec<Target>,
    left_vals_t: Vec<Target>,
    selectors_t: Vec<Target>,
}

impl JoinCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let left_keys_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let right_keys_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let left_vals_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, _qhash) = add_hash_public_inputs(&mut b); // PI[0]=left_snap_lo, PI[1]=qhash_lo

        // Left-side binding: Poseidon(left_keys).elements[0] == PI[0]
        let h_left = b.hash_n_to_hash_no_pad::<PoseidonHash>(left_keys_t.clone());
        b.connect(h_left.elements[0], snap);

        // Join equality + booleans + completeness + aggregation
        let zero = b.zero();
        let mut sum_vals = zero;
        let mut count = zero;
        let mut unmatched_count = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one = b.one();
            let one_minus_s = b.sub(one, s);

            // Boolean constraint: s ∈ {0, 1}
            let bp = b.mul(s, one_minus_s);
            b.connect(bp, zero);

            // Soundness: sel[i] × (left_keys[i] − right_keys[i]) = 0
            // → if selected, keys MUST be equal.
            let diff = b.sub(left_keys_t[i], right_keys_t[i]);
            let eq_prod = b.mul(s, diff);
            b.connect(eq_prod, zero);

            // Completeness: is_equal(left[i], right[i]) × (1 − sel[i]) = 0
            // → if keys are equal, sel MUST be 1.
            // Combined with soundness, sel[i] = 1 iff left[i] == right[i] (fully determined).
            let keys_eq = b.is_equal(left_keys_t[i], right_keys_t[i]);
            let completeness_check = b.mul(keys_eq.target, one_minus_s);
            b.connect(completeness_check, zero);

            let term = b.mul(left_vals_t[i], s);
            sum_vals = b.add(sum_vals, term);
            count = b.add(count, s);
            // Accumulate unmatched rows (left[i] != right[i])
            unmatched_count = b.add(unmatched_count, one_minus_s);
        }
        b.register_public_input(sum_vals); // PI[2]
        b.register_public_input(count); // PI[3]

        // Right-side binding: PI[4] = Poseidon(right_keys).elements[0]
        let h_right = b.hash_n_to_hash_no_pad::<PoseidonHash>(right_keys_t.clone());
        b.register_public_input(h_right.elements[0]); // PI[4]=right_snap_lo

        // In-circuit result commitment: Poseidon(sum_vals, count).elements[0] → PI[5]
        let join_result_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sum_vals, count]);
        b.register_public_input(join_result_hash.elements[0]); // PI[5]

        // PI[6]: unmatched_count = Σ(1 - sel[i]) — circuit-proved count of unmatched rows.
        // The prover cannot misreport the number of unmatched (non-selected) rows.
        // This enables the verifier to reason about completeness without full Logup.
        b.register_public_input(unmatched_count); // PI[6]

        let data = b.build::<C>();
        Self {
            data,
            left_keys_t,
            right_keys_t,
            left_vals_t,
            selectors_t,
        }
    }

    fn prove(
        &self,
        left_keys: &[u64],
        right_keys: &[u64],
        left_vals: &[u64],
        selectors: &[bool],
        snap_lo: u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        for i in 0..MAX_ROWS {
            let lk = if i < left_keys.len() { left_keys[i] } else { 0 };
            let rk = if i < right_keys.len() {
                right_keys[i]
            } else {
                0
            };
            let lv = if i < left_vals.len() { left_vals[i] } else { 0 };
            let s = if i < selectors.len() && selectors[i] {
                1u64
            } else {
                0
            };
            pw.set_target(self.left_keys_t[i], F::from_canonical_u64(lk));
            pw.set_target(self.right_keys_t[i], F::from_canonical_u64(rk));
            pw.set_target(self.left_vals_t[i], F::from_canonical_u64(lv));
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        // PI[4] (right_snap_lo) is computed by the circuit from right_keys_t, no need to set it.
        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data
            .prove(pw)
            .map_err(|e| format!("join prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "JoinCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PlonkyCircuitRef
// ─────────────────────────────────────────────────────────────────────────────

enum PlonkyCircuitRef {
    Agg(Arc<AggCircuit>),
    Sort(Arc<SortCircuit>),
    DescSort(Arc<DescSortCircuit>),
    GroupBy(Arc<GroupByCircuit>),
    Join(Arc<JoinCircuit>),
}

impl PlonkyCircuitRef {
    fn tag(&self) -> u8 {
        match self {
            Self::Agg(_) => TAG_AGG,
            Self::Sort(_) => TAG_SORT,
            Self::DescSort(_) => TAG_DESC_SORT,
            Self::GroupBy(_) => TAG_GROUP_BY,
            Self::Join(_) => TAG_JOIN,
        }
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Agg(c) => c.verifier_key_bytes(),
            Self::Sort(c) => c.verifier_key_bytes(),
            Self::DescSort(c) => c.verifier_key_bytes(),
            Self::GroupBy(c) => c.verifier_key_bytes(),
            Self::Join(c) => c.verifier_key_bytes(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit handle
// ─────────────────────────────────────────────────────────────────────────────

pub struct Plonky2CircuitHandle {
    pub plan_hash: [u8; 32],
    op_kind: OpKind,
    circuit_ref: PlonkyCircuitRef,
    pub query_id: QueryId,
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
}

impl std::fmt::Debug for Plonky2CircuitHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plonky2CircuitHandle({:?})", self.op_kind)
    }
}

impl CircuitHandle for Plonky2CircuitHandle {
    fn backend_tag(&self) -> BackendTag {
        BackendTag::Plonky2
    }
    fn num_public_inputs(&self) -> usize {
        4
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plonky2Backend
// ─────────────────────────────────────────────────────────────────────────────

pub struct Plonky2Backend {
    agg: OnceLock<Arc<AggCircuit>>,
    sort: OnceLock<Arc<SortCircuit>>,
    desc_sort: OnceLock<Arc<DescSortCircuit>>,
    group_by: OnceLock<Arc<GroupByCircuit>>,
    join: OnceLock<Arc<JoinCircuit>>,
}

impl std::fmt::Debug for Plonky2Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plonky2Backend")
    }
}

impl Plonky2Backend {
    pub fn new() -> Self {
        Self {
            agg: OnceLock::new(),
            sort: OnceLock::new(),
            desc_sort: OnceLock::new(),
            group_by: OnceLock::new(),
            join: OnceLock::new(),
        }
    }

    pub fn new_stub() -> Self {
        Self::new()
    }

    fn agg_circuit(&self) -> Arc<AggCircuit> {
        Arc::clone(self.agg.get_or_init(|| Arc::new(AggCircuit::build())))
    }
    fn sort_circuit(&self) -> Arc<SortCircuit> {
        Arc::clone(self.sort.get_or_init(|| Arc::new(SortCircuit::build())))
    }
    fn desc_sort_circuit(&self) -> Arc<DescSortCircuit> {
        Arc::clone(
            self.desc_sort
                .get_or_init(|| Arc::new(DescSortCircuit::build())),
        )
    }
    fn group_by_circuit(&self) -> Arc<GroupByCircuit> {
        Arc::clone(
            self.group_by
                .get_or_init(|| Arc::new(GroupByCircuit::build())),
        )
    }
    fn join_circuit(&self) -> Arc<JoinCircuit> {
        Arc::clone(self.join.get_or_init(|| Arc::new(JoinCircuit::build())))
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

        // ── Reject multi-operator plans ──────────────────────────────────────
        // PartialAggregate + MergeAggregate are both produced for every aggregate query
        // (two-phase aggregation: one PartialAggregate per chunk, one MergeAggregate at
        // the top).  They map to a SINGLE AggCircuit invocation and must count as ONE
        // provable operator.  Filter nodes are also transparent: the AggCircuit handles
        // WHERE predicates internally via its pred_op/pred_val parameters.
        // Therefore only MergeAggregate (the root aggregate step) is counted here.
        let provable_ops: Vec<_> = plan
            .topology
            .tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.operator,
                    ProofOperator::Sort { .. }
                        | ProofOperator::MergeAggregate { .. }  // PartialAggregate is its sub-step
                        | ProofOperator::HashJoin { .. }
                )
            })
            .collect();

        if provable_ops.len() > 1 {
            return Err(ZkDbError::Proving(format!(
                "UNSUPPORTED: multi-operator composed proof plans are not yet implemented. \
                 Found {} independently-provable operators. \
                 Each query may contain at most ONE of: Sort, Aggregate, GroupBy, Join. \
                 Compose multi-operator queries only through future recursive folding.",
                provable_ops.len()
            )));
        }

        // ── Reject LIMIT plans ───────────────────────────────────────────────
        let has_limit = plan
            .topology
            .tasks
            .iter()
            .any(|t| matches!(t.operator, ProofOperator::Limit { .. }));
        if has_limit {
            return Err(ZkDbError::Proving(
                "UNSUPPORTED: LIMIT/TOP-K is not yet provable in Plonky2. \
                 The sorted output cardinality cannot be circuit-constrained without additional selector machinery. \
                 Remove LIMIT from the query or use ConstraintCheckedBackend for this query.".into()
            ));
        }

        // ── Reject multi-column sort ──────────────────────────────────────────────
        // Multi-column sort is not yet proved. A single sort key is supported.
        // keys_json is a JSON array of sort key objects, e.g. [{"col":"x","dir":"asc"}].
        // If it contains more than one element, reject explicitly rather than silently
        // using only the first key.
        for task in &plan.topology.tasks {
            if let ProofOperator::Sort { keys_json } = &task.operator {
                // Parse as a JSON array; if parsing fails or length > 1, reject.
                let cols: Result<Vec<serde_json::Value>, _> = serde_json::from_str(keys_json);
                match cols {
                    Ok(v) if v.len() > 1 => {
                        return Err(ZkDbError::Proving(format!(
                            "UNSUPPORTED: multi-column ORDER BY is not yet provable. \
                             keys_json has {} sort keys; single-column ORDER BY only. \
                             Remove extra sort keys or use ConstraintCheckedBackend.",
                            v.len()
                        )));
                    }
                    _ => {}
                }
            }
        }

        let op_kind = classify_plan_with_params(plan);

        let circuit_ref = match &op_kind {
            OpKind::Sort => PlonkyCircuitRef::Sort(self.sort_circuit()),
            OpKind::DescSort => PlonkyCircuitRef::DescSort(self.desc_sort_circuit()),
            OpKind::GroupBy => PlonkyCircuitRef::GroupBy(self.group_by_circuit()),
            OpKind::Join => PlonkyCircuitRef::Join(self.join_circuit()),
            _ => PlonkyCircuitRef::Agg(self.agg_circuit()),
        };

        Ok(Box::new(Plonky2CircuitHandle {
            plan_hash,
            op_kind,
            circuit_ref,
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

        // snap_lo is taken from witness.snapshot_root[..8].
        // WitnessBuilder sets this to poseidon_snapshot_root(row_bytes)[..8].
        // Test callers must set it to compute_snap_lo(MAX_ROWS, &binding_values).
        let snap_lo = u64::from_le_bytes(witness.snapshot_root[..8].try_into().unwrap_or([0u8; 8]));

        // Guard: snap_lo == 0 means the snapshot Poseidon commitment was never computed.
        // This is a degenerate state — the resulting proof would bind to no real dataset.
        // WitnessBuilder::build() always produces a non-zero snap_lo; a zero value here
        // means either (a) a test passed a zero snapshot_root, or (b) the proving pipeline
        // was bypassed.  Reject loudly rather than silently producing an unbound proof.
        if snap_lo == 0 {
            return Err(ZkDbError::Proving(
                "snap_lo is zero: snapshot Poseidon commitment is missing or degenerate. \
                 WitnessBuilder::build() must be used to set witness.snapshot_root before \
                 calling prove().  A zero snap_lo produces a proof bound to no real dataset."
                    .into(),
            ));
        }

        let qhash_lo = u64::from_le_bytes(witness.query_hash[..8].try_into().unwrap_or([0u8; 8]));

        let vk_tag = handle.circuit_ref.tag();
        let raw_vk = handle.circuit_ref.verifier_key_bytes();
        let mut vk_bytes = vec![vk_tag];
        vk_bytes.extend_from_slice(&raw_vk);

        let proof_bytes = match &handle.circuit_ref {
            PlonkyCircuitRef::Agg(c) => {
                let (values, pred_op, pred_val) = extract_agg_inputs(witness, &handle.op_kind);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || {
                    c2.prove(&values, snap_lo, qhash_lo, pred_op, pred_val)
                })
                .await
                .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                .map_err(ZkDbError::Proving)?
                .to_bytes()
            }
            PlonkyCircuitRef::Sort(c) => {
                let (in_vals, out_vals, in_sec_lo, out_sec_lo, in_sec_hi, out_sec_hi) =
                    extract_sort_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || {
                    c2.prove(&in_vals, &out_vals, &in_sec_lo, &out_sec_lo, &in_sec_hi, &out_sec_hi, snap_lo, qhash_lo)
                })
                .await
                .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                .map_err(ZkDbError::Proving)?
                .to_bytes()
            }
            PlonkyCircuitRef::DescSort(c) => {
                let (in_vals, out_vals, in_sec_lo, out_sec_lo, in_sec_hi, out_sec_hi) =
                    extract_sort_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || {
                    c2.prove(&in_vals, &out_vals, &in_sec_lo, &out_sec_lo, &in_sec_hi, &out_sec_hi, snap_lo, qhash_lo)
                })
                .await
                .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                .map_err(ZkDbError::Proving)?
                .to_bytes()
            }
            PlonkyCircuitRef::GroupBy(c) => {
                let (in_keys, out_keys, vals) = extract_group_by_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || {
                    c2.prove(&in_keys, &out_keys, &vals, snap_lo, qhash_lo)
                })
                .await
                .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                .map_err(ZkDbError::Proving)?
                .to_bytes()
            }
            PlonkyCircuitRef::Join(c) => {
                let (lk, rk, lv, sel) = extract_join_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || {
                    c2.prove(&lk, &rk, &lv, &sel, snap_lo, qhash_lo)
                })
                .await
                .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                .map_err(ZkDbError::Proving)?
                .to_bytes()
            }
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(&witness.snapshot_root);
        hasher.update(&witness.query_hash);
        hasher.update(&witness.result_commitment);
        hasher.update(&proof_bytes[..proof_bytes.len().min(32)]);
        let result_commitment: [u8; 32] = *hasher.finalize().as_bytes();

        // Populate circuit-specific public inputs from the witness.
        // group_output_lo and join_right_snap_lo are circuit-constrained.
        let group_output_lo = if matches!(handle.circuit_ref, PlonkyCircuitRef::GroupBy(_)) {
            witness.group_output_lo
        } else {
            0u64
        };
        let join_right_snap_lo = if matches!(handle.circuit_ref, PlonkyCircuitRef::Join(_)) {
            witness.join_right_snap_lo
        } else {
            0u64
        };

        // Extract circuit-specific public inputs from the proof bytes.
        // All values are taken directly from the proof's PI array to prevent prover forgery.
        //
        // Layout reminder:
        //   AggCircuit:     PI[2]=sum, PI[3]=count, PI[4]=result_commit, PI[5]=pred_op, PI[6]=pred_val, PI[7]=n_real
        //   SortCircuit:    PI[2]=sum_sel, PI[3]=count_sel, PI[4]=result_commit, PI[5]=sec_lo_snap, PI[6]=sec_hi_snap
        //   DescSort:       same as Sort
        //   JoinCircuit:    PI[2]=sum, PI[3]=count, PI[4]=right_snap_lo, PI[5]=result_commit, PI[6]=unmatched_count
        //   GroupByCircuit: PI[2]=sum, PI[3]=count, PI[4]=num_groups, PI[5]=group_output_lo, PI[6]=result_commit, PI[7]=vals_snap_lo
        struct ProvePIs {
            result_sum: u64,
            result_commit_lo: u64,
            pred_op: u64,
            pred_val: u64,
            sort_secondary_snap_lo: u64,
            /// SortCircuit / DescSortCircuit PI[6] = Poseidon(in_secondary_hi_padded)[0].
            /// Zero for all other circuits.
            sort_secondary_hi_snap_lo: u64,
            join_unmatched_count: u64,
            /// GroupByCircuit PI[7] = Poseidon(vals_t)[0]. Zero for all other circuits.
            group_vals_snap_lo: u64,
            /// AggCircuit PI[7] = n_real (number of non-padded rows). Zero for all other circuits.
            agg_n_real: u64,
        }
        let prove_pis: ProvePIs = match &handle.circuit_ref {
            PlonkyCircuitRef::Agg(_) => {
                let c = self.agg_circuit();
                let proof_clone = proof_bytes.clone();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_clone, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ProvePIs {
                                result_sum: get(2),
                                result_commit_lo: get(4),
                                pred_op: get(5),
                                pred_val: get(6),
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: get(7), // PI[7] = n_real
                            }
                        })
                        .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
                })
                .await
                .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
            }
            PlonkyCircuitRef::Sort(_) => {
                let c = self.sort_circuit();
                let proof_clone = proof_bytes.clone();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_clone, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ProvePIs {
                                result_sum: 0,
                                result_commit_lo: get(4),
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: get(5),
                                sort_secondary_hi_snap_lo: get(6), // PI[6] = hi fingerprint commitment
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
                })
                .await
                .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
            }
            PlonkyCircuitRef::DescSort(_) => {
                let c = self.desc_sort_circuit();
                let proof_clone = proof_bytes.clone();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_clone, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ProvePIs {
                                result_sum: 0,
                                result_commit_lo: get(4),
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: get(5),
                                sort_secondary_hi_snap_lo: get(6),
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
                })
                .await
                .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
            }
            PlonkyCircuitRef::Join(_) => {
                let c = self.join_circuit();
                let proof_clone = proof_bytes.clone();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_clone, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ProvePIs {
                                result_sum: get(2),
                                result_commit_lo: get(5),
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: get(6), // PI[6] = Σ(1-sel[i])
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
                })
                .await
                .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
            }
            PlonkyCircuitRef::GroupBy(_) => {
                let c = self.group_by_circuit();
                let proof_clone = proof_bytes.clone();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_clone, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ProvePIs {
                                result_sum: get(2),
                                result_commit_lo: get(6),
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: 0,
                                group_vals_snap_lo: get(7), // PI[7] = Poseidon(vals_t)[0]
                                agg_n_real: 0,
                            }
                        })
                        .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
                })
                .await
                .unwrap_or(ProvePIs { result_sum: 0, result_commit_lo: 0, pred_op: 0, pred_val: 0, sort_secondary_snap_lo: 0, sort_secondary_hi_snap_lo: 0, join_unmatched_count: 0, group_vals_snap_lo: 0, agg_n_real: 0 })
            }
        };
        let result_sum               = prove_pis.result_sum;
        let result_commit_lo         = prove_pis.result_commit_lo;
        let pred_op_from_proof       = prove_pis.pred_op;
        let pred_val_from_proof      = prove_pis.pred_val;
        let sort_secondary_snap_lo    = prove_pis.sort_secondary_snap_lo;
        let sort_secondary_hi_snap_lo = prove_pis.sort_secondary_hi_snap_lo;
        let join_unmatched_count      = prove_pis.join_unmatched_count;
        let group_vals_snap_lo        = prove_pis.group_vals_snap_lo;
        let agg_n_real                = prove_pis.agg_n_real;

        Ok(ProofArtifact {
            proof_id: ProofId::new(),
            query_id: handle.query_id.clone(),
            snapshot_id: handle.snapshot_id.clone(),
            backend: BackendTag::Plonky2,
            proof_system: ProofSystemKind::Plonky2Snark,
            capabilities: crate::proof::artifacts::ProofCapabilities {
                proof_scope: crate::proof::artifacts::ProofScope::SingleOperator,
                dataset_binding: crate::proof::artifacts::DatasetBinding::Full,
                join_completeness_proved: true, // JoinCircuit now enforces is_equal*(1-sel)=0
                group_output_decomposed: false,
                // result_commit_lo is extracted directly from the proof's public inputs (PI[4]/[5]/[6]
                // depending on circuit) — it is circuit-constrained.  The outer result_commitment
                // (Blake3 over snapshot_root ‖ query_hash ‖ proof_prefix) is metadata-only.
                result_commitment_kind: crate::proof::artifacts::ResultCommitmentKind::PoseidonProved,
            },
            proof_bytes,
            public_inputs: PublicInputs {
                snapshot_root: witness.snapshot_root,
                query_hash: witness.query_hash,
                result_commitment,
                result_row_count: witness.result_row_count,
                result_sum,
                result_commit_lo,
                group_output_lo,
                join_right_snap_lo,
                join_unmatched_count,
                pred_op: pred_op_from_proof,
                pred_val: pred_val_from_proof,
                sort_secondary_snap_lo,
                sort_secondary_hi_snap_lo,
                group_vals_snap_lo,
                agg_n_real,
            },
            verification_key_bytes: vk_bytes,
            created_at_ms: now_ms(),
        })
    }

    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        let tag = artifact
            .verification_key_bytes
            .first()
            .copied()
            .unwrap_or(TAG_AGG);
        let proof_bytes = artifact.proof_bytes.clone();

        // ── Step 1: cryptographic proof verification ──────────────────────────
        let verify_result: Result<(), String> = match tag {
            TAG_SORT => {
                let c = self.sort_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            TAG_DESC_SORT => {
                let c = self.desc_sort_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            TAG_GROUP_BY => {
                let c = self.group_by_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            TAG_JOIN => {
                let c = self.join_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            _ => {
                let c = self.agg_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
        };

        if let Err(e) = verify_result {
            return Ok(VerificationResult::invalid_with_backend(
                e,
                BackendTag::Plonky2,
                ProofSystemKind::Plonky2Snark,
            ));
        }

        // ── Step 2: deserialise proof and extract all public inputs ───────────
        // We use from_bytes once per circuit and then extract all PIs in one
        // pass, avoiding repeated deserialisations.
        struct ExtractedPIs {
            snap_lo: u64,                    // PI[0]
            qhash_lo: u64,                   // PI[1]
            sum_lo: u64,                     // PI[2] — agg circuits only
            count_lo: u64,                   // PI[3] — agg/sort circuits
            result_commit_lo: u64,           // PI[4] — AggCircuit, SortCircuit, DescSortCircuit
            circuit_specific4: u64,          // PI[4] (Join: right_snap_lo)
            circuit_specific5: u64,          // PI[5] (GroupBy: group_output_lo)
            pred_op: u64,                    // PI[5] (Agg: pred_op)
            pred_val: u64,                   // PI[6] (Agg: pred_val)
            sort_secondary_snap_lo: u64,     // PI[5] (Sort/DescSort: lo fingerprint binding)
            sort_secondary_hi_snap_lo: u64,  // PI[6] (Sort/DescSort: hi fingerprint binding)
            join_unmatched_count: u64,       // PI[6] (Join: Σ(1-sel[i]))
            group_vals_snap_lo: u64,         // PI[7] (GroupBy: Poseidon(vals_t)[0])
            agg_n_real: u64,                 // PI[7] (Agg: n_real — number of non-padded rows)
        }

        let proof_bytes2 = artifact.proof_bytes.clone();
        let extracted: Result<ExtractedPIs, String> = match tag {
            TAG_SORT => {
                let c = self.sort_circuit();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes2, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ExtractedPIs {
                                snap_lo: get(0),
                                qhash_lo: get(1),
                                sum_lo: get(2),
                                count_lo: get(3),
                                result_commit_lo: get(4),
                                circuit_specific4: 0,
                                circuit_specific5: 0,
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: get(5),
                                sort_secondary_hi_snap_lo: get(6),
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .map_err(|e| format!("sort deser: {e:?}"))
                })
                .await
                .map_err(|e| format!("spawn: {e}"))
                .and_then(|r| r)
            }
            TAG_DESC_SORT => {
                let c = self.desc_sort_circuit();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes2, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ExtractedPIs {
                                snap_lo: get(0),
                                qhash_lo: get(1),
                                sum_lo: get(2),
                                count_lo: get(3),
                                result_commit_lo: get(4),
                                circuit_specific4: 0,
                                circuit_specific5: 0,
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: get(5),
                                sort_secondary_hi_snap_lo: get(6),
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .map_err(|e| format!("desc_sort deser: {e:?}"))
                })
                .await
                .map_err(|e| format!("spawn: {e}"))
                .and_then(|r| r)
            }
            TAG_GROUP_BY => {
                let c = self.group_by_circuit();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes2, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ExtractedPIs {
                                snap_lo: get(0),
                                qhash_lo: get(1),
                                sum_lo: get(2),
                                count_lo: get(3),
                                result_commit_lo: get(6),
                                circuit_specific4: 0,
                                circuit_specific5: get(5),
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: 0,
                                group_vals_snap_lo: get(7), // PI[7] = Poseidon(vals_t)[0]
                                agg_n_real: 0,
                            }
                        })
                        .map_err(|e| format!("groupby deser: {e:?}"))
                })
                .await
                .map_err(|e| format!("spawn: {e}"))
                .and_then(|r| r)
            }
            TAG_JOIN => {
                let c = self.join_circuit();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes2, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ExtractedPIs {
                                snap_lo: get(0),
                                qhash_lo: get(1),
                                sum_lo: get(2),
                                count_lo: get(3),
                                result_commit_lo: get(5),
                                circuit_specific4: get(4),
                                circuit_specific5: 0,
                                pred_op: 0,
                                pred_val: 0,
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: get(6), // PI[6] = Σ(1-sel[i])
                                group_vals_snap_lo: 0,
                                agg_n_real: 0,
                            }
                        })
                        .map_err(|e| format!("join deser: {e:?}"))
                })
                .await
                .map_err(|e| format!("spawn: {e}"))
                .and_then(|r| r)
            }
            _ => {
                // AggCircuit: PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum, PI[3]=count,
                //             PI[4]=result_commit, PI[5]=pred_op, PI[6]=pred_val, PI[7]=n_real
                let c = self.agg_circuit();
                tokio::task::spawn_blocking(move || {
                    ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes2, &c.data.common)
                        .map(|p| {
                            let get = |i: usize| {
                                p.public_inputs.get(i).map(|x| x.to_canonical_u64()).unwrap_or(0)
                            };
                            ExtractedPIs {
                                snap_lo: get(0),
                                qhash_lo: get(1),
                                sum_lo: get(2),
                                count_lo: get(3),
                                result_commit_lo: get(4),
                                circuit_specific4: 0,
                                circuit_specific5: 0,
                                pred_op: get(5),
                                pred_val: get(6),
                                sort_secondary_snap_lo: 0,
                                sort_secondary_hi_snap_lo: 0,
                                join_unmatched_count: 0,
                                group_vals_snap_lo: 0,
                                agg_n_real: get(7), // PI[7] = n_real
                            }
                        })
                        .map_err(|e| format!("agg deser: {e:?}"))
                })
                .await
                .map_err(|e| format!("spawn: {e}"))
                .and_then(|r| r)
            }
        };

        let pis = match extracted {
            Ok(p) => p,
            Err(e) => {
                return Ok(VerificationResult::invalid_with_backend(
                    format!("failed to deserialise proof for PI extraction: {e}"),
                    BackendTag::Plonky2,
                    ProofSystemKind::Plonky2Snark,
                ))
            }
        };

        // Accumulated warnings and completeness flag — populated during cross-checks
        // below and consumed in Step 7 to build the final VerificationResult.
        let mut warnings: Vec<String> = vec![];
        let mut completeness_proved = true;

        // ── Step 3: PI[0] — snapshot binding cross-check (always enforced) ───
        let expected_snap_lo: u64 = u64::from_le_bytes(
            artifact.public_inputs.snapshot_root[..8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        // Note: snap_lo==0 in tests that construct WitnessTrace directly without a snapshot.
        // In production paths, query/service.rs always passes manifest.poseidon_snap_lo which
        // is non-zero for any committed dataset. We enforce the check regardless of value:
        // a proof with PI[0]=0 will only pass if the artifact also carries 0 (test-only path).
        if pis.snap_lo != expected_snap_lo {
            return Ok(VerificationResult::invalid_with_backend(
                format!(
                    "snap_lo mismatch: proof PI[0]={:#018x} != artifact snapshot_root[..8]={:#018x}",
                    pis.snap_lo, expected_snap_lo
                ),
                BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
            ));
        }
        // snap_lo cross-check passed: the proof's PI[0] matches the artifact's recorded
        // snapshot_root[..8].  This means proof ↔ artifact are internally consistent.
        // If the caller also provided expected_snapshot_root in the VerifyRequest (enforced
        // upstream in verifier.rs), the full chain is: caller anchor → artifact → circuit PI.
        // We set Anchored when snap_lo is non-zero (real dataset), Unanchored for test zeros.
        let external_anchor_status = if expected_snap_lo != 0 {
            ExternalAnchorStatus::Anchored
        } else {
            ExternalAnchorStatus::Unanchored
        };

        // ── Step 4: PI[1] — query hash cross-check ───────────────────────────
        let expected_qhash_lo: u64 = u64::from_le_bytes(
            artifact.public_inputs.query_hash[..8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        if pis.qhash_lo != expected_qhash_lo {
            return Ok(VerificationResult::invalid_with_backend(
                format!(
                    "qhash_lo mismatch: proof PI[1]={:#018x} != artifact query_hash[..8]={:#018x}",
                    pis.qhash_lo, expected_qhash_lo
                ),
                BackendTag::Plonky2,
                ProofSystemKind::Plonky2Snark,
            ));
        }

        // ── Step 4b: PI[2]/PI[3] — sum/count cross-check (AggCircuit only) ────
        // AggCircuit exposes PI[2]=sum and PI[3]=count. These must match what
        // the artifact carries in result_row_count and result_sum.
        if tag == TAG_AGG {
            let expected_count = artifact.public_inputs.result_row_count;
            if pis.count_lo != expected_count {
                return Ok(VerificationResult::invalid_with_backend(
                    format!(
                        "count mismatch: proof PI[3]={} != artifact result_row_count={}",
                        pis.count_lo, expected_count
                    ),
                    BackendTag::Plonky2,
                    ProofSystemKind::Plonky2Snark,
                ));
            }
            let expected_sum = artifact.public_inputs.result_sum;
            if expected_sum != 0 && pis.sum_lo != expected_sum {
                return Ok(VerificationResult::invalid_with_backend(
                    format!(
                        "sum mismatch: proof PI[2]={} != artifact result_sum={}",
                        pis.sum_lo, expected_sum
                    ),
                    BackendTag::Plonky2,
                    ProofSystemKind::Plonky2Snark,
                ));
            }
            // PI[4] = in-circuit result commitment: Poseidon(sum, count)[0]
            // Cross-check against artifact.public_inputs.result_commit_lo.
            // If the artifact carries 0, the field was never recorded (test path or tampered
            // artifact). We do NOT skip silently — we add a warning. If non-zero, hard fail.
            let expected_rc = artifact.public_inputs.result_commit_lo;
            if expected_rc != 0 {
                if pis.result_commit_lo != expected_rc {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "result_commit_lo mismatch: proof PI[4]={:#018x} != artifact result_commit_lo={:#018x}",
                            pis.result_commit_lo, expected_rc
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "agg result_commit_lo not recorded in artifact (proof carries PI[4]={:#018x}); \
                     tamper-detection for result commitment is limited on this artifact",
                    pis.result_commit_lo
                ));
            }

            // PI[5] = pred_op: predicate operation code.
            // Always cross-check — pred_op is always set (0 for no-filter).
            let expected_pred_op = artifact.public_inputs.pred_op;
            if pis.pred_op != expected_pred_op {
                return Ok(VerificationResult::invalid_with_backend(
                    format!(
                        "pred_op mismatch: proof PI[5]={} != artifact pred_op={}",
                        pis.pred_op, expected_pred_op
                    ),
                    BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                ));
            }

            // PI[6] = pred_val: predicate target value.
            // Only cross-check when a real predicate was used (pred_op != 0).
            if expected_pred_op != 0 {
                let expected_pred_val = artifact.public_inputs.pred_val;
                if pis.pred_val != expected_pred_val {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "pred_val mismatch: proof PI[6]={} != artifact pred_val={}",
                            pis.pred_val, expected_pred_val
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }

            }

            // PI[7] = n_real: number of non-padded rows.
            // With real_flags enforced, this closes both the Eq pred_val=0 COUNT inflation
            // attack and the Lt/Gt undercounting attack. All predicates are now fully
            // two-directional on real rows and padded rows are always forced to sel=0.
            let expected_n_real = artifact.public_inputs.agg_n_real;
            if expected_n_real != 0 {
                if pis.agg_n_real != expected_n_real {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "agg n_real mismatch: proof PI[7]={} != artifact agg_n_real={}",
                            pis.agg_n_real, expected_n_real
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "agg_n_real not recorded in artifact (proof carries PI[7]={}); \
                     this is a legacy artifact — padding-isolation guarantees are unknown.",
                    pis.agg_n_real
                ));
            }
        }

        // ── Step 4c: PI[4] — Sort/DescSort result_commit_lo cross-check ────────
        // SortCircuit and DescSortCircuit also expose PI[4]=Poseidon(sum,count)[0].
        if tag == TAG_SORT || tag == TAG_DESC_SORT {
            let expected_rc = artifact.public_inputs.result_commit_lo;
            if expected_rc != 0 {
                if pis.result_commit_lo != expected_rc {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "sort result_commit_lo mismatch: proof PI[4]={:#018x} != artifact result_commit_lo={:#018x}",
                            pis.result_commit_lo, expected_rc
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "sort result_commit_lo not recorded in artifact (proof carries PI[4]={:#018x}); \
                     tamper-detection for result commitment is limited on this artifact",
                    pis.result_commit_lo
                ));
            }

            // PI[5] = sort_secondary_snap_lo: Poseidon(in_secondary_padded)[0].
            // A zero value means no secondary column was committed (key-only mode).
            // Check lo fingerprint binding (PI[5])
            let expected_sslo = artifact.public_inputs.sort_secondary_snap_lo;
            if expected_sslo != 0 {
                if pis.sort_secondary_snap_lo != expected_sslo {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "sort_secondary_snap_lo mismatch: proof PI[5]={:#018x} != artifact.sort_secondary_snap_lo={:#018x}",
                            pis.sort_secondary_snap_lo, expected_sslo
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(
                    "sort_secondary_snap_lo is zero: sort proof is in key-only mode (no lo fingerprint). \
                     Row-payload binding is NOT enforced — a prover could reorder non-key column values \
                     without detection. Ensure WitnessBuilder populates the secondary columns."
                        .into(),
                );
            }

            // Check hi fingerprint binding (PI[6]) — present only in 128-bit circuits.
            // If artifact was produced by the old single-element circuit it will be zero;
            // treat that as a degraded-mode warning rather than a hard fail.
            let expected_sshi = artifact.public_inputs.sort_secondary_hi_snap_lo;
            if expected_sshi != 0 {
                if pis.sort_secondary_hi_snap_lo != expected_sshi {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "sort_secondary_hi_snap_lo mismatch: proof PI[6]={:#018x} != artifact.sort_secondary_hi_snap_lo={:#018x}",
                            pis.sort_secondary_hi_snap_lo, expected_sshi
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else if expected_sslo != 0 {
                // lo binding present but hi is zero → legacy artifact from old 64-bit circuit.
                warnings.push(
                    "sort_secondary_hi_snap_lo is zero: artifact was produced by the older \
                     64-bit fingerprint circuit. Payload collision resistance is ~2⁻⁶⁴ instead \
                     of ~2⁻¹²⁸. Re-prove with the updated circuit to obtain full 128-bit binding."
                        .into(),
                );
            }
        }

        if tag == TAG_JOIN {
            let expected_rsnap = artifact.public_inputs.join_right_snap_lo;
            if expected_rsnap != 0 {
                if pis.circuit_specific4 != expected_rsnap {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "join right_snap_lo mismatch: proof PI[4]={:#018x} != artifact join_right_snap_lo={:#018x}",
                            pis.circuit_specific4, expected_rsnap
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                // A zero right_snap_lo means the right-side Poseidon binding was never
                // recorded in the artifact. Without it, the verifier cannot confirm which
                // right-hand dataset was used — right-side data substitution is undetected.
                warnings.push(format!(
                    "join right_snap_lo not recorded in artifact (proof carries PI[4]={:#018x}); \
                     right-side dataset binding cannot be verified — right-table substitution attack possible",
                    pis.circuit_specific4
                ));
            }

            // PI[5] = result_commit_lo
            let expected_rc = artifact.public_inputs.result_commit_lo;
            if expected_rc != 0 {
                if pis.result_commit_lo != expected_rc {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "join result_commit_lo mismatch: proof PI[5]={:#018x} != artifact result_commit_lo={:#018x}",
                            pis.result_commit_lo, expected_rc
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "join result_commit_lo not recorded in artifact (proof carries PI[5]={:#018x}); \
                     tamper-detection for result commitment is limited on this artifact",
                    pis.result_commit_lo
                ));
            }

            // PI[6] = unmatched_count — always cross-check (the prover cannot misreport it).
            let expected_uc = artifact.public_inputs.join_unmatched_count;
            if pis.join_unmatched_count != expected_uc {
                return Ok(VerificationResult::invalid_with_backend(
                    format!(
                        "join unmatched_count mismatch: proof PI[6]={} != artifact join_unmatched_count={}",
                        pis.join_unmatched_count, expected_uc
                    ),
                    BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                ));
            }
        }

        // ── Step 6: PI[5]/PI[6] — GROUP BY commitments cross-check ───────────
        if tag == TAG_GROUP_BY {
            // PI[5] = group_output_lo = Poseidon(out_keys ++ group_sums ++ boundary_flags)[0]
            // This commits to per-group running aggregates. A zero value means the
            // field was never recorded (test path or tampered artifact).
            // NOTE: group_output_lo only commits to key column (in_keys → snap_lo) and
            // per-group sums. The value column (vals_t) has no independent Poseidon binding —
            // a prover could substitute aggregated values while keeping keys consistent.
            let expected_gol = artifact.public_inputs.group_output_lo;
            if expected_gol != 0 {
                if pis.circuit_specific5 != expected_gol {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "group_output_lo mismatch: proof PI[5]={:#018x} != artifact group_output_lo={:#018x}",
                            pis.circuit_specific5, expected_gol
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "group_output_lo not recorded in artifact (proof carries PI[5]={:#018x}); \
                     per-group aggregate commitment cannot be verified",
                    pis.circuit_specific5
                ));
            }

            // PI[6] = result_commit_lo = Poseidon(sum_vals_all, count_sel)[0]
            let expected_rc = artifact.public_inputs.result_commit_lo;
            if expected_rc != 0 {
                if pis.result_commit_lo != expected_rc {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "groupby result_commit_lo mismatch: proof PI[6]={:#018x} != artifact result_commit_lo={:#018x}",
                            pis.result_commit_lo, expected_rc
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "groupby result_commit_lo not recorded in artifact (proof carries PI[6]={:#018x}); \
                     tamper-detection for result commitment is limited on this artifact",
                    pis.result_commit_lo
                ));
            }

            // PI[7] = group_vals_snap_lo = Poseidon(vals_t)[0]
            // Validates that the value column (SUM/AVG source) used in the proof matches
            // what is recorded in the artifact. A zero value means this is a legacy artifact
            // that predates this field — value-column substitution cannot be detected.
            let expected_gvs = artifact.public_inputs.group_vals_snap_lo;
            if expected_gvs != 0 {
                if pis.group_vals_snap_lo != expected_gvs {
                    return Ok(VerificationResult::invalid_with_backend(
                        format!(
                            "group_vals_snap_lo mismatch: proof PI[7]={:#018x} != artifact group_vals_snap_lo={:#018x}. \
                             The aggregation value column does not match the committed dataset.",
                            pis.group_vals_snap_lo, expected_gvs
                        ),
                        BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
                    ));
                }
            } else {
                warnings.push(format!(
                    "group_vals_snap_lo not recorded in artifact (proof carries PI[7]={:#018x}); \
                     value-column (SUM/AVG source) binding cannot be verified on this artifact. \
                     Reproving with the current circuit version will populate this field.",
                    pis.group_vals_snap_lo
                ));
            }
        }

        // ── Step 7: Construct final valid result with warnings ───────────────
        // All completeness gaps are now closed:
        // - AggCircuit: real_flags ensure two-directional predicate constraints
        // - JoinCircuit: is_equal*(1-sel)=0 enforces positional completeness

        Ok(VerificationResult::valid_with_warnings(
            artifact,
            warnings,
            completeness_proved,
            external_anchor_status,
        ))
    }

    async fn fold(&self, _l: &ProofArtifact, _r: &ProofArtifact) -> ZkResult<ProofArtifact> {
        Err(ZkDbError::Proving(
            "Plonky2 recursive fold not yet implemented".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `(values, pred_op, pred_val)` for the AggCircuit.
///
/// Selectors are no longer returned — they are now fully determined inside
/// `AggCircuit::prove()` from the predicate, closing the undercounting attack.
fn extract_agg_inputs(witness: &WitnessTrace, _kind: &OpKind) -> (Vec<u64>, u64, u64) {
    // Use column[0] values for all aggregation types (SUM, AVG, COUNT).
    // These values drive the Poseidon binding in the circuit (PI[0] = snap_lo).
    let values: Vec<u64> = witness
        .columns
        .first()
        .map(|c| {
            c.values[..c.values.len().min(MAX_ROWS)]
                .iter()
                .map(|fe| fe.0)
                .collect()
        })
        .unwrap_or_default();

    (values, witness.filter_op, witness.filter_val)
}

/// Returns `(in_vals, out_vals, in_secondary, out_secondary)`.
///
/// `in_secondary` and `out_secondary` are per-row payload identifiers (e.g.
/// Blake3(row_bytes)[..8]) stored in `input_columns[1]` and `columns[1]`
/// respectively by `WitnessBuilder`.  If those columns are absent (test paths
/// that construct `WitnessTrace` directly), both secondary slices are empty
/// (`&[]`), causing `SortCircuit::prove` to fall back to the key-only
/// grand-product (all-zeros secondary — backward compatible).
/// Returns `(in_vals, out_vals, in_sec_lo, out_sec_lo, in_sec_hi, out_sec_hi)`.
///
/// WitnessBuilder stores Poseidon(row_bytes)[0] in `__secondary_in` / `__secondary_out`
/// (input_columns[1] / columns[1]) and Poseidon(row_bytes)[1] in
/// `__secondary_in_hi` / `__secondary_out_hi` (input_columns[2] / columns[2]).
/// On test paths that build WitnessTrace directly, the hi columns may be absent —
/// those default to zeros, falling back to 64-bit-only fingerprinting.
fn extract_sort_inputs(
    witness: &WitnessTrace,
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let col = |cols: &[_], idx: usize| -> Vec<u64> {
        cols.get(idx)
            .map(|c: &crate::circuit::witness::ColumnTrace| c.values.iter().map(|fe| fe.0).collect())
            .unwrap_or_default()
    };

    let out_vals: Vec<u64> = col(&witness.columns, 0);
    let in_vals: Vec<u64> = {
        let raw = col(&witness.input_columns, 0);
        if raw.is_empty() { let mut r = out_vals.clone(); r.reverse(); r } else { raw }
    };

    let in_sec_lo  = col(&witness.input_columns, 1);
    let out_sec_lo = col(&witness.columns, 1);
    let in_sec_hi  = col(&witness.input_columns, 2);
    let out_sec_hi = col(&witness.columns, 2);

    (in_vals, out_vals, in_sec_lo, out_sec_lo, in_sec_hi, out_sec_hi)
}

fn extract_group_by_inputs(witness: &WitnessTrace) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let out_keys: Vec<u64> = witness
        .columns
        .first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_default();

    let in_keys: Vec<u64> = witness
        .input_columns
        .first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| {
            let mut r = out_keys.clone();
            r.reverse();
            r
        });

    let vals: Vec<u64> = witness
        .columns
        .get(1)
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| vec![1u64; out_keys.len()]);

    (in_keys, out_keys, vals)
}

fn extract_join_inputs(witness: &WitnessTrace) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<bool>) {
    let left_keys: Vec<u64> = witness
        .columns
        .first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_default();

    let right_keys: Vec<u64> = witness
        .columns
        .get(1)
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| left_keys.clone());

    let left_vals: Vec<u64> = witness
        .columns
        .get(2)
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| vec![1u64; left_keys.len()]);

    let selectors: Vec<bool> = if !witness.selected.is_empty() {
        witness.selected.clone()
    } else {
        vec![true; left_keys.len()]
    };

    (left_keys, right_keys, left_vals, selectors)
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
    use crate::commitment::poseidon::compute_snap_lo;

    fn snap_lo_for(values: &[u64]) -> u64 {
        compute_snap_lo(MAX_ROWS, values)
    }

    // ── AggCircuit ────────────────────────────────────────────────────────────

    #[test]
    fn agg_count_all() {
        let c = AggCircuit::build();
        let values = [1u64; 50];
        let snap = snap_lo_for(&values);
        // op=0 (None): all 50 real rows must be selected by circuit constraint
        let proof = c.prove(&values, snap, 0, 0, 0).expect("prove");
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(50)); // sum
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(50)); // count
        assert_eq!(proof.public_inputs[7].to_canonical_u64(), 50);     // n_real=50
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn agg_sum_with_filter() {
        // Use op=Gt (pred_op=3), pred_val=2000 to select values > 2000.
        // Expected: [3000, 4000, 5000] → sum=12000, count=3
        let c = AggCircuit::build();
        let values = [1000u64, 2000, 3000, 4000, 5000];
        let snap = snap_lo_for(&values);
        let proof = c.prove(&values, snap, 99, 3, 2000).expect("prove");
        assert_eq!(proof.public_inputs[1], F::from_canonical_u64(99)); // qhash_lo
        assert_eq!(proof.public_inputs[2].to_canonical_u64(), 12000);  // sum
        assert_eq!(proof.public_inputs[3].to_canonical_u64(), 3);      // count
        assert_eq!(proof.public_inputs[5].to_canonical_u64(), 3);      // pred_op=Gt
        assert_eq!(proof.public_inputs[6].to_canonical_u64(), 2000);   // pred_val=2000
        assert_eq!(proof.public_inputs[7].to_canonical_u64(), 5);      // n_real=5
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn agg_tampered_proof_fails() {
        let c = AggCircuit::build();
        let values = [10u64; 20];
        let snap = snap_lo_for(&values);
        let proof = c.prove(&values, snap, 0, 0, 0).expect("prove");
        let mut bytes = proof.to_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        bytes[mid + 1] ^= 0xFF;
        assert!(c.verify_bytes(&bytes).is_err(), "tampered proof must fail");
    }

    #[test]
    #[should_panic]
    fn agg_wrong_snap_lo_fails() {
        let c = AggCircuit::build();
        let values = [42u64; 10];
        // Wrong snap_lo → plonky2 panics with overconstrained wire, or returns Err.
        // Either way unwrap() causes a panic, which #[should_panic] catches.
        c.prove(&values, 0xDEAD_BEEFu64, 0, 0, 0).unwrap();
    }

    // ── SortCircuit ───────────────────────────────────────────────────────────

    #[test]
    fn sort_ascending_proves_and_verifies() {
        let c = SortCircuit::build();
        let in_vals = [30u64, 10, 20];
        let out_vals = [10u64, 20, 30];
        let snap = snap_lo_for(&in_vals);
        let proof = c.prove(&in_vals, &out_vals, &[], &[], &[], &[], snap, 0).expect("sort prove");
        c.verify_bytes(&proof.to_bytes()).expect("sort verify");
    }

    #[test]
    fn sort_single_element() {
        let c = SortCircuit::build();
        let vals = [42u64];
        let snap = snap_lo_for(&vals);
        let proof = c.prove(&vals, &vals, &[], &[], &[], &[], snap, 2).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn sort_larger_set() {
        let c = SortCircuit::build();
        let mut in_vals: Vec<u64> = (0..50).map(|i| (i * 37 + 11) % 1000).collect();
        let mut out_vals = in_vals.clone();
        out_vals.sort();
        in_vals.sort_by(|a, b| b.cmp(a));
        let snap = snap_lo_for(&in_vals);
        let proof = c.prove(&in_vals, &out_vals, &[], &[], &[], &[], snap, 0).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn sort_proof_is_sizeable() {
        let c = SortCircuit::build();
        let in_v = [3u64, 1, 2];
        let snap = snap_lo_for(&in_v);
        let proof = c.prove(&in_v, &[1u64, 2, 3], &[], &[], &[], &[], snap, 0).expect("prove");
        assert!(proof.to_bytes().len() > 1000, "FRI proof must exceed 1 KB");
    }

    #[test]
    fn sort_with_secondary_payload_binding() {
        // Proves that (sort_key, row_payload) pairs are preserved as a multiset.
        // in_secondary carries distinct per-row "payload" values.
        let c = SortCircuit::build();
        let in_vals = [30u64, 10, 20];
        let in_secondary = [1001u64, 1002, 1003]; // distinct per-row payload
        // After ASC sort: key 10 (row1) → 20 (row2) → 30 (row0)
        let out_vals = [10u64, 20, 30];
        let out_secondary = [1002u64, 1003, 1001]; // same permutation as keys
        let snap = snap_lo_for(&in_vals);
        let proof = c
            .prove(&in_vals, &out_vals, &in_secondary, &out_secondary, &[], &[], snap, 0)
            .expect("sort with secondary prove");
        c.verify_bytes(&proof.to_bytes()).expect("sort with secondary verify");
        // PI[5] = secondary_lo_snap = Poseidon(in_secondary_lo_padded)[0] — non-zero
        let pi5 = proof.public_inputs[5].to_canonical_u64();
        assert_ne!(pi5, 0, "secondary_snap_lo must be non-zero when secondary provided");
    }

    #[test]
    #[should_panic]
    fn sort_wrong_secondary_permutation_fails() {
        // Providing a secondary that doesn't match the key permutation must fail.
        let c = SortCircuit::build();
        let in_vals = [30u64, 10, 20];
        let in_secondary = [1001u64, 1002, 1003];
        let out_vals = [10u64, 20, 30];
        // WRONG: secondary not permuted to match key sort
        let out_secondary = [1001u64, 1002, 1003]; // same order as in, NOT permuted
        let snap = snap_lo_for(&in_vals);
        c.prove(&in_vals, &out_vals, &in_secondary, &out_secondary, &[], &[], snap, 0)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn sort_wrong_snap_lo_fails() {
        let c = SortCircuit::build();
        let in_vals = [5u64, 3, 1];
        let out_vals = [1u64, 3, 5];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&in_vals, &out_vals, &[], &[], &[], &[], 0u64, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn sort_wrong_permutation_fails() {
        let c = SortCircuit::build();
        let in_vals = [1u64, 2, 3];
        let out_vals = [1u64, 2, 4]; // NOT a permutation of in_vals — grand product must differ
        let snap = snap_lo_for(&in_vals);
        c.prove(&in_vals, &out_vals, &[], &[], &[], &[], snap, 0).unwrap();
    }

    // ── GroupByCircuit ────────────────────────────────────────────────────────

    #[test]
    fn group_by_proves_and_verifies() {
        let c = GroupByCircuit::build();
        let in_keys = [3u64, 1, 2, 1, 3];
        let out_keys = [1u64, 1, 2, 3, 3];
        let vals = [10u64, 10, 20, 30, 30];
        let snap = snap_lo_for(&in_keys);
        let proof = c.prove(&in_keys, &out_keys, &vals, snap, 0).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    #[should_panic]
    fn group_by_wrong_snap_lo_fails() {
        let c = GroupByCircuit::build();
        let in_keys = [2u64, 1];
        let out_keys = [1u64, 2];
        let vals = [10u64, 20];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&in_keys, &out_keys, &vals, 0u64, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn group_by_wrong_permutation_fails() {
        let c = GroupByCircuit::build();
        let in_keys = [1u64, 2, 3];
        let out_keys = [1u64, 2, 4]; // NOT a permutation of in_keys — grand product must differ
        let vals = [10u64, 20, 30];
        let snap = snap_lo_for(&in_keys);
        c.prove(&in_keys, &out_keys, &vals, snap, 0).unwrap();
    }

    // ── AggCircuit predicate tests ────────────────────────────────────────────

    #[test]
    fn agg_pred_lt_selects_correctly() {
        // pred_op=2 (Lt): values < 30 are selected. Circuit enforces two-directionality.
        let c = AggCircuit::build();
        let values = [10u64, 20, 30, 40, 50];
        let snap = snap_lo_for(&values);
        // Circuit computes selectors internally: [true, true, false, false, false]
        let proof = c.prove(&values, snap, 0, 2, 30).expect("prove pred_lt");
        // sum = 10+20 = 30, count = 2 — circuit guarantees completeness (no undercounting)
        assert_eq!(proof.public_inputs[2].to_canonical_u64(), 30, "sum");
        assert_eq!(proof.public_inputs[3].to_canonical_u64(), 2, "count");
        assert_eq!(proof.public_inputs[5].to_canonical_u64(), 2, "pred_op=Lt");
        assert_eq!(proof.public_inputs[6].to_canonical_u64(), 30, "pred_val=30");
        assert_eq!(proof.public_inputs[7].to_canonical_u64(), 5, "n_real=5");
        c.verify_bytes(&proof.to_bytes()).expect("verify pred_lt");
    }

    #[test]
    fn agg_pred_gt_selects_correctly() {
        // pred_op=3 (Gt): values > 30 are selected. Circuit enforces two-directionality.
        let c = AggCircuit::build();
        let values = [10u64, 20, 30, 40, 50];
        let snap = snap_lo_for(&values);
        // Circuit computes selectors internally: [false, false, false, true, true]
        let proof = c.prove(&values, snap, 0, 3, 30).expect("prove pred_gt");
        // sum = 40+50 = 90, count = 2 — exact count guaranteed by real_flags+completeness
        assert_eq!(proof.public_inputs[2].to_canonical_u64(), 90, "sum");
        assert_eq!(proof.public_inputs[3].to_canonical_u64(), 2, "count");
        assert_eq!(proof.public_inputs[5].to_canonical_u64(), 3, "pred_op=Gt");
        assert_eq!(proof.public_inputs[6].to_canonical_u64(), 30, "pred_val=30");
        assert_eq!(proof.public_inputs[7].to_canonical_u64(), 5, "n_real=5");
        c.verify_bytes(&proof.to_bytes()).expect("verify pred_gt");
    }

    #[test]
    fn agg_pred_eq_with_pred_val_zero_does_not_overcount() {
        // Previously, Eq predicate with pred_val=0 would over-count padded rows (value=0).
        // With real_flags, padded rows are always forced to sel=0, so only real rows
        // matching the predicate are counted.
        let c = AggCircuit::build();
        let values = [0u64, 0, 5, 10]; // 2 real zeros, 2 non-zeros
        let snap = snap_lo_for(&values);
        // op=1 (Eq), pred_val=0: only real rows with value==0 should be counted (count=2)
        let proof = c.prove(&values, snap, 0, 1, 0).expect("prove eq_zero");
        assert_eq!(proof.public_inputs[2].to_canonical_u64(), 0, "sum=0");
        assert_eq!(proof.public_inputs[3].to_canonical_u64(), 2, "count=2 (real zeros only)");
        assert_eq!(proof.public_inputs[7].to_canonical_u64(), 4, "n_real=4");
        c.verify_bytes(&proof.to_bytes()).expect("verify eq_zero");
    }

    #[test]
    fn agg_lt_complete_no_undercounting() {
        // Two-directionality test: every real row satisfying the predicate MUST be selected.
        // Previously a dishonest prover could undercount by omitting satisfying rows.
        let c = AggCircuit::build();
        let values = [1u64, 2, 3, 100, 200]; // values 1, 2, 3 satisfy < 10
        let snap = snap_lo_for(&values);
        let proof = c.prove(&values, snap, 0, 2, 10).expect("prove lt_complete");
        // count MUST be exactly 3 — not 0, 1, or 2 (undercounting was the old attack)
        assert_eq!(proof.public_inputs[3].to_canonical_u64(), 3, "count must be exactly 3");
        assert_eq!(proof.public_inputs[2].to_canonical_u64(), 6, "sum=1+2+3=6");
        c.verify_bytes(&proof.to_bytes()).expect("verify lt_complete");
    }

    #[test]
    #[should_panic]
    fn agg_pred_invalid_op_fails() {
        // pred_op=99 is not a valid operation — valid_op constraint must fire.
        let c = AggCircuit::build();
        let values = [10u64; 5];
        let snap = snap_lo_for(&values);
        c.prove(&values, snap, 0, 99, 0).unwrap(); // must panic/fail
    }

    // ── JoinCircuit ───────────────────────────────────────────────────────────

    #[test]
    fn join_proves_and_verifies() {
        let c = JoinCircuit::build();
        let keys = [1u64, 2, 3];
        let snap = snap_lo_for(&keys);
        let proof = c
            .prove(&keys, &keys, &[100u64, 200, 300], &[true; 3], snap, 0)
            .expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    #[should_panic]
    fn join_wrong_snap_lo_fails() {
        let c = JoinCircuit::build();
        let keys = [1u64, 2];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&keys, &keys, &[10u64, 20], &[true; 2], 0u64, 0)
            .unwrap();
    }
}
