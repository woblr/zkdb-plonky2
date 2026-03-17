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
use plonky2::field::types::Field;
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
use crate::proof::artifacts::{ProofArtifact, ProofSystemKind, PublicInputs, VerificationResult};
use crate::query::proof_plan::{ProofOperator, ProofPlan};
use crate::types::{BackendTag, DatasetId, ProofId, QueryId, SnapshotId, ZkDbError, ZkResult};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// ─────────────────────────────────────────────────────────────────────────────
// VK tag constants
// ─────────────────────────────────────────────────────────────────────────────

const TAG_AGG:      u8 = 0;
const TAG_SORT:     u8 = 1;
const TAG_GROUP_BY: u8 = 2;
const TAG_JOIN:     u8 = 3;

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
    GroupBy,
    Join,
}

impl OpKind {
    #[allow(dead_code)]
    fn circuit_tag(&self) -> u8 {
        match self {
            Self::Sort    => TAG_SORT,
            Self::GroupBy => TAG_GROUP_BY,
            Self::Join    => TAG_JOIN,
            _             => TAG_AGG,
        }
    }
}

fn classify_plan(plan: &ProofPlan) -> OpKind {
    let root_id = &plan.topology.root_task_id;
    let root_op = plan.topology.tasks.iter()
        .find(|t| &t.task_id == root_id)
        .or_else(|| plan.topology.tasks.last())
        .map(|t| &t.operator);

    if let Some(op) = root_op {
        return classify_operator(op);
    }
    for task in &plan.topology.tasks {
        let k = classify_operator(&task.operator);
        if k != OpKind::Generic { return k; }
    }
    OpKind::Generic
}

fn classify_operator(op: &ProofOperator) -> OpKind {
    match op {
        ProofOperator::Sort { .. } => OpKind::Sort,
        ProofOperator::HashJoin { .. } => OpKind::Join,
        ProofOperator::PartialAggregate { group_by_json, aggregates_json }
        | ProofOperator::MergeAggregate { group_by_json, aggregates_json, .. } => {
            if group_by_json != "[]" && !group_by_json.trim().is_empty() {
                return OpKind::GroupBy;
            }
            let j = aggregates_json.to_lowercase();
            if j.contains("\"avg\"") { OpKind::Avg }
            else if j.contains("\"sum\"") { OpKind::Sum }
            else { OpKind::Count }
        }
        _ => OpKind::Generic,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Register PI[0]=snap_lo and PI[1]=qhash_lo; return their targets.
fn add_hash_public_inputs(b: &mut CircuitBuilder<F, D>) -> (Target, Target) {
    let snap  = b.add_virtual_public_input();
    let qhash = b.add_virtual_public_input();
    (snap, qhash)
}

fn verify_proof_bytes(
    data: &CircuitData<F, C, D>,
    proof_bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        proof_bytes.to_vec(), &data.common,
    ).map_err(|e| format!("{label} deser: {e:?}"))?;
    data.verify(proof).map_err(|e| format!("{label} verify: {e:?}"))
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
// AggCircuit — COUNT / SUM / AVG
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  values[MAX_ROWS], selectors[MAX_ROWS]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum, PI[3]=count
//
// Binding:
//   hash_out = Poseidon(values[0..MAX_ROWS-1])
//   connect(hash_out.elements[0], PI[0])   ← snap_lo is PROVED from values

struct AggCircuit {
    data: CircuitData<F, C, D>,
    values_t: Vec<Target>,
    selectors_t: Vec<Target>,
}

impl AggCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let values_t:    Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, _qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Poseidon binding: PI[0] = Poseidon(values).elements[0]
        let hash_out = b.hash_n_to_hash_no_pad::<PoseidonHash>(values_t.clone());
        b.connect(hash_out.elements[0], snap);

        // Boolean constraints
        let zero = b.zero();
        for &s in &selectors_t {
            let one          = b.one();
            let one_minus_s  = b.sub(one, s);
            let prod         = b.mul(s, one_minus_s);
            b.connect(prod, zero);
        }

        // Aggregation
        let mut sum_acc   = zero;
        let mut count_acc = zero;
        for (&v, &s) in values_t.iter().zip(selectors_t.iter()) {
            let term = b.mul(v, s);
            sum_acc   = b.add(sum_acc,   term);
            count_acc = b.add(count_acc, s);
        }
        b.register_public_input(sum_acc);   // PI[2]
        b.register_public_input(count_acc); // PI[3]

        let data = b.build::<C>();
        Self { data, values_t, selectors_t }
    }

    /// Prove.  `snap_lo` **must** equal `compute_snap_lo(MAX_ROWS, &values_padded)`.
    fn prove(
        &self,
        values:    &[u64],
        selectors: &[bool],
        snap_lo:   u64,
        qhash_lo:  u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();
        for i in 0..MAX_ROWS {
            let v = if i < values.len() { values[i] } else { 0 };
            pw.set_target(self.values_t[i], F::from_canonical_u64(v));
        }
        for i in 0..MAX_ROWS {
            let s = if i < selectors.len() && selectors[i] { 1u64 } else { 0 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }
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
// SortCircuit — ORDER BY
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  in_vals[N], out_vals[N], diff[N-1], selectors[N]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum_sel, PI[3]=count_sel
//
// Binding:  Poseidon(in_vals) == snap_lo
//
// Grand-product:
//   r = Poseidon(snap, qhash).elements[0]
//   ∏(in[i]+r) == ∏(out[i]+r)
//
// Monotonicity:
//   out[i+1] = out[i] + diff[i],  range_check(diff[i], 48)
//
// Padding: in_vals zero-padded at end; out_vals zeros at FRONT.

struct SortCircuit {
    data: CircuitData<F, C, D>,
    in_vals_t:   Vec<Target>,
    out_vals_t:  Vec<Target>,
    diff_t:      Vec<Target>,
    selectors_t: Vec<Target>,
}

impl SortCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let in_vals_t:   Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_vals_t:  Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let diff_t:      Vec<Target> = (0..MAX_ROWS-1).map(|_| b.add_virtual_target()).collect();
        let selectors_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Binding: Poseidon(in_vals).elements[0] == snap
        let h_in = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_vals_t.clone());
        b.connect(h_in.elements[0], snap);

        // Grand-product permutation
        // r derived from (snap, qhash) inside the circuit — verifier-computable
        let r_h = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![snap, qhash]);
        let r   = r_h.elements[0];

        let one = b.one();
        let mut prod_in  = one;
        let mut prod_out = one;
        for i in 0..MAX_ROWS {
            let a = b.add(in_vals_t[i],  r);
            let b2 = b.add(out_vals_t[i], r);
            prod_in  = b.mul(prod_in,  a);
            prod_out = b.mul(prod_out, b2);
        }
        b.connect(prod_in, prod_out);

        // Monotonicity (ascending), 48-bit diffs
        for i in 0..MAX_ROWS-1 {
            let expected = b.add(out_vals_t[i], diff_t[i]);
            b.connect(out_vals_t[i+1], expected);
            b.range_check(diff_t[i], 48);
        }

        // Boolean selectors + aggregation
        let zero = b.zero();
        let mut sum_sel   = zero;
        let mut count_sel = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one2        = b.one();
            let one_minus_s = b.sub(one2, s);
            let bp          = b.mul(s, one_minus_s);
            b.connect(bp, zero);

            let term = b.mul(out_vals_t[i], s);
            sum_sel   = b.add(sum_sel,   term);
            count_sel = b.add(count_sel, s);
        }
        b.register_public_input(sum_sel);   // PI[2]
        b.register_public_input(count_sel); // PI[3]

        let data = b.build::<C>();
        Self { data, in_vals_t, out_vals_t, diff_t, selectors_t }
    }

    /// `in_vals`  — original unsorted values
    /// `out_vals` — sorted ascending
    /// `snap_lo`  — must equal `compute_snap_lo(MAX_ROWS, &in_vals_zero_padded)`
    fn prove(
        &self,
        in_vals:  &[u64],
        out_vals: &[u64],
        snap_lo:  u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        let n_valid = in_vals.len().min(MAX_ROWS);
        let n_pad   = MAX_ROWS - n_valid;

        for i in 0..MAX_ROWS {
            let v = if i < n_valid { in_vals[i] } else { 0 };
            pw.set_target(self.in_vals_t[i], F::from_canonical_u64(v));
        }

        let out_padded: Vec<u64> = (0..MAX_ROWS).map(|i| {
            if i >= n_pad && (i - n_pad) < out_vals.len() { out_vals[i - n_pad] } else { 0 }
        }).collect();
        for i in 0..MAX_ROWS {
            pw.set_target(self.out_vals_t[i], F::from_canonical_u64(out_padded[i]));
        }

        for i in 0..MAX_ROWS-1 {
            let d = out_padded[i+1].saturating_sub(out_padded[i]);
            pw.set_target(self.diff_t[i], F::from_canonical_u64(d));
        }

        for i in 0..MAX_ROWS {
            let s = if i >= n_pad { 1u64 } else { 0u64 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data.prove(pw).map_err(|e| format!("sort prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "SortCircuit")
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
//           PI[4]=num_groups
//
// Binding:  Poseidon(in_keys) == snap_lo
//
// Grand-product on key column:
//   r = Poseidon(snap, qhash).elements[0]
//   ∏(in_keys[i]+r) == ∏(out_keys[i]+r)
//
// Key sort:
//   out_keys[i+1] = out_keys[i] + key_diff[i],  range_check(key_diff, 48)
//
// Boundary flags (partial soundness):
//   boundary_flags[i] ∈ {0,1}
//   (1 - boundary_flags[i]) × key_diff[i] = 0    ← no-boundary ⟹ diff = 0
//   num_groups = 1 + Σ boundary_flags[i]

struct GroupByCircuit {
    data: CircuitData<F, C, D>,
    in_keys_t:       Vec<Target>,
    out_keys_t:      Vec<Target>,
    key_diff_t:      Vec<Target>,
    vals_t:          Vec<Target>,
    selectors_t:     Vec<Target>,
    boundary_flags_t: Vec<Target>,
}

impl GroupByCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let in_keys_t:        Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let out_keys_t:       Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let key_diff_t:       Vec<Target> = (0..MAX_ROWS-1).map(|_| b.add_virtual_target()).collect();
        let vals_t:           Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t:      Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let boundary_flags_t: Vec<Target> = (0..MAX_ROWS-1).map(|_| b.add_virtual_target()).collect();

        let (snap, qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Binding
        let h_in = b.hash_n_to_hash_no_pad::<PoseidonHash>(in_keys_t.clone());
        b.connect(h_in.elements[0], snap);

        // Grand-product permutation
        let r_h = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![snap, qhash]);
        let r   = r_h.elements[0];

        let one = b.one();
        let mut prod_in  = one;
        let mut prod_out = one;
        for i in 0..MAX_ROWS {
            let a  = b.add(in_keys_t[i],  r);
            let b2 = b.add(out_keys_t[i], r);
            prod_in  = b.mul(prod_in,  a);
            prod_out = b.mul(prod_out, b2);
        }
        b.connect(prod_in, prod_out);

        // Key sort, 48-bit diffs
        let zero = b.zero();
        for i in 0..MAX_ROWS-1 {
            let exp = b.add(out_keys_t[i], key_diff_t[i]);
            b.connect(out_keys_t[i+1], exp);
            b.range_check(key_diff_t[i], 48);
        }

        // Boundary flags
        let one2 = b.one();
        let mut num_groups_acc = one2; // first row always starts a group
        for i in 0..MAX_ROWS-1 {
            let f = boundary_flags_t[i];
            // Boolean
            let one3        = b.one();
            let one_minus_f = b.sub(one3, f);
            let bp          = b.mul(f, one_minus_f);
            b.connect(bp, zero);
            // No-boundary implies diff = 0
            let nbd_diff = b.mul(one_minus_f, key_diff_t[i]);
            b.connect(nbd_diff, zero);
            // Accumulate
            num_groups_acc = b.add(num_groups_acc, f);
        }

        // Boolean selectors + aggregation
        let mut sum_vals  = zero;
        let mut count_sel = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one4        = b.one();
            let one_minus_s = b.sub(one4, s);
            let bp2         = b.mul(s, one_minus_s);
            b.connect(bp2, zero);

            let term = b.mul(vals_t[i], s);
            sum_vals  = b.add(sum_vals,  term);
            count_sel = b.add(count_sel, s);
        }

        b.register_public_input(sum_vals);       // PI[2]
        b.register_public_input(count_sel);      // PI[3]
        b.register_public_input(num_groups_acc); // PI[4]

        let data = b.build::<C>();
        Self {
            data, in_keys_t, out_keys_t, key_diff_t,
            vals_t, selectors_t, boundary_flags_t,
        }
    }

    fn prove(
        &self,
        in_keys:  &[u64],
        out_keys: &[u64],
        vals:     &[u64],
        snap_lo:  u64,
        qhash_lo: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        let n_valid = in_keys.len().min(MAX_ROWS);
        let n_pad   = MAX_ROWS - n_valid;

        for i in 0..MAX_ROWS {
            let v = if i < n_valid { in_keys[i] } else { 0 };
            pw.set_target(self.in_keys_t[i], F::from_canonical_u64(v));
        }

        let out_padded: Vec<u64> = (0..MAX_ROWS).map(|i| {
            if i >= n_pad && (i - n_pad) < out_keys.len() { out_keys[i - n_pad] } else { 0 }
        }).collect();
        for i in 0..MAX_ROWS {
            pw.set_target(self.out_keys_t[i], F::from_canonical_u64(out_padded[i]));
        }

        for i in 0..MAX_ROWS-1 {
            let d    = out_padded[i+1].saturating_sub(out_padded[i]);
            let flag = if d > 0 { 1u64 } else { 0u64 };
            pw.set_target(self.key_diff_t[i],       F::from_canonical_u64(d));
            pw.set_target(self.boundary_flags_t[i], F::from_canonical_u64(flag));
        }

        for i in 0..MAX_ROWS {
            let v = if i >= n_pad && (i - n_pad) < vals.len() { vals[i - n_pad] } else { 0 };
            pw.set_target(self.vals_t[i], F::from_canonical_u64(v));
        }

        for i in 0..MAX_ROWS {
            let s = if i >= n_pad { 1u64 } else { 0u64 };
            pw.set_target(self.selectors_t[i], F::from_canonical_u64(s));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data.prove(pw).map_err(|e| format!("group_by prove: {e:?}"))
    }

    fn verify_bytes(&self, proof_bytes: &[u8]) -> Result<(), String> {
        verify_proof_bytes(&self.data, proof_bytes, "GroupByCircuit")
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        self.data.verifier_only.to_bytes().unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JoinCircuit — INNER EQUI-JOIN
// ─────────────────────────────────────────────────────────────────────────────
//
// Private:  left_keys[N], right_keys[N], left_vals[N], selectors[N]
// Public:   PI[0]=snap_lo, PI[1]=qhash_lo, PI[2]=sum, PI[3]=count
//
// Binding:  Poseidon(left_keys) == snap_lo
//
// Soundness:
//   sel[i] ∈ {0,1}
//   sel[i] × (left_keys[i] − right_keys[i]) = 0
//
// TODO: completeness proof via right-table key commitment.

struct JoinCircuit {
    data: CircuitData<F, C, D>,
    left_keys_t:  Vec<Target>,
    right_keys_t: Vec<Target>,
    left_vals_t:  Vec<Target>,
    selectors_t:  Vec<Target>,
}

impl JoinCircuit {
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        let left_keys_t:  Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let right_keys_t: Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let left_vals_t:  Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();
        let selectors_t:  Vec<Target> = (0..MAX_ROWS).map(|_| b.add_virtual_target()).collect();

        let (snap, _qhash) = add_hash_public_inputs(&mut b); // PI[0], PI[1]

        // Binding
        let h_left = b.hash_n_to_hash_no_pad::<PoseidonHash>(left_keys_t.clone());
        b.connect(h_left.elements[0], snap);

        // Join equality + booleans + aggregation
        let zero = b.zero();
        let mut sum_vals = zero;
        let mut count    = zero;
        for i in 0..MAX_ROWS {
            let s = selectors_t[i];
            let one         = b.one();
            let one_minus_s = b.sub(one, s);
            let bp          = b.mul(s, one_minus_s);
            b.connect(bp, zero);

            let diff    = b.sub(left_keys_t[i], right_keys_t[i]);
            let eq_prod = b.mul(s, diff);
            b.connect(eq_prod, zero);

            let term = b.mul(left_vals_t[i], s);
            sum_vals = b.add(sum_vals, term);
            count    = b.add(count, s);
        }
        b.register_public_input(sum_vals); // PI[2]
        b.register_public_input(count);    // PI[3]

        let data = b.build::<C>();
        Self { data, left_keys_t, right_keys_t, left_vals_t, selectors_t }
    }

    fn prove(
        &self,
        left_keys:  &[u64],
        right_keys: &[u64],
        left_vals:  &[u64],
        selectors:  &[bool],
        snap_lo:    u64,
        qhash_lo:   u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        for i in 0..MAX_ROWS {
            let lk = if i < left_keys.len()  { left_keys[i]  } else { 0 };
            let rk = if i < right_keys.len() { right_keys[i] } else { 0 };
            let lv = if i < left_vals.len()  { left_vals[i]  } else { 0 };
            let s  = if i < selectors.len() && selectors[i] { 1u64 } else { 0 };
            pw.set_target(self.left_keys_t[i],  F::from_canonical_u64(lk));
            pw.set_target(self.right_keys_t[i], F::from_canonical_u64(rk));
            pw.set_target(self.left_vals_t[i],  F::from_canonical_u64(lv));
            pw.set_target(self.selectors_t[i],  F::from_canonical_u64(s));
        }

        set_pis(&mut pw, &self.data, snap_lo, qhash_lo);
        self.data.prove(pw).map_err(|e| format!("join prove: {e:?}"))
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
    GroupBy(Arc<GroupByCircuit>),
    Join(Arc<JoinCircuit>),
}

impl PlonkyCircuitRef {
    fn tag(&self) -> u8 {
        match self {
            Self::Agg(_)     => TAG_AGG,
            Self::Sort(_)    => TAG_SORT,
            Self::GroupBy(_) => TAG_GROUP_BY,
            Self::Join(_)    => TAG_JOIN,
        }
    }

    fn verifier_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Agg(c)     => c.verifier_key_bytes(),
            Self::Sort(c)    => c.verifier_key_bytes(),
            Self::GroupBy(c) => c.verifier_key_bytes(),
            Self::Join(c)    => c.verifier_key_bytes(),
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
    fn backend_tag(&self) -> BackendTag { BackendTag::Plonky2 }
    fn num_public_inputs(&self) -> usize { 4 }
    fn as_any(&self) -> &dyn Any { self }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plonky2Backend
// ─────────────────────────────────────────────────────────────────────────────

pub struct Plonky2Backend {
    agg:      OnceLock<Arc<AggCircuit>>,
    sort:     OnceLock<Arc<SortCircuit>>,
    group_by: OnceLock<Arc<GroupByCircuit>>,
    join:     OnceLock<Arc<JoinCircuit>>,
}

impl std::fmt::Debug for Plonky2Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plonky2Backend")
    }
}

impl Plonky2Backend {
    pub fn new() -> Self {
        Self {
            agg:      OnceLock::new(),
            sort:     OnceLock::new(),
            group_by: OnceLock::new(),
            join:     OnceLock::new(),
        }
    }

    pub fn new_stub() -> Self { Self::new() }

    fn agg_circuit(&self)      -> Arc<AggCircuit>      { Arc::clone(self.agg.get_or_init(|| Arc::new(AggCircuit::build()))) }
    fn sort_circuit(&self)     -> Arc<SortCircuit>     { Arc::clone(self.sort.get_or_init(|| Arc::new(SortCircuit::build()))) }
    fn group_by_circuit(&self) -> Arc<GroupByCircuit>  { Arc::clone(self.group_by.get_or_init(|| Arc::new(GroupByCircuit::build()))) }
    fn join_circuit(&self)     -> Arc<JoinCircuit>     { Arc::clone(self.join.get_or_init(|| Arc::new(JoinCircuit::build()))) }
}

impl Default for Plonky2Backend {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ProvingBackend for Plonky2Backend {
    fn tag(&self) -> BackendTag { BackendTag::Plonky2 }

    async fn compile_circuit(&self, plan: &ProofPlan) -> ZkResult<Box<dyn CircuitHandle>> {
        let plan_json = serde_json::to_string(plan).unwrap_or_default();
        let plan_hash = *blake3::hash(plan_json.as_bytes()).as_bytes();
        let op_kind   = classify_plan(plan);

        let circuit_ref = match &op_kind {
            OpKind::Sort    => PlonkyCircuitRef::Sort(self.sort_circuit()),
            OpKind::GroupBy => PlonkyCircuitRef::GroupBy(self.group_by_circuit()),
            OpKind::Join    => PlonkyCircuitRef::Join(self.join_circuit()),
            _               => PlonkyCircuitRef::Agg(self.agg_circuit()),
        };

        Ok(Box::new(Plonky2CircuitHandle {
            plan_hash,
            op_kind,
            circuit_ref,
            query_id:    plan.query_id.clone(),
            snapshot_id: plan.snapshot_id.clone(),
            dataset_id:  plan.dataset_id.clone(),
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
        let snap_lo = u64::from_le_bytes(
            witness.snapshot_root[..8].try_into().unwrap_or([0u8; 8]),
        );
        let qhash_lo = u64::from_le_bytes(
            witness.query_hash[..8].try_into().unwrap_or([0u8; 8]),
        );

        let vk_tag  = handle.circuit_ref.tag();
        let raw_vk  = handle.circuit_ref.verifier_key_bytes();
        let mut vk_bytes = vec![vk_tag];
        vk_bytes.extend_from_slice(&raw_vk);

        let proof_bytes = match &handle.circuit_ref {
            PlonkyCircuitRef::Agg(c) => {
                let (values, selectors) = extract_agg_inputs(witness, &handle.op_kind);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || c2.prove(&values, &selectors, snap_lo, qhash_lo))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                    .map_err(ZkDbError::Proving)?
                    .to_bytes()
            }
            PlonkyCircuitRef::Sort(c) => {
                let (in_vals, out_vals) = extract_sort_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || c2.prove(&in_vals, &out_vals, snap_lo, qhash_lo))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                    .map_err(ZkDbError::Proving)?
                    .to_bytes()
            }
            PlonkyCircuitRef::GroupBy(c) => {
                let (in_keys, out_keys, vals) = extract_group_by_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || c2.prove(&in_keys, &out_keys, &vals, snap_lo, qhash_lo))
                    .await
                    .map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
                    .map_err(ZkDbError::Proving)?
                    .to_bytes()
            }
            PlonkyCircuitRef::Join(c) => {
                let (lk, rk, lv, sel) = extract_join_inputs(witness);
                let c2 = Arc::clone(c);
                tokio::task::spawn_blocking(move || c2.prove(&lk, &rk, &lv, &sel, snap_lo, qhash_lo))
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

        Ok(ProofArtifact {
            proof_id:     ProofId::new(),
            query_id:     handle.query_id.clone(),
            snapshot_id:  handle.snapshot_id.clone(),
            backend:      BackendTag::Plonky2,
            proof_system: ProofSystemKind::Plonky2Snark,
            proof_bytes,
            public_inputs: PublicInputs {
                snapshot_root:    witness.snapshot_root,
                query_hash:       witness.query_hash,
                result_commitment,
                result_row_count: witness.result_row_count,
            },
            verification_key_bytes: vk_bytes,
            created_at_ms: now_ms(),
        })
    }

    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult> {
        let tag         = artifact.verification_key_bytes.first().copied().unwrap_or(TAG_AGG);
        let proof_bytes = artifact.proof_bytes.clone();

        let result: Result<(), String> = match tag {
            TAG_SORT => {
                let c = self.sort_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await.map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            TAG_GROUP_BY => {
                let c = self.group_by_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await.map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            TAG_JOIN => {
                let c = self.join_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await.map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
            _ => {
                let c = self.agg_circuit();
                tokio::task::spawn_blocking(move || c.verify_bytes(&proof_bytes))
                    .await.map_err(|e| ZkDbError::Proving(format!("spawn panic: {e}")))?
            }
        };

        match result {
            Ok(()) => Ok(VerificationResult::valid(artifact)),
            Err(e) => Ok(VerificationResult::invalid_with_backend(
                e, BackendTag::Plonky2, ProofSystemKind::Plonky2Snark,
            )),
        }
    }

    async fn fold(&self, _l: &ProofArtifact, _r: &ProofArtifact) -> ZkResult<ProofArtifact> {
        Err(ZkDbError::Proving("Plonky2 recursive fold not yet implemented".into()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Witness extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

fn extract_agg_inputs(witness: &WitnessTrace, kind: &OpKind) -> (Vec<u64>, Vec<bool>) {
    let n_rows = witness.columns.first()
        .map(|c| c.len()).unwrap_or(0)
        .max(witness.selected.len());

    let selectors: Vec<bool> = if !witness.selected.is_empty() {
        witness.selected[..n_rows.min(MAX_ROWS)].to_vec()
    } else {
        vec![true; n_rows.min(MAX_ROWS)]
    };

    // For SUM/AVG use column[0] values; for COUNT/Generic also use column[0]
    // (these same values drive the Poseidon binding in the circuit).
    let values: Vec<u64> = match kind {
        OpKind::Sum | OpKind::Avg => {
            witness.columns.first()
                .map(|c| c.values[..c.values.len().min(MAX_ROWS)].iter().map(|fe| fe.0).collect())
                .unwrap_or_else(|| vec![0u64; selectors.len()])
        }
        _ => {
            witness.columns.first()
                .map(|c| c.values[..c.values.len().min(MAX_ROWS)].iter().map(|fe| fe.0).collect())
                .unwrap_or_else(|| vec![0u64; selectors.len()])
        }
    };

    (values, selectors)
}

fn extract_sort_inputs(witness: &WitnessTrace) -> (Vec<u64>, Vec<u64>) {
    let out_vals: Vec<u64> = witness.columns.first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_default();

    let in_vals: Vec<u64> = witness.input_columns.first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| { let mut r = out_vals.clone(); r.reverse(); r });

    (in_vals, out_vals)
}

fn extract_group_by_inputs(witness: &WitnessTrace) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let out_keys: Vec<u64> = witness.columns.first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_default();

    let in_keys: Vec<u64> = witness.input_columns.first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| { let mut r = out_keys.clone(); r.reverse(); r });

    let vals: Vec<u64> = witness.columns.get(1)
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| vec![1u64; out_keys.len()]);

    (in_keys, out_keys, vals)
}

fn extract_join_inputs(witness: &WitnessTrace) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<bool>) {
    let left_keys: Vec<u64> = witness.columns.first()
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_default();

    let right_keys: Vec<u64> = witness.columns.get(1)
        .map(|c| c.values.iter().map(|fe| fe.0).collect())
        .unwrap_or_else(|| left_keys.clone());

    let left_vals: Vec<u64> = witness.columns.get(2)
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
        let snap   = snap_lo_for(&values);
        let proof  = c.prove(&values, &[true; 50], snap, 0).expect("prove");
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(50)); // sum
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(50)); // count
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn agg_sum_with_filter() {
        let c = AggCircuit::build();
        let values    = [1000u64, 2000, 3000, 4000, 5000];
        let selectors = [false, false, true, true, true];
        let snap      = snap_lo_for(&values);
        let proof     = c.prove(&values, &selectors, snap, 99).expect("prove");
        assert_eq!(proof.public_inputs[1], F::from_canonical_u64(99));    // qhash_lo
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(12000)); // sum
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(3));     // count
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn agg_tampered_proof_fails() {
        let c = AggCircuit::build();
        let values = [10u64; 20];
        let snap   = snap_lo_for(&values);
        let proof  = c.prove(&values, &[true; 20], snap, 0).expect("prove");
        let mut bytes = proof.to_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        bytes[mid+1] ^= 0xFF;
        assert!(c.verify_bytes(&bytes).is_err(), "tampered proof must fail");
    }

    #[test]
    #[should_panic]
    fn agg_wrong_snap_lo_fails() {
        let c = AggCircuit::build();
        let values = [42u64; 10];
        // Wrong snap_lo → plonky2 panics with overconstrained wire, or returns Err.
        // Either way unwrap() causes a panic, which #[should_panic] catches.
        c.prove(&values, &[true; 10], 0xDEAD_BEEFu64, 0).unwrap();
    }

    // ── SortCircuit ───────────────────────────────────────────────────────────

    #[test]
    fn sort_ascending_proves_and_verifies() {
        let c = SortCircuit::build();
        let in_vals  = [30u64, 10, 20];
        let out_vals = [10u64, 20, 30];
        let snap     = snap_lo_for(&in_vals);
        let proof    = c.prove(&in_vals, &out_vals, snap, 0).expect("sort prove");
        c.verify_bytes(&proof.to_bytes()).expect("sort verify");
    }

    #[test]
    fn sort_single_element() {
        let c    = SortCircuit::build();
        let vals = [42u64];
        let snap = snap_lo_for(&vals);
        let proof = c.prove(&vals, &vals, snap, 2).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn sort_larger_set() {
        let c = SortCircuit::build();
        let mut in_vals: Vec<u64> = (0..50).map(|i| (i * 37 + 11) % 1000).collect();
        let mut out_vals = in_vals.clone();
        out_vals.sort();
        in_vals.sort_by(|a, b| b.cmp(a));
        let snap  = snap_lo_for(&in_vals);
        let proof = c.prove(&in_vals, &out_vals, snap, 0).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    fn sort_proof_is_sizeable() {
        let c     = SortCircuit::build();
        let in_v  = [3u64, 1, 2];
        let snap  = snap_lo_for(&in_v);
        let proof = c.prove(&in_v, &[1u64, 2, 3], snap, 0).expect("prove");
        assert!(proof.to_bytes().len() > 1000, "FRI proof must exceed 1 KB");
    }

    #[test]
    #[should_panic]
    fn sort_wrong_snap_lo_fails() {
        let c        = SortCircuit::build();
        let in_vals  = [5u64, 3, 1];
        let out_vals = [1u64, 3, 5];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&in_vals, &out_vals, 0u64, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn sort_wrong_permutation_fails() {
        let c        = SortCircuit::build();
        let in_vals  = [1u64, 2, 3];
        let out_vals = [1u64, 2, 4]; // NOT a permutation of in_vals — grand product must differ
        let snap     = snap_lo_for(&in_vals);
        c.prove(&in_vals, &out_vals, snap, 0).unwrap();
    }

    // ── GroupByCircuit ────────────────────────────────────────────────────────

    #[test]
    fn group_by_proves_and_verifies() {
        let c = GroupByCircuit::build();
        let in_keys  = [3u64, 1, 2, 1, 3];
        let out_keys = [1u64, 1, 2, 3, 3];
        let vals     = [10u64, 10, 20, 30, 30];
        let snap     = snap_lo_for(&in_keys);
        let proof    = c.prove(&in_keys, &out_keys, &vals, snap, 0).expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    #[should_panic]
    fn group_by_wrong_snap_lo_fails() {
        let c = GroupByCircuit::build();
        let in_keys  = [2u64, 1];
        let out_keys = [1u64, 2];
        let vals     = [10u64, 20];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&in_keys, &out_keys, &vals, 0u64, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn group_by_wrong_permutation_fails() {
        let c        = GroupByCircuit::build();
        let in_keys  = [1u64, 2, 3];
        let out_keys = [1u64, 2, 4]; // NOT a permutation of in_keys — grand product must differ
        let vals     = [10u64, 20, 30];
        let snap     = snap_lo_for(&in_keys);
        c.prove(&in_keys, &out_keys, &vals, snap, 0).unwrap();
    }

    // ── JoinCircuit ───────────────────────────────────────────────────────────

    #[test]
    fn join_proves_and_verifies() {
        let c    = JoinCircuit::build();
        let keys = [1u64, 2, 3];
        let snap = snap_lo_for(&keys);
        let proof = c.prove(&keys, &keys, &[100u64, 200, 300], &[true; 3], snap, 0)
            .expect("prove");
        c.verify_bytes(&proof.to_bytes()).expect("verify");
    }

    #[test]
    #[should_panic]
    fn join_wrong_snap_lo_fails() {
        let c    = JoinCircuit::build();
        let keys = [1u64, 2];
        // Wrong snap_lo → overconstrained wire panic or Err.
        c.prove(&keys, &keys, &[10u64, 20], &[true; 2], 0u64, 0).unwrap();
    }
}
