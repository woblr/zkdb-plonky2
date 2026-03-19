# zkDB — Technical Limitations Report

This document explains the technical reasons behind each known limitation in the current zkDB implementation. These are deliberate design decisions, not unnoticed bugs.

---

## 1. JOIN Relational Completeness — ❌ Not Proved

**Status in SQL Support table:** `JOIN completeness (cross-position matches)` ❌

### What is proved today

`JoinCircuit` uses a **zip model**: left-table row `i` is aligned with right-table row `i`. If `left[i] == right[i]`, the circuit enforces `sel[i] = 1` (positional completeness constraint 3):

```
is_equal(left_keys[i], right_keys[i]) × (1 − sel[i]) = 0
```

This means: if the keys match at position `i`, the selector must be 1. A prover cannot omit a match at any aligned position.

### What is not proved

Relational SQL JOIN semantics require: if `left[3] = 47` and `right[9] = 47`, that pair must appear in the result — regardless of their positions. The zip model does not enforce this because it only checks `left[i]` against `right[i]`, not `left[i]` against all of `{right[0], ..., right[n]}`.

A prover controlling the witness alignment can place `right[3] = 99` (not 47) and omit the cross-position match entirely without violating any circuit constraint.

### Why it is not fixed yet

Full relational completeness requires a **lookup argument**:

```
"left[i] ∈ { right[0], right[1], ..., right[n] }"
```

This is proved by Logup or plookup — a grand-product accumulator over the set membership claim. In Plonky2, this adds roughly 200–300 lines of circuit code, an additional accumulator target, and a second challenge derivation. It is the next planned circuit milestone.

---

## 2. LIMIT / TOP-K — ❌ Rejected

**Status:** Returns an explicit `UNSUPPORTED` error at plan compile time.

### Why `LIMIT k` cannot be proved with the current circuit design

Proving `SELECT ... ORDER BY col LIMIT k` means proving:

1. The output is a permutation of the input (already done by `SortCircuit`).
2. The output contains **exactly k rows**.
3. The output rows are the **lexicographically first k** rows of the sorted sequence.

Claim 3 requires a **prefix commitment**: the prover must commit to a boundary point in the sorted array and prove that everything after it was cut off correctly. This requires either:

- A **range proof** — "the (k+1)-th element, if it exists, is ≥ the k-th element and was excluded"
- A **prefix selector** — a boolean mask `[1,1,...,1,0,0,...,0]` with the boundary proved to be at position k

The current `SortCircuit` treats all 128 rows uniformly; there is no concept of a "result window". Adding `LIMIT` support without this produces silent correctness failures (prover can return any k rows claiming they are the top-k), so the feature is explicitly rejected rather than partially implemented.

---

## 3. Multi-Operator Composition — ❌ Rejected

**Status:** Returns an explicit `UNSUPPORTED` error at plan compile time.

### Why `ORDER BY col GROUP BY other_col` cannot be proved in a single proof

Each operator is a separate circuit: `SortCircuit`, `GroupByCircuit`, `AggCircuit`, `JoinCircuit`. A composed query like `ORDER BY salary GROUP BY department` requires chaining two circuits where the output commitment of the first becomes a verified input to the second:

```
Proof₁ (SortCircuit)     → output commitment  C₁  =  Poseidon(sorted_vals)[0]
Proof₂ (GroupByCircuit)  → must prove: its PI[0] == C₁
```

For `verify()` to accept this chain, a **verifier circuit** must exist that:
1. Reads `Proof₁` and extracts `C₁` as a verified public input.
2. Passes `C₁` to `Proof₂`'s witness as the anchored input commitment.
3. Produces a single root proof attesting to the entire pipeline.

This is **Incrementally Verifiable Computation (IVC)** — Plonky2 has the API (`add_recursive_proofs_target`), but setting it up correctly requires careful VK management and PI threading. Single-operator proofs were completed first; composition is the next planned milestone.

---

## 4. Recursive Proof Folding (Cross-Chunk) — ❌ Not Implemented

**Status:** `fold()` method is a stub. Multi-chunk datasets produce independent per-chunk proofs.

### Why folding is needed

The circuits are fixed at **MAX_ROWS = 128** per instance. A 1 000-row dataset produces `ceil(1000/128) = 8` independent chunk proofs. Each chunk proof attests to `SUM(chunk_i)` and `COUNT(chunk_i)` independently. There is currently no single proof that says "the total SUM and COUNT across all 8 chunks is X".

### What folding would look like

```
ChunkProof[0]: sum=S₀, count=C₀
ChunkProof[1]: sum=S₁, count=C₁
...
ChunkProof[7]: sum=S₇, count=C₇

FoldedProof: sum = S₀+S₁+...+S₇, count = C₀+C₁+...+C₇
             AND each ChunkProof[i] is verified inside the folded circuit
```

Plonky2's `CircuitBuilder::add_recursive_proofs_target()` supports this pattern. The implementation requires embedding each chunk's `VerifierData` into the folding circuit and constructing an accumulating PI for sum and count. This is the largest remaining engineering task.

---

## 5. Nested Queries / Subqueries — ❌ Not Proved

**Status:** Parsed but not proved; falls through to aggregate path.

### Why subqueries are difficult to prove

```sql
SELECT * FROM (SELECT SUM(salary) FROM employees) sub WHERE sub.sum > 100000
```

This requires two circuit executions where the **output of the inner query becomes the input witness of the outer query**. Concretely:

- `Proof_inner`: proves `SUM(salary) = X` over the employees table.
- `Proof_outer`: proves `X > 100000`, where `X` is taken from `Proof_inner`'s public inputs.

The outer circuit must **verify `Proof_inner` inside itself** — this is again IVC / recursive proof composition. The same infrastructure gap as multi-operator composition applies. Until `fold()` and recursive targets are implemented, the SQL parser accepts these queries but the physical planner flattens the inner subquery into the outer aggregate scan, silently dropping the inner proof obligation.

---

## 6. `result_commitment` (Full Result Set) — ⚠️ Partial

**Status:** `AggCircuit` carries `PI[4] = Poseidon(sum, count)[0]` as an in-circuit commitment. The field `result_commitment` (Blake3) is unproven metadata.

### What is proved

`AggCircuit` computes `result_commit_lo = Poseidon(sum, count)[0]` as a circuit-constrained public input (`PI[4]`). Because `sum` and `count` are themselves proved values (`PI[2]` and `PI[3]`), this Poseidon commitment is cryptographically bound to the query result:

```
PI[4] = Poseidon(PI[2], PI[3])[0]
```

`verify()` cross-checks `PI[4]` against `artifact.public_inputs.result_commit_poseidon_proved`.

### What is not proved

The field `result_commitment_blake3_metadata` (also called `unsafe_metadata_commitment_hex`) is computed **after** the proof is generated by hashing the full result rows with Blake3. This hash is not constrained by any circuit; a tampered result set with a re-computed Blake3 hash would pass the metadata check while the Poseidon PI check would catch it.

**Rule:** Security-critical consumers must use `result_commit_poseidon_proved` (PI[4]) only. The Blake3 field is for content-addressing and deduplication, not for cryptographic integrity.

### Gap for Sort, Join, GroupBy

For non-Agg circuits, no output commitment PI exists yet. The result set is computed post-proof and attached to the artifact as metadata. Adding an output Poseidon commitment to each circuit type is a planned improvement.

---

## 7. `result_sum` (PI[2]) and `result_count` (PI[3]) — ✅ Proved

These are **fully circuit-constrained**. `AggCircuit` enforces:

```
sum   = Σ values[i] × sel[i]    for i in 0..128
count = Σ sel[i]                 for i in 0..128
```

Both are registered as public inputs and cross-checked by `verify()`:

```rust
if pis.agg_sum != artifact.public_inputs.result_sum {
    return Err("result_sum mismatch — proof is for a different query result");
}
```

A prover cannot claim a different `sum` or `count` without producing a proof that fails verification. These are the gold-standard proved values in the current implementation.

---

## 8. Blake3 Merkle Root — ❌ Not In-Circuit

**Status:** Decorative; used for content-addressing only.

### Why Blake3 cannot be used inside a Plonky2 circuit efficiently

Plonky2 circuits operate over the **Goldilocks field** (p = 2⁶⁴ − 2³² + 1). All arithmetic is native 64-bit field arithmetic. Gate costs are measured in field multiplications and additions.

Blake3 operates with 32-bit word XOR, bit-rotation, and mixing functions. Implementing Blake3 in a Goldilocks circuit requires:
- Decomposing each 64-bit field element into 32-bit words
- Emulating each XOR and rotate as bit-decomposition constraints
- Approximately **1 000–2 000 constraints per Blake3 permutation**

For a Merkle root over 1 000 rows, this multiplies to millions of constraints — completely impractical.

**Poseidon** was designed specifically for ZK-friendly circuits over prime fields. In Goldilocks, a `t=8` Poseidon permutation costs approximately **250 constraints**. This is why all in-circuit commitments (snapshot binding, secondary payload, output commitment, group output) use Poseidon.

Blake3 is retained for **content-addressed IDs** (dataset IDs, artifact IDs, snapshot content hashes) where the goal is fast deduplication and deterministic naming, not cryptographic proof.

---

## Summary

| Limitation | Root cause | Fix path |
|---|---|---|
| JOIN cross-position completeness | No lookup argument (Logup/plookup not yet implemented) | Add grand-product set-membership accumulator |
| LIMIT / TOP-K | No prefix selector or range proof for output window | Add boundary PI + prefix mask constraint |
| Multi-operator composition | No IVC / recursive proof chaining | Implement `add_recursive_proofs_target` folding |
| Cross-chunk folding | `fold()` stub; no accumulating root proof | Implement Plonky2 recursive folding |
| Nested subqueries | Same as multi-operator composition | IVC prerequisite |
| result_commitment (Sort/Join/GroupBy) | Output Poseidon PI missing from non-Agg circuits | Add output commitment PI to each circuit |
| Blake3 in-circuit | ~1 000–2 000 constraints per hash, impractical | Not needed; Poseidon covers all ZK commitment needs |
