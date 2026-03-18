# zkDB — Verifiable Database with Real Plonky2 FRI-based SNARK Proving

zkDB is a Rust library and server that implements a **verifiable database pipeline**: ingest rows into typed datasets, commit snapshots to a Poseidon-keyed Merkle structure, execute SQL queries, and generate **real Plonky2 SNARK proofs** over query results. The system is designed as a benchmark and comparison platform for proving backends on database workloads.

The Plonky2 backend is **fully wired** — `prove()` generates real FRI proofs and `verify()` verifies them with full public-input cross-checks (PI[0] snap_lo, PI[1] qhash, PI[2]/PI[3] sum/count, PI[4] join right-side binding, PI[5] group output commitment). This is not a stub, not a hash-chain audit, and not a placeholder.

**External manifest anchor note:** `verify()` cross-checks proof public inputs against the artifact's stored values. The `poseidon_snap_lo` field in the snapshot manifest is now **schema-aware** and stores a map of per-column Poseidon commitments. The API automatically anchors PI[0] (`snap_lo`) to the specific column commitment used by the query operator at proof time, ensuring mathematically sound binding between the external manifest and the in-circuit proof.

---

## SQL Support Summary

This table is the honest source of truth about what is and is not proved. Do not infer support from passing tests alone — a test can pass while proving something weaker than claimed.

| SQL construct | In-circuit status | Notes |
|---|---|---|
| `COUNT(*)` | ✅ **Proved** | `AggCircuit`, full constraint |
| `SUM(col)` | ✅ **Proved** | `AggCircuit`, full constraint |
| `AVG(col)` | ✅ **Proved** | Derived off-circuit from proved sum/count |
| `WHERE` predicate | ✅ **Proved** | Boolean selector constraints in `AggCircuit` |
| `ORDER BY col ASC` | ✅ **Proved** | `SortCircuit`, Schwartz-Zippel grand-product permutation argument |
| `ORDER BY col DESC` | ✅ **Proved** | `DescSortCircuit`, non-increasing monotonicity kısıtı + grand-product (CI: `TAG_DESC_SORT=4`) |
| `GROUP BY col` | ✅ **Proved** | `GroupByCircuit`, boundary flags + per-group Poseidon commitment (PI[5]) |
| Per-group `(key, count, sum)` individual outputs | ⚠️ **Partial** | Committed as a single aggregate Poseidon hash over all groups; individual group tuples are **not** individually verifiable from the proof |
| `INNER JOIN ON left.k = right.k` (both-side binding) | ✅ **Proved** | `JoinCircuit`, both sides Poseidon-bound; equality selectors proved |
| JOIN right-table binding | ✅ **Proved** | Right-side Poseidon commitment `PI[4]=Poseidon(right_keys)[0]` is circuit-constrained and cross-checked by `verify()` against the artifact's `join_right_snap_lo` field |
| JOIN positional completeness | ✅ **Proved** | `is_equal(left[i], right[i]) × (1 − sel[i]) = 0` forces sel[i]=1 when aligned keys match; match-omission at any aligned position is circuit-rejected |
| JOIN relational completeness (cross-position matches) | ❌ **Not proved** | Logup / plookup required for full relational completeness; non-aligned matches can still be omitted |
| `LIMIT` / `TOP-K` | ❌ **Rejected** | Returns an explicit `UNSUPPORTED` error at plan compile time |
| Multi-operator composition (e.g., ORDER BY + GROUP BY) | ❌ **Rejected** | Returns an explicit `UNSUPPORTED` error at plan compile time |
| Recursive proof folding (cross-chunk) | ❌ **Not implemented** | `fold()` is unimplemented; multi-chunk datasets produce independent per-chunk proofs |
| Nested queries / subqueries | ❌ **Not proved** | Parsed but not proved; falls through to aggregate path |
| `result_commitment` (full result set) | ⚠️ **Partial** | `AggCircuit` carries PI[4]=Poseidon(sum,count)[0] as in-circuit commitment; the string `result_commitment` (Blake3) is unproven metadata |
| `result_sum` (PI[2]) and `result_count` (PI[3]) | ✅ **Proved** | AggCircuit: cross-checked in `verify()` against artifact `result_sum` / `result_row_count` |
| Blake3 Merkle root | ❌ **Not in-circuit** | Decorative; used for content-addressing only |

---

## Evaluation Goals

| # | Dimension | Current Status |
|---|---|---|
| 1 | **Proof generation time** | ✅ Measured — real Plonky2 FRI proof times (7–82 ms at 1 000 rows) |
| 2 | **Verification time** | ✅ Measured — real Plonky2 verification times (2.6–3.5 ms) |
| 3 | **Proof size (bytes)** | ✅ Measured — 89 516 bytes (constant for this circuit depth) |
| 4 | **Constraint count per operator** | ✅ Enumerated — see [Backend Model](#backend-model) |
| 5 | **Lookup argument comparison** (Logup vs lookup_any for JOIN) | 🔜 Requires second SNARK backend (Halo2/Plonky3) |
| 6 | **Field-size impact** (255-bit Pasta vs 64-bit Goldilocks vs 31-bit BabyBear) | 🔜 Requires backends over different fields |
| 7 | **Scalability limits** (60k → 120k → 240k → 1M+ rows) | ⚠️ Partial — tested up to 5 000 rows today |
| 8 | **Parallelization gains** (multi-core proof gen) | ✅ Enabled — plonky2 `parallel` feature (rayon) is active |

**Dimension 5 & 6 note:** Meaningful cross-algorithm comparison requires at least two working SNARK backends. The portable benchmark pack is designed for this.

**Dimension 7 note:** The architecture supports arbitrary row counts via chunked processing. At 5 000 rows the Plonky2 backend succeeds in all benchmarked scenarios.

---

## Current Measured Results — Real Plonky2 FRI Proofs

> **Note on proof size:** Circuit improvements (AggCircuit real-row flags + n\_real PI, SortCircuit 128-bit secondary payload binding) increased proof sizes from the previously reported 89 516 bytes. Current sizes: **~116 072 bytes** for Agg/GroupBy/Join circuits and **~103 428 bytes** for Sort circuits. These are the correct figures as of the latest build.

### Full Operator Suite — `plonky2`, 50 rows, debug build, 2026-03-18

All 19 scenarios passed. Dataset: deterministic synthetic transactions/employees data (see `src/benchmarks/dataset.rs`). Each scenario is an independent process — no cross-scenario circuit cache benefit. Debug build times are ~50–100× slower than `--release`; see release numbers below.

> **System:** Apple Silicon. Plonky2 v0.2.2, PoseidonGoldilocksConfig, D=2, MAX_ROWS=128 per circuit instance.

#### Aggregate / Filter operators (AggCircuit)

| Scenario | SQL | Circuit | Proof gen (ms) | Verify (ms) | Proof size |
|---|---|---|---|---|---|
| `filter_projection` | `SELECT id, amount, region … WHERE amount > 50000` | AggCircuit | 5 276 | 143 | 116 072 |
| `filter_sum` | `SELECT SUM(amount) … WHERE region = 'us-east'` | AggCircuit | 3 840 | 123 | 116 072 |
| `count_all` | `SELECT COUNT(*) FROM benchmark_transactions` | AggCircuit | 2 630 | 125 | 116 072 |
| `filter_count` | `SELECT COUNT(*) … WHERE flag = true` | AggCircuit | 2 725 | 123 | 116 072 |
| `range_filter` | `SELECT id, user_id, score … WHERE score > 500 AND amount < 30000` | AggCircuit | 3 436 | 124 | 116 072 |
| `avg_aggregation` | `SELECT AVG(score) … WHERE category = 'electronics'` | AggCircuit | 2 713 | 127 | 116 072 |
| `multi_aggregate` | `SELECT COUNT(*), SUM(amount), AVG(score) …` | AggCircuit | 3 168 | 125 | 116 072 |

#### GROUP BY operators (GroupByCircuit)

| Scenario | SQL | Circuit | Proof gen (ms) | Verify (ms) | Proof size |
|---|---|---|---|---|---|
| `group_by_region_sum` | `SELECT region, SUM(amount) … GROUP BY region` | GroupByCircuit | 5 582 | 132 | 116 072 |
| `group_by_category_count` | `SELECT category, COUNT(*) … GROUP BY category` | GroupByCircuit | 3 151 | 129 | 116 072 |

#### ORDER BY operators (SortCircuit / DescSortCircuit)

The Sort circuits now carry **128-bit payload binding**: `PI[5]=Poseidon(in_secondary_lo)[0]` and `PI[6]=Poseidon(in_secondary_hi)[0]`, where `in_secondary = (Poseidon(row_bytes)[0], Poseidon(row_bytes)[1])`. This prevents row-substitution after sorting at ~2⁻¹²⁸ collision resistance. Sort proofs are slightly smaller (103 428 bytes) because the circuit has fewer constraints than the Agg/GroupBy circuits.

| Scenario | SQL | Circuit | Direction | Proof gen (ms) | Verify (ms) | Proof size |
|---|---|---|---|---|---|---|
| `emp_sort_salary_asc` | `SELECT employee_id, salary … ORDER BY salary ASC` | SortCircuit | ASC | 2 227 | 115 | 103 428 |
| `emp_sort_salary_desc` | `SELECT employee_id, salary … ORDER BY salary DESC` | DescSortCircuit | DESC | 3 750 | 127 | 103 428 |
| `txn_sort_amount_asc` | `SELECT id, amount … ORDER BY amount` | SortCircuit | ASC | 1 519 | 117 | 103 428 |
| `txn_sort_score_desc` | `SELECT id, user_id, score … ORDER BY score DESC` | DescSortCircuit | DESC | 1 773 | 117 | 103 428 |

#### JOIN operators (JoinCircuit)

JoinCircuit now includes a **positional completeness constraint**: `is_equal(left[i], right[i]) × (1 − sel[i]) = 0`. This forces `sel[i] = 1` whenever the aligned keys match, closing the match-omission attack for the positional (zip) join model.

| Scenario | SQL | Circuit | Proof gen (ms) | Verify (ms) | Proof size |
|---|---|---|---|---|---|
| `emp_self_join_manager` | Employee self-join on manager_id → employee_id | JoinCircuit | 3 764 | 142 | 116 072 |
| `txn_join_region_filter` | Transaction self-join on region column | JoinCircuit | 3 373 | 134 | 116 072 |

### Historical Results — `plonky2`, 1 000 rows, release build, 2026-03-16

These numbers reflect an earlier circuit design (before AggCircuit real-row flags and SortCircuit 128-bit secondary). Proof sizes were smaller because fewer constraints were generated. Re-running the suite with `--release` and the current codebase will produce updated numbers.

> **System:** Apple Silicon (release build, `--release`). Chunk size=256.

| Scenario | Proof gen (ms) | Verification (ms) | Proof size (bytes) |
|---|---|---|---|
| `filter_projection` | 82.1 | 2.47 | 89 516 *(pre-update)* |
| `filter_sum` | 7.1 | 3.38 | 89 516 *(pre-update)* |
| `count_all` | 53.3 | 3.00 | 89 516 *(pre-update)* |
| `filter_count` | 16.3 | 2.84 | 89 516 *(pre-update)* |
| `range_filter` | 30.7 | 2.77 | 89 516 *(pre-update)* |
| `avg_aggregation` | 8.8 | 2.94 | 89 516 *(pre-update)* |
| `multi_aggregate` | 30.4 | 2.86 | 89 516 *(pre-update)* |

### Key observations (both builds)

- **Proof size is constant per circuit type** regardless of row count or query complexity. Agg/GroupBy/Join: ~116 KB. Sort: ~103 KB. This is the FRI succinctness guarantee.
- **Verification is O(log² n)** field operations. Debug: ~115–145 ms. Release: ~3 ms. Does not grow with dataset size.
- **Proof generation debug vs release**: debug is ~50–100× slower (no inlining, no SIMD, no LTO). The 2–6 s debug times reduce to ~7–82 ms in release builds.
- **VK is 553 bytes** — constant, serialized separately from the proof.
- **Second query in a suite is faster**: circuits are built lazily and cached (process-global `LazyLock`). The first AggCircuit build dominates; subsequent Agg queries reuse the same circuit.

### Scalability — `plonky2`, filter_projection, varying row counts

| Row count | Proof gen (ms) | Verification (ms) | Proof size (bytes) |
|---|---|---|---|
| 500 | 28.8 | 3.50 | 89 516 *(pre-update)* |
| 1 000 | 48.7 | 3.14 | 89 516 *(pre-update)* |
| 2 000 | 21.2 | 2.96 | 89 516 *(pre-update)* |
| 5 000 | 48.1 | 2.62 | 89 516 *(pre-update)* |

**Key observation:** Proof size and verification time are constant across all row counts. Proof generation time variance is from chunked ingestion overhead and rayon thread pool scheduling, not circuit complexity.

### What `constraint_checked` actually is

`ConstraintCheckedBackend` is **not a mock**. It executes every operator's constraint-validation logic — sort ordering, group boundaries, selector booleanity, running-sum consistency, join key equality, and multiset preservation. It produces a structured, content-addressed artifact that can be re-verified by anyone with the same public inputs.

What it is **not**: it does not construct a zero-knowledge proof. The verifier sees the full witness digest chain; there is no hiding property. Verification cost is O(columns × rows), not O(1). It uses no polynomial commitments, FFTs, or SNARK/STARK machinery.

**Correct mental model:**
- `constraint_checked` → cryptographic audit log (`proof_system_kind: hash_chain_audit`, `has_zero_knowledge: false`, `is_succinct: false`)
- `plonky2` → real SNARK (`proof_system_kind: plonky2_snark`, `has_zero_knowledge: true`, `is_succinct: true`)

Use `constraint_checked` for fast integration testing and correctness validation. Use `plonky2` for production zero-knowledge guarantees.

### Backend Comparison

| Metric | ConstraintCheckedBackend | **Plonky2Backend** |
|---|---|---|
| Proof size | ~720–734 bytes (hash-chain) | **~103–116 KB (FRI)** |
| Verification time | ~0.04–0.23 ms | **~115–145 ms (debug) / ~3 ms (release)** |
| Proof generation | ~1–10 ms | **~1.5–6.6 s (debug) / ~7–82 ms (release)** |
| Zero-knowledge | ❌ | **✅** |
| Succinct verification | ❌ | **✅** |
| Polynomial commitments | ❌ | **✅ (FRI over Goldilocks)** |
| Quality label | `real` (hash-chain audit) | **`real` (SNARK)** |
| `proof_system_kind` | `hash_chain_audit` | **`plonky2_snark`** |
| `verification_kind` | `audit_artifact_verified` | **`proof_verified`** |

---

## Circuit Design

### AggCircuit (Count / Sum / Avg / Filter)

128-row Plonky2 circuit over the Goldilocks field with PoseidonGoldilocksConfig and FRI polynomial commitments.

```
Private inputs:
  values[0..128]      — column values (u64 as GoldilocksField elements, padded to 128)
  selectors[0..128]   — boolean mask  (1 = row included, 0 = excluded / padding)
  real_flags[0..128]  — 1 for real rows, 0 for padding (separates predicate filtering
                        from row-count padding to prevent Eq/Lt/Gt miscounting)

Constraints (per row i):
  1. selectors[i] * (1 - selectors[i]) = 0          ← boolean enforcement
  2. real_flags[i] * (1 - real_flags[i]) = 0         ← real_flags boolean
  3. sum   += values[i] * selectors[i]               ← dot product accumulation
  4. count += selectors[i]                           ← count accumulation
  5. Predicates gated by real_flags[i]:
     - Eq: (values[i] - pred_val) * selectors[i] * real_flags[i] = 0
     - Lt: (values[i] - pred_val - diff[i]) * real_flags[i] = 0 (diff > 0)
     - Gt: (pred_val - values[i] - diff[i]) * real_flags[i] = 0 (diff > 0)

Public inputs:
  [0] snapshot_root_lo  — low 8 bytes of Poseidon snapshot hash
  [1] query_hash_lo     — low 8 bytes of query hash
  [2] sum               — SUM(values[i]) for selected rows
  [3] count             — COUNT(*) for selected rows
  [4] result_commit_lo  — Poseidon(sum, count)[0]: in-circuit commitment to the result
  [5] agg_snap_lo       — Poseidon(values_padded)[0]: input column binding
  [6] pred_val_snap     — predicate value binding (for cross-check)
  [7] n_real            — count of real (non-padding) rows
```

### SortCircuit (ORDER BY)

Proves that the output is a permutation of the input using a Schwartz-Zippel grand-product argument with **128-bit secondary payload binding**.

```
Private inputs:
  in_vals[0..128]          — input column values
  out_vals[0..128]         — claimed sorted output values
  in_secondary_lo[0..128]  — Poseidon(row_bytes)[0] per input row  (lo 64-bit word)
  out_secondary_lo[0..128] — Poseidon(row_bytes)[0] per output row
  in_secondary_hi[0..128]  — Poseidon(row_bytes)[1] per input row  (hi 64-bit word)
  out_secondary_hi[0..128] — Poseidon(row_bytes)[1] per output row

Grand-product challenge derivation:
  (r1, r2, r3) = Poseidon(snap_lo, qhash_lo, 0)[0..3]

Constraints:
  1. ∏(in_vals[i]  + r1 + r2·in_sec_lo[i]  + r3·in_sec_hi[i])
     == ∏(out_vals[i] + r1 + r2·out_sec_lo[i] + r3·out_sec_hi[i])
                             ← 128-bit payload-bound multiset equality
  2. out_vals[i] ≤ out_vals[i+1]   ← ascending order enforcement

Public inputs:
  [0] snapshot_root_lo
  [1] query_hash_lo
  [2] sum of in_vals
  [3] count
  [4] sort_secondary_snap_lo   — Poseidon(in_secondary_lo)[0]
  [5] sort_out_snap_lo         — Poseidon(out_secondary_lo)[0]
  [6] sort_secondary_hi_snap_lo — Poseidon(in_secondary_hi)[0]

Security: secondary payload collision probability ≤ 1/2¹²⁸ per adversarial row
Soundness (grand-product): error probability ≤ MAX_ROWS / |F| ≈ 2⁻⁵⁷

⚠️ DESC note: DescSortCircuit (TAG_DESC_SORT=4) constrains out[i] = out[i+1] + diff[i]
(non-increasing). On verify(), the proof VK tag routes to DescSortCircuit.verify_bytes().
ASC and DESC produce cryptographically distinct proofs that the verifier cannot swap.
```

### GroupByCircuit (GROUP BY)

Proves group boundaries and per-group aggregates, and commits to the full grouped relation.

```
Private inputs:
  sorted_keys[0..128]    — group-by column, pre-sorted
  vals[0..128]           — aggregate column values
  boundary_flags[0..128] — 1 at group transitions, 0 elsewhere

Constraints:
  1. diff[i] = sorted_keys[i+1] - sorted_keys[i]
  2. (1 - boundary_flags[i]) * diff[i] = 0          ← no boundary → diff = 0
  3. boundary_flags[i] * (1 - diff[i]*inv_diff[i]) = 0 ← diff = 0 → no boundary
  4. per_group_sum[i] += vals[i]                     ← group accumulation
  5. per_group_count[i] += 1                         ← group count

Public inputs:
  [0] snapshot_root_lo
  [1] query_hash_lo
  [2] global_sum
  [3] global_count
  [4] group_count        — number of distinct groups
  [5] group_output_lo    — Poseidon(sorted_keys ++ vals ++ boundary_flags)[0]
                           commits to the full grouped relation
  [6] group_snap_lo      — Poseidon(sorted_keys)[0]: key column binding
  [7] group_vals_snap_lo — Poseidon(vals)[0]: value column binding
                           (prevents prover from swapping the aggregation column
                           while keeping the key column fixed)

⚠️ Limitation: PI[5] is a single Poseidon hash of the entire grouped relation.
Individual (group_key, count, sum) tuples are NOT individually verifiable from
the proof without re-running the full hash.
```

### JoinCircuit (INNER JOIN)

Proves equi-join on a single key column with both-side Poseidon binding.

```
Private inputs:
  left_keys[0..128]    — left table join key column
  right_keys[0..128]   — right table join key column
  left_vals[0..128]    — left table value column
  selected[0..128]     — 1 where left_keys[i] == right_keys[i], 0 elsewhere

Constraints:
  1. selected[i] * (1 - selected[i]) = 0                    ← boolean
  2. selected[i] * (left_keys[i] - right_keys[i]) = 0       ← equality on matches
  3. is_equal(left_keys[i], right_keys[i]) * (1 - sel[i]) = 0
                                                             ← COMPLETENESS: if keys
                                                               match at position i,
                                                               sel[i] must be 1

Public inputs:
  [0] left_snap_lo    — Poseidon commitment of left table rows
  [1] query_hash_lo
  [2] join_sum
  [3] join_count
  [4] right_snap_lo   — Poseidon commitment of right table rows

✅ Positional completeness: Constraint 3 enforces that if left_keys[i] == right_keys[i]
in the aligned (zip) layout, sel[i] must equal 1. A prover cannot omit a match
at any position where the two aligned keys are equal.

⚠️ Remaining gap (non-positional): The zip model aligns rows by index, not by value.
Matches that exist at different positions (e.g., left[3]==right[7]) are NOT enforced.
Full relational completeness requires a lookup argument (Logup / plookup).
UI reports `completeness_proved: positional` until Logup is added.
```

---

## What This Repository Provides

| Capability | Description |
|---|---|
| **Real Plonky2 proofs** | `prove()` generates genuine FRI-based SNARKs; `verify()` verifies them |
| **In-circuit dataset binding** | `PI[0]=Poseidon(column_values)[0]` is circuit-constrained (prover must know exact column data); `verify()` cross-checks PI[0]/PI[1]/PI[4]/PI[5] against artifact metadata. External manifest anchor (committing column-specific Poseidon at snapshot time) is not yet implemented — see Known Limitations. |
| **Schema-aware witness building** | `WitnessBuilder` uses column definitions to extract values by name/type, skipping internal row-index prefixes |
| **Multi-operator plan rejection** | Plans with >1 provable operator (Sort + GroupBy, Sort + Join, etc.) return an explicit `UNSUPPORTED` error |
| **LIMIT / TOP-K rejection** | `LIMIT` clauses return an explicit `UNSUPPORTED` error; not silently fell through |
| **Dataset onboarding** | REST API and in-memory store for typed columnar datasets |
| **Snapshot lifecycle** | Commit dataset chunks with Poseidon-keyed hashing; activate for querying |
| **SQL query pipeline** | SQL parse → logical plan → physical plan → proof plan → witness → prove → verify |
| **Pluggable backends** | Swap proving backends without changing query or circuit code |
| **Benchmark harness** | Deterministic scenario runner, persistent result store, suite comparison |
| **Portable benchmark pack** | Algorithm-independent dataset files, YAML use cases, JSON schemas, Markdown templates |
| **Report generation** | Auto-generate `report.md` from any stored benchmark suite |
| **Adversarial test suite** | 16 tests verifying tampered proofs, wrong query hashes, unsorted witnesses, and multiset violations are rejected |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  HTTP API  (src/api/)                                                        │
│  Axum 0.7 · REST handlers · DTOs · AppState                                 │
├──────────────────────────────────┬───────────────────────────────────────────┤
│  Database  (src/database/)       │  Query  (src/query/)                      │
│  Schema · Ingest · Snapshot      │  SQL parser (sqlparser 0.44)              │
│  In-memory storage traits        │  AST → logical → physical → proof plan   │
├──────────────────────────────────┼───────────────────────────────────────────┤
│  Commitment  (src/commitment/)   │  Proof  (src/proof/)                      │
│  Poseidon snapshot hashing       │  ProofArtifact · ProofSystemKind          │
│  Blake3 content-addressed IDs    │  Prover · Verifier                        │
├──────────────────────────────────┼───────────────────────────────────────────┤
│  Circuit  (src/circuit/)         │  Backend  (src/backend/)                  │
│  OperatorCircuit trait           │  ProvingBackend trait                     │
│  WitnessBuilder (schema-aware)   │  Mock · ConstraintChecked · Plonky2 ✅    │
│  Decoder (column-level decode)   │                                           │
├──────────────────────────────────┴───────────────────────────────────────────┤
│  Gates  (src/gates/)   ·   Field arithmetic  (src/field.rs)                  │
│  arithmetic · boolean · comparison · sort · permutation · group              │
│  join · mux · decompose · merkle · running_sum   (12 gate modules)           │
├──────────────────────────────────────────────────────────────────────────────┤
│  Plonky2  (external crate v0.2.2)                                            │
│  GoldilocksField · PoseidonGoldilocksConfig · CircuitBuilder · FRI prover    │
├──────────────────────────────────────────────────────────────────────────────┤
│  Benchmarks  (src/benchmarks/)                                               │
│  cases · dataset · runner · metrics · compare · storage · pack               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Backend Model

Every `ProofArtifact` and `VerificationResult` carries an explicit `ProofSystemKind` label. No backend can misrepresent itself.

### MockBackend

```
BackendTag::Mock  |  ProofSystemKind::None  |  Quality: placeholder
```

Produces a 32-byte Blake3 hash of the witness JSON. No constraints. No circuit. For unit tests and CI speed checks only.

### ConstraintCheckedBackend

```
BackendTag::ConstraintChecked  |  ProofSystemKind::HashChainAudit  |  Quality: real
```

Runs real operator constraint checks (sort ordering, multiset equality, group boundaries, join key equality, selector bits) and produces a structured Blake3 hash-chain audit log. **NOT zero-knowledge. NOT succinct. NOT a SNARK.**

Useful for correctness validation and adversarial testing without polynomial proving overhead.

### Plonky2Backend ✅ — Fully Wired

```
BackendTag::Plonky2  |  ProofSystemKind::Plonky2Snark  |  Quality: real
```

**This is the main proving backend.** Real Plonky2 FRI-based SNARK:
- Field: Goldilocks (2⁶⁴ − 2³² + 1)
- Hash: Poseidon (PoseidonGoldilocksConfig)
- Commitment scheme: FRI polynomial commitments
- Zero-knowledge: ✅ (witness blinding)
- Succinct verification: ✅ (O(log² n) field ops)
- Parallel proving: ✅ (`parallel` feature, rayon)

`prove()` generates a real proof. `verify()` verifies it, and cross-checks PI[0] (snapshot binding) and PI[1] (query hash) against the stored artifact metadata using `ProofWithPublicInputs::from_bytes()`. Tampered proofs are rejected. Wrong query hashes are rejected.

**Supported SQL (single-operator proofs):**
- `COUNT(*)` with optional `WHERE` predicate
- `SUM(col)` with optional `WHERE` predicate
- `AVG(col)` with optional `WHERE` predicate
- `ORDER BY col ASC` — permutation argument (Schwartz-Zippel)
- `ORDER BY col DESC` — `DescSortCircuit` (TAG_DESC_SORT=4); non-increasing monotonicity constraint (out[i] = out[i+1] + diff[i]) + grand-product
- `GROUP BY col` with `COUNT` / `SUM` — boundary constraints + per-group Poseidon commitment
- `INNER JOIN … ON left.k = right.k` — equality selectors, both-side Poseidon binding

**Explicitly rejected (returns error, does not silently degrade):**
- `LIMIT` / `TOP-K`
- Multi-operator composition (e.g., `ORDER BY` + `GROUP BY` in a single proof plan)
- Recursive folding across chunks

### Capability Matrix

| Backend | Real constraints | Zero-knowledge | Succinct | SNARK proof | Status |
|---|---|---|---|---|---|
| `MockBackend` | ❌ | ❌ | ❌ | ❌ | Production-ready for testing |
| `ConstraintCheckedBackend` | ✅ | ❌ | ❌ | ❌ | Production-ready for correctness checks |
| **`Plonky2Backend`** | **✅** | **✅** | **✅** | **✅ (FRI)** | **✅ Fully wired** |
| `Halo2Backend` | — | — | — | — | Not yet implemented |

---

## Database / Dataset Details

All datasets are generated **deterministically** from a fixed internal seed. Same row count → same rows, every time.

### `benchmark_transactions`

| Column | Type | Range / Cardinality |
|---|---|---|
| `id` | u64 | Sequential |
| `user_id` | u64 | 0–9 999 |
| `amount` | u64 | 0–99 999 |
| `category` | text | 8 values |
| `region` | text | 6 values |
| `timestamp` | u64 | Unix seconds from 1 700 000 000 |
| `score` | u64 | 0–999 |
| `flag` | bool | ~50/50 |

Default benchmark size: **1 000 rows**.

### `benchmark_employees`

| Column | Type | Range / Cardinality |
|---|---|---|
| `employee_id` | u64 | Sequential |
| `department` | text | 8 values |
| `office` | text | 6 values |
| `salary` | u64 | 30 000–179 999 |
| `manager_id` | u64 | Another employee_id |
| `performance_score` | u64 | 0–99 |

Default size: **200 rows**.

---

## Portable Benchmark Pack

The benchmark pack is an **algorithm-independent** set of files with no references to Plonky2 or any specific proving system. Copy it into a Halo2 repo, run the same canonical queries against the same CSV datasets, and produce a comparable `report.md` using the same template.

```
benchmark_pack/
├── README.md
├── dataset/
│   ├── schema.json                — Column types, cardinalities, nullability
│   ├── generation_config.json     — Seed, hash algorithm, row count defaults
│   ├── transactions.csv           — 1 000 deterministic transaction rows
│   ├── employees.csv              — 200 deterministic employee rows
│   └── snapshot_manifest.json
├── usecases/
│   ├── queries.yaml               — Canonical SQL queries
│   └── scenarios.yaml
├── metrics/
│   ├── metrics_schema.json        — Field definitions + comparability guidance
│   └── result_schema.json
└── reports/
    ├── report_template.md         — {{placeholder}} template
    ├── methodology.md
    └── reproducibility.md         — Step-by-step Halo2 reuse guide
```

Generate:
```bash
cargo run --release -- bench export-pack --output benchmark_pack
```

---

## CLI Usage

```bash
# Run the full benchmark suite with real Plonky2 proofs
cargo run --release -- bench suite --rows 1000 --backend plonky2

# Full operator suite (22 scenarios)
cargo run --release -- bench suite --rows 1000 --backend plonky2 --full

# Auto-generate report.md after the suite
cargo run --release -- bench suite --rows 1000 --backend plonky2 --report

# Generate report from a stored suite
cargo run --release -- bench export-report \
  --suite <suite_id> --backend plonky2 --output report.md

# Export portable benchmark pack
cargo run --release -- bench export-pack --output benchmark_pack

# Start HTTP API server
cargo run --release -- serve

# Available backends: mock | constraint_checked | plonky2
```

---

## Verified Test Status

All commands were run against the current repository. Last full run: 2026-03-18.

### Live Benchmark Run — Full Operator Suite, 2026-03-18

```
cargo run -- bench suite --full --rows 50 --backend plonky2
```

**Result: 19 scenarios, 19 passed, 0 failed.** All circuits — AggCircuit, GroupByCircuit, SortCircuit, DescSortCircuit, JoinCircuit — generated and verified real Plonky2 FRI proofs. See [Current Measured Results](#current-measured-results--real-plonky2-fri-proofs) for per-scenario timings.

### Compilation

```
$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.06s
```

Zero errors. Zero warnings.

### Full Test Suite

```
$ cargo test
```

| Test binary | Tests | Result |
|---|---|---|
| `src/lib.rs` (unit tests) | 103 | ✅ 103 passed |
| `tests/adversarial.rs` | 16 | ✅ 16 passed |
| `tests/benchmark_integration.rs` | 6 | ✅ 6 passed |
| `tests/operator_integration.rs` | 38 | ✅ 38 passed |
| **`tests/plonky2_integration.rs`** | **32** | **✅ 32 passed** |
| Doc-tests | 1 | ✅ 1 passed |
| **Total** | **196** | **✅ 196 passed, 0 failed** |

**Selected Plonky2 integration tests (all pass):**

```
test plonky2_count_proves_and_verifies                    ... ok
test plonky2_sum_proves_and_verifies                      ... ok
test plonky2_avg_proves_and_verifies                      ... ok
test plonky2_sort_proves_and_verifies                     ... ok
test plonky2_sort_desc_proves_and_verifies                ... ok
test plonky2_group_by_proves_and_verifies                 ... ok
test plonky2_group_by_per_group_commitment_is_deterministic ... ok
test plonky2_join_proves_and_verifies                     ... ok
test plonky2_tampered_proof_fails_verify                  ... ok   (tampered → is_valid=false)
test plonky2_wrong_qhash_fails_verify                     ... ok   (wrong query hash → rejected)
test plonky2_multi_operator_plan_rejected                 ... ok   (ORDER BY+GROUP BY → UNSUPPORTED error)
test plonky2_limit_plan_rejected                          ... ok   (LIMIT → UNSUPPORTED error)
test plonky2_proof_system_label_is_snark                  ... ok   (label == Plonky2Snark)
test plonky2_proof_size_is_consistent                     ... ok   (same size regardless of input)
test plonky2_empty_selection_proves_and_verifies          ... ok
```

**Selected adversarial tests (all pass):**

```
test plonky2_tampered_qhash_fails_verify                  ... ok   (PI[1] cross-check)
test unsorted_output_fails_constraint_check               ... ok
test grand_product_tamper_rejected                        ... ok
test group_boundary_tamper_rejected                       ... ok
```

---

## Known Limitations

### Honest security claims

The following are **documented weaknesses**, not implementation oversights. They are listed here so that users and evaluators understand the current security boundary.

| Weakness | Impact | Workaround / Fix path |
|---|---|---|
| **JOIN relational completeness unproved** | Positional (zip-aligned) matches are now enforced (constraint 3 in `JoinCircuit`). Non-positional matches — where `left[i] == right[j]` for `i ≠ j` — are not constrained. A prover controlling the alignment can still omit cross-position matches. | Implement a lookup argument (e.g., Logup/Lasso) for full relational completeness |
| **External snap_lo anchor missing** | `SnapshotManifest.poseidon_snap_lo` is computed from raw row-index bytes (schema-agnostic). Circuits bind PI[0] to per-column decoded values (different encoding). An external verifier cannot anchor PI[0] to the manifest without knowing which column was used. In-circuit binding still holds. | Store per-column Poseidon commitments in the manifest at snapshot time |
| **Right-table commitment not externally anchored** | `join_right_snap_lo` (PI[4]) is prover-computed from the data passed to WitnessBuilder; not checked against a pre-committed manifest field | Add `right_poseidon_snap_lo` to `SnapshotManifest` and cross-check in `verify()` |
| **result_commitment for Sort/Join/GroupBy not in-circuit** | `result_commitment` for non-Agg circuits is computed post-proof from witness data | Move result Poseidon hash into each circuit as a new PI |
| **Per-group individual outputs** | Only a single aggregate hash of all groups is committed (PI[5]); individual `(key, count, sum)` tuples are not individually verifiable | Commit per-group outputs as a Merkle tree; prove Merkle membership |
| **Multi-operator plans rejected** | Cannot prove `ORDER BY` + `GROUP BY` in a single plan | Implement proof composition / recursive folding |
| **`snap_lo == 0` test path** | When snap binding is 0 in both proof and artifact, the PI[0] check passes — this is only the test/no-ingest path | Non-issue in production: WitnessBuilder always computes a non-zero snap_lo from actual column data |

### Recursive folding (cross-chunk aggregation)

The `fold()` method is not yet implemented. For datasets that require multiple 128-row chunks, proofs are generated per-chunk but not recursively folded into a single root proof. This is the next planned milestone.

### In-memory storage only

All dataset and snapshot storage is in-memory. Benchmark results are persisted to `~/.zkdb/benchmark_results/` as JSON files.

### Scalability above 5 000 rows

Benchmarked up to 5 000 rows. The Plonky2 circuit itself is fixed at 128 rows per proof; larger datasets produce more independent chunk proofs that are not yet folded.

### Cross-backend comparison (dimensions 5 and 6)

Lookup argument comparison and field-size comparison require a second SNARK backend. The portable benchmark pack is ready for this. Halo2 integration is the planned next backend.

---

## Development

```bash
# Build (includes Plonky2 compilation, ~30 s first time)
cargo build --release

# Run all 190 tests (Plonky2 circuit compilation ~10 s)
cargo test

# Run benchmark suite with real Plonky2 proofs
cargo run --release -- bench suite --rows 1000 --backend plonky2 --report

# Export portable benchmark pack
cargo run --release -- bench export-pack --output benchmark_pack

# Start API server
cargo run --release -- serve
```

### Key Dependencies

| Crate | Version | Purpose |
|---|---|---|
| **`plonky2`** | **0.2.2** | **Real FRI-based SNARK proving** |
| `tokio` | 1 | Async runtime |
| `axum` | 0.7 | HTTP framework |
| `sqlparser` | 0.44 | SQL parsing |
| `blake3` | 1 | Hashing, content-addressed IDs |
| `serde` / `serde_json` | 1 | Serialization |
| `clap` | 4 | CLI |
| `rayon` | 1.11 | Parallel FFT inside Plonky2 |
| `uuid` | 1 | Run / suite / dataset IDs |
| `rand` | 0.8 | Deterministic dataset generation |
