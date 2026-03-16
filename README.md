# zkDB — Verifiable Database with Pluggable Proving Backends

zkDB is a Rust library and server that implements a **verifiable database pipeline**: ingest rows into typed datasets, commit snapshots to a Blake3 Merkle tree, execute SQL queries, generate cryptographic proofs over query results, and verify them. The system is designed to be a **benchmark and comparison platform** for multiple proving backends and algorithms. The same query-to-proof pipeline runs today against a constraint-checked hash-chain backend; the same code and datasets will run against Plonky2, Halo2, and other SNARK/STARK systems as backends are wired in.

---

## Evaluation Goals

This repository is designed not only as a zkDB prototype but as a **structured benchmark platform** for comparing proving systems on database workloads. The following dimensions are the explicit research and measurement targets of this project.

### Measurement Dimensions

| # | Dimension | Current Status |
|---|---|---|
| 1 | **Proof generation time** | ✅ Measured on every benchmark run (`ConstraintCheckedBackend`) |
| 2 | **Verification time** | ✅ Measured on every benchmark run (`ConstraintCheckedBackend`) |
| 3 | **Proof size (bytes)** | ✅ Measured on every benchmark run (`ConstraintCheckedBackend`) |
| 4 | **Constraint count per operator** | ✅ Enumerated per circuit (see Backend Model section) |
| 5 | **Lookup argument comparison** (Logup vs lookup_any for JOIN-heavy queries) | 🔜 Planned — requires Plonky2/Halo2 backend |
| 6 | **Field-size impact** (255-bit Pasta vs 64-bit Goldilocks vs 31-bit BabyBear) | 🔜 Planned — requires multiple SNARK backends |
| 7 | **Scalability limits** (60k → 120k → 240k → 1M+ rows) | ⚠️ Partial — tested up to 5 000 rows today; architecture is scale-ready |
| 8 | **Parallelization gains** (multi-core proof generation) | 🔜 Planned — single-threaded today; Tokio runtime is in place |

**Honest note on dimensions 5–8:** These are research targets. Numbers 5 and 6 require at least two working SNARK backends to produce comparable data. Number 7 is technically runnable at larger scale using `--rows N`, but proof times for `ConstraintCheckedBackend` are dominated by ingestion and hashing (not polynomial arithmetic), so the numbers are not representative of a real SNARK at scale. Number 8 will be meaningful once a prover with real parallel FFTs is wired.

---

## Current Measured Results

All numbers below were observed by running `cargo run --release -- bench suite --rows 1000 --backend constraint_checked` on 2026-03-16. The backend is `ConstraintCheckedBackend` (quality label: **real**). These are not placeholder values.

> **Important:** `ConstraintCheckedBackend` is a hash-chain audit backend, NOT a zero-knowledge SNARK. Proof times and sizes below reflect Blake3-based constraint validation, not polynomial proving. See the [Backend Model](#backend-model) section for the exact meaning of these numbers.

### Standard Suite — `constraint_checked`, 1 000 rows, chunk size 256

| Scenario | Operator Family | Proof gen (ms) | Verification (ms) | Proof size (bytes) |
|---|---|---|---|---|
| `filter_projection` | Filter + Project | **8.06** | **0.22** | **728** |
| `filter_sum` | Filter + SUM | **6.10** | **0.05** | **733** |
| `count_all` | COUNT(\*) | **4.78** | **0.04** | **719** |
| `filter_count` | Filter + COUNT | **4.41** | **0.04** | **723** |
| `range_filter` | Compound filter + Project | **4.22** | **0.04** | **730** |
| `avg_aggregation` | Filter + AVG | **4.58** | **0.04** | **734** |
| `multi_aggregate` | COUNT + SUM + AVG | **4.73** | **0.04** | **727** |
| `select_star_limit` | Scan + LIMIT | **4.57** | **0.05** | **720** |

### Full Operator Suite — `constraint_checked`, 1 000 rows (selected scenarios)

| Scenario | Operator | Proof gen (ms) | Verification (ms) | Proof size (bytes) |
|---|---|---|---|---|
| `emp_group_by_dept_count` | GROUP BY + COUNT | **4.19** | **0.03** | **725** |
| `emp_group_by_dept_avg_salary` | GROUP BY + AVG | **4.26** | **0.04** | **730** |
| `emp_sort_salary_asc` | ORDER BY ASC | **4.84** | **0.04** | **724** |
| `emp_sort_salary_desc` | ORDER BY DESC | **4.92** | **0.04** | **719** |
| `emp_top10_salary` | Sort + LIMIT (top-K) | **6.17** | **0.04** | **726** |
| `txn_sort_amount_asc` | ORDER BY ASC | **6.83** | **0.14** | **723** |
| `emp_self_join_manager` | Equi-Join | **4.43** | **0.04** | **725** |
| `txn_join_region_filter` | Join + Filter | **4.43** | **0.05** | **729** |

### Scalability Observation (filter_projection scenario, `constraint_checked`)

| Row count | Proof gen (ms) | Verification (ms) | Proof size (bytes) |
|---|---|---|---|
| 500 | 3.05 | 0.16 | 725 |
| 1 000 | 8.64 | 0.23 | 726 |
| 2 000 | 11.61 | 0.16 | 727 |
| 5 000 | 21.25 | 0.13 | 733 |

**Observation:** Proof size is nearly constant (~720–733 bytes) regardless of row count because `ConstraintCheckedBackend` produces a fixed-size hash-chain envelope. Proof generation time scales roughly linearly with ingestion and hashing cost, not with polynomial degree. This is a property of the hash-chain backend, not of a real SNARK.

### MockBackend Comparison

`MockBackend` produces a 32-byte Blake3 hash of the witness as a placeholder proof. Timing numbers from MockBackend are labelled `[placeholder]` and are not meaningful for comparison — they reflect system overhead only.

| Metric | MockBackend (placeholder) | ConstraintCheckedBackend (real) |
|---|---|---|
| Proof size | 32 bytes | ~720–734 bytes |
| Verification time | ~0.003 ms | ~0.04–0.23 ms |
| Quality label | `placeholder` | `real` |
| Constraints enforced | None | Yes (per-operator) |

---

## Database / Dataset Details

All datasets are generated **deterministically** from a fixed internal seed using wrapping integer arithmetic. The same row count always produces the same rows. No external data source or file is required — datasets are generated in-process.

### `benchmark_transactions`

**Purpose:** stress filter, projection, aggregation, GROUP BY, ORDER BY, and top-K

| Column | Type | Range / Cardinality |
|---|---|---|
| `id` | u64 | Sequential (0…N−1) |
| `user_id` | u64 | 0–9 999 (10 000 unique values) |
| `amount` | u64 | 0–99 999 |
| `category` | text | 8 values: electronics, clothing, food, services, travel, entertainment, health, education |
| `region` | text | 6 values: us-east, us-west, eu-west, eu-central, ap-south, ap-east |
| `timestamp` | u64 | Unix seconds from 1 700 000 000 |
| `score` | u64 | 0–999 |
| `flag` | bool | ~50/50 split |

Default canonical size: **1 000 rows**. Portable pack default: **1 000 rows**.

### `benchmark_employees`

**Purpose:** stress GROUP BY department/office, AVG salary, ORDER BY, top-K, and equi-join with transactions

| Column | Type | Range / Cardinality |
|---|---|---|
| `employee_id` | u64 | Sequential (0…N−1) |
| `department` | text | 8 values: engineering, marketing, sales, finance, hr, operations, legal, research |
| `office` | text | 6 values |
| `salary` | u64 | 30 000–179 999 |
| `manager_id` | u64 | Points to another employee_id |
| `performance_score` | u64 | 0–99 |

Default canonical size: **200 rows**. Portable pack default: **200 rows**.

### Operator Coverage by Dataset

| Operator | Transactions | Employees |
|---|---|---|
| Filter | ✅ (amount, region, flag, score) | ✅ (dept, salary) |
| Projection | ✅ | ✅ |
| COUNT | ✅ | ✅ |
| SUM | ✅ (amount) | ✅ (salary) |
| AVG | ✅ (score) | ✅ (salary, performance_score) |
| GROUP BY | ✅ (category, region) | ✅ (department, office) |
| ORDER BY | ✅ (amount, score) | ✅ (salary, performance_score) |
| Top-K | ✅ | ✅ (top-10 salary) |
| Equi-Join | ✅ × employees | ✅ × transactions |

---

## What This Repository Provides

| Capability | Description |
|---|---|
| **Dataset onboarding** | REST API and in-memory store for typed columnar datasets |
| **Snapshot lifecycle** | Commit dataset chunks to a Blake3 Merkle tree; activate a snapshot for querying |
| **SQL query pipeline** | SQL parse → logical plan → physical plan → proof plan → witness → prove → verify |
| **Pluggable backends** | Swap proving backends without changing query or circuit code |
| **Benchmark harness** | Deterministic scenario runner, persistent result store, suite comparison |
| **Portable benchmark pack** | Algorithm-independent dataset files, YAML use cases, JSON schemas, Markdown templates |
| **Report generation** | Auto-generate `report.md` from any stored benchmark suite |
| **Adversarial test suite** | 15 tests verifying that tampered proofs, unsorted witnesses, and multiset violations are rejected |

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
│  Blake3 Merkle tree              │  ProofArtifact · PublicInputs             │
│  Content-addressed snapshot root │  ProofSystemKind · Prover · Verifier      │
├──────────────────────────────────┼───────────────────────────────────────────┤
│  Circuit  (src/circuit/)         │  Backend  (src/backend/)                  │
│  OperatorCircuit trait           │  ProvingBackend trait                     │
│  WitnessBuilder (per-operator)   │  Mock · ConstraintChecked · Plonky2 stub  │
├──────────────────────────────────┴───────────────────────────────────────────┤
│  Gates  (src/gates/)   ·   Field arithmetic  (src/field.rs)                  │
│  arithmetic · boolean · comparison · sort · permutation · group              │
│  join · mux · decompose · merkle · running_sum   (12 gate modules)           │
├──────────────────────────────────────────────────────────────────────────────┤
│  Cross-cutting: types.rs · policy/ · jobs/ · audit/ · crypto/ · utils/      │
├──────────────────────────────────────────────────────────────────────────────┤
│  Benchmarks  (src/benchmarks/)                                               │
│  cases · dataset · runner · metrics · compare · storage · pack (13 files)   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Module Summary

| Module | Purpose |
|---|---|
| `api/` | Axum router, REST handlers, DTOs, AppState |
| `database/` | Schema validation, row encoding, chunk ingestion, snapshot management |
| `commitment/` | Blake3 Merkle tree, snapshot root, commitment service |
| `query/` | SQL parser, logical/physical/proof plan pipeline, operator execution |
| `gates/` | Arithmetic gadgets: sort, permutation, group boundaries, join, running sum, mux, decompose |
| `circuit/` | `OperatorCircuit` trait, per-operator constraint validators, `WitnessBuilder` |
| `proof/` | `ProofArtifact`, `ProofSystemKind`, `PublicInputs`, prover/verifier interfaces |
| `backend/` | `ProvingBackend` trait + three implementations (Mock, ConstraintChecked, Plonky2 stub) |
| `benchmarks/` | Scenario runner, dataset generator, result storage, comparison, pack exporter |
| `policy/` | Access control and column-masking engine |
| `jobs/` | Async job registry for long-running prove tasks |

---

## Backend Model

The `ProvingBackend` trait is the single interface between the query pipeline and any cryptographic backend. Every artifact carries an explicit `ProofSystemKind` label. No backend can misrepresent itself.

### MockBackend

```
BackendTag::Mock  |  ProofSystemKind::None  |  Quality: placeholder
```

- Produces a **32-byte Blake3 hash** of the witness JSON as the "proof".
- No operator constraints are checked. No circuit is constructed.
- Verification passes iff the proof bytes are non-empty and derived from the same public inputs.
- **Use for:** unit tests, API smoke tests, CI speed checks.
- **Do not use for:** any correctness or performance claim.

### ConstraintCheckedBackend

```
BackendTag::ConstraintChecked  |  ProofSystemKind::HashChainAudit  |  Quality: real
```

Runs every operator circuit's `validate_witness()` with real mathematical checks:

| Operator | Constraints enforced |
|---|---|
| **TableScan** | Column length equality (1 constraint) |
| **Filter** | Selector bits are boolean; selected count == result_row_count (2 constraints) |
| **Projection** | Output column lengths consistent (1 constraint) |
| **Aggregate** | SUM/COUNT/AVG internal consistency |
| **GroupBy** | Key column sorted ascending; group boundaries valid; group count ≥ 1; multiset equality (input permutation preserved); running sum trace consistent (5 constraints) |
| **Sort** | Output is sorted (ASC or DESC); output is a valid permutation of input via `multiset_equal` (2 constraints) |
| **Join** | Key equality for all matched pairs; left/right column lengths equal; matched row count == result_row_count (3 constraints) |

Produces a structured Blake3 hash-chain artifact: `constraint_digest → public_input_binding → column_root → proof_envelope`.

**What it IS NOT:**
- NOT zero-knowledge — the verifier sees the full witness digest chain; there is no hiding property.
- NOT succinct — verification cost is O(columns × rows), not O(log n).
- NOT a SNARK/STARK — no polynomial commitments, no FFT, no elliptic curve arithmetic.
- NOT suitable for comparison with Plonky2 or Halo2 proof sizes/times.

**Honest label:** `ProofSystemKind::HashChainAudit`

### Plonky2Backend (stub)

```
BackendTag::Plonky2  |  ProofSystemKind::Plonky2Snark  |  Status: NOT YET WIRED
```

- **Honest stub.** `compile_circuit()` succeeds. `prove()` returns `Err("not yet wired")`. `verify()` returns `VerificationResult::invalid`.
- The Plonky2 crate is not yet in `Cargo.toml`.
- The stub exists so the registry, CLI, and API enumerate this backend with accurate capability flags (`is_zero_knowledge: true`, `is_succinct: true`) before a live prover is integrated.
- When wired: Plonky2 FRI-based SNARK over the Goldilocks field (2⁶⁴ − 2³² + 1), zero-knowledge, O(log n) verification, native recursive proof folding.

### Backend Capability Summary

| Backend | Real constraints | Zero-knowledge | Succinct | Foldable | Status |
|---|---|---|---|---|---|
| `MockBackend` | ❌ | ❌ | ❌ | ✅ (mock) | Production-ready for testing |
| `ConstraintCheckedBackend` | ✅ | ❌ | ❌ | ✅ | Production-ready for correctness validation |
| `Plonky2Backend` | ✅ (planned) | ✅ (planned) | ✅ (planned) | ✅ (planned) | Stub — not yet wired |
| `Halo2Backend` | — | — | — | — | Not yet implemented |

---

## Portable Benchmark Pack

The benchmark pack is an **algorithm-independent** set of files that specifies the complete benchmark workload without any reference to a proving system. It can be copied into a Halo2 repo, a RISC-V zkVM repo, or any other zkDB implementation and used to run identical workloads for cross-algorithm comparison.

### Directory Layout

```
benchmark_pack/
├── README.md
├── dataset/
│   ├── schema.json               — Column types, cardinalities, nullability
│   ├── generation_config.json    — Seed, hash algorithm, row count defaults
│   ├── transactions.csv          — 1 000 deterministic transaction rows
│   ├── employees.csv             — 200 deterministic employee rows
│   └── snapshot_manifest.json    — Chunk sizes, commit timestamps
├── usecases/
│   ├── queries.yaml              — 16 canonical SQL queries
│   └── scenarios.yaml           — Standard / group_by / sort / join / scale suites
├── metrics/
│   ├── metrics_schema.json       — Field definitions + comparability guidance
│   └── result_schema.json        — Portable result record schema, cross-backend rules
└── reports/
    ├── report_template.md        — Reusable template with {{placeholder}} syntax
    ├── methodology.md            — Pipeline description, quality flags, comparison rules
    └── reproducibility.md        — Step-by-step Halo2 reuse guide
```

### Generate the Pack

```bash
# Default sizes (1 000 transactions, 200 employees)
cargo run --release -- bench export-pack --output benchmark_pack

# Custom sizes
cargo run --release -- bench export-pack \
  --output benchmark_pack \
  --transactions 5000 \
  --employees 500
```

### Why Portable

- `dataset/` files contain row data and schemas only — no reference to any proof system.
- `usecases/` files contain SQL and operator labels only.
- `metrics/` files define what to measure and how to compare; backend-specific fields are deliberately excluded.
- `reports/` templates use `{{backend_name}}`, `{{proof_system}}`, and similar placeholders filled at report-generation time.

A Halo2 implementer can copy `benchmark_pack/` into their repository, implement the `ProvingBackend` trait, run the same 16 queries against the same CSV datasets, and generate a comparable `report.md` using the same template.

---

## Benchmark Use Cases

The standard suite covers **8 scenarios**. The full operator suite covers **22 scenarios**. The portable pack defines **16 canonical queries** in `benchmark_pack/usecases/queries.yaml`. The benchmark module contains **26 scenario definitions** across all suites.

| Query ID | Dataset | SQL operator(s) | Complexity |
|---|---|---|---|
| `filter_projection` | transactions | Filter + Project | linear |
| `range_filter` | transactions | Compound filter + Project | linear |
| `count_all` | transactions | COUNT(\*) | linear |
| `filter_count` | transactions | Filter + COUNT | linear |
| `filter_sum` | transactions | Filter + SUM | moderate |
| `avg_score` | transactions | Filter + AVG | linear |
| `multi_agg` | transactions | COUNT + SUM + AVG | moderate |
| `select_star_limit` | transactions | Scan + LIMIT | linear |
| `group_by_category` | transactions | GROUP BY + COUNT | moderate |
| `group_by_region_sum` | transactions | GROUP BY + SUM | moderate |
| `emp_group_by_dept_avg` | employees | GROUP BY + AVG | moderate |
| `emp_sort_salary_asc` | employees | ORDER BY ASC | heavy |
| `emp_sort_salary_desc` | employees | ORDER BY DESC | heavy |
| `emp_top10_salary` | employees | Sort + LIMIT (top-K) | moderate |
| `txn_sort_amount_asc` | transactions | ORDER BY ASC | heavy |
| `equi_join_baseline` | transactions × employees | Equi-Join | heavy |

---

## CLI Usage

### Run a Benchmark Suite

```bash
# Standard suite (8 scenarios)
cargo run --release -- bench suite --rows 1000 --backend constraint_checked

# Full operator suite (22 scenarios — includes sort, group_by, join)
cargo run --release -- bench suite --rows 1000 --backend mock --full

# Auto-generate report.md after the suite
cargo run --release -- bench suite --rows 1000 --backend constraint_checked --report

# Available backends: mock | constraint_checked | plonky2
```

### Run a Single Scenario

```bash
cargo run --release -- bench run \
  --sql "SELECT SUM(amount) FROM benchmark_transactions WHERE region = 'us-east'" \
  --rows 1000 \
  --backend constraint_checked
```

### Export the Portable Benchmark Pack

```bash
cargo run --release -- bench export-pack --output benchmark_pack
cargo run --release -- bench export-pack \
  --output benchmark_pack \
  --transactions 2000 \
  --employees 400
```

### List and Compare Stored Results

```bash
cargo run --release -- bench list
cargo run --release -- bench compare <suite_id_a> <suite_id_b>
cargo run --release -- bench export --output results.json
```

### Generate a Report

```bash
# From the most recent suite
cargo run --release -- bench export-report --backend constraint_checked --output report.md

# From a specific stored suite
cargo run --release -- bench export-report \
  --suite <suite_id> \
  --backend constraint_checked \
  --output report.md
```

---

## HTTP API

Start the server:

```bash
cargo run --release -- serve
# or
ZKDB_BIND=0.0.0.0:8080 cargo run --release
```

Key endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/datasets` | Create dataset |
| `POST` | `/v1/datasets/:id/ingest` | Ingest rows |
| `POST` | `/v1/datasets/:id/snapshots` | Commit snapshot |
| `POST` | `/v1/queries` | Submit SQL query for proving |
| `GET` | `/v1/queries/:id` | Get result and proof status |
| `GET` | `/v1/proofs/:id` | Get proof artifact |
| `POST` | `/v1/proofs/verify` | Verify a proof |
| `POST` | `/v1/benchmarks/suite` | Run benchmark suite |
| `POST` | `/v1/benchmarks/compare` | Compare stored results |
| `GET` | `/health` | Health check |

---

## Report Generation

`bench export-report` reads any stored suite from disk, fills in environment metadata (OS, architecture, timestamp), and writes a self-contained Markdown report. The report includes:

- Backend identity and capability flags
- Environment table (OS, arch, backend kind, proof system label)
- Dataset summary and row counts
- Use-case operator coverage table
- Per-scenario results table (proof time, verification time, proof size, quality label, status)
- Summary statistics (slowest scenario, largest proof)
- Limitations section auto-populated from `ReportContext`
- Exact CLI command needed to reproduce the run

`MetricQuality` prevents any backend from silently misrepresenting results. MockBackend results are always labelled `quality: placeholder`. ConstraintCheckedBackend results are labelled `quality: real`. Neither label implies a zero-knowledge property.

---

## Verified Test Status

All commands below were run on 2026-03-16 against the current repository.

### Compilation

```
$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.11s
```

Zero errors, zero warnings.

### Full Test Suite

```
$ cargo test
```

| Test binary | Tests | Result |
|---|---|---|
| `src/lib.rs` (unit tests) | 88 | ✅ 88 passed |
| `tests/adversarial.rs` | 15 | ✅ 15 passed |
| `tests/benchmark_integration.rs` | 6 | ✅ 6 passed |
| `tests/operator_integration.rs` | 38 | ✅ 38 passed |
| **Total** | **147** | **✅ 147 passed, 0 failed** |

**Selected adversarial tests (all pass):**

```
test tampered_proof_bytes_fails_verification       ... ok
test tampered_result_commitment_fails_verification ... ok
test tampered_snapshot_root_fails_verification     ... ok
test tampered_query_hash_fails_verification        ... ok
test unsorted_witness_fails_sort_prove             ... ok
test sort_multiset_violation_fails_prove           ... ok
test unsorted_group_key_fails_prove                ... ok
test group_by_multiset_violation_fails_prove       ... ok
test join_key_mismatch_fails_prove                 ... ok
test join_column_length_mismatch_fails_prove       ... ok
test join_result_row_count_mismatch_fails_prove    ... ok
test plonky2_stub_prove_always_errors              ... ok
test constraint_checked_never_labeled_as_real_snark ... ok
```

### Benchmark Smoke Tests

```
$ cargo run --release -- bench suite --rows 1000 --backend mock
Suite Summary: 8 scenarios, 8 passed, 0 failed

$ cargo run --release -- bench suite --rows 1000 --backend constraint_checked
Suite Summary: 8 scenarios, 8 passed, 0 failed

$ cargo run --release -- bench suite --rows 1000 --backend constraint_checked --full
Suite Summary: 22 scenarios, 22 passed, 0 failed

$ cargo run --release -- bench export-pack --output benchmark_pack
Files written: 13
```

---

## Current Limitations

### ConstraintCheckedBackend is not a SNARK

`ConstraintCheckedBackend` provides mathematically enforced operator constraints plus a Blake3 hash-chain audit log. It does **not** provide:
- Zero-knowledge (the verifier sees all witness hashes)
- Succinctness (verification is O(columns × rows))
- Any polynomial commitment scheme
- Any hiding or binding property beyond collision resistance of Blake3

Proof sizes (~720–734 bytes) and verification times (~0.04–0.23 ms) are properties of the hash-chain format, not of a SNARK. Do not compare these numbers to Plonky2 or Halo2 benchmarks.

### Plonky2Backend is a stub

`prove()` always returns `Err("not yet wired")`. The Plonky2 dependency is not in `Cargo.toml`. Integration is planned as the next major milestone.

### Scalability above 5 000 rows

The architecture supports arbitrary row counts via chunked processing (default chunk size: 256 rows). Proof times at 5 000 rows are ~21 ms for `ConstraintCheckedBackend`. At 1M+ rows, the bottleneck will be Blake3 hashing of column data, not polynomial proving — these numbers will not be representative of a real SNARK at scale. Meaningful scalability benchmarks require Plonky2 or Halo2.

### Lookup argument comparison (dimension 5)

Logup vs lookup_any comparison for JOIN-heavy queries requires at least two working SNARK backends with different lookup strategies. Not yet applicable.

### Field-size comparison (dimension 6)

255-bit Pasta vs 64-bit Goldilocks vs 31-bit BabyBear comparison requires backends that actually use those fields. `ConstraintCheckedBackend` uses 64-bit field elements (`FieldElement(u64)`) internally but does not perform polynomial proving, so field size does not affect proof characteristics today.

### Parallelization (dimension 8)

The Tokio async runtime is in place and chunk processing could be parallelized. Currently all proof generation is single-threaded. This will become meaningful once polynomial FFTs are part of the critical path.

### In-memory storage only

All dataset, snapshot, and chunk storage is in-memory. Benchmark results are persisted to `~/.zkdb/benchmark_results/` as JSON files. There is no persistent database backend.

---

## Development

```bash
# Build
cargo build

# Run all tests
cargo test

# Start API server
cargo run -- serve

# Run benchmark suite with real constraints
cargo run -- bench suite --rows 1000 --backend constraint_checked --report

# Export portable benchmark pack
cargo run -- bench export-pack --output benchmark_pack
```

### Key Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1 | Async runtime |
| `axum` | 0.7 | HTTP framework |
| `sqlparser` | 0.44 | SQL parsing |
| `blake3` | 1 | Hashing, Merkle commitments |
| `serde` / `serde_json` | 1 | Serialization |
| `clap` | 4 | CLI argument parsing |
| `uuid` | 1 | Run / suite / dataset IDs |
| `chrono` | 0.4 | Timestamps in reports |
| `rand` | 0.8 | Deterministic dataset generation |
| `thiserror` | 1 | Structured error types |
| `tracing` | 0.1 | Structured logging |
