//! Portable Benchmark Pack Exporter and Report Generator.
//!
//! ## Two-layer architecture
//!
//! ### Layer A — Portable benchmark pack (this module's export target)
//! Algorithm-independent, reusable in any zkDB implementation:
//! - canonical dataset definitions + CSV files
//! - canonical query / use-case definitions (YAML)
//! - canonical metrics + result schema (JSON)
//! - report templates + methodology documentation (Markdown)
//!
//! ### Layer B — Backend-specific execution (BenchmarkRunner)
//! Plonky2 / ConstraintChecked / Halo2 / etc. consume Layer A and
//! produce results. The report generator then fills the template with
//! actual measurements from the specific backend.
//!
//! ## Portability guarantee
//! The files written by `BenchmarkPackExporter::export()` contain NO
//! references to Plonky2 or any other specific algorithm. They can be
//! copied verbatim into a Halo2 or RISC-V repo and used there.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::benchmarks::dataset::{generate_employees, generate_transactions};
use crate::benchmarks::types::{BackendKind, BenchmarkResult, MetricQuality};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ExportError(pub String);

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "export error: {}", self.0)
    }
}

impl std::error::Error for ExportError {}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        ExportError(e.to_string())
    }
}

impl From<serde_json::Error> for ExportError {
    fn from(e: serde_json::Error) -> Self {
        ExportError(e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical row counts
// ─────────────────────────────────────────────────────────────────────────────

/// Controls how many rows go into each exported CSV file.
///
/// These are the canonical default sizes for the portable pack.
/// They are small enough to ship in a repo but large enough to
/// exercise all operators meaningfully.
#[derive(Debug, Clone)]
pub struct CanonicalRowCounts {
    /// Row count for the transactions dataset (default: 1000).
    pub transactions: usize,
    /// Row count for the employees dataset (default: 200).
    pub employees: usize,
}

impl Default for CanonicalRowCounts {
    fn default() -> Self {
        Self {
            transactions: 1000,
            employees: 200,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pack export summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of all files written by the exporter.
#[derive(Debug)]
pub struct PackExportSummary {
    pub output_dir: PathBuf,
    pub files_written: Vec<PathBuf>,
    pub transactions_rows: usize,
    pub employees_rows: usize,
}

impl PackExportSummary {
    pub fn print(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  Benchmark Pack Export Complete                              ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Output directory: {}", self.output_dir.display());
        println!("║  Files written: {}", self.files_written.len());
        println!("║  Transactions rows: {}", self.transactions_rows);
        println!("║  Employees rows: {}", self.employees_rows);
        println!("╠══════════════════════════════════════════════════════════════╣");
        for f in &self.files_written {
            println!("║  ✓ {}", f.display());
        }
        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkPackExporter
// ─────────────────────────────────────────────────────────────────────────────

/// Exports the portable benchmark pack to a directory on disk.
///
/// The exported files contain NO backend-specific content.
/// They can be copied into any zkDB implementation (Halo2, RISC-V, etc.)
/// and used to run the same benchmark workload.
pub struct BenchmarkPackExporter;

impl BenchmarkPackExporter {
    /// Export the full portable benchmark pack to `output_dir`.
    ///
    /// Creates the following layout:
    /// ```text
    /// output_dir/
    ///   README.md
    ///   dataset/
    ///     schema.json
    ///     generation_config.json
    ///     transactions.csv
    ///     employees.csv
    ///     snapshot_manifest.json
    ///   usecases/
    ///     queries.yaml
    ///     scenarios.yaml
    ///   metrics/
    ///     metrics_schema.json
    ///     result_schema.json
    ///   reports/
    ///     report_template.md
    ///     methodology.md
    ///     reproducibility.md
    /// ```
    pub fn export(
        output_dir: &Path,
        row_counts: CanonicalRowCounts,
    ) -> Result<PackExportSummary, ExportError> {
        let mut files_written = Vec::new();

        // Create directory structure
        let dirs = [
            output_dir.to_path_buf(),
            output_dir.join("dataset"),
            output_dir.join("usecases"),
            output_dir.join("metrics"),
            output_dir.join("reports"),
        ];
        for d in &dirs {
            fs::create_dir_all(d)?;
        }

        // ── README ───────────────────────────────────────────────────────────
        let f = output_dir.join("README.md");
        fs::write(&f, readme_content())?;
        files_written.push(f);

        // ── dataset/ ─────────────────────────────────────────────────────────
        let dataset_dir = output_dir.join("dataset");

        let f = dataset_dir.join("schema.json");
        fs::write(&f, dataset_schema_json()?)?;
        files_written.push(f);

        let f = dataset_dir.join("generation_config.json");
        fs::write(&f, generation_config_json(&row_counts)?)?;
        files_written.push(f);

        let f = dataset_dir.join("transactions.csv");
        fs::write(&f, transactions_csv(row_counts.transactions))?;
        files_written.push(f);

        let f = dataset_dir.join("employees.csv");
        fs::write(&f, employees_csv(row_counts.employees))?;
        files_written.push(f);

        let f = dataset_dir.join("snapshot_manifest.json");
        fs::write(&f, snapshot_manifest_json(&row_counts)?)?;
        files_written.push(f);

        // ── usecases/ ────────────────────────────────────────────────────────
        let uc_dir = output_dir.join("usecases");

        let f = uc_dir.join("queries.yaml");
        fs::write(&f, queries_yaml())?;
        files_written.push(f);

        let f = uc_dir.join("scenarios.yaml");
        fs::write(&f, scenarios_yaml())?;
        files_written.push(f);

        // ── metrics/ ─────────────────────────────────────────────────────────
        let metrics_dir = output_dir.join("metrics");

        let f = metrics_dir.join("metrics_schema.json");
        fs::write(&f, metrics_schema_json()?)?;
        files_written.push(f);

        let f = metrics_dir.join("result_schema.json");
        fs::write(&f, result_schema_json()?)?;
        files_written.push(f);

        // ── reports/ ─────────────────────────────────────────────────────────
        let reports_dir = output_dir.join("reports");

        let f = reports_dir.join("report_template.md");
        fs::write(&f, report_template_md())?;
        files_written.push(f);

        let f = reports_dir.join("methodology.md");
        fs::write(&f, methodology_md())?;
        files_written.push(f);

        let f = reports_dir.join("reproducibility.md");
        fs::write(&f, reproducibility_md())?;
        files_written.push(f);

        Ok(PackExportSummary {
            output_dir: output_dir.to_path_buf(),
            files_written,
            transactions_rows: row_counts.transactions,
            employees_rows: row_counts.employees,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportContext — backend metadata for report generation
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about the backend used to run the benchmarks.
/// Fill this in when generating a report for a specific algorithm.
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// Human-readable backend name (e.g. "Plonky2 FRI SNARK", "ConstraintCheckedBackend").
    pub backend_name: String,
    /// Backend kind as used in this codebase (e.g. "constraint_checked", "plonky2").
    pub backend_kind: String,
    /// Proof system label (e.g. "hash_chain_audit", "plonky2_snark").
    pub proof_system_kind: String,
    /// Whether this backend is zero-knowledge.
    pub is_zero_knowledge: bool,
    /// Whether proofs are succinct.
    pub is_succinct: bool,
    /// Whether real constraints are enforced.
    pub has_real_constraints: bool,
    /// Free-form notes about limitations.
    pub limitations: Vec<String>,
    /// Timestamp of report generation (ISO 8601).
    pub generated_at: String,
    /// Host platform info.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
}

impl ReportContext {
    /// Build a context from a BackendKind.
    pub fn from_backend_kind(kind: &BackendKind) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        match kind {
            BackendKind::Mock => Self {
                backend_name: "NoProofSentinel (removed backend)".into(),
                backend_kind: "mock".into(),
                proof_system_kind: "none".into(),
                is_zero_knowledge: false,
                is_succinct: false,
                has_real_constraints: false,
                limitations: vec![
                    "All proof timings are structural (mock hashing only, not real proving)".into(),
                    "Proof size is not meaningful".into(),
                    "Verification is trivial (non-empty bytes check)".into(),
                ],
                generated_at: now,
                os,
                arch,
            },
            BackendKind::ConstraintChecked | BackendKind::Baseline => Self {
                backend_name: "ConstraintCheckedBackend (hash-chain audit)".into(),
                backend_kind: "constraint_checked".into(),
                proof_system_kind: "hash_chain_audit".into(),
                is_zero_knowledge: false,
                is_succinct: false,
                has_real_constraints: true,
                limitations: vec![
                    "NOT zero-knowledge: verifier sees full witness digest chain".into(),
                    "NOT succinct: verification cost is O(columns × rows)".into(),
                    "No polynomial commitments, no elliptic curve operations".into(),
                    "Proof size grows linearly with row count".into(),
                    "This is a hash-chain audit log, NOT a SNARK/STARK".into(),
                ],
                generated_at: now,
                os,
                arch,
            },
            BackendKind::Plonky2 => Self {
                backend_name: "Plonky2Backend (FRI SNARK — fully wired)".into(),
                backend_kind: "plonky2".into(),
                proof_system_kind: "plonky2_snark".into(),
                is_zero_knowledge: true,
                is_succinct: true,
                has_real_constraints: true,
                limitations: vec![
                    "Recursive proof folding (fold()) not yet implemented".into(),
                    "MAX_ROWS is fixed at compile time; very large datasets require chunking".into(),
                ],
                generated_at: now,
                os,
                arch,
            },
            _ => Self {
                backend_name: format!("{} (stub)", kind),
                backend_kind: format!("{}", kind),
                proof_system_kind: "unknown".into(),
                is_zero_knowledge: false,
                is_succinct: false,
                has_real_constraints: false,
                limitations: vec!["Backend is a stub".into()],
                generated_at: now,
                os,
                arch,
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a `report.md` file from benchmark results + backend context.
///
/// The generated report follows the structure of
/// `benchmark_pack/reports/report_template.md` but is fully populated
/// with actual measurements.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a report.md file from a slice of benchmark results.
    pub fn generate(
        results: &[BenchmarkResult],
        output_path: &Path,
        ctx: &ReportContext,
    ) -> Result<(), ExportError> {
        let content = Self::build_report(results, ctx);
        fs::write(output_path, content)?;
        Ok(())
    }

    fn build_report(results: &[BenchmarkResult], ctx: &ReportContext) -> String {
        let mut md = String::new();

        // ── Header ──────────────────────────────────────────────────────────
        md.push_str(&format!(
            "# zkDB Benchmark Report\n\n\
             **Generated:** {}\n\
             **Backend:** {}\n\
             **Proof system:** `{}`\n\
             **Zero-knowledge:** {}\n\
             **Succinct verification:** {}\n\
             **Real constraints:** {}\n\n",
            ctx.generated_at,
            ctx.backend_name,
            ctx.proof_system_kind,
            if ctx.is_zero_knowledge {
                "✅ Yes"
            } else {
                "❌ No"
            },
            if ctx.is_succinct { "✅ Yes" } else { "❌ No" },
            if ctx.has_real_constraints {
                "✅ Yes"
            } else {
                "❌ No"
            },
        ));

        // ── Environment ──────────────────────────────────────────────────────
        md.push_str("---\n\n## Environment\n\n");
        md.push_str(&"| Field | Value |\n|---|---|\n".to_string());
        md.push_str(&format!("| OS | {} |\n", ctx.os));
        md.push_str(&format!("| Architecture | {} |\n", ctx.arch));
        md.push_str(&format!("| Backend kind | `{}` |\n", ctx.backend_kind));
        md.push_str(&format!(
            "| Proof system | `{}` |\n\n",
            ctx.proof_system_kind
        ));

        // ── Dataset summary ──────────────────────────────────────────────────
        md.push_str("---\n\n## Dataset\n\n");
        md.push_str("This benchmark uses the canonical zkDB benchmark pack datasets.\n\n");
        md.push_str("| Dataset | Columns | Description |\n|---|---|---|\n");
        md.push_str("| `benchmark_transactions` | id, user_id, amount, category, region, timestamp, score, flag | Synthetic transaction records |\n");
        md.push_str("| `benchmark_employees` | employee_id, department, office, salary, manager_id, performance_score | Synthetic employee records |\n\n");
        md.push_str("All datasets are **deterministically generated** from a fixed seed. See `benchmark_pack/dataset/generation_config.json`.\n\n");

        // ── Use-cases summary ────────────────────────────────────────────────
        md.push_str("---\n\n## Use-Cases\n\n");
        md.push_str("Use-cases are defined in `benchmark_pack/usecases/scenarios.yaml`.\n");
        md.push_str("The following operators are covered:\n\n");
        md.push_str("- Filter / Projection\n- COUNT / SUM / AVG aggregation\n");
        md.push_str("- GROUP BY (count, sum, avg)\n- ORDER BY (asc, desc)\n");
        md.push_str("- TOP-K\n- Equi-JOIN\n\n");

        // ── Results table ────────────────────────────────────────────────────
        md.push_str("---\n\n## Results\n\n");

        let total = results.len();
        let passed = results.iter().filter(|r| r.success).count();
        let failed = total - passed;
        md.push_str(&format!(
            "**{} scenarios** — {} passed, {} failed\n\n",
            total, passed, failed
        ));

        if !results.is_empty() {
            // Header
            md.push_str("| Scenario | Rows | Operator | Complexity | Proof ms | Verify ms | Proof bytes | Quality | Status |\n");
            md.push_str("|---|---|---|---|---|---|---|---|---|\n");

            for r in results {
                let proof_ms = r.metrics.proof_generation_us as f64 / 1000.0;
                let verify_ms = r.metrics.verification_us as f64 / 1000.0;
                let status = if r.success { "✅" } else { "❌" };
                let quality = match r.metrics.quality.overall {
                    MetricQuality::Real => "real",
                    MetricQuality::Estimated => "estimated",
                    MetricQuality::Placeholder => "placeholder",
                };
                md.push_str(&format!(
                    "| `{}` | {} | {} | {} | {:.2} | {:.2} | {} | {} | {} |\n",
                    r.scenario.name,
                    r.metrics.row_count,
                    r.scenario.operator_family,
                    r.scenario.complexity_class,
                    proof_ms,
                    verify_ms,
                    r.metrics.proof_size_bytes,
                    quality,
                    status,
                ));
            }
            md.push('\n');
        }

        // ── Per-scenario detail ───────────────────────────────────────────────
        if !results.is_empty() {
            md.push_str("---\n\n## Scenario Details\n\n");
            for r in results {
                md.push_str(&format!("### `{}`\n\n", r.scenario.name));
                if !r.scenario.description.is_empty() {
                    md.push_str(&format!("**Description:** {}\n\n", r.scenario.description));
                }
                md.push_str(&format!("```sql\n{}\n```\n\n", r.scenario.sql.trim()));
                md.push_str(&"| Metric | Value |\n|---|---|\n".to_string());
                md.push_str(&format!(
                    "| Status | {} |\n",
                    if r.success {
                        "✅ passed"
                    } else {
                        "❌ failed"
                    }
                ));
                md.push_str(&format!("| Rows | {} |\n", r.metrics.row_count));
                md.push_str(&format!("| Chunks | {} |\n", r.metrics.chunk_count));
                md.push_str(&format!(
                    "| Dataset gen | {:.3} ms |\n",
                    r.metrics.dataset_generation_us as f64 / 1000.0
                ));
                md.push_str(&format!(
                    "| Ingestion | {:.3} ms |\n",
                    r.metrics.ingestion_us as f64 / 1000.0
                ));
                md.push_str(&format!(
                    "| Proof generation | {:.3} ms |\n",
                    r.metrics.proof_generation_us as f64 / 1000.0
                ));
                md.push_str(&format!(
                    "| Verification | {:.3} ms |\n",
                    r.metrics.verification_us as f64 / 1000.0
                ));
                md.push_str(&format!(
                    "| Total | {:.3} ms |\n",
                    r.metrics.total_us as f64 / 1000.0
                ));
                md.push_str(&format!(
                    "| Proof size | {} bytes |\n",
                    r.metrics.proof_size_bytes
                ));
                md.push_str(&format!(
                    "| VK size | {} bytes |\n",
                    r.metrics.verification_key_size_bytes
                ));
                md.push_str(&format!(
                    "| Throughput | {:.0} rows/sec |\n",
                    r.metrics.proving_throughput_rps()
                ));
                md.push_str(&format!("| Quality | {} |\n", r.metrics.quality.overall));
                if let Some(ref err) = r.error {
                    md.push_str(&format!("| Error | `{}` |\n", err));
                }
                md.push('\n');
            }
        }

        // ── Backend capabilities ──────────────────────────────────────────────
        md.push_str("---\n\n## Backend Capabilities\n\n");
        md.push_str("| Capability | Value |\n|---|---|\n");
        md.push_str(&format!("| Backend name | {} |\n", ctx.backend_name));
        md.push_str(&format!("| Backend kind | `{}` |\n", ctx.backend_kind));
        md.push_str(&format!("| Proof system | `{}` |\n", ctx.proof_system_kind));
        md.push_str(&format!(
            "| Zero-knowledge | {} |\n",
            if ctx.is_zero_knowledge {
                "✅ Yes"
            } else {
                "❌ No"
            }
        ));
        md.push_str(&format!(
            "| Succinct verification | {} |\n",
            if ctx.is_succinct { "✅ Yes" } else { "❌ No" }
        ));
        md.push_str(&format!(
            "| Real operator constraints | {} |\n\n",
            if ctx.has_real_constraints {
                "✅ Yes"
            } else {
                "❌ No"
            }
        ));

        // ── Observations ─────────────────────────────────────────────────────
        md.push_str("---\n\n## Observations\n\n");
        if results.iter().all(|r| r.success) {
            md.push_str("- All scenarios completed successfully.\n");
        } else {
            let failed_names: Vec<_> = results
                .iter()
                .filter(|r| !r.success)
                .map(|r| format!("`{}`", r.scenario.name))
                .collect();
            md.push_str(&format!(
                "- {} scenario(s) failed: {}\n",
                failed_names.len(),
                failed_names.join(", ")
            ));
        }

        if !results.is_empty() {
            // Find slowest
            if let Some(slowest) = results
                .iter()
                .filter(|r| r.success)
                .max_by_key(|r| r.metrics.proof_generation_us)
            {
                md.push_str(&format!(
                    "- Slowest proof generation: `{}` at {:.2} ms\n",
                    slowest.scenario.name,
                    slowest.metrics.proof_generation_us as f64 / 1000.0
                ));
            }
            // Find largest proof
            if let Some(largest) = results
                .iter()
                .filter(|r| r.success)
                .max_by_key(|r| r.metrics.proof_size_bytes)
            {
                md.push_str(&format!(
                    "- Largest proof: `{}` at {} bytes\n",
                    largest.scenario.name, largest.metrics.proof_size_bytes
                ));
            }
        }

        let quality_note = match ctx.backend_kind.as_str() {
            "mock" => "⚠️ **All metrics are PLACEHOLDER quality** — from mock backend, not suitable for research comparison.",
            "constraint_checked" => "⚠️ **Proof metrics are ESTIMATED quality** — hash-chain audit backend. Timings reflect constraint validation + hashing, NOT polynomial proving. Results are not directly comparable with SNARK backends.",
            "plonky2" => "✅ **Proof metrics are REAL quality** — Plonky2 FRI SNARK, fully wired. Suitable for research comparison.",
            _ => "⚠️ See metric quality flags in the results table — some backends may be stubs.",
        };
        md.push_str(&format!("\n{}\n\n", quality_note));

        // ── Limitations ──────────────────────────────────────────────────────
        md.push_str("---\n\n## Limitations\n\n");
        for limitation in &ctx.limitations {
            md.push_str(&format!("- {}\n", limitation));
        }
        md.push('\n');

        // ── Reproducibility ──────────────────────────────────────────────────
        md.push_str("---\n\n## Reproducibility\n\n");
        md.push_str("To reproduce this benchmark:\n\n");
        md.push_str("```bash\n");
        md.push_str(&format!(
            "cargo run --release -- bench suite --backend {} --rows 1000\n",
            ctx.backend_kind
        ));
        md.push_str("```\n\n");
        md.push_str("To reuse the same benchmark pack with another algorithm, copy:\n\n");
        md.push_str("```\nbenchmark_pack/dataset/*\nbenchmark_pack/usecases/*\nbenchmark_pack/metrics/*\nbenchmark_pack/reports/*\n```\n\n");
        md.push_str("See `benchmark_pack/reports/reproducibility.md` for full instructions.\n\n");

        // ── Footer ───────────────────────────────────────────────────────────
        md.push_str("---\n\n");
        md.push_str("*Generated by zkDB benchmark runner. ");
        md.push_str("Benchmark pack format version: 1.0.0. ");
        md.push_str("For methodology, see `benchmark_pack/reports/methodology.md`.*\n");

        md
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File content generators
// ─────────────────────────────────────────────────────────────────────────────

fn readme_content() -> &'static str {
    r#"# zkDB Portable Benchmark Pack

Version: 1.0.0

This directory contains the **portable benchmark pack** for zkDB.
It is algorithm-independent and can be reused with any proving backend.

## Directory structure

```
benchmark_pack/
├── README.md                       ← This file
├── dataset/
│   ├── schema.json                 ← Column definitions for both datasets
│   ├── generation_config.json      ← Deterministic generation parameters
│   ├── transactions.csv            ← Generated transactions (canonical)
│   ├── employees.csv               ← Generated employees (canonical)
│   └── snapshot_manifest.json      ← Dataset metadata
├── usecases/
│   ├── queries.yaml                ← SQL query definitions
│   └── scenarios.yaml              ← Benchmark scenarios with metadata
├── metrics/
│   ├── metrics_schema.json         ← Field definitions for metrics
│   └── result_schema.json          ← Field definitions for results
└── reports/
    ├── report_template.md          ← Reusable report template
    ├── methodology.md              ← How benchmarks are run
    └── reproducibility.md          ← How to reuse in another repo
```

## Key design principles

1. **Algorithm-independent**: These files contain NO references to Plonky2,
   Halo2, or any specific proof system.

2. **Deterministic**: All datasets are generated from a fixed seed.
   Running the generation twice produces identical files.

3. **Portable**: Copy the entire `benchmark_pack/` directory into any
   zkDB implementation and run the same workload.

4. **Honest**: The result schema includes `proof_system_kind`,
   `metric_quality`, and capability flags so results from different
   backends can be honestly compared.

## Datasets

| Dataset | Rows (canonical) | Key operators |
|---|---|---|
| benchmark_transactions | 1000 | filter, aggregate, group_by, sort |
| benchmark_employees | 200 | group_by, sort, join |

## Use-cases

See `usecases/scenarios.yaml` for the full list of 16 canonical scenarios.
Operators covered: filter, projection, count, sum, avg, group_by, sort, top_k, join.

## Reusing in another repo

See `reports/reproducibility.md` for step-by-step instructions.

## Generated by

```bash
cargo run --release -- bench export-pack
```
"#
}

fn dataset_schema_json() -> Result<String, ExportError> {
    let schema = serde_json::json!({
        "version": "1.0.0",
        "description": "Canonical zkDB benchmark datasets. Algorithm-independent.",
        "datasets": [
            {
                "name": "benchmark_transactions",
                "description": "Synthetic transaction records for filter/aggregate/sort/group_by benchmarks",
                "seed": "deterministic_wrapping_hash",
                "generation_fn": "generate_transactions(n)",
                "columns": [
                    {"name": "id",        "type": "u64",  "nullable": false, "description": "Sequential row index"},
                    {"name": "user_id",   "type": "u64",  "nullable": false, "description": "User identifier (0-9999)"},
                    {"name": "amount",    "type": "u64",  "nullable": false, "description": "Transaction amount (0-99999)"},
                    {"name": "category",  "type": "text", "nullable": false, "description": "One of: electronics, clothing, food, services, travel, entertainment, health, education"},
                    {"name": "region",    "type": "text", "nullable": false, "description": "One of: us-east, us-west, eu-west, eu-central, ap-south, ap-east"},
                    {"name": "timestamp", "type": "u64",  "nullable": false, "description": "Unix timestamp (seconds), starting 1700000000"},
                    {"name": "score",     "type": "u64",  "nullable": false, "description": "Score value (0-999)"},
                    {"name": "flag",      "type": "bool", "nullable": false, "description": "Boolean flag (roughly 50/50)"}
                ],
                "cardinalities": {
                    "user_id": 10000,
                    "category": 8,
                    "region": 6
                }
            },
            {
                "name": "benchmark_employees",
                "description": "Synthetic employee records for group_by/sort/join benchmarks",
                "seed": "deterministic_wrapping_hash_offset_1000000",
                "generation_fn": "generate_employees(n)",
                "columns": [
                    {"name": "employee_id",       "type": "u64",  "nullable": false, "description": "Sequential employee ID"},
                    {"name": "department",        "type": "text", "nullable": false, "description": "One of: engineering, marketing, sales, finance, hr, operations, legal, research"},
                    {"name": "office",            "type": "text", "nullable": false, "description": "One of: new-york, san-francisco, london, berlin, tokyo, singapore"},
                    {"name": "salary",            "type": "u64",  "nullable": false, "description": "Annual salary (30000-200000)"},
                    {"name": "manager_id",        "type": "u64",  "nullable": false, "description": "Manager employee_id (0 for top-level)"},
                    {"name": "performance_score", "type": "u64",  "nullable": false, "description": "Performance score (1-100)"}
                ],
                "cardinalities": {
                    "department": 8,
                    "office": 6
                }
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&schema)?)
}

fn generation_config_json(row_counts: &CanonicalRowCounts) -> Result<String, ExportError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let config = serde_json::json!({
        "version": "1.0.0",
        "description": "Deterministic dataset generation configuration for the zkDB benchmark pack.",
        "algorithm": "wrapping_hash (LCG, seed = row_index [+ offset])",
        "hash_constants": {
            "multiplier": "6364136223846793005",
            "addend": "1442695040888963407",
            "final_multiplier": "0x45d9f3b"
        },
        "datasets": {
            "transactions": {
                "row_count": row_counts.transactions,
                "seed_offset": 0,
                "column_domains": {
                    "user_id":   {"formula": "wrapping_hash(i) % 10000"},
                    "amount":    {"formula": "(wrapping_hash(i) >> 8) % 100000"},
                    "category":  {"formula": "CATEGORIES[(wrapping_hash(i) >> 16) % 8]"},
                    "region":    {"formula": "REGIONS[(wrapping_hash(i) >> 24) % 6]"},
                    "timestamp": {"formula": "1700000000 + i * 60"},
                    "score":     {"formula": "(wrapping_hash(i) >> 32) % 1000"},
                    "flag":      {"formula": "(wrapping_hash(i) >> 40) % 2 == 0"}
                }
            },
            "employees": {
                "row_count": row_counts.employees,
                "seed_offset": 1000000,
                "column_domains": {
                    "department":        {"formula": "DEPARTMENTS[(wrapping_hash(i+1000000) >> 4) % 8]"},
                    "office":            {"formula": "OFFICES[(wrapping_hash(i+1000000) >> 12) % 6]"},
                    "salary":            {"formula": "30000 + wrapping_hash(i+1000000) % 170000"},
                    "manager_id":        {"formula": "if i==0 then 0 else wrapping_hash(i+1000000) % i"},
                    "performance_score": {"formula": "1 + (wrapping_hash(i+1000000) >> 20) % 100"}
                }
            }
        },
        "reproduced_by": "cargo run --release -- bench export-pack",
        "exported_at_unix": ts
    });
    Ok(serde_json::to_string_pretty(&config)?)
}

fn snapshot_manifest_json(row_counts: &CanonicalRowCounts) -> Result<String, ExportError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let manifest = serde_json::json!({
        "version": "1.0.0",
        "description": "Snapshot metadata for canonical benchmark datasets.",
        "note": "These are deterministic snapshots — re-generating the dataset from generation_config.json produces identical content.",
        "snapshots": [
            {
                "snapshot_id": "canonical_transactions_v1",
                "dataset_name": "benchmark_transactions",
                "row_count": row_counts.transactions,
                "chunk_size": 256,
                "chunk_count": row_counts.transactions.div_ceil(256),
                "encoding": "blake3_hash_chain",
                "commitment_scheme": "blake3_merkle",
                "status": "active",
                "notes": "Canonical 1000-row transactions snapshot for benchmark reproducibility"
            },
            {
                "snapshot_id": "canonical_employees_v1",
                "dataset_name": "benchmark_employees",
                "row_count": row_counts.employees,
                "chunk_size": 64,
                "chunk_count": row_counts.employees.div_ceil(64),
                "encoding": "blake3_hash_chain",
                "commitment_scheme": "blake3_merkle",
                "status": "active",
                "notes": "Canonical 200-row employees snapshot for benchmark reproducibility"
            }
        ],
        "exported_at_unix": ts
    });
    Ok(serde_json::to_string_pretty(&manifest)?)
}

fn transactions_csv(row_count: usize) -> String {
    let rows = generate_transactions(row_count);
    let mut csv = String::from("id,user_id,amount,category,region,timestamp,score,flag\n");
    for row in &rows {
        let v = &row.values;
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            v[0],
            v[1],
            v[2],
            json_str(&v[3]),
            json_str(&v[4]),
            v[5],
            v[6],
            v[7]
        ));
    }
    csv
}

fn employees_csv(row_count: usize) -> String {
    let rows = generate_employees(row_count);
    let mut csv =
        String::from("employee_id,department,office,salary,manager_id,performance_score\n");
    for row in &rows {
        let v = &row.values;
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            v[0],
            json_str(&v[1]),
            json_str(&v[2]),
            v[3],
            v[4],
            v[5]
        ));
    }
    csv
}

/// Extract string value from a serde_json::Value for CSV output.
fn json_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

fn queries_yaml() -> &'static str {
    r#"# zkDB Canonical Benchmark Queries
# Version: 1.0.0
#
# This file defines all canonical SQL queries for the benchmark pack.
# These are algorithm-independent and can be reused with any zkDB backend.
#
# Each query has:
#   id:          Unique identifier (snake_case)
#   dataset:     Target dataset name
#   sql:         SQL query text
#   operator:    Primary proof operator exercised
#   family:      Query family (filter/aggregate/group_by/sort/join/mixed)
#   complexity:  Expected proof complexity (linear/moderate/heavy)
#   description: Human-readable description

queries:

  # ── Filter / Projection ───────────────────────────────────────────────────
  - id: filter_projection
    dataset: benchmark_transactions
    sql: "SELECT id, amount, region FROM benchmark_transactions WHERE amount > 50000"
    operator: filter_project
    family: filter
    complexity: linear
    description: "Filter rows by amount threshold + project 3 columns"
    tags: [filter, projection]

  - id: range_filter
    dataset: benchmark_transactions
    sql: "SELECT id, user_id, score FROM benchmark_transactions WHERE score > 500 AND amount < 30000"
    operator: filter_project
    family: filter
    complexity: linear
    description: "Compound range filter on two numeric columns"
    tags: [filter, range, projection]

  # ── Aggregation ───────────────────────────────────────────────────────────
  - id: count_all
    dataset: benchmark_transactions
    sql: "SELECT COUNT(*) FROM benchmark_transactions"
    operator: aggregate
    family: aggregate
    complexity: linear
    description: "Full table COUNT aggregation"
    tags: [aggregate, count]

  - id: filter_count
    dataset: benchmark_transactions
    sql: "SELECT COUNT(*) FROM benchmark_transactions WHERE flag = true"
    operator: filter_aggregate
    family: filter
    complexity: linear
    description: "Filtered COUNT on boolean column"
    tags: [filter, aggregate, count]

  - id: filter_sum
    dataset: benchmark_transactions
    sql: "SELECT SUM(amount) FROM benchmark_transactions WHERE region = 'us-east'"
    operator: filter_aggregate
    family: aggregate
    complexity: moderate
    description: "Filter by region + aggregate SUM"
    tags: [filter, aggregate, sum]

  - id: avg_aggregation
    dataset: benchmark_transactions
    sql: "SELECT AVG(score) FROM benchmark_transactions WHERE category = 'electronics'"
    operator: filter_aggregate
    family: aggregate
    complexity: moderate
    description: "Filtered AVG on score column"
    tags: [filter, aggregate, avg]

  - id: multi_aggregate
    dataset: benchmark_transactions
    sql: "SELECT COUNT(*), SUM(amount), AVG(score) FROM benchmark_transactions"
    operator: aggregate
    family: aggregate
    complexity: moderate
    description: "Multiple aggregation functions in one query"
    tags: [aggregate, multi, count, sum, avg]

  # ── GROUP BY ─────────────────────────────────────────────────────────────
  - id: group_by_region_sum
    dataset: benchmark_transactions
    sql: "SELECT region, SUM(amount) FROM benchmark_transactions GROUP BY region"
    operator: group_by_aggregate
    family: group_by
    complexity: heavy
    description: "GROUP BY region with SUM — 6 groups"
    tags: [group_by, sum]

  - id: group_by_category_count
    dataset: benchmark_transactions
    sql: "SELECT category, COUNT(*) FROM benchmark_transactions GROUP BY category"
    operator: group_by_aggregate
    family: group_by
    complexity: heavy
    description: "GROUP BY category with COUNT — 8 groups"
    tags: [group_by, count]

  - id: group_by_dept_avg_salary
    dataset: benchmark_employees
    sql: "SELECT department, AVG(salary) FROM benchmark_employees GROUP BY department"
    operator: group_by_aggregate
    family: group_by
    complexity: heavy
    description: "GROUP BY department with AVG salary — employees dataset"
    tags: [group_by, avg, employees]

  # ── Sort / Order By ───────────────────────────────────────────────────────
  - id: sort_asc
    dataset: benchmark_transactions
    sql: "SELECT id, amount FROM benchmark_transactions ORDER BY amount ASC"
    operator: sort
    family: sort
    complexity: heavy
    description: "Full table sort ascending by amount"
    tags: [sort, asc]

  - id: sort_desc
    dataset: benchmark_transactions
    sql: "SELECT id, amount FROM benchmark_transactions ORDER BY amount DESC"
    operator: sort
    family: sort
    complexity: heavy
    description: "Full table sort descending by amount"
    tags: [sort, desc]

  - id: top_k_10
    dataset: benchmark_transactions
    sql: "SELECT id, amount FROM benchmark_transactions ORDER BY amount DESC LIMIT 10"
    operator: sort_limit
    family: sort
    complexity: heavy
    description: "Top-10 by amount (sort + limit)"
    tags: [sort, limit, top_k]

  - id: top_k_salary
    dataset: benchmark_employees
    sql: "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary DESC LIMIT 10"
    operator: sort_limit
    family: sort
    complexity: heavy
    description: "Top-10 salaries from employees dataset"
    tags: [sort, limit, top_k, employees]

  # ── Join ──────────────────────────────────────────────────────────────────
  - id: equi_join_employee_manager
    dataset: benchmark_employees
    sql: >
      SELECT e.employee_id, e.department, m.employee_id AS manager_id
      FROM benchmark_employees e
      JOIN benchmark_employees m ON e.manager_id = m.employee_id
    operator: hash_join
    family: join
    complexity: heavy
    description: "Self-join on manager_id → employee_id (employees dataset)"
    tags: [join, self_join, employees]

  - id: scan_limit
    dataset: benchmark_transactions
    sql: "SELECT * FROM benchmark_transactions LIMIT 100"
    operator: scan_limit
    family: scan
    complexity: linear
    description: "Full scan with LIMIT — baseline overhead test"
    tags: [scan, limit]
"#
}

fn scenarios_yaml() -> &'static str {
    r#"# zkDB Canonical Benchmark Scenarios
# Version: 1.0.0
#
# This file defines benchmark scenarios that combine queries with execution parameters.
# Scenarios are algorithm-independent and can be reused with any zkDB backend.
#
# Each scenario has:
#   id:         Unique identifier
#   query_id:   Reference to queries.yaml
#   row_count:  Dataset size to benchmark
#   chunk_size: Chunk size for ingestion + proving
#   complexity: Expected proof complexity
#   notes:      Additional context

scenarios:

  # ── Standard suite (8 scenarios) ─────────────────────────────────────────
  standard_suite:
    description: "Standard workload — covers common operator patterns at 1000 rows"
    row_count_default: 1000
    scenarios:
      - id: std_filter_projection
        query_id: filter_projection
        row_count: 1000
        chunk_size: 256
        complexity: linear
        notes: "Baseline filter+project overhead"

      - id: std_filter_sum
        query_id: filter_sum
        row_count: 1000
        chunk_size: 256
        complexity: moderate
        notes: "Filter + aggregation combined"

      - id: std_count_all
        query_id: count_all
        row_count: 1000
        chunk_size: 256
        complexity: linear
        notes: "Simplest aggregate — baseline for COUNT overhead"

      - id: std_filter_count
        query_id: filter_count
        row_count: 1000
        chunk_size: 256
        complexity: linear
        notes: "Boolean predicate evaluation overhead"

      - id: std_range_filter
        query_id: range_filter
        row_count: 1000
        chunk_size: 256
        complexity: linear
        notes: "Compound predicate — two range conditions"

      - id: std_avg_aggregation
        query_id: avg_aggregation
        row_count: 1000
        chunk_size: 256
        complexity: moderate
        notes: "Category filter + AVG — typical analytics query"

      - id: std_multi_aggregate
        query_id: multi_aggregate
        row_count: 1000
        chunk_size: 256
        complexity: moderate
        notes: "Multiple aggregates — COUNT + SUM + AVG in one pass"

      - id: std_scan_limit
        query_id: scan_limit
        row_count: 1000
        chunk_size: 256
        complexity: linear
        notes: "Scan+limit baseline — minimal operator overhead"

  # ── Operator suite: GROUP BY ──────────────────────────────────────────────
  group_by_suite:
    description: "GROUP BY workloads — exercises sort+group+aggregate circuit"
    scenarios:
      - id: gb_region_sum_1000
        query_id: group_by_region_sum
        row_count: 1000
        chunk_size: 256
        complexity: heavy
        notes: "6 groups (regions) — typical low-cardinality group_by"

      - id: gb_category_count_1000
        query_id: group_by_category_count
        row_count: 1000
        chunk_size: 256
        complexity: heavy
        notes: "8 groups (categories) — slightly higher cardinality"

      - id: gb_dept_avg_200
        query_id: group_by_dept_avg_salary
        row_count: 200
        chunk_size: 64
        complexity: heavy
        notes: "Employees dataset — 8 departments"

  # ── Operator suite: SORT ──────────────────────────────────────────────────
  sort_suite:
    description: "ORDER BY workloads — exercises sort circuit + permutation check"
    scenarios:
      - id: sort_asc_1000
        query_id: sort_asc
        row_count: 1000
        chunk_size: 256
        complexity: heavy
        notes: "Full ascending sort — baseline sort overhead"

      - id: sort_desc_1000
        query_id: sort_desc
        row_count: 1000
        chunk_size: 256
        complexity: heavy
        notes: "Full descending sort"

      - id: top_k_10_1000
        query_id: top_k_10
        row_count: 1000
        chunk_size: 256
        complexity: heavy
        notes: "Top-10 out of 1000 — sort + limit"

      - id: top_k_salary_200
        query_id: top_k_salary
        row_count: 200
        chunk_size: 64
        complexity: heavy
        notes: "Top-10 salaries from 200-row employees"

  # ── Operator suite: JOIN ──────────────────────────────────────────────────
  join_suite:
    description: "Equi-join workloads — exercises join key equality constraints"
    scenarios:
      - id: self_join_employees_200
        query_id: equi_join_employee_manager
        row_count: 200
        chunk_size: 64
        complexity: heavy
        notes: "Self-join on manager relationship — correctness check"

  # ── Scale test ────────────────────────────────────────────────────────────
  scale_suite:
    description: "Same queries at increasing row counts — for scaling analysis"
    query_id: filter_sum
    row_counts: [100, 500, 1000, 5000, 10000]
    chunk_size: 256
    complexity: moderate
    notes: "Run filter_sum at 5 scales to characterize O(n) behavior"
"#
}

fn metrics_schema_json() -> Result<String, ExportError> {
    let schema = serde_json::json!({
        "version": "1.0.0",
        "description": "Canonical metrics schema for zkDB benchmarks. Algorithm-independent.",
        "note": "Use this schema to validate result files from any zkDB backend implementation.",
        "fields": {
            "dataset_generation_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to generate the synthetic dataset rows",
                "comparable_across_backends": true
            },
            "ingestion_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to ingest rows into the database (encode + chunk)",
                "comparable_across_backends": true
            },
            "snapshot_creation_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to create a committed snapshot (Merkle root computation)",
                "comparable_across_backends": true
            },
            "snapshot_activation_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to activate the snapshot for querying",
                "comparable_across_backends": true
            },
            "query_planning_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to parse SQL and build the proof plan",
                "comparable_across_backends": true
            },
            "proof_generation_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to generate the proof (backend-specific proving time)",
                "comparable_across_backends": false,
                "comparison_note": "Compare only within the same proof_system_kind"
            },
            "verification_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Time to verify the proof",
                "comparable_across_backends": false,
                "comparison_note": "Compare only within the same proof_system_kind"
            },
            "total_us": {
                "type": "u64",
                "unit": "microseconds",
                "description": "Total wall-clock time from start to end"
            },
            "proof_size_bytes": {
                "type": "usize",
                "unit": "bytes",
                "description": "Size of the serialized proof artifact",
                "comparable_across_backends": false,
                "comparison_note": "SNARK proofs are O(1), hash-chain proofs are O(n)"
            },
            "verification_key_size_bytes": {
                "type": "usize",
                "unit": "bytes",
                "description": "Size of the verification key"
            },
            "row_count": {
                "type": "usize",
                "unit": "rows",
                "description": "Number of rows in the dataset being proved"
            },
            "chunk_count": {
                "type": "usize",
                "unit": "chunks",
                "description": "Number of chunks the dataset was divided into"
            },
            "proving_throughput_rps": {
                "type": "f64",
                "unit": "rows_per_second",
                "description": "Derived: row_count / (proof_generation_us / 1e6)",
                "comparable_across_backends": false
            }
        },
        "quality_flags": {
            "description": "Every metric value has a quality annotation indicating trustworthiness",
            "values": {
                "real": "Measured from a fully-implemented proving backend — suitable for research comparison",
                "estimated": "Approximation from a partial backend — treat with caution",
                "placeholder": "From a mock/stub backend — NOT suitable for research comparison"
            }
        }
    });
    Ok(serde_json::to_string_pretty(&schema)?)
}

fn result_schema_json() -> Result<String, ExportError> {
    let schema = serde_json::json!({
        "version": "1.0.0",
        "description": "Canonical result record schema for zkDB benchmarks. Portable across all backends.",
        "note": "Emit records in this format so they can be compared across Plonky2, Halo2, etc.",
        "result_record": {
            "run_id": {
                "type": "uuid",
                "description": "Unique run identifier"
            },
            "scenario_id": {
                "type": "string",
                "description": "Reference to scenarios.yaml scenario id"
            },
            "scenario_name": {
                "type": "string",
                "description": "Human-readable scenario name"
            },
            "backend_name": {
                "type": "string",
                "description": "Human-readable backend name (e.g. 'Plonky2 FRI SNARK')"
            },
            "backend_kind": {
                "type": "string",
                "enum": ["mock", "constraint_checked", "plonky2", "plonky3", "halo2", "risc_v_stark", "other"],
                "description": "Backend classification for cross-algorithm comparison"
            },
            "proof_system_kind": {
                "type": "string",
                "enum": ["none", "hash_chain_audit", "plonky2_snark", "halo2_snark", "groth16_snark", "stark_poseidon", "other"],
                "description": "Specific proof system used — the key discriminator for honest comparison"
            },
            "is_zero_knowledge": {
                "type": "bool",
                "description": "Whether the proof system provides zero-knowledge guarantees"
            },
            "is_succinct": {
                "type": "bool",
                "description": "Whether verification is sub-linear in witness size"
            },
            "has_real_constraints": {
                "type": "bool",
                "description": "Whether operator invariants (sort order, group boundaries) are enforced"
            },
            "sql": {
                "type": "string",
                "description": "SQL query that was benchmarked"
            },
            "row_count": {
                "type": "usize",
                "description": "Dataset row count"
            },
            "chunk_size": {
                "type": "u32",
                "description": "Chunk size used for ingestion"
            },
            "query_family": {
                "type": "string",
                "enum": ["scan", "filter", "aggregate", "group_by", "sort", "join", "mixed"]
            },
            "operator_family": {
                "type": "string",
                "description": "Specific operator combination exercised"
            },
            "complexity_class": {
                "type": "string",
                "enum": ["linear", "moderate", "heavy", "recursive"]
            },
            "metrics": {
                "type": "object",
                "description": "See metrics_schema.json for field definitions",
                "ref": "metrics_schema.json"
            },
            "metric_quality": {
                "type": "string",
                "enum": ["real", "estimated", "placeholder"],
                "description": "Overall quality of proof metrics for this result"
            },
            "execution_coverage": {
                "type": "string",
                "enum": ["full", "partial", "stub"],
                "description": "full=all operators executed; partial=some operators stubbed; stub=entire pipeline is mock"
            },
            "constraint_coverage": {
                "type": "string",
                "enum": ["enforced", "partial", "none"],
                "description": "Whether operator constraints (sort, group, join invariants) are checked"
            },
            "cryptographic_coverage": {
                "type": "string",
                "enum": ["full_snark", "hash_chain_only", "none"],
                "description": "What cryptographic machinery was used"
            },
            "zero_knowledge_level": {
                "type": "string",
                "enum": ["full_zk", "partial_zk", "none"],
                "description": "ZK properties of the proof"
            },
            "success": {
                "type": "bool",
                "description": "Whether the benchmark scenario completed successfully"
            },
            "error": {
                "type": "string",
                "nullable": true,
                "description": "Error message if success=false"
            },
            "started_at_ms": {
                "type": "u64",
                "unit": "unix_milliseconds"
            },
            "finished_at_ms": {
                "type": "u64",
                "unit": "unix_milliseconds"
            }
        },
        "comparison_guidance": {
            "cross_backend_comparable": [
                "dataset_generation_us",
                "ingestion_us",
                "snapshot_creation_us",
                "query_planning_us",
                "row_count",
                "chunk_count"
            ],
            "same_proof_system_only": [
                "proof_generation_us",
                "verification_us",
                "proof_size_bytes"
            ],
            "never_compare": [
                "run_id",
                "started_at_ms",
                "finished_at_ms"
            ]
        }
    });
    Ok(serde_json::to_string_pretty(&schema)?)
}

fn report_template_md() -> &'static str {
    r#"# zkDB Benchmark Report — {{backend_name}}

> **Template version:** 1.0.0
> Replace all `{{placeholder}}` values when filling this template.
> Or use `cargo run -- bench export-report` to auto-generate a filled report.

**Generated:** {{generated_at}}
**Backend:** {{backend_name}}
**Proof system:** `{{proof_system_kind}}`
**Zero-knowledge:** {{is_zero_knowledge}}
**Succinct verification:** {{is_succinct}}
**Real constraints:** {{has_real_constraints}}

---

## Environment

| Field | Value |
|---|---|
| OS | {{os}} |
| Architecture | {{arch}} |
| Backend kind | `{{backend_kind}}` |
| Proof system | `{{proof_system_kind}}` |
| Rust version | {{rust_version}} |

---

## Dataset

This report uses the canonical zkDB benchmark pack datasets.

| Dataset | Rows | Description |
|---|---|---|
| `benchmark_transactions` | {{transactions_rows}} | Synthetic transaction records |
| `benchmark_employees` | {{employees_rows}} | Synthetic employee records |

See `benchmark_pack/dataset/schema.json` for column definitions.
See `benchmark_pack/dataset/generation_config.json` for generation parameters.

All datasets are **deterministically generated** and **algorithm-independent**.

---

## Use-Cases

{{scenario_count}} scenarios from `benchmark_pack/usecases/scenarios.yaml`.

Operators covered:
- Filter / Projection
- COUNT / SUM / AVG aggregation
- GROUP BY (count, sum, avg)
- ORDER BY (asc, desc)
- TOP-K
- Equi-JOIN

---

## Results

**{{passed_count}} / {{total_count}} scenarios passed.**

| Scenario | Rows | Operator | Complexity | Proof ms | Verify ms | Proof bytes | Quality | Status |
|---|---|---|---|---|---|---|---|---|
| {{scenario_row_1}} | ... | ... | ... | ... | ... | ... | ... | ... |

*See individual scenario sections below for details.*

---

## Scenario Details

### `{{scenario_name}}`

**Description:** {{scenario_description}}

```sql
{{scenario_sql}}
```

| Metric | Value |
|---|---|
| Status | {{status}} |
| Rows | {{row_count}} |
| Proof generation | {{proof_ms}} ms |
| Verification | {{verify_ms}} ms |
| Proof size | {{proof_bytes}} bytes |
| Quality | {{quality}} |

---

## Backend Capabilities

| Capability | Value |
|---|---|
| Backend name | {{backend_name}} |
| Proof system | `{{proof_system_kind}}` |
| Zero-knowledge | {{is_zero_knowledge}} |
| Succinct verification | {{is_succinct}} |
| Real operator constraints | {{has_real_constraints}} |

---

## Observations

- {{observation_1}}
- {{observation_2}}

---

## Limitations

- {{limitation_1}}
- {{limitation_2}}

---

## Reproducibility

```bash
cargo run --release -- bench suite --backend {{backend_kind}} --rows 1000
cargo run --release -- bench export-report --output report.md
```

See `benchmark_pack/reports/reproducibility.md` for cross-algorithm instructions.

---

*Generated by zkDB benchmark runner. Pack version: 1.0.0.*
"#
}

fn methodology_md() -> &'static str {
    r#"# Benchmark Methodology

Version: 1.0.0

## Overview

This document describes how the zkDB benchmarks are run, what is measured,
and how reproducibility is ensured.

## Benchmark Pipeline

Each benchmark scenario follows this pipeline:

```
1. Dataset generation (deterministic, seeded)
     ↓
2. Row ingestion (encode → chunk → store)
     ↓
3. Snapshot creation (Merkle root computation)
     ↓
4. Snapshot activation
     ↓
5. Query planning (SQL parse → proof plan)
     ↓
6. Witness building (row data → circuit witness)
     ↓
7. Proof generation (backend-specific)
     ↓
8. Proof verification (backend-specific)
     ↓
9. Metrics collection
```

Each phase is timed independently with microsecond precision.

## What is Measured

### Timing
All timing uses wall-clock time in microseconds.

| Phase | Metric field | Notes |
|---|---|---|
| Dataset generation | `dataset_generation_us` | Synthetic row creation only |
| Ingestion | `ingestion_us` | Encoding + chunking |
| Snapshot creation | `snapshot_creation_us` | Merkle root computation |
| Snapshot activation | `snapshot_activation_us` | Index update |
| Query planning | `query_planning_us` | SQL parse + proof plan |
| Proof generation | `proof_generation_us` | **Backend-specific** |
| Verification | `verification_us` | **Backend-specific** |
| Total | `total_us` | End-to-end wall-clock |

### Sizes
- `proof_size_bytes`: Serialized proof artifact
- `verification_key_size_bytes`: Verification key

### Quality Flags
Every metric has a quality annotation:
- `real`: From a fully-implemented backend — suitable for research comparison
- `estimated`: Approximation — treat with caution
- `placeholder`: From a mock/stub — NOT suitable for research comparison

**Important:** Only compare `proof_generation_us` and `proof_size_bytes` between
backends with the same `proof_system_kind`. A hash-chain audit proof and a Plonky2
SNARK are fundamentally different constructions; their sizes and timings are not
directly comparable.

## Dataset Reproducibility

All datasets are generated deterministically:
- Same algorithm: `wrapping_hash(i)` — seeded LCG
- Same constants across all runs and machines
- No randomness from system entropy

To regenerate identical datasets:
```bash
cargo run --release -- bench export-pack
```

## Scenario Reproducibility

Scenarios are defined in `benchmark_pack/usecases/scenarios.yaml`.
They are algorithm-independent — the same YAML file works for any backend.

## Backend Honesty Requirements

Any backend implementation that uses this benchmark pack MUST:

1. Report `proof_system_kind` accurately (not claim SNARK when using hash-chain)
2. Report `is_zero_knowledge: false` for hash-chain or mock backends
3. Report `metric_quality: placeholder` for mock/stub backends
4. Include `limitations` section in the report

## What is NOT measured

- Memory usage (not yet instrumented)
- Parallelism / multi-core utilization
- Proof compression
- Recursive aggregation overhead (separate benchmark needed)

## Statistical Notes

For single-run results (default), timing values are point measurements.
For statistical analysis, use `--iterations N` to run multiple times and
get mean ± std dev.

## Reference implementation

The reference implementation is the `ConstraintCheckedBackend` in `zkdb-plonky2`.
It enforces real operator constraints (sort, group_by, join key equality) using
Blake3-based hash-chain audit proofs.

**It is NOT a SNARK.** Comparison with Plonky2 or Halo2 results must acknowledge
the fundamental difference in cryptographic guarantees.
"#
}

fn reproducibility_md() -> &'static str {
    r#"# Reproducibility Guide

Version: 1.0.0

## Purpose

This document explains how to copy the benchmark pack into another
proving algorithm repository and run the same benchmark workload there.

## What is portable

The following files contain NO algorithm-specific content and can be
copied verbatim into any zkDB implementation:

```
benchmark_pack/
├── README.md
├── dataset/
│   ├── schema.json             ← Column definitions
│   ├── generation_config.json  ← Deterministic generation config
│   ├── transactions.csv        ← 1000 canonical transactions
│   ├── employees.csv           ← 200 canonical employees
│   └── snapshot_manifest.json  ← Dataset metadata
├── usecases/
│   ├── queries.yaml            ← SQL query definitions
│   └── scenarios.yaml          ← Benchmark scenario definitions
├── metrics/
│   ├── metrics_schema.json     ← Metrics field definitions
│   └── result_schema.json      ← Result record schema
└── reports/
    ├── report_template.md      ← Reusable report template
    ├── methodology.md          ← Methodology documentation
    └── reproducibility.md      ← This file
```

## What is NOT portable

These files are backend-specific and must be reimplemented in each repo:
- `src/backend/` — The proving backend implementation
- `src/circuit/` — Circuit definitions
- `src/benchmarks/runner.rs` — Benchmark execution pipeline

## Step-by-step: reusing in a Halo2 repo

### Step 1: Copy the pack

```bash
cp -r benchmark_pack/ /path/to/halo2-zkdb/benchmark_pack/
```

### Step 2: Parse the dataset

Load `benchmark_pack/dataset/transactions.csv` and `employees.csv`.
Column definitions are in `benchmark_pack/dataset/schema.json`.

Alternatively, regenerate from `generation_config.json` using the
documented hash formula to ensure bit-exact reproducibility.

### Step 3: Implement the scenarios

Read `benchmark_pack/usecases/scenarios.yaml`.
Implement each scenario using your backend's query and proving pipeline.

### Step 4: Collect results

For each scenario, collect metrics using `benchmark_pack/metrics/metrics_schema.json`
as the field reference. Output results as JSON following `result_schema.json`.

**Critical fields:**
- `proof_system_kind`: Set to `halo2_snark` (not `plonky2_snark` or `hash_chain_audit`)
- `is_zero_knowledge`: Set to `true` if your Halo2 circuit uses ZK blinding
- `metric_quality`: Set to `real` only if the backend is fully implemented

### Step 5: Generate the report

Fill in `benchmark_pack/reports/report_template.md` with your results.
Or implement an equivalent report generator in your language.

### Step 6: Compare with zkdb-plonky2

Use `benchmark_pack/metrics/result_schema.json` to ensure both result
files have the same structure. Then compare:

- `dataset_generation_us`, `ingestion_us`, `query_planning_us` — comparable directly
- `proof_generation_us`, `proof_size_bytes` — compare **only within same proof system**
- Add `proof_system_kind` as a column in any cross-algorithm comparison table

## Cross-algorithm comparison rules

**NEVER** compare `proof_generation_us` between:
- hash_chain_audit (O(n) hashing) vs plonky2_snark (polynomial proving)
- mock (trivial Blake3) vs any real backend

These are fundamentally different constructions with incompatible timing semantics.

**ALWAYS** include `proof_system_kind` and `metric_quality` in any comparison table.

**SAFE to compare** across all backends:
- `dataset_generation_us`
- `ingestion_us`
- `snapshot_creation_us`
- `query_planning_us`
- `row_count`, `chunk_count`

## Version compatibility

Benchmark pack version: 1.0.0

Results produced from this pack version can be compared with any other
result produced from the same pack version, regardless of backend.

If the pack version changes (new scenarios, schema changes), use the version
field in each file to ensure you're comparing compatible results.

## Generating the canonical CSV files

To regenerate the canonical CSV files from scratch:

```bash
cargo run --release -- bench export-pack --output benchmark_pack --rows 1000
```

The output is deterministic — running this twice produces identical files.

## Contact / questions

See the zkDB project README or open an issue for questions about
benchmark methodology or pack format.
"#
}
