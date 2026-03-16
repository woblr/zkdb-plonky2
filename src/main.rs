//! zkDB binary entry point.
//!
//! Supports two modes:
//! - `zkdb serve` — start the HTTP API server (default)
//! - `zkdb bench <subcommand>` — CLI benchmark commands

use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zkdb_plonky2::{
    api::{build_router, AppState},
    backend::MockBackend,
    benchmarks::{
        cases::{extended_suite, full_operator_suite, standard_suite},
        compare::BenchmarkComparison,
        pack::{BenchmarkPackExporter, CanonicalRowCounts, ReportContext, ReportGenerator},
        runner::BenchmarkRunner,
        storage::BenchmarkStore,
        types::{BackendKind, BenchmarkScenario},
    },
    commitment::service::Blake3CommitmentService,
    database::storage::{InMemoryChunkStore, InMemoryDatasetRepository, InMemorySnapshotRepository},
    policy::engine::PolicyEngine,
};

// ─────────────────────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "zkdb", about = "Zero-knowledge database with snapshot-based proving")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP API server.
    Serve {
        /// Bind address (default: 0.0.0.0:3000).
        #[arg(short, long, default_value = "0.0.0.0:3000")]
        bind: String,
    },
    /// Run benchmark commands.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },
}

#[derive(Subcommand)]
enum BenchAction {
    /// Run a single benchmark scenario.
    Run {
        /// SQL query to benchmark.
        #[arg(short, long)]
        sql: String,
        /// Number of rows.
        #[arg(short, long, default_value = "1000")]
        rows: usize,
        /// Backend (mock, constraint_checked, plonky2).
        #[arg(short, long, default_value = "mock")]
        backend: String,
        /// Chunk size.
        #[arg(short, long, default_value = "256")]
        chunk_size: u32,
        /// Number of iterations.
        #[arg(short, long, default_value = "1")]
        iterations: usize,
    },
    /// Run the standard benchmark suite.
    Suite {
        /// Number of rows per scenario.
        #[arg(short, long, default_value = "1000")]
        rows: usize,
        /// Backend (mock, constraint_checked, plonky2).
        #[arg(short, long, default_value = "mock")]
        backend: String,
        /// Run extended suite with heavier scenarios (more scenarios).
        #[arg(short = 'x', long)]
        extended: bool,
        /// Run full operator suite (group_by + sort + join).
        #[arg(short, long)]
        full: bool,
        /// Auto-generate report.md after the suite completes.
        #[arg(long)]
        report: bool,
    },
    /// Compare two stored suite results.
    Compare {
        /// First suite ID.
        suite_a: String,
        /// Second suite ID.
        suite_b: String,
    },
    /// List stored benchmark results.
    List,
    /// Export all stored results as JSON.
    Export {
        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Export the portable benchmark pack (datasets, use-cases, metrics schema, report templates).
    ExportPack {
        /// Output directory (default: benchmark_pack).
        #[arg(short, long, default_value = "benchmark_pack")]
        output: String,
        /// Number of transaction rows to generate.
        #[arg(long, default_value = "1000")]
        transactions: usize,
        /// Number of employee rows to generate.
        #[arg(long, default_value = "200")]
        employees: usize,
    },
    /// Generate report.md from stored benchmark results.
    ExportReport {
        /// Suite ID to generate report from. If omitted, uses most recent suite.
        #[arg(long)]
        suite: Option<String>,
        /// Output file path (default: report.md).
        #[arg(short, long, default_value = "report.md")]
        output: String,
        /// Backend kind for capability metadata (mock, constraint_checked, plonky2).
        #[arg(short, long, default_value = "mock")]
        backend: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zkdb=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Serve { .. }) => {
            let bind = match cli.command {
                Some(Commands::Serve { bind }) => bind,
                _ => std::env::var("ZKDB_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string()),
            };
            run_server(bind).await
        }
        Some(Commands::Bench { action }) => run_bench(action).await,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_server(bind: String) -> anyhow::Result<()> {
    tracing::info!("starting zkDB server");

    let dataset_repo = Arc::new(InMemoryDatasetRepository::new());
    let snapshot_repo = Arc::new(InMemorySnapshotRepository::new());
    let chunk_store = Arc::new(InMemoryChunkStore::new());
    let commitment_svc = Arc::new(Blake3CommitmentService);
    let backend = Arc::new(MockBackend::default());
    let policy_engine = PolicyEngine::new();

    let state = AppState::new(
        dataset_repo,
        snapshot_repo,
        chunk_store,
        commitment_svc,
        backend,
        policy_engine,
    );

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on http://{}", bind);

    let router = build_router(state);
    axum::serve(listener, router).await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark CLI
// ─────────────────────────────────────────────────────────────────────────────

async fn run_bench(action: BenchAction) -> anyhow::Result<()> {
    match action {
        BenchAction::Run {
            sql,
            rows,
            backend,
            chunk_size,
            iterations,
        } => {
            let backend_kind = parse_backend(&backend);
            let backend_impl = make_backend(&backend_kind);
            let runner = BenchmarkRunner::in_memory(backend_impl);

            let scenario = BenchmarkScenario::new("cli_run", &sql, rows)
                .with_chunk_size(chunk_size)
                .with_backend(backend_kind);

            if iterations == 1 {
                let result = runner.run(&scenario).await;
                result.print_summary();

                if let Ok(store) = BenchmarkStore::default_location() {
                    store.save(&result)?;
                    println!("\nStored as run_id: {}", result.run_id);
                }
            } else {
                let results = runner.run_repeated(&scenario, iterations).await;
                for r in &results {
                    r.print_summary();
                }

                let metrics: Vec<_> = results.iter().map(|r| r.metrics.clone()).collect();
                let agg = zkdb_plonky2::benchmarks::metrics::aggregate_metrics(&metrics);
                println!();
                agg.print();

                if let Ok(store) = BenchmarkStore::default_location() {
                    for r in &results {
                        store.save(r)?;
                    }
                    println!("\nStored {} results", results.len());
                }
            }
        }

        BenchAction::Suite {
            rows,
            backend,
            extended,
            full,
            report,
        } => {
            let backend_kind = parse_backend(&backend);
            let backend_impl = make_backend(&backend_kind);
            let runner = BenchmarkRunner::in_memory(backend_impl);

            let scenarios = if full {
                full_operator_suite(rows, backend_kind.clone())
            } else if extended {
                extended_suite(rows, backend_kind.clone())
            } else {
                standard_suite(rows, backend_kind.clone())
            };

            let results = runner.run_suite(&scenarios).await;

            let total = results.len();
            let ok = results.iter().filter(|r| r.success).count();
            let fail = total - ok;

            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║  Suite Summary: {} scenarios, {} passed, {} failed", total, ok, fail);
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            for r in &results {
                r.print_summary();
            }

            let suite_id_opt = if let Ok(store) = BenchmarkStore::default_location() {
                let suite_id = store.save_suite(&results)?;
                println!("\nStored suite as: {}", suite_id);
                Some(suite_id)
            } else {
                None
            };

            // Auto-generate report.md if --report flag was passed
            if report {
                let ctx = ReportContext::from_backend_kind(&backend_kind);
                let output_path = std::path::Path::new("report.md");
                match ReportGenerator::generate(&results, output_path, &ctx) {
                    Ok(()) => println!("Report written to report.md"),
                    Err(e) => eprintln!("Warning: report generation failed: {}", e),
                }
                let _ = suite_id_opt; // suppress unused warning
            }
        }

        BenchAction::Compare { suite_a, suite_b } => {
            let store = BenchmarkStore::default_location()?;
            let results_a = store.load_suite(&suite_a)?;
            let results_b = store.load_suite(&suite_b)?;

            let comparison =
                BenchmarkComparison::compare(&suite_a, &suite_b, &results_a, &results_b);
            comparison.print();
        }

        BenchAction::List => {
            let store = BenchmarkStore::default_location()?;

            let suites = store.list_suites()?;
            if !suites.is_empty() {
                println!("Stored suites:");
                for s in &suites {
                    println!(
                        "  {} — {} scenarios ({} successful)",
                        s.suite_id, s.scenario_count, s.successful
                    );
                }
            }

            let ids = store.list_run_ids()?;
            println!("\nTotal stored runs: {}", ids.len());
            for id in ids.iter().take(20) {
                println!("  {}", id);
            }
            if ids.len() > 20 {
                println!("  ... and {} more", ids.len() - 20);
            }
        }

        BenchAction::Export { output } => {
            let store = BenchmarkStore::default_location()?;
            let json = store.export_all_json()?;

            match output {
                Some(path) => {
                    std::fs::write(&path, &json)?;
                    println!("Exported to {}", path);
                }
                None => {
                    println!("{}", json);
                }
            }
        }

        BenchAction::ExportPack {
            output,
            transactions,
            employees,
        } => {
            let row_counts = CanonicalRowCounts {
                transactions,
                employees,
            };
            let output_dir = std::path::Path::new(&output);
            match BenchmarkPackExporter::export(output_dir, row_counts) {
                Ok(summary) => summary.print(),
                Err(e) => {
                    eprintln!("Export failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        BenchAction::ExportReport {
            suite,
            output,
            backend,
        } => {
            let store = BenchmarkStore::default_location()?;

            // Load the requested suite, or fall back to the most recent one.
            let results = match suite {
                Some(ref id) => store.load_suite(id)?,
                None => {
                    let suites = store.list_suites()?;
                    match suites.into_iter().next() {
                        Some(s) => store.load_suite(&s.suite_id)?,
                        None => {
                            eprintln!("No stored suites found. Run `bench suite` first.");
                            std::process::exit(1);
                        }
                    }
                }
            };

            let backend_kind = parse_backend(&backend);
            let ctx = ReportContext::from_backend_kind(&backend_kind);
            let output_path = std::path::Path::new(&output);

            ReportGenerator::generate(&results, output_path, &ctx)?;
            println!("Report written to {}", output);
        }
    }

    Ok(())
}

fn parse_backend(s: &str) -> BackendKind {
    match s {
        "constraint_checked" | "baseline" | "real" => BackendKind::ConstraintChecked,
        "plonky2" => BackendKind::Plonky2,
        "plonky3" => BackendKind::Plonky3,
        "halo2" => BackendKind::Halo2,
        _ => BackendKind::Mock,
    }
}

fn make_backend(kind: &BackendKind) -> Arc<dyn zkdb_plonky2::backend::ProvingBackend> {
    use zkdb_plonky2::backend::{ConstraintCheckedBackend, Plonky2Backend};
    match kind {
        BackendKind::ConstraintChecked | BackendKind::Baseline => {
            Arc::new(ConstraintCheckedBackend::default())
        }
        BackendKind::Plonky2 => Arc::new(Plonky2Backend::new_stub()),
        _ => Arc::new(MockBackend::default()),
    }
}
