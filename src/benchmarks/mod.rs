//! Benchmarking framework for zkDB.
//!
//! Provides deterministic dataset generation, benchmark scenarios,
//! metrics collection, comparison, persistence, and a runner that
//! drives the full pipeline: ingest → snapshot → query → prove → verify → measure.

pub mod cases;
pub mod compare;
pub mod dataset;
pub mod metrics;
pub mod pack;
pub mod runner;
pub mod storage;
pub mod types;

pub use compare::BenchmarkComparison;
pub use pack::{BenchmarkPackExporter, CanonicalRowCounts, ReportContext, ReportGenerator};
pub use runner::BenchmarkRunner;
pub use storage::BenchmarkStore;
pub use types::{BenchmarkResult, BenchmarkRunId, BenchmarkScenario};
