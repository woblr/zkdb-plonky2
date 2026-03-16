//! Core benchmark types: IDs, scenarios, result records, metric quality, and classification enums.

use crate::types::{BackendTag, DatasetId, ProofId, QueryId, SnapshotId};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkRunId
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BenchmarkRunId(pub Uuid);

impl BenchmarkRunId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for BenchmarkRunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BenchmarkRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for BenchmarkRunId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<Uuid>()?))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackendKind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Deterministic stub. No constraints. No proof system.
    Mock,
    /// DEPRECATED alias kept for JSON compat — same as ConstraintChecked.
    #[serde(alias = "baseline")]
    Baseline,
    /// Real constraints + hash-chain audit. NOT zero-knowledge. NOT succinct.
    ConstraintChecked,
    /// Plonky2 FRI SNARK. Zero-knowledge. Succinct. (stub — not yet wired)
    Plonky2,
    /// Plonky3 (stub — not yet wired)
    Plonky3,
    /// Halo2 (stub — not yet wired)
    Halo2,
}

impl From<&BackendTag> for BackendKind {
    fn from(tag: &BackendTag) -> Self {
        match tag {
            BackendTag::Mock              => BackendKind::Mock,
            BackendTag::Baseline          => BackendKind::ConstraintChecked,
            BackendTag::ConstraintChecked => BackendKind::ConstraintChecked,
            BackendTag::Plonky2           => BackendKind::Plonky2,
            BackendTag::Plonky3           => BackendKind::Plonky3,
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendKind::Mock              => write!(f, "mock"),
            BackendKind::Baseline          => write!(f, "constraint_checked"),
            BackendKind::ConstraintChecked => write!(f, "constraint_checked"),
            BackendKind::Plonky2           => write!(f, "plonky2"),
            BackendKind::Plonky3           => write!(f, "plonky3"),
            BackendKind::Halo2             => write!(f, "halo2"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricQuality — indicates whether a metric is from a real proving backend
// ─────────────────────────────────────────────────────────────────────────────

/// Indicates trustworthiness of a benchmark metric.
///
/// - `Real`: measured from a fully-implemented proving backend.
/// - `Estimated`: computed from a partial implementation with known approximation.
/// - `Placeholder`: produced by a mock/stub; not meaningful for research comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricQuality {
    /// The metric comes from a real proving backend (e.g. Plonky2 native).
    Real,
    /// The metric is an approximation from a partial backend.
    Estimated,
    /// The metric is from a mock/stub backend — structurally correct but not meaningful.
    Placeholder,
}

impl MetricQuality {
    pub fn is_real(&self) -> bool {
        matches!(self, MetricQuality::Real)
    }
}

impl fmt::Display for MetricQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricQuality::Real => write!(f, "real"),
            MetricQuality::Estimated => write!(f, "estimated"),
            MetricQuality::Placeholder => write!(f, "placeholder"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricQualityFlags — per-metric quality annotations
// ─────────────────────────────────────────────────────────────────────────────

/// Per-metric quality annotations so consumers know which numbers are trustworthy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQualityFlags {
    pub proof_generation_time: MetricQuality,
    pub verification_time: MetricQuality,
    pub proof_size: MetricQuality,
    pub vk_size: MetricQuality,
    /// Overall quality: the minimum across all critical proof metrics.
    pub overall: MetricQuality,
}

impl MetricQualityFlags {
    pub fn all_placeholder() -> Self {
        Self {
            proof_generation_time: MetricQuality::Placeholder,
            verification_time: MetricQuality::Placeholder,
            proof_size: MetricQuality::Placeholder,
            vk_size: MetricQuality::Placeholder,
            overall: MetricQuality::Placeholder,
        }
    }

    pub fn all_real() -> Self {
        Self {
            proof_generation_time: MetricQuality::Real,
            verification_time: MetricQuality::Real,
            proof_size: MetricQuality::Real,
            vk_size: MetricQuality::Real,
            overall: MetricQuality::Real,
        }
    }

    /// Derive from a `BackendKind` — mock is always placeholder.
    pub fn from_backend(kind: &BackendKind) -> Self {
        match kind {
            BackendKind::Mock => Self::all_placeholder(),
            _ => Self::all_real(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryFamily / OperatorFamily / ComplexityClass
// ─────────────────────────────────────────────────────────────────────────────

/// Broad category of a benchmark query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryFamily {
    Scan,
    Filter,
    Aggregate,
    GroupBy,
    Sort,
    Join,
    Mixed,
}

impl fmt::Display for QueryFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            QueryFamily::Scan => "scan",
            QueryFamily::Filter => "filter",
            QueryFamily::Aggregate => "aggregate",
            QueryFamily::GroupBy => "group_by",
            QueryFamily::Sort => "sort",
            QueryFamily::Join => "join",
            QueryFamily::Mixed => "mixed",
        })
    }
}

/// Which proof operators are exercised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorFamily {
    TableScan,
    Filter,
    Projection,
    Aggregate,
    GroupByAggregate,
    Sort,
    Limit,
    Join,
    FilterProject,
    FilterAggregate,
    GroupBySort,
    Multi,
}

impl fmt::Display for OperatorFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Expected proof complexity tier (used to categorize benchmarks for reporting).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplexityClass {
    /// O(n) scan, simple constraints.
    Linear,
    /// Filter + aggregate, still per-row.
    Moderate,
    /// Group-by / sort / join — requires cross-row gadgets.
    Heavy,
    /// Recursive aggregation over many chunks.
    Recursive,
}

impl fmt::Display for ComplexityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkScenario
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkScenario {
    pub name: String,
    pub description: String,
    pub sql: String,
    pub row_count: usize,
    pub chunk_size: u32,
    pub backend: BackendKind,
    pub tags: Vec<String>,
    /// Classification metadata.
    pub query_family: QueryFamily,
    pub operator_family: OperatorFamily,
    pub complexity_class: ComplexityClass,
}

impl BenchmarkScenario {
    pub fn new(name: impl Into<String>, sql: impl Into<String>, row_count: usize) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            sql: sql.into(),
            row_count,
            chunk_size: 256,
            backend: BackendKind::Mock,
            tags: Vec::new(),
            query_family: QueryFamily::Mixed,
            operator_family: OperatorFamily::Multi,
            complexity_class: ComplexityClass::Moderate,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_chunk_size(mut self, size: u32) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_backend(mut self, backend: BackendKind) -> Self {
        self.backend = backend;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_classification(
        mut self,
        family: QueryFamily,
        operator: OperatorFamily,
        complexity: ComplexityClass,
    ) -> Self {
        self.query_family = family;
        self.operator_family = operator;
        self.complexity_class = complexity;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkMetrics
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    // ── Timing (microseconds) ──
    pub dataset_generation_us: u64,
    pub ingestion_us: u64,
    pub snapshot_creation_us: u64,
    pub snapshot_activation_us: u64,
    pub query_planning_us: u64,
    pub proof_generation_us: u64,
    pub verification_us: u64,
    pub total_us: u64,

    // ── Size ──
    pub proof_size_bytes: usize,
    pub verification_key_size_bytes: usize,

    // ── Counts ──
    pub row_count: usize,
    pub chunk_count: usize,

    // ── Quality ──
    pub quality: MetricQualityFlags,
}

impl BenchmarkMetrics {
    pub fn empty() -> Self {
        Self {
            dataset_generation_us: 0,
            ingestion_us: 0,
            snapshot_creation_us: 0,
            snapshot_activation_us: 0,
            query_planning_us: 0,
            proof_generation_us: 0,
            verification_us: 0,
            total_us: 0,
            proof_size_bytes: 0,
            verification_key_size_bytes: 0,
            row_count: 0,
            chunk_count: 0,
            quality: MetricQualityFlags::all_placeholder(),
        }
    }

    pub fn print(&self) {
        println!("║  ── Timing ──");
        println!("║    Dataset generation:  {:>10} µs ({:.3} ms)", self.dataset_generation_us, self.dataset_generation_us as f64 / 1000.0);
        println!("║    Ingestion:           {:>10} µs ({:.3} ms)", self.ingestion_us, self.ingestion_us as f64 / 1000.0);
        println!("║    Snapshot creation:   {:>10} µs ({:.3} ms)", self.snapshot_creation_us, self.snapshot_creation_us as f64 / 1000.0);
        println!("║    Snapshot activation: {:>10} µs ({:.3} ms)", self.snapshot_activation_us, self.snapshot_activation_us as f64 / 1000.0);
        println!("║    Query planning:      {:>10} µs ({:.3} ms)", self.query_planning_us, self.query_planning_us as f64 / 1000.0);
        println!("║    Proof generation:    {:>10} µs ({:.3} ms) [{}]", self.proof_generation_us, self.proof_generation_us as f64 / 1000.0, self.quality.proof_generation_time);
        println!("║    Verification:        {:>10} µs ({:.3} ms) [{}]", self.verification_us, self.verification_us as f64 / 1000.0, self.quality.verification_time);
        println!("║    TOTAL:               {:>10} µs ({:.3} ms)", self.total_us, self.total_us as f64 / 1000.0);
        println!("║  ── Size ──");
        println!("║    Proof size:          {:>10} bytes [{}]", self.proof_size_bytes, self.quality.proof_size);
        println!("║    VK size:             {:>10} bytes [{}]", self.verification_key_size_bytes, self.quality.vk_size);
        println!("║  ── Counts ──");
        println!("║    Rows:                {:>10}", self.row_count);
        println!("║    Chunks:              {:>10}", self.chunk_count);
        println!("║  ── Quality: {} ──", self.quality.overall);
    }

    pub fn proving_throughput_rps(&self) -> f64 {
        if self.proof_generation_us == 0 {
            return 0.0;
        }
        (self.row_count as f64) / (self.proof_generation_us as f64 / 1_000_000.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkResult
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub run_id: BenchmarkRunId,
    pub scenario: BenchmarkScenario,
    pub dataset_id: DatasetId,
    pub snapshot_id: SnapshotId,
    pub query_id: QueryId,
    pub proof_id: Option<ProofId>,
    pub metrics: BenchmarkMetrics,
    pub success: bool,
    pub error: Option<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

impl BenchmarkResult {
    pub fn print_summary(&self) {
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  Benchmark: {:<48} ║", self.scenario.name);
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Run ID:      {}", self.run_id);
        println!("║  Backend:     {} (quality: {})", self.scenario.backend, self.metrics.quality.overall);
        println!("║  Family:      {} / {} / {}", self.scenario.query_family, self.scenario.operator_family, self.scenario.complexity_class);
        println!("║  Rows:        {}", self.scenario.row_count);
        println!("║  Chunk size:  {}", self.scenario.chunk_size);
        println!("║  SQL:         {}", truncate_sql(&self.scenario.sql, 50));
        println!("║  Success:     {}", self.success);
        if let Some(ref err) = self.error {
            println!("║  Error:       {}", err);
        }
        println!("╠══════════════════════════════════════════════════════════════╣");
        self.metrics.print();
        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryBenchmarkCase
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryBenchmarkCase {
    pub name: String,
    pub sql: String,
    pub expected_operator: String,
    pub tags: Vec<String>,
}

impl QueryBenchmarkCase {
    pub fn new(name: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sql: sql.into(),
            expected_operator: String::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_operator(mut self, op: impl Into<String>) -> Self {
        self.expected_operator = op.into();
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn truncate_sql(sql: &str, max_len: usize) -> String {
    let trimmed = sql.trim().replace('\n', " ");
    if trimmed.len() > max_len {
        format!("{}…", &trimmed[..max_len])
    } else {
        trimmed
    }
}
