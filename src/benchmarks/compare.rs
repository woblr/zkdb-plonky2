//! Benchmark comparison and delta analysis types.
//!
//! Used to compare results across backends, scenarios, or runs.

use crate::benchmarks::types::BenchmarkResult;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// MetricDelta
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the delta between two metric values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub label: String,
    pub value_a: f64,
    pub value_b: f64,
    pub absolute_delta: f64,
    /// Percentage change: positive means B is larger (worse for time/size).
    pub percent_change: f64,
    /// Which side "wins" (lower is better for time/size metrics).
    pub winner: DeltaWinner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaWinner {
    A,
    B,
    Tie,
}

impl MetricDelta {
    /// Create a delta where lower is better (time, size metrics).
    pub fn lower_is_better(label: impl Into<String>, a: f64, b: f64) -> Self {
        let absolute_delta = b - a;
        let percent_change = if a > 0.0 { ((b - a) / a) * 100.0 } else { 0.0 };
        let winner = if a < b {
            DeltaWinner::A
        } else if b < a {
            DeltaWinner::B
        } else {
            DeltaWinner::Tie
        };
        Self {
            label: label.into(),
            value_a: a,
            value_b: b,
            absolute_delta,
            percent_change,
            winner,
        }
    }

    /// Create a delta where higher is better (throughput metrics).
    pub fn higher_is_better(label: impl Into<String>, a: f64, b: f64) -> Self {
        let absolute_delta = b - a;
        let percent_change = if a > 0.0 { ((b - a) / a) * 100.0 } else { 0.0 };
        let winner = if a > b {
            DeltaWinner::A
        } else if b > a {
            DeltaWinner::B
        } else {
            DeltaWinner::Tie
        };
        Self {
            label: label.into(),
            value_a: a,
            value_b: b,
            absolute_delta,
            percent_change,
            winner,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComparisonRow
// ─────────────────────────────────────────────────────────────────────────────

/// A single scenario comparison between two runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonRow {
    pub scenario_name: String,
    pub proof_generation: MetricDelta,
    pub verification: MetricDelta,
    pub proof_size: MetricDelta,
    pub total_time: MetricDelta,
    pub throughput: MetricDelta,
    pub quality_a: String,
    pub quality_b: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkComparison
// ─────────────────────────────────────────────────────────────────────────────

/// Full comparison report between two benchmark runs or suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkComparison {
    pub label_a: String,
    pub label_b: String,
    pub backend_a: String,
    pub backend_b: String,
    pub rows: Vec<ComparisonRow>,
    pub summary: ComparisonSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub total_scenarios: usize,
    pub a_wins_proof_gen: usize,
    pub b_wins_proof_gen: usize,
    pub a_wins_verification: usize,
    pub b_wins_verification: usize,
    pub a_wins_proof_size: usize,
    pub b_wins_proof_size: usize,
}

impl BenchmarkComparison {
    /// Compare two sets of results, matched by scenario name.
    pub fn compare(
        label_a: impl Into<String>,
        label_b: impl Into<String>,
        results_a: &[BenchmarkResult],
        results_b: &[BenchmarkResult],
    ) -> Self {
        let label_a = label_a.into();
        let label_b = label_b.into();

        let backend_a = results_a
            .first()
            .map(|r| r.scenario.backend.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let backend_b = results_b
            .first()
            .map(|r| r.scenario.backend.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Index B by scenario name
        let b_by_name: std::collections::HashMap<&str, &BenchmarkResult> = results_b
            .iter()
            .map(|r| (r.scenario.name.as_str(), r))
            .collect();

        let mut rows = Vec::new();
        for ra in results_a {
            if let Some(rb) = b_by_name.get(ra.scenario.name.as_str()) {
                let row = ComparisonRow {
                    scenario_name: ra.scenario.name.clone(),
                    proof_generation: MetricDelta::lower_is_better(
                        "proof_generation_us",
                        ra.metrics.proof_generation_us as f64,
                        rb.metrics.proof_generation_us as f64,
                    ),
                    verification: MetricDelta::lower_is_better(
                        "verification_us",
                        ra.metrics.verification_us as f64,
                        rb.metrics.verification_us as f64,
                    ),
                    proof_size: MetricDelta::lower_is_better(
                        "proof_size_bytes",
                        ra.metrics.proof_size_bytes as f64,
                        rb.metrics.proof_size_bytes as f64,
                    ),
                    total_time: MetricDelta::lower_is_better(
                        "total_us",
                        ra.metrics.total_us as f64,
                        rb.metrics.total_us as f64,
                    ),
                    throughput: MetricDelta::higher_is_better(
                        "throughput_rps",
                        ra.metrics.proving_throughput_rps(),
                        rb.metrics.proving_throughput_rps(),
                    ),
                    quality_a: ra.metrics.quality.overall.to_string(),
                    quality_b: rb.metrics.quality.overall.to_string(),
                };
                rows.push(row);
            }
        }

        let summary = ComparisonSummary {
            total_scenarios: rows.len(),
            a_wins_proof_gen: rows
                .iter()
                .filter(|r| r.proof_generation.winner == DeltaWinner::A)
                .count(),
            b_wins_proof_gen: rows
                .iter()
                .filter(|r| r.proof_generation.winner == DeltaWinner::B)
                .count(),
            a_wins_verification: rows
                .iter()
                .filter(|r| r.verification.winner == DeltaWinner::A)
                .count(),
            b_wins_verification: rows
                .iter()
                .filter(|r| r.verification.winner == DeltaWinner::B)
                .count(),
            a_wins_proof_size: rows
                .iter()
                .filter(|r| r.proof_size.winner == DeltaWinner::A)
                .count(),
            b_wins_proof_size: rows
                .iter()
                .filter(|r| r.proof_size.winner == DeltaWinner::B)
                .count(),
        };

        Self {
            label_a,
            label_b,
            backend_a,
            backend_b,
            rows,
            summary,
        }
    }

    /// Print a comparison table to stdout.
    pub fn print(&self) {
        println!("╔══════════════════════════════════════════════════════════════════════╗");
        println!("║  Comparison: {} vs {}", self.label_a, self.label_b);
        println!("║  Backends:   {} vs {}", self.backend_a, self.backend_b);
        println!("╠══════════════════════════════════════════════════════════════════════╣");

        for row in &self.rows {
            println!("║  Scenario: {}", row.scenario_name);
            println!(
                "║    Proof gen:    {:>10.0} vs {:>10.0} µs ({:+.1}%)",
                row.proof_generation.value_a,
                row.proof_generation.value_b,
                row.proof_generation.percent_change
            );
            println!(
                "║    Verification: {:>10.0} vs {:>10.0} µs ({:+.1}%)",
                row.verification.value_a, row.verification.value_b, row.verification.percent_change
            );
            println!(
                "║    Proof size:   {:>10.0} vs {:>10.0} B  ({:+.1}%)",
                row.proof_size.value_a, row.proof_size.value_b, row.proof_size.percent_change
            );
            println!("║    Quality:      {} vs {}", row.quality_a, row.quality_b);
            println!("║  ──────────────────────────────────────────────────────────────────");
        }

        println!("║  Summary ({} scenarios):", self.summary.total_scenarios);
        println!(
            "║    Proof gen wins:    A={} B={}",
            self.summary.a_wins_proof_gen, self.summary.b_wins_proof_gen
        );
        println!(
            "║    Verification wins: A={} B={}",
            self.summary.a_wins_verification, self.summary.b_wins_verification
        );
        println!(
            "║    Proof size wins:   A={} B={}",
            self.summary.a_wins_proof_size, self.summary.b_wins_proof_size
        );
        println!("╚══════════════════════════════════════════════════════════════════════╝");
    }
}
