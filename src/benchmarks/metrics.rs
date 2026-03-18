//! Metrics utilities: timing helpers, comparison, and JSON export.

use crate::benchmarks::types::{BenchmarkMetrics, BenchmarkResult};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Stopwatch — convenience for accumulating phase timings
// ─────────────────────────────────────────────────────────────────────────────

/// A simple phase timer. Call `lap()` to record the elapsed time since
/// the last lap (or creation), returned in microseconds.
pub struct Stopwatch {
    start: Instant,
    last_lap: Instant,
}

impl Stopwatch {
    pub fn start() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last_lap: now,
        }
    }

    /// Returns microseconds since the last lap (or start), and resets the lap marker.
    pub fn lap(&mut self) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_lap).as_micros() as u64;
        self.last_lap = now;
        elapsed
    }

    /// Total microseconds since the stopwatch was created.
    pub fn total_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Comparison utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Compare two benchmark results side by side.
pub fn compare_results(a: &BenchmarkResult, b: &BenchmarkResult) {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  Benchmark Comparison                                       │");
    println!("├────────────────────────┬──────────────────┬─────────────────┤");
    println!(
        "│  Metric                │  {:^16} │  {:^15} │",
        a.scenario.name, b.scenario.name
    );
    println!("├────────────────────────┼──────────────────┼─────────────────┤");

    let am = &a.metrics;
    let bm = &b.metrics;

    print_comparison_row(
        "Proof gen (µs)",
        am.proof_generation_us,
        bm.proof_generation_us,
    );
    print_comparison_row("Verification (µs)", am.verification_us, bm.verification_us);
    print_comparison_row(
        "Proof size (B)",
        am.proof_size_bytes as u64,
        bm.proof_size_bytes as u64,
    );
    print_comparison_row("Total (µs)", am.total_us, bm.total_us);
    print_comparison_row("Rows", am.row_count as u64, bm.row_count as u64);
    print_comparison_row("Chunks", am.chunk_count as u64, bm.chunk_count as u64);

    println!("└────────────────────────┴──────────────────┴─────────────────┘");
}

fn print_comparison_row(label: &str, a_val: u64, b_val: u64) {
    let indicator = if a_val < b_val {
        "◄"
    } else if a_val > b_val {
        "►"
    } else {
        "="
    };
    println!(
        "│  {:<22} │  {:>14}  │  {:>13} {} │",
        label, a_val, b_val, indicator
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON export
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a list of benchmark results to pretty JSON.
pub fn results_to_json(results: &[BenchmarkResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Compute aggregate statistics from multiple runs of the same scenario.
pub fn aggregate_metrics(metrics: &[BenchmarkMetrics]) -> AggregateStats {
    if metrics.is_empty() {
        return AggregateStats::default();
    }
    let _n = metrics.len() as f64;

    let proof_gen: Vec<f64> = metrics
        .iter()
        .map(|m| m.proof_generation_us as f64)
        .collect();
    let verification: Vec<f64> = metrics.iter().map(|m| m.verification_us as f64).collect();
    let proof_size: Vec<f64> = metrics.iter().map(|m| m.proof_size_bytes as f64).collect();
    let total: Vec<f64> = metrics.iter().map(|m| m.total_us as f64).collect();

    AggregateStats {
        runs: metrics.len(),
        proof_generation_mean_us: mean(&proof_gen),
        proof_generation_stddev_us: stddev(&proof_gen),
        verification_mean_us: mean(&verification),
        verification_stddev_us: stddev(&verification),
        proof_size_mean_bytes: mean(&proof_size),
        total_mean_us: mean(&total),
        total_stddev_us: stddev(&total),
        min_proof_generation_us: proof_gen.iter().cloned().fold(f64::INFINITY, f64::min) as u64,
        max_proof_generation_us: proof_gen.iter().cloned().fold(0.0f64, f64::max) as u64,
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AggregateStats {
    pub runs: usize,
    pub proof_generation_mean_us: f64,
    pub proof_generation_stddev_us: f64,
    pub verification_mean_us: f64,
    pub verification_stddev_us: f64,
    pub proof_size_mean_bytes: f64,
    pub total_mean_us: f64,
    pub total_stddev_us: f64,
    pub min_proof_generation_us: u64,
    pub max_proof_generation_us: u64,
}

impl AggregateStats {
    pub fn print(&self) {
        println!("Aggregate over {} runs:", self.runs);
        println!(
            "  Proof gen:    {:.1} ± {:.1} µs (min={}, max={})",
            self.proof_generation_mean_us,
            self.proof_generation_stddev_us,
            self.min_proof_generation_us,
            self.max_proof_generation_us
        );
        println!(
            "  Verification: {:.1} ± {:.1} µs",
            self.verification_mean_us, self.verification_stddev_us
        );
        println!("  Proof size:   {:.0} bytes", self.proof_size_mean_bytes);
        println!(
            "  Total:        {:.1} ± {:.1} µs",
            self.total_mean_us, self.total_stddev_us
        );
    }
}

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().sum::<f64>() / vals.len() as f64
}

fn stddev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let m = mean(vals);
    let variance = vals.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    variance.sqrt()
}
