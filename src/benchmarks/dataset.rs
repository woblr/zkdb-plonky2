//! Deterministic synthetic dataset generator for benchmarks.
//!
//! Generates a "transactions" dataset suitable for testing:
//! - filtering (WHERE amount > X, WHERE region = 'Y')
//! - projection (SELECT id, amount)
//! - aggregation (SUM, COUNT, AVG)
//! - grouping (GROUP BY category, GROUP BY region)
//! - sorting (ORDER BY amount, ORDER BY score)

use crate::database::encoding::RawRow;
use crate::database::schema::{ColumnSchema, DatasetSchema};
use crate::types::{ColumnType, DatasetId};
use serde_json::Value;

/// Canonical regions used in the generated dataset.
const REGIONS: &[&str] = &[
    "us-east",
    "us-west",
    "eu-west",
    "eu-central",
    "ap-south",
    "ap-east",
];

/// Canonical categories used in the generated dataset.
const CATEGORIES: &[&str] = &[
    "electronics",
    "clothing",
    "food",
    "services",
    "travel",
    "entertainment",
    "health",
    "education",
];

/// Build the schema for the benchmark "transactions" dataset.
pub fn transactions_schema(dataset_id: DatasetId) -> DatasetSchema {
    DatasetSchema::new(
        dataset_id,
        "benchmark_transactions",
        vec![
            ColumnSchema::new("id", ColumnType::U64),
            ColumnSchema::new("user_id", ColumnType::U64),
            ColumnSchema::new("amount", ColumnType::U64),
            ColumnSchema::new(
                "category",
                ColumnType::Text {
                    max_bytes: Some(32),
                },
            ),
            ColumnSchema::new(
                "region",
                ColumnType::Text {
                    max_bytes: Some(16),
                },
            ),
            ColumnSchema::new("timestamp", ColumnType::U64),
            ColumnSchema::new("score", ColumnType::U64),
            ColumnSchema::new("flag", ColumnType::Bool),
        ],
    )
}

/// Deterministically generate `row_count` transaction rows as `RawRow`s.
///
/// Uses simple seeded arithmetic for reproducibility — same `row_count`
/// always produces the same rows.
pub fn generate_transactions(row_count: usize) -> Vec<RawRow> {
    let mut rows = Vec::with_capacity(row_count);

    for i in 0..row_count {
        let hash = wrapping_hash(i as u64);

        let user_id = (hash % 10_000);
        let amount = ((hash >> 8) % 100_000);
        let category_idx = ((hash >> 16) % CATEGORIES.len() as u64) as usize;
        let region_idx = ((hash >> 24) % REGIONS.len() as u64) as usize;
        let timestamp = 1_700_000_000u64 + (i as u64 * 60);
        let score = ((hash >> 32) % 1000);
        let flag = (hash >> 40).is_multiple_of(2);

        let values = vec![
            Value::Number(serde_json::Number::from(i as u64)),
            Value::Number(serde_json::Number::from(user_id)),
            Value::Number(serde_json::Number::from(amount)),
            Value::String(CATEGORIES[category_idx].to_string()),
            Value::String(REGIONS[region_idx].to_string()),
            Value::Number(serde_json::Number::from(timestamp)),
            Value::Number(serde_json::Number::from(score)),
            Value::Bool(flag),
        ];

        rows.push(RawRow {
            row_index: i as u64,
            values,
        });
    }

    rows
}

/// Simple deterministic hash for seeding. Not cryptographic — just reproducible.
fn wrapping_hash(seed: u64) -> u64 {
    let mut x = seed;
    x = x.wrapping_mul(6364136223846793005);
    x = x.wrapping_add(1442695040888963407);
    x ^= x >> 16;
    x = x.wrapping_mul(0x45d9f3b);
    x ^= x >> 16;
    x
}

/// Generate and return both schema + rows for convenience.
pub fn generate_benchmark_dataset(row_count: usize) -> (DatasetSchema, Vec<RawRow>) {
    let dataset_id = DatasetId::new();
    let schema = transactions_schema(dataset_id);
    let rows = generate_transactions(row_count);
    (schema, rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// Dataset Profiles — control data distribution for benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Distribution shape for numeric columns.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionProfile {
    /// Uniform random distribution across [min, max].
    Uniform,
    /// Values clustered around `center` with given `spread`.
    Skewed { center: u64, spread: u64 },
    /// 80% of values fall in a small "hot" range.
    Hotspot {
        hot_min: u64,
        hot_max: u64,
        cold_max: u64,
    },
    /// All values are the same (worst-case for certain circuits).
    Constant(u64),
}

/// Configuration for synthetic dataset generation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatasetProfile {
    pub name: String,
    pub description: String,
    pub row_count: usize,
    pub amount_distribution: DistributionProfile,
    pub score_distribution: DistributionProfile,
    /// Number of distinct user_ids. Lower = more collisions = harder group-by.
    pub cardinality_user_id: u64,
    /// Number of distinct regions. Lower = fewer groups.
    pub cardinality_region: usize,
}

impl DatasetProfile {
    /// Default "uniform" profile.
    pub fn uniform(row_count: usize) -> Self {
        Self {
            name: "uniform".into(),
            description: "Uniform distribution across all columns".into(),
            row_count,
            amount_distribution: DistributionProfile::Uniform,
            score_distribution: DistributionProfile::Uniform,
            cardinality_user_id: 10_000,
            cardinality_region: REGIONS.len(),
        }
    }

    /// "Skewed" profile: most amounts clustered around a center value.
    pub fn skewed(row_count: usize) -> Self {
        Self {
            name: "skewed".into(),
            description: "Amount values clustered around 50000".into(),
            row_count,
            amount_distribution: DistributionProfile::Skewed {
                center: 50_000,
                spread: 5_000,
            },
            score_distribution: DistributionProfile::Uniform,
            cardinality_user_id: 1_000,
            cardinality_region: 3,
        }
    }

    /// "Hotspot" profile: 80% of amounts in a narrow range.
    pub fn hotspot(row_count: usize) -> Self {
        Self {
            name: "hotspot".into(),
            description: "80% of amounts between 40000-60000, rest up to 100000".into(),
            row_count,
            amount_distribution: DistributionProfile::Hotspot {
                hot_min: 40_000,
                hot_max: 60_000,
                cold_max: 100_000,
            },
            score_distribution: DistributionProfile::Skewed {
                center: 500,
                spread: 100,
            },
            cardinality_user_id: 500,
            cardinality_region: 2,
        }
    }
}

/// Generate transactions using a specific dataset profile.
pub fn generate_with_profile(profile: &DatasetProfile) -> Vec<RawRow> {
    let mut rows = Vec::with_capacity(profile.row_count);
    let regions_subset = &REGIONS[..profile.cardinality_region.min(REGIONS.len())];

    for i in 0..profile.row_count {
        let hash = wrapping_hash(i as u64);

        let user_id = hash % profile.cardinality_user_id;
        let amount = apply_distribution(&profile.amount_distribution, hash >> 8, 100_000);
        let category_idx = ((hash >> 16) % CATEGORIES.len() as u64) as usize;
        let region_idx = ((hash >> 24) % regions_subset.len() as u64) as usize;
        let timestamp = 1_700_000_000u64 + (i as u64 * 60);
        let score = apply_distribution(&profile.score_distribution, hash >> 32, 1000);
        let flag = (hash >> 40).is_multiple_of(2);

        let values = vec![
            Value::Number(serde_json::Number::from(i as u64)),
            Value::Number(serde_json::Number::from(user_id)),
            Value::Number(serde_json::Number::from(amount)),
            Value::String(CATEGORIES[category_idx].to_string()),
            Value::String(regions_subset[region_idx].to_string()),
            Value::Number(serde_json::Number::from(timestamp)),
            Value::Number(serde_json::Number::from(score)),
            Value::Bool(flag),
        ];

        rows.push(RawRow {
            row_index: i as u64,
            values,
        });
    }

    rows
}

/// Apply a distribution profile to a raw hash value.
fn apply_distribution(dist: &DistributionProfile, hash: u64, default_max: u64) -> u64 {
    match dist {
        DistributionProfile::Uniform => hash % default_max,
        DistributionProfile::Skewed { center, spread } => {
            // Map hash to range [center - spread, center + spread]
            let offset = (hash % (spread * 2)) as i64 - *spread as i64;
            (*center as i64 + offset).max(0) as u64
        }
        DistributionProfile::Hotspot {
            hot_min,
            hot_max,
            cold_max,
        } => {
            // 80% hot, 20% cold
            if !hash.is_multiple_of(5) {
                // Hot range
                hot_min + (hash % (hot_max - hot_min + 1))
            } else {
                // Cold range
                hash % cold_max
            }
        }
        DistributionProfile::Constant(val) => *val,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_generation() {
        let rows_a = generate_transactions(100);
        let rows_b = generate_transactions(100);
        for (a, b) in rows_a.iter().zip(rows_b.iter()) {
            assert_eq!(a.values, b.values);
        }
    }

    #[test]
    fn correct_column_count() {
        let (schema, rows) = generate_benchmark_dataset(50);
        let expected_cols = schema.columns.len();
        for row in &rows {
            assert_eq!(row.values.len(), expected_cols);
        }
    }

    #[test]
    fn nonzero_rows() {
        let rows = generate_transactions(1000);
        assert_eq!(rows.len(), 1000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Employees dataset
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical departments used in the employees dataset.
const DEPARTMENTS: &[&str] = &[
    "engineering",
    "marketing",
    "sales",
    "finance",
    "hr",
    "operations",
    "legal",
    "research",
];

/// Canonical office locations.
const OFFICES: &[&str] = &[
    "new-york",
    "san-francisco",
    "london",
    "berlin",
    "tokyo",
    "singapore",
];

/// Build the schema for the benchmark "employees" dataset.
pub fn employees_schema(dataset_id: DatasetId) -> DatasetSchema {
    DatasetSchema::new(
        dataset_id,
        "benchmark_employees",
        vec![
            ColumnSchema::new("employee_id", ColumnType::U64),
            ColumnSchema::new(
                "department",
                ColumnType::Text {
                    max_bytes: Some(32),
                },
            ),
            ColumnSchema::new(
                "office",
                ColumnType::Text {
                    max_bytes: Some(24),
                },
            ),
            ColumnSchema::new("salary", ColumnType::U64),
            ColumnSchema::new("manager_id", ColumnType::U64),
            ColumnSchema::new("performance_score", ColumnType::U64),
        ],
    )
}

/// Deterministically generate `row_count` employee rows.
///
/// Supports GROUP BY department, GROUP BY office, ORDER BY salary,
/// self-JOIN on manager_id → employee_id, etc.
pub fn generate_employees(row_count: usize) -> Vec<RawRow> {
    let mut rows = Vec::with_capacity(row_count);

    for i in 0..row_count {
        let hash = wrapping_hash(i as u64 + 1_000_000); // offset seed from transactions

        let department_idx = ((hash >> 4) % DEPARTMENTS.len() as u64) as usize;
        let office_idx = ((hash >> 12) % OFFICES.len() as u64) as usize;
        let salary = 30_000 + (hash % 170_000); // 30k–200k range
                                                // Manager is a lower employee_id (0 for top-level)
        let manager_id = if i == 0 { 0 } else { hash % (i as u64) };
        let performance_score = 1 + ((hash >> 20) % 100); // 1–100

        let values = vec![
            Value::Number(serde_json::Number::from(i as u64)),
            Value::String(DEPARTMENTS[department_idx].to_string()),
            Value::String(OFFICES[office_idx].to_string()),
            Value::Number(serde_json::Number::from(salary)),
            Value::Number(serde_json::Number::from(manager_id)),
            Value::Number(serde_json::Number::from(performance_score)),
        ];

        rows.push(RawRow {
            row_index: i as u64,
            values,
        });
    }

    rows
}

/// Generate both schema + rows for the employees dataset.
pub fn generate_employees_dataset(row_count: usize) -> (DatasetSchema, Vec<RawRow>) {
    let dataset_id = DatasetId::new();
    let schema = employees_schema(dataset_id);
    let rows = generate_employees(row_count);
    (schema, rows)
}
