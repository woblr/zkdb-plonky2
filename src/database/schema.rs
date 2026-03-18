//! Dataset schema definitions and validation.

use crate::types::{ColumnType, DatasetId, ZkDbError, ZkResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ─────────────────────────────────────────────────────────────────────────────
// Schema types
// ─────────────────────────────────────────────────────────────────────────────

/// Access policy for a single column, stored in schema metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ColumnPolicy {
    /// Column is fully visible.
    #[default]
    Public,
    /// Redact: return NULL for all values.
    Redact,
    /// Hash: return H(value) instead of value.
    Hash,
    /// Blur numeric values to nearest bucket.
    Blur { bucket_size: u64 },
    /// Only users with this role may see this column.
    RoleRestricted { role: String },
}

/// Definition for a single column in a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSchema {
    /// Column name (must be unique within schema, lowercase snake_case recommended).
    pub name: String,
    /// Data type.
    pub col_type: ColumnType,
    /// Whether NULL values are permitted.
    pub nullable: bool,
    /// Optional access policy override.
    #[serde(default)]
    pub policy: ColumnPolicy,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

impl ColumnSchema {
    pub fn new(name: impl Into<String>, col_type: ColumnType) -> Self {
        Self {
            name: name.into(),
            col_type,
            nullable: false,
            policy: ColumnPolicy::Public,
            description: None,
        }
    }

    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    pub fn with_policy(mut self, policy: ColumnPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Full dataset schema definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    pub dataset_id: DatasetId,
    /// Human-readable name (does not need to be unique across all datasets).
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Ordered column definitions.
    pub columns: Vec<ColumnSchema>,
    /// Optional primary key column names.
    #[serde(default)]
    pub primary_key: Option<Vec<String>>,
    /// Schema version — bumped whenever schema evolves.
    pub schema_version: u32,
    /// Version of the canonical encoding spec (bumped if encoding changes).
    pub encoding_spec_version: u8,
    /// When this schema was created (Unix timestamp millis).
    pub created_at_ms: u64,
}

impl DatasetSchema {
    pub fn new(dataset_id: DatasetId, name: impl Into<String>, columns: Vec<ColumnSchema>) -> Self {
        Self {
            dataset_id,
            name: name.into(),
            description: None,
            columns,
            primary_key: None,
            schema_version: 1,
            encoding_spec_version: 1,
            created_at_ms: now_ms(),
        }
    }

    /// Canonical deterministic schema hash (used in snapshot manifest).
    pub fn schema_hash(&self) -> [u8; 32] {
        let json = serde_json::to_string(self).unwrap_or_default();
        *blake3::hash(json.as_bytes()).as_bytes()
    }

    /// Resolve column index by name (case-insensitive).
    pub fn column_index(&self, name: &str) -> Option<usize> {
        let lower = name.to_lowercase();
        self.columns
            .iter()
            .position(|c| c.name.to_lowercase() == lower)
    }

    /// Return column definition by name.
    pub fn column(&self, name: &str) -> Option<&ColumnSchema> {
        let lower = name.to_lowercase();
        self.columns.iter().find(|c| c.name.to_lowercase() == lower)
    }

    pub fn column_count(&self) -> usize {
        self.columns.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validates a schema definition, returning descriptive errors.
pub fn validate_schema(schema: &DatasetSchema) -> ZkResult<()> {
    if schema.columns.is_empty() {
        return Err(ZkDbError::Schema(
            "schema must have at least one column".into(),
        ));
    }

    let mut names = HashSet::new();
    for col in &schema.columns {
        let name = col.name.trim().to_lowercase();
        if name.is_empty() {
            return Err(ZkDbError::Schema("column name cannot be empty".into()));
        }
        if !names.insert(name.clone()) {
            return Err(ZkDbError::Schema(format!(
                "duplicate column name: {}",
                name
            )));
        }
        // Validate decimal precision/scale
        if let ColumnType::Decimal { precision, scale } = &col.col_type {
            if *precision == 0 || *precision > 38 {
                return Err(ZkDbError::Schema(format!(
                    "column {}: decimal precision must be 1–38",
                    col.name
                )));
            }
            if *scale > *precision {
                return Err(ZkDbError::Schema(format!(
                    "column {}: decimal scale cannot exceed precision",
                    col.name
                )));
            }
        }
    }

    // Validate primary key references
    if let Some(pk) = &schema.primary_key {
        for key_col in pk {
            if schema.column(key_col).is_none() {
                return Err(ZkDbError::Schema(format!(
                    "primary key column '{}' not found in schema",
                    key_col
                )));
            }
        }
    }

    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DatasetId;

    fn make_schema() -> DatasetSchema {
        DatasetSchema::new(
            DatasetId::new(),
            "test",
            vec![
                ColumnSchema::new("id", ColumnType::U64),
                ColumnSchema::new(
                    "name",
                    ColumnType::Text {
                        max_bytes: Some(128),
                    },
                ),
                ColumnSchema::new("salary", ColumnType::I64).nullable(),
            ],
        )
    }

    #[test]
    fn valid_schema_passes() {
        assert!(validate_schema(&make_schema()).is_ok());
    }

    #[test]
    fn duplicate_column_fails() {
        let mut s = make_schema();
        s.columns.push(ColumnSchema::new("id", ColumnType::U64));
        assert!(validate_schema(&s).is_err());
    }

    #[test]
    fn empty_columns_fails() {
        let s = DatasetSchema::new(DatasetId::new(), "empty", vec![]);
        assert!(validate_schema(&s).is_err());
    }

    #[test]
    fn schema_hash_is_deterministic() {
        let s = make_schema();
        assert_eq!(s.schema_hash(), s.schema_hash());
    }
}
