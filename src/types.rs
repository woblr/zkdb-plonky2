//! Core domain types, ID newtypes, and error definitions.
//!
//! This module is the single source of truth for shared identifiers,
//! status enums, and the top-level error type. Nothing in this module
//! depends on any other module in this crate.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// ID newtypes
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! newtype_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(s.parse::<Uuid>()?))
            }
        }
    };
}

newtype_id!(DatasetId);
newtype_id!(SnapshotId);
newtype_id!(QueryId);
newtype_id!(ProofId);
newtype_id!(JobId);
newtype_id!(ChunkId);

// ─────────────────────────────────────────────────────────────────────────────
// Status enums
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetStatus {
    /// Schema created, no ingestion yet.
    Created,
    /// Rows are being ingested into staging.
    Ingesting,
    /// Ingestion complete, awaiting snapshot commit.
    Staged,
    /// At least one committed snapshot is active.
    Active,
    /// Soft-deleted.
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    /// Snapshot commit job queued.
    Pending,
    /// Merkle roots being computed.
    Building,
    /// Committed and immutable; not yet query-eligible.
    Committed,
    /// Query-eligible; the dataset's current active snapshot.
    Active,
    /// Superseded by a newer active snapshot.
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Pending,
    Planning,
    WitnessBuilding,
    Proving,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Column types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ColumnType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Decimal { precision: u8, scale: u8 },
    Text { max_bytes: Option<u32> },
    Bytes { max_len: Option<u32> },
    Timestamp,
    Uuid,
}

impl ColumnType {
    /// Returns true if this type can be used as a sort/group key.
    pub fn is_orderable(&self) -> bool {
        matches!(
            self,
            ColumnType::U8
                | ColumnType::U16
                | ColumnType::U32
                | ColumnType::U64
                | ColumnType::I8
                | ColumnType::I16
                | ColumnType::I32
                | ColumnType::I64
                | ColumnType::F32
                | ColumnType::F64
                | ColumnType::Decimal { .. }
                | ColumnType::Text { .. }
                | ColumnType::Timestamp
        )
    }

    /// Canonical byte width for fixed-width types (None for variable-width).
    pub fn fixed_byte_width(&self) -> Option<usize> {
        match self {
            ColumnType::Bool => Some(1),
            ColumnType::U8 | ColumnType::I8 => Some(1),
            ColumnType::U16 | ColumnType::I16 => Some(2),
            ColumnType::U32 | ColumnType::I32 | ColumnType::F32 => Some(4),
            ColumnType::U64 | ColumnType::I64 | ColumnType::F64 | ColumnType::Timestamp => Some(8),
            ColumnType::Uuid => Some(16),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend identifier
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendTag {
    /// Testing/debug stub. No real constraints. No real proof system.
    Mock,
    /// DEPRECATED alias kept for JSON compatibility. Maps to ConstraintChecked.
    #[serde(alias = "baseline")]
    Baseline,
    /// Real operator constraint validation + hash-chain audit log.
    /// NOT zero-knowledge. NOT succinct. NOT a SNARK.
    ConstraintChecked,
    /// Plonky2 FRI-based SNARK. Zero-knowledge. Succinct. Fully wired.
    Plonky2,
    /// Plonky3 continuation of Plonky2. (not yet implemented)
    Plonky3,
}

impl fmt::Display for BackendTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendTag::Mock => write!(f, "mock"),
            BackendTag::Baseline => write!(f, "constraint_checked"), // canonical
            BackendTag::ConstraintChecked => write!(f, "constraint_checked"),
            BackendTag::Plonky2 => write!(f, "plonky2"),
            BackendTag::Plonky3 => write!(f, "plonky3"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate function kinds
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggKind {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    CountDistinct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    Cross,
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ZkDbError {
    #[error("dataset not found: {0}")]
    DatasetNotFound(DatasetId),

    #[error("snapshot not found: {0}")]
    SnapshotNotFound(SnapshotId),

    #[error("no active snapshot for dataset {0}")]
    NoActiveSnapshot(DatasetId),

    #[error("query not found: {0}")]
    QueryNotFound(QueryId),

    #[error("job not found: {0}")]
    JobNotFound(JobId),

    #[error("schema error: {0}")]
    Schema(String),

    #[error("ingestion error: {0}")]
    Ingest(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("commitment error: {0}")]
    Commitment(String),

    #[error("query parse error: {0}")]
    QueryParse(String),

    #[error("query planning error: {0}")]
    QueryPlan(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("proving error: {0}")]
    Proving(String),

    #[error("verification failed")]
    VerificationFailed,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ZkResult<T> = std::result::Result<T, ZkDbError>;

impl ZkDbError {
    pub fn internal(msg: impl Into<String>) -> Self {
        ZkDbError::Internal(msg.into())
    }
}
