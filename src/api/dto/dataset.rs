//! Dataset-related request/response DTOs.

use crate::database::storage::DatasetRecord;
use crate::types::{ColumnType, DatasetStatus};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Request DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateDatasetRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub columns: Vec<ColumnSchemaDto>,
    #[serde(default)]
    pub primary_key: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ColumnSchemaDto {
    pub name: String,
    pub col_type: ColumnTypeDto,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ColumnTypeDto {
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

impl From<ColumnTypeDto> for ColumnType {
    fn from(dto: ColumnTypeDto) -> Self {
        match dto {
            ColumnTypeDto::Bool => ColumnType::Bool,
            ColumnTypeDto::U8 => ColumnType::U8,
            ColumnTypeDto::U16 => ColumnType::U16,
            ColumnTypeDto::U32 => ColumnType::U32,
            ColumnTypeDto::U64 => ColumnType::U64,
            ColumnTypeDto::I8 => ColumnType::I8,
            ColumnTypeDto::I16 => ColumnType::I16,
            ColumnTypeDto::I32 => ColumnType::I32,
            ColumnTypeDto::I64 => ColumnType::I64,
            ColumnTypeDto::F32 => ColumnType::F32,
            ColumnTypeDto::F64 => ColumnType::F64,
            ColumnTypeDto::Decimal { precision, scale } => ColumnType::Decimal { precision, scale },
            ColumnTypeDto::Text { max_bytes } => ColumnType::Text { max_bytes },
            ColumnTypeDto::Bytes { max_len } => ColumnType::Bytes { max_len },
            ColumnTypeDto::Timestamp => ColumnType::Timestamp,
            ColumnTypeDto::Uuid => ColumnType::Uuid,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IngestRowsRequest {
    pub rows: Vec<serde_json::Value>,
    #[serde(default)]
    pub chunk_size: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DatasetResponse {
    pub dataset_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: DatasetStatus,
    pub column_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_snapshot_id: Option<String>,
    pub created_at_ms: u64,
}

impl From<DatasetRecord> for DatasetResponse {
    fn from(r: DatasetRecord) -> Self {
        let column_count = r.schema.columns.len();
        Self {
            dataset_id: r.dataset_id.to_string(),
            name: r.name,
            description: r.description,
            status: r.status,
            column_count,
            active_snapshot_id: r.active_snapshot_id.map(|id| id.to_string()),
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub dataset_id: String,
    pub rows_ingested: u64,
    pub chunks_created: u32,
    pub job_id: String,
}
