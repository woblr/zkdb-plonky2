//! Query and snapshot DTOs.

use crate::database::snapshot::SnapshotRecord;
use crate::types::{SnapshotStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SubmitQueryRequest {
    pub dataset_id: String,
    pub sql: String,
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QuerySubmittedResponse {
    pub query_id: String,
    pub snapshot_id: String,
    pub status: String,
    pub submitted_at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct QueryResultResponse {
    pub query_id: String,
    pub snapshot_id: String,
    pub status: crate::types::QueryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotResponse {
    pub snapshot_id: String,
    pub dataset_id: String,
    pub status: SnapshotStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_count: Option<u32>,
    pub created_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at_ms: Option<u64>,
}

impl From<SnapshotRecord> for SnapshotResponse {
    fn from(r: SnapshotRecord) -> Self {
        let (root, rows, chunks) = if let Some(m) = &r.manifest {
            (
                Some(m.snapshot_root.to_hex()),
                Some(m.row_count),
                Some(m.chunk_count),
            )
        } else {
            (None, None, None)
        };
        Self {
            snapshot_id: r.snapshot_id.to_string(),
            dataset_id: r.dataset_id.to_string(),
            status: r.status,
            snapshot_root: root,
            row_count: rows,
            chunk_count: chunks,
            created_at_ms: r.created_at_ms,
            activated_at_ms: r.activated_at_ms,
        }
    }
}
