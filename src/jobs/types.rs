//! Job type definitions for async lifecycle management.

use crate::types::{DatasetId, JobId, JobStatus, ProofId, QueryId, SnapshotId};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Individual job kinds
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestJob {
    pub job_id: JobId,
    pub dataset_id: DatasetId,
    /// Number of rows submitted.
    pub row_count: u64,
    pub submitted_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitJob {
    pub job_id: JobId,
    pub dataset_id: DatasetId,
    pub submitted_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryJob {
    pub job_id: JobId,
    pub query_id: QueryId,
    pub dataset_id: DatasetId,
    pub snapshot_id: SnapshotId,
    pub sql: String,
    pub user_id: Option<String>,
    pub submitted_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationJob {
    pub job_id: JobId,
    pub proof_id: ProofId,
    pub submitted_at_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified job enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobKind {
    Ingest(IngestJob),
    Commit(CommitJob),
    Query(QueryJob),
    Verification(VerificationJob),
}

impl JobKind {
    pub fn job_id(&self) -> &JobId {
        match self {
            JobKind::Ingest(j) => &j.job_id,
            JobKind::Commit(j) => &j.job_id,
            JobKind::Query(j) => &j.job_id,
            JobKind::Verification(j) => &j.job_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Job record stored in the registry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: JobId,
    pub kind: JobKind,
    pub status: JobStatus,
    pub progress_pct: u8,
    pub error: Option<String>,
    /// JSON-serialized result (type depends on job kind).
    pub result_json: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

impl JobRecord {
    pub fn new(kind: JobKind) -> Self {
        let job_id = kind.job_id().clone();
        let now = now_ms();
        Self {
            job_id,
            kind,
            status: JobStatus::Queued,
            progress_pct: 0,
            error: None,
            result_json: None,
            created_at_ms: now,
            updated_at_ms: now,
            completed_at_ms: None,
        }
    }

    pub fn start(mut self) -> Self {
        self.status = JobStatus::Running;
        self.updated_at_ms = now_ms();
        self
    }

    pub fn complete(mut self, result: Option<String>) -> Self {
        self.status = JobStatus::Completed;
        self.result_json = result;
        self.progress_pct = 100;
        let now = now_ms();
        self.updated_at_ms = now;
        self.completed_at_ms = Some(now);
        self
    }

    pub fn fail(mut self, error: impl Into<String>) -> Self {
        self.status = JobStatus::Failed;
        self.error = Some(error.into());
        self.updated_at_ms = now_ms();
        self
    }

    pub fn set_progress(mut self, pct: u8) -> Self {
        self.progress_pct = pct;
        self.updated_at_ms = now_ms();
        self
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
