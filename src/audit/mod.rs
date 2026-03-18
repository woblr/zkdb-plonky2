//! Append-only audit log.

use crate::types::{DatasetId, QueryId, SnapshotId};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    DatasetCreated {
        dataset_id: DatasetId,
        name: String,
    },
    RowsIngested {
        dataset_id: DatasetId,
        row_count: u64,
        chunk_count: u32,
    },
    SnapshotCreated {
        dataset_id: DatasetId,
        snapshot_id: SnapshotId,
    },
    SnapshotActivated {
        dataset_id: DatasetId,
        snapshot_id: SnapshotId,
    },
    QuerySubmitted {
        query_id: QueryId,
        dataset_id: DatasetId,
        user_id: Option<String>,
    },
    QueryCompleted {
        query_id: QueryId,
        snapshot_id: SnapshotId,
    },
    QueryFailed {
        query_id: QueryId,
        error: String,
    },
    PolicyDenied {
        dataset_id: DatasetId,
        user_id: Option<String>,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub event: AuditEvent,
}

pub struct AuditLog {
    seq: AtomicU64,
    records: Arc<DashMap<u64, AuditRecord>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            records: Arc::new(DashMap::new()),
        }
    }

    pub fn append(&self, event: AuditEvent) -> AuditRecord {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let record = AuditRecord {
            seq,
            timestamp_ms: crate::utils::now_ms(),
            event,
        };
        self.records.insert(seq, record.clone());
        record
    }

    pub fn all(&self) -> Vec<AuditRecord> {
        let mut records: Vec<AuditRecord> = self.records.iter().map(|r| r.clone()).collect();
        records.sort_by_key(|r| r.seq);
        records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
