//! In-memory job registry.

use crate::jobs::types::{JobKind, JobRecord};
use crate::types::{JobId, JobStatus, ZkDbError, ZkResult};
use dashmap::DashMap;
use std::sync::Arc;

pub struct JobRegistry {
    records: Arc<DashMap<JobId, JobRecord>>,
}

impl JobRegistry {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
        }
    }

    /// Register a new job and return its record.
    pub fn register(&self, kind: JobKind) -> JobRecord {
        let record = JobRecord::new(kind);
        self.records.insert(record.job_id.clone(), record.clone());
        record
    }

    pub fn get(&self, job_id: &JobId) -> ZkResult<JobRecord> {
        self.records
            .get(job_id)
            .map(|r| r.clone())
            .ok_or_else(|| ZkDbError::JobNotFound(job_id.clone()))
    }

    pub fn update(&self, record: JobRecord) -> ZkResult<()> {
        if !self.records.contains_key(&record.job_id) {
            return Err(ZkDbError::JobNotFound(record.job_id));
        }
        self.records.insert(record.job_id.clone(), record);
        Ok(())
    }

    pub fn mark_running(&self, job_id: &JobId) -> ZkResult<()> {
        let record = self.get(job_id)?;
        self.update(record.start())
    }

    pub fn mark_completed(&self, job_id: &JobId, result: Option<String>) -> ZkResult<()> {
        let record = self.get(job_id)?;
        self.update(record.complete(result))
    }

    pub fn mark_failed(&self, job_id: &JobId, error: impl Into<String>) -> ZkResult<()> {
        let record = self.get(job_id)?;
        self.update(record.fail(error))
    }

    pub fn set_progress(&self, job_id: &JobId, pct: u8) -> ZkResult<()> {
        let record = self.get(job_id)?;
        self.update(record.set_progress(pct))
    }

    pub fn list(&self) -> Vec<JobRecord> {
        self.records.iter().map(|r| r.clone()).collect()
    }

    pub fn list_by_status(&self, status: JobStatus) -> Vec<JobRecord> {
        self.records
            .iter()
            .filter(|r| r.status == status)
            .map(|r| r.clone())
            .collect()
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}
