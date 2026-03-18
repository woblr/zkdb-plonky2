//! Storage traits and in-memory implementations.
//!
//! `DatasetRepository` and `SnapshotRepository` are the persistence layer.
//! The in-memory implementations are used for development and tests.
//! Swap in SQLite / file-backed impls for production without changing callers.

use crate::database::schema::DatasetSchema;
use crate::database::snapshot::SnapshotRecord;
use crate::types::{DatasetId, DatasetStatus, SnapshotId, ZkDbError, ZkResult};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Dataset metadata record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRecord {
    pub dataset_id: DatasetId,
    pub name: String,
    pub description: Option<String>,
    pub status: DatasetStatus,
    pub schema: DatasetSchema,
    pub active_snapshot_id: Option<SnapshotId>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl DatasetRecord {
    pub fn new(schema: DatasetSchema) -> Self {
        let now = now_ms();
        Self {
            dataset_id: schema.dataset_id.clone(),
            name: schema.name.clone(),
            description: schema.description.clone(),
            status: DatasetStatus::Created,
            schema,
            active_snapshot_id: None,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Staging chunk storage
// ─────────────────────────────────────────────────────────────────────────────

/// Raw chunk of canonical row bytes held in staging until snapshot commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedChunk {
    pub chunk_index: u32,
    pub row_start: u64,
    pub row_end: u64,
    /// Leaf hashes for all rows in this chunk.
    pub leaf_hashes: Vec<[u8; 32]>,
    /// Canonical bytes for each row (needed for witness generation).
    pub row_bytes: Vec<Vec<u8>>,
}

impl StagedChunk {
    pub fn row_count(&self) -> u64 {
        self.row_end - self.row_start
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository traits
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait DatasetRepository: Send + Sync {
    async fn create(&self, record: DatasetRecord) -> ZkResult<()>;
    async fn get(&self, id: &DatasetId) -> ZkResult<DatasetRecord>;
    async fn list(&self) -> ZkResult<Vec<DatasetRecord>>;
    async fn update_status(&self, id: &DatasetId, status: DatasetStatus) -> ZkResult<()>;
    async fn set_active_snapshot(
        &self,
        id: &DatasetId,
        snapshot_id: Option<SnapshotId>,
    ) -> ZkResult<()>;
    async fn exists(&self, id: &DatasetId) -> bool;
}

#[async_trait]
pub trait SnapshotRepository: Send + Sync {
    async fn create(&self, record: SnapshotRecord) -> ZkResult<()>;
    async fn get(&self, id: &SnapshotId) -> ZkResult<SnapshotRecord>;
    async fn update(&self, record: SnapshotRecord) -> ZkResult<()>;
    async fn list_for_dataset(&self, dataset_id: &DatasetId) -> ZkResult<Vec<SnapshotRecord>>;
    async fn active_for_dataset(&self, dataset_id: &DatasetId) -> ZkResult<Option<SnapshotRecord>>;
}

/// Chunk storage for staged (pre-commit) data.
#[async_trait]
pub trait ChunkStore: Send + Sync {
    async fn write_chunks(&self, dataset_id: &DatasetId, chunks: Vec<StagedChunk>) -> ZkResult<()>;
    async fn read_chunks(&self, dataset_id: &DatasetId) -> ZkResult<Vec<StagedChunk>>;
    async fn clear_staging(&self, dataset_id: &DatasetId) -> ZkResult<()>;
    async fn snapshot_chunks(
        &self,
        dataset_id: &DatasetId,
        snapshot_id: &SnapshotId,
    ) -> ZkResult<()>;
    async fn read_snapshot_chunks(&self, snapshot_id: &SnapshotId) -> ZkResult<Vec<StagedChunk>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory implementations
// ─────────────────────────────────────────────────────────────────────────────

pub struct InMemoryDatasetRepository {
    records: DashMap<DatasetId, DatasetRecord>,
}

impl InMemoryDatasetRepository {
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
        }
    }
}

impl Default for InMemoryDatasetRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DatasetRepository for InMemoryDatasetRepository {
    async fn create(&self, record: DatasetRecord) -> ZkResult<()> {
        let id = record.dataset_id.clone();
        if self.records.contains_key(&id) {
            return Err(ZkDbError::Storage(format!("dataset {} already exists", id)));
        }
        self.records.insert(id, record);
        Ok(())
    }

    async fn get(&self, id: &DatasetId) -> ZkResult<DatasetRecord> {
        self.records
            .get(id)
            .map(|r| r.clone())
            .ok_or_else(|| ZkDbError::DatasetNotFound(id.clone()))
    }

    async fn list(&self) -> ZkResult<Vec<DatasetRecord>> {
        Ok(self.records.iter().map(|r| r.clone()).collect())
    }

    async fn update_status(&self, id: &DatasetId, status: DatasetStatus) -> ZkResult<()> {
        let mut record = self
            .records
            .get_mut(id)
            .ok_or_else(|| ZkDbError::DatasetNotFound(id.clone()))?;
        record.status = status;
        record.updated_at_ms = now_ms();
        Ok(())
    }

    async fn set_active_snapshot(
        &self,
        id: &DatasetId,
        snapshot_id: Option<SnapshotId>,
    ) -> ZkResult<()> {
        let mut record = self
            .records
            .get_mut(id)
            .ok_or_else(|| ZkDbError::DatasetNotFound(id.clone()))?;
        record.active_snapshot_id = snapshot_id;
        record.updated_at_ms = now_ms();
        Ok(())
    }

    async fn exists(&self, id: &DatasetId) -> bool {
        self.records.contains_key(id)
    }
}

pub struct InMemorySnapshotRepository {
    records: DashMap<SnapshotId, SnapshotRecord>,
}

impl InMemorySnapshotRepository {
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
        }
    }
}

impl Default for InMemorySnapshotRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SnapshotRepository for InMemorySnapshotRepository {
    async fn create(&self, record: SnapshotRecord) -> ZkResult<()> {
        let id = record.snapshot_id.clone();
        self.records.insert(id, record);
        Ok(())
    }

    async fn get(&self, id: &SnapshotId) -> ZkResult<SnapshotRecord> {
        self.records
            .get(id)
            .map(|r| r.clone())
            .ok_or_else(|| ZkDbError::SnapshotNotFound(id.clone()))
    }

    async fn update(&self, record: SnapshotRecord) -> ZkResult<()> {
        let id = record.snapshot_id.clone();
        if !self.records.contains_key(&id) {
            return Err(ZkDbError::SnapshotNotFound(id));
        }
        self.records.insert(id, record);
        Ok(())
    }

    async fn list_for_dataset(&self, dataset_id: &DatasetId) -> ZkResult<Vec<SnapshotRecord>> {
        Ok(self
            .records
            .iter()
            .filter(|r| &r.dataset_id == dataset_id)
            .map(|r| r.clone())
            .collect())
    }

    async fn active_for_dataset(&self, dataset_id: &DatasetId) -> ZkResult<Option<SnapshotRecord>> {
        Ok(self
            .records
            .iter()
            .filter(|r| &r.dataset_id == dataset_id && r.is_query_eligible())
            .map(|r| r.clone())
            .next())
    }
}

pub struct InMemoryChunkStore {
    staging: DashMap<DatasetId, Vec<StagedChunk>>,
    snapshots: DashMap<SnapshotId, Vec<StagedChunk>>,
}

impl InMemoryChunkStore {
    pub fn new() -> Self {
        Self {
            staging: DashMap::new(),
            snapshots: DashMap::new(),
        }
    }
}

impl Default for InMemoryChunkStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChunkStore for InMemoryChunkStore {
    async fn write_chunks(&self, dataset_id: &DatasetId, chunks: Vec<StagedChunk>) -> ZkResult<()> {
        self.staging
            .entry(dataset_id.clone())
            .or_default()
            .extend(chunks);
        Ok(())
    }

    async fn read_chunks(&self, dataset_id: &DatasetId) -> ZkResult<Vec<StagedChunk>> {
        Ok(self
            .staging
            .get(dataset_id)
            .map(|c| c.clone())
            .unwrap_or_default())
    }

    async fn clear_staging(&self, dataset_id: &DatasetId) -> ZkResult<()> {
        self.staging.remove(dataset_id);
        Ok(())
    }

    async fn snapshot_chunks(
        &self,
        dataset_id: &DatasetId,
        snapshot_id: &SnapshotId,
    ) -> ZkResult<()> {
        let chunks = self
            .staging
            .get(dataset_id)
            .map(|c| c.clone())
            .unwrap_or_default();
        self.snapshots.insert(snapshot_id.clone(), chunks);
        Ok(())
    }

    async fn read_snapshot_chunks(&self, snapshot_id: &SnapshotId) -> ZkResult<Vec<StagedChunk>> {
        self.snapshots
            .get(snapshot_id)
            .map(|c| c.clone())
            .ok_or_else(|| ZkDbError::SnapshotNotFound(snapshot_id.clone()))
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
