//! Dataset and snapshot service — the product-facing facade for the database layer.

use crate::commitment::service::CommitmentService;
use crate::database::encoding::RawRow;
use crate::database::ingest::{IngestPipeline, IngestRequest, IngestResult};
use crate::database::schema::{validate_schema, DatasetSchema};
use crate::database::snapshot::SnapshotRecord;
use crate::database::storage::{ChunkStore, DatasetRecord, DatasetRepository, SnapshotRepository};
use crate::types::{DatasetId, DatasetStatus, SnapshotId, ZkDbError, ZkResult};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// DatasetService
// ─────────────────────────────────────────────────────────────────────────────

pub struct DatasetService {
    dataset_repo: Arc<dyn DatasetRepository>,
    snapshot_repo: Arc<dyn SnapshotRepository>,
    chunk_store: Arc<dyn ChunkStore>,
    ingest_pipeline: Arc<IngestPipeline>,
    commitment_svc: Arc<dyn CommitmentService>,
}

impl DatasetService {
    pub fn new(
        dataset_repo: Arc<dyn DatasetRepository>,
        snapshot_repo: Arc<dyn SnapshotRepository>,
        chunk_store: Arc<dyn ChunkStore>,
        commitment_svc: Arc<dyn CommitmentService>,
    ) -> Self {
        let pipeline = Arc::new(IngestPipeline::with_default_encoder(chunk_store.clone()));
        Self {
            dataset_repo,
            snapshot_repo,
            chunk_store,
            ingest_pipeline: pipeline,
            commitment_svc,
        }
    }

    // ── Dataset lifecycle ─────────────────────────────────────────────────

    /// Create a new dataset. Schema is validated before storage.
    pub async fn create_dataset(&self, schema: DatasetSchema) -> ZkResult<DatasetRecord> {
        validate_schema(&schema)?;
        let record = DatasetRecord::new(schema);
        self.dataset_repo.create(record.clone()).await?;
        Ok(record)
    }

    pub async fn get_dataset(&self, id: &DatasetId) -> ZkResult<DatasetRecord> {
        self.dataset_repo.get(id).await
    }

    pub async fn list_datasets(&self) -> ZkResult<Vec<DatasetRecord>> {
        self.dataset_repo.list().await
    }

    // ── Ingestion ─────────────────────────────────────────────────────────

    /// Ingest rows into staging. Dataset must exist.
    pub async fn ingest_rows(
        &self,
        dataset_id: &DatasetId,
        rows: Vec<RawRow>,
        chunk_size: Option<u32>,
    ) -> ZkResult<IngestResult> {
        let record = self.dataset_repo.get(dataset_id).await?;
        if record.status == DatasetStatus::Archived {
            return Err(ZkDbError::internal("cannot ingest into archived dataset"));
        }

        let req = IngestRequest {
            dataset_id: dataset_id.clone(),
            rows,
            chunk_size,
        };
        let result = self.ingest_pipeline.run(req, &record.schema).await?;

        // Move status to Ingesting / Staged
        self.dataset_repo
            .update_status(dataset_id, DatasetStatus::Ingesting)
            .await?;

        Ok(result)
    }

    // ── Snapshot lifecycle ────────────────────────────────────────────────

    /// Build a committed snapshot from the current staging area.
    pub async fn create_snapshot(&self, dataset_id: &DatasetId) -> ZkResult<SnapshotRecord> {
        let record = self.dataset_repo.get(dataset_id).await?;

        // Read staged chunks
        let staged_chunks = self.chunk_store.read_chunks(dataset_id).await?;
        if staged_chunks.is_empty() {
            return Err(ZkDbError::internal(
                "no staged rows to commit into a snapshot",
            ));
        }

        // Build commitment
        let snapshot_id = SnapshotId::new();
        let manifest = self
            .commitment_svc
            .build_snapshot_manifest(
                snapshot_id.clone(),
                dataset_id.clone(),
                &record.schema,
                &staged_chunks,
            )
            .await?;

        // Archive chunks under snapshot_id
        self.chunk_store
            .snapshot_chunks(dataset_id, &snapshot_id)
            .await?;
        // Clear staging
        self.chunk_store.clear_staging(dataset_id).await?;

        // Persist snapshot record
        let snap_record =
            SnapshotRecord::new(snapshot_id.clone(), dataset_id.clone()).with_manifest(manifest);
        self.snapshot_repo.create(snap_record.clone()).await?;

        self.dataset_repo
            .update_status(dataset_id, DatasetStatus::Staged)
            .await?;

        Ok(snap_record)
    }

    /// Activate a committed snapshot, making it query-eligible.
    pub async fn activate_snapshot(
        &self,
        dataset_id: &DatasetId,
        snapshot_id: &SnapshotId,
    ) -> ZkResult<SnapshotRecord> {
        // Verify snapshot exists and belongs to dataset
        let snap = self.snapshot_repo.get(snapshot_id).await?;
        if &snap.dataset_id != dataset_id {
            return Err(ZkDbError::internal("snapshot does not belong to dataset"));
        }
        if snap.manifest.is_none() {
            return Err(ZkDbError::internal(
                "cannot activate snapshot without committed manifest",
            ));
        }

        // Supersede any previously active snapshot
        if let Some(prev) = self.snapshot_repo.active_for_dataset(dataset_id).await? {
            if prev.snapshot_id != *snapshot_id {
                let superseded = prev.supersede();
                self.snapshot_repo.update(superseded).await?;
            }
        }

        // Activate new snapshot
        let activated = snap.activate();
        self.snapshot_repo.update(activated.clone()).await?;

        // Update dataset
        self.dataset_repo
            .set_active_snapshot(dataset_id, Some(snapshot_id.clone()))
            .await?;
        self.dataset_repo
            .update_status(dataset_id, DatasetStatus::Active)
            .await?;

        Ok(activated)
    }

    pub async fn list_snapshots(&self, dataset_id: &DatasetId) -> ZkResult<Vec<SnapshotRecord>> {
        self.dataset_repo.get(dataset_id).await?; // ensure dataset exists
        self.snapshot_repo.list_for_dataset(dataset_id).await
    }

    pub async fn get_active_snapshot(&self, dataset_id: &DatasetId) -> ZkResult<SnapshotRecord> {
        let record = self.dataset_repo.get(dataset_id).await?;
        let snap_id = record
            .active_snapshot_id
            .ok_or_else(|| ZkDbError::NoActiveSnapshot(dataset_id.clone()))?;
        self.snapshot_repo.get(&snap_id).await
    }

    pub async fn get_snapshot(&self, snapshot_id: &SnapshotId) -> ZkResult<SnapshotRecord> {
        self.snapshot_repo.get(snapshot_id).await
    }
}
