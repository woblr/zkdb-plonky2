//! Snapshot domain types.
//!
//! A snapshot is an immutable, committed view of a dataset at a point in time.
//! Only committed snapshots may be used as proof targets.

use crate::commitment::root::{ChunkEntry, CommitmentRoot, TableRoot};

use crate::types::{DatasetId, SnapshotId, SnapshotStatus, ZkDbError, ZkResult};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Chunk metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata describing the ingested staging area awaiting a snapshot commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingInfo {
    pub dataset_id: DatasetId,
    pub row_count: u64,
    pub chunk_count: u32,
    pub chunk_size: u32,
    pub staging_at_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot manifest
// ─────────────────────────────────────────────────────────────────────────────

/// The authoritative record of a committed snapshot.
///
/// This is the public input anchor for all proofs generated against this snapshot.
/// Once created it is never mutated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,

    /// Blake3 hash of the `DatasetSchema` JSON at commit time.
    pub schema_hash: [u8; 32],

    /// Root commitment over all table roots.
    pub snapshot_root: CommitmentRoot,

    /// Per-table roots (single-table datasets have one entry).
    pub table_roots: Vec<TableRoot>,

    /// All chunk entries, in order.
    pub chunks: Vec<ChunkEntry>,

    pub row_count: u64,
    pub chunk_count: u32,
    pub chunk_size: u32,

    /// Encoding spec version used (must match prover's expectation).
    pub encoding_spec_version: u8,

    pub committed_at_ms: u64,

    /// Poseidon commitment over individual columns, padded to MAX_ROWS.
    /// Maps column name -> compute_snap_lo(MAX_ROWS, &column_fes).
    /// Used as PI[0] in operator circuits, so the WitnessBuilder can select the
    /// appropriate column root depending on the query's primary operator.
    /// Backward compatible keys like `__primary` can be used for root fallbacks.
    pub column_poseidon_roots: std::collections::HashMap<String, u64>,
    
    /// Default fallback (legacy) — Poseidon commitment over first 8 bytes.
    pub poseidon_snap_lo: u64,
}

impl SnapshotManifest {
    pub fn new(
        snapshot_id: SnapshotId,
        dataset_id: DatasetId,
        schema_hash: [u8; 32],
        snapshot_root: CommitmentRoot,
        table_roots: Vec<TableRoot>,
        chunks: Vec<ChunkEntry>,
        row_count: u64,
        chunk_size: u32,
        encoding_spec_version: u8,
        column_poseidon_roots: std::collections::HashMap<String, u64>,
        poseidon_snap_lo: u64,
    ) -> Self {
        let chunk_count = chunks.len() as u32;
        Self {
            snapshot_id,
            dataset_id,
            schema_hash,
            snapshot_root,
            table_roots,
            chunks,
            row_count,
            chunk_count,
            chunk_size,
            encoding_spec_version,
            committed_at_ms: now_ms(),
            column_poseidon_roots,
            poseidon_snap_lo,
        }
    }

    /// Returns the chunk entry for the given 0-based chunk index.
    pub fn chunk(&self, index: usize) -> ZkResult<&ChunkEntry> {
        self.chunks.get(index).ok_or_else(|| {
            ZkDbError::Commitment(format!(
                "snapshot {} has no chunk at index {}",
                self.snapshot_id, index
            ))
        })
    }

    /// Blake3 hash of the manifest itself (used as a proof public input).
    pub fn manifest_hash(&self) -> [u8; 32] {
        let json = serde_json::to_string(self).unwrap_or_default();
        *blake3::hash(json.as_bytes()).as_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot record (stored in SnapshotRepository)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
    pub status: SnapshotStatus,
    pub manifest: Option<SnapshotManifest>,
    pub created_at_ms: u64,
    pub activated_at_ms: Option<u64>,
}

impl SnapshotRecord {
    pub fn new(snapshot_id: SnapshotId, dataset_id: DatasetId) -> Self {
        Self {
            snapshot_id,
            dataset_id,
            status: SnapshotStatus::Pending,
            manifest: None,
            created_at_ms: now_ms(),
            activated_at_ms: None,
        }
    }

    pub fn with_manifest(mut self, manifest: SnapshotManifest) -> Self {
        self.status = SnapshotStatus::Committed;
        self.manifest = Some(manifest);
        self
    }

    pub fn activate(mut self) -> Self {
        self.status = SnapshotStatus::Active;
        self.activated_at_ms = Some(now_ms());
        self
    }

    pub fn supersede(mut self) -> Self {
        self.status = SnapshotStatus::Superseded;
        self
    }

    pub fn is_query_eligible(&self) -> bool {
        self.status == SnapshotStatus::Active
    }

    pub fn manifest_required(&self) -> ZkResult<&SnapshotManifest> {
        self.manifest.as_ref().ok_or_else(|| {
            ZkDbError::Commitment(format!(
                "snapshot {} has no committed manifest",
                self.snapshot_id
            ))
        })
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
