//! Commitment service: builds snapshot manifests from staged chunks.

use crate::commitment::merkle::{hash_leaf, MerkleTree};
use crate::commitment::poseidon::{commitment_lo, poseidon_snapshot_root};
use crate::commitment::root::{ChunkEntry, TableRoot};
use crate::database::schema::DatasetSchema;
use crate::database::snapshot::SnapshotManifest;
use crate::database::storage::StagedChunk;
use crate::types::{ChunkId, DatasetId, SnapshotId, ZkDbError, ZkResult};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// CommitmentService trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait CommitmentService: Send + Sync {
    /// Build a complete `SnapshotManifest` from staged chunks.
    async fn build_snapshot_manifest(
        &self,
        snapshot_id: SnapshotId,
        dataset_id: DatasetId,
        schema: &DatasetSchema,
        staged_chunks: &[StagedChunk],
    ) -> ZkResult<SnapshotManifest>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Blake3-based implementation
// ─────────────────────────────────────────────────────────────────────────────

pub struct Blake3CommitmentService;

#[async_trait]
impl CommitmentService for Blake3CommitmentService {
    async fn build_snapshot_manifest(
        &self,
        snapshot_id: SnapshotId,
        dataset_id: DatasetId,
        schema: &DatasetSchema,
        staged_chunks: &[StagedChunk],
    ) -> ZkResult<SnapshotManifest> {
        if staged_chunks.is_empty() {
            return Err(ZkDbError::Commitment(
                "cannot build manifest from empty chunks".into(),
            ));
        }

        let schema_hash = schema.schema_hash();
        let mut chunk_entries: Vec<ChunkEntry> = Vec::new();
        let mut chunk_roots: Vec<[u8; 32]> = Vec::new();
        let mut total_rows: u64 = 0;

        let chunk_size = staged_chunks
            .first()
            .map(|c| (c.row_end - c.row_start) as u32)
            .unwrap_or(512);

        for chunk in staged_chunks {
            // Build Merkle tree for this chunk from pre-computed leaf hashes.
            let leaves: Vec<[u8; 32]> = chunk.leaf_hashes.iter().map(|h| hash_leaf(h)).collect();

            if leaves.is_empty() {
                return Err(ZkDbError::Commitment(format!(
                    "chunk {} has no rows",
                    chunk.chunk_index
                )));
            }

            let tree = MerkleTree::build(&leaves);
            let chunk_root = tree.root();
            let chunk_root_bytes = *chunk_root.as_bytes();

            let chunk_id = ChunkId::from_root(&chunk_root);
            chunk_entries.push(ChunkEntry {
                chunk_index: chunk.chunk_index,
                chunk_id,
                chunk_root: chunk_root.clone(),
                row_start: chunk.row_start,
                row_end: chunk.row_end,
                leaf_count: leaves.len() as u32,
            });
            chunk_roots.push(chunk_root_bytes);
            total_rows += chunk.row_count();
        }

        // Build table root (Merkle root over chunk roots).
        let table_tree = MerkleTree::build(&chunk_roots);
        let table_root = table_tree.root();

        let table_roots = vec![TableRoot {
            table_name: schema.name.clone(),
            root: table_root.clone(),
            chunk_count: chunk_entries.len() as u32,
            row_count: total_rows,
        }];

        // Snapshot root = Merkle root over table roots.
        let table_root_bytes = vec![*table_root.as_bytes()];
        let snapshot_tree = MerkleTree::build(&table_root_bytes);
        let snapshot_root = snapshot_tree.root();

        // Compute Poseidon snap_lo for each column in the schema.
        // This gives the query engine a circuit-compatible anchor regardless of
        // which column is chosen as the primary extraction point (e.g. aggregate or sort key).
        let all_row_bytes: Vec<Vec<u8>> = staged_chunks
            .iter()
            .flat_map(|c| c.row_bytes.iter().cloned())
            .collect();
        
        let mut column_poseidon_roots = std::collections::HashMap::new();
        // Fallback root over the first 8 bytes
        let mut fallback_root_computed = false;
        
        for col in &schema.columns {
            use std::sync::Arc;
            // A temporary dummy schema used just to call extract_col on this single column.
            let dummy_schema = DatasetSchema {
                dataset_id: dataset_id.clone(),
                name: schema.name.clone(),
                columns: vec![col.clone()],
                encoding_spec_version: schema.encoding_spec_version,
                description: None,
                primary_key: None,
                schema_version: 1,
                created_at_ms: 0,
            };
            if let Ok(col_fes) = crate::circuit::witness::extract_col(&all_row_bytes, &Some(dummy_schema), &Some(col.name.clone()), 0) {
                let snap_lo = crate::commitment::poseidon::compute_snap_lo(crate::commitment::poseidon::MAX_ROWS, &col_fes);
                column_poseidon_roots.insert(col.name.clone(), snap_lo);
                // The first column can act as a fallback if needed
                if !fallback_root_computed {
                    fallback_root_computed = true;
                }
            }
        }
        
        let poseidon_root = poseidon_snapshot_root(&all_row_bytes);
        let poseidon_snap_lo = commitment_lo(&poseidon_root);

        Ok(SnapshotManifest::new(
            snapshot_id,
            dataset_id,
            schema_hash,
            snapshot_root,
            table_roots,
            chunk_entries,
            total_rows,
            chunk_size,
            schema.encoding_spec_version,
            column_poseidon_roots,
            poseidon_snap_lo,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::{ColumnSchema, DatasetSchema};
    use crate::database::storage::StagedChunk;
    use crate::types::{ColumnType, DatasetId, SnapshotId};

    fn make_chunk(idx: u32) -> StagedChunk {
        let leaf_hashes: Vec<[u8; 32]> = (0u8..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = idx as u8;
                h[1] = i;
                h
            })
            .collect();
        let row_bytes = vec![vec![idx as u8]; 4];
        StagedChunk {
            chunk_index: idx,
            row_start: (idx as u64) * 4,
            row_end: (idx as u64) * 4 + 4,
            leaf_hashes,
            row_bytes,
        }
    }

    #[tokio::test]
    async fn builds_deterministic_manifest() {
        let dataset_id = DatasetId::new();
        let schema = DatasetSchema::new(
            dataset_id.clone(),
            "test",
            vec![ColumnSchema::new("id", ColumnType::U64)],
        );
        let chunks = vec![make_chunk(0), make_chunk(1)];

        let svc = Blake3CommitmentService;
        let snap_id = SnapshotId::new();

        let manifest1 = svc
            .build_snapshot_manifest(snap_id.clone(), dataset_id.clone(), &schema, &chunks)
            .await
            .unwrap();

        // Same inputs → same roots (determinism test).
        let manifest2 = svc
            .build_snapshot_manifest(snap_id.clone(), dataset_id, &schema, &chunks)
            .await
            .unwrap();

        assert_eq!(manifest1.snapshot_root, manifest2.snapshot_root);
        assert_eq!(manifest1.row_count, 8);
        assert_eq!(manifest1.chunk_count, 2);
    }
}
