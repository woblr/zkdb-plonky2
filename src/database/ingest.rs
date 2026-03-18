//! Ingestion pipeline: validate → encode → chunk → stage.

use crate::database::encoding::{CanonicalRow, DefaultRowEncoder, RawRow, RowEncoder};
use crate::database::schema::DatasetSchema;
use crate::database::storage::{ChunkStore, StagedChunk};
use crate::types::{DatasetId, ZkResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default number of rows per chunk.
pub const DEFAULT_CHUNK_SIZE: u32 = 512;

// ─────────────────────────────────────────────────────────────────────────────
// Ingest request
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    pub dataset_id: DatasetId,
    pub rows: Vec<RawRow>,
    pub chunk_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub rows_ingested: u64,
    pub chunks_created: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Chunker
// ─────────────────────────────────────────────────────────────────────────────

/// Splits a list of canonical rows into fixed-size chunks.
pub struct Chunker {
    pub chunk_size: u32,
}

impl Chunker {
    pub fn new(chunk_size: u32) -> Self {
        Self { chunk_size }
    }

    pub fn chunk(&self, rows: Vec<CanonicalRow>) -> Vec<StagedChunk> {
        let size = self.chunk_size as usize;
        let mut chunks = Vec::new();
        let mut chunk_index = 0u32;

        for window in rows.chunks(size) {
            let row_start = window.first().map(|r| r.row_index).unwrap_or(0);
            let row_end = window.last().map(|r| r.row_index + 1).unwrap_or(row_start);
            let leaf_hashes: Vec<[u8; 32]> = window.iter().map(|r| r.leaf_hash()).collect();
            let row_bytes: Vec<Vec<u8>> = window.iter().map(|r| r.bytes.clone()).collect();

            chunks.push(StagedChunk {
                chunk_index,
                row_start,
                row_end,
                leaf_hashes,
                row_bytes,
            });
            chunk_index += 1;
        }

        chunks
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingest pipeline
// ─────────────────────────────────────────────────────────────────────────────

pub struct IngestPipeline {
    encoder: Arc<dyn RowEncoder>,
    chunk_store: Arc<dyn ChunkStore>,
    default_chunk_size: u32,
}

impl IngestPipeline {
    pub fn new(encoder: Arc<dyn RowEncoder>, chunk_store: Arc<dyn ChunkStore>) -> Self {
        Self {
            encoder,
            chunk_store,
            default_chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn with_default_encoder(chunk_store: Arc<dyn ChunkStore>) -> Self {
        Self::new(Arc::new(DefaultRowEncoder), chunk_store)
    }

    pub async fn run(
        &self,
        request: IngestRequest,
        schema: &DatasetSchema,
    ) -> ZkResult<IngestResult> {
        let chunk_size = request.chunk_size.unwrap_or(self.default_chunk_size);

        // 1. Encode all rows canonically.
        let canonical_rows: Vec<CanonicalRow> = request
            .rows
            .iter()
            .map(|row| self.encoder.encode(row, schema))
            .collect::<ZkResult<_>>()?;

        let rows_ingested = canonical_rows.len() as u64;

        // 2. Chunk encoded rows.
        let chunker = Chunker::new(chunk_size);
        let chunks = chunker.chunk(canonical_rows);
        let chunks_created = chunks.len() as u32;

        // 3. Write chunks to staging.
        self.chunk_store
            .write_chunks(&request.dataset_id, chunks)
            .await?;

        Ok(IngestResult {
            rows_ingested,
            chunks_created,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::ColumnSchema;
    use crate::database::storage::InMemoryChunkStore;
    use crate::types::{ColumnType, DatasetId};
    use serde_json::Value;

    fn make_schema(dataset_id: DatasetId) -> DatasetSchema {
        DatasetSchema::new(
            dataset_id,
            "test",
            vec![ColumnSchema::new("id", ColumnType::U64)],
        )
    }

    #[tokio::test]
    async fn ingest_produces_chunks() {
        let dataset_id = DatasetId::new();
        let schema = make_schema(dataset_id.clone());
        let store = Arc::new(InMemoryChunkStore::new());
        let pipeline = IngestPipeline::with_default_encoder(store.clone());

        let rows: Vec<RawRow> = (0u64..10)
            .map(|i| RawRow {
                row_index: i,
                values: vec![Value::Number(i.into())],
            })
            .collect();

        let req = IngestRequest {
            dataset_id: dataset_id.clone(),
            rows,
            chunk_size: Some(4),
        };

        let result = pipeline.run(req, &schema).await.unwrap();
        assert_eq!(result.rows_ingested, 10);
        assert_eq!(result.chunks_created, 3); // 4+4+2

        let stored = store.read_chunks(&dataset_id).await.unwrap();
        assert_eq!(stored.len(), 3);
    }
}
