//! Dataset handlers: create, get, ingest, snapshot, activate.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::api::dto::dataset::{
    CreateDatasetRequest, DatasetResponse, IngestResponse, IngestRowsRequest,
};
use crate::api::dto::query::SnapshotResponse;
use crate::api::error::{ApiError, ApiResult};
use crate::api::state::AppState;
use crate::database::encoding::RawRow;
use crate::database::schema::{ColumnSchema, DatasetSchema};
use crate::jobs::types::{CommitJob, IngestJob, JobKind};
use crate::types::{DatasetId, JobId, SnapshotId};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/datasets
// ─────────────────────────────────────────────────────────────────────────────

pub async fn create_dataset(
    State(state): State<AppState>,
    Json(req): Json<CreateDatasetRequest>,
) -> ApiResult<(StatusCode, Json<DatasetResponse>)> {
    let dataset_id = DatasetId::new();
    let columns: Vec<ColumnSchema> = req
        .columns
        .into_iter()
        .map(|c| {
            let mut col = ColumnSchema::new(c.name, c.col_type.into());
            if c.nullable {
                col = col.nullable();
            }
            col.description = c.description;
            col
        })
        .collect();

    let mut schema = DatasetSchema::new(dataset_id, req.name, columns);
    schema.description = req.description;
    schema.primary_key = req.primary_key;

    let record = state
        .dataset_service
        .create_dataset(schema)
        .await
        .map_err(ApiError::from)?;

    Ok((StatusCode::CREATED, Json(record.into())))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/datasets/:dataset_id
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_dataset(
    State(state): State<AppState>,
    Path(dataset_id): Path<String>,
) -> ApiResult<Json<DatasetResponse>> {
    let id = parse_dataset_id(&dataset_id)?;
    let record = state
        .dataset_service
        .get_dataset(&id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(record.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/datasets
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_datasets(State(state): State<AppState>) -> ApiResult<Json<Vec<DatasetResponse>>> {
    let records = state
        .dataset_service
        .list_datasets()
        .await
        .map_err(ApiError::from)?;
    Ok(Json(records.into_iter().map(Into::into).collect()))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/datasets/:dataset_id/ingest
// ─────────────────────────────────────────────────────────────────────────────

pub async fn ingest_rows(
    State(state): State<AppState>,
    Path(dataset_id): Path<String>,
    Json(req): Json<IngestRowsRequest>,
) -> ApiResult<(StatusCode, Json<IngestResponse>)> {
    let id = parse_dataset_id(&dataset_id)?;

    // Convert JSON rows to RawRow
    let raw_rows: Vec<RawRow> = req
        .rows
        .into_iter()
        .enumerate()
        .map(|(i, row_val)| {
            let values = match row_val {
                Value::Array(arr) => arr,
                Value::Object(map) => {
                    // Accept objects too — extract values in declaration order (simple approach).
                    map.into_values().collect()
                }
                other => vec![other],
            };
            RawRow {
                row_index: i as u64,
                values,
            }
        })
        .collect();

    let row_count = raw_rows.len() as u64;

    let result = state
        .dataset_service
        .ingest_rows(&id, raw_rows, req.chunk_size)
        .await
        .map_err(ApiError::from)?;

    let job_id = JobId::new();
    let job = state.job_registry.register(JobKind::Ingest(IngestJob {
        job_id: job_id.clone(),
        dataset_id: id.clone(),
        row_count,
        submitted_at_ms: now_ms(),
    }));
    state
        .job_registry
        .mark_completed(&job.job_id, Some(format!("{} rows", result.rows_ingested)))
        .ok();

    Ok((
        StatusCode::OK,
        Json(IngestResponse {
            dataset_id: id.to_string(),
            rows_ingested: result.rows_ingested,
            chunks_created: result.chunks_created,
            job_id: job_id.to_string(),
        }),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/datasets/:dataset_id/snapshots
// ─────────────────────────────────────────────────────────────────────────────

pub async fn create_snapshot(
    State(state): State<AppState>,
    Path(dataset_id): Path<String>,
) -> ApiResult<(StatusCode, Json<SnapshotResponse>)> {
    let id = parse_dataset_id(&dataset_id)?;

    let snap = state
        .dataset_service
        .create_snapshot(&id)
        .await
        .map_err(ApiError::from)?;

    let job_id = JobId::new();
    let job = state.job_registry.register(JobKind::Commit(CommitJob {
        job_id: job_id.clone(),
        dataset_id: id,
        submitted_at_ms: now_ms(),
    }));
    state
        .job_registry
        .mark_completed(&job.job_id, Some(snap.snapshot_id.to_string()))
        .ok();

    Ok((StatusCode::CREATED, Json(snap.into())))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/datasets/:dataset_id/snapshots/:snapshot_id/activate
// ─────────────────────────────────────────────────────────────────────────────

pub async fn activate_snapshot(
    State(state): State<AppState>,
    Path((dataset_id, snapshot_id)): Path<(String, String)>,
) -> ApiResult<Json<SnapshotResponse>> {
    let d_id = parse_dataset_id(&dataset_id)?;
    let s_id = parse_snapshot_id(&snapshot_id)?;

    let snap = state
        .dataset_service
        .activate_snapshot(&d_id, &s_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(snap.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/datasets/:dataset_id/snapshots
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_snapshots(
    State(state): State<AppState>,
    Path(dataset_id): Path<String>,
) -> ApiResult<Json<Vec<SnapshotResponse>>> {
    let id = parse_dataset_id(&dataset_id)?;
    let snaps = state
        .dataset_service
        .list_snapshots(&id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(snaps.into_iter().map(Into::into).collect()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_dataset_id(s: &str) -> ApiResult<DatasetId> {
    s.parse::<DatasetId>().map_err(|_| {
        ApiError(crate::types::ZkDbError::internal(format!(
            "invalid dataset_id: {}",
            s
        )))
    })
}

fn parse_snapshot_id(s: &str) -> ApiResult<SnapshotId> {
    s.parse::<SnapshotId>().map_err(|_| {
        ApiError(crate::types::ZkDbError::internal(format!(
            "invalid snapshot_id: {}",
            s
        )))
    })
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
