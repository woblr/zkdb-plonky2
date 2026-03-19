//! Query and proof handlers.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::api::dto::proof::{ProofResponse, VerificationResponse, VerifyRequest};
use crate::api::dto::query::{QueryResultResponse, QuerySubmittedResponse, SubmitQueryRequest};
use crate::api::error::{ApiError, ApiResult};
use crate::api::state::AppState;
use crate::jobs::types::{JobKind, QueryJob, VerificationJob};
use crate::proof::artifacts::{ProofSystemKind, VerificationRequest};
use crate::query::service::QueryRequest;
use crate::query::service::QueryResult;
use crate::types::{BackendTag, JobId, ProofId, QueryId, QueryStatus, SnapshotId, ZkDbError};

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/queries
// ─────────────────────────────────────────────────────────────────────────────

pub async fn submit_query(
    State(state): State<AppState>,
    Json(req): Json<SubmitQueryRequest>,
) -> ApiResult<(StatusCode, Json<QuerySubmittedResponse>)> {
    let dataset_id = req
        .dataset_id
        .parse::<crate::types::DatasetId>()
        .map_err(|_| ApiError(ZkDbError::internal("invalid dataset_id")))?;

    let snapshot_id = req
        .snapshot_id
        .as_deref()
        .map(|s| {
            s.parse::<SnapshotId>()
                .map_err(|_| ApiError(ZkDbError::internal("invalid snapshot_id")))
        })
        .transpose()?;

    let query_request = QueryRequest {
        dataset_id: dataset_id.clone(),
        sql: req.sql,
        snapshot_id,
        user_id: None, // TODO: extract from auth middleware
        user_roles: vec![],
    };

    // Validate, authorize, normalize
    let normalized = state
        .query_service
        .submit(query_request)
        .await
        .map_err(ApiError::from)?;

    let query_id = normalized.query_id.clone();
    let snapshot_id = normalized.snapshot_id.clone();
    let submitted_at = normalized.submitted_at_ms;

    // Register job
    let job_id = JobId::new();
    state.job_registry.register(JobKind::Query(QueryJob {
        job_id: job_id.clone(),
        query_id: query_id.clone(),
        dataset_id,
        snapshot_id: snapshot_id.clone(),
        sql: normalized.sql.clone(),
        user_id: normalized.user_id.clone(),
        submitted_at_ms: submitted_at,
    }));

    // Run proof pipeline (synchronous inline — the prover blocks until proof is complete)
    let prover = state.get_prover(&req.backend);
    let proof_result = async {
        let proof_plan = state.query_service.build_proof_plan(&normalized).await?;
        let artifact = prover.prove(&normalized, &proof_plan).await?;
        Ok::<_, ZkDbError>(artifact)
    }
    .await;

    match proof_result {
        Ok(artifact) => {
            let proof_id = artifact.proof_id.clone();
            state.query_service.save_result(QueryResult {
                query_id: query_id.clone(),
                snapshot_id: snapshot_id.clone(),
                status: QueryStatus::Completed,
                result_json: Some(
                    serde_json::json!({
                        "row_count": artifact.public_inputs.result_row_count,
                        // Blake3 over (snapshot_root ‖ query_hash ‖ proof_bytes[:32]).
                        // This is metadata-only; it is NOT circuit-constrained.
                        // For the circuit-proved result use result_commit_lo from the artifact.
                        "result_commitment_blake3_metadata": hex::encode(artifact.public_inputs.result_commitment),
                        "result_commit_lo_poseidon_proved": artifact.public_inputs.result_commit_lo,
                        "result_commitment_kind": format!("{:?}", artifact.capabilities.result_commitment_kind),
                    })
                    .to_string(),
                ),
                proof_id: Some(proof_id),
                capabilities: Some(artifact.capabilities.clone()),
                error: None,
            });
            state
                .job_registry
                .mark_completed(&job_id, Some(query_id.to_string()))
                .ok();
        }
        Err(e) => {
            state.query_service.save_result(QueryResult {
                query_id: query_id.clone(),
                snapshot_id: snapshot_id.clone(),
                status: QueryStatus::Failed,
                result_json: None,
                proof_id: None,
                capabilities: None,
                error: Some(e.to_string()),
            });
            state.job_registry.mark_failed(&job_id, e.to_string()).ok();
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(QuerySubmittedResponse {
            query_id: query_id.to_string(),
            snapshot_id: snapshot_id.to_string(),
            status: "submitted".into(),
            submitted_at_ms: submitted_at,
        }),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/queries/:query_id
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_query_result(
    State(state): State<AppState>,
    Path(query_id): Path<String>,
) -> ApiResult<Json<QueryResultResponse>> {
    let id = query_id
        .parse::<QueryId>()
        .map_err(|_| ApiError(ZkDbError::internal("invalid query_id")))?;

    let result = state
        .query_service
        .get_result(&id)
        .map_err(ApiError::from)?;

    let result_value = result
        .result_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    Ok(Json(QueryResultResponse {
        query_id: result.query_id.to_string(),
        snapshot_id: result.snapshot_id.to_string(),
        status: result.status,
        result: result_value,
        proof_id: result.proof_id.map(|p| p.to_string()),
        capabilities: result.capabilities,
        error: result.error,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/proofs/:proof_id
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_proof(
    State(state): State<AppState>,
    Path(proof_id): Path<String>,
) -> ApiResult<Json<ProofResponse>> {
    let id = proof_id
        .parse::<ProofId>()
        .map_err(|_| ApiError(ZkDbError::internal("invalid proof_id")))?;

    let artifact = state.proof_store.get(&id).map_err(ApiError::from)?;

    Ok(Json(artifact.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/proofs/verify
// ─────────────────────────────────────────────────────────────────────────────

pub async fn verify_proof(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> ApiResult<Json<VerificationResponse>> {
    let proof_id = req
        .proof_id
        .parse::<ProofId>()
        .map_err(|_| ApiError(ZkDbError::internal("invalid proof_id")))?;

    // Reject artifacts that carry no real cryptographic proof.
    // Checking both proof_system and backend ensures a mislabeled artifact cannot slip through
    // (e.g. an artifact with ProofSystemKind::None but a non-Mock backend tag, or vice versa).
    let artifact = state.proof_store.get(&proof_id).map_err(ApiError::from)?;
    let is_no_proof = artifact.proof_system == ProofSystemKind::None
        || artifact.backend == BackendTag::Mock;
    if is_no_proof {
        return Err(ApiError(ZkDbError::Schema(format!(
            "artifact carries no real cryptographic proof \
             (backend={}, proof_system={:?}). \
             Only constraint_checked (audit) and plonky2 (ZK-SNARK) artifacts \
             may be submitted for verification.",
            artifact.backend, artifact.proof_system
        ))));
    }

    // Parse required expected bindings.
    let expected_root = {
        let s = &req.expected_snapshot_root;
        let bytes =
            hex::decode(s).map_err(|_| ZkDbError::internal("invalid hex for expected_snapshot_root"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ZkDbError::internal("expected_snapshot_root must be 32 bytes hex"))?;
        arr
    };

    let expected_hash = {
        let s = &req.expected_query_hash;
        let bytes =
            hex::decode(s).map_err(|_| ZkDbError::internal("invalid hex for expected_query_hash"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ZkDbError::internal("expected_query_hash must be 32 bytes hex"))?;
        arr
    };

    let ver_req = VerificationRequest {
        proof_id,
        expected_snapshot_root: Some(expected_root),
        expected_query_hash: Some(expected_hash),
    };

    let result = state
        .verifier
        .verify(ver_req)
        .await
        .map_err(ApiError::from)?;

    // Register verification job
    let job_id = JobId::new();
    state
        .job_registry
        .register(JobKind::Verification(VerificationJob {
            job_id: job_id.clone(),
            proof_id: req.proof_id.parse().unwrap_or_default(),
            submitted_at_ms: now_ms(),
        }));
    state
        .job_registry
        .mark_completed(&job_id, Some(result.is_valid.to_string()))
        .ok();

    Ok(Json(result.into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/jobs/:job_id
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = job_id
        .parse::<JobId>()
        .map_err(|_| ApiError(ZkDbError::internal("invalid job_id")))?;

    let record = state.job_registry.get(&id).map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({
        "job_id": record.job_id.to_string(),
        "status": record.status,
        "progress_pct": record.progress_pct,
        "error": record.error,
        "created_at_ms": record.created_at_ms,
        "completed_at_ms": record.completed_at_ms,
    })))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
