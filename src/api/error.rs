//! Maps domain errors to HTTP responses.

use crate::types::ZkDbError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub code: String,
}

pub struct ApiError(pub ZkDbError);

impl From<ZkDbError> for ApiError {
    fn from(e: ZkDbError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            ZkDbError::DatasetNotFound(_) => (StatusCode::NOT_FOUND, "dataset_not_found"),
            ZkDbError::SnapshotNotFound(_) => (StatusCode::NOT_FOUND, "snapshot_not_found"),
            ZkDbError::NoActiveSnapshot(_) => (StatusCode::CONFLICT, "no_active_snapshot"),
            ZkDbError::QueryNotFound(_) => (StatusCode::NOT_FOUND, "query_not_found"),
            ZkDbError::JobNotFound(_) => (StatusCode::NOT_FOUND, "job_not_found"),
            ZkDbError::Schema(_) => (StatusCode::BAD_REQUEST, "schema_error"),
            ZkDbError::Ingest(_) => (StatusCode::BAD_REQUEST, "ingest_error"),
            ZkDbError::Encoding(_) => (StatusCode::BAD_REQUEST, "encoding_error"),
            ZkDbError::QueryParse(_) => (StatusCode::BAD_REQUEST, "query_parse_error"),
            ZkDbError::QueryPlan(_) => (StatusCode::BAD_REQUEST, "query_plan_error"),
            ZkDbError::PolicyDenied(_) => (StatusCode::FORBIDDEN, "policy_denied"),
            ZkDbError::VerificationFailed => (StatusCode::BAD_REQUEST, "verification_failed"),
            ZkDbError::Proving(_) => (StatusCode::INTERNAL_SERVER_ERROR, "proving_error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let body = ErrorBody {
            error: self.0.to_string(),
            code: code.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
