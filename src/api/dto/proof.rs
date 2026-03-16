//! Proof-related DTOs.

use crate::proof::artifacts::{ProofArtifact, VerificationResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub proof_id: String,
    #[serde(default)]
    pub expected_snapshot_root: Option<String>,
    #[serde(default)]
    pub expected_query_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub proof_id: String,
    pub query_id: String,
    pub snapshot_id: String,
    pub backend: String,
    pub proof_hex: String,
    pub snapshot_root_hex: String,
    pub query_hash_hex: String,
    pub result_commitment_hex: String,
    pub result_row_count: u64,
    pub created_at_ms: u64,
}

impl From<ProofArtifact> for ProofResponse {
    fn from(a: ProofArtifact) -> Self {
        Self {
            proof_id: a.proof_id.to_string(),
            query_id: a.query_id.to_string(),
            snapshot_id: a.snapshot_id.to_string(),
            backend: a.backend.to_string(),
            proof_hex: a.hex_proof(),
            snapshot_root_hex: hex::encode(a.public_inputs.snapshot_root),
            query_hash_hex: hex::encode(a.public_inputs.query_hash),
            result_commitment_hex: hex::encode(a.public_inputs.result_commitment),
            result_row_count: a.public_inputs.result_row_count,
            created_at_ms: a.created_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationResponse {
    pub is_valid: bool,
    pub snapshot_root_hex: String,
    pub query_hash_hex: String,
    pub result_commitment_hex: String,
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<VerificationResult> for VerificationResponse {
    fn from(r: VerificationResult) -> Self {
        Self {
            is_valid: r.is_valid,
            snapshot_root_hex: hex::encode(r.snapshot_root),
            query_hash_hex: hex::encode(r.query_hash),
            result_commitment_hex: hex::encode(r.result_commitment),
            backend: r.backend.to_string(),
            error: r.error,
        }
    }
}
