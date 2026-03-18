//! Proof-related DTOs.
//!
//! ## Commitment naming convention
//!
//! Two distinct commitments are exposed in every response:
//!
//! | Field                               | Source                           | Security status             |
//! |-------------------------------------|----------------------------------|-----------------------------|
//! | `unsafe_metadata_commitment_hex`    | Blake3 outer hash (metadata)     | **NOT circuit-proved**      |
//! | `result_commit_poseidon_proved_hex` | Poseidon PI[4]/[5]/[6] in-circuit | **Circuit-proved**          |
//!
//! **ALWAYS** use `result_commit_poseidon_proved_hex` for security-critical checks.
//! `unsafe_metadata_commitment_hex` is for correlation/audit **only** and carries
//! no cryptographic binding from the circuit. Using it for security decisions is wrong.

use crate::proof::artifacts::{ExternalAnchorStatus, ProofArtifact, ProofSystemKind, VerificationResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub proof_id: String,
    /// Required. The snapshot root the caller expects this proof to bind to.
    /// Providing the wrong root causes verification to fail — this prevents
    /// replay attacks and context confusion.
    pub expected_snapshot_root: String,
    /// Required. The query hash (Blake3 of the SQL text) the caller expects.
    /// Must match the proof's committed query_hash public input.
    pub expected_query_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub proof_id: String,
    pub query_id: String,
    pub snapshot_id: String,
    pub backend: String,
    /// Proof system used (e.g. "plonky2_snark", "hash_chain_audit", "none").
    pub proof_system_kind: String,
    pub proof_hex: String,
    pub snapshot_root_hex: String,
    pub query_hash_hex: String,
    /// Blake3 outer hash — **NOT circuit-proved**. For correlation/audit only.
    /// Do NOT use this for security-critical checks. Use `result_commit_poseidon_proved_hex`.
    pub unsafe_metadata_commitment_hex: String,
    /// Poseidon in-circuit result commitment — **circuit-proved**.
    /// This is the authoritative security-relevant commitment.
    /// Encoded as a 16-character hex string (8 bytes / 64-bit Goldilocks element).
    pub result_commit_poseidon_proved_hex: String,
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
            proof_system_kind: match &a.proof_system {
                ProofSystemKind::None => "none",
                ProofSystemKind::HashChainAudit => "hash_chain_audit",
                ProofSystemKind::Plonky2Snark => "plonky2_snark",
                ProofSystemKind::Halo2Snark => "halo2_snark",
            }
            .into(),
            proof_hex: a.hex_proof(),
            snapshot_root_hex: hex::encode(a.public_inputs.snapshot_root),
            query_hash_hex: hex::encode(a.public_inputs.query_hash),
            unsafe_metadata_commitment_hex: hex::encode(a.public_inputs.result_commitment),
            result_commit_poseidon_proved_hex: hex::encode(
                a.public_inputs.result_commit_lo.to_le_bytes(),
            ),
            result_row_count: a.public_inputs.result_row_count,
            created_at_ms: a.created_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationResponse {
    pub is_valid: bool,
    /// Human-readable label distinguishing audit artifacts from real ZK proofs.
    /// Values: "proof_verified", "audit_artifact_verified", "mock_stub_verified"
    pub verification_kind: String,
    /// Proof system used. Consumers MUST check this before trusting `is_valid`.
    /// Values: "plonky2_snark", "hash_chain_audit", "none"
    pub proof_system_kind: String,
    /// Whether the proof system provides a zero-knowledge guarantee.
    /// `false` for ConstraintChecked (hash-chain audit) and Mock.
    pub has_zero_knowledge: bool,
    /// Whether verification is succinct (sub-linear in witness size).
    /// `false` for ConstraintChecked (O(columns × rows)) and Mock.
    pub is_succinct: bool,
    pub snapshot_root_hex: String,
    pub query_hash_hex: String,
    /// Blake3 outer hash — **NOT circuit-proved**. For correlation/audit only.
    /// Do NOT use this for security-critical checks. Use `result_commit_poseidon_proved_hex`.
    pub unsafe_metadata_commitment_hex: String,
    /// Poseidon in-circuit result commitment — **circuit-proved**.
    /// This is the authoritative security-relevant commitment.
    pub result_commit_poseidon_proved_hex: String,
    pub backend: String,
    pub completeness_proved: bool,
    /// Whether the proof's snapshot was verified against an external manifest anchor.
    /// Values: "unanchored" | "anchored" | "mismatch" | "encoding_mismatch"
    pub external_anchor_status: String,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<VerificationResult> for VerificationResponse {
    fn from(r: VerificationResult) -> Self {
        let external_anchor_status = match &r.external_anchor_status {
            ExternalAnchorStatus::Unanchored => "unanchored".into(),
            ExternalAnchorStatus::Anchored => "anchored".into(),
            ExternalAnchorStatus::Mismatch { expected_snap_lo, proof_snap_lo } => {
                format!(
                    "mismatch(expected={:#018x},proof={:#018x})",
                    expected_snap_lo, proof_snap_lo
                )
            }
            ExternalAnchorStatus::EncodingMismatch => "encoding_mismatch".into(),
        };

        let proof_system_kind = match &r.proof_system {
            ProofSystemKind::None => "none",
            ProofSystemKind::HashChainAudit => "hash_chain_audit",
            ProofSystemKind::Plonky2Snark => "plonky2_snark",
            ProofSystemKind::Halo2Snark => "halo2_snark",
        };

        let verification_kind = match &r.proof_system {
            ProofSystemKind::Plonky2Snark | ProofSystemKind::Halo2Snark => "proof_verified",
            ProofSystemKind::HashChainAudit => "audit_artifact_verified",
            ProofSystemKind::None => "mock_stub_verified",
        };

        Self {
            is_valid: r.is_valid,
            verification_kind: verification_kind.into(),
            proof_system_kind: proof_system_kind.into(),
            has_zero_knowledge: r.proof_system.is_zero_knowledge(),
            is_succinct: r.proof_system.is_succinct(),
            snapshot_root_hex: hex::encode(r.snapshot_root),
            query_hash_hex: hex::encode(r.query_hash),
            unsafe_metadata_commitment_hex: hex::encode(r.result_commitment),
            result_commit_poseidon_proved_hex: hex::encode(
                r.result_commit_poseidon_lo.to_le_bytes(),
            ),
            backend: r.backend.to_string(),
            completeness_proved: r.completeness_proved,
            external_anchor_status,
            warnings: r.warnings,
            error: r.error,
        }
    }
}
