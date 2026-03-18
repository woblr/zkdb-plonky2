//! Backend-agnostic proving abstraction.
//!
//! All concrete proving backends (Plonky2, Plonky3, …) implement these traits.
//! The rest of the system depends only on these traits, never on backend-specific types.

use crate::circuit::witness::WitnessTrace;
use crate::proof::artifacts::{ProofArtifact, VerificationResult};
use crate::query::proof_plan::ProofPlan;
use crate::types::{BackendTag, ZkResult};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit handle — opaque per-backend circuit descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// An opaque handle to a compiled circuit.
/// Each backend defines its own concrete type.
pub trait CircuitHandle: Send + Sync + std::fmt::Debug + std::any::Any {
    fn backend_tag(&self) -> BackendTag;
    fn num_public_inputs(&self) -> usize;
    /// Downcast support for backend-specific handle types.
    fn as_any(&self) -> &dyn std::any::Any;
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvingBackend trait
// ─────────────────────────────────────────────────────────────────────────────

/// The main backend abstraction.
///
/// Implementors:
/// - `ConstraintCheckedBackend` (hash-chain audit, real constraints, not ZK)
/// - `Plonky2Backend` (future)
/// - `Plonky3Backend` (future)
#[async_trait]
pub trait ProvingBackend: Send + Sync + std::fmt::Debug {
    fn tag(&self) -> BackendTag;

    /// Compile a circuit for the given proof plan.
    /// Returns an opaque handle used in subsequent `prove` calls.
    async fn compile_circuit(&self, plan: &ProofPlan) -> ZkResult<Box<dyn CircuitHandle>>;

    /// Generate a proof given a compiled circuit and a witness trace.
    async fn prove(
        &self,
        circuit: &dyn CircuitHandle,
        witness: &WitnessTrace,
    ) -> ZkResult<ProofArtifact>;

    /// Verify a proof against its public inputs.
    async fn verify(&self, artifact: &ProofArtifact) -> ZkResult<VerificationResult>;

    /// Recursively fold two proofs into one.
    async fn fold(&self, left: &ProofArtifact, right: &ProofArtifact) -> ZkResult<ProofArtifact>;
}
