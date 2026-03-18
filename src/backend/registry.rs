//! Backend registry: catalog of available proving backends and their capabilities.

use crate::backend::traits::ProvingBackend;
use crate::benchmarks::types::BackendKind;
use crate::proof::artifacts::ProofSystemKind;
use crate::types::BackendTag;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// BackendCapabilities — explicit per-dimension capability flags
// ─────────────────────────────────────────────────────────────────────────────

/// Explicit, per-dimension capability declaration for a backend.
///
/// Every field must be honestly set. Fields are grouped by what property they
/// describe. Downstream consumers (API, benchmark output, CLI) use these flags
/// to accurately communicate what guarantees a proof carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    // ── execution + constraint dimensions ───────────────────────────────────
    /// True if the backend is a stub with no real logic (testing only).
    pub is_mock: bool,
    /// True if real operator invariants are enforced during proving
    /// (sort order, group boundaries, selector booleanity, running-sum
    /// consistency, join key equality, multiset preservation).
    pub has_real_constraints: bool,

    // ── cryptographic / proof system dimensions ──────────────────────────────
    /// True if proofs have a zero-knowledge property (witness is hidden).
    pub has_zero_knowledge: bool,
    /// True if verification is succinct (sub-linear in witness size).
    pub has_succinct_verification: bool,
    /// True if a polynomial commitment scheme (FRI, KZG, IPA, …) is used.
    pub has_polynomial_commitments: bool,
    /// True if the backend uses a real proof system end-to-end.
    /// False for hash-chain / audit-log backends.
    pub has_real_proof_system: bool,

    // ── operational dimensions ───────────────────────────────────────────────
    /// True if recursive proof folding is supported.
    pub supports_recursion: bool,
    /// True if custom gate definitions can be registered.
    pub custom_gates: bool,
    /// Maximum number of constraints handled efficiently. None = unlimited.
    pub max_constraints: Option<u64>,
    /// Supported operator families.
    pub supported_operators: Vec<String>,

    // ── proof system label ───────────────────────────────────────────────────
    /// The `ProofSystemKind` that artifacts from this backend carry.
    pub proof_system: ProofSystemKind,
}

impl BackendCapabilities {
    fn all_operators() -> Vec<String> {
        vec![
            "table_scan".into(),
            "filter".into(),
            "projection".into(),
            "aggregate".into(),
            "group_by".into(),
            "sort".into(),
            "limit".into(),
            "join".into(),
        ]
    }

    /// Capabilities for a "no-proof" sentinel (used internally for error results).
    /// Not registered in the production backend registry.
    pub fn mock() -> Self {
        Self {
            is_mock: true,
            has_real_constraints: false,
            has_zero_knowledge: false,
            has_succinct_verification: false,
            has_polynomial_commitments: false,
            has_real_proof_system: false,
            supports_recursion: false,
            custom_gates: false,
            max_constraints: None,
            supported_operators: Self::all_operators(),
            proof_system: ProofSystemKind::None,
        }
    }

    /// ConstraintCheckedBackend: real constraints, hash-chain audit, NOT zk.
    pub fn constraint_checked() -> Self {
        Self {
            is_mock: false,
            has_real_constraints: true,
            has_zero_knowledge: false,         // audit log, not zk
            has_succinct_verification: false,  // O(columns × rows)
            has_polynomial_commitments: false, // Blake3, not polynomial
            has_real_proof_system: false,      // NOT a SNARK
            supports_recursion: true,          // hash-chain fold is supported
            custom_gates: true,
            max_constraints: Some(1 << 20),
            supported_operators: Self::all_operators(),
            proof_system: ProofSystemKind::HashChainAudit,
        }
    }

    /// Plonky2Backend: real FRI-based SNARK, fully wired.
    pub fn plonky2_live() -> Self {
        Self {
            is_mock: false,
            has_real_constraints: true,
            has_zero_knowledge: true,
            has_succinct_verification: true,
            has_polynomial_commitments: true, // FRI
            has_real_proof_system: true,
            supports_recursion: false, // fold() not yet implemented
            custom_gates: true,
            max_constraints: Some(1 << 22),
            supported_operators: vec![
                "count".into(),
                "sum".into(),
                "avg".into(),
                "filter".into(),
                "order_by_asc".into(),
                "order_by_desc".into(),
                "group_by".into(),
                "inner_join".into(),
            ],
            proof_system: ProofSystemKind::Plonky2Snark,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackendDescriptor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendDescriptor {
    pub kind: BackendKind,
    pub tag: BackendTag,
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: BackendCapabilities,
}

impl BackendDescriptor {
    /// Sentinel descriptor — not registered in production, kept for internal error tagging.
    pub fn mock() -> Self {
        Self {
            kind: BackendKind::Mock,
            tag: BackendTag::Mock,
            name: "NoProofSentinel".into(),
            version: "0.0.0".into(),
            description: "Internal sentinel — no proof system. Never registered in production."
                .into(),
            capabilities: BackendCapabilities::mock(),
        }
    }

    pub fn constraint_checked() -> Self {
        Self {
            kind: BackendKind::ConstraintChecked,
            tag: BackendTag::ConstraintChecked,
            name: "ConstraintCheckedBackend".into(),
            version: "0.1.0".into(),
            description: concat!(
                "Real operator constraint validation (sort, group_by, join, filter). ",
                "Produces hash-chain audit artifacts. ",
                "NOT zero-knowledge. NOT succinct. NOT a SNARK."
            )
            .into(),
            capabilities: BackendCapabilities::constraint_checked(),
        }
    }

    pub fn plonky2_live() -> Self {
        Self {
            kind: BackendKind::Plonky2,
            tag: BackendTag::Plonky2,
            name: "Plonky2Backend".into(),
            version: "0.3.0-live".into(),
            description: concat!(
                "Plonky2 FRI-based SNARK. Zero-knowledge. Succinct. ",
                "Fully wired: prove() generates real Goldilocks-field FRI proofs; ",
                "verify() performs real proof verification with PI cross-checks."
            )
            .into(),
            capabilities: BackendCapabilities::plonky2_live(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackendRegistry
// ─────────────────────────────────────────────────────────────────────────────

pub struct BackendRegistry {
    backends: HashMap<BackendKind, Arc<dyn ProvingBackend>>,
    descriptors: HashMap<BackendKind, BackendDescriptor>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            descriptors: HashMap::new(),
        }
    }

    pub fn register(&mut self, descriptor: BackendDescriptor, backend: Arc<dyn ProvingBackend>) {
        let kind = descriptor.kind.clone();
        self.descriptors.insert(kind.clone(), descriptor);
        self.backends.insert(kind, backend);
    }

    pub fn get(&self, kind: &BackendKind) -> Option<Arc<dyn ProvingBackend>> {
        self.backends.get(kind).cloned()
    }

    pub fn descriptor(&self, kind: &BackendKind) -> Option<&BackendDescriptor> {
        self.descriptors.get(kind)
    }

    pub fn list_kinds(&self) -> Vec<BackendKind> {
        self.descriptors.keys().cloned().collect()
    }

    pub fn list_descriptors(&self) -> Vec<&BackendDescriptor> {
        self.descriptors.values().collect()
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a registry pre-populated with constraint_checked and plonky2_live.
///
/// MockBackend has been removed. "mock" is no longer a valid backend for API or
/// benchmark requests. Use "constraint_checked" for lightweight integration tests
/// and "plonky2" for production ZK proving.
pub fn default_registry() -> BackendRegistry {
    use crate::backend::{ConstraintCheckedBackend, Plonky2Backend};
    let mut registry = BackendRegistry::new();
    registry.register(
        BackendDescriptor::constraint_checked(),
        Arc::new(ConstraintCheckedBackend::default()),
    );
    registry.register(
        BackendDescriptor::plonky2_live(),
        Arc::new(Plonky2Backend::new()),
    );
    registry
}

/// Instantiate a concrete backend from a `BackendKind`.
///
/// Returns `None` only for variants that are not yet implemented (Plonky3, Halo2).
pub fn backend_for_kind(
    kind: &crate::benchmarks::types::BackendKind,
) -> Option<Arc<dyn ProvingBackend>> {
    use crate::backend::{ConstraintCheckedBackend, Plonky2Backend};
    use crate::benchmarks::types::BackendKind;
    match kind {
        BackendKind::ConstraintChecked | BackendKind::Baseline => {
            Some(Arc::new(ConstraintCheckedBackend::default()))
        }
        BackendKind::Plonky2 => Some(Arc::new(Plonky2Backend::new())),
        _ => None,
    }
}
