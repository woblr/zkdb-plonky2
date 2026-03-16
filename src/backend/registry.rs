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
            "table_scan".into(), "filter".into(), "projection".into(),
            "aggregate".into(), "group_by".into(), "sort".into(),
            "limit".into(), "join".into(),
        ]
    }

    /// MockBackend: no real logic, no proof system.
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
            has_zero_knowledge: false,           // audit log, not zk
            has_succinct_verification: false,    // O(columns × rows)
            has_polynomial_commitments: false,   // Blake3, not polynomial
            has_real_proof_system: false,        // NOT a SNARK
            supports_recursion: true,            // hash-chain fold is supported
            custom_gates: true,
            max_constraints: Some(1 << 20),
            supported_operators: Self::all_operators(),
            proof_system: ProofSystemKind::HashChainAudit,
        }
    }

    /// Plonky2Backend stub: real zk SNARK, not yet wired.
    pub fn plonky2_stub() -> Self {
        Self {
            is_mock: false,
            has_real_constraints: true,
            has_zero_knowledge: true,
            has_succinct_verification: true,
            has_polynomial_commitments: true,    // FRI
            has_real_proof_system: true,
            supports_recursion: true,
            custom_gates: true,
            max_constraints: Some(1 << 22),
            supported_operators: Self::all_operators(),
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
    pub fn mock() -> Self {
        Self {
            kind: BackendKind::Mock,
            tag: BackendTag::Mock,
            name: "MockBackend".into(),
            version: "0.1.0".into(),
            description: "Deterministic Blake3-stub for testing. No real constraints or proof system.".into(),
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
            ).into(),
            capabilities: BackendCapabilities::constraint_checked(),
        }
    }

    pub fn plonky2_stub() -> Self {
        Self {
            kind: BackendKind::Plonky2,
            tag: BackendTag::Plonky2,
            name: "Plonky2Backend".into(),
            version: "0.0.0-stub".into(),
            description: concat!(
                "Plonky2 FRI-based SNARK. Zero-knowledge. Succinct. ",
                "STUB — proof generation path not yet wired. ",
                "prove() returns an error."
            ).into(),
            capabilities: BackendCapabilities::plonky2_stub(),
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

    pub fn register(
        &mut self,
        descriptor: BackendDescriptor,
        backend: Arc<dyn ProvingBackend>,
    ) {
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

    pub fn len(&self) -> usize { self.backends.len() }
    pub fn is_empty(&self) -> bool { self.backends.is_empty() }
}

impl Default for BackendRegistry {
    fn default() -> Self { Self::new() }
}

/// Create a registry pre-populated with mock, constraint_checked, and plonky2_stub.
pub fn default_registry() -> BackendRegistry {
    use crate::backend::{ConstraintCheckedBackend, MockBackend, Plonky2Backend};
    let mut registry = BackendRegistry::new();
    registry.register(BackendDescriptor::mock(), Arc::new(MockBackend::default()));
    registry.register(BackendDescriptor::constraint_checked(), Arc::new(ConstraintCheckedBackend::default()));
    registry.register(BackendDescriptor::plonky2_stub(), Arc::new(Plonky2Backend::new_stub()));
    registry
}
