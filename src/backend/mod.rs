pub mod constraint_checked;
pub mod plonky2;
pub mod registry;
pub mod traits;

pub use constraint_checked::ConstraintCheckedBackend;
pub use plonky2::Plonky2Backend;
pub use registry::{BackendCapabilities, BackendDescriptor, BackendRegistry, backend_for_kind};
pub use traits::{CircuitHandle, ProvingBackend};
