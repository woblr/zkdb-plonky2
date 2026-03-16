pub mod constraint_checked;
pub mod mock;
pub mod plonky2;
pub mod registry;
pub mod traits;

pub use constraint_checked::ConstraintCheckedBackend;
pub use mock::MockBackend;
pub use plonky2::Plonky2Backend;
pub use traits::{CircuitHandle, ProvingBackend};
pub use registry::{BackendRegistry, BackendDescriptor, BackendCapabilities};
