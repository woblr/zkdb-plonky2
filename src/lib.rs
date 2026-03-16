//! zkdb-plonky2: Zero-knowledge database library.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  API layer  (api/)                                           │
//! │  HTTP handlers · DTOs · Router · AppState                   │
//! ├───────────────────────────────┬─────────────────────────────┤
//! │  Database layer (database/)   │  Query layer (query/)        │
//! │  Schema · Ingest · Snapshot   │  Parser · Logical plan       │
//! │  Storage traits               │  Physical plan · Proof plan  │
//! ├───────────────────────────────┼─────────────────────────────┤
//! │  Commitment layer             │  Proof layer (proof/)        │
//! │  (commitment/)                │  Prover · Verifier · Store   │
//! │  Merkle · Root · Service      │                              │
//! ├───────────────────────────────┼─────────────────────────────┤
//! │  Circuit layer (circuit/)     │  Backend layer (backend/)    │
//! │  Operator circuits            │  ProvingBackend trait        │
//! │  Witness generation           │  MockBackend                 │
//! ├───────────────────────────────┴─────────────────────────────┤
//! │  Gates (gates/)    Field (field.rs)    Crypto (crypto/)      │
//! │  Gadget interfaces             Field element arithmetic       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Cross-cutting: types.rs · policy/ · jobs/ · audit/ · utils/│
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod api;
pub mod audit;
pub mod backend;
pub mod benchmarks;
pub mod circuit;
pub mod commitment;
pub mod crypto;
pub mod database;
pub mod field;
pub mod gates;
pub mod jobs;
pub mod policy;
pub mod proof;
pub mod query;
pub mod types;
pub mod utils;

// Convenient re-exports for integration tests.
pub use types::{
    AggKind, BackendTag, ColumnType, DatasetId, DatasetStatus, JobId, JobStatus, ProofId, QueryId,
    QueryStatus, SnapshotId, SnapshotStatus, ZkDbError, ZkResult,
};
