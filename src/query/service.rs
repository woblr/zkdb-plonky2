//! Query service — coordinates parsing, planning, and execution dispatch.

use crate::commitment::root::CommitmentRoot;
use crate::database::service::DatasetService;
use crate::policy::engine::PolicyEngine;
use crate::policy::rules::PolicyContext;
use crate::query::logical_plan::LogicalPlanner;
use crate::query::parser::QueryParser;
use crate::query::physical_plan::PhysicalPlanner;
use crate::query::proof_plan::{ProofPlan, ProofPlanner};
use crate::types::{DatasetId, QueryId, SnapshotId, ZkDbError, ZkResult};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Query request / result types
// ─────────────────────────────────────────────────────────────────────────────

/// Submitted by a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub dataset_id: DatasetId,
    /// SQL query text.
    pub sql: String,
    /// Optional explicit snapshot to query (defaults to active snapshot).
    pub snapshot_id: Option<SnapshotId>,
    /// Requesting user (from auth layer).
    pub user_id: Option<String>,
    pub user_roles: Vec<String>,
}

/// Query bound to a specific snapshot (after auth + policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedQuery {
    pub query_id: QueryId,
    pub dataset_id: DatasetId,
    pub snapshot_id: SnapshotId,
    pub snapshot_root: CommitmentRoot,
    pub sql: String,
    pub user_id: Option<String>,
    pub submitted_at_ms: u64,
}

/// Result of a completed query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub query_id: QueryId,
    pub snapshot_id: SnapshotId,
    pub status: crate::types::QueryStatus,
    /// JSON-serialized result rows.
    pub result_json: Option<String>,
    /// Proof ID if proving completed.
    pub proof_id: Option<crate::types::ProofId>,
    pub capabilities: Option<crate::proof::artifacts::ProofCapabilities>,
    pub error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory query repository
// ─────────────────────────────────────────────────────────────────────────────

pub struct InMemoryQueryRepository {
    records: DashMap<QueryId, NormalizedQuery>,
    results: DashMap<QueryId, QueryResult>,
}

impl InMemoryQueryRepository {
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
            results: DashMap::new(),
        }
    }

    pub fn save_query(&self, q: NormalizedQuery) {
        self.records.insert(q.query_id.clone(), q);
    }

    pub fn get_query(&self, id: &QueryId) -> ZkResult<NormalizedQuery> {
        self.records
            .get(id)
            .map(|r| r.clone())
            .ok_or_else(|| ZkDbError::QueryNotFound(id.clone()))
    }

    pub fn save_result(&self, r: QueryResult) {
        self.results.insert(r.query_id.clone(), r);
    }

    pub fn get_result(&self, id: &QueryId) -> ZkResult<QueryResult> {
        self.results
            .get(id)
            .map(|r| r.clone())
            .ok_or_else(|| ZkDbError::QueryNotFound(id.clone()))
    }
}

impl Default for InMemoryQueryRepository {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryService
// ─────────────────────────────────────────────────────────────────────────────

pub struct QueryService {
    dataset_service: Arc<DatasetService>,
    policy_engine: Arc<PolicyEngine>,
    query_repo: Arc<InMemoryQueryRepository>,
}

impl QueryService {
    pub fn new(dataset_service: Arc<DatasetService>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            dataset_service,
            policy_engine,
            query_repo: Arc::new(InMemoryQueryRepository::new()),
        }
    }

    /// Validate, authorize, and normalize a query request into a snapshot-bound query.
    pub async fn submit(&self, request: QueryRequest) -> ZkResult<NormalizedQuery> {
        // 1. Resolve snapshot
        let snapshot = if let Some(snap_id) = &request.snapshot_id {
            let s = self.dataset_service.get_snapshot(snap_id).await?;
            if !s.is_query_eligible() {
                return Err(ZkDbError::internal(
                    "specified snapshot is not active/query-eligible",
                ));
            }
            s
        } else {
            self.dataset_service
                .get_active_snapshot(&request.dataset_id)
                .await?
        };

        let snapshot_id = snapshot.snapshot_id.clone();
        let manifest = snapshot.manifest_required()?;
        let snapshot_root = manifest.snapshot_root.clone();

        // 2. Parse query (validates SQL syntax)
        let stmt = QueryParser::parse(&request.sql)?;
        let referenced_cols = stmt.all_referenced_columns();
        let is_aggregate = stmt.has_aggregates();

        // 3. Policy evaluation
        let ctx = PolicyContext::new(request.dataset_id.clone())
            .with_user(
                request.user_id.clone().unwrap_or_default(),
                request.user_roles.clone(),
            )
            .with_query(request.sql.clone(), referenced_cols);
        let ctx = PolicyContext {
            is_aggregate,
            ..ctx
        };
        let evaluation = self.policy_engine.evaluate(&ctx);
        evaluation.into_result()?;

        // 4. Build normalized query
        let query_id = QueryId::new();
        let normalized = NormalizedQuery {
            query_id: query_id.clone(),
            dataset_id: request.dataset_id,
            snapshot_id,
            snapshot_root,
            sql: request.sql,
            user_id: request.user_id,
            submitted_at_ms: now_ms(),
        };

        self.query_repo.save_query(normalized.clone());
        Ok(normalized)
    }

    /// Build the full `ProofPlan` for a normalized query.
    pub async fn build_proof_plan(&self, normalized: &NormalizedQuery) -> ZkResult<ProofPlan> {
        let snapshot = self
            .dataset_service
            .get_snapshot(&normalized.snapshot_id)
            .await?;
        let manifest = snapshot.manifest_required()?;

        // Parse again to get AST (parser is cheap)
        let stmt = QueryParser::parse(&normalized.sql)?;

        // Logical plan
        let logical_planner = LogicalPlanner::new(
            normalized.dataset_id.clone(),
            normalized.snapshot_id.clone(),
        );
        let logical_plan = logical_planner.plan(stmt)?;

        // Physical plan
        let physical_plan = PhysicalPlanner::plan(logical_plan, manifest)?;

        // Schema JSON for schema-aware witness building
        let schema_json = self
            .dataset_service
            .get_dataset(&normalized.dataset_id)
            .await
            .ok()
            .and_then(|r| serde_json::to_string(&r.schema).ok());

        // Proof plan
        let proof_plan = ProofPlanner::plan(
            physical_plan,
            normalized.snapshot_root.clone(),
            normalized.query_id.clone(),
            manifest,
            schema_json,
        )?;

        Ok(proof_plan)
    }

    pub fn get_query(&self, id: &QueryId) -> ZkResult<NormalizedQuery> {
        self.query_repo.get_query(id)
    }

    pub fn save_result(&self, result: QueryResult) {
        self.query_repo.save_result(result);
    }

    pub fn get_result(&self, id: &QueryId) -> ZkResult<QueryResult> {
        self.query_repo.get_result(id)
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
