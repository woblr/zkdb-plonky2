//! Proof plan — maps a physical plan onto a set of proving tasks
//! with recursive aggregation topology.

use crate::commitment::root::CommitmentRoot;
use crate::query::physical_plan::{PhysicalNode, PhysicalPlan};
use crate::types::{DatasetId, QueryId, SnapshotId, ZkDbError, ZkResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Task ID
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub Uuid);

impl TaskId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator kind for proving
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum ProofOperator {
    Scan {
        chunk_indices: Vec<u32>,
        column_names: Option<Vec<String>>,
    },
    Filter {
        predicate_json: String,
    },
    Projection {
        items_json: String,
    },
    PartialAggregate {
        group_by_json: String,
        aggregates_json: String,
    },
    MergeAggregate {
        group_by_json: String,
        aggregates_json: String,
        having_json: Option<String>,
    },
    Sort {
        keys_json: String,
    },
    Limit {
        n: u64,
        offset: u64,
    },
    /// Hash join operator.
    HashJoin {
        condition_json: Option<String>,
        kind_json: String,
    },
    /// Recursive fold: verify two inner proofs and combine their commitments.
    RecursiveFold {
        left_task: TaskId,
        right_task: TaskId,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Proving task
// ─────────────────────────────────────────────────────────────────────────────

/// A single unit of proving work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingTask {
    pub task_id: TaskId,
    pub operator: ProofOperator,
    /// Tasks whose proofs are inputs to this task (empty for leaf tasks).
    pub depends_on: Vec<TaskId>,
}

impl ProvingTask {
    pub fn is_leaf(&self) -> bool {
        self.depends_on.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation topology
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how leaf proofs are recursively folded into the root proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationTopology {
    /// Ordered list of tasks (topological order: leaves first, root last).
    pub tasks: Vec<ProvingTask>,
    /// The task_id of the root proof.
    pub root_task_id: TaskId,
}

// ─────────────────────────────────────────────────────────────────────────────
// OperatorParams
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed operator-specific parameters extracted at plan build time.
/// Avoids re-parsing JSON in the hot proving path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorParams {
    /// For Sort: column name to sort on (first key only; multi-col sort not yet supported).
    #[serde(default)]
    pub sort_column: Option<String>,
    /// For Sort: true = sort descending.
    #[serde(default)]
    pub sort_descending: bool,
    /// For Sort: LIMIT top-K value (0 = no limit). Plonky2 rejects plans with limit > 0.
    #[serde(default)]
    pub limit: u64,
    /// For GroupBy: column name to group on.
    #[serde(default)]
    pub group_by_column: Option<String>,
    /// For GroupBy/Agg: column to aggregate (sum/avg target).
    #[serde(default)]
    pub agg_column: Option<String>,
    /// For JOIN: left-table key column.
    #[serde(default)]
    pub join_left_key: Option<String>,
    /// For JOIN: right-table key column.
    #[serde(default)]
    pub join_right_key: Option<String>,
    /// For JOIN: left-table value column for aggregating output.
    #[serde(default)]
    pub join_left_val_column: Option<String>,
    /// For JOIN: externally anchored commitment to the right table.
    /// Used by WitnessBuilder to verify the prover is using the correct table.
    #[serde(default)]
    pub join_right_poseidon_snap_lo: u64,
    /// For WHERE: filter column
    #[serde(default)]
    pub filter_column: Option<String>,
    /// For WHERE: filter operator (e.g. "eq", "gt", "lt")
    #[serde(default)]
    pub filter_op: Option<String>,
    /// For WHERE: filter value (only u64 supported for now)
    #[serde(default)]
    pub filter_value: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof plan
// ─────────────────────────────────────────────────────────────────────────────

/// The complete plan for generating a proof for a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPlan {
    pub query_id: QueryId,
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
    /// The snapshot root that will be a public input to every proof.
    pub snapshot_root: CommitmentRoot,
    pub topology: AggregationTopology,
    /// Number of leaf proving tasks (one per chunk in the base scan).
    pub leaf_count: u32,
    /// Poseidon snapshot commitment (first 8 bytes of Poseidon(row_values)[0..MAX_ROWS]).
    /// Enforced by WitnessBuilder: must match the data chunks provided.
    #[serde(default)]
    pub poseidon_snap_lo: u64,
    /// Structured operator parameters for schema-aware witness building.
    #[serde(default)]
    pub operator_params: OperatorParams,
    /// Serialised `DatasetSchema` (JSON). Set when proving against a real snapshot.
    /// Used by `WitnessBuilder` to schema-decode row bytes.
    #[serde(default)]
    pub schema_json: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ProofPlanner: PhysicalPlan → ProofPlan
// ─────────────────────────────────────────────────────────────────────────────

pub struct ProofPlanner;

impl ProofPlanner {
    pub fn plan(
        physical: PhysicalPlan,
        snapshot_root: CommitmentRoot,
        query_id: QueryId,
        manifest: &crate::database::snapshot::SnapshotManifest,
        schema_json: Option<String>,
    ) -> ZkResult<ProofPlan> {
        let mut tasks: Vec<ProvingTask> = vec![];
        let root_task_id = Self::translate_node(&physical.root, &mut tasks)?;
        let leaf_count = tasks.iter().filter(|t| t.is_leaf()).count() as u32;
        let operator_params = Self::extract_operator_params(&physical.root);

        // Determine the primary binding column to use for snap_lo
        let binding_col = operator_params.sort_column.as_ref()
            .or(operator_params.group_by_column.as_ref())
            .or(operator_params.agg_column.as_ref());
            
        let poseidon_snap_lo = binding_col
            .and_then(|col| manifest.column_poseidon_roots.get(col).copied())
            .unwrap_or(manifest.poseidon_snap_lo);

        Ok(ProofPlan {
            query_id,
            snapshot_id: physical.snapshot_id,
            dataset_id: physical.dataset_id,
            snapshot_root,
            topology: AggregationTopology {
                tasks,
                root_task_id,
            },
            leaf_count,
            poseidon_snap_lo,
            operator_params,
            schema_json,
        })
    }

    fn extract_operator_params(node: &PhysicalNode) -> OperatorParams {
        match node {
            PhysicalNode::Sort { input: _, keys } => {
                let first = keys.first();
                let col = first.and_then(|k| match &k.expr {
                    crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
                    _ => None,
                });
                let descending = first
                    .map(|k| matches!(k.order, crate::types::SortOrder::Desc))
                    .unwrap_or(false);
                OperatorParams {
                    sort_column: col,
                    sort_descending: descending,
                    ..Default::default()
                }
            }
            PhysicalNode::Limit { input, n, .. } => {
                let mut p = Self::extract_operator_params(input);
                p.limit = *n;
                p
            }
            PhysicalNode::PartialAggregate {
                group_by,
                aggregates,
                input,
            } => {
                // Recurse into input to propagate Filter params (filter_op, filter_value, etc.)
                let mut p = Self::extract_operator_params(input);
                p.group_by_column = group_by.first().and_then(|e| match e {
                    crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
                    _ => None,
                });
                p.agg_column = aggregates.first().and_then(|a| match &a.input {
                    crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
                    _ => None,
                });
                p
            }
            PhysicalNode::MergeAggregate {
                group_by,
                aggregates,
                input,
                ..
            } => {
                // Recurse into input to propagate Filter params (filter_op, filter_value, etc.)
                let mut p = Self::extract_operator_params(input);
                p.group_by_column = group_by.first().and_then(|e| match e {
                    crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
                    _ => None,
                });
                p.agg_column = aggregates.first().and_then(|a| match &a.input {
                    crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
                    _ => None,
                });
                p
            }
            PhysicalNode::HashJoin {
                condition,
                right_poseidon_snap_lo,
                ..
            } => {
                let (lk, rk) = extract_join_keys_from_condition(condition.as_ref());
                OperatorParams {
                    join_left_key: lk,
                    join_right_key: rk,
                    join_right_poseidon_snap_lo: right_poseidon_snap_lo.unwrap_or(0),
                    ..Default::default()
                }
            }
            PhysicalNode::Filter { input, predicate } => {
                let mut p = Self::extract_operator_params(input);
                if let crate::query::ast::Expr::BinOp { left, op, right } = &predicate {
                    if let crate::query::ast::Expr::Column { name, .. } = &**left {
                        p.filter_column = Some(name.clone());
                    }
                    if let crate::query::ast::BinOp::Eq = op {
                        p.filter_op = Some("eq".into());
                    } else if let crate::query::ast::BinOp::Gt = op {
                        p.filter_op = Some("gt".into());
                    } else if let crate::query::ast::BinOp::Lt = op {
                        p.filter_op = Some("lt".into());
                    }
                    if let crate::query::ast::Expr::Literal(crate::query::ast::Literal::Int(n)) = &**right {
                        p.filter_value = Some(*n as u64);
                    } else if let crate::query::ast::Expr::Literal(crate::query::ast::Literal::UInt(n)) = &**right {
                        p.filter_value = Some(*n);
                    } else if let crate::query::ast::Expr::Literal(crate::query::ast::Literal::Bool(b)) = &**right {
                        // Boolean predicates: true → 1, false → 0 (matches Bool column encoding)
                        p.filter_value = Some(*b as u64);
                    }
                }
                p
            }
            PhysicalNode::Projection { input, .. } => {
                Self::extract_operator_params(input)
            }
            _ => OperatorParams::default(),
        }
    }

    fn translate_node(node: &PhysicalNode, tasks: &mut Vec<ProvingTask>) -> ZkResult<TaskId> {
        match node {
            PhysicalNode::ChunkedScan {
                chunk_indices,
                columns,
                ..
            } => {
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::Scan {
                        chunk_indices: chunk_indices.clone(),
                        column_names: columns.clone(),
                    },
                    depends_on: vec![],
                });
                Ok(task_id)
            }

            PhysicalNode::Filter { input, predicate } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                let predicate_json = serde_json::to_string(predicate)
                    .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?;
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::Filter { predicate_json },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::Projection { input, items } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                let items_json = serde_json::to_string(items)
                    .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?;
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::Projection { items_json },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::PartialAggregate {
                input,
                group_by,
                aggregates,
            } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::PartialAggregate {
                        group_by_json: serde_json::to_string(group_by)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                        aggregates_json: serde_json::to_string(aggregates)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                    },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::MergeAggregate {
                input,
                group_by,
                aggregates,
                having,
            } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::MergeAggregate {
                        group_by_json: serde_json::to_string(group_by)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                        aggregates_json: serde_json::to_string(aggregates)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                        having_json: having
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                    },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::Sort { input, keys } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::Sort {
                        keys_json: serde_json::to_string(keys)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                    },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::Limit { input, n, offset } => {
                let dep = Self::translate_node(input, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::Limit {
                        n: *n,
                        offset: *offset,
                    },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::HashJoin {
                left,
                right,
                kind,
                condition,
                ..
            } => {
                let left_dep = Self::translate_node(left, tasks)?;
                let right_dep = Self::translate_node(right, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::HashJoin {
                        condition_json: condition
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                        kind_json: serde_json::to_string(&kind)
                            .map_err(|e| ZkDbError::QueryPlan(e.to_string()))?,
                    },
                    depends_on: vec![left_dep, right_dep],
                });
                Ok(task_id)
            }
        }
    }
}

fn extract_join_keys_from_condition(
    cond: Option<&crate::query::ast::Expr>,
) -> (Option<String>, Option<String>) {
    if let Some(crate::query::ast::Expr::BinOp { left, op: _, right }) = cond {
        let lk = match left.as_ref() {
            crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
            _ => None,
        };
        let rk = match right.as_ref() {
            crate::query::ast::Expr::Column { name, .. } => Some(name.clone()),
            _ => None,
        };
        return (lk, rk);
    }
    (None, None)
}
