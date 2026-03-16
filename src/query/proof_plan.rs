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
    ) -> ZkResult<ProofPlan> {
        let mut tasks: Vec<ProvingTask> = vec![];
        let root_task_id = Self::translate_node(&physical.root, &mut tasks)?;
        let leaf_count = tasks.iter().filter(|t| t.is_leaf()).count() as u32;

        Ok(ProofPlan {
            query_id,
            snapshot_id: physical.snapshot_id,
            dataset_id: physical.dataset_id,
            snapshot_root,
            topology: AggregationTopology { tasks, root_task_id },
            leaf_count,
        })
    }

    fn translate_node(node: &PhysicalNode, tasks: &mut Vec<ProvingTask>) -> ZkResult<TaskId> {
        match node {
            PhysicalNode::ChunkedScan { chunk_indices, columns, .. } => {
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

            PhysicalNode::PartialAggregate { input, group_by, aggregates } => {
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

            PhysicalNode::MergeAggregate { input, group_by, aggregates, having } => {
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
                            .map(|h| serde_json::to_string(h))
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
                    operator: ProofOperator::Limit { n: *n, offset: *offset },
                    depends_on: vec![dep],
                });
                Ok(task_id)
            }

            PhysicalNode::HashJoin { left, right, kind, condition } => {
                let left_dep = Self::translate_node(left, tasks)?;
                let right_dep = Self::translate_node(right, tasks)?;
                let task_id = TaskId::new();
                tasks.push(ProvingTask {
                    task_id: task_id.clone(),
                    operator: ProofOperator::HashJoin {
                        condition_json: condition
                            .as_ref()
                            .map(|c| serde_json::to_string(c))
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
