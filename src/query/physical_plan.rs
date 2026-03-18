//! Physical plan — execution-ready plan with chunk assignments.

use crate::database::snapshot::SnapshotManifest;
use crate::query::ast::{Expr, OrderByItem};
use crate::query::logical_plan::{AggExpr, LogicalNode, LogicalPlan, ProjectionItem};
use crate::types::{DatasetId, SnapshotId, ZkResult};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Physical node
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhysicalNode {
    /// Sequential scan of specific chunks from a committed snapshot.
    ChunkedScan {
        dataset_id: DatasetId,
        snapshot_id: SnapshotId,
        chunk_indices: Vec<u32>,
        columns: Option<Vec<String>>,
    },

    /// Filter applied per-chunk.
    Filter {
        input: Box<PhysicalNode>,
        predicate: Expr,
    },

    /// Column projection.
    Projection {
        input: Box<PhysicalNode>,
        items: Vec<ProjectionItem>,
    },

    /// Partial aggregate per-chunk, then merge.
    PartialAggregate {
        input: Box<PhysicalNode>,
        group_by: Vec<Expr>,
        aggregates: Vec<AggExpr>,
    },

    /// Merge aggregated partial results.
    MergeAggregate {
        input: Box<PhysicalNode>,
        group_by: Vec<Expr>,
        aggregates: Vec<AggExpr>,
        having: Option<Expr>,
    },

    /// Sort.
    Sort {
        input: Box<PhysicalNode>,
        keys: Vec<OrderByItem>,
    },

    /// Limit + offset.
    Limit {
        input: Box<PhysicalNode>,
        n: u64,
        offset: u64,
    },

    /// Hash join between two inputs.
    HashJoin {
        left: Box<PhysicalNode>,
        right: Box<PhysicalNode>,
        kind: crate::types::JoinKind,
        condition: Option<crate::query::ast::Expr>,
        /// The Poseidon commitment of the right table snapshot.
        right_poseidon_snap_lo: Option<u64>,
    },
}

impl PhysicalNode {
    pub fn node_name(&self) -> &'static str {
        match self {
            PhysicalNode::ChunkedScan { .. } => "ChunkedScan",
            PhysicalNode::Filter { .. } => "Filter",
            PhysicalNode::Projection { .. } => "Projection",
            PhysicalNode::PartialAggregate { .. } => "PartialAggregate",
            PhysicalNode::MergeAggregate { .. } => "MergeAggregate",
            PhysicalNode::Sort { .. } => "Sort",
            PhysicalNode::Limit { .. } => "Limit",
            PhysicalNode::HashJoin { .. } => "HashJoin",
        }
    }
}

/// Execution-ready physical plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalPlan {
    pub root: PhysicalNode,
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
    /// Total chunks involved.
    pub chunk_count: u32,
    /// Total rows to be scanned.
    pub estimated_row_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical planner: LogicalPlan + SnapshotManifest → PhysicalPlan
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhysicalPlanner;

impl PhysicalPlanner {
    pub fn plan(logical: LogicalPlan, manifest: &SnapshotManifest) -> ZkResult<PhysicalPlan> {
        let chunk_indices: Vec<u32> = manifest.chunks.iter().map(|c| c.chunk_index).collect();
        let chunk_count = chunk_indices.len() as u32;
        let estimated_row_count = manifest.row_count;

        let physical_root = Self::translate_node(
            logical.root,
            &chunk_indices,
            &logical.dataset_id,
            &logical.snapshot_id,
            manifest,
        )?;

        Ok(PhysicalPlan {
            root: physical_root,
            snapshot_id: logical.snapshot_id,
            dataset_id: logical.dataset_id,
            chunk_count,
            estimated_row_count,
        })
    }

    fn translate_node(
        node: LogicalNode,
        chunk_indices: &[u32],
        dataset_id: &DatasetId,
        snapshot_id: &SnapshotId,
        manifest: &SnapshotManifest,
    ) -> ZkResult<PhysicalNode> {
        match node {
            LogicalNode::TableScan {
                dataset_id,
                snapshot_id,
                columns,
                ..
            } => Ok(PhysicalNode::ChunkedScan {
                dataset_id,
                snapshot_id,
                chunk_indices: chunk_indices.to_vec(),
                columns,
            }),

            LogicalNode::Filter { input, predicate } => {
                let phys_input =
                    Self::translate_node(*input, chunk_indices, dataset_id, snapshot_id, manifest)?;
                Ok(PhysicalNode::Filter {
                    input: Box::new(phys_input),
                    predicate,
                })
            }

            LogicalNode::Projection { input, items } => {
                let phys_input =
                    Self::translate_node(*input, chunk_indices, dataset_id, snapshot_id, manifest)?;
                Ok(PhysicalNode::Projection {
                    input: Box::new(phys_input),
                    items,
                })
            }

            LogicalNode::Aggregate {
                input,
                group_by,
                aggregates,
                having,
            } => {
                let phys_input =
                    Self::translate_node(*input, chunk_indices, dataset_id, snapshot_id, manifest)?;
                // Two-phase aggregation: partial then merge.
                let partial = PhysicalNode::PartialAggregate {
                    input: Box::new(phys_input),
                    group_by: group_by.clone(),
                    aggregates: aggregates.clone(),
                };
                Ok(PhysicalNode::MergeAggregate {
                    input: Box::new(partial),
                    group_by,
                    aggregates,
                    having,
                })
            }

            LogicalNode::Sort { input, keys } => {
                let phys_input =
                    Self::translate_node(*input, chunk_indices, dataset_id, snapshot_id, manifest)?;
                Ok(PhysicalNode::Sort {
                    input: Box::new(phys_input),
                    keys,
                })
            }

            LogicalNode::Limit { input, n, offset } => {
                let phys_input =
                    Self::translate_node(*input, chunk_indices, dataset_id, snapshot_id, manifest)?;
                Ok(PhysicalNode::Limit {
                    input: Box::new(phys_input),
                    n,
                    offset,
                })
            }

            LogicalNode::Join {
                left,
                right,
                kind,
                condition,
            } => {
                let phys_left =
                    Self::translate_node(*left, chunk_indices, dataset_id, snapshot_id, manifest)?;
                let phys_right =
                    Self::translate_node(*right, chunk_indices, dataset_id, snapshot_id, manifest)?;
                Ok(PhysicalNode::HashJoin {
                    left: Box::new(phys_left),
                    right: Box::new(phys_right),
                    kind,
                    condition,
                    // TODO(completeness): In a multi-table query, this should be the right table's manifest commitment.
                    // For now, if we're self-joining, we use the primary manifest's poseidon_snap_lo.
                    right_poseidon_snap_lo: Some(manifest.poseidon_snap_lo),
                })
            }
        }
    }
}
