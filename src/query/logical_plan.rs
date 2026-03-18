//! Logical plan — backend-agnostic relational algebra tree.

use crate::query::ast::SelectStatement;
use crate::query::ast::{Expr, OrderByItem};
use crate::types::{AggKind, DatasetId, JoinKind, SnapshotId, ZkResult};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Logical plan nodes
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggExpr {
    pub kind: AggKind,
    pub input: Expr,
    pub distinct: bool,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionItem {
    pub expr: Expr,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalNode {
    /// Base table scan against a specific snapshot.
    TableScan {
        dataset_id: DatasetId,
        snapshot_id: SnapshotId,
        table_name: String,
        /// Columns to project (None = all columns).
        columns: Option<Vec<String>>,
    },

    /// Row-level filter.
    Filter {
        input: Box<LogicalNode>,
        predicate: Expr,
    },

    /// Column projection.
    Projection {
        input: Box<LogicalNode>,
        items: Vec<ProjectionItem>,
    },

    /// Aggregation.
    Aggregate {
        input: Box<LogicalNode>,
        group_by: Vec<Expr>,
        aggregates: Vec<AggExpr>,
        having: Option<Expr>,
    },

    /// Sort.
    Sort {
        input: Box<LogicalNode>,
        keys: Vec<OrderByItem>,
    },

    /// Row count limit.
    Limit {
        input: Box<LogicalNode>,
        n: u64,
        offset: u64,
    },

    /// Join (two-table).
    Join {
        left: Box<LogicalNode>,
        right: Box<LogicalNode>,
        kind: JoinKind,
        condition: Option<Expr>,
    },
}

impl LogicalNode {
    pub fn node_name(&self) -> &'static str {
        match self {
            LogicalNode::TableScan { .. } => "TableScan",
            LogicalNode::Filter { .. } => "Filter",
            LogicalNode::Projection { .. } => "Projection",
            LogicalNode::Aggregate { .. } => "Aggregate",
            LogicalNode::Sort { .. } => "Sort",
            LogicalNode::Limit { .. } => "Limit",
            LogicalNode::Join { .. } => "Join",
        }
    }
}

/// A fully resolved logical plan rooted at a `LogicalNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalPlan {
    pub root: LogicalNode,
    pub snapshot_id: SnapshotId,
    pub dataset_id: DatasetId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Logical planner: AST → LogicalPlan
// ─────────────────────────────────────────────────────────────────────────────

pub struct LogicalPlanner {
    pub dataset_id: DatasetId,
    pub snapshot_id: SnapshotId,
}

impl LogicalPlanner {
    pub fn new(dataset_id: DatasetId, snapshot_id: SnapshotId) -> Self {
        Self {
            dataset_id,
            snapshot_id,
        }
    }

    pub fn plan(&self, stmt: SelectStatement) -> ZkResult<LogicalPlan> {
        let mut node = LogicalNode::TableScan {
            dataset_id: self.dataset_id.clone(),
            snapshot_id: self.snapshot_id.clone(),
            table_name: stmt.from_table.clone(),
            columns: None, // will be pushed down by optimizer later
        };

        // Handle joins — build a left-deep join tree
        for join_clause in &stmt.joins {
            let right_scan = LogicalNode::TableScan {
                dataset_id: self.dataset_id.clone(),
                snapshot_id: self.snapshot_id.clone(),
                table_name: join_clause.table.clone(),
                columns: None,
            };
            node = LogicalNode::Join {
                left: Box::new(node),
                right: Box::new(right_scan),
                kind: join_clause.kind.clone(),
                condition: join_clause.condition.clone(),
            };
        }

        // Compute has_aggregates before any partial moves of stmt
        let has_agg = stmt.has_aggregates();

        // WHERE → Filter
        if let Some(pred) = stmt.where_clause {
            node = LogicalNode::Filter {
                input: Box::new(node),
                predicate: pred,
            };
        }

        // GROUP BY / aggregates
        if has_agg || !stmt.group_by.is_empty() {
            let mut aggregates = vec![];
            for item in &stmt.projections {
                collect_agg_exprs(&item.expr, item.alias.clone(), &mut aggregates);
            }
            if let Some(h) = &stmt.having {
                collect_agg_exprs(h, None, &mut aggregates);
            }

            node = LogicalNode::Aggregate {
                input: Box::new(node),
                group_by: stmt.group_by.clone(),
                aggregates,
                having: stmt.having.clone(),
            };
        }

        // Projection
        let items: Vec<ProjectionItem> = stmt
            .projections
            .iter()
            .map(|p| ProjectionItem {
                expr: p.expr.clone(),
                alias: p.alias.clone(),
            })
            .collect();
        node = LogicalNode::Projection {
            input: Box::new(node),
            items,
        };

        // ORDER BY
        if !stmt.order_by.is_empty() {
            node = LogicalNode::Sort {
                input: Box::new(node),
                keys: stmt.order_by,
            };
        }

        // LIMIT
        if let Some(n) = stmt.limit {
            node = LogicalNode::Limit {
                input: Box::new(node),
                n,
                offset: stmt.offset.unwrap_or(0),
            };
        }

        Ok(LogicalPlan {
            root: node,
            snapshot_id: self.snapshot_id.clone(),
            dataset_id: self.dataset_id.clone(),
        })
    }
}

fn collect_agg_exprs(expr: &Expr, alias: Option<String>, out: &mut Vec<AggExpr>) {
    match expr {
        Expr::Agg {
            kind,
            input,
            distinct,
        } => {
            out.push(AggExpr {
                kind: kind.clone(),
                input: *input.clone(),
                distinct: *distinct,
                alias,
            });
        }
        Expr::BinOp { left, right, .. } => {
            collect_agg_exprs(left, None, out);
            collect_agg_exprs(right, None, out);
        }
        _ => {}
    }
}
