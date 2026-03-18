//! Query AST types — output of the SQL parser.

use crate::types::{AggKind, JoinKind, SortOrder};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Expressions
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Expr {
    /// A column reference, e.g. `salary` or `t.salary`.
    Column { table: Option<String>, name: String },

    /// A literal value.
    Literal(Literal),

    /// Binary operation.
    BinOp {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },

    /// Unary operation.
    UnaryOp { op: UnaryOp, operand: Box<Expr> },

    /// Aggregate function.
    Agg {
        kind: AggKind,
        input: Box<Expr>,
        distinct: bool,
    },

    /// CASE WHEN … THEN … ELSE … END
    Case {
        conditions: Vec<(Expr, Expr)>,
        else_result: Option<Box<Expr>>,
    },

    /// IS NULL / IS NOT NULL
    IsNull { expr: Box<Expr>, negated: bool },

    /// Column BETWEEN low AND high
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },

    /// IN list
    InList {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },

    /// Wildcard SELECT *
    Wildcard,
}

impl Expr {
    pub fn column(name: impl Into<String>) -> Self {
        Expr::Column {
            table: None,
            name: name.into(),
        }
    }

    pub fn int(n: i64) -> Self {
        Expr::Literal(Literal::Int(n))
    }

    pub fn float(f: f64) -> Self {
        Expr::Literal(Literal::Float(f))
    }

    pub fn text(s: impl Into<String>) -> Self {
        Expr::Literal(Literal::Text(s.into()))
    }

    pub fn bool_val(b: bool) -> Self {
        Expr::Literal(Literal::Bool(b))
    }

    /// Collect all column names referenced in this expression.
    pub fn referenced_columns(&self) -> Vec<String> {
        match self {
            Expr::Column { name, .. } => vec![name.clone()],
            Expr::BinOp { left, right, .. } => {
                let mut cols = left.referenced_columns();
                cols.extend(right.referenced_columns());
                cols
            }
            Expr::UnaryOp { operand, .. } => operand.referenced_columns(),
            Expr::Agg { input, .. } => input.referenced_columns(),
            Expr::Case {
                conditions,
                else_result,
            } => {
                let mut cols = vec![];
                for (cond, then) in conditions {
                    cols.extend(cond.referenced_columns());
                    cols.extend(then.referenced_columns());
                }
                if let Some(e) = else_result {
                    cols.extend(e.referenced_columns());
                }
                cols
            }
            Expr::IsNull { expr, .. } => expr.referenced_columns(),
            Expr::Between {
                expr, low, high, ..
            } => {
                let mut cols = expr.referenced_columns();
                cols.extend(low.referenced_columns());
                cols.extend(high.referenced_columns());
                cols
            }
            Expr::InList { expr, list, .. } => {
                let mut cols = expr.referenced_columns();
                for e in list {
                    cols.extend(e.referenced_columns());
                }
                cols
            }
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Literal {
    Int(i64),
    UInt(u64),
    Float(f64),
    Text(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BinOp {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Add,
    Sub,
    Mul,
    Div,
    Like,
    NotLike,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

// ─────────────────────────────────────────────────────────────────────────────
// SELECT components
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectItem {
    pub expr: Expr,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderByItem {
    pub expr: Expr,
    pub order: SortOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinClause {
    pub table: String,
    pub alias: Option<String>,
    pub kind: JoinKind,
    pub condition: Option<Expr>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Full SELECT statement AST
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectStatement {
    pub distinct: bool,
    pub projections: Vec<SelectItem>,
    pub from_table: String,
    pub from_alias: Option<String>,
    pub joins: Vec<JoinClause>,
    pub where_clause: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
    pub order_by: Vec<OrderByItem>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

impl SelectStatement {
    /// Return all column names referenced across the entire statement.
    pub fn all_referenced_columns(&self) -> Vec<String> {
        let mut cols = vec![];
        for item in &self.projections {
            cols.extend(item.expr.referenced_columns());
        }
        if let Some(w) = &self.where_clause {
            cols.extend(w.referenced_columns());
        }
        for g in &self.group_by {
            cols.extend(g.referenced_columns());
        }
        if let Some(h) = &self.having {
            cols.extend(h.referenced_columns());
        }
        for o in &self.order_by {
            cols.extend(o.expr.referenced_columns());
        }
        cols.sort();
        cols.dedup();
        cols
    }

    pub fn has_aggregates(&self) -> bool {
        self.projections.iter().any(|p| is_aggregate(&p.expr)) || !self.group_by.is_empty()
    }
}

fn is_aggregate(expr: &Expr) -> bool {
    match expr {
        Expr::Agg { .. } => true,
        Expr::BinOp { left, right, .. } => is_aggregate(left) || is_aggregate(right),
        _ => false,
    }
}
