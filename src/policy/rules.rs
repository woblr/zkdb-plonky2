//! Policy rule types and decision types.

use crate::types::{DatasetId, SnapshotId};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Policy decision
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum PolicyDecision {
    /// Query is allowed with no modifications.
    Allow,

    /// Query is denied. Reason is logged but not sent to the client in detail.
    Deny { reason: String },

    /// Column should be masked using the specified strategy.
    MaskColumn {
        column: String,
        strategy: MaskingStrategy,
    },

    /// Column value should be replaced with NULL.
    RedactColumn { column: String },

    /// Inject an invisible row-level filter (e.g., tenant isolation).
    InjectRowFilter { condition: String },
}

impl PolicyDecision {
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    /// Replace with NULL.
    Nullify,
    /// Return Blake3(value) as hex.
    Hash,
    /// Return a static constant (e.g., "REDACTED").
    StaticValue(String),
    /// Round numeric to nearest bucket_size.
    Blur { bucket_size: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy context passed to rules
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub user_id: Option<String>,
    pub user_roles: Vec<String>,
    pub dataset_id: DatasetId,
    pub snapshot_id: Option<SnapshotId>,
    /// The SQL query string (before parsing).
    pub query_text: Option<String>,
    /// Columns referenced in the query.
    pub referenced_columns: Vec<String>,
    /// Whether the query is an aggregate-only query.
    pub is_aggregate: bool,
    /// Approximate number of rows the query will touch.
    pub estimated_row_count: Option<u64>,
}

impl PolicyContext {
    pub fn new(dataset_id: DatasetId) -> Self {
        Self {
            user_id: None,
            user_roles: vec![],
            dataset_id,
            snapshot_id: None,
            query_text: None,
            referenced_columns: vec![],
            is_aggregate: false,
            estimated_row_count: None,
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>, roles: Vec<String>) -> Self {
        self.user_id = Some(user_id.into());
        self.user_roles = roles;
        self
    }

    pub fn with_query(mut self, sql: impl Into<String>, columns: Vec<String>) -> Self {
        self.query_text = Some(sql.into());
        self.referenced_columns = columns;
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.user_roles.iter().any(|r| r == role)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy rule trait
// ─────────────────────────────────────────────────────────────────────────────

/// A single policy rule.
///
/// Rules are evaluated in order. The first `Deny` immediately halts evaluation
/// and rejects the query. `Allow` continues to the next rule. Masking/redaction
/// rules are collected and applied during query rewriting.
pub trait PolicyRule: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in rules
// ─────────────────────────────────────────────────────────────────────────────

/// Deny any unauthenticated request.
#[derive(Debug)]
pub struct RequireAuthRule;

impl PolicyRule for RequireAuthRule {
    fn name(&self) -> &str {
        "require_auth"
    }

    fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        if ctx.user_id.is_none() {
            Some(PolicyDecision::deny("unauthenticated request"))
        } else {
            None
        }
    }
}

/// Block queries that do not touch at least one aggregate (anti-row-dump rule).
#[derive(Debug)]
pub struct RequireAggregateRule;

impl PolicyRule for RequireAggregateRule {
    fn name(&self) -> &str {
        "require_aggregate"
    }

    fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        if !ctx.is_aggregate {
            Some(PolicyDecision::deny(
                "non-aggregate queries are not permitted on this dataset",
            ))
        } else {
            None
        }
    }
}

/// Mask a specific column for all non-admin users.
#[derive(Debug)]
pub struct MaskColumnRule {
    pub column: String,
    pub strategy: MaskingStrategy,
    pub exempt_role: Option<String>,
}

impl MaskColumnRule {
    pub fn new(column: impl Into<String>, strategy: MaskingStrategy) -> Self {
        Self {
            column: column.into(),
            strategy,
            exempt_role: None,
        }
    }

    pub fn exempt_for_role(mut self, role: impl Into<String>) -> Self {
        self.exempt_role = Some(role.into());
        self
    }
}

impl PolicyRule for MaskColumnRule {
    fn name(&self) -> &str {
        "mask_column"
    }

    fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        let is_referenced = ctx
            .referenced_columns
            .iter()
            .any(|c| c.to_lowercase() == self.column.to_lowercase());

        if !is_referenced {
            return None;
        }

        if let Some(ref role) = self.exempt_role {
            if ctx.has_role(role) {
                return None;
            }
        }

        Some(PolicyDecision::MaskColumn {
            column: self.column.clone(),
            strategy: self.strategy.clone(),
        })
    }
}

/// Deny queries that scan more than `max_rows` rows (anti-exfiltration).
#[derive(Debug)]
pub struct MaxRowsRule {
    pub max_rows: u64,
}

impl PolicyRule for MaxRowsRule {
    fn name(&self) -> &str {
        "max_rows"
    }

    fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        if let Some(est) = ctx.estimated_row_count {
            if est > self.max_rows {
                return Some(PolicyDecision::deny(format!(
                    "query would scan ~{} rows, limit is {}",
                    est, self.max_rows
                )));
            }
        }
        None
    }
}
