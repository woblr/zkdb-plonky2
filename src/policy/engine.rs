//! Policy engine: evaluates ordered rules and collects decisions.

use crate::policy::rules::{PolicyContext, PolicyDecision, PolicyRule};
use crate::types::{ZkDbError, ZkResult};
use std::sync::Arc;

/// The result of running all policy rules against a query context.
#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    /// If Some, the query is denied with this reason.
    pub denial: Option<String>,
    /// Masking and redaction directives to apply during query rewriting.
    pub rewrites: Vec<PolicyDecision>,
    /// Row-level filter conditions to inject.
    pub row_filters: Vec<String>,
}

impl PolicyEvaluation {
    pub fn is_allowed(&self) -> bool {
        self.denial.is_none()
    }

    pub fn into_result(self) -> ZkResult<PolicyEvaluation> {
        if let Some(reason) = &self.denial {
            Err(ZkDbError::PolicyDenied(reason.clone()))
        } else {
            Ok(self)
        }
    }
}

/// Evaluates an ordered chain of `PolicyRule`s against a `PolicyContext`.
///
/// Rules are evaluated in registration order.
/// The first `Deny` decision immediately halts evaluation.
/// `MaskColumn`, `RedactColumn`, and `InjectRowFilter` decisions are
/// collected for application during query rewriting.
pub struct PolicyEngine {
    rules: Vec<Arc<dyn PolicyRule>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn add_rule(&mut self, rule: Arc<dyn PolicyRule>) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn with_rule(mut self, rule: Arc<dyn PolicyRule>) -> Self {
        self.add_rule(rule);
        self
    }

    /// Evaluate all rules and return a `PolicyEvaluation`.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyEvaluation {
        let mut rewrites = Vec::new();
        let mut row_filters = Vec::new();

        for rule in &self.rules {
            if let Some(decision) = rule.evaluate(ctx) {
                match &decision {
                    PolicyDecision::Deny { reason } => {
                        return PolicyEvaluation {
                            denial: Some(reason.clone()),
                            rewrites,
                            row_filters,
                        };
                    }
                    PolicyDecision::Allow => {
                        // Allow is a no-op; continue to next rule.
                    }
                    PolicyDecision::MaskColumn { .. } | PolicyDecision::RedactColumn { .. } => {
                        rewrites.push(decision);
                    }
                    PolicyDecision::InjectRowFilter { condition } => {
                        row_filters.push(condition.clone());
                    }
                }
            }
        }

        PolicyEvaluation {
            denial: None,
            rewrites,
            row_filters,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::rules::{MaskColumnRule, MaskingStrategy, RequireAuthRule};
    use crate::types::DatasetId;

    #[test]
    fn unauthenticated_denied() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Arc::new(RequireAuthRule));

        let ctx = PolicyContext::new(DatasetId::new());
        let eval = engine.evaluate(&ctx);
        assert!(!eval.is_allowed());
    }

    #[test]
    fn authenticated_allowed() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Arc::new(RequireAuthRule));

        let ctx = PolicyContext::new(DatasetId::new()).with_user("alice", vec!["user".into()]);
        let eval = engine.evaluate(&ctx);
        assert!(eval.is_allowed());
    }

    #[test]
    fn column_masking_collected() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Arc::new(RequireAuthRule));
        engine.add_rule(Arc::new(MaskColumnRule::new(
            "salary",
            MaskingStrategy::Blur { bucket_size: 10000 },
        )));

        let ctx = PolicyContext::new(DatasetId::new())
            .with_user("alice", vec![])
            .with_query("SELECT salary FROM t", vec!["salary".into()]);

        let eval = engine.evaluate(&ctx);
        assert!(eval.is_allowed());
        assert_eq!(eval.rewrites.len(), 1);
    }
}
