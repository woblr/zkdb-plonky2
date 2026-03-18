//! SQL parser: converts a SQL string into the internal AST.
//!
//! Uses `sqlparser` as the front-end and translates into our own AST types.

use crate::query::ast::*;
use crate::types::{AggKind, JoinKind, SortOrder, ZkDbError, ZkResult};
use sqlparser::ast as sql;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser as SqlParser;

pub struct QueryParser;

impl QueryParser {
    pub fn parse(sql_text: &str) -> ZkResult<SelectStatement> {
        let dialect = GenericDialect {};
        let mut stmts = SqlParser::parse_sql(&dialect, sql_text)
            .map_err(|e| ZkDbError::QueryParse(e.to_string()))?;

        if stmts.len() != 1 {
            return Err(ZkDbError::QueryParse(format!(
                "expected exactly 1 statement, got {}",
                stmts.len()
            )));
        }

        match stmts.remove(0) {
            sql::Statement::Query(q) => translate_query(*q),
            other => Err(ZkDbError::QueryParse(format!(
                "only SELECT queries are supported, got: {}",
                other
            ))),
        }
    }
}

fn translate_query(query: sql::Query) -> ZkResult<SelectStatement> {
    let limit = query.limit.as_ref().and_then(|e| {
        if let sql::Expr::Value(sql::Value::Number(n, _)) = e {
            n.parse::<u64>().ok()
        } else {
            None
        }
    });

    let offset = query.offset.as_ref().and_then(|o| {
        if let sql::Expr::Value(sql::Value::Number(n, _)) = &o.value {
            n.parse::<u64>().ok()
        } else {
            None
        }
    });

    let order_by: Vec<OrderByItem> = query
        .order_by
        .iter()
        .map(|o| {
            Ok(OrderByItem {
                expr: translate_expr(&o.expr)?,
                order: if o.asc.unwrap_or(true) {
                    SortOrder::Asc
                } else {
                    SortOrder::Desc
                },
            })
        })
        .collect::<ZkResult<_>>()?;

    match *query.body {
        sql::SetExpr::Select(select) => translate_select(*select, order_by, limit, offset),
        other => Err(ZkDbError::QueryParse(format!(
            "unsupported query body: {}",
            other
        ))),
    }
}

fn translate_select(
    select: sql::Select,
    order_by: Vec<OrderByItem>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ZkResult<SelectStatement> {
    // FROM clause
    if select.from.is_empty() {
        return Err(ZkDbError::QueryParse(
            "SELECT requires a FROM clause".into(),
        ));
    }
    let (from_table, from_alias, joins) = translate_from(&select.from)?;

    // Projections
    let projections: Vec<SelectItem> = select
        .projection
        .iter()
        .map(translate_select_item)
        .collect::<ZkResult<_>>()?;

    // WHERE
    let where_clause = select.selection.as_ref().map(translate_expr).transpose()?;

    // GROUP BY
    let group_by = match &select.group_by {
        sql::GroupByExpr::All => vec![],
        sql::GroupByExpr::Expressions(exprs) => {
            exprs.iter().map(translate_expr).collect::<ZkResult<_>>()?
        }
    };

    // HAVING
    let having = select.having.as_ref().map(translate_expr).transpose()?;

    Ok(SelectStatement {
        distinct: select.distinct.is_some(),
        projections,
        from_table,
        from_alias,
        joins,
        where_clause,
        group_by,
        having,
        order_by,
        limit,
        offset,
    })
}

fn translate_from(
    from: &[sql::TableWithJoins],
) -> ZkResult<(String, Option<String>, Vec<JoinClause>)> {
    let first = &from[0];

    let (table_name, alias) = match &first.relation {
        sql::TableFactor::Table { name, alias, .. } => {
            let n = name.0.last().map(|i| i.value.clone()).unwrap_or_default();
            let a = alias.as_ref().map(|a| a.name.value.clone());
            (n, a)
        }
        other => {
            return Err(ZkDbError::QueryParse(format!(
                "unsupported FROM: {}",
                other
            )))
        }
    };

    let joins: Vec<JoinClause> = first
        .joins
        .iter()
        .map(translate_join)
        .collect::<ZkResult<_>>()?;

    Ok((table_name, alias, joins))
}

fn translate_join(join: &sql::Join) -> ZkResult<JoinClause> {
    let (table, alias) = match &join.relation {
        sql::TableFactor::Table { name, alias, .. } => {
            let n = name.0.last().map(|i| i.value.clone()).unwrap_or_default();
            let a = alias.as_ref().map(|a| a.name.value.clone());
            (n, a)
        }
        other => {
            return Err(ZkDbError::QueryParse(format!(
                "unsupported JOIN relation: {}",
                other
            )))
        }
    };

    let (kind, condition) = match &join.join_operator {
        sql::JoinOperator::Inner(c) => (JoinKind::Inner, Some(c)),
        sql::JoinOperator::LeftOuter(c) => (JoinKind::LeftOuter, Some(c)),
        sql::JoinOperator::RightOuter(c) => (JoinKind::RightOuter, Some(c)),
        sql::JoinOperator::FullOuter(c) => (JoinKind::FullOuter, Some(c)),
        sql::JoinOperator::CrossJoin => (JoinKind::Cross, None),
        other => {
            return Err(ZkDbError::QueryParse(format!(
                "unsupported join kind: {:?}",
                other
            )))
        }
    };

    let cond_expr = if let Some(c) = condition {
        match c {
            sql::JoinConstraint::On(e) => Some(translate_expr(e)?),
            sql::JoinConstraint::Using(_) => None,
            sql::JoinConstraint::Natural | sql::JoinConstraint::None => None,
        }
    } else {
        None
    };

    Ok(JoinClause {
        table,
        alias,
        kind,
        condition: cond_expr,
    })
}

fn translate_select_item(item: &sql::SelectItem) -> ZkResult<SelectItem> {
    match item {
        sql::SelectItem::UnnamedExpr(e) => Ok(SelectItem {
            expr: translate_expr(e)?,
            alias: None,
        }),
        sql::SelectItem::ExprWithAlias { expr, alias } => Ok(SelectItem {
            expr: translate_expr(expr)?,
            alias: Some(alias.value.clone()),
        }),
        sql::SelectItem::Wildcard(_) => Ok(SelectItem {
            expr: Expr::Wildcard,
            alias: None,
        }),
        other => Err(ZkDbError::QueryParse(format!(
            "unsupported SELECT item: {}",
            other
        ))),
    }
}

fn translate_expr(expr: &sql::Expr) -> ZkResult<Expr> {
    match expr {
        sql::Expr::Identifier(id) => Ok(Expr::Column {
            table: None,
            name: id.value.clone(),
        }),

        sql::Expr::CompoundIdentifier(parts) => {
            let table = if parts.len() > 1 {
                Some(parts[parts.len() - 2].value.clone())
            } else {
                None
            };
            let name = parts.last().map(|i| i.value.clone()).unwrap_or_default();
            Ok(Expr::Column { table, name })
        }

        sql::Expr::Value(v) => translate_value(v),

        sql::Expr::BinaryOp { left, op, right } => Ok(Expr::BinOp {
            op: translate_binop(op)?,
            left: Box::new(translate_expr(left)?),
            right: Box::new(translate_expr(right)?),
        }),

        sql::Expr::UnaryOp { op, expr } => Ok(Expr::UnaryOp {
            op: match op {
                sql::UnaryOperator::Not => UnaryOp::Not,
                sql::UnaryOperator::Minus => UnaryOp::Neg,
                other => {
                    return Err(ZkDbError::QueryParse(format!(
                        "unsupported unary op: {:?}",
                        other
                    )))
                }
            },
            operand: Box::new(translate_expr(expr)?),
        }),

        sql::Expr::Function(f) => translate_function(f),

        sql::Expr::IsNull(e) => Ok(Expr::IsNull {
            expr: Box::new(translate_expr(e)?),
            negated: false,
        }),
        sql::Expr::IsNotNull(e) => Ok(Expr::IsNull {
            expr: Box::new(translate_expr(e)?),
            negated: true,
        }),

        sql::Expr::Between {
            expr,
            negated,
            low,
            high,
        } => Ok(Expr::Between {
            expr: Box::new(translate_expr(expr)?),
            low: Box::new(translate_expr(low)?),
            high: Box::new(translate_expr(high)?),
            negated: *negated,
        }),

        sql::Expr::InList {
            expr,
            list,
            negated,
        } => {
            let list = list.iter().map(translate_expr).collect::<ZkResult<_>>()?;
            Ok(Expr::InList {
                expr: Box::new(translate_expr(expr)?),
                list,
                negated: *negated,
            })
        }

        sql::Expr::Like {
            expr,
            negated,
            pattern,
            ..
        } => Ok(Expr::BinOp {
            op: if *negated {
                BinOp::NotLike
            } else {
                BinOp::Like
            },
            left: Box::new(translate_expr(expr)?),
            right: Box::new(translate_expr(pattern)?),
        }),

        sql::Expr::Nested(inner) => translate_expr(inner),

        sql::Expr::Cast { expr, .. } => translate_expr(expr),

        other => Err(ZkDbError::QueryParse(format!(
            "unsupported expression: {}",
            other
        ))),
    }
}

fn translate_value(v: &sql::Value) -> ZkResult<Expr> {
    match v {
        sql::Value::Number(n, _) => {
            if let Ok(i) = n.parse::<i64>() {
                return Ok(Expr::Literal(Literal::Int(i)));
            }
            if let Ok(f) = n.parse::<f64>() {
                return Ok(Expr::Literal(Literal::Float(f)));
            }
            Err(ZkDbError::QueryParse(format!("cannot parse number: {}", n)))
        }
        sql::Value::SingleQuotedString(s) => Ok(Expr::Literal(Literal::Text(s.clone()))),
        sql::Value::DoubleQuotedString(s) => Ok(Expr::Literal(Literal::Text(s.clone()))),
        sql::Value::Boolean(b) => Ok(Expr::Literal(Literal::Bool(*b))),
        sql::Value::Null => Ok(Expr::Literal(Literal::Null)),
        other => Err(ZkDbError::QueryParse(format!(
            "unsupported literal: {}",
            other
        ))),
    }
}

fn translate_binop(op: &sql::BinaryOperator) -> ZkResult<BinOp> {
    Ok(match op {
        sql::BinaryOperator::Eq => BinOp::Eq,
        sql::BinaryOperator::NotEq => BinOp::Ne,
        sql::BinaryOperator::Lt => BinOp::Lt,
        sql::BinaryOperator::LtEq => BinOp::Lte,
        sql::BinaryOperator::Gt => BinOp::Gt,
        sql::BinaryOperator::GtEq => BinOp::Gte,
        sql::BinaryOperator::And => BinOp::And,
        sql::BinaryOperator::Or => BinOp::Or,
        sql::BinaryOperator::Plus => BinOp::Add,
        sql::BinaryOperator::Minus => BinOp::Sub,
        sql::BinaryOperator::Multiply => BinOp::Mul,
        sql::BinaryOperator::Divide => BinOp::Div,
        other => {
            return Err(ZkDbError::QueryParse(format!(
                "unsupported binary op: {}",
                other
            )))
        }
    })
}

fn translate_function(f: &sql::Function) -> ZkResult<Expr> {
    let name = f
        .name
        .0
        .last()
        .map(|i| i.value.to_uppercase())
        .unwrap_or_default();

    let kind = match name.as_str() {
        "COUNT" => AggKind::Count,
        "SUM" => AggKind::Sum,
        "AVG" => AggKind::Avg,
        "MIN" => AggKind::Min,
        "MAX" => AggKind::Max,
        other => {
            return Err(ZkDbError::QueryParse(format!(
                "unsupported function: {}",
                other
            )))
        }
    };

    let arg_expr = if f.args.is_empty() {
        Expr::Wildcard
    } else {
        match &f.args[0] {
            sql::FunctionArg::Unnamed(sql::FunctionArgExpr::Expr(e)) => translate_expr(e)?,
            sql::FunctionArg::Unnamed(sql::FunctionArgExpr::Wildcard) => Expr::Wildcard,
            other => {
                return Err(ZkDbError::QueryParse(format!(
                    "unsupported function arg: {:?}",
                    other
                )))
            }
        }
    };
    let distinct = false;

    Ok(Expr::Agg {
        kind,
        input: Box::new(arg_expr),
        distinct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_select() {
        let stmt =
            QueryParser::parse("SELECT id, salary FROM employees WHERE salary > 50000").unwrap();
        assert_eq!(stmt.from_table, "employees");
        assert_eq!(stmt.projections.len(), 2);
        assert!(stmt.where_clause.is_some());
    }

    #[test]
    fn parse_aggregate() {
        let stmt =
            QueryParser::parse("SELECT dept, COUNT(*), AVG(salary) FROM employees GROUP BY dept")
                .unwrap();
        assert!(stmt.has_aggregates());
        assert_eq!(stmt.group_by.len(), 1);
    }

    #[test]
    fn parse_limit_offset() {
        let stmt = QueryParser::parse("SELECT id FROM t LIMIT 100 OFFSET 50").unwrap();
        assert_eq!(stmt.limit, Some(100));
        assert_eq!(stmt.offset, Some(50));
    }
}
