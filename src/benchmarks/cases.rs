//! Pre-defined benchmark scenarios covering the main query operator types.
//!
//! Each case is a `BenchmarkScenario` ready to be fed into `BenchmarkRunner::run`.

use crate::benchmarks::types::{
    BackendKind, BenchmarkScenario, ComplexityClass, OperatorFamily, QueryBenchmarkCase,
    QueryFamily,
};

/// Standard benchmark suite: a set of scenarios exercising different query patterns.
pub fn standard_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let chunk_size = default_chunk_size(row_count);

    vec![
        BenchmarkScenario::new(
            "filter_projection",
            "SELECT id, amount, region FROM benchmark_transactions WHERE amount > 50000",
            row_count,
        )
        .with_description("Filter rows by amount threshold + project 3 columns")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "projection".into()])
        .with_classification(QueryFamily::Filter, OperatorFamily::FilterProject, ComplexityClass::Linear),

        BenchmarkScenario::new(
            "filter_sum",
            "SELECT SUM(amount) FROM benchmark_transactions WHERE region = 'us-east'",
            row_count,
        )
        .with_description("Filter by region + aggregate SUM")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "aggregate".into(), "sum".into()])
        .with_classification(QueryFamily::Aggregate, OperatorFamily::FilterAggregate, ComplexityClass::Moderate),

        BenchmarkScenario::new(
            "count_all",
            "SELECT COUNT(*) FROM benchmark_transactions",
            row_count,
        )
        .with_description("Full table COUNT aggregation")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["aggregate".into(), "count".into()])
        .with_classification(QueryFamily::Aggregate, OperatorFamily::Aggregate, ComplexityClass::Linear),

        BenchmarkScenario::new(
            "filter_count",
            "SELECT COUNT(*) FROM benchmark_transactions WHERE flag = true",
            row_count,
        )
        .with_description("Filtered COUNT on boolean column")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "aggregate".into(), "count".into()])
        .with_classification(QueryFamily::Filter, OperatorFamily::FilterAggregate, ComplexityClass::Linear),

        BenchmarkScenario::new(
            "range_filter",
            "SELECT id, user_id, score FROM benchmark_transactions WHERE score > 500 AND amount < 30000",
            row_count,
        )
        .with_description("Compound range filter on two numeric columns")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "range".into()])
        .with_classification(QueryFamily::Filter, OperatorFamily::FilterProject, ComplexityClass::Linear),

        BenchmarkScenario::new(
            "avg_aggregation",
            "SELECT AVG(score) FROM benchmark_transactions WHERE category = 'electronics'",
            row_count,
        )
        .with_description("Filtered AVG on score column")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "aggregate".into(), "avg".into()])
        .with_classification(QueryFamily::Aggregate, OperatorFamily::FilterAggregate, ComplexityClass::Moderate),

        BenchmarkScenario::new(
            "multi_aggregate",
            "SELECT COUNT(*), SUM(amount), AVG(score) FROM benchmark_transactions",
            row_count,
        )
        .with_description("Multiple aggregation functions in one query")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["aggregate".into(), "multi".into()])
        .with_classification(QueryFamily::Aggregate, OperatorFamily::Aggregate, ComplexityClass::Moderate),

    ]
}

/// Extended suite with heavier scenarios for comparative analysis.
pub fn extended_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let mut scenarios = standard_suite(row_count, backend.clone());
    let chunk_size = default_chunk_size(row_count);

    scenarios.extend(vec![
        BenchmarkScenario::new(
            "group_by_region_sum",
            "SELECT region, SUM(amount) FROM benchmark_transactions GROUP BY region",
            row_count,
        )
        .with_description("Group by region with SUM aggregation")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "aggregate".into()])
        .with_classification(QueryFamily::GroupBy, OperatorFamily::GroupByAggregate, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "sort_by_amount",
            "SELECT id, amount FROM benchmark_transactions ORDER BY amount",
            row_count,
        )
        .with_description("Sort by amount column")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["sort".into()])
        .with_classification(QueryFamily::Sort, OperatorFamily::Sort, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "group_by_category_count",
            "SELECT category, COUNT(*) FROM benchmark_transactions GROUP BY category",
            row_count,
        )
        .with_description("Group by category with COUNT")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "count".into()])
        .with_classification(QueryFamily::GroupBy, OperatorFamily::GroupByAggregate, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "compound_filter_aggregate",
            "SELECT COUNT(*), SUM(amount), AVG(score) FROM benchmark_transactions WHERE region = 'us-east' AND amount > 10000",
            row_count,
        )
        .with_description("Compound filter with multiple aggregations")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["filter".into(), "aggregate".into(), "compound".into()])
        .with_classification(QueryFamily::Mixed, OperatorFamily::FilterAggregate, ComplexityClass::Moderate),
    ]);

    scenarios
}

/// Query benchmark case descriptors (lightweight, for programmatic use).
pub fn standard_query_cases() -> Vec<QueryBenchmarkCase> {
    vec![
        QueryBenchmarkCase::new(
            "filter_projection",
            "SELECT id, amount, region FROM benchmark_transactions WHERE amount > 50000",
        ).with_operator("filter+project"),

        QueryBenchmarkCase::new(
            "filter_sum",
            "SELECT SUM(amount) FROM benchmark_transactions WHERE region = 'us-east'",
        ).with_operator("filter+aggregate"),

        QueryBenchmarkCase::new(
            "count_all",
            "SELECT COUNT(*) FROM benchmark_transactions",
        ).with_operator("aggregate"),

        QueryBenchmarkCase::new(
            "range_filter",
            "SELECT id, user_id, score FROM benchmark_transactions WHERE score > 500 AND amount < 30000",
        ).with_operator("filter+project"),
    ]
}

/// Reasonable default chunk size based on row count.
fn default_chunk_size(row_count: usize) -> u32 {
    if row_count <= 256 {
        64
    } else if row_count <= 4096 {
        256
    } else if row_count <= 65536 {
        1024
    } else {
        4096
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator-focused benchmark suites targeting real operators
// ─────────────────────────────────────────────────────────────────────────────

/// Suite specifically targeting GROUP BY workloads on the employees dataset.
///
/// These scenarios exercise: sort-then-boundary, running-sum accumulators,
/// and multi-column group keys.
pub fn group_by_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let chunk_size = default_chunk_size(row_count);

    vec![
        BenchmarkScenario::new(
            "emp_group_by_department_count",
            "SELECT department, COUNT(*) FROM benchmark_employees GROUP BY department",
            row_count,
        )
        .with_description("GROUP BY department, COUNT — 8 groups, employees dataset")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "count".into(), "employees".into()])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
        BenchmarkScenario::new(
            "emp_group_by_department_sum_salary",
            "SELECT department, SUM(salary) FROM benchmark_employees GROUP BY department",
            row_count,
        )
        .with_description("GROUP BY department, SUM(salary) — running-sum per group")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "sum".into(), "employees".into()])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
        BenchmarkScenario::new(
            "emp_group_by_department_avg_salary",
            "SELECT department, AVG(salary) FROM benchmark_employees GROUP BY department",
            row_count,
        )
        .with_description("GROUP BY department, AVG(salary) — requires sum + count per group")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "avg".into(), "employees".into()])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
        BenchmarkScenario::new(
            "emp_group_by_office_count",
            "SELECT office, COUNT(*) FROM benchmark_employees GROUP BY office",
            row_count,
        )
        .with_description("GROUP BY office, COUNT — 6 groups, employees dataset")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "count".into(), "employees".into()])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
        BenchmarkScenario::new(
            "txn_group_by_region_sum",
            "SELECT region, SUM(amount) FROM benchmark_transactions GROUP BY region",
            row_count,
        )
        .with_description("GROUP BY region, SUM(amount) — 6 groups, transactions dataset")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["group_by".into(), "sum".into(), "transactions".into()])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
        BenchmarkScenario::new(
            "txn_group_by_category_count",
            "SELECT category, COUNT(*) FROM benchmark_transactions GROUP BY category",
            row_count,
        )
        .with_description("GROUP BY category, COUNT — 8 groups, transactions dataset")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec![
            "group_by".into(),
            "count".into(),
            "transactions".into(),
        ])
        .with_classification(
            QueryFamily::GroupBy,
            OperatorFamily::GroupByAggregate,
            ComplexityClass::Heavy,
        ),
    ]
}

/// Suite specifically targeting SORT workloads.
///
/// These scenarios exercise: sort permutation, verify_sorted checks,
/// top-k truncation, and multi-key sort.
pub fn sort_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let chunk_size = default_chunk_size(row_count);

    vec![
        BenchmarkScenario::new(
            "emp_sort_salary_asc",
            "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary ASC",
            row_count,
        )
        .with_description("Sort employees by salary ascending — full permutation circuit")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["sort".into(), "asc".into(), "employees".into()])
        .with_classification(QueryFamily::Sort, OperatorFamily::Sort, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "emp_sort_salary_desc",
            "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary DESC",
            row_count,
        )
        .with_description("Sort employees by salary descending")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["sort".into(), "desc".into(), "employees".into()])
        .with_classification(QueryFamily::Sort, OperatorFamily::Sort, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "txn_sort_amount_asc",
            "SELECT id, amount FROM benchmark_transactions ORDER BY amount ASC",
            row_count,
        )
        .with_description("Sort transactions by amount ascending")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["sort".into(), "asc".into(), "transactions".into()])
        .with_classification(QueryFamily::Sort, OperatorFamily::Sort, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "txn_sort_score_desc",
            "SELECT id, user_id, score FROM benchmark_transactions ORDER BY score DESC",
            row_count,
        )
        .with_description("Sort transactions by score descending")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["sort".into(), "desc".into(), "transactions".into()])
        .with_classification(QueryFamily::Sort, OperatorFamily::Sort, ComplexityClass::Heavy),
    ]
}

/// Suite specifically targeting JOIN workloads.
///
/// These scenarios exercise the equi-join baseline (hash join) and
/// join key equality constraint validation.
pub fn join_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let chunk_size = default_chunk_size(row_count);

    vec![
        BenchmarkScenario::new(
            "emp_self_join_manager",
            "SELECT e.employee_id, e.salary, m.salary FROM benchmark_employees e JOIN benchmark_employees m ON e.manager_id = m.employee_id",
            row_count,
        )
        .with_description("Self-join on manager_id = employee_id — equi-join baseline")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["join".into(), "equi_join".into(), "self_join".into(), "employees".into()])
        .with_classification(QueryFamily::Join, OperatorFamily::Join, ComplexityClass::Heavy),

        BenchmarkScenario::new(
            "txn_join_region_filter",
            "SELECT t.id, t.amount, t.region FROM benchmark_transactions t JOIN benchmark_transactions t2 ON t.user_id = t2.user_id WHERE t.amount > 50000",
            row_count,
        )
        .with_description("Transaction equi-join on user_id with amount filter")
        .with_chunk_size(chunk_size)
        .with_backend(backend.clone())
        .with_tags(vec!["join".into(), "filter".into(), "transactions".into()])
        .with_classification(QueryFamily::Join, OperatorFamily::Join, ComplexityClass::Heavy),
    ]
}

/// Full operator suite: standard + group_by + sort + join scenarios.
pub fn full_operator_suite(row_count: usize, backend: BackendKind) -> Vec<BenchmarkScenario> {
    let mut all = standard_suite(row_count, backend.clone());
    all.extend(group_by_suite(row_count, backend.clone()));
    all.extend(sort_suite(row_count, backend.clone()));
    all.extend(join_suite(row_count, backend.clone()));
    all
}
