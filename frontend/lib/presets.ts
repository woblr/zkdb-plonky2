export interface PresetQuery {
  label: string;
  sql: string;
  circuit: string;
  description: string;
  category: "aggregate" | "sort" | "groupby" | "join";
}

export const PRESET_QUERIES: PresetQuery[] = [
  // ── Aggregate / Filter ────────────────────────────────────────────────────
  {
    label: "SUM with numeric filter",
    sql: "SELECT SUM(amount) FROM benchmark_transactions WHERE amount > 50000",
    circuit: "AggCircuit",
    description:
      "Proves SUM over rows where amount > 50000. Same column for both filter and aggregation — required by AggCircuit.",
    category: "aggregate",
  },
  {
    label: "COUNT(*) all rows",
    sql: "SELECT COUNT(*) FROM benchmark_transactions",
    circuit: "AggCircuit",
    description:
      "Full table row count. PI[3] = proved count. Zero-knowledge via Plonky2 FRI-SNARK.",
    category: "aggregate",
  },
  {
    label: "COUNT flagged transactions",
    sql: "SELECT COUNT(*) FROM benchmark_transactions WHERE flag = true",
    circuit: "AggCircuit",
    description:
      "Boolean column filter: flag is stored as 0/1, circuit evaluates Eq predicate. PI[3] = count of flagged rows.",
    category: "aggregate",
  },
  {
    label: "AVG(score) all rows",
    sql: "SELECT AVG(score) FROM benchmark_transactions",
    circuit: "AggCircuit",
    description:
      "AVG derived off-circuit as sum÷count. PI[2] = proved SUM(score), PI[3] = proved COUNT.",
    category: "aggregate",
  },
  {
    label: "SUM salary high earners",
    sql: "SELECT SUM(salary) FROM benchmark_employees WHERE salary > 100000",
    circuit: "AggCircuit",
    description:
      "Proves total salary for employees above 100k. Filter column = aggregation column — circuit-sound.",
    category: "aggregate",
  },
  {
    label: "AVG performance score",
    sql: "SELECT AVG(performance_score) FROM benchmark_employees",
    circuit: "AggCircuit",
    description:
      "Average performance_score across all employees. PI[2]/PI[3] gives proved average.",
    category: "aggregate",
  },
  // ── ORDER BY ──────────────────────────────────────────────────────────────
  {
    label: "ORDER BY amount ASC",
    sql: "SELECT id, amount FROM benchmark_transactions ORDER BY amount",
    circuit: "SortCircuit",
    description:
      "Ascending sort. Schwartz-Zippel grand-product permutation check. 128-bit payload binding.",
    category: "sort",
  },
  {
    label: "ORDER BY score DESC",
    sql: "SELECT id, score FROM benchmark_transactions ORDER BY score DESC",
    circuit: "DescSortCircuit",
    description:
      "Descending sort on numeric score column. Non-increasing monotonicity constraint.",
    category: "sort",
  },
  {
    label: "ORDER BY salary ASC",
    sql: "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary ASC",
    circuit: "SortCircuit",
    description: "Employee salary sort ascending. Proves sorted permutation of salary column.",
    category: "sort",
  },
  {
    label: "ORDER BY salary DESC",
    sql: "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary DESC",
    circuit: "DescSortCircuit",
    description: "Employee salary sort descending. DescSortCircuit monotonicity.",
    category: "sort",
  },
  // ── GROUP BY ──────────────────────────────────────────────────────────────
  {
    label: "GROUP BY flag SUM(amount)",
    sql: "SELECT flag, SUM(amount) FROM benchmark_transactions GROUP BY flag",
    circuit: "GroupByCircuit",
    description:
      "Groups by boolean flag (0 or 1 — numeric). Produces 2 groups with proved per-group SUM(amount).",
    category: "groupby",
  },
  {
    label: "GROUP BY manager SUM(salary)",
    sql: "SELECT manager_id, SUM(salary) FROM benchmark_employees GROUP BY manager_id",
    circuit: "GroupByCircuit",
    description:
      "Groups by numeric manager_id. Employees sharing a manager are aggregated. PI[5] = per-group output commitment.",
    category: "groupby",
  },
  // ── JOIN ──────────────────────────────────────────────────────────────────
  {
    label: "INNER JOIN (self-join)",
    sql: "SELECT e.employee_id, e.salary, m.salary FROM benchmark_employees e JOIN benchmark_employees m ON e.manager_id = m.employee_id",
    circuit: "JoinCircuit",
    description:
      "Self-join: match each employee to their manager. Equi-join on numeric keys. Positional completeness proved.",
    category: "join",
  },
];

export const CATEGORY_LABELS: Record<string, string> = {
  aggregate: "Aggregate / Filter",
  sort: "ORDER BY",
  groupby: "GROUP BY",
  join: "JOIN",
};
