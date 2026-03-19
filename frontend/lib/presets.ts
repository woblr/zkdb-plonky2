export interface PresetQuery {
  label: string;
  sql: string;
  circuit: string;
  description: string;
  category: "aggregate" | "sort" | "groupby" | "join";
}

export const PRESET_QUERIES: PresetQuery[] = [
  {
    label: "SUM with filter",
    sql: "SELECT SUM(amount) FROM benchmark_transactions WHERE amount > 50000",
    circuit: "AggCircuit",
    description: "Proves SUM over filtered rows. Soundness: PI[2]=sum, PI[3]=count, PI[7]=n_real.",
    category: "aggregate",
  },
  {
    label: "COUNT(*) all rows",
    sql: "SELECT COUNT(*) FROM benchmark_transactions",
    circuit: "AggCircuit",
    description: "Full table count aggregation. Zero-knowledge if backend=plonky2.",
    category: "aggregate",
  },
  {
    label: "COUNT with boolean filter",
    sql: "SELECT COUNT(*) FROM benchmark_transactions WHERE flag = true",
    circuit: "AggCircuit",
    description: "Filtered count on boolean column. Predicate gated by real_flags.",
    category: "aggregate",
  },
  {
    label: "AVG(score) by category",
    sql: "SELECT AVG(score) FROM benchmark_transactions WHERE category = 'electronics'",
    circuit: "AggCircuit",
    description: "AVG derived off-circuit from proved sum/count (PI[2]/PI[3]).",
    category: "aggregate",
  },
  {
    label: "Multi-aggregate",
    sql: "SELECT COUNT(*), SUM(amount), AVG(score) FROM benchmark_transactions",
    circuit: "AggCircuit",
    description: "Multiple aggregation functions in one circuit instance.",
    category: "aggregate",
  },
  {
    label: "ORDER BY amount ASC",
    sql: "SELECT id, amount FROM benchmark_transactions ORDER BY amount",
    circuit: "SortCircuit",
    description: "Schwartz-Zippel grand-product permutation. 128-bit payload binding.",
    category: "sort",
  },
  {
    label: "ORDER BY score DESC",
    sql: "SELECT id, user_id, score FROM benchmark_transactions ORDER BY score DESC",
    circuit: "DescSortCircuit",
    description: "DescSortCircuit: non-increasing monotonicity constraint + grand-product.",
    category: "sort",
  },
  {
    label: "ORDER BY salary ASC",
    sql: "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary ASC",
    circuit: "SortCircuit",
    description: "Employee salary sort ascending. VK tag=3.",
    category: "sort",
  },
  {
    label: "ORDER BY salary DESC",
    sql: "SELECT employee_id, salary FROM benchmark_employees ORDER BY salary DESC",
    circuit: "DescSortCircuit",
    description: "Employee salary sort descending. VK tag=4.",
    category: "sort",
  },
  {
    label: "GROUP BY region SUM",
    sql: "SELECT region, SUM(amount) FROM benchmark_transactions GROUP BY region",
    circuit: "GroupByCircuit",
    description: "Group boundaries + per-group Poseidon commitment (PI[5]).",
    category: "groupby",
  },
  {
    label: "GROUP BY category COUNT",
    sql: "SELECT category, COUNT(*) FROM benchmark_transactions GROUP BY category",
    circuit: "GroupByCircuit",
    description: "GroupByCircuit with COUNT. PI[7]=Poseidon(vals) value column binding.",
    category: "groupby",
  },
  {
    label: "INNER JOIN (self-join)",
    sql: "SELECT e.employee_id, e.salary, m.salary FROM benchmark_employees e JOIN benchmark_employees m ON e.manager_id = m.employee_id",
    circuit: "JoinCircuit",
    description: "Equi-join. Both-side Poseidon binding. Positional completeness proved.",
    category: "join",
  },
];

export const CATEGORY_LABELS: Record<string, string> = {
  aggregate: "Aggregate / Filter",
  sort: "ORDER BY",
  groupby: "GROUP BY",
  join: "JOIN",
};
