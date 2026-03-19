import { api } from "./api";

// Deterministic synthetic data (approximate match to src/benchmarks/dataset.rs)

function hash(seed: number): number {
  let h = seed * 2654435761;
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
  return (h ^ (h >>> 16)) >>> 0;
}

const CATEGORIES = ["electronics", "clothing", "food", "books", "sports", "toys", "beauty", "home"];
const REGIONS = ["us-east", "us-west", "eu-central", "ap-south", "sa-east", "af-north"];
const DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "HR", "Operations", "Legal", "Design"];
const OFFICES = ["NYC", "SF", "London", "Berlin", "Tokyo", "Sydney"];

export function generateTransactions(n: number): unknown[][] {
  const rows: unknown[][] = [];
  for (let i = 0; i < n; i++) {
    const h = hash(i * 1234567 + 42);
    const h2 = hash(h + 1);
    const h3 = hash(h + 2);
    const userId = h % 10000;
    const amount = h2 % 100000;
    const category = CATEGORIES[h3 % 8];
    const region = REGIONS[hash(h + 3) % 6];
    const timestamp = 1700000000 + i * 60;
    const score = hash(h + 4) % 1000;
    const flag = hash(h + 5) % 2 === 1;
    rows.push([i, userId, amount, category, region, timestamp, score, flag]);
  }
  return rows;
}

export function generateEmployees(n: number): unknown[][] {
  const rows: unknown[][] = [];
  for (let i = 0; i < n; i++) {
    const h = hash(i * 987654 + 99);
    const h2 = hash(h + 1);
    const dept = DEPARTMENTS[h % 8];
    const office = OFFICES[h2 % 6];
    const salary = 30000 + (hash(h + 2) % 150000);
    const mgr = hash(h + 3) % n;
    const perf = hash(h + 4) % 100;
    rows.push([i, dept, office, salary, mgr, perf]);
  }
  return rows;
}

export interface DemoState {
  txnDatasetId: string;
  txnSnapshotId: string;
  empDatasetId: string;
  empSnapshotId: string;
}

export async function setupDemoDatasets(
  rowCount = 100,
  onProgress?: (msg: string) => void
): Promise<DemoState> {
  const log = (msg: string) => onProgress?.(msg);

  log("Creating transactions dataset…");
  const txnDs = await api.createDataset({
    name: "benchmark_transactions",
    description: "Synthetic transactions for zkDB demo",
    columns: [
      { name: "id", col_type: { type: "u64" } },
      { name: "user_id", col_type: { type: "u64" } },
      { name: "amount", col_type: { type: "u64" } },
      { name: "category", col_type: { type: "text" } },
      { name: "region", col_type: { type: "text" } },
      { name: "timestamp", col_type: { type: "u64" } },
      { name: "score", col_type: { type: "u64" } },
      { name: "flag", col_type: { type: "bool" } },
    ],
  });

  log(`Ingesting ${rowCount} transaction rows…`);
  await api.ingestRows(txnDs.dataset_id, generateTransactions(rowCount));

  log("Creating transactions snapshot…");
  const txnSnap = await api.createSnapshot(txnDs.dataset_id);
  await api.activateSnapshot(txnDs.dataset_id, txnSnap.snapshot_id);

  log("Creating employees dataset…");
  const empDs = await api.createDataset({
    name: "benchmark_employees",
    description: "Synthetic employee data for zkDB demo",
    columns: [
      { name: "employee_id", col_type: { type: "u64" } },
      { name: "department", col_type: { type: "text" } },
      { name: "office", col_type: { type: "text" } },
      { name: "salary", col_type: { type: "u64" } },
      { name: "manager_id", col_type: { type: "u64" } },
      { name: "performance_score", col_type: { type: "u64" } },
    ],
  });

  log(`Ingesting ${rowCount} employee rows…`);
  await api.ingestRows(empDs.dataset_id, generateEmployees(rowCount));

  log("Creating employees snapshot…");
  const empSnap = await api.createSnapshot(empDs.dataset_id);
  await api.activateSnapshot(empDs.dataset_id, empSnap.snapshot_id);

  log("Demo datasets ready.");
  return {
    txnDatasetId: txnDs.dataset_id,
    txnSnapshotId: txnSnap.snapshot_id,
    empDatasetId: empDs.dataset_id,
    empSnapshotId: empSnap.snapshot_id,
  };
}
