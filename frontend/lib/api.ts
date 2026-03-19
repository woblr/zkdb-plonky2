// Use relative paths so Next.js rewrites proxy /v1/* and /health to the Rust backend.
// The backend runs on port 3001; next.config.ts rewrites forward the requests.
const BASE = "";

export interface Column {
  name: string;
  col_type: { type: string };
  nullable?: boolean;
  description?: string;
}

export interface Dataset {
  dataset_id: string;
  name: string;
  description?: string;
  column_count: number;
  created_at_ms: number;
}

export interface Snapshot {
  snapshot_id: string;
  dataset_id: string;
  status: string;
  snapshot_root?: string;
  row_count?: number;
  chunk_count?: number;
  created_at_ms: number;
  activated_at_ms?: number;
}

export interface PublicInputs {
  snapshot_root_lo: number;
  query_hash_lo: number;
  result_sum: number;
  result_row_count: number;
  result_commit_lo: number;
  agg_snap_lo: number;
  agg_n_real: number;
  sort_secondary_snap_lo: number;
  sort_out_snap_lo: number;
  sort_secondary_hi_snap_lo: number;
  join_right_snap_lo: number;
  group_output_lo: number;
  group_snap_lo: number;
  group_vals_snap_lo: number;
}

export interface AllPublicInputs {
  snap_lo_hex: string;
  query_hash_hex: string;
  result_sum: number;
  result_row_count: number;
  result_commit_or_join_right_hex: string;
  group_output_or_sort_snap_hex: string;
  sort_secondary_hi_snap_lo_hex: string;
  group_vals_or_n_real: number;
  agg_n_real: number;
  pred_op: number;
  pred_val: number;
  sort_secondary_snap_lo_hex: string;
  sort_secondary_hi_snap_lo_hex_2: string;
  join_right_snap_lo_hex: string;
  join_unmatched_count: number;
  group_output_lo_hex: string;
  group_vals_snap_lo_hex: string;
}

export interface Proof {
  proof_id: string;
  query_id: string;
  snapshot_id: string;
  backend: string;
  proof_system_kind: string;
  proof_hex: string;
  snapshot_root_hex: string;
  query_hash_hex: string;
  unsafe_metadata_commitment_hex: string;
  result_commit_poseidon_proved_hex: string;
  result_sum: number;
  result_row_count: number;
  public_inputs: AllPublicInputs;
  created_at_ms: number;
}

export interface VerificationResponse {
  is_valid: boolean;
  verification_kind: string;
  proof_system_kind: string;
  has_zero_knowledge: boolean;
  is_succinct: boolean;
  snapshot_root_hex: string;
  query_hash_hex: string;
  unsafe_metadata_commitment_hex: string;
  result_commit_poseidon_proved_hex: string;
  backend: string;
  completeness_proved: boolean;
  external_anchor_status: string;
  warnings: string[];
  error?: string;
}

export interface QueryResult {
  query_id: string;
  snapshot_id: string;
  status: string;
  result?: string;
  proof_id?: string;
  capabilities?: {
    proof_system_kind?: string;
    has_zero_knowledge?: boolean;
    is_succinct?: boolean;
    completeness_proved?: boolean;
    join_completeness_proved?: boolean;
  };
  error?: string;
}

export interface SystemInfo {
  service: string;
  version: string;
  default_backend: string;
  available_backends: Array<{
    name: string;
    has_zero_knowledge: boolean;
    is_succinct: boolean;
    description: string;
  }>;
  max_rows_per_circuit: number;
  field: string;
  hash: string;
}

// ─── API helpers ─────────────────────────────────────────────────────────────

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status} ${body}`);
  }
  return res.json();
}

export const api = {
  health: () => req<{ status: string }>("/health"),
  systemInfo: () => req<SystemInfo>("/v1/system/info"),

  // Datasets
  listDatasets: () => req<Dataset[]>("/v1/datasets"),
  createDataset: (body: { name: string; description?: string; columns: Column[] }) =>
    req<Dataset>("/v1/datasets", { method: "POST", body: JSON.stringify(body) }),
  getDataset: (id: string) => req<Dataset>(`/v1/datasets/${id}`),
  ingestRows: (id: string, rows: unknown[][]) =>
    req<{ ingested: number }>(`/v1/datasets/${id}/ingest`, {
      method: "POST",
      body: JSON.stringify({ rows }),
    }),

  // Snapshots
  createSnapshot: (datasetId: string) =>
    req<Snapshot>(`/v1/datasets/${datasetId}/snapshots`, { method: "POST", body: "{}" }),
  listSnapshots: (datasetId: string) =>
    req<Snapshot[]>(`/v1/datasets/${datasetId}/snapshots`),
  activateSnapshot: (datasetId: string, snapshotId: string) =>
    req<Snapshot>(
      `/v1/datasets/${datasetId}/snapshots/${snapshotId}/activate`,
      { method: "POST", body: "{}" }
    ),

  // Queries
  submitQuery: (body: { dataset_id: string; sql: string; backend: string; snapshot_id?: string }) =>
    req<{ query_id: string; snapshot_id: string; status: string; submitted_at_ms: number }>(
      "/v1/queries",
      { method: "POST", body: JSON.stringify(body) }
    ),
  getQueryResult: (queryId: string) => req<QueryResult>(`/v1/queries/${queryId}`),

  // Proofs
  getProof: (proofId: string) => req<Proof>(`/v1/proofs/${proofId}`),
  verifyProof: (body: {
    proof_id: string;
    expected_snapshot_root: string;
    expected_query_hash: string;
  }) =>
    req<VerificationResponse>("/v1/proofs/verify", {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
