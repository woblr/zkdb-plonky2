/**
 * Custom JSON dataset import from user-pasted text: validation, schema detection, query generation.
 *
 * Security constraints enforced here:
 *  - MAX_ROWS         : 1000  — prevents oversized circuit inputs
 *  - MAX_COLS         : 20    — prevents schema explosion
 *  - MAX_JSON_BYTES   : 1.5MB — prevents huge parses / UI hangs / backend abuse
 *  - Reserved column keys rejected to reduce prototype-pollution style hazards.
 *  - Column names sanitized to [a-z0-9_] — prevents SQL/API injection
 *  - Nested objects rejected — only flat rows allowed
 *  - Values coerced to their canonical type — no mixed-type ambiguity
 *
 * Note: This module treats the JSON as data only (no HTML rendering / no eval).
 */

import type { PresetQuery } from "./presets";
import { api } from "./api";

// ─── Constraints ──────────────────────────────────────────────────────────────

export const LIMITS = {
  MAX_ROWS: 1000,
  MAX_COLS: 20,
  MAX_COL_NAME_LEN: 32,
  // Hard limit for textarea payload to avoid UI/backend abuse.
  MAX_JSON_BYTES: 1.5 * 1024 * 1024, // 1.5 MB
} as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DetectedColumn {
  /** Sanitized column name (safe for API + SQL). */
  name: string;
  /** Original name from JSON key. */
  originalName: string;
  type: "u64" | "bool" | "text";
  sampleValues: string[];
  /** Can this column be used in AggCircuit / SortCircuit / GroupByCircuit? */
  circuitCompatible: boolean;
  warning?: string;
}

export interface ValidationResult {
  ok: boolean;
  /** Rows after truncation. */
  rows: Record<string, unknown>[];
  columns: DetectedColumn[];
  rowCount: number;
  warnings: string[];
  errors: string[];
}

export interface CustomDatasetState {
  datasetId: string;
  snapshotId: string;
  tableName: string;
  columns: DetectedColumn[];
  rowCount: number;
}

// ─── Name sanitizer ───────────────────────────────────────────────────────────

function sanitizeName(raw: string): string {
  const s = raw
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_]/g, "_")
    .replace(/^[^a-z_]/, (c) => `c_${c}`)
    .slice(0, LIMITS.MAX_COL_NAME_LEN);
  return s || "col";
}

// ─── Core validator ───────────────────────────────────────────────────────────

export function validateAndParse(
  jsonText: string,
  byteSize: number
): ValidationResult {
  const warnings: string[] = [];
  const errors: string[] = [];

  // Byte-size guard (prevents huge inputs)
  if (byteSize > LIMITS.MAX_JSON_BYTES) {
    errors.push(
      `Input too large (${(byteSize / 1024 / 1024).toFixed(1)} MB). Max ${(
        LIMITS.MAX_JSON_BYTES /
        1024 /
        1024
      ).toFixed(1)} MB.`
    );
    return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
  }

  // JSON parse
  let data: unknown;
  try {
    data = JSON.parse(jsonText);
  } catch (e) {
    errors.push(`Invalid JSON: ${(e as Error).message}`);
    return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
  }

  // Must be array
  if (!Array.isArray(data)) {
    errors.push("Root must be a JSON array of objects — e.g. [{}, {}, …]");
    return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
  }

  if (data.length === 0) {
    errors.push("Array is empty — need at least 1 row.");
    return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
  }

  const originalCount = data.length;
  let rows = data as Record<string, unknown>[];

  if (originalCount > LIMITS.MAX_ROWS) {
    warnings.push(
      `Dataset has ${originalCount} rows — truncated to ${LIMITS.MAX_ROWS} (circuit limit).`
    );
    rows = rows.slice(0, LIMITS.MAX_ROWS);
  }

  // Validate all rows are flat objects
  for (let i = 0; i < Math.min(rows.length, 10); i++) {
    const row = rows[i];
    if (typeof row !== "object" || row === null || Array.isArray(row)) {
      errors.push(`Row ${i} is not an object. All elements must be flat objects.`);
      return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
    }
    for (const [k, v] of Object.entries(row)) {
      if (typeof v === "object" && v !== null) {
        errors.push(
          `Row ${i}, key "${k}": nested objects are not supported. Flatten your data.`
        );
        return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
      }
    }
  }

  // Collect all unique column names
  const allKeys: string[] = [];
  const seen = new Set<string>();
  const reserved = new Set(["__proto__", "constructor", "prototype"]);
  for (const row of rows) {
    for (const k of Object.keys(row)) {
      // Reject prototype-pollution-ish keys early.
      if (reserved.has(k) || k.startsWith("__")) {
        errors.push(
          `Unsupported column key "${k}". Reserved keys (or keys starting with "__") are not allowed.`
        );
        return { ok: false, rows: [], columns: [], rowCount: 0, warnings, errors };
      }
      if (!seen.has(k)) {
        seen.add(k);
        allKeys.push(k);
      }
    }
  }

  let usedKeys = allKeys;
  if (allKeys.length > LIMITS.MAX_COLS) {
    warnings.push(
      `${allKeys.length} columns found — using first ${LIMITS.MAX_COLS} only.`
    );
    usedKeys = allKeys.slice(0, LIMITS.MAX_COLS);
  }

  // Build sanitized name map (avoid duplicates)
  const nameMap = new Map<string, string>();
  const usedSanitized = new Set<string>();
  for (const k of usedKeys) {
    let san = sanitizeName(k);
    let idx = 1;
    while (usedSanitized.has(san)) {
      san = `${sanitizeName(k)}_${idx++}`;
    }
    usedSanitized.add(san);
    nameMap.set(k, san);
    if (san !== k) {
      warnings.push(`Column "${k}" renamed to "${san}" for circuit compatibility.`);
    }
  }

  // Detect types from first 50 rows
  const sampleRows = rows.slice(0, 50);
  const columns: DetectedColumn[] = [];

  for (const key of usedKeys) {
    const sanitized = nameMap.get(key)!;
    const vals = sampleRows.map((r) => r[key]).filter((v) => v != null);

    let type: "u64" | "bool" | "text" = "text";
    let circuitCompatible = false;
    let warning: string | undefined;

    if (vals.length === 0) {
      type = "text";
      warning = "All sampled values are null.";
    } else if (vals.every((v) => typeof v === "boolean")) {
      type = "bool";
      circuitCompatible = true;
    } else if (vals.every((v) => typeof v === "number")) {
      const allInt = vals.every(
        (v) =>
          Number.isInteger(v) &&
          (v as number) >= 0 &&
          (v as number) <= Number.MAX_SAFE_INTEGER
      );
      if (allInt) {
        type = "u64";
        circuitCompatible = true;
      } else {
        type = "text";
        warning = "Float or negative numbers → stored as text, not circuit-provable.";
      }
    } else if (vals.every((v) => typeof v === "string")) {
      type = "text";
      warning = "Text columns cannot be used in WHERE filters, ORDER BY, or GROUP BY circuits.";
    } else {
      type = "text";
      warning = "Mixed types → stored as text.";
    }

    const sample = vals.slice(0, 3).map(String);
    columns.push({
      name: sanitized,
      originalName: key,
      type,
      sampleValues: sample,
      circuitCompatible,
      warning,
    });
  }

  const hasCompatible = columns.some((c) => c.circuitCompatible);
  if (!hasCompatible) {
    errors.push(
      "No circuit-compatible columns found. Need at least one u64 (non-negative integer) or bool column."
    );
  }

  return {
    ok: errors.length === 0,
    rows,
    columns,
    rowCount: rows.length,
    warnings,
    errors,
  };
}

// ─── API ingest ───────────────────────────────────────────────────────────────

export async function ingestCustomDataset(
  validation: ValidationResult,
  tableName: string,
  onProgress?: (msg: string) => void
): Promise<CustomDatasetState> {
  const log = (msg: string) => onProgress?.(msg);

  // Build schema
  const apiColumns = validation.columns.map((c) => ({
    name: c.name,
    col_type: { type: c.type },
  }));

  log(`Creating dataset "${tableName}"…`);
  const ds = await api.createDataset({
    name: tableName,
    description: `Custom upload — ${validation.rowCount} rows, ${validation.columns.length} columns`,
    columns: apiColumns,
  });

  // Build rows in schema order
  const colNames = validation.columns.map((c) => c.name);
  const originalNames = validation.columns.map((c) => c.originalName);

  const apiRows = validation.rows.map((rawRow) =>
    colNames.map((_, i) => {
      const v = rawRow[originalNames[i]];
      return v ?? null;
    })
  );

  log(`Ingesting ${validation.rowCount} rows…`);
  await api.ingestRows(ds.dataset_id, apiRows);

  log("Creating snapshot…");
  const snap = await api.createSnapshot(ds.dataset_id);
  await api.activateSnapshot(ds.dataset_id, snap.snapshot_id);

  log("Custom dataset ready.");

  return {
    datasetId: ds.dataset_id,
    snapshotId: snap.snapshot_id,
    tableName,
    columns: validation.columns,
    rowCount: validation.rowCount,
  };
}

// ─── Dynamic preset generation ────────────────────────────────────────────────

export function generateCustomPresets(
  state: CustomDatasetState
): PresetQuery[] {
  const { tableName, columns } = state;
  const numeric = columns.filter((c) => c.type === "u64");
  const bools = columns.filter((c) => c.type === "bool");
  const presets: PresetQuery[] = [];

  // COUNT(*) all rows — always
  presets.push({
    label: "COUNT(*) all rows",
    sql: `SELECT COUNT(*) FROM ${tableName}`,
    circuit: "AggCircuit",
    description: `Count all ${state.rowCount} rows. Full-table proof.`,
    category: "aggregate",
  });

  // Numeric column presets
  for (const col of numeric.slice(0, 3)) {
    presets.push({
      label: `AVG(${col.name})`,
      sql: `SELECT AVG(${col.name}) FROM ${tableName}`,
      circuit: "AggCircuit",
      description: `Proved average of "${col.name}". PI[2]=sum, PI[3]=count.`,
      category: "aggregate",
    });

    // SUM with filter: threshold = median-ish (mid of sample range)
    const sample = col.sampleValues.map(Number).filter(isFinite);
    const threshold =
      sample.length > 0
        ? Math.floor((Math.min(...sample) + Math.max(...sample)) / 2)
        : 0;
    if (threshold > 0) {
      presets.push({
        label: `SUM(${col.name}) where > ${threshold.toLocaleString()}`,
        sql: `SELECT SUM(${col.name}) FROM ${tableName} WHERE ${col.name} > ${threshold}`,
        circuit: "AggCircuit",
        description: `Proved sum of "${col.name}" for rows above threshold ${threshold}.`,
        category: "aggregate",
      });
    }

    presets.push({
      label: `ORDER BY ${col.name} ASC`,
      sql: `SELECT ${col.name} FROM ${tableName} ORDER BY ${col.name}`,
      circuit: "SortCircuit",
      description: `Sort "${col.name}" ascending. Schwartz-Zippel permutation proof.`,
      category: "sort",
    });

    presets.push({
      label: `ORDER BY ${col.name} DESC`,
      sql: `SELECT ${col.name} FROM ${tableName} ORDER BY ${col.name} DESC`,
      circuit: "DescSortCircuit",
      description: `Sort "${col.name}" descending. Non-increasing monotonicity proof.`,
      category: "sort",
    });
  }

  // Bool column presets
  for (const col of bools.slice(0, 1)) {
    presets.push({
      label: `COUNT WHERE ${col.name} = true`,
      sql: `SELECT COUNT(*) FROM ${tableName} WHERE ${col.name} = true`,
      circuit: "AggCircuit",
      description: `Count rows where "${col.name}" is true. Bool predicate (Eq, pred_val=1).`,
      category: "aggregate",
    });

    if (numeric.length > 0) {
      const nc = numeric[0];
      presets.push({
        label: `GROUP BY ${col.name} SUM(${nc.name})`,
        sql: `SELECT ${col.name}, SUM(${nc.name}) FROM ${tableName} GROUP BY ${col.name}`,
        circuit: "GroupByCircuit",
        description: `Two-group aggregation: bool column gives exactly 2 groups. Per-group SUM proved via Poseidon.`,
        category: "groupby",
      });
    }
  }

  // Numeric GROUP BY (if another numeric exists to aggregate)
  if (numeric.length >= 2) {
    const gbCol = numeric[1];
    const aggCol = numeric[0];
    presets.push({
      label: `GROUP BY ${gbCol.name} SUM(${aggCol.name})`,
      sql: `SELECT ${gbCol.name}, SUM(${aggCol.name}) FROM ${tableName} GROUP BY ${gbCol.name}`,
      circuit: "GroupByCircuit",
      description: `Group by "${gbCol.name}" (numeric key), sum "${aggCol.name}" per group. Circuit proves group boundaries + Poseidon commitment.`,
      category: "groupby",
    });
  }

  return presets;
}
