"use client";

import { useEffect, useRef, useState } from "react";
import { api, Proof, VerificationResponse, AllPublicInputs } from "@/lib/api";
import { setupDemoDatasets, DemoState } from "@/lib/demo";
import { PRESET_QUERIES, PresetQuery, CATEGORY_LABELS } from "@/lib/presets";
import {
  validateAndParse,
  ingestCustomDataset,
  generateCustomPresets,
  CustomDatasetState,
  LIMITS,
} from "@/lib/custom-dataset";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Hash,
  Timer,
  FileDigit,
  ChevronDown,
  ChevronUp,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Info,
  Copy,
  Check,
  Code2,
  Binary,
  Braces,
  TableProperties,
  AlertCircle,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

type Phase = "idle" | "setting-up" | "proving" | "done" | "error";

interface ProofRun {
  queryId: string;
  proofId: string;
  proof: Proof;
  sql: string;
  proofMs: number;
  verifyMs?: number;
  verification?: VerificationResponse;
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function fmtMs(ms: number) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${ms.toFixed(0)}ms`;
}

function fmtBytes(b: number) {
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

function truncHex(hex: string, len = 20) {
  if (!hex || hex.length <= len) return hex;
  return hex.slice(0, len) + "…";
}

// ─── Copy Button ─────────────────────────────────────────────────────────────

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }
  return (
    <button
      onClick={handleCopy}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 5,
        padding: "4px 10px",
        background: copied ? "rgba(0,229,160,0.15)" : "rgba(90,98,130,0.2)",
        border: `1px solid ${copied ? "rgba(0,229,160,0.4)" : "var(--border)"}`,
        borderRadius: 4,
        color: copied ? "var(--accent-green)" : "var(--text-dim)",
        cursor: "pointer",
        fontSize: 11,
        fontFamily: "inherit",
        transition: "all 0.15s",
        flexShrink: 0,
      }}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
      {copied ? "Copied!" : label}
    </button>
  );
}

// ─── Proof Explorer ───────────────────────────────────────────────────────────

type ProofTab = "summary" | "hex" | "json" | "bytes";

function ProofExplorer({ proof }: { proof: Proof }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<ProofTab>("hex");

  const proofBytes = Math.ceil(proof.proof_hex.length / 2);

  // Build a clean JSON summary object
  const proofJson = JSON.stringify(
    {
      proof_id: proof.proof_id,
      query_id: proof.query_id,
      snapshot_id: proof.snapshot_id,
      backend: proof.backend,
      proof_system_kind: proof.proof_system_kind,
      proof_size_bytes: proofBytes,
      snapshot_root_hex: proof.snapshot_root_hex,
      query_hash_hex: proof.query_hash_hex,
      result_commit_poseidon_proved_hex: proof.result_commit_poseidon_proved_hex,
      unsafe_metadata_commitment_hex: proof.unsafe_metadata_commitment_hex,
      public_inputs: proof.public_inputs,
      created_at_ms: proof.created_at_ms,
    },
    null,
    2
  );

  // Format hex into 16-byte rows with offsets
  function hexGrid(hex: string) {
    const lines: string[] = [];
    for (let i = 0; i < hex.length; i += 32) {
      const offset = String((i / 2).toString(16).padStart(6, "0"));
      const chunk = hex.slice(i, i + 32).toUpperCase();
      const spaced = chunk.match(/.{1,2}/g)?.join(" ") ?? chunk;
      lines.push(`${offset}  ${spaced}`);
    }
    return lines.join("\n");
  }

  const tabs: { id: ProofTab; label: string; icon: React.ReactNode }[] = [
    { id: "hex", label: "Hex", icon: <Code2 size={12} /> },
    { id: "json", label: "JSON", icon: <Braces size={12} /> },
    { id: "bytes", label: "Byte Grid", icon: <Binary size={12} /> },
    { id: "summary", label: "Fields", icon: <FileDigit size={12} /> },
  ];

  return (
    <div style={{ marginBottom: 20 }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: open ? "8px 8px 0 0" : 8,
          padding: "10px 16px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          cursor: "pointer",
          color: "var(--text)",
          fontFamily: "inherit",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <FileDigit size={14} style={{ color: "var(--accent-blue)" }} />
          <span style={{ fontSize: 13, fontWeight: 500 }}>Proof Explorer</span>
          <span style={{ fontSize: 11, color: "var(--text-dim)", background: "var(--border)", borderRadius: 3, padding: "1px 7px" }}>
            {(proofBytes / 1024).toFixed(1)} KB · Plonky2 FRI-SNARK
          </span>
        </div>
        {open ? <ChevronUp size={14} style={{ color: "var(--text-dim)" }} /> : <ChevronDown size={14} style={{ color: "var(--text-dim)" }} />}
      </button>

      {open && (
        <div
          style={{
            background: "#080a0f",
            border: "1px solid var(--border)",
            borderTop: "none",
            borderRadius: "0 0 8px 8px",
            overflow: "hidden",
          }}
        >
          {/* Tab bar */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--border)", background: "var(--surface)" }}>
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "8px 16px",
                  background: "transparent",
                  border: "none",
                  borderBottom: tab === t.id ? "2px solid var(--accent-blue)" : "2px solid transparent",
                  color: tab === t.id ? "var(--accent-blue)" : "var(--text-dim)",
                  cursor: "pointer",
                  fontSize: 12,
                  fontFamily: "inherit",
                  transition: "color 0.15s",
                }}
              >
                {t.icon} {t.label}
              </button>
            ))}
            <div style={{ flex: 1 }} />
            <div style={{ display: "flex", alignItems: "center", padding: "0 12px" }}>
              <CopyButton
                text={
                  tab === "hex" ? proof.proof_hex
                  : tab === "json" ? proofJson
                  : tab === "bytes" ? hexGrid(proof.proof_hex)
                  : proofJson
                }
                label={`Copy ${tab === "hex" ? "Hex" : tab === "json" ? "JSON" : tab === "bytes" ? "Grid" : "Fields"}`}
              />
            </div>
          </div>

          {/* Content */}
          <div style={{ padding: "12px 16px", maxHeight: 360, overflowY: "auto" }}>
            {tab === "hex" && (
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--accent-green)", lineHeight: 1.6, wordBreak: "break-all" }}>
                <div style={{ color: "var(--text-dim)", fontSize: 10, marginBottom: 8 }}>
                  Full proof · {proofBytes} bytes · {proof.proof_hex.length} hex chars
                </div>
                {proof.proof_hex}
              </div>
            )}

            {tab === "json" && (
              <pre style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--text-dim)", lineHeight: 1.7, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                <span style={{ color: "#8b949e" }}>{proofJson.split("\n").map((line, i) => {
                  // Syntax highlight keys and values
                  const highlighted = line
                    .replace(/"([^"]+)":/g, '<key>"$1":</key>')
                    .replace(/: "([^"]*)"(,?)/g, ': <str>"$1"</str>$2')
                    .replace(/: (\d+)(,?)/g, ': <num>$1</num>$2');
                  return line;
                }).join("\n")}</span>
                {proofJson}
              </pre>
            )}

            {tab === "bytes" && (
              <pre style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--text-dim)", lineHeight: 1.8, margin: 0 }}>
                <div style={{ color: "var(--text-muted)", marginBottom: 8, fontSize: 9 }}>
                  OFFSET   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                </div>
                {hexGrid(proof.proof_hex)}
              </pre>
            )}

            {tab === "summary" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {[
                  { label: "proof_id", value: proof.proof_id, mono: true },
                  { label: "query_id", value: proof.query_id, mono: true },
                  { label: "snapshot_id", value: proof.snapshot_id, mono: true },
                  { label: "backend", value: proof.backend, mono: false },
                  { label: "proof_system_kind", value: proof.proof_system_kind, mono: false },
                  { label: "proof_size_bytes", value: proofBytes.toLocaleString(), mono: false },
                  { label: "snapshot_root_hex", value: proof.snapshot_root_hex, mono: true },
                  { label: "query_hash_hex", value: proof.query_hash_hex, mono: true },
                  { label: "result_commit_poseidon_proved_hex", value: proof.result_commit_poseidon_proved_hex, mono: true },
                  { label: "unsafe_metadata_commitment_hex", value: proof.unsafe_metadata_commitment_hex, mono: true },
                ].map(({ label, value, mono }) => (
                  <div key={label} style={{ display: "flex", gap: 12, alignItems: "flex-start", padding: "6px 0", borderBottom: "1px solid rgba(90,98,130,0.1)" }}>
                    <span style={{ fontSize: 11, color: "var(--text-dim)", minWidth: 220, flexShrink: 0 }}>{label}</span>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", flex: 1, minWidth: 0 }}>
                      <span style={{
                        fontSize: 11,
                        fontFamily: mono ? "'JetBrains Mono', monospace" : "inherit",
                        color: mono ? "var(--accent-blue)" : "var(--text)",
                        wordBreak: "break-all",
                        flex: 1,
                      }}>{value}</span>
                      <CopyButton text={value} label="Copy" />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Dataset Uploader ─────────────────────────────────────────────────────────

interface DatasetUploaderProps {
  onReady: (state: CustomDatasetState, presets: PresetQuery[]) => void;
  onProgress: (msg: string) => void;
}

function DatasetUploader({ onReady, onProgress }: DatasetUploaderProps) {
  const [jsonText, setJsonText] = useState<string>("");
  const [validation, setValidation] = useState<ReturnType<typeof validateAndParse> | null>(null);
  const [inputBytes, setInputBytes] = useState<number>(0);
  const [ingesting, setIngesting] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  function bytesOf(s: string) {
    return new TextEncoder().encode(s).byteLength;
  }

  function handleValidate() {
    setUploadError(null);
    const bytes = bytesOf(jsonText);
    setInputBytes(bytes);
    setValidation(validateAndParse(jsonText, bytes));
  }

  async function handleIngest() {
    if (!validation?.ok) return;
    setIngesting(true);
    setUploadError(null);
    const tableName = `custom_data`;
    try {
      const state = await ingestCustomDataset(validation, tableName, onProgress);
      const presets = generateCustomPresets(state);
      onReady(state, presets);
    } catch (e: unknown) {
      setUploadError(e instanceof Error ? e.message : String(e));
    } finally {
      setIngesting(false);
    }
  }

  return (
    <div>
      <div style={{ background: "rgba(77,159,255,0.04)", border: "1px solid rgba(77,159,255,0.18)", borderRadius: 8, padding: 12 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--text-dim)", marginBottom: 8 }}>
          Paste JSON DB (flat rows)
        </div>

        <textarea
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          placeholder={`[
  {"id": 1, "score": 42},
  {"id": 2, "score": 7}
]`}
          spellCheck={false}
          style={{
            width: "100%",
            minHeight: 140,
            background: "#0d0f15",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "10px 12px",
            color: "var(--text)",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12,
            lineHeight: 1.6,
            resize: "vertical",
            outline: "none",
          }}
        />

        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          <button
            onClick={handleValidate}
            disabled={ingesting}
            style={{
              flex: 1,
              padding: "10px 0",
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              cursor: ingesting ? "not-allowed" : "pointer",
              color: "var(--text)",
              fontWeight: 600,
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
              fontFamily: "inherit",
            }}
          >
            <TableProperties size={14} />
            Validate & Preview
          </button>

          <button
            onClick={handleIngest}
            disabled={ingesting || !validation?.ok}
            style={{
              flex: 1,
              padding: "10px 0",
              background: ingesting ? "rgba(0,229,160,0.1)" : "rgba(0,229,160,0.15)",
              border: "1px solid rgba(0,229,160,0.35)",
              borderRadius: 6,
              cursor: ingesting || !validation?.ok ? "not-allowed" : "pointer",
              color: ingesting ? "var(--accent-green)" : "var(--accent-green)",
              fontWeight: 700,
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
              fontFamily: "inherit",
            }}
          >
            {ingesting ? (
              <>
                <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />
                Creating dataset…
              </>
            ) : (
              <>Ingest & Generate Presets</>
            )}
          </button>
        </div>

        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-dim)", lineHeight: 1.6 }}>
          Constraints: max {LIMITS.MAX_ROWS.toLocaleString()} rows · {LIMITS.MAX_COLS} columns · max{" "}
          {(LIMITS.MAX_JSON_BYTES / 1024 / 1024).toFixed(1)} MB · flat objects only · reserved keys like `__proto__` rejected.
        </div>

        {inputBytes > 0 && (
          <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-muted)" }}>
            Input size: {fmtBytes(inputBytes)}
          </div>
        )}
      </div>

      {validation && (
        <div style={{ marginTop: 12 }}>
          {validation.errors.length > 0 && (
            <div style={{ background: "rgba(255,77,106,0.08)", border: "1px solid rgba(255,77,106,0.25)", borderRadius: 6, padding: "10px 12px", marginBottom: 8 }}>
              {validation.errors.map((e, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--accent-red)", display: "flex", gap: 6 }}>
                  <AlertCircle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
                  {e}
                </div>
              ))}
            </div>
          )}

          {validation.warnings.length > 0 && (
            <div style={{ background: "rgba(255,162,0,0.06)", border: "1px solid rgba(255,162,0,0.2)", borderRadius: 6, padding: "8px 12px", marginBottom: 8 }}>
              {validation.warnings.map((w, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--accent-amber)", display: "flex", gap: 6 }}>
                  <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
                  {w}
                </div>
              ))}
            </div>
          )}

          {validation.ok && (
            <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.15)", borderRadius: 6, padding: "10px 12px", marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: "var(--accent-green)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                <CheckCircle2 size={11} style={{ display: "inline", marginRight: 4 }} />
                {validation.rowCount} rows · {validation.columns.length} columns detected
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 4 }}>
                {validation.columns.map((col) => (
                  <div
                    key={col.name}
                    style={{
                      background: "var(--surface)",
                      border: `1px solid ${col.circuitCompatible ? "rgba(0,229,160,0.2)" : "rgba(255,162,0,0.2)"}`,
                      borderRadius: 4,
                      padding: "5px 8px",
                      fontSize: 10,
                    }}
                    title={col.warning}
                  >
                    <div style={{ fontFamily: "monospace", color: col.circuitCompatible ? "var(--accent-green)" : "var(--accent-amber)" }}>
                      {col.name}
                    </div>
                    <div style={{ color: "var(--text-dim)", marginTop: 1 }}>
                      {col.type}
                      {!col.circuitCompatible && " ⚠"}
                    </div>
                    {col.sampleValues.length > 0 && (
                      <div style={{ color: "var(--text-muted)", fontSize: 9, marginTop: 1 }}>
                        e.g. {col.sampleValues[0]}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              {validation.columns.some((c) => !c.circuitCompatible) && (
                <div style={{ fontSize: 10, color: "var(--accent-amber)", marginTop: 8 }}>
                  ⚠ Text columns shown in orange cannot be used in circuit queries (sort/filter/groupby).
                </div>
              )}
            </div>
          )}

          {uploadError && (
            <div style={{ background: "rgba(255,77,106,0.08)", border: "1px solid rgba(255,77,106,0.25)", borderRadius: 6, padding: "8px 12px", marginTop: 8, fontSize: 11, color: "var(--accent-red)" }}>
              {uploadError}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Detect query type from SQL to show the right result interpretation */
function detectQueryKind(sql: string): "sum" | "count" | "avg" | "sort" | "groupby" | "join" | "filter" {
  const s = sql.toLowerCase();
  if (s.includes("join")) return "join";
  if (s.includes("group by")) return "groupby";
  if (s.includes("order by")) return "sort";
  if (s.includes("avg(")) return "avg";
  if (s.includes("sum(")) return "sum";
  if (s.includes("count(")) return "count";
  return "filter";
}

function detectDataset(sql: string, demo: DemoState | null) {
  if (!demo) return null;
  const s = sql.toLowerCase();
  if (s.includes("benchmark_employees")) return { datasetId: demo.empDatasetId };
  return { datasetId: demo.txnDatasetId };
}

// ─── Result Interpretation ────────────────────────────────────────────────────

function QueryResultBox({ proof, sql }: { proof: Proof; sql: string }) {
  const kind = detectQueryKind(sql);
  const pi = proof.public_inputs;
  const sum = proof.result_sum;
  const count = proof.result_row_count;
  const hasWhere = /\bwhere\b/i.test(sql);

  const items: { label: string; value: string; proved: boolean; note?: string }[] = [];

  if (kind === "avg") {
    const avg = count > 0 ? (sum / count).toFixed(2) : "—";
    items.push({ label: "AVG result", value: avg, proved: false, note: "derived: sum ÷ count (off-circuit)" });
    items.push({ label: "SUM (PI[2])", value: sum.toLocaleString(), proved: true, note: "circuit-proved" });
    items.push({ label: "COUNT (PI[3])", value: count.toLocaleString(), proved: true, note: "circuit-proved" });
    items.push({ label: "n_real (PI[7])", value: pi.agg_n_real.toLocaleString(), proved: false, note: "total rows in dataset" });
  } else if (kind === "sum") {
    items.push({ label: "SUM (PI[2])", value: sum.toLocaleString(), proved: true, note: "circuit-proved" });
    items.push({ label: "Rows matched (PI[3])", value: count.toLocaleString(), proved: true, note: "circuit-proved" });
    items.push({ label: "n_real (PI[7])", value: pi.agg_n_real.toLocaleString(), proved: false, note: "total rows in dataset" });
  } else if (kind === "count") {
    items.push({ label: "COUNT (PI[3])", value: count.toLocaleString(), proved: true, note: "circuit-proved" });
    if (hasWhere && sum > 0) {
      // With a numeric WHERE filter, PI[2] = sum of the filter column over matched rows
      items.push({ label: "SUM of filtered col (PI[2])", value: sum.toLocaleString(), proved: true, note: "sum of filter column for matched rows" });
    }
    items.push({ label: "n_real (PI[7])", value: pi.agg_n_real.toLocaleString(), proved: false, note: "total rows in dataset" });
  } else if (kind === "sort") {
    items.push({ label: "Rows sorted (PI[3])", value: count.toLocaleString(), proved: true, note: "circuit-proved" });
    items.push({ label: "SUM of col (PI[2])", value: sum.toLocaleString(), proved: true, note: "sum of sorted column — integrity check" });
  } else if (kind === "groupby") {
    items.push({ label: "Total rows proved (PI[3])", value: count.toLocaleString(), proved: true });
    items.push({ label: "Global SUM (PI[2])", value: sum.toLocaleString(), proved: true, note: "sum of agg column across all groups" });
  } else if (kind === "join") {
    items.push({ label: "Matched rows (PI[3])", value: count.toLocaleString(), proved: true });
    items.push({ label: "Left col SUM (PI[2])", value: sum.toLocaleString(), proved: true });
    items.push({ label: "Unmatched rows", value: pi.join_unmatched_count.toLocaleString(), proved: true, note: "PI[6] circuit-proved" });
  } else {
    items.push({ label: "Rows matched (PI[3])", value: count.toLocaleString(), proved: true });
    items.push({ label: "n_real (PI[7])", value: pi.agg_n_real.toLocaleString(), proved: false, note: "total rows in dataset" });
  }

  return (
    <div
      style={{
        background: "rgba(0,229,160,0.05)",
        border: "1px solid rgba(0,229,160,0.2)",
        borderRadius: 8,
        padding: "14px 16px",
        marginBottom: 20,
      }}
    >
      <div
        style={{
          fontSize: 10,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--accent-green)",
          marginBottom: 10,
        }}
      >
        Query Result
      </div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {items.map((item) => (
          <div
            key={item.label}
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "8px 14px",
              minWidth: 140,
            }}
          >
            <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 3 }}>
              {item.label}
            </div>
            <div
              style={{
                fontSize: 22,
                fontWeight: 600,
                color: item.proved ? "var(--accent-green)" : "var(--accent-amber)",
              }}
            >
              {item.value}
            </div>
            {item.note && (
              <div style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 2 }}>
                {item.note}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Public Inputs Panel ──────────────────────────────────────────────────────

function PublicInputsPanel({ pi, sql }: { pi: AllPublicInputs; sql: string }) {
  const kind = detectQueryKind(sql);
  const hasWhere = /\bwhere\b/i.test(sql);

  // For COUNT(*) without WHERE, PI[2] = sum of first schema column (binding col, not requested)
  const pi2Active = !(kind === "count" && !hasWhere);
  const pi2Note = kind === "sort"
    ? "sum of sorted column — integrity"
    : kind === "join"
    ? "sum of left join column"
    : kind === "count" && !hasWhere
    ? "⚠ binding col sum — not requested by COUNT(*); ignore this"
    : kind === "count" && hasWhere
    ? "sum of filter column over matched rows"
    : "SUM of selected rows";

  const rows: { label: string; value: string; pi: string; note?: string; active?: boolean }[] = [
    {
      label: "Snapshot binding",
      value: pi.snap_lo_hex,
      pi: "PI[0]",
      note: "Poseidon(column_values)[0] — data commitment",
      active: true,
    },
    {
      label: "Query hash",
      value: truncHex(pi.query_hash_hex),
      pi: "PI[1]",
      note: "Blake3(SQL text) — query commitment",
      active: true,
    },
    {
      label: kind === "count" && !hasWhere ? "binding_col_sum (ignored)" : "result_sum",
      value: pi.result_sum.toLocaleString(),
      pi: "PI[2]",
      note: pi2Note,
      active: pi2Active,
    },
    {
      label: "result_count",
      value: pi.result_row_count.toLocaleString(),
      pi: "PI[3]",
      note: "COUNT of matching rows",
      active: true,
    },
  ];

  // PI[4] depends on circuit
  if (kind === "join") {
    rows.push({
      label: "join_right_snap_lo",
      value: pi.join_right_snap_lo_hex,
      pi: "PI[4]",
      note: "Poseidon(right_keys)[0] — right-table binding",
      active: pi.join_right_snap_lo_hex !== "0x0000000000000000",
    });
  } else {
    rows.push({
      label: "result_commit_lo",
      value: pi.result_commit_or_join_right_hex,
      pi: "PI[4]",
      note: "Poseidon(sum, count)[0] — in-circuit result commitment",
      active: true,
    });
  }

  // PI[5] depends on circuit
  if (kind === "groupby") {
    rows.push({
      label: "group_output_lo",
      value: pi.group_output_lo_hex,
      pi: "PI[5]",
      note: "Poseidon(keys ++ vals ++ boundaries)[0] — full relation commitment",
      active: pi.group_output_lo_hex !== "0x0000000000000000",
    });
  } else if (kind === "sort") {
    rows.push({
      label: "sort_secondary_snap_lo",
      value: pi.sort_secondary_snap_lo_hex,
      pi: "PI[5]",
      note: "Poseidon(secondary_lo)[0] — 128-bit payload binding (lo)",
      active: pi.sort_secondary_snap_lo_hex !== "0x0000000000000000",
    });
    rows.push({
      label: "sort_secondary_hi_snap_lo",
      value: pi.sort_secondary_hi_snap_lo_hex,
      pi: "PI[6]",
      note: "Poseidon(secondary_hi)[0] — 128-bit payload binding (hi)",
      active: pi.sort_secondary_hi_snap_lo_hex !== "0x0000000000000000",
    });
  }

  // PI[7]
  if (kind === "groupby") {
    rows.push({
      label: "group_vals_snap_lo",
      value: pi.group_vals_snap_lo_hex,
      pi: "PI[7]",
      note: "Poseidon(vals)[0] — value column binding",
      active: pi.group_vals_snap_lo_hex !== "0x0000000000000000",
    });
  } else if (kind !== "sort" && kind !== "join") {
    rows.push({
      label: "n_real",
      value: pi.agg_n_real.toLocaleString(),
      pi: "PI[7]",
      note: "non-padding rows in dataset — prevents Lt/Gt undercounting",
      active: pi.agg_n_real > 0,
    });
    if (pi.pred_op > 0) {
      const ops = ["", "Eq", "Lt", "Gt"];
      rows.push({
        label: "pred_op / pred_val",
        value: `${ops[pi.pred_op] ?? pi.pred_op} (${pi.pred_val})`,
        pi: "PI[5]/[6]",
        note: "predicate operator and target value — circuit-constrained",
        active: true,
      });
    }
  }

  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "56px 1fr 2fr auto",
          gap: 0,
        }}
      >
        {/* Header */}
        {["Index", "Name", "Value", ""].map((h) => (
          <div
            key={h}
            style={{
              padding: "6px 12px",
              fontSize: 10,
              color: "var(--text-muted)",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              borderBottom: "1px solid var(--border)",
              background: "rgba(0,0,0,0.2)",
            }}
          >
            {h}
          </div>
        ))}
        {rows.map((row) => (
          <>
            <div
              key={row.pi + "-idx"}
              style={{
                padding: "7px 12px",
                fontSize: 11,
                color: "var(--accent-purple)",
                borderBottom: "1px solid var(--border)",
                fontWeight: 600,
              }}
            >
              {row.pi}
            </div>
            <div
              key={row.pi + "-label"}
              style={{
                padding: "7px 12px",
                fontSize: 11,
                color: row.active ? "var(--text)" : "var(--text-muted)",
                borderBottom: "1px solid var(--border)",
              }}
            >
              {row.label}
            </div>
            <div
              key={row.pi + "-value"}
              style={{
                padding: "7px 12px",
                fontSize: 11,
                fontFamily: "monospace",
                color: row.active ? "var(--accent-blue)" : "var(--text-muted)",
                borderBottom: "1px solid var(--border)",
                wordBreak: "break-all",
              }}
            >
              {row.value}
              {row.note && (
                <div style={{ fontSize: 9, color: "var(--text-dim)", marginTop: 1 }}>
                  {row.note}
                </div>
              )}
            </div>
            <div
              key={row.pi + "-check"}
              style={{
                padding: "7px 10px",
                borderBottom: "1px solid var(--border)",
                display: "flex",
                alignItems: "center",
              }}
            >
              {row.active ? (
                <CheckCircle2 size={12} style={{ color: "var(--accent-green)" }} />
              ) : (
                <XCircle size={12} style={{ color: "var(--text-muted)" }} />
              )}
            </div>
          </>
        ))}
      </div>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div
        style={{
          fontSize: 10,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-dim)",
          marginBottom: 10,
          borderBottom: "1px solid var(--border)",
          paddingBottom: 6,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function MetricBox({
  icon,
  label,
  value,
  sub,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  color?: string;
}) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: "12px 16px",
        flex: 1,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <span style={{ color: color ?? "var(--text-dim)" }}>{icon}</span>
        <span style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.05em" }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 20, fontWeight: 600, color: color ?? "var(--text)" }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function VerifyBadge({ vr }: { vr: VerificationResponse }) {
  const ok = vr.is_valid;
  const color = ok ? "var(--accent-green)" : "var(--accent-red)";
  const bg = ok ? "rgba(0,229,160,0.08)" : "rgba(255,77,106,0.08)";
  const border = ok ? "rgba(0,229,160,0.3)" : "rgba(255,77,106,0.3)";
  const Icon = ok ? ShieldCheck : ShieldAlert;

  return (
    <div
      style={{ background: bg, border: `1px solid ${border}`, borderRadius: 8, padding: "14px 18px" }}
      className="animate-slide-in"
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <Icon size={20} style={{ color }} />
        <span style={{ color, fontWeight: 600, fontSize: 15 }}>
          {ok ? "Proof Valid ✓" : "Proof Invalid ✗"}
        </span>
        <span
          style={{
            fontSize: 11,
            color: "var(--text-dim)",
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            padding: "2px 8px",
          }}
        >
          {vr.verification_kind}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
        {[
          { k: "Anchor", v: vr.external_anchor_status },
          { k: "Completeness", v: vr.completeness_proved ? "positional ✓" : "partial" },
          { k: "Zero-knowledge", v: vr.has_zero_knowledge ? "✅ yes" : "❌ no" },
          { k: "Succinct verify", v: vr.is_succinct ? "✅ yes" : "❌ no" },
          { k: "Backend", v: vr.backend },
          { k: "Proof system", v: vr.proof_system_kind },
        ].map(({ k, v }) => (
          <div
            key={k}
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              padding: "6px 10px",
            }}
          >
            <div style={{ fontSize: 9, color: "var(--text-dim)", marginBottom: 2 }}>{k}</div>
            <div style={{ fontSize: 11, color: "var(--text)" }}>{v}</div>
          </div>
        ))}
      </div>

      {vr.warnings.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {vr.warnings.map((w, i) => (
            <div
              key={i}
              style={{ display: "flex", gap: 6, padding: "3px 0", color: "var(--accent-amber)", fontSize: 11 }}
            >
              <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
              {w}
            </div>
          ))}
        </div>
      )}
      {vr.error && (
        <div style={{ marginTop: 8, color: "var(--accent-red)", fontSize: 11 }}>⚠ {vr.error}</div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Home() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [setupLog, setSetupLog] = useState<string[]>([]);
  const [demo, setDemo] = useState<DemoState | null>(null);
  const [datasetMode, setDatasetMode] = useState<"demo" | "custom">("demo");
  const [customDataset, setCustomDataset] = useState<CustomDatasetState | null>(null);
  const [customPresets, setCustomPresets] = useState<PresetQuery[] | null>(null);
  const [systemInfo, setSystemInfo] = useState<Awaited<ReturnType<typeof api.systemInfo>> | null>(null);
  const [sql, setSql] = useState(PRESET_QUERIES[0].sql);
  const [selectedPreset, setSelectedPreset] = useState<PresetQuery>(PRESET_QUERIES[0]);
  const [showPresets, setShowPresets] = useState(false);
  const [run, setRun] = useState<ProofRun | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const presetRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.systemInfo().then(setSystemInfo).catch(() => {});
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [setupLog]);

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (presetRef.current && !presetRef.current.contains(e.target as Node)) {
        setShowPresets(false);
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  async function handleRun() {
    setError(null);
    setRun(null);

    let datasetId: string | null = null;

    if (datasetMode === "demo") {
      let demoState = demo;
      if (!demoState) {
        setPhase("setting-up");
        setSetupLog([]);
        try {
          demoState = await setupDemoDatasets(100, (msg) =>
            setSetupLog((prev) => [...prev, msg])
          );
          setDemo(demoState);
        } catch (e: unknown) {
          setError(`Setup failed: ${e instanceof Error ? e.message : String(e)}`);
          setPhase("error");
          return;
        }
      }

      const target = detectDataset(sql, demoState);
      if (!target) {
        setError("Cannot detect dataset from SQL.");
        setPhase("error");
        return;
      }
      datasetId = target.datasetId;
    } else {
      if (!customDataset) {
        setError("Custom dataset is not ingested yet. Paste JSON and click \"Ingest & Generate Presets\".");
        setPhase("error");
        return;
      }
      // Prevent accidental mixing of demo SQL with the custom dataset.
      if (!/\bfrom\s+custom_data\b/i.test(sql)) {
        setError("In custom mode, SQL must query `custom_data` (the ingested table).");
        setPhase("error");
        return;
      }
      datasetId = customDataset.datasetId;
    }

    setPhase("proving");
    const t0 = Date.now();

    try {
      const submitted = await api.submitQuery({
        dataset_id: datasetId!,
        sql,
        backend: "plonky2",
      });

      const queryResult = await api.getQueryResult(submitted.query_id);
      const proofMs = Date.now() - t0;

      if (queryResult.status === "failed" || queryResult.error) {
        throw new Error(queryResult.error ?? "Query failed");
      }
      if (!queryResult.proof_id) throw new Error("No proof_id in result");

      const proof = await api.getProof(queryResult.proof_id);

      setRun({ queryId: submitted.query_id, proofId: queryResult.proof_id, proof, sql, proofMs });
      setPhase("done");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  async function handleVerify() {
    if (!run) return;
    setVerifying(true);
    const t0 = Date.now();
    try {
      const vr = await api.verifyProof({
        proof_id: run.proofId,
        expected_snapshot_root: run.proof.snapshot_root_hex,
        expected_query_hash: run.proof.query_hash_hex,
      });
      setRun((prev) => (prev ? { ...prev, verification: vr, verifyMs: Date.now() - t0 } : prev));
    } catch (e: unknown) {
      setError(`Verify error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setVerifying(false);
    }
  }

  function handleReset() {
    setPhase("idle");
    setRun(null);
    setError(null);
    setSetupLog([]);
    setDemo(null);
    setDatasetMode("demo");
    setCustomDataset(null);
    setCustomPresets(null);
    setSql(PRESET_QUERIES[0].sql);
    setSelectedPreset(PRESET_QUERIES[0]);
    setShowPresets(false);
  }

  const effectivePresets = datasetMode === "custom" ? (customPresets ?? []) : PRESET_QUERIES;
  const presetsByCategory = effectivePresets.reduce(
    (acc, p) => { (acc[p.category] ??= []).push(p); return acc; },
    {} as Record<string, PresetQuery[]>
  );

  const isRunning = phase === "proving" || phase === "setting-up";

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <header
        style={{
          borderBottom: "1px solid var(--border)",
          padding: "14px 28px",
          display: "flex",
          alignItems: "center",
          gap: 16,
          background: "var(--surface)",
          position: "sticky",
          top: 0,
          zIndex: 100,
        }}
      >
        <Shield size={18} style={{ color: "var(--accent-green)" }} />
        <span style={{ fontWeight: 600, fontSize: 15, letterSpacing: "-0.01em" }}>zkDB</span>
        <span style={{ color: "var(--text-dim)", fontSize: 11 }}>Zero-Knowledge Verifiable Database</span>
        {systemInfo && (
          <div style={{ marginLeft: "auto", display: "flex", gap: 20, alignItems: "center" }}>
            <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
              Plonky2 v0.2.2 · {systemInfo.field}
            </span>
            <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
              MAX_ROWS={systemInfo.max_rows_per_circuit} · {systemInfo.hash}
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                background: "rgba(0,229,160,0.08)",
                border: "1px solid rgba(0,229,160,0.25)",
                borderRadius: 4,
                padding: "3px 10px",
              }}
            >
              <div style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--accent-green)", animation: "pulse-green 2s infinite" }} />
              <span style={{ fontSize: 11, color: "var(--accent-green)", fontWeight: 500 }}>Plonky2 SNARK</span>
            </div>
          </div>
        )}
      </header>

      {/* Body */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "360px 1fr",
          flex: 1,
          height: "calc(100vh - 53px)",
          overflow: "hidden",
        }}
      >
        {/* Left Panel */}
        <div
          style={{
            borderRight: "1px solid var(--border)",
            padding: 20,
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Backend info (read-only) */}
          <Section title="Proving Backend">
            <div
              style={{
                background: "rgba(0,229,160,0.06)",
                border: "1px solid rgba(0,229,160,0.3)",
                borderRadius: 8,
                padding: "12px 16px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent-green)" }} />
                <span style={{ fontWeight: 600, fontSize: 13 }}>Plonky2 SNARK</span>
                <span className="tag-snark">ZK</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.6 }}>
                FRI-based SNARK over Goldilocks field. Real polynomial commitments. Zero-knowledge and succinct.
              </div>
              <div style={{ marginTop: 8, display: "flex", gap: 14 }}>
                {[
                  { ok: true, label: "Zero-Knowledge" },
                  { ok: true, label: "Succinct" },
                  { ok: true, label: "FRI Commitments" },
                ].map(({ ok, label }) => (
                  <span key={label} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: "var(--accent-green)" }}>
                    <CheckCircle2 size={10} />{label}
                  </span>
                ))}
              </div>
            </div>
          </Section>

          {/* Dataset source */}
          <Section title="Dataset Source">
            <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
              <button
                onClick={() => {
                  setDatasetMode("demo");
                  setSelectedPreset(PRESET_QUERIES[0]);
                  setSql(PRESET_QUERIES[0].sql);
                  setShowPresets(false);
                  setRun(null);
                  setError(null);
                }}
                style={{
                  flex: 1,
                  padding: "10px 0",
                  background: datasetMode === "demo" ? "rgba(0,229,160,0.15)" : "var(--surface)",
                  border: `1px solid ${datasetMode === "demo" ? "rgba(0,229,160,0.35)" : "var(--border)"}`,
                  borderRadius: 6,
                  cursor: "pointer",
                  color: datasetMode === "demo" ? "var(--accent-green)" : "var(--text-dim)",
                  fontWeight: 700,
                  fontSize: 13,
                  fontFamily: "inherit",
                }}
              >
                Demo DB
              </button>

              <button
                onClick={() => {
                  setDatasetMode("custom");
                  setRun(null);
                  setError(null);
                  setShowPresets(false);
                }}
                style={{
                  flex: 1,
                  padding: "10px 0",
                  background: datasetMode === "custom" ? "rgba(77,159,255,0.12)" : "var(--surface)",
                  border: `1px solid ${datasetMode === "custom" ? "rgba(77,159,255,0.25)" : "var(--border)"}`,
                  borderRadius: 6,
                  cursor: "pointer",
                  color: datasetMode === "custom" ? "var(--accent-blue)" : "var(--text-dim)",
                  fontWeight: 700,
                  fontSize: 13,
                  fontFamily: "inherit",
                }}
              >
                Custom JSON
              </button>
            </div>

            {datasetMode === "demo" ? (
              <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.15)", borderRadius: 8, padding: 12, fontSize: 11, color: "var(--text-dim)", lineHeight: 1.6 }}>
                Default demo DB is created automatically on first run (up to 100 rows per dataset).
              </div>
            ) : (
              <DatasetUploader
                onProgress={(msg) => setSetupLog((prev) => [...prev, msg])}
                onReady={(state, presets) => {
                  setCustomDataset(state);
                  setCustomPresets(presets);
                  setDatasetMode("custom");
                  setShowPresets(false);
                  const first = presets[0] ?? PRESET_QUERIES[0];
                  setSelectedPreset(first);
                  setSql(first.sql);
                  setRun(null);
                  setError(null);
                }}
              />
            )}
          </Section>

          {/* Preset dropdown */}
          <Section title="Preset Queries">
            <div ref={presetRef} style={{ position: "relative" }}>
              <button
                onClick={() => {
                  if (datasetMode === "custom" && effectivePresets.length === 0) return;
                  setShowPresets(!showPresets);
                }}
                style={{
                  width: "100%",
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "8px 12px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  cursor: "pointer",
                  color: "var(--text)",
                }}
              >
                <span style={{ fontSize: 12 }}>{selectedPreset.label}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 10, color: "var(--text-dim)", background: "var(--border)", borderRadius: 3, padding: "1px 6px" }}>
                    {selectedPreset.circuit}
                  </span>
                  <ChevronDown size={14} style={{ color: "var(--text-dim)", transform: showPresets ? "rotate(180deg)" : "none", transition: "0.15s" }} />
                </div>
              </button>

              {showPresets && (
                <div
                  style={{
                    position: "absolute",
                    top: "calc(100% + 4px)",
                    left: 0,
                    right: 0,
                    background: "var(--surface)",
                    border: "1px solid var(--border-bright)",
                    borderRadius: 8,
                    zIndex: 200,
                    maxHeight: 380,
                    overflowY: "auto",
                    boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
                  }}
                >
                  {Object.entries(presetsByCategory).map(([cat, queries]) => (
                    <div key={cat}>
                      <div style={{ padding: "8px 12px 4px", fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.08em", textTransform: "uppercase", background: "rgba(0,0,0,0.25)" }}>
                        {CATEGORY_LABELS[cat]}
                      </div>
                      {queries.map((q) => (
                        <button
                          key={q.sql}
                          onClick={() => {
                            setSelectedPreset(q);
                            setSql(q.sql);
                            setShowPresets(false);
                            setRun(null);
                            setError(null);
                          }}
                          style={{
                            display: "block",
                            width: "100%",
                            padding: "8px 12px",
                            textAlign: "left",
                            background: selectedPreset.sql === q.sql ? "rgba(77,159,255,0.1)" : "transparent",
                            border: "none",
                            cursor: "pointer",
                            color: "var(--text)",
                            borderBottom: "1px solid var(--border)",
                          }}
                        >
                          <div style={{ fontSize: 12, marginBottom: 2 }}>{q.label}</div>
                          <div style={{ fontSize: 10, color: "var(--text-dim)" }}>{q.circuit}</div>
                        </button>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {selectedPreset && (
              <div style={{ marginTop: 8, padding: "8px 10px", background: "rgba(77,159,255,0.05)", border: "1px solid rgba(77,159,255,0.15)", borderRadius: 6, fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5, display: "flex", gap: 6 }}>
                <Info size={12} style={{ flexShrink: 0, marginTop: 1, color: "var(--accent-blue)" }} />
                {selectedPreset.description}
              </div>
            )}
          </Section>

          {/* SQL Editor */}
          <Section title="SQL Query">
            <textarea
              value={sql}
              onChange={(e) => setSql(e.target.value)}
              spellCheck={false}
              style={{
                width: "100%",
                minHeight: 100,
                background: "#0d0f15",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "10px 12px",
                color: "var(--text)",
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
                lineHeight: 1.6,
                resize: "vertical",
                outline: "none",
              }}
            />
          </Section>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
            <button
              onClick={handleRun}
              disabled={isRunning}
              style={{
                flex: 1,
                padding: "10px 0",
                background: isRunning ? "rgba(0,229,160,0.1)" : "var(--accent-green)",
                color: isRunning ? "var(--accent-green)" : "#000",
                border: "none",
                borderRadius: 6,
                cursor: isRunning ? "not-allowed" : "pointer",
                fontWeight: 600,
                fontSize: 13,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 6,
                fontFamily: "inherit",
              }}
            >
              {isRunning ? (
                <>
                  <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />
                  {phase === "setting-up" ? "Creating datasets (100 rows)…" : "Generating ZK proof…"}
                </>
              ) : (
                <><Play size={14} />Run & Prove</>
              )}
            </button>
            {(phase === "done" || phase === "error") && (
              <button
                onClick={handleReset}
                style={{
                  padding: "10px 14px",
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  cursor: "pointer",
                  color: "var(--text-dim)",
                  fontFamily: "inherit",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <RotateCcw size={13} />
                Reset
              </button>
            )}
          </div>

          {/* Setup log */}
          {setupLog.length > 0 && (
            <div style={{ background: "#0a0c10", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px", fontSize: 11, color: "var(--text-dim)", maxHeight: 140, overflowY: "auto", lineHeight: 1.8 }}>
              {setupLog.map((l, i) => (
                <div key={i} style={{ display: "flex", gap: 8 }}>
                  <span style={{ color: "var(--accent-green)" }}>›</span>{l}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          )}

          {error && (
            <div style={{ background: "rgba(255,77,106,0.08)", border: "1px solid rgba(255,77,106,0.3)", borderRadius: 6, padding: "10px 12px", color: "var(--accent-red)", fontSize: 11, marginTop: 8, wordBreak: "break-word" }}>
              <XCircle size={12} style={{ display: "inline", marginRight: 6 }} />
              {error}
            </div>
          )}
        </div>

        {/* Right Panel */}
        <div style={{ overflowY: "auto", padding: 28 }}>
          {!run && !isRunning && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", gap: 12 }}>
              <Shield size={52} style={{ opacity: 0.15 }} />
              <div style={{ fontSize: 14 }}>Select a query and click Run & Prove</div>
              <div style={{ fontSize: 11, maxWidth: 380, textAlign: "center", lineHeight: 1.6 }}>
                First run creates 100-row demo datasets automatically. Each query generates a real Plonky2 FRI-SNARK proof. Results (SUM, COUNT, AVG) appear alongside circuit-proved public inputs. Use the Proof Explorer to inspect hex, JSON, and byte layout.
              </div>
            </div>
          )}

          {isRunning && !run && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
              <Loader2 size={38} style={{ color: "var(--accent-green)", animation: "spin 1s linear infinite" }} />
              <div style={{ color: "var(--text-dim)", fontSize: 13 }}>
                {phase === "setting-up" ? "Creating datasets and snapshots…" : "Generating Plonky2 FRI-SNARK proof…"}
              </div>
              <div className="proving-shimmer" style={{ width: 300, height: 3, borderRadius: 2 }} />
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Generating zero-knowledge proof…
              </div>
            </div>
          )}

          {run && (
            <div className="animate-slide-in" style={{ maxWidth: 800, margin: "0 auto" }}>
              {/* Title bar */}
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
                <span className="tag-snark">Plonky2 SNARK</span>
                <span style={{ fontSize: 11, color: "var(--text-dim)", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 4, padding: "2px 8px" }}>
                  proof_id: {run.proofId.slice(0, 22)}…
                </span>
              </div>

              {/* SQL */}
              <div style={{ background: "#0d0f15", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 14px", fontSize: 12, color: "var(--accent-blue)", marginBottom: 20, lineHeight: 1.5 }}>
                {run.sql}
              </div>

              {/* Query result box — shows actual values */}
              <QueryResultBox proof={run.proof} sql={run.sql} />

              {/* Metrics */}
              <Section title="Proof Metrics">
                <div style={{ display: "flex", gap: 10 }}>
                  <MetricBox icon={<Timer size={14} />} label="Proof Generation" value={fmtMs(run.proofMs)} sub="release · native CPU" color="var(--accent-green)" />
                  <MetricBox icon={<Timer size={14} />} label="Verification Time" value={run.verifyMs != null ? fmtMs(run.verifyMs) : "—"} sub={run.verifyMs != null ? "O(log² n)" : "click Verify below"} />
                  <MetricBox icon={<FileDigit size={14} />} label="Proof Size" value={fmtBytes(Math.ceil(run.proof.proof_hex.length / 2))} sub="FRI — constant regardless of rows" />
                  <MetricBox icon={<Hash size={14} />} label="Dataset Size" value={`${run.proof.public_inputs.agg_n_real || run.proof.result_row_count} rows`} sub="PI[7] n_real or count" />
                </div>
              </Section>

              {/* Public Inputs */}
              <Section title="Circuit Public Inputs">
                <PublicInputsPanel pi={run.proof.public_inputs} sql={run.sql} />
              </Section>

              {/* Commitments */}
              <Section title="Commitments">
                <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: "12px 16px" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <div style={{ fontSize: 10, color: "var(--accent-green)", marginBottom: 4 }}>
                        ✅ result_commit_poseidon (circuit-proved)
                      </div>
                      <div style={{ fontSize: 11, fontFamily: "monospace", color: "var(--accent-blue)", wordBreak: "break-all" }}>
                        {run.proof.result_commit_poseidon_proved_hex}
                      </div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>
                        Use this for security-critical checks
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 10, color: "var(--accent-amber)", marginBottom: 4 }}>
                        ⚠ unsafe_metadata_commitment (Blake3, NOT proved)
                      </div>
                      <div style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-dim)", wordBreak: "break-all" }}>
                        {truncHex(run.proof.unsafe_metadata_commitment_hex, 24)}
                      </div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>
                        Content-addressing only — not circuit-constrained
                      </div>
                    </div>
                  </div>
                </div>
              </Section>

              {/* Proof Explorer */}
              <ProofExplorer proof={run.proof} />

              {/* Verify */}
              <Section title="Verification">
                {!run.verification && (
                  <>
                    <button
                      onClick={handleVerify}
                      disabled={verifying}
                      style={{
                        padding: "10px 24px",
                        background: verifying ? "rgba(77,159,255,0.1)" : "rgba(77,159,255,0.15)",
                        border: "1px solid rgba(77,159,255,0.4)",
                        borderRadius: 6,
                        color: "var(--accent-blue)",
                        cursor: verifying ? "not-allowed" : "pointer",
                        fontFamily: "inherit",
                        fontSize: 13,
                        fontWeight: 500,
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        marginBottom: 12,
                      }}
                    >
                      {verifying ? (
                        <><Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />Verifying proof…</>
                      ) : (
                        <><Cpu size={14} />Verify Proof</>
                      )}
                    </button>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.7, padding: "8px 12px", background: "rgba(90,98,130,0.07)", border: "1px solid var(--border)", borderRadius: 6 }}>
                      Verification checks: PI[0] snap_lo · PI[1] query_hash · PI[2]/[3] sum/count · PI[4]/[5] commitments · 128-bit secondary binding (Sort) · Plonky2 FRI proof deserialization
                    </div>
                  </>
                )}
                {run.verification && <VerifyBadge vr={run.verification} />}
              </Section>
            </div>
          )}
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
