//! Persistent benchmark result storage (filesystem JSON).
//!
//! Each benchmark run is stored as a JSON file under a configurable directory.
//! Results can be listed, retrieved by ID, and exported.

use crate::benchmarks::types::BenchmarkResult;
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkStore
// ─────────────────────────────────────────────────────────────────────────────

/// Filesystem-backed store for benchmark results.
pub struct BenchmarkStore {
    base_dir: PathBuf,
}

impl BenchmarkStore {
    /// Create a new store rooted at the given directory.
    /// Creates the directory if it doesn't exist.
    pub fn new(base_dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let base_dir = base_dir.into();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Default store location: `./benchmark_results/`
    pub fn default_location() -> std::io::Result<Self> {
        Self::new("benchmark_results")
    }

    /// Save a single benchmark result.
    pub fn save(&self, result: &BenchmarkResult) -> std::io::Result<()> {
        let filename = format!("{}.json", result.run_id);
        let path = self.base_dir.join(&filename);
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| std::io::Error::other(e))?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Save multiple results from a suite run.
    /// Also saves a suite manifest file linking all run IDs.
    pub fn save_suite(&self, results: &[BenchmarkResult]) -> std::io::Result<String> {
        let suite_id = uuid::Uuid::new_v4().to_string();
        let suite_dir = self.base_dir.join(&suite_id);
        fs::create_dir_all(&suite_dir)?;

        let mut run_ids = Vec::new();
        for result in results {
            let filename = format!("{}.json", result.run_id);
            let path = suite_dir.join(&filename);
            let json = serde_json::to_string_pretty(result)
                .map_err(|e| std::io::Error::other(e))?;
            fs::write(&path, json)?;
            run_ids.push(result.run_id.to_string());
        }

        // Write manifest
        let manifest = SuiteManifest {
            suite_id: suite_id.clone(),
            run_ids,
            created_at_ms: now_ms(),
            scenario_count: results.len(),
            successful: results.iter().filter(|r| r.success).count(),
        };
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| std::io::Error::other(e))?;
        fs::write(suite_dir.join("manifest.json"), manifest_json)?;

        Ok(suite_id)
    }

    /// Load a single result by run ID.
    pub fn load(&self, run_id: &str) -> std::io::Result<BenchmarkResult> {
        // First try direct file
        let path = self.base_dir.join(format!("{}.json", run_id));
        if path.exists() {
            let json = fs::read_to_string(&path)?;
            let result: BenchmarkResult = serde_json::from_str(&json)
                .map_err(|e| std::io::Error::other(e))?;
            return Ok(result);
        }

        // Search in suite subdirectories
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let candidate = entry.path().join(format!("{}.json", run_id));
                if candidate.exists() {
                    let json = fs::read_to_string(&candidate)?;
                    let result: BenchmarkResult = serde_json::from_str(&json)
                        .map_err(|e| std::io::Error::other(e))?;
                    return Ok(result);
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("benchmark run {} not found", run_id),
        ))
    }

    /// List all stored run IDs (both standalone and suite-nested).
    pub fn list_run_ids(&self) -> std::io::Result<Vec<String>> {
        let mut ids = Vec::new();

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    ids.push(stem.to_string_lossy().to_string());
                }
            } else if path.is_dir() {
                // Look inside suite directories
                for sub_entry in fs::read_dir(&path)? {
                    let sub_entry = sub_entry?;
                    let sub_path = sub_entry.path();
                    if sub_path.extension().map(|e| e == "json").unwrap_or(false) {
                        if let Some(stem) = sub_path.file_stem() {
                            let name = stem.to_string_lossy().to_string();
                            if name != "manifest" {
                                ids.push(name);
                            }
                        }
                    }
                }
            }
        }

        Ok(ids)
    }

    /// List all suite manifests.
    pub fn list_suites(&self) -> std::io::Result<Vec<SuiteManifest>> {
        let mut manifests = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let manifest_path = entry.path().join("manifest.json");
                if manifest_path.exists() {
                    let json = fs::read_to_string(&manifest_path)?;
                    if let Ok(manifest) = serde_json::from_str::<SuiteManifest>(&json) {
                        manifests.push(manifest);
                    }
                }
            }
        }
        manifests.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        Ok(manifests)
    }

    /// Load all results from a suite.
    pub fn load_suite(&self, suite_id: &str) -> std::io::Result<Vec<BenchmarkResult>> {
        let suite_dir = self.base_dir.join(suite_id);
        if !suite_dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("suite {} not found", suite_id),
            ));
        }

        let mut results = Vec::new();
        for entry in fs::read_dir(&suite_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false)
                && path.file_stem().map(|s| s != "manifest").unwrap_or(false) {
                    let json = fs::read_to_string(&path)?;
                    if let Ok(result) = serde_json::from_str::<BenchmarkResult>(&json) {
                        results.push(result);
                    }
                }
        }
        Ok(results)
    }

    /// Export all results as a single JSON array string.
    pub fn export_all_json(&self) -> std::io::Result<String> {
        let ids = self.list_run_ids()?;
        let mut results = Vec::new();
        for id in &ids {
            if let Ok(r) = self.load(id) {
                results.push(r);
            }
        }
        serde_json::to_string_pretty(&results)
            .map_err(|e| std::io::Error::other(e))
    }

    /// Get the base directory path.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SuiteManifest
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuiteManifest {
    pub suite_id: String,
    pub run_ids: Vec<String>,
    pub created_at_ms: u64,
    pub scenario_count: usize,
    pub successful: usize,
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
