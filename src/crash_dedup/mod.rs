//! Crash deduplication and optional minimization pipeline.
//!
//! This module powers `wuppiefuzz dedup`.
//! High-level flow:
//! 1. Discover crash files in input directory.
//! 2. Replay each file and derive a crash identity key.
//! 3. Group files by key into clusters and pick smallest representative.
//! 4. Write one representative per cluster to `output/unique`.
//! 5. Optionally minimize representatives (or all members) while preserving cluster key.
//! 6. Emit `clusters.json` with summary counts and per-cluster details.
//!
//! Where to find things:
//! - [`dedup_crashes`] orchestrates end-to-end command behavior.
//! - `identity` defines crash identity dimensions and cluster keys.
//! - `replay` replays an input and reports observed crash identity.
//! - `minimizer` performs delta-debugging minimization.

mod identity;
pub mod minimizer;
pub mod replay;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use libafl::inputs::Input;
use serde::Serialize;
use walkdir::WalkDir;

use crate::{
    configuration::{Configuration, MinimizationMode},
    crash_dedup::{
        identity::{CrashClusterKey, CrashIdentity},
        minimizer::{
            MinimizationReport, MinimizationResult, MinimizationStatus, failed, minimize_with,
        },
        replay::{ObservedCrash, ReplayOutcome, replay_input},
    },
    input::OpenApiInput,
    openapi::{parse_api_spec, spec::Spec},
};

const DEDUP_PROGRESS_INTERVAL: usize = 100;

/// Deduplicate crash files by replayed crash identity and optionally minimize outputs.
///
/// Preconditions:
/// - `crash_directory` must exist and be a directory.
/// - `output_directory` must not be equal to, or nested under, `crash_directory`.
/// - Global configuration must already be loadable via [`Configuration::get`].
pub fn dedup_crashes(
    crash_directory: &Path,
    output_directory: &Path,
    minimize: Option<MinimizationMode>,
) -> Result<()> {
    let output_directory = prepare_output_directory(crash_directory, output_directory)?;
    let config = Configuration::get().map_err(anyhow::Error::msg)?;
    crate::setup_logging(config);

    let api = parse_api_spec(config)?;
    let crash_files = get_crash_files(crash_directory)?;
    let mut clusters: BTreeMap<CrashClusterKey, CrashCluster> = BTreeMap::new();
    let mut non_reproducible = Vec::new();
    let mut skipped = Vec::new();

    for (index, crash_file) in crash_files.iter().enumerate() {
        let source_path = relative_string(crash_directory, crash_file);
        match process_crash_file(crash_file, &api, config) {
            FileOutcome::Clustered { crash, size } => {
                add_to_clusters(&mut clusters, crash_file, source_path, size, crash);
            }
            FileOutcome::NonReproducible(reason) => {
                non_reproducible.push(CrashFileResult {
                    path: source_path,
                    reason,
                });
            }
            FileOutcome::Skipped(reason) => {
                skipped.push(CrashFileResult {
                    path: source_path,
                    reason,
                });
            }
        }
        log_progress(
            index + 1,
            crash_files.len(),
            clusters.len(),
            non_reproducible.len(),
            skipped.len(),
        );
    }

    write_cluster_outputs(
        crash_directory,
        &output_directory,
        &mut clusters,
        &api,
        config,
        minimize,
    )?;

    let clusters: Vec<_> = clusters.into_values().collect();
    let report = DedupReport {
        summary: DedupSummary {
            total_files: crash_files.len(),
            reproduced: clusters.iter().map(|c| c.member_count).sum(),
            unique_clusters: clusters.len(),
            non_reproducible: non_reproducible.len(),
            skipped: skipped.len(),
            minimization: minimization_summary(&clusters),
        },
        clusters,
        non_reproducible,
        skipped,
    };
    write_report(&output_directory, &report)?;
    log_summary(&report.summary, &output_directory);

    Ok(())
}

#[derive(Debug, Serialize)]
struct DedupReport {
    summary: DedupSummary,
    clusters: Vec<CrashCluster>,
    non_reproducible: Vec<CrashFileResult>,
    skipped: Vec<CrashFileResult>,
}

#[derive(Debug, Serialize)]
struct DedupSummary {
    total_files: usize,
    reproduced: usize,
    unique_clusters: usize,
    non_reproducible: usize,
    skipped: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimization: Option<MinimizationSummary>,
}

#[derive(Debug, Serialize)]
struct MinimizationSummary {
    minimized: usize,
    unchanged: usize,
    failed: usize,
}

#[derive(Debug, Serialize)]
struct CrashCluster {
    key: String,
    #[serde(skip)]
    representative_source: PathBuf,
    #[serde(skip)]
    representative_size: u64,
    representative: String,
    members: Vec<String>,
    member_count: usize,
    representative_crashing_request_index: usize,
    identity: SerializableCrashIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimization: Option<ClusterMinimizationReport>,
}

#[derive(Debug, Serialize)]
struct ClusterMinimizationReport {
    mode: MinimizationMode,
    files: BTreeMap<String, MinimizationReport>,
}

#[derive(Debug, Serialize)]
struct SerializableCrashIdentity {
    exit_kind: String,
    crash_kind: String,
    http_status: Option<u16>,
    validation_error_discriminant: Option<String>,
    endpoint: Option<String>,
    response_class: String,
}

impl From<&CrashIdentity> for SerializableCrashIdentity {
    fn from(identity: &CrashIdentity) -> Self {
        Self {
            exit_kind: identity.exit_kind.to_string(),
            crash_kind: identity.crash_kind.to_string(),
            http_status: identity.http_status,
            validation_error_discriminant: identity
                .validation_error_discriminant
                .as_ref()
                .map(|d| format!("{d:?}")),
            endpoint: identity.endpoint.clone(),
            response_class: identity.response_class.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CrashFileResult {
    path: String,
    reason: String,
}

/// Validate crash/output directories and return normalized absolute output path.
///
/// Rejects output paths inside crash directory to avoid recursively reprocessing generated output.
fn prepare_output_directory(crash_directory: &Path, output_directory: &Path) -> Result<PathBuf> {
    ensure_crash_directory(crash_directory)?;

    fs::create_dir_all(&output_directory)?;

    let crash_directory = std::fs::canonicalize(crash_directory)?;
    let output_directory = std::fs::canonicalize(output_directory)?;
    if output_directory.starts_with(&crash_directory) {
        return Err(anyhow!(
            "Output directory {} must not be inside or equal to crash directory {} because crash collection is recursive",
            output_directory.display(),
            crash_directory.display()
        ));
    }
    if output_directory.exists() && !output_directory.is_dir() {
        return Err(anyhow!(
            "Output path {} exists but is not a directory",
            output_directory.display()
        ));
    }

    Ok(output_directory)
}

/// Recursively collect candidate crash input files from `crash_directory`.
///
/// Hidden files and `.metadata` sidecars are skipped.
fn get_crash_files(crash_directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(crash_directory).min_depth(1) {
        let entry = entry.with_context(|| {
            format!(
                "Walking crash directory {}",
                crash_directory.to_string_lossy()
            )
        })?;

        if entry.file_type().is_file() && is_crash_input_file(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }

    files.sort();
    Ok(files)
}

/// Validate that crash input root exists and is a directory.
fn ensure_crash_directory(crash_directory: &Path) -> Result<()> {
    if !crash_directory.exists() {
        return Err(anyhow!(
            "Crash directory {} does not exist",
            crash_directory.display()
        ));
    }
    if !crash_directory.is_dir() {
        return Err(anyhow!(
            "Crash path {} is not a directory",
            crash_directory.display()
        ));
    }
    Ok(())
}

/// Return `true` for replayable crash input files.
///
/// Current filter excludes hidden files and `.metadata` files.
fn is_crash_input_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    !file_name.starts_with('.') && !file_name.ends_with(".metadata")
}

/// Copy one representative input per cluster to `output_directory/unique`.
///
/// Updates each cluster's `representative` field to its output-relative destination path.
fn copy_unique_representatives(
    output_directory: &Path,
    clusters: &mut BTreeMap<CrashClusterKey, CrashCluster>,
) -> Result<()> {
    let unique_directory = output_directory.join("unique");
    fs::create_dir_all(&unique_directory).with_context(|| {
        format!(
            "Creating unique crash directory {}",
            unique_directory.display()
        )
    })?;

    for (index, cluster) in clusters.values_mut().enumerate() {
        let destination =
            unique_directory.join(unique_file_name(index, &cluster.representative_source));
        fs::copy(&cluster.representative_source, &destination).with_context(|| {
            format!(
                "Copying representative {} to {}",
                cluster.representative_source.display(),
                destination.display()
            )
        })?;
        cluster.representative = relative_string(output_directory, &destination);
    }

    Ok(())
}

/// Write per-cluster outputs according to minimization mode.
///
/// With no mode, this copies representatives only. With minimization enabled, it writes
/// minimized files and records per-file minimization reports.
fn write_cluster_outputs(
    crash_directory: &Path,
    output_directory: &Path,
    clusters: &mut BTreeMap<CrashClusterKey, CrashCluster>,
    api: &Spec,
    config: &Configuration,
    mode: Option<MinimizationMode>,
) -> Result<()> {
    let Some(mode) = mode else {
        return copy_unique_representatives(output_directory, clusters);
    };

    let unique_directory = output_directory.join("unique");
    fs::create_dir_all(&unique_directory).with_context(|| {
        format!(
            "Creating unique crash directory {}",
            unique_directory.display()
        )
    })?;

    let total = clusters.len();
    let minimized_directory = output_directory.join("minimized");
    log::info!("Starting crash minimization ({mode:?}): {total} clusters");

    for (index, (cluster_key, cluster)) in clusters.iter_mut().enumerate() {
        let unique_destination =
            unique_directory.join(unique_file_name(index, &cluster.representative_source));
        let representative_member = cluster.representative.clone();
        let mut files = BTreeMap::new();

        match mode {
            MinimizationMode::Representative => {
                let mut result =
                    minimize_source(&cluster.representative_source, cluster_key, api, config);
                write_minimization_output(
                    &cluster.representative_source,
                    &unique_destination,
                    &mut result,
                )?;
                if let Some(idx) = result.crashing_request_index {
                    cluster.representative_crashing_request_index = idx;
                }
                result.report.output = Some(relative_string(output_directory, &unique_destination));
                files.insert(representative_member, result.report);
            }
            MinimizationMode::All => {
                let mut representative_minimized = None;

                for member in &cluster.members {
                    let source = crash_directory.join(member);
                    let dest = minimized_directory.join(member);
                    let mut result = minimize_source(&source, cluster_key, api, config);
                    write_minimization_output(&source, &dest, &mut result)?;
                    if member == &representative_member {
                        representative_minimized = Some(dest.clone());
                        if let Some(idx) = result.crashing_request_index {
                            cluster.representative_crashing_request_index = idx;
                        }
                    }
                    result.report.output = Some(relative_string(output_directory, &dest));
                    files.insert(member.clone(), result.report);
                }

                let rep = representative_minimized.with_context(|| {
                    format!(
                        "Locating minimized representative for cluster {}",
                        cluster.key
                    )
                })?;
                fs::copy(&rep, &unique_destination).with_context(|| {
                    format!(
                        "Copying minimized representative to {}",
                        unique_destination.display()
                    )
                })?;
            }
        }

        cluster.representative = relative_string(output_directory, &unique_destination);
        cluster.minimization = Some(ClusterMinimizationReport { mode, files });
        log::info!(
            "Crash minimization progress: {}/{total} clusters processed",
            index + 1
        );
    }

    Ok(())
}

/// Load one crash input file and run delta-debugging minimization against expected cluster key.
///
/// If input cannot be read, returns a failed minimization result instead of bubbling error.
fn minimize_source(
    source: &Path,
    cluster_key: &CrashClusterKey,
    api: &Spec,
    config: &Configuration,
) -> MinimizationResult {
    let input = match OpenApiInput::from_file(source) {
        Ok(input) => input,
        Err(error) => return failed(0, 0, format!("Could not read crash input: {error}")),
    };
    minimize_with(input, cluster_key, |candidate| {
        replay_input(candidate, api, config)
    })
}

/// Persist minimization output for one source file.
///
/// Writes minimized input when available; otherwise copies original source unchanged.
fn write_minimization_output(
    source: &Path,
    destination: &Path,
    result: &mut MinimizationResult,
) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
    }
    if let Some(input) = result.input.take() {
        input.to_file(destination).map_err(anyhow::Error::msg)?;
    } else {
        fs::copy(source, destination).with_context(|| {
            format!("Copying {} to {}", source.display(), destination.display())
        })?;
    }
    Ok(())
}

/// Build deterministic output file name for unique representatives.
fn unique_file_name(index: usize, source_path: &Path) -> String {
    let file_name = source_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("crash");
    format!("{index:06}_{file_name}")
}

/// Write final dedup report to `clusters.json` under output directory.
fn write_report(output_directory: &Path, report: &DedupReport) -> Result<()> {
    let report_path = output_directory.join("clusters.json");
    let file = fs::File::create(&report_path)
        .with_context(|| format!("Creating dedup report {}", report_path.display()))?;
    serde_json::to_writer_pretty(file, report)
        .with_context(|| format!("Writing dedup report {}", report_path.display()))?;
    Ok(())
}

/// Aggregate per-file minimization statuses into top-level summary counts.
///
/// Returns `None` when no minimization data exists.
fn minimization_summary(clusters: &[CrashCluster]) -> Option<MinimizationSummary> {
    let mut reports = clusters
        .iter()
        .filter_map(|c| c.minimization.as_ref())
        .flat_map(|m| m.files.values())
        .peekable();
    reports.peek()?;
    let mut summary = MinimizationSummary {
        minimized: 0,
        unchanged: 0,
        failed: 0,
    };
    for report in reports {
        match report.status {
            MinimizationStatus::Minimized => summary.minimized += 1,
            MinimizationStatus::Unchanged => summary.unchanged += 1,
            MinimizationStatus::Failed => summary.failed += 1,
        }
    }
    Some(summary)
}

/// Log end-of-run counts and optional minimization breakdown.
fn log_summary(summary: &DedupSummary, output_directory: &Path) {
    log::info!(
        "Dedup complete: {} crash files, {} reproduced, {} unique clusters, {} non-reproducible, {} skipped. Output: {}",
        summary.total_files,
        summary.reproduced,
        summary.unique_clusters,
        summary.non_reproducible,
        summary.skipped,
        output_directory.display()
    );
    if let Some(m) = &summary.minimization {
        log::info!(
            "Minimization: {} minimized, {} unchanged, {} failed",
            m.minimized,
            m.unchanged,
            m.failed
        );
    }
}

enum FileOutcome {
    Clustered { crash: ObservedCrash, size: u64 },
    NonReproducible(String),
    Skipped(String),
}

/// Replay one crash file and classify outcome for dedup accounting.
///
/// Returns:
/// - `Clustered` when replay reproduces crash and metadata can be read.
/// - `NonReproducible` when replay completes or stops without crash.
/// - `Skipped` for unreadable inputs or replay/metadata errors.
fn process_crash_file(crash_file: &Path, api: &Spec, config: &Configuration) -> FileOutcome {
    let input = match OpenApiInput::from_file(crash_file) {
        Ok(input) => input,
        Err(error) => return FileOutcome::Skipped(format!("Could not read crash input: {error}")),
    };

    let crash = match replay_input(&input, api, config) {
        Ok(ReplayOutcome::Crash(crash)) => crash,
        Ok(ReplayOutcome::Completed) => {
            return FileOutcome::NonReproducible(String::from("Replay did not reproduce a crash"));
        }
        Ok(ReplayOutcome::Stopped(reason)) => {
            return FileOutcome::NonReproducible(format!("Replay stopped: {reason}"));
        }
        Err(error) => {
            return FileOutcome::Skipped(format!("Could not replay crash input: {error}"));
        }
    };

    match fs::metadata(crash_file) {
        Ok(metadata) => FileOutcome::Clustered {
            crash,
            size: metadata.len(),
        },
        Err(error) => FileOutcome::Skipped(format!("Could not read crash input metadata: {error}")),
    }
}

/// Insert crash into cluster map and update representative selection.
///
/// Smallest source file per key is kept as representative.
fn add_to_clusters(
    clusters: &mut BTreeMap<CrashClusterKey, CrashCluster>,
    source_file: &Path,
    source_path: String,
    source_size: u64,
    observed_crash: ObservedCrash,
) {
    let key = observed_crash.identity.cluster_key();
    match clusters.get_mut(&key) {
        Some(cluster) => {
            cluster.members.push(source_path.clone());
            cluster.member_count = cluster.members.len();
            if source_size < cluster.representative_size {
                cluster.representative_source = source_file.to_path_buf();
                cluster.representative_size = source_size;
                cluster.representative = source_path;
                cluster.representative_crashing_request_index =
                    observed_crash.crashing_request_index;
            }
        }
        None => {
            clusters.insert(
                key.clone(),
                CrashCluster {
                    key: key.to_string(),
                    representative_source: source_file.to_path_buf(),
                    representative_size: source_size,
                    representative: source_path.clone(),
                    members: vec![source_path],
                    member_count: 1,
                    representative_crashing_request_index: observed_crash.crashing_request_index,
                    identity: SerializableCrashIdentity::from(&observed_crash.identity),
                    minimization: None,
                },
            );
        }
    }
}

/// Emit periodic progress logs while scanning crash files.
///
/// Logs every [`DEDUP_PROGRESS_INTERVAL`] files, excluding final summary.
fn log_progress(
    processed: usize,
    total: usize,
    unique_clusters: usize,
    non_reproducible: usize,
    skipped: usize,
) {
    if processed < total && processed.is_multiple_of(DEDUP_PROGRESS_INTERVAL) {
        log::info!(
            "Dedup progress: {processed}/{total} files processed, {unique_clusters} unique clusters, {non_reproducible} non-reproducible, {skipped} skipped"
        );
    }
}

/// Convert `path` to slash-normalized string relative to `base` when possible.
fn relative_string(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::crash_dedup::identity::{CrashKind, ObservedExitKind, ResponseClass};

    fn make_crash(endpoint: &str) -> ObservedCrash {
        make_crash_with_index(endpoint, 0)
    }

    fn make_crash_with_index(endpoint: &str, crashing_request_index: usize) -> ObservedCrash {
        ObservedCrash {
            identity: CrashIdentity {
                exit_kind: ObservedExitKind::Crash,
                crash_kind: CrashKind::Http5xx,
                http_status: Some(500),
                validation_error_discriminant: None,
                endpoint: Some(endpoint.to_string()),
                response_class: ResponseClass::Json,
            },
            crashing_request_index,
        }
    }

    #[test]
    fn get_crash_files_ignores_metadata_and_hidden_files() -> Result<()> {
        let dir = TempDir::new()?;
        fs::write(dir.path().join("crash-a"), b"")?;
        fs::write(dir.path().join("crash-b.metadata"), b"")?;
        fs::write(dir.path().join(".hidden"), b"")?;

        let files = get_crash_files(dir.path())?;

        assert_eq!(files, vec![dir.path().join("crash-a")]);
        Ok(())
    }

    #[test]
    fn add_to_clusters_groups_deduplicates_and_prefers_smaller_representative() {
        let mut clusters = BTreeMap::new();

        // large first, then a smaller duplicate — representative should flip to smaller
        add_to_clusters(
            &mut clusters,
            Path::new("large"),
            String::from("large"),
            100,
            make_crash_with_index("GET /items", 2),
        );
        add_to_clusters(
            &mut clusters,
            Path::new("small"),
            String::from("small"),
            10,
            make_crash_with_index("GET /items", 1),
        );
        // different endpoint -> second cluster
        add_to_clusters(
            &mut clusters,
            Path::new("other"),
            String::from("other"),
            10,
            make_crash("POST /items"),
        );

        assert_eq!(clusters.len(), 2);
        let get_cluster = clusters.values().next().unwrap();
        assert_eq!(get_cluster.member_count, 2);
        assert_eq!(get_cluster.representative, "small");
        assert_eq!(get_cluster.representative_crashing_request_index, 1);
    }

    #[test]
    fn prepare_output_directory_rejects_nested_output() -> Result<()> {
        let dir = TempDir::new()?;
        let crashes = dir.path().join("crashes");
        fs::create_dir(&crashes)?;

        let err = prepare_output_directory(&crashes, &crashes.join("out")).unwrap_err();
        assert!(
            err.to_string()
                .contains("must not be inside or equal to crash directory")
        );
        Ok(())
    }

    #[test]
    fn copy_unique_representatives_names_and_updates_paths() -> Result<()> {
        let dir = TempDir::new()?;
        let crash_a = dir.path().join("a-crash");
        let crash_b = dir.path().join("b-crash");
        fs::write(&crash_a, b"aaa")?;
        fs::write(&crash_b, b"bbb")?;

        let output = dir.path().join("out");
        let mut clusters = BTreeMap::new();
        add_to_clusters(
            &mut clusters,
            &crash_a,
            String::from("a-crash"),
            3,
            make_crash("GET /a"),
        );
        add_to_clusters(
            &mut clusters,
            &crash_b,
            String::from("b-crash"),
            3,
            make_crash("POST /b"),
        );
        copy_unique_representatives(&output, &mut clusters)?;

        let reps: Vec<_> = clusters
            .values()
            .map(|c| c.representative.as_str())
            .collect();
        assert_eq!(reps, ["unique/000000_a-crash", "unique/000001_b-crash"]);
        assert_eq!(fs::read(output.join("unique/000000_a-crash"))?, b"aaa");
        assert_eq!(fs::read(output.join("unique/000001_b-crash"))?, b"bbb");
        Ok(())
    }
}
