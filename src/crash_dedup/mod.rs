mod identity;
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
    configuration::Configuration,
    crash_dedup::{
        identity::{CrashClusterKey, CrashIdentity},
        replay::{ObservedCrash, ReplayOutcome, replay_input},
    },
    input::OpenApiInput,
    openapi::{parse_api_spec, spec::Spec},
};

const DEDUP_PROGRESS_INTERVAL: usize = 100;

pub fn dedup_crashes(crash_directory: &Path, output_directory: &Path) -> Result<()> {
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

    copy_unique_representatives(&output_directory, &mut clusters)?;

    let clusters: Vec<_> = clusters.into_values().collect();
    let report = DedupReport {
        summary: DedupSummary {
            total_files: crash_files.len(),
            reproduced: clusters.iter().map(|c| c.member_count).sum(),
            unique_clusters: clusters.len(),
            non_reproducible: non_reproducible.len(),
            skipped: skipped.len(),
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

fn prepare_output_directory(crash_directory: &Path, output_directory: &Path) -> Result<PathBuf> {
    ensure_crash_directory(crash_directory)?;

    let crash_directory = std::path::absolute(crash_directory)?;
    let output_directory = std::path::absolute(output_directory)?;
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

    fs::create_dir_all(&output_directory)?;
    Ok(output_directory)
}

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

fn is_crash_input_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    !file_name.starts_with('.') && !file_name.ends_with(".metadata")
}

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

fn unique_file_name(index: usize, source_path: &Path) -> String {
    let file_name = source_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("crash");
    format!("{index:06}_{file_name}")
}

fn write_report(output_directory: &Path, report: &DedupReport) -> Result<()> {
    let report_path = output_directory.join("clusters.json");
    let file = fs::File::create(&report_path)
        .with_context(|| format!("Creating dedup report {}", report_path.display()))?;
    serde_json::to_writer_pretty(file, report)
        .with_context(|| format!("Writing dedup report {}", report_path.display()))?;
    Ok(())
}

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
}

enum FileOutcome {
    Clustered { crash: ObservedCrash, size: u64 },
    NonReproducible(String),
    Skipped(String),
}

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
                },
            );
        }
    }
}

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
        // different endpoint → second cluster
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
}
