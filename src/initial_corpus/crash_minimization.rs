//! Crash corpus minimization.
//!
//! After a fuzzing campaign, the crash directory may contain many duplicate or overlapping
//! crash files. This module provides a minimization pass that finds the smallest subset
//! of crashes that still covers all unique crash signatures.
//!
//! A crash signature is a tuple of (HTTP method, path, status code, validation error type).
//! The minimizer uses a greedy set cover algorithm, preferring crashes with fewer requests
//! and smaller request payloads (i.e. simpler reproducers).

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use libafl::{executors::ExitKind, inputs::Input};
use strum::IntoDiscriminant;

use crate::{
    authentication::build_http_client,
    configuration::Configuration,
    executor::process_response,
    input::{Method, OpenApiInput},
    openapi::{
        build_request::build_request_from_input,
        spec::Spec,
        validate_response::{Response, ValidationErrorDiscriminants},
    },
    parameter_feedback::ParameterFeedback,
};

/// A single element in a crash signature: (method, path, status_code, error_discriminant).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CrashSignatureEntry {
    method: Method,
    path: String,
    status: u16,
    error: Option<ValidationErrorDiscriminants>,
}

/// Computes a score for a crash input. Lower score means a simpler reproducer.
///
/// This uses the average request size within the sequence multiplied by the number
/// of requests, as suggested in <https://github.com/TNO-S3/WuppieFuzz/issues/156>.
/// This avoids relying on byte-level fuzzing metrics (like `LenTimeMulTestcasePenalty`)
/// which are not meaningful for REST API request sequences.
fn crash_score(input: &OpenApiInput) -> f64 {
    let num_requests = input.0.len().max(1) as f64;
    let total_size: usize = input
        .0
        .iter()
        .map(|req| serde_yaml::to_string(req).map(|s| s.len()).unwrap_or(0))
        .sum();
    let avg_size = total_size as f64 / num_requests;
    num_requests * avg_size
}

/// Replays a crash input against the API and returns the set of crash signatures it triggers.
fn replay_crash(
    input: &OpenApiInput,
    api: &Spec,
    config: &Configuration,
    client: &reqwest::blocking::Client,
    authentication: &mut crate::authentication::Authentication,
    cookie_store: &std::sync::Arc<reqwest_cookie_store::CookieStoreMutex>,
) -> HashSet<CrashSignatureEntry> {
    let mut signatures = HashSet::new();
    let mut parameter_feedback = ParameterFeedback::new(input.0.len());

    for (request_index, request) in input.0.iter().enumerate() {
        let mut request = request.clone();
        if request
            .resolve_parameter_references(&parameter_feedback)
            .is_err()
        {
            break;
        }

        let request_builder = match build_request_from_input(
            client,
            authentication,
            cookie_store,
            api,
            &request,
        ) {
            Err(_) => continue,
            Ok(r) => r.timeout(Duration::from_millis(config.request_timeout)),
        };

        let request_built = match request_builder.build() {
            Ok(r) => r,
            Err(_) => break,
        };

        match client.execute(request_built) {
            Ok(response) => {
                let response: Response = response.into();
                let status = response.status().as_u16();
                let mut exit_kind = ExitKind::Ok;
                let validation_error = process_response(
                    request_index,
                    &request,
                    &response,
                    api,
                    &config.crash_criteria,
                    &mut exit_kind,
                    &mut parameter_feedback,
                );

                if exit_kind == ExitKind::Crash {
                    signatures.insert(CrashSignatureEntry {
                        method: request.method,
                        path: request.path.clone(),
                        status,
                        error: validation_error.map(|e| e.discriminant()),
                    });
                    break;
                }
            }
            Err(_) => break,
        }
    }

    signatures
}

/// A crash file with its parsed input, replay signature, and score.
struct CrashEntry {
    path: PathBuf,
    input: OpenApiInput,
    signature: HashSet<CrashSignatureEntry>,
    score: f64,
}

/// Minimizes the crash corpus using a greedy set cover algorithm.
///
/// Replays each crash from `crash_dir` to determine its error signature (the set of
/// method+path+status+error tuples it triggers), then selects the smallest subset of
/// crashes that covers all observed signatures. Among crashes covering equal signatures,
/// shorter and simpler sequences are preferred.
///
/// Original crash files in `crash_dir` are preserved; minimized results are written to `out_dir`.
pub fn minimize_crash_corpus(
    crash_dir: &Path,
    out_dir: &Path,
    api: &Spec,
    config: &Configuration,
) -> Result<()> {
    let crash_files = load_crash_files(crash_dir)?;
    if crash_files.is_empty() {
        log::info!("No crash files found in {crash_dir:?}, skipping crash minimization");
        return Ok(());
    }
    log::info!(
        "Crash corpus minimization: replaying {} crash files",
        crash_files.len()
    );

    let (mut authentication, cookie_store, client) = build_http_client(api)?;

    let mut entries: Vec<CrashEntry> = Vec::new();
    for (path, input) in crash_files.iter() {
        let signature = replay_crash(input, api, config, &client, &mut authentication, &cookie_store);
        if signature.is_empty() {
            log::debug!("Crash file {path:?} did not reproduce, skipping");
            continue;
        }
        let score = crash_score(input);
        entries.push(CrashEntry {
            path: path.clone(),
            input: input.clone(),
            signature,
            score,
        });
    }

    if entries.is_empty() {
        log::warn!("No crashes could be reproduced during minimization");
        return Ok(());
    }

    // Collect all unique signature entries
    let all_signatures: HashSet<_> = entries
        .iter()
        .flat_map(|e| e.signature.iter().cloned())
        .collect();

    log::info!(
        "Found {} unique crash signatures across {} reproducible crashes",
        all_signatures.len(),
        entries.len()
    );

    // Greedy set cover: repeatedly pick the crash covering the most uncovered signatures,
    // breaking ties by preferring lower score (simpler reproducer).
    let mut uncovered = all_signatures;
    let mut selected: Vec<usize> = Vec::new();
    let mut used = vec![false; entries.len()];

    while !uncovered.is_empty() {
        let best = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !used[*i])
            .max_by(|(_, a), (_, b)| {
                let a_new = a.signature.intersection(&uncovered).count();
                let b_new = b.signature.intersection(&uncovered).count();
                a_new
                    .cmp(&b_new)
                    // On tie: prefer lower score (simpler crash)
                    .then_with(|| {
                        b.score
                            .partial_cmp(&a.score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            });

        match best {
            Some((idx, entry)) => {
                if entry.signature.intersection(&uncovered).count() == 0 {
                    break;
                }
                used[idx] = true;
                selected.push(idx);
                for sig in &entries[idx].signature {
                    uncovered.remove(sig);
                }
            }
            None => break,
        }
    }

    // Write minimized crashes to output directory
    fs::create_dir_all(out_dir)?;
    for (out_idx, &crash_idx) in selected.iter().enumerate() {
        let entry = &entries[crash_idx];
        let out_file = out_dir.join(format!("{out_idx}"));
        entry
            .input
            .to_file(&out_file)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        log::debug!(
            "Selected crash {out_idx}: {:?}",
            entry.path.file_name().unwrap_or_default()
        );
    }

    log::info!(
        "Crash corpus minimized: {} -> {} crashes (output: {out_dir:?})",
        crash_files.len(),
        selected.len()
    );

    Ok(())
}

fn load_crash_files(crash_dir: &Path) -> Result<Vec<(PathBuf, OpenApiInput)>> {
    if !crash_dir.exists() {
        return Ok(vec![]);
    }

    let mut files = vec![];
    for entry in fs::read_dir(crash_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            match OpenApiInput::from_file(&path) {
                Ok(input) => files.push((path, input)),
                Err(err) => log::warn!("Could not parse crash file {path:?}: {err}"),
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::input::{Body, OpenApiRequest};

    fn dummy_request() -> OpenApiRequest {
        OpenApiRequest {
            method: Method::Get,
            path: "/test".to_string(),
            body: Body::Empty,
            parameters: BTreeMap::new(),
        }
    }

    #[test]
    fn test_crash_score_prefers_shorter_sequences() {
        let short = OpenApiInput(vec![dummy_request()]);
        let long = OpenApiInput(vec![dummy_request(), dummy_request()]);
        assert!(crash_score(&short) <= crash_score(&long));
    }

    #[test]
    fn test_empty_input_score() {
        let empty = OpenApiInput(vec![]);
        let score = crash_score(&empty);
        assert!(score.is_finite());
    }
}
