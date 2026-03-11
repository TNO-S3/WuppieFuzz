//! Crash corpus minimization.
//!
//! After a fuzzing campaign, the crash directory may contain many duplicate or overlapping
//! crash files. This module provides a minimization pass that finds the smallest subset
//! of crashes that still covers all unique crash signatures.
//!
//! A crash signature is a tuple of (HTTP method, path, status code, validation error type).
//! The minimizer uses a greedy set cover algorithm, preferring crashes that are simpler
//! to reproduce and understand: fewer requests, fewer parameters, and fewer back-references.

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
    input::{Body, Method, OpenApiInput, OpenApiRequest, parameter::ParameterContents},
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
/// The score is a composite of dimensions relevant to REST API crash reproducibility:
/// - **effective_length**: only requests up to and including the crashing one matter.
///   A crash at request 0 is simpler than one at request 4.
/// - **parameter_count**: more parameters = harder to isolate the triggering value.
/// - **back_reference_count**: references to earlier responses add inter-request
///   dependencies, making manual reproduction harder.
/// - **avg_body_complexity**: average serialized body size across effective requests,
///   a proxy for payload complexity and nesting depth.
///
/// This avoids relying on byte-level fuzzing metrics (like `LenTimeMulTestcasePenalty`)
/// which are not meaningful for REST API request sequences.
/// See <https://github.com/TNO-S3/WuppieFuzz/issues/156>.
fn crash_score(effective_requests: &[OpenApiRequest]) -> f64 {
    let effective_length = effective_requests.len().max(1) as f64;

    let total_params: usize = effective_requests
        .iter()
        .map(|req| req.parameters.len())
        .sum();

    let back_refs: usize = effective_requests
        .iter()
        .map(count_references)
        .sum();

    let total_body_size: usize = effective_requests
        .iter()
        .map(|req| body_serialized_size(&req.body))
        .sum();
    let avg_body = total_body_size as f64 / effective_length;

    // Multiplicative composite: each dimension independently penalizes complexity.
    // +1 offsets prevent zeroing out the score when a dimension is 0.
    effective_length * (1.0 + total_params as f64) * (1.0 + back_refs as f64) * (1.0 + avg_body)
}

/// Counts the number of back-references (OReference / IReference) in a request's
/// parameters and body.
fn count_references(request: &OpenApiRequest) -> usize {
    let param_refs = request
        .parameters
        .values()
        .filter(|p| p.is_reference())
        .count();
    let body_refs = match &request.body {
        Body::Empty => 0,
        Body::TextPlain(p) | Body::ApplicationJson(p) | Body::XWwwFormUrlencoded(p) => {
            count_refs_in_contents(p)
        }
    };
    param_refs + body_refs
}

/// Recursively counts references inside a `ParameterContents` tree.
fn count_refs_in_contents(contents: &ParameterContents) -> usize {
    match contents {
        ParameterContents::OReference(_) | ParameterContents::IReference(_) => 1,
        ParameterContents::Object(map) => map.values().map(count_refs_in_contents).sum(),
        ParameterContents::Array(arr) => arr.iter().map(count_refs_in_contents).sum(),
        ParameterContents::LeafValue(_) | ParameterContents::Bytes(_) => 0,
    }
}

/// Returns the serialized size of a request body (0 for empty bodies).
fn body_serialized_size(body: &Body) -> usize {
    match body {
        Body::Empty => 0,
        _ => serde_yaml::to_string(body).map(|s| s.len()).unwrap_or(0),
    }
}

/// Result from replaying a crash: the set of crash signatures and the effective
/// length (index of crashing request + 1).
struct ReplayResult {
    signatures: HashSet<CrashSignatureEntry>,
    effective_length: usize,
}

/// Replays a crash input against the API and returns the set of crash signatures it triggers,
/// along with the effective length (number of requests up to and including the crash).
fn replay_crash(
    input: &OpenApiInput,
    api: &Spec,
    config: &Configuration,
    client: &reqwest::blocking::Client,
    authentication: &mut crate::authentication::Authentication,
    cookie_store: &std::sync::Arc<reqwest_cookie_store::CookieStoreMutex>,
) -> ReplayResult {
    let mut signatures = HashSet::new();
    let mut parameter_feedback = ParameterFeedback::new(input.0.len());
    let mut effective_length = input.0.len();

    for (request_index, request) in input.0.iter().enumerate() {
        let mut request = request.clone();
        if request
            .resolve_parameter_references(&parameter_feedback)
            .is_err()
        {
            effective_length = request_index;
            break;
        }

        let request_builder =
            match build_request_from_input(client, authentication, cookie_store, api, &request) {
                Err(_) => continue,
                Ok(r) => r.timeout(Duration::from_millis(config.request_timeout)),
            };

        let request_built = match request_builder.build() {
            Ok(r) => r,
            Err(_) => {
                effective_length = request_index;
                break;
            }
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
                    effective_length = request_index + 1;
                    break;
                }
            }
            Err(_) => {
                effective_length = request_index;
                break;
            }
        }
    }

    ReplayResult {
        signatures,
        effective_length,
    }
}

/// A crash file with its parsed input, replay signature, and score.
struct CrashEntry {
    path: PathBuf,
    input: OpenApiInput,
    signature: HashSet<CrashSignatureEntry>,
    /// Lower score = simpler reproducer, preferred during selection.
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
        let replay = replay_crash(
            input,
            api,
            config,
            &client,
            &mut authentication,
            &cookie_store,
        );
        if replay.signatures.is_empty() {
            log::debug!("Crash file {path:?} did not reproduce, skipping");
            continue;
        }
        // Score only the effective prefix (requests up to and including the crash)
        let effective_requests = &input.0[..replay.effective_length.min(input.0.len())];
        let score = crash_score(effective_requests);
        entries.push(CrashEntry {
            path: path.clone(),
            input: input.clone(),
            signature: replay.signatures,
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
    use crate::{
        input::{
            Body, OpenApiRequest,
            parameter::{OReference, ParameterContents, ParameterKind},
        },
        parameter_access::{ParameterAccess, ParameterAccessElements},
    };

    fn dummy_request() -> OpenApiRequest {
        OpenApiRequest {
            method: Method::Get,
            path: "/test".to_string(),
            body: Body::Empty,
            parameters: BTreeMap::new(),
        }
    }

    fn request_with_params(n: usize) -> OpenApiRequest {
        let mut params = BTreeMap::new();
        for i in 0..n {
            params.insert(
                (format!("param{i}"), ParameterKind::Query),
                ParameterContents::LeafValue(crate::input::parameter::SimpleValue::String(
                    "val".to_string(),
                )),
            );
        }
        OpenApiRequest {
            method: Method::Post,
            path: "/test".to_string(),
            body: Body::Empty,
            parameters: params,
        }
    }

    fn request_with_reference() -> OpenApiRequest {
        let mut params = BTreeMap::new();
        params.insert(
            ("ref_param".to_string(), ParameterKind::Query),
            ParameterContents::OReference(OReference {
                request_index: 0,
                parameter_access: ParameterAccess::response_body(ParameterAccessElements(vec![])),
            }),
        );
        OpenApiRequest {
            method: Method::Get,
            path: "/test/{id}".to_string(),
            body: Body::Empty,
            parameters: params,
        }
    }

    #[test]
    fn test_crash_score_prefers_shorter_sequences() {
        let short = [dummy_request()];
        let long = [dummy_request(), dummy_request()];
        assert!(crash_score(&short) <= crash_score(&long));
    }

    #[test]
    fn test_empty_input_score() {
        let empty: [OpenApiRequest; 0] = [];
        let score = crash_score(&empty);
        assert!(score.is_finite());
    }

    #[test]
    fn test_score_penalizes_more_parameters() {
        let few = [request_with_params(1)];
        let many = [request_with_params(10)];
        assert!(
            crash_score(&few) < crash_score(&many),
            "More parameters should produce a higher (worse) score"
        );
    }

    #[test]
    fn test_score_penalizes_back_references() {
        let no_refs = [dummy_request(), dummy_request()];
        let with_refs = [dummy_request(), request_with_reference()];
        assert!(
            crash_score(&no_refs) < crash_score(&with_refs),
            "Back-references should produce a higher (worse) score"
        );
    }

    #[test]
    fn test_count_references_empty() {
        assert_eq!(count_references(&dummy_request()), 0);
    }

    #[test]
    fn test_count_references_with_ref() {
        assert_eq!(count_references(&request_with_reference()), 1);
    }
}
