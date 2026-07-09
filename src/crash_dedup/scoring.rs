//! Crash reproducer complexity scoring.
//!
//! Ported from the `crash_min` prototype (see
//! <https://github.com/TNO-S3/WuppieFuzz/issues/156>). Byte size of a serialized crash
//! file is a poor proxy for how easy a REST API crash reproducer is to read and act on:
//! a short sequence with a huge JSON body can be simpler to understand than a long
//! sequence of small requests, or vice versa. This module computes a composite score
//! over dimensions that matter for REST API crash reproducibility, so dedup can pick
//! the *simplest* representative of a cluster rather than merely the smallest file.

use crate::input::{Body, OpenApiRequest, ParameterContents};

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
/// or raw file size, which are not meaningful proxies for REST API request sequence
/// complexity.
pub fn crash_score(effective_requests: &[OpenApiRequest]) -> f64 {
    let effective_length = effective_requests.len().max(1) as f64;

    let total_params: usize = effective_requests
        .iter()
        .map(|req| req.parameters.len())
        .sum();

    let back_refs: usize = effective_requests.iter().map(count_references).sum();

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
    let body_refs = request
        .body
        .contents()
        .map(count_refs_in_contents)
        .unwrap_or(0);
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

/// Scores the effective (pre-crash) prefix of `input`: only requests up to and including
/// `crashing_request_index` matter for reproducer complexity, since anything after the
/// crash is never reached during replay.
pub fn score_effective_prefix(requests: &[OpenApiRequest], crashing_request_index: usize) -> f64 {
    let cutoff = (crashing_request_index + 1).min(requests.len());
    crash_score(&requests[..cutoff])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::input::{
        Method,
        parameter::{ParameterKind, SimpleValue},
    };

    fn request(params: usize) -> OpenApiRequest {
        let mut parameters = BTreeMap::new();
        for i in 0..params {
            parameters.insert(
                (format!("p{i}"), ParameterKind::Query),
                ParameterContents::LeafValue(SimpleValue::String(String::from("v"))),
            );
        }
        OpenApiRequest {
            method: Method::Get,
            path: String::from("/x"),
            body: Body::Empty,
            parameters,
        }
    }

    #[test]
    fn fewer_params_score_lower() {
        let simple = crash_score(&[request(0)]);
        let complex = crash_score(&[request(5)]);
        assert!(simple < complex);
    }

    #[test]
    fn shorter_effective_prefix_scores_lower() {
        let short = crash_score(&[request(1)]);
        let long = crash_score(&[request(1), request(1)]);
        assert!(short < long);
    }

    #[test]
    fn score_effective_prefix_ignores_requests_after_crash() {
        let requests = vec![request(0), request(0), request(10)];
        // Crash happens at index 0: only the first request should count, so adding a
        // huge trailing request must not change the score.
        let score = score_effective_prefix(&requests, 0);
        let baseline = crash_score(&requests[..1]);
        assert_eq!(score, baseline);
    }
}
