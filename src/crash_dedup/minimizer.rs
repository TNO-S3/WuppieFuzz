use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    crash_dedup::{identity::CrashClusterKey, replay::ReplayOutcome},
    input::{Body, OpenApiInput, OpenApiRequest, ParameterContents},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimizationStatus {
    Minimized,
    Unchanged,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct MinimizationReport {
    pub status: MinimizationStatus,
    pub original_request_count: usize,
    pub minimized_request_count: usize,
    pub candidate_replays: usize,
    pub removed_request_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

pub struct MinimizationResult {
    pub input: Option<OpenApiInput>,
    pub crashing_request_index: Option<usize>,
    pub report: MinimizationReport,
}

pub fn minimize_with<Replay>(
    input: OpenApiInput,
    expected_cluster_key: &CrashClusterKey,
    mut replay: Replay,
) -> MinimizationResult
where
    Replay: FnMut(&OpenApiInput) -> Result<ReplayOutcome>,
{
    let original_request_count = input.0.len();
    let baseline = match replay(&input).context("Replaying baseline representative") {
        Ok(ReplayOutcome::Crash(baseline)) => baseline,
        Ok(ReplayOutcome::Completed) => {
            return failed(
                original_request_count,
                0,
                String::from("Baseline input did not reproduce a crash"),
            );
        }
        Ok(ReplayOutcome::Stopped(reason)) => {
            return failed(
                original_request_count,
                0,
                format!("Baseline replay stopped: {reason}"),
            );
        }
        Err(error) => {
            return failed(original_request_count, 0, format!("{error:#}"));
        }
    };
    if baseline.identity.cluster_key() != *expected_cluster_key {
        return failed(
            original_request_count,
            0,
            String::from("Baseline input reproduced a different crash identity"),
        );
    }

    let mut current = input;
    let mut current_crashing_request_index = baseline.crashing_request_index;
    let mut candidate_replays = 0;

    'minimization: loop {
        for request_index in 0..current.0.len() {
            let Some(candidate) = without_request(&current, request_index) else {
                continue;
            };

            candidate_replays += 1;
            let observation = match replay(&candidate).with_context(|| {
                format!("Replaying candidate after removing request {request_index}")
            }) {
                Ok(observation) => observation,
                Err(error) => {
                    return failed(
                        original_request_count,
                        candidate_replays,
                        format!("{error:#}"),
                    );
                }
            };

            if let ReplayOutcome::Crash(observation) = observation
                && observation.identity.cluster_key() == *expected_cluster_key
            {
                current = candidate;
                current_crashing_request_index = observation.crashing_request_index;
                continue 'minimization;
            }
        }
        break;
    }

    let minimized_request_count = current.0.len();
    let removed_request_count = original_request_count.saturating_sub(minimized_request_count);
    let status = if removed_request_count > 0 {
        MinimizationStatus::Minimized
    } else {
        MinimizationStatus::Unchanged
    };

    MinimizationResult {
        input: (removed_request_count > 0).then_some(current),
        crashing_request_index: (removed_request_count > 0)
            .then_some(current_crashing_request_index),
        report: MinimizationReport {
            status,
            original_request_count,
            minimized_request_count,
            candidate_replays,
            removed_request_count,
            failure_reason: None,
            output: None,
        },
    }
}

pub fn failed(
    original_request_count: usize,
    candidate_replays: usize,
    failure_reason: String,
) -> MinimizationResult {
    MinimizationResult {
        input: None,
        crashing_request_index: None,
        report: MinimizationReport {
            status: MinimizationStatus::Failed,
            original_request_count,
            minimized_request_count: original_request_count,
            candidate_replays,
            removed_request_count: 0,
            failure_reason: Some(failure_reason),
            output: None,
        },
    }
}

fn without_request(input: &OpenApiInput, request_index: usize) -> Option<OpenApiInput> {
    if input.0.len() <= 1 || request_index >= input.0.len() {
        return None;
    }
    if input.0.iter().enumerate().any(|(index, request)| {
        index != request_index && request_references_index(request, request_index)
    }) {
        return None;
    }

    let mut candidate = input.clone();
    candidate.0.remove(request_index);
    for request in &mut candidate.0 {
        rewrite_request_references_after_removal(request, request_index);
    }
    Some(candidate)
}

fn request_references_index(request: &OpenApiRequest, request_index: usize) -> bool {
    request
        .parameters
        .values()
        .any(|parameter| parameter_references_index(parameter, request_index))
        || request
            .body
            .contents()
            .is_some_and(|body| parameter_references_index(body, request_index))
}

fn parameter_references_index(parameter: &ParameterContents, request_index: usize) -> bool {
    match parameter {
        ParameterContents::Object(values) => values
            .values()
            .any(|value| parameter_references_index(value, request_index)),
        ParameterContents::Array(values) => values
            .iter()
            .any(|value| parameter_references_index(value, request_index)),
        ParameterContents::OReference(reference) => reference.request_index == request_index,
        ParameterContents::IReference(reference) => reference.request_index == request_index,
        ParameterContents::LeafValue(_) | ParameterContents::Bytes(_) => false,
    }
}

fn rewrite_request_references_after_removal(
    request: &mut OpenApiRequest,
    removed_request_index: usize,
) {
    for parameter in request.parameters.values_mut() {
        rewrite_parameter_references_after_removal(parameter, removed_request_index);
    }
    if let Some(body) = request.body.contents_mut() {
        rewrite_parameter_references_after_removal(body, removed_request_index);
    }
}

fn rewrite_parameter_references_after_removal(
    parameter: &mut ParameterContents,
    removed_request_index: usize,
) {
    match parameter {
        ParameterContents::Object(values) => {
            for value in values.values_mut() {
                rewrite_parameter_references_after_removal(value, removed_request_index);
            }
        }
        ParameterContents::Array(values) => {
            for value in values {
                rewrite_parameter_references_after_removal(value, removed_request_index);
            }
        }
        ParameterContents::OReference(reference) => {
            if reference.request_index > removed_request_index {
                reference.request_index -= 1;
            }
        }
        ParameterContents::IReference(reference) => {
            if reference.request_index > removed_request_index {
                reference.request_index -= 1;
            }
        }
        ParameterContents::LeafValue(_) | ParameterContents::Bytes(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crash_dedup::{
            identity::{CrashIdentity, CrashKind, ObservedExitKind, ResponseClass},
            replay::ObservedCrash,
        },
        input::Method,
    };

    fn request(path: &str) -> OpenApiRequest {
        OpenApiRequest {
            method: Method::Get,
            path: path.into(),
            body: Body::Empty,
            parameters: Default::default(),
        }
    }

    fn observed_crash() -> ObservedCrash {
        ObservedCrash {
            identity: CrashIdentity {
                exit_kind: ObservedExitKind::Crash,
                crash_kind: CrashKind::Http5xx,
                http_status: Some(500),
                validation_error_discriminant: None,
                endpoint: Some(String::from("GET /crash")),
                response_class: ResponseClass::Json,
            },
            crashing_request_index: 1,
        }
    }

    #[test]
    fn minimization_removes_unnecessary_request() {
        let crash = observed_crash();
        let cluster_key = crash.identity.cluster_key();
        let input = OpenApiInput(vec![request("/setup"), request("/crash")]);
        let mut replay_count = 0;

        let result = minimize_with(input, &cluster_key, |_| {
            replay_count += 1;
            Ok(ReplayOutcome::Crash(crash.clone()))
        });

        assert_eq!(result.report.status, MinimizationStatus::Minimized);
        assert_eq!(result.report.removed_request_count, 1);
        assert_eq!(result.report.minimized_request_count, 1);
    }

    #[test]
    fn stopped_candidate_does_not_preserve_crash() {
        let crash = observed_crash();
        let cluster_key = crash.identity.cluster_key();
        let input = OpenApiInput(vec![request("/setup"), request("/crash")]);
        let mut replay_count = 0;

        let result = minimize_with(input, &cluster_key, |_| {
            replay_count += 1;
            if replay_count == 1 {
                Ok(ReplayOutcome::Crash(crash.clone()))
            } else {
                Ok(ReplayOutcome::Stopped(String::from(
                    "missing backreference",
                )))
            }
        });

        assert_eq!(result.report.status, MinimizationStatus::Unchanged);
        assert_eq!(result.report.removed_request_count, 0);
        assert_eq!(result.report.candidate_replays, 2);
    }
}
