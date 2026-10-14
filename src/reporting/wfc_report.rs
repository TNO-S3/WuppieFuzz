//! Support for generating reports that conform to the Web Fuzzing Commons (WFC)
//! report schema, so results from WuppieFuzz can be consumed by WFC-compatible
//! tooling. See:
//! <https://github.com/WebFuzzing/Commons/blob/master/src/main/resources/wfc/schemas/report.yaml>

use std::{
    fs::{File, create_dir_all},
    path::Path,
    time::Duration,
};

use chrono::SecondsFormat;
use libafl::{
    corpus::Corpus,
    state::{HasCorpus, HasSolutions},
};
use serde::Serialize;

use crate::{
    configuration::Configuration, coverage_clients::endpoint::EndpointCoverageClient,
    executor::summarize_sequence, openapi::validate_response::ValidationErrorDiscriminants,
    types::OpenApiFuzzerStateType, wuppie_version::get_wuppie_version,
};

/// The version of the WFC report schema that WuppieFuzz produces reports for.
const WFC_SCHEMA_VERSION: &str = "0.8.0";

/// The human-readable name under which WuppieFuzz identifies itself in WFC reports.
const TOOL_NAME: &str = "WuppieFuzz";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WfcReport {
    schema_version: String,
    tool_name: String,
    tool_version: String,
    creation_time: String,
    faults: Faults,
    problem_details: ProblemDetails,
    total_tests: u64,
    test_file_paths: Vec<String>,
    test_cases: Vec<TestCase>,
    execution_time_in_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<Vec<Coverage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Faults {
    total_number: u64,
    found_faults: Vec<FoundFault>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundFault {
    operation_id: String,
    test_case_id: String,
    fault_categories: Vec<FaultCategoryId>,
}

#[derive(Serialize)]
struct FaultCategoryId {
    id: String,
    code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemDetails {
    rest: RestReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestReport {
    output_http_calls: u64,
    evaluated_http_calls: u64,
    endpoint_ids: Vec<String>,
    covered_http_status: Vec<CoveredEndpoint>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoveredEndpoint {
    endpoint_id: String,
    test_case_id: String,
    http_status: Vec<Option<u16>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    id: String,
    file_path: String,
    name: String,
    // WuppieFuzz test cases are serialized request-sequence files, not generated
    // source code, so there is no meaningful line range to report here. These
    // fields are optional in the WFC schema, so they are omitted entirely rather
    // than defaulting to a misleading `0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    named_examples: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Coverage {
    tool_name: String,
    criteria: Vec<CoverageCriterion>,
}

#[derive(Serialize)]
struct CoverageCriterion {
    name: String,
    covered: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Warning {
    message: String,
    category: String,
    display_priority: u32,
}

/// Maps a validation error (and the HTTP status that triggered it) onto the
/// closest-matching WFC fault category. Where WFC does not (yet) define a
/// matching category, a WuppieFuzz-specific category in the 900-999 "custom"
/// range (reserved by the WFC schema for tool-specific faults) is used instead.
fn fault_category(
    discriminant: ValidationErrorDiscriminants,
    status: u16,
    message: &str,
) -> FaultCategoryId {
    use ValidationErrorDiscriminants::*;

    let (id, code) = match discriminant {
        OperationNotInSpec => ("WUP_OPERATION_NOT_IN_SPEC", 900),
        Status5xxNotSpecified => {
            if status == 500 {
                ("HTTP_STATUS_500", 100)
            } else {
                ("HTTP_OTHER_STATUS_5XX", 121)
            }
        }
        OtherStatusNotSpecified => ("WUP_STATUS_NOT_SPECIFIED", 901),
        ResponseReferenceBroken
        | ResponseObjectIncorrect
        | ResponseEnumIncorrect
        | ResponseMalformedJSON
        | UnexpectedContent => ("SCHEMA_INVALID_RESPONSE", 200),
        MediaTypeContainsNoSchema => ("WUP_MEDIA_TYPE_CONTAINS_NO_SCHEMA", 902),
        SchemaIsAny => ("WUP_SCHEMA_IS_ANY", 903),
        SchemaIsFalse => ("WUP_SCHEMA_IS_FALSE", 904),
        PossibleInjectionSignature => ("WUP_POSSIBLE_INJECTION_SIGNATURE", 905),
    };

    FaultCategoryId {
        id: id.to_string(),
        code,
        context: Some(message.to_string()),
    }
}

/// Inputs needed to assemble a WFC report, gathered from the fuzzer executor at the
/// end of a campaign.
pub struct WfcReportContext<'a> {
    pub config: &'a Configuration,
    pub state: &'a OpenApiFuzzerStateType,
    pub endpoint_client: &'a EndpointCoverageClient,
    pub evaluated_http_calls: u64,
    pub fuzzing_duration: Duration,
    pub report_path: Option<&'a Path>,
    pub code_coverage_ratio: (u64, u64),
    pub endpoint_coverage_ratio: (u64, u64),
}

/// Generates a WFC-compliant `report.json` file, summarizing the fuzzing campaign:
/// the generated test cases (the corpus), the endpoints covered and the HTTP status
/// codes observed for them, and any faults (validation errors) found.
///
/// `ctx.report_path` is the directory the report should be written to; if `None`, a new
/// timestamped `reports/<timestamp>` directory is created for it.
pub fn write_report(ctx: WfcReportContext<'_>) -> anyhow::Result<()> {
    let WfcReportContext {
        config,
        state,
        endpoint_client,
        evaluated_http_calls,
        fuzzing_duration,
        report_path,
        code_coverage_ratio,
        endpoint_coverage_ratio,
    } = ctx;

    let output_dir = match report_path {
        Some(path) => path.to_path_buf(),
        None => super::generate_report_path(),
    };
    create_dir_all(&output_dir)?;

    let corpus = state.corpus();
    let mut test_cases = Vec::with_capacity(corpus.count());
    let mut test_file_paths = Vec::with_capacity(corpus.count());
    let mut output_http_calls = 0u64;
    for id in corpus.ids() {
        let Ok(testcase) = corpus.get(id) else {
            continue;
        };
        let testcase_ref = testcase.borrow();
        let Some(input) = testcase_ref.input() else {
            continue;
        };
        output_http_calls += input.0.len() as u64;
        let file_path = testcase_ref
            .file_path()
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("queue/{id:?}"));
        test_file_paths.push(file_path.clone());
        test_cases.push(TestCase {
            id: file_path.clone(),
            file_path,
            name: summarize_sequence(input),
            start_line: None,
            end_line: None,
            named_examples: None,
        });
    }

    let found_faults: Vec<FoundFault> = endpoint_client
        .faults()
        .iter()
        .map(|fault| {
            let test_case_id = fault.test_case_path.clone().unwrap_or_else(|| {
                format!(
                    "endpoint-coverage:{}:{}:{}",
                    fault.method, fault.path, fault.status
                )
            });
            if let Some(reproducer_path) = &fault.test_case_path {
                test_file_paths.push(reproducer_path.clone());
                test_cases.push(TestCase {
                    id: reproducer_path.clone(),
                    file_path: reproducer_path.clone(),
                    name: format!("{} {} ({})", fault.method, fault.path, fault.status),
                    start_line: None,
                    end_line: None,
                    named_examples: None,
                });
            }
            FoundFault {
                operation_id: format!("{}:{}", fault.method, fault.path),
                test_case_id,
                fault_categories: vec![fault_category(
                    fault.discriminant,
                    fault.status,
                    &format!("{} (observed {} time(s))", fault.message, fault.occurrences),
                )],
            }
        })
        .collect();
    let total_number = found_faults
        .iter()
        .map(|f| f.fault_categories.len() as u64)
        .sum();
    test_file_paths.sort();
    test_file_paths.dedup();
    let total_tests = test_cases.len() as u64;

    let covered_http_status = endpoint_client
        .covered_http_status()
        .into_iter()
        .map(|(endpoint_id, http_status)| CoveredEndpoint {
            endpoint_id,
            test_case_id: "aggregate-run".to_string(),
            http_status,
        })
        .collect();

    let report = WfcReport {
        schema_version: WFC_SCHEMA_VERSION.to_string(),
        tool_name: TOOL_NAME.to_string(),
        tool_version: get_wuppie_version(),
        creation_time: chrono::offset::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        faults: Faults {
            total_number,
            found_faults,
        },
        problem_details: ProblemDetails {
            rest: RestReport {
                output_http_calls,
                evaluated_http_calls,
                endpoint_ids: endpoint_client.endpoint_ids(),
                covered_http_status,
            },
        },
        total_tests,
        test_file_paths,
        test_cases,
        execution_time_in_seconds: fuzzing_duration.as_secs(),
        extra: Some(vec![Coverage {
            tool_name: TOOL_NAME.to_string(),
            criteria: vec![
                CoverageCriterion {
                    name: format!("line ({})", config.coverage_configuration.type_str()),
                    covered: code_coverage_ratio.0,
                    total: Some(code_coverage_ratio.1),
                },
                CoverageCriterion {
                    name: "endpoint".to_string(),
                    covered: endpoint_coverage_ratio.0,
                    total: Some(endpoint_coverage_ratio.1),
                },
            ],
        }]),
        warnings: None,
    };

    // Objectives (crashes/timeouts) do not necessarily have an associated validation
    // error recorded in the endpoint coverage map (e.g. plain timeouts), but their
    // count is still useful context for consumers of this report.
    log::info!(
        "Writing WFC report with {} test cases, {} found faults and {} objectives (crashes/timeouts) to {}",
        report.total_tests,
        report.faults.total_number,
        state.solutions().count(),
        output_dir.display()
    );

    let report_file = output_dir.join("report.json");
    let file = File::create(&report_file)?;
    serde_json::to_writer_pretty(file, &report)?;
    log::info!("WFC report written to {}", report_file.display());

    Ok(())
}
