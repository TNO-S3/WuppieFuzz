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
use indexmap::IndexMap;
use libafl::{corpus::Corpus, state::HasCorpus};
use serde::Serialize;

use crate::{
    configuration::{Configuration, CoverageConfiguration},
    coverage_clients::endpoint::{EndpointCoverageClient, locate_test_case},
    executor::summarize_sequence,
    openapi::validate_response::ValidationErrorDiscriminants,
    types::OpenApiFuzzerStateType,
    wuppie_version::get_wuppie_version,
};

/// The version of the WFC report schema that WuppieFuzz produces reports for.
const WFC_SCHEMA_VERSION: &str = "0.8.0";

/// The human-readable name under which WuppieFuzz identifies itself in WFC reports.
const TOOL_NAME: &str = "WuppieFuzz";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WfcReport {
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
///
/// Exposed as `pub(crate)` (rather than folded directly into `fault_category`) so
/// the HTML endpoint coverage report (`coverage_clients::endpoint`) can label and
/// filter faults using the exact same category vocabulary as the WFC report.
pub(crate) fn fault_category_name(
    discriminant: ValidationErrorDiscriminants,
    status: u16,
) -> (&'static str, u32) {
    use ValidationErrorDiscriminants::*;

    match discriminant {
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
    }
}

fn fault_category(
    discriminant: ValidationErrorDiscriminants,
    status: u16,
    message: &str,
) -> FaultCategoryId {
    let (id, code) = fault_category_name(discriminant, status);

    FaultCategoryId {
        id: id.to_string(),
        code,
        context: Some(message.to_string()),
    }
}

/// Registers a `TestCase` for `id` in `test_cases` (a no-op if already present),
/// and tracks its reproducer file path in `test_file_paths`. `id` is expected to
/// be a stable content-hash test case name (see `coverage_clients::endpoint::
/// ensure_crash_file`); its on-disk location is looked up via `locate_test_case`,
/// falling back to `id` itself if the file can't be found (e.g. removed from
/// under us mid-campaign), so that every `testCaseId` referenced elsewhere in the
/// report is still guaranteed to resolve to a `TestCase` entry here (see
/// WebFuzzing/Commons#49).
fn register_test_case(
    test_cases: &mut IndexMap<String, TestCase>,
    test_file_paths: &mut Vec<String>,
    id: &str,
    name: impl FnOnce() -> String,
) {
    if test_cases.contains_key(id) {
        return;
    }
    let file_path = match locate_test_case(id) {
        Some(path) => {
            test_file_paths.push(path.clone());
            path
        }
        None => {
            log::warn!("Could not locate a test case file named {id} on disk");
            id.to_string()
        }
    };
    test_cases.insert(
        id.to_string(),
        TestCase {
            id: id.to_string(),
            file_path,
            name: name(),
            start_line: None,
            end_line: None,
            named_examples: None,
        },
    );
}

/// Inputs needed to assemble a WFC report, gathered from the fuzzer executor at the
/// end of a campaign.
pub struct WfcReportContext<'a> {
    /// The active fuzzer configuration, used to decide whether the "line" coverage
    /// criterion is meaningful to report (see `CoverageConfiguration::Endpoint`).
    pub config: &'a Configuration,
    /// The fuzzer state, whose corpus/solutions are walked to build `testCases`.
    pub state: &'a OpenApiFuzzerStateType,
    /// Source of endpoint coverage, faults and covered-status data (see
    /// `EndpointCoverageClient::{faults, covered_http_status, endpoint_ids}`).
    pub endpoint_client: &'a EndpointCoverageClient,
    /// Total number of HTTP calls evaluated (not just those in the output corpus)
    /// during the campaign.
    pub evaluated_http_calls: u64,
    /// Wall-clock duration of the fuzzing campaign.
    pub fuzzing_duration: Duration,
    /// Code-coverage ratio (covered, total), omitted from the report entirely in
    /// black-box/endpoint-only mode (see `CoverageConfiguration::Endpoint`).
    pub code_coverage_ratio: (u64, u64),
    /// Endpoint-coverage ratio (covered, total); always meaningful since it only
    /// needs the OpenAPI spec.
    pub endpoint_coverage_ratio: (u64, u64),
}

/// Assembles a WFC-compliant report in memory: the generated test cases (the
/// corpus), the endpoints covered and the HTTP status codes observed for them,
/// and any faults (validation errors) found.
///
/// No I/O is performed here (see `persist_report` for that), so callers only need
/// to hold `ctx.endpoint_client`'s lock for the duration of this call, rather than
/// across the subsequent file write as well.
pub(crate) fn build_report(ctx: WfcReportContext<'_>) -> WfcReport {
    let WfcReportContext {
        config,
        state,
        endpoint_client,
        evaluated_http_calls,
        fuzzing_duration,
        code_coverage_ratio,
        endpoint_coverage_ratio,
    } = ctx;

    let corpus = state.corpus();
    let mut test_cases: IndexMap<String, TestCase> = IndexMap::with_capacity(corpus.count());
    let mut test_file_paths = Vec::with_capacity(corpus.count());
    let mut output_http_calls = 0u64;
    for id in corpus.ids() {
        let Ok(testcase) = corpus.get(id) else {
            continue;
        };
        let mut testcase_ref = testcase.borrow_mut();
        let file_path = testcase_ref
            .file_path()
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("queue/{id:?}"));
        // Use the bare file name (LibAFL's deterministic content-hash, the same
        // name `ensure_crash_file`/`generate_name` produce) as the id, so it is
        // consistent with the ids used for faults and covered endpoints - never
        // prefixed with the containing directory (e.g. "queue/").
        let case_id = Path::new(&file_path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.clone());
        // `input()` only returns an already-cached value: LibAFL frees a testcase's
        // input from memory right after it's first written to disk, and only
        // re-populates the cache if it's later reused as a mutation base. Entries
        // that were never reused (e.g. the newest finds, right before the
        // campaign's timeout) would otherwise be silently dropped from the report
        // even though their file is on disk - so load explicitly instead.
        let Ok(input) = testcase_ref.load_input(corpus) else {
            log::warn!(
                "Could not load corpus entry {id:?} from disk, skipping it in the WFC report"
            );
            continue;
        };
        output_http_calls += input.0.len() as u64;
        test_file_paths.push(file_path.clone());
        test_cases.insert(
            case_id.clone(),
            TestCase {
                id: case_id,
                file_path,
                name: summarize_sequence(input),
                start_line: None,
                end_line: None,
                named_examples: None,
            },
        );
    }

    let found_faults: Vec<FoundFault> = endpoint_client
        .faults()
        .iter()
        .map(|fault| {
            // `fault.test_case_id` is a stable content-hash name, proactively
            // persisted to `CRASHES_DIR` the moment this fault was first recorded
            // (see `ensure_crash_file`), so it is used directly as the testCaseId -
            // `register_test_case` guarantees a matching `TestCase` entry exists for
            // it regardless of whether that file can still be located on disk.
            let test_case_id = fault.test_case_id.clone();
            register_test_case(&mut test_cases, &mut test_file_paths, &test_case_id, || {
                format!("{} {} ({})", fault.method, fault.path, fault.status)
            });
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
    // Each `FoundFault` always carries exactly one category (see `fault_category`
    // above), so this is currently equivalent to `found_faults.len()`; summed over
    // `fault_categories` instead so it stays correct if a fault is ever classified
    // under more than one category.
    let total_number = found_faults
        .iter()
        .map(|f| f.fault_categories.len() as u64)
        .sum();

    // One `CoveredEndpoint` per distinct (endpoint, status) observed, each citing
    // the real test case (see `ensure_crash_file`) whose example demonstrated it.
    // This is schema-valid (`httpStatus` just needs to be an array), though the WFC
    // schema's own doc for `httpStatus` envisions one entry per (endpoint, test
    // case) grouping together every status that test case's calls observed; we
    // don't track multiple statuses per test case internally, so emit the more
    // granular but equally valid per-status form instead.
    let covered_http_status: Vec<CoveredEndpoint> = endpoint_client
        .covered_http_status()
        .into_iter()
        .map(|covered| {
            register_test_case(
                &mut test_cases,
                &mut test_file_paths,
                &covered.test_case_id,
                || {
                    let status = covered
                        .status
                        .map_or_else(|| "no response".to_string(), |s| s.to_string());
                    format!("{} ({status})", covered.endpoint_id)
                },
            );
            CoveredEndpoint {
                endpoint_id: covered.endpoint_id,
                test_case_id: covered.test_case_id,
                http_status: vec![covered.status],
            }
        })
        .collect();

    test_file_paths.sort();
    test_file_paths.dedup();
    let total_tests = test_cases.len() as u64;
    let test_cases: Vec<TestCase> = test_cases.into_values().collect();

    // Endpoint coverage is always meaningful (it only needs the OpenAPI spec), but
    // in black-box mode (`CoverageConfiguration::Endpoint`) there is no real code
    // coverage agent, so `code_coverage_ratio` is a meaningless dummy value - omit
    // the "line" criterion entirely rather than report it.
    let mut criteria = vec![CoverageCriterion {
        name: "endpoint".to_string(),
        covered: endpoint_coverage_ratio.0,
        total: Some(endpoint_coverage_ratio.1),
    }];
    if !matches!(
        config.coverage_configuration,
        CoverageConfiguration::Endpoint
    ) {
        criteria.push(CoverageCriterion {
            name: format!("line ({})", config.coverage_configuration.type_str()),
            covered: code_coverage_ratio.0,
            total: Some(code_coverage_ratio.1),
        });
    }

    WfcReport {
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
            criteria,
        }]),
        warnings: None,
    }
}

/// Writes `report` to `report_path/report.json`, creating `report_path` if needed.
/// Pure I/O, no `EndpointCoverageClient` access required (see `build_report`).
pub(crate) fn persist_report(
    report: &WfcReport,
    report_path: &Path,
    solutions_count: usize,
) -> anyhow::Result<()> {
    create_dir_all(report_path)?;

    // Objectives (crashes/timeouts) do not necessarily have an associated validation
    // error recorded in the endpoint coverage map (e.g. plain timeouts), but their
    // count is still useful context for consumers of this report.
    log::info!(
        "Writing WFC report with {} test cases, {} found faults and {} objectives (crashes/timeouts) to {}",
        report.total_tests,
        report.faults.total_number,
        solutions_count,
        report_path.display()
    );

    let report_file = report_path.join("report.json");
    let file = File::create(&report_file)?;
    serde_json::to_writer_pretty(file, report)?;
    log::info!("WFC report written to {}", report_file.display());

    Ok(())
}
