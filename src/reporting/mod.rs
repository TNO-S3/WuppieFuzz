use std::{fs::create_dir_all, path::PathBuf};

use libafl::{corpus::Corpus, state::HasCorpus};

use crate::{
    input::OpenApiRequest,
    openapi::{curl_request::CurlRequest, validate_response::Response},
    types::OpenApiFuzzerStateType,
};

pub mod sqlite;

/// Cumulative reasons why an input sequence either finished or stopped early.
#[derive(Debug, Clone, Copy, Default)]
pub struct SequenceStopStats {
    /// Number of input sequences that finished without an early stop.
    pub completed: u64,
    /// Number of sequences stopped because a backreference could not be resolved.
    pub missing_backreference: u64,
    /// Number of sequences stopped because a request could not be built by reqwest.
    pub request_build_error: u64,
    /// Number of sequences stopped by a crash or crash-criteria validation error.
    pub crash_or_validation: u64,
    /// Number of sequences stopped by a transport-layer error.
    pub transport_error: u64,
}

/// Cumulative wall-clock time spent in major executor phases.
#[derive(Debug, Clone, Copy, Default)]
pub struct SequenceTimingStats {
    /// Time spent resolving parameter backreferences before a request is sent.
    pub resolve_backreference_us: u64,
    /// Time spent building reqwest requests from OpenAPI inputs.
    pub build_request_us: u64,
    /// Time spent recording the outgoing request for reporting.
    pub report_request_us: u64,
    /// Time spent waiting for HTTP execution and reading the full response body.
    pub http_execute_us: u64,
    /// Time spent recording responses or transport errors for reporting.
    pub report_response_us: u64,
    /// Time spent validating responses and updating parameter feedback.
    pub process_response_us: u64,
    /// Time spent updating endpoint coverage bookkeeping after a response.
    pub endpoint_cover_us: u64,
    /// Time spent in the code coverage backend after each sequence.
    pub code_coverage_phase_us: u64,
    /// Time spent in endpoint coverage aggregation after each sequence.
    pub endpoint_coverage_phase_us: u64,
    /// Time spent in post-exec stats/reporting after coverage collection.
    pub post_exec_reporting_us: u64,
}

/// Periodic high-level campaign statistics for dashboard reporting.
#[derive(Debug, Clone, Copy)]
pub struct CampaignStats {
    /// Number of input sequences executed per second in the latest reporting window.
    pub seq_per_sec: f64,
    /// Number of successfully completed HTTP requests per second in the latest reporting window.
    pub req_per_sec: f64,
    /// Cumulative number of successfully completed HTTP requests in this campaign.
    pub requests_completed_total: u64,
    /// Current number of corpus entries.
    pub corpus_size: u32,
    /// Current number of objective entries.
    pub objectives: u32,
    /// Cumulative sequence completion and stop reasons.
    pub sequence_stop_stats: SequenceStopStats,
    /// Cumulative executor phase timing totals.
    pub sequence_timing_stats: SequenceTimingStats,
}

/// Creates and returns the report path for this run. It is typically of the form
/// `reports/2023-06-13T105302.602Z`, the filename being an ISO 8601 timestamp.
pub fn generate_report_path() -> PathBuf {
    let timestamp = format!(
        "{}",
        chrono::offset::Utc::now().format("%Y-%m-%dT%H%M%S%.3fZ")
    );
    let report_path = PathBuf::from("reports").join(timestamp);
    create_dir_all(&report_path).expect("unable to make reports directory");
    report_path
}

// The reporting trait allows reporting requests and responses for later analysis.
// The type `T` is the type used by the underlying data store to refer to records,
// so that information can be added to a record made earlier.
pub trait Reporting<T, S> {
    /// Report the request with the corresponding input id for further analysis
    fn report_request(
        &self,
        request: &OpenApiRequest,
        curl: &CurlRequest,
        state: &S,
        input_id: u32,
    ) -> T;

    /// Report a valid response link to the corresponding request
    fn report_response(&self, response: &Response, request_id: T);

    /// Report a response error linked to the corresponding request
    fn report_response_error(&self, error: &str, request_id: T);

    /// Report a response error linked to the corresponding request
    fn report_coverage(
        &self,
        line_coverage: u32,
        line_coverage_total: u32,
        endpoint_coverage: u32,
        endpoint_coverage_total: u32,
    );

    /// Report a periodic snapshot of high-level campaign statistics.
    fn report_stats(&self, stats: CampaignStats);
}

impl<R, T, S> Reporting<T, S> for Option<R>
where
    R: Reporting<T, S>,
    T: Default,
{
    fn report_request(
        &self,
        request: &OpenApiRequest,
        curl: &CurlRequest,
        state: &S,
        input_id: u32,
    ) -> T {
        match self.as_ref() {
            Some(reporter) => reporter.report_request(request, curl, state, input_id),
            _ => Default::default(),
        }
    }

    fn report_response(&self, response: &Response, request_id: T) {
        if let Some(reporter) = self.as_ref() {
            reporter.report_response(response, request_id)
        }
    }

    fn report_response_error(&self, error: &str, request_id: T) {
        if let Some(reporter) = self.as_ref() {
            reporter.report_response_error(error, request_id)
        }
    }

    fn report_coverage(
        &self,
        line_coverage: u32,
        line_coverage_total: u32,
        endpoint_coverage: u32,
        endpoint_coverage_total: u32,
    ) {
        if let Some(reporter) = self.as_ref() {
            reporter.report_coverage(
                line_coverage,
                line_coverage_total,
                endpoint_coverage,
                endpoint_coverage_total,
            )
        }
    }

    fn report_stats(&self, stats: CampaignStats) {
        if let Some(reporter) = self.as_ref() {
            reporter.report_stats(stats)
        }
    }
}

fn get_current_test_case_file_name(state: &OpenApiFuzzerStateType) -> Option<String> {
    let corpus = state.corpus();
    corpus
        .current()
        .and_then(|id| corpus.get(id).ok())
        .and_then(|testcase| {
            testcase
                .borrow()
                .file_path()
                .as_ref()
                .map(|pb| pb.to_string_lossy().to_string())
        })
}
