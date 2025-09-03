use std::{fs::create_dir_all, path::PathBuf};

use libafl::{corpus::Corpus, state::HasCorpus};

use crate::{
    input::OpenApiRequest,
    openapi::{curl_request::CurlRequest, validate_response::Response},
    types::{ExecutorType, OpenApiFuzzerStateType},
};

pub mod sqlite;

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

pub fn generate_coverage_reports(report_path: Option<PathBuf>, executor: ExecutorType) {
    if let Some(report_path) = report_path {
        executor.generate_coverage_report(&report_path);
    }
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
        input_id: usize,
    ) -> T;

    /// Report a valid response link to the corresponding request
    fn report_response(&self, response: &Response, request_id: T);

    /// Report a response error linked to the corresponding request
    fn report_response_error(&self, error: &str, request_id: T);

    /// Report a response error linked to the corresponding request
    fn report_coverage(
        &self,
        line_coverage: u64,
        line_coverage_total: u64,
        endpoint_coverage: u64,
        endpoint_coverage_total: u64,
    );
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
        input_id: usize,
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
        line_coverage: u64,
        line_coverage_total: u64,
        endpoint_coverage: u64,
        endpoint_coverage_total: u64,
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
