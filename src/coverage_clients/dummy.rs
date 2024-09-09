//! Coverage client that does nothing, useful for testing purposes.

use std::path::Path;

use super::CoverageClient;

/// The Dummy coverage client is a minimal implementation that only yields empty
/// coverage bitmaps.
pub struct DummyCoverageClient {
    endpoint_cov_map_pointer: *mut u8,
}

impl DummyCoverageClient {
    /// Creates a new dummy coverage client.
    pub fn new(endpoint_cov_map_pointer: *mut u8) -> Self {
        Self {
            endpoint_cov_map_pointer,
        }
    }
}

impl CoverageClient for DummyCoverageClient {
    /// Fetch and process the current coverage. If `reset` is true, tells the remote
    /// coverage agent to reset its coverage map.
    fn fetch_coverage(&mut self, _reset: bool) {}

    /// Retrieve a pointer to the coverage bitmap (this is used by LibAFL).
    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.endpoint_cov_map_pointer
    }

    /// Retrieve the coverage ratio: nodes hit and total number of nodes.
    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        (0, 0)
    }

    /// Write a format-dependent report to disk
    fn generate_coverage_report(&self, _report_dir: &Path) {}
}
