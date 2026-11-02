//! Coverage from WSan's `X-WSan-Sinks` response header.
//!
//! For each request WSan lists the sinks it reached and whether each one broke,
//! as `<cwe>:<location>=<err>#<base64(sql)>` entries joined by ';'. Each distinct
//! `<cwe>:<location>=<err>` gets one bit in the coverage map, so reaching a new
//! sink, or breaking one for the first time, counts as new coverage. The SQL is
//! not part of the key: it changes with every mutated value and would make every
//! input look new. Works like `EndpointCoverageClient`.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use indexmap::IndexMap;

use crate::coverage_clients::{CoverageClient, MAP_SIZE};

/// A WSan coverage client with an empty map.
pub fn setup_wsan_coverage() -> Arc<Mutex<WsanCoverageClient>> {
    Arc::new(Mutex::new(WsanCoverageClient::new()))
}

/// Coverage client backed by WSan's per-request sink signal.
pub struct WsanCoverageClient {
    /// Each distinct `<cwe>:<location>=<err>` gets the next free bit. Reached
    /// (err=0) and broke (err=1) are different entries.
    sinks: IndexMap<String, ()>,
    /// Bits set by the current request; LibAFL reads and resets this.
    cov_map: [u8; MAP_SIZE],
    /// Bits set over the whole run, for the coverage report.
    cov_map_total: [u8; MAP_SIZE],
    /// Number of distinct entries seen so far.
    len: usize,
}

impl Default for WsanCoverageClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WsanCoverageClient {
    /// An empty client.
    pub fn new() -> Self {
        Self {
            sinks: IndexMap::new(),
            cov_map: [0; MAP_SIZE],
            cov_map_total: [0; MAP_SIZE],
            len: 0,
        }
    }

    /// Records one `X-WSan-Sinks` header value: sets the bit of each entry's
    /// `<cwe>:<location>=<err>`.
    pub fn record(&mut self, header_value: &str) {
        for entry in header_value.split(';') {
            let key = entry.split('#').next().unwrap_or_default().trim();
            if key.is_empty() {
                continue;
            }
            let (index, _) = self.sinks.insert_full(key.to_owned(), ());
            assert!(index / 8 < MAP_SIZE, "WSan coverage map is full");
            self.len = std::cmp::max(self.len, index + 1);
            let bit = 0b1000_0000u8 >> (index % 8);
            self.cov_map[index / 8] |= bit;
            self.cov_map_total[index / 8] |= bit;
        }
    }
}

impl CoverageClient for Arc<Mutex<WsanCoverageClient>> {
    fn fetch_coverage(&mut self, _reset: bool) {}

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.lock().unwrap().cov_map.as_mut_ptr()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let guard = self.lock().unwrap();
        let hit = guard
            .cov_map_total
            .iter()
            .map(|b| b.count_ones() as u64)
            .sum();
        (hit, guard.len as u64)
    }

    fn generate_coverage_report(&self, report_path: &Path) {
        let guard = self.lock().unwrap();
        let mut lines: Vec<&str> = guard.sinks.keys().map(String::as_str).collect();
        lines.sort_unstable();
        let _ = std::fs::write(report_path.join("wsancoverage.txt"), lines.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::WsanCoverageClient;

    #[test]
    fn keys_on_sink_and_outcome_not_sql() {
        let mut c = WsanCoverageClient::new();
        c.record("89:A.java:1=0#U0VMRUNU;89:A.java:1=1#eA==");
        // Same sink and outcome, different SQL: no new bit.
        c.record("89:A.java:1=0#b3RoZXI=");
        assert_eq!(c.len, 2);
        assert_eq!(c.cov_map[0], 0b1100_0000);
    }
}
